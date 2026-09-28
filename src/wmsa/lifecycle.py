"""
Lifecycle State Machine and Evidence Gate for WMSA.
Enforces non-negotiable human analyst decisions and category-specific evidence gates.
No tool or LLM can promote a finding to TRIAGED, VERIFIED, or FIXED.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from wmsa.db import Database
from wmsa.evidence import EvidenceManager
from wmsa.normalize import Finding, FindingStatus

ActorType = Literal["tool", "analyst", "llm", "system"]


class LifecycleViolation(Exception):
    """Raised when an illegal state transition or evidence gate failure occurs."""


# Allowed transition matrix
ALLOWED_TRANSITIONS: Dict[FindingStatus, List[FindingStatus]] = {
    "CANDIDATE": ["TRIAGED", "REJECTED"],
    "TRIAGED": ["VERIFIED", "REJECTED", "NEEDS_REVIEW", "ACCEPTED_RISK"],
    "NEEDS_REVIEW": ["TRIAGED", "REJECTED"],
    "VERIFIED": ["PATCH_PROPOSED", "ACCEPTED_RISK", "CLOSED"],
    "PATCH_PROPOSED": ["PATCH_APPLIED", "VERIFIED"],
    "PATCH_APPLIED": ["RETEST_PENDING"],
    "RETEST_PENDING": ["FIXED", "NOT_FIXED", "REGRESSION", "INCONCLUSIVE"],
    "NOT_FIXED": ["PATCH_PROPOSED", "VERIFIED"],
    "REGRESSION": ["PATCH_PROPOSED", "VERIFIED"],
    "INCONCLUSIVE": ["RETEST_PENDING", "VERIFIED"],
    "FIXED": ["CLOSED", "RETEST_PENDING"],
    "ACCEPTED_RISK": ["TRIAGED", "CLOSED"],
    "CLOSED": ["CANDIDATE"],  # Reopening only with new evidence
}


class LifecycleManager:
    """Manages finding state transitions and enforces the evidence gate."""

    def __init__(self, db: Optional[Database] = None, evidence_mgr: Optional[EvidenceManager] = None):
        self.db = db or Database()
        self.evidence_mgr = evidence_mgr or EvidenceManager(self.db)

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        with self.db.get_connection() as conn:
            row = conn.execute(
                "SELECT data_json FROM findings WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()
            if not row:
                return None
            return Finding(**json.loads(row["data_json"]))

    def _validate_actor_permissions(self, to_status: FindingStatus, actor_type: ActorType, finding_id: str) -> None:
        """Enforces that LLM and Tool actors can NEVER promote to TRIAGED, VERIFIED, or FIXED."""
        restricted_targets = {"TRIAGED", "VERIFIED", "FIXED"}
        if to_status in restricted_targets and actor_type in ("tool", "llm"):
            # Audit the unauthorized attempt
            self.db.log_audit_event(
                event_type="unauthorized_transition_attempt",
                actor_type=actor_type,
                actor_id="restricted_actor",
                payload={
                    "finding_id": finding_id,
                    "target_status": to_status,
                    "rejection": f"Actor '{actor_type}' is strictly forbidden from setting '{to_status}'",
                },
            )
            raise LifecycleViolation(
                f"Actor type '{actor_type}' is strictly forbidden from setting status '{to_status}'. "
                f"Analyst action required."
            )

    def _validate_evidence_gate(
        self,
        finding: Finding,
        to_status: FindingStatus,
        actor_type: ActorType,
        reason: str,
        impact: Optional[str] = None,
    ) -> None:
        """Enforces minimum category evidence requirements for VERIFIED and FIXED."""
        if to_status == "VERIFIED":
            # 1. Analyst actor required
            if actor_type != "analyst":
                raise LifecycleViolation("VERIFIED status requires an 'analyst' actor.")
            if not reason or len(reason.strip()) < 5:
                raise LifecycleViolation("VERIFIED status requires an explicit decision reason from the analyst.")

            # 2. Pinned commit and build recorded
            if not finding.commit_sha or not finding.build_id:
                raise LifecycleViolation("VERIFIED status requires pinned commit_sha and build_id.")

            # 3. Scope ID recorded
            if not finding.scope_id:
                raise LifecycleViolation("VERIFIED status requires scope_id.")

            # 4. Impact written
            written_impact = impact or finding.impact
            if not written_impact or len(written_impact.strip()) < 5:
                raise LifecycleViolation("VERIFIED status requires documented business/security impact.")

            # 5. Hashed evidence artifact in DB
            evidence_records = self.evidence_mgr.list_evidence(finding.finding_id)
            if not evidence_records:
                raise LifecycleViolation(
                    f"VERIFIED status requires at least one cryptographically hashed evidence artifact in DB."
                )

            # 6. Category-specific gate checks
            cat = finding.category
            if cat == "sast":
                if not finding.file or not finding.line_start or not finding.rule_id:
                    raise LifecycleViolation("SAST evidence gate requires file, line_start, and rule_id.")
            elif cat == "sca":
                if not finding.package or not finding.package_version:
                    raise LifecycleViolation("SCA evidence gate requires package name and version.")
            elif cat == "secret":
                if not finding.file or not finding.commit_sha:
                    raise LifecycleViolation("Secret evidence gate requires file and commit location.")
            elif cat == "dast_io":
                if not finding.endpoint or not finding.method:
                    raise LifecycleViolation("DAST evidence gate requires approved endpoint and method.")
            elif cat == "authorization":
                if not written_impact:
                    raise LifecycleViolation("Authorization evidence gate requires written impact analysis.")

        elif to_status == "FIXED":
            if actor_type != "analyst":
                raise LifecycleViolation("FIXED status requires an 'analyst' actor review.")
            # Check retests table for passing retest
            with self.db.get_connection() as conn:
                retest_row = conn.execute(
                    "SELECT outcome FROM retests WHERE finding_id = ? ORDER BY timestamp DESC LIMIT 1",
                    (finding.finding_id,),
                ).fetchone()
                if not retest_row or retest_row["outcome"] != "FIXED":
                    raise LifecycleViolation(
                        "FIXED status requires an exact recipe retest run with outcome 'FIXED'."
                    )

    def transition(
        self,
        finding_id: str,
        to_status: FindingStatus,
        actor_type: ActorType,
        actor_id: str,
        reason: str,
        impact: Optional[str] = None,
    ) -> Finding:
        """
        Executes a validated state transition.
        Records an append-only entry in state_transitions and updates findings table.
        """
        finding = self.get_finding(finding_id)
        if not finding:
            raise LifecycleViolation(f"Finding '{finding_id}' not found.")

        current_status = finding.status

        # Verify transition is allowed in state graph
        allowed = ALLOWED_TRANSITIONS.get(current_status, [])
        if to_status not in allowed:
            raise LifecycleViolation(
                f"Illegal state transition from '{current_status}' to '{to_status}'. Allowed: {allowed}"
            )

        # Actor permission check
        self._validate_actor_permissions(to_status, actor_type, finding_id)

        # Evidence gate check
        self._validate_evidence_gate(finding, to_status, actor_type, reason, impact=impact)

        now = datetime.now(timezone.utc).isoformat()
        finding.status = to_status
        finding.updated_at = now
        if impact:
            finding.impact = impact

        # Update findings table
        with self.db.get_connection() as conn:
            conn.execute(
                """
                UPDATE findings
                SET status = ?, data_json = ?, updated_at = ?
                WHERE finding_id = ?
                """,
                (to_status, json.dumps(finding.model_dump()), now, finding_id),
            )

        # Record append-only transition
        self.db.record_transition(
            finding_id=finding_id,
            from_status=current_status,
            to_status=to_status,
            actor_type=actor_type,
            actor_id=actor_id,
            reason=reason,
        )

        # Log audit event
        self.db.log_audit_event(
            event_type="state_transition",
            actor_type=actor_type,
            actor_id=actor_id,
            payload={
                "finding_id": finding_id,
                "from_status": current_status,
                "to_status": to_status,
                "reason": reason,
            },
        )

        return finding
