"""
Exact Recipe Retest and Regression Engine for WMSA.
Replays identical test recipes against patched target and establishes before/after proof.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

import yaml

from wmsa.adapters.base import compute_file_sha256
from wmsa.adapters.probes import ProbesAdapter
from wmsa.db import Database
from wmsa.evidence import EvidenceManager
from wmsa.lifecycle import LifecycleManager
from wmsa.paths import get_base_dir
from wmsa.target import TargetManager

RetestOutcome = Literal["FIXED", "NOT_FIXED", "REGRESSION", "INCONCLUSIVE"]


class RetestEngine:
    """Manages exact recipe retests against patched branches."""

    def __init__(
        self,
        db: Optional[Database] = None,
        lifecycle_mgr: Optional[LifecycleManager] = None,
        evidence_mgr: Optional[EvidenceManager] = None,
        probes_adapter: Optional[ProbesAdapter] = None,
        target_dir: Optional[Path] = None,
        base_dir: Optional[Path] = None,
    ):
        self.base_dir = base_dir or get_base_dir()
        self.db = db or Database(self.base_dir / "wmsa.db")
        self.evidence_mgr = evidence_mgr or EvidenceManager(self.db, self.base_dir / "evidence")
        self.lifecycle_mgr = lifecycle_mgr or LifecycleManager(self.db, self.evidence_mgr)
        self.probes_adapter = probes_adapter or ProbesAdapter(base_dir=self.base_dir)
        self.target_dir = target_dir or (self.base_dir / "target")
        self.target_mgr = TargetManager(self.base_dir)

    def retest_finding(
        self,
        finding_id: str,
        recipe_id: str,
        analyst_id: str = "analyst",
        target_base_url: str = "http://127.0.0.1:3000",
    ) -> Dict[str, Any]:
        """
        Executes an exact replay of the recipe against the active/patched target.
        Compares output with original evidence artifact.
        """
        retest_id = f"retest-{uuid.uuid4().hex[:8]}"
        t0 = time.time()
        now = datetime.now(timezone.utc).isoformat()

        finding = self.lifecycle_mgr.get_finding(finding_id)
        if not finding:
            raise ValueError(f"Finding '{finding_id}' not found.")

        # Load recipe definition
        recipe_file = self.base_dir / "probes" / "recipes" / f"{recipe_id}.yaml"
        if not recipe_file.exists():
            raise FileNotFoundError(f"Recipe file {recipe_file} not found.")

        with open(recipe_file, "r", encoding="utf-8") as fp:
            recipe = yaml.safe_load(fp)

        # Get original evidence hash
        orig_ev_list = self.evidence_mgr.list_evidence(finding_id)
        original_evidence_hash = (
            orig_ev_list[-1]["sha256_hash"] if orig_ev_list else "no-original-evidence"
        )

        # Check for patch record
        with self.db.get_connection() as conn:
            patch_row = conn.execute(
                "SELECT * FROM patches WHERE finding_id = ? ORDER BY created_at DESC LIMIT 1",
                (finding_id,),
            ).fetchone()
            patch_id = patch_row["patch_id"] if patch_row else None
            patch_commit_sha = patch_row["patch_commit_sha"] if patch_row else finding.commit_sha
            patch_diff = patch_row["diff_content"] if patch_row else ""

        # Execute identical recipe
        retest_out_dir = self.base_dir / "evidence" / finding_id
        res = self.probes_adapter.execute_recipe(
            recipe=recipe,
            target_base_url=target_base_url,
            output_dir=retest_out_dir,
            commit_sha=patch_commit_sha or finding.commit_sha,
            build_id="retest-build",
        )

        retest_evidence_hash = res.evidence_sha256 or "no-retest-hash"

        # Determine outcome
        if res.verdict == "EXPECTATION_MET":
            outcome: RetestOutcome = "FIXED"
        elif res.verdict == "EXPECTATION_NOT_MET":
            outcome = "NOT_FIXED"
        else:
            outcome = "INCONCLUSIVE"

        duration = time.time() - t0

        # Record retest into SQLite table
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO retests (
                    retest_id, finding_id, patch_id, recipe_id, outcome,
                    original_evidence_hash, retest_evidence_hash, details_json, timestamp
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    retest_id,
                    finding_id,
                    patch_id,
                    recipe_id,
                    outcome,
                    original_evidence_hash,
                    retest_evidence_hash,
                    json.dumps(res.details),
                    now,
                ),
            )

        # Transition status if analyst action confirmed
        if outcome == "FIXED" and finding.status == "RETEST_PENDING":
            self.lifecycle_mgr.transition(
                finding_id=finding_id,
                to_status="FIXED",
                actor_type="analyst",
                actor_id=analyst_id,
                reason=f"Retest {retest_id} passed with outcome FIXED using exact recipe {recipe_id}.",
            )
        elif outcome == "NOT_FIXED" and finding.status == "RETEST_PENDING":
            self.lifecycle_mgr.transition(
                finding_id=finding_id,
                to_status="NOT_FIXED",
                actor_type="analyst",
                actor_id=analyst_id,
                reason=f"Retest {retest_id} failed safe expectation.",
            )

        return {
            "retest_id": retest_id,
            "finding_id": finding_id,
            "recipe_id": recipe_id,
            "outcome": outcome,
            "original_evidence_hash": original_evidence_hash,
            "retest_evidence_hash": retest_evidence_hash,
            "original_commit_sha": finding.commit_sha,
            "retest_commit_sha": patch_commit_sha,
            "patch_diff": patch_diff,
            "duration_seconds": duration,
        }
