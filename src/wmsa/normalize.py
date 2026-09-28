"""
Normalization and Deduplication Engine for WMSA.
Converts multi-tool candidate findings into canonical Finding records with stable fingerprints.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

from wmsa.adapters.base import CandidateFinding, CategoryType
from wmsa.db import Database

FindingStatus = Literal[
    "CANDIDATE",
    "TRIAGED",
    "VERIFIED",
    "REJECTED",
    "NEEDS_REVIEW",
    "PATCH_PROPOSED",
    "PATCH_APPLIED",
    "RETEST_PENDING",
    "FIXED",
    "NOT_FIXED",
    "REGRESSION",
    "INCONCLUSIVE",
    "ACCEPTED_RISK",
    "CLOSED",
]


class FindingSourceRef(BaseModel):
    tool_name: str
    tool_version: Optional[str] = None
    rule_id: Optional[str] = None
    snippet_hash: Optional[str] = None
    raw_ref: Optional[str] = None


class Finding(BaseModel):
    schema_version: str = "1.0"
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    stable_fingerprint: str
    title: str
    category: CategoryType
    status: FindingStatus = "CANDIDATE"
    severity: str = "INFO"
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    severity_source: Optional[str] = None
    confidence_label: str = "UNVERIFIED"
    repo: str
    commit_sha: str
    build_id: str
    scope_id: str
    environment: str = "local-isolated"
    file: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None
    package: Optional[str] = None
    package_version: Optional[str] = None
    cwe: List[str] = Field(default_factory=list)
    cve: List[str] = Field(default_factory=list)
    ghsa: List[str] = Field(default_factory=list)
    kev_match: bool = False
    description: str
    impact: Optional[str] = None
    remediation_proposal: Optional[str] = None
    sources: List[FindingSourceRef] = Field(default_factory=list)
    evidence_refs: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def compute_stable_fingerprint(
    category: str,
    location: str,
    rule_or_cwe: str,
    package_id: str = "",
    salt: str = "wmsa-stable-salt-v1",
) -> str:
    """
    Computes a deterministic SHA-256 fingerprint for finding deduplication.
    (category, file or endpoint+method, cwe or rule family, package@version)
    """
    norm_cat = category.strip().lower()
    norm_loc = location.strip().lower()
    norm_rule = rule_or_cwe.strip().upper()
    norm_pkg = package_id.strip().lower()
    token = f"{norm_cat}|{norm_loc}|{norm_rule}|{norm_pkg}|{salt}"
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Normalizer:
    """Normalizes candidate findings and handles database deduplication."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()

    def normalize_candidate(self, cand: CandidateFinding) -> Finding:
        loc = cand.file or f"{cand.method or 'GET'}:{cand.endpoint or '/'}"
        rule_or_cwe = cand.cwe[0] if cand.cwe else cand.rule_id
        pkg = f"{cand.package or ''}@{cand.package_version or ''}"

        fp = cand.stable_fingerprint or compute_stable_fingerprint(
            category=cand.category,
            location=loc,
            rule_or_cwe=rule_or_cwe,
            package_id=pkg,
        )

        source_ref = FindingSourceRef(
            tool_name=cand.tool,
            tool_version=cand.tool_version,
            rule_id=cand.rule_id,
            snippet_hash=cand.snippet_hash,
            raw_ref=cand.raw_result_ref,
        )

        return Finding(
            finding_id=cand.finding_id,
            stable_fingerprint=fp,
            title=cand.title,
            category=cand.category,
            status="CANDIDATE",
            severity=cand.severity,
            cvss_score=cand.cvss_score,
            cvss_vector=cand.cvss_vector,
            severity_source=cand.severity_source,
            confidence_label=cand.confidence_label,
            repo=cand.repo,
            commit_sha=cand.commit_sha,
            build_id=cand.build_id,
            scope_id=cand.scope_id,
            file=cand.file,
            line_start=cand.line_start,
            line_end=cand.line_end,
            endpoint=cand.endpoint,
            method=cand.method,
            package=cand.package,
            package_version=cand.package_version,
            cwe=cand.cwe,
            cve=cand.cve,
            ghsa=cand.ghsa,
            kev_match=cand.kev_match,
            description=cand.description,
            remediation_proposal=cand.remediation_proposal,
            sources=[source_ref],
        )

    def ingest_findings(self, candidates: List[CandidateFinding]) -> List[Finding]:
        """
        Deduplicates candidate findings by stable fingerprint against existing database records.
        Preserves original tool references in finding_sources.
        """
        results: List[Finding] = []
        now = datetime.now(timezone.utc).isoformat()

        with self.db.get_connection() as conn:
            for cand in candidates:
                norm_finding = self.normalize_candidate(cand)
                fp = norm_finding.stable_fingerprint

                # Check if fingerprint already exists
                row = conn.execute(
                    "SELECT finding_id, status, data_json FROM findings WHERE stable_fingerprint = ?",
                    (fp,),
                ).fetchone()

                if row:
                    existing_id = row["finding_id"]
                    existing_data = json.loads(row["data_json"])
                    existing_sources = existing_data.get("sources", [])
                    new_source = norm_finding.sources[0].model_dump()

                    # Add new source if not already present
                    if not any(
                        s.get("tool_name") == new_source["tool_name"]
                        and s.get("rule_id") == new_source["rule_id"]
                        for s in existing_sources
                    ):
                        existing_sources.append(new_source)
                        existing_data["sources"] = existing_sources
                        existing_data["updated_at"] = now
                        conn.execute(
                            "UPDATE findings SET data_json = ?, updated_at = ? WHERE finding_id = ?",
                            (json.dumps(existing_data), now, existing_id),
                        )

                    # Insert source link into finding_sources table
                    conn.execute(
                        """
                        INSERT INTO finding_sources (finding_id, tool_name, tool_version, rule_id, snippet_hash, raw_ref, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            existing_id,
                            new_source["tool_name"],
                            new_source.get("tool_version"),
                            new_source.get("rule_id"),
                            new_source.get("snippet_hash"),
                            new_source.get("raw_ref"),
                            now,
                        ),
                    )
                    norm_finding.finding_id = existing_id
                    norm_finding.status = row["status"]
                    results.append(norm_finding)
                else:
                    # New finding
                    finding_dict = norm_finding.model_dump()
                    conn.execute(
                        """
                        INSERT INTO findings (
                            finding_id, stable_fingerprint, title, category, status,
                            severity, cvss_score, repo, commit_sha, build_id, scope_id,
                            data_json, created_at, updated_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            norm_finding.finding_id,
                            fp,
                            norm_finding.title,
                            norm_finding.category,
                            norm_finding.status,
                            norm_finding.severity,
                            norm_finding.cvss_score,
                            norm_finding.repo,
                            norm_finding.commit_sha,
                            norm_finding.build_id,
                            norm_finding.scope_id,
                            json.dumps(finding_dict),
                            now,
                            now,
                        ),
                    )

                    new_source = norm_finding.sources[0]
                    conn.execute(
                        """
                        INSERT INTO finding_sources (finding_id, tool_name, tool_version, rule_id, snippet_hash, raw_ref, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            norm_finding.finding_id,
                            new_source.tool_name,
                            new_source.tool_version,
                            new_source.rule_id,
                            new_source.snippet_hash,
                            new_source.raw_ref,
                            now,
                        ),
                    )
                    results.append(norm_finding)

        return results
