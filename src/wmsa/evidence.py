"""
Evidence Management and Cryptographic Hashing Engine for WMSA.
Collects, redacts, hashes, and stores evidence artifacts per finding.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from wmsa.adapters.base import compute_file_sha256
from wmsa.adapters.gitleaks import redact
from wmsa.db import Database


class EvidenceManager:
    """Manages sanitized evidence packets with SHA-256 verification."""

    def __init__(self, db: Optional[Database] = None, evidence_dir: Optional[Path] = None):
        self.db = db or Database()
        self.evidence_dir = evidence_dir or (Path.cwd() / "evidence")

    def create_evidence_artifact(
        self,
        finding_id: str,
        recipe_id: str,
        artifact_type: str,
        data: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Redacts sensitive tokens, saves evidence artifact JSON, computes SHA-256,
        and records in SQLite evidence table.
        """
        target_dir = self.evidence_dir / finding_id
        target_dir.mkdir(parents=True, exist_ok=True)

        now = datetime.now(timezone.utc).isoformat()
        evidence_id = f"ev-{uuid.uuid4().hex[:8]}"
        file_path = target_dir / f"{recipe_id}_{evidence_id}.json"

        # Apply deep redaction on data
        serialized = json.dumps(data)
        sanitized_str = redact(serialized)
        sanitized_data = json.loads(sanitized_str)

        packet = {
            "evidence_id": evidence_id,
            "finding_id": finding_id,
            "recipe_id": recipe_id,
            "artifact_type": artifact_type,
            "created_at": now,
            "metadata": metadata or {},
            "data": sanitized_data,
        }

        with open(file_path, "w", encoding="utf-8") as fp:
            json.dump(packet, fp, indent=2)

        file_sha = compute_file_sha256(file_path)

        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO evidence (evidence_id, finding_id, recipe_id, artifact_type, file_path, sha256_hash, metadata_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence_id,
                    finding_id,
                    recipe_id,
                    artifact_type,
                    str(file_path),
                    file_sha,
                    json.dumps(metadata or {}),
                    now,
                ),
            )

        return {
            "evidence_id": evidence_id,
            "finding_id": finding_id,
            "file_path": str(file_path),
            "sha256_hash": file_sha,
            "created_at": now,
        }

    def list_evidence(self, finding_id: str) -> List[Dict[str, Any]]:
        with self.db.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM evidence WHERE finding_id = ? ORDER BY created_at ASC",
                (finding_id,),
            ).fetchall()
            return [dict(r) for r in rows]
