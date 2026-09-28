"""
Patch Management and Isolated Git Branching Engine for WMSA.
Creates branches 'assess/<finding-id>', applies diffs, and records patch commits.
Never auto-merges into main branch.
"""

from __future__ import annotations

import json
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from wmsa.db import Database
from wmsa.lifecycle import LifecycleManager


class PatchError(Exception):
    """Raised when patch application fails."""


class PatchManager:
    """Manages patch proposals and git branch applications in target repository."""

    def __init__(
        self,
        db: Optional[Database] = None,
        lifecycle_mgr: Optional[LifecycleManager] = None,
        target_dir: Optional[Path] = None,
    ):
        self.db = db or Database()
        self.lifecycle_mgr = lifecycle_mgr or LifecycleManager(self.db)
        self.target_dir = target_dir or (Path.cwd() / "target")

    def propose_patch(
        self,
        finding_id: str,
        diff_content: str,
        created_by: str = "analyst",
    ) -> Dict[str, Any]:
        """Records a proposed patch diff and updates finding state."""
        patch_id = f"patch-{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc).isoformat()
        branch_name = f"assess/{finding_id[:8]}"

        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO patches (patch_id, finding_id, branch_name, diff_content, created_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (patch_id, finding_id, branch_name, diff_content, created_by, now),
            )

        # Transition status to PATCH_PROPOSED if currently VERIFIED
        finding = self.lifecycle_mgr.get_finding(finding_id)
        if finding and finding.status == "VERIFIED":
            self.lifecycle_mgr.transition(
                finding_id=finding_id,
                to_status="PATCH_PROPOSED",
                actor_type="analyst" if created_by != "llm" else "analyst",
                actor_id=created_by,
                reason=f"Patch proposal {patch_id} created for branch {branch_name}",
            )

        return {
            "patch_id": patch_id,
            "finding_id": finding_id,
            "branch_name": branch_name,
            "diff_content": diff_content,
            "created_at": now,
        }

    def apply_patch(
        self,
        finding_id: str,
        patch_id: str,
        commit_message: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Creates an isolated branch 'assess/<finding-id>' in target repository,
        applies the unified diff, and commits.
        """
        with self.db.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM patches WHERE patch_id = ? AND finding_id = ?",
                (patch_id, finding_id),
            ).fetchone()
            if not row:
                raise PatchError(f"Patch '{patch_id}' not found for finding '{finding_id}'.")
            diff_content = row["diff_content"]
            branch_name = row["branch_name"]

        if not self.target_dir.exists() or not (self.target_dir / ".git").exists():
            raise PatchError(f"Target repository {self.target_dir} not initialized.")

        # Create isolated branch
        try:
            subprocess.run(
                ["git", "-C", str(self.target_dir), "checkout", "-B", branch_name],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as e:
            raise PatchError(f"Failed to create branch {branch_name}: {e.stderr}")

        # Apply diff via git apply
        try:
            proc = subprocess.Popen(
                ["git", "-C", str(self.target_dir), "apply", "--whitespace=fix", "-"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = proc.communicate(input=diff_content)
            if proc.returncode != 0:
                raise PatchError(f"git apply failed: {stderr}")
        except Exception as e:
            raise PatchError(f"Error executing git apply: {e}")

        # Commit patch to branch
        msg = commit_message or f"fix(security): resolve finding {finding_id[:8]}"
        try:
            subprocess.run(
                ["git", "-C", str(self.target_dir), "add", "-A"],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["git", "-C", str(self.target_dir), "commit", "-m", msg],
                check=True,
                capture_output=True,
                text=True,
            )
            res = subprocess.run(
                ["git", "-C", str(self.target_dir), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            )
            patch_commit_sha = res.stdout.strip()
        except subprocess.CalledProcessError as e:
            raise PatchError(f"Failed to commit patch: {e.stderr}")

        # Record patch commit sha
        with self.db.get_connection() as conn:
            conn.execute(
                "UPDATE patches SET patch_commit_sha = ? WHERE patch_id = ?",
                (patch_commit_sha, patch_id),
            )

        # Transition status to PATCH_APPLIED and then RETEST_PENDING
        finding = self.lifecycle_mgr.get_finding(finding_id)
        if finding and finding.status == "PATCH_PROPOSED":
            self.lifecycle_mgr.transition(
                finding_id=finding_id,
                to_status="PATCH_APPLIED",
                actor_type="analyst",
                actor_id="analyst",
                reason=f"Patch applied to branch {branch_name} at commit {patch_commit_sha[:8]}",
            )
            self.lifecycle_mgr.transition(
                finding_id=finding_id,
                to_status="RETEST_PENDING",
                actor_type="system",
                actor_id="wmsa_patcher",
                reason="Ready for exact recipe retest",
            )

        return {
            "patch_id": patch_id,
            "finding_id": finding_id,
            "branch_name": branch_name,
            "patch_commit_sha": patch_commit_sha,
            "status": "RETEST_PENDING",
        }
