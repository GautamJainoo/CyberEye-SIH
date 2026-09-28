"""
Target environment manager for World Monitor.
Handles pinned git checkout, commit verification, docker compose lifecycle, and health gate.
"""

from __future__ import annotations

import os
import subprocess
import uuid
from pathlib import Path
from typing import Dict, Optional, Tuple

import httpx

from wmsa.db import Database
from wmsa.scope import ScopeGuard, ScopeManifest, ScopeViolation, load_scope_manifest


class TargetError(Exception):
    """Raised when target setup or health checks fail."""


class TargetManager:
    """Manages the pinned World Monitor target checkout and local containers."""

    def __init__(
        self,
        base_dir: Optional[Path] = None,
        db: Optional[Database] = None,
        scope_manifest: Optional[ScopeManifest] = None,
    ):
        self.base_dir = base_dir or Path.cwd()
        self.db = db or Database(self.base_dir / "wmsa.db")
        self.manifest = scope_manifest or load_scope_manifest(self.base_dir / "config" / "scope.yaml")
        self.target_dir = self.base_dir / self.manifest.local_path

    def setup(self, force_clean: bool = False) -> Dict[str, str]:
        """
        Clones target repo if absent, fetches and checks out pinned commit_sha.
        Writes build metadata to DB.
        """
        repo_url = self.manifest.repo_url
        pinned_sha = self.manifest.commit_sha

        self.target_dir.parent.mkdir(parents=True, exist_ok=True)

        if not (self.target_dir / ".git").exists():
            print(f"Cloning {repo_url} into {self.target_dir}...")
            subprocess.run(
                ["git", "clone", repo_url, str(self.target_dir)],
                check=True,
                capture_output=True,
                text=True,
            )

        # Fetch latest and checkout pinned SHA
        subprocess.run(
            ["git", "-C", str(self.target_dir), "fetch", "--all"],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            ["git", "-C", str(self.target_dir), "checkout", pinned_sha],
            check=True,
            capture_output=True,
            text=True,
        )

        # Verify current commit
        res = subprocess.run(
            ["git", "-C", str(self.target_dir), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
        current_sha = res.stdout.strip()
        if not current_sha.startswith(pinned_sha) and not pinned_sha.startswith(current_sha):
            raise TargetError(
                f"Checkout commit mismatch! Expected {pinned_sha}, got {current_sha}."
            )

        build_id = f"build-{current_sha[:8]}-{uuid.uuid4().hex[:6]}"

        # Record in DB audit
        self.db.log_audit_event(
            event_type="target_setup",
            actor_type="system",
            actor_id="wmsa_cli",
            payload={
                "repo_url": repo_url,
                "commit_sha": current_sha,
                "build_id": build_id,
                "target_dir": str(self.target_dir),
            },
        )

        return {
            "status": "ready",
            "repo_url": repo_url,
            "commit_sha": current_sha,
            "build_id": build_id,
            "local_path": str(self.target_dir),
        }

    def verify_commit(self) -> str:
        """Returns the currently checked-out commit and verifies it matches pinned SHA."""
        if not (self.target_dir / ".git").exists():
            raise TargetError(f"Target directory {self.target_dir} is not initialized.")
        res = subprocess.run(
            ["git", "-C", str(self.target_dir), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
        current_sha = res.stdout.strip()
        pinned = self.manifest.commit_sha
        if not current_sha.startswith(pinned) and not pinned.startswith(current_sha):
            raise TargetError(
                f"Commit verification failed: target is at {current_sha}, expected {pinned}"
            )
        return current_sha

    def check_health(self, base_url: str = "http://127.0.0.1:3000") -> Tuple[bool, str]:
        """
        Health check gate. Every active probe/DAST run requires healthy target.
        Enforces scope guard check on base_url.
        """
        guard = ScopeGuard(self.manifest, self.base_dir)
        try:
            canonical = guard.guard(base_url)
        except Exception as e:
            return False, f"Scope guard error: {e}"

        try:
            with httpx.Client(timeout=3.0) as client:
                res = client.get(canonical)
                if res.status_code in (200, 301, 302, 304, 404):
                    # Service is responding on loopback
                    return True, f"HTTP {res.status_code} response received"
                return False, f"Unexpected response status {res.status_code}"
        except httpx.ConnectError:
            return False, "Connection refused (target is not running on loopback)"
        except Exception as e:
            return False, f"Health check failed: {e}"

    def up(self) -> str:
        """Starts isolated target via docker compose."""
        compose_file = self.base_dir / "docker" / "compose.target.yaml"
        if not compose_file.exists():
            raise TargetError(f"Compose file {compose_file} not found.")

        cmd = ["docker", "compose", "-f", str(compose_file), "up", "-d"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            raise TargetError(f"docker compose up failed: {res.stderr}")
        return res.stdout

    def down(self) -> str:
        """Stops target containers."""
        compose_file = self.base_dir / "docker" / "compose.target.yaml"
        cmd = ["docker", "compose", "-f", str(compose_file), "down"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        return res.stdout
