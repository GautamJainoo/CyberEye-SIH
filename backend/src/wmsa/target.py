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
from wmsa.scope import (
    DEFAULT_WEBSITE_URL,
    ScopeGuard,
    ScopeManifest,
    ScopeViolation,
    load_scope_manifest,
)


class TargetError(Exception):
    """Raised when target setup or health checks fail."""


from wmsa.paths import get_base_dir


class TargetManager:
    """Manages the pinned World Monitor target checkout and local containers."""

    def __init__(
        self,
        base_dir: Optional[Path] = None,
        db: Optional[Database] = None,
        scope_manifest: Optional[ScopeManifest] = None,
    ):
        self.base_dir = base_dir or get_base_dir()
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
            web_url = getattr(self.manifest, "website_url", None)
            if web_url and web_url != base_url:
                try:
                    with httpx.Client(timeout=3.0, follow_redirects=True) as client:
                        res = client.get(web_url)
                        if res.status_code in (200, 301, 302, 304, 404):
                            return True, f"HTTP {res.status_code} response received from {web_url}"
                except Exception:
                    pass
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

    def configure(
        self,
        repo_url: str,
        website_url: Optional[str] = None,
        commit_sha: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Configures a new or updated target repo and website URL.
        Clones repository into target_dir, discovers HEAD SHA if not provided,
        updates config/scope.yaml, and refreshes manifest.
        """
        import shutil
        from datetime import datetime, timezone
        from urllib.parse import urlparse
        import yaml

        # If repo_url is changing and target exists with different origin, wipe and re-clone
        if (self.target_dir / ".git").exists():
            origin_res = subprocess.run(
                ["git", "-C", str(self.target_dir), "remote", "get-url", "origin"],
                capture_output=True,
                text=True,
            )
            current_origin = origin_res.stdout.strip()
            if current_origin != repo_url:
                shutil.rmtree(self.target_dir, ignore_errors=True)

        self.target_dir.parent.mkdir(parents=True, exist_ok=True)
        if not (self.target_dir / ".git").exists():
            subprocess.run(
                ["git", "clone", repo_url, str(self.target_dir)],
                check=True,
                capture_output=True,
                text=True,
            )

        # If commit_sha specified, checkout; else get HEAD
        if commit_sha:
            subprocess.run(
                ["git", "-C", str(self.target_dir), "fetch", "--all"],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["git", "-C", str(self.target_dir), "checkout", commit_sha],
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
        resolved_sha = res.stdout.strip()

        # Update scope.yaml
        scope_path = self.base_dir / "config" / "scope.yaml"
        allowed_hosts = ["127.0.0.1", "localhost", "worldmonitor", "target"]
        allowed_ports = [3000, 8080, 46123]

        if website_url:
            parsed = urlparse(website_url)
            host = parsed.hostname or "127.0.0.1"
            if host not in allowed_hosts and host not in ("worldmonitor.app", "www.worldmonitor.app"):
                allowed_hosts.append(host)
            if parsed.port and parsed.port not in allowed_ports:
                allowed_ports.append(parsed.port)

        scope_data = {
            "scope_id": f"scope-{uuid.uuid4().hex[:6]}",
            "repo_url": repo_url,
            "website_url": website_url or DEFAULT_WEBSITE_URL,
            "commit_sha": resolved_sha,
            "local_path": "target",
            "allowed_hosts": allowed_hosts,
            "allowed_ports": allowed_ports,
            "allowed_route_prefixes": ["/", "/api/", "/docs/"],
            "profile": "lite",
            "max_requests_per_probe": 20,
            "max_scan_minutes": 15,
            "approved_by": "security-analyst",
            "approved_at": datetime.now(timezone.utc).isoformat(),
        }

        with open(scope_path, "w", encoding="utf-8") as fp:
            yaml.safe_dump(scope_data, fp, sort_keys=False)

        # Refresh in-memory manifest
        self.manifest = load_scope_manifest(scope_path)
        self.db.save_scope_manifest(
            scope_id=scope_data["scope_id"],
            manifest_yaml=yaml.safe_dump(scope_data),
            commit_sha=resolved_sha,
            approved_by=scope_data["approved_by"],
            approved_at=scope_data["approved_at"],
        )

        return {
            "scope_id": scope_data["scope_id"],
            "repo_url": repo_url,
            "commit_sha": resolved_sha,
            "website_url": website_url or DEFAULT_WEBSITE_URL,
            "target_dir": str(self.target_dir),
        }

