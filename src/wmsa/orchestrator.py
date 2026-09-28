"""
Scan Orchestrator for WMSA.
Executes profiles ('lite', 'standard') with resource tracking, sequential tool runs,
and normalizer integration.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from wmsa.adapters.base import CandidateFinding, RawRun
from wmsa.adapters.gitleaks import GitleaksAdapter
from wmsa.adapters.osv import OSVScannerAdapter
from wmsa.adapters.probes import ProbesAdapter
from wmsa.adapters.semgrep import SemgrepAdapter
from wmsa.adapters.zap import ZAPAdapter
from wmsa.db import Database
from wmsa.normalize import Finding, Normalizer
from wmsa.scope import ScopeManifest, load_scope_manifest
from wmsa.target import TargetManager


class Orchestrator:
    """Orchestrates security scanners with resource tracking and database persistence."""

    def __init__(
        self,
        db: Optional[Database] = None,
        scope_manifest: Optional[ScopeManifest] = None,
        profiles_path: Optional[Path] = None,
        base_dir: Optional[Path] = None,
    ):
        self.base_dir = base_dir or Path.cwd()
        self.db = db or Database(self.base_dir / "wmsa.db")
        self.manifest = scope_manifest or load_scope_manifest(self.base_dir / "config" / "scope.yaml")
        self.profiles_path = profiles_path or (self.base_dir / "config" / "profiles.yaml")
        self.normalizer = Normalizer(self.db)
        self.target_mgr = TargetManager(self.base_dir, db=self.db, scope_manifest=self.manifest)

    def load_profile(self, profile_name: str = "lite") -> Dict[str, Any]:
        if not self.profiles_path.exists():
            return {"tools": ["gitleaks", "osv", "semgrep", "probes"], "enable_zap": False}
        with open(self.profiles_path, "r", encoding="utf-8") as fp:
            data = yaml.safe_load(fp)
        return data.get("profiles", {}).get(profile_name, {})

    def run_scan(
        self,
        profile_name: str = "lite",
        selected_tools: Optional[List[str]] = None,
        output_base_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """
        Executes an end-to-end security assessment scan.
        Tracks peak RAM, duration, raw output hashes, and stores normalized findings.
        """
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"
        start_time = datetime.now(timezone.utc).isoformat()
        t0 = time.time()

        profile = self.load_profile(profile_name)
        active_tools = selected_tools or profile.get("tools", ["gitleaks", "osv", "semgrep", "probes"])

        evidence_dir = output_base_dir or (self.base_dir / "evidence" / scan_id)
        evidence_dir.mkdir(parents=True, exist_ok=True)
        target_path = self.base_dir / self.manifest.local_path

        commit_sha = self.manifest.commit_sha
        build_id = f"build-{commit_sha[:8]}"

        # Initialize scan record in DB
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO scans (scan_id, profile, status, start_time, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (scan_id, profile_name, "RUNNING", start_time, start_time),
            )

        raw_runs: List[RawRun] = []
        all_candidates: List[CandidateFinding] = []

        # Tool mapping
        adapters: Dict[str, Any] = {
            "gitleaks": GitleaksAdapter(),
            "osv": OSVScannerAdapter(),
            "semgrep": SemgrepAdapter(),
            "zap": ZAPAdapter(scope_manifest=self.manifest, base_dir=self.base_dir),
            "probes": ProbesAdapter(scope_manifest=self.manifest, base_dir=self.base_dir),
        }

        custom_semgrep_dir = self.base_dir / "rules" / "semgrep" / "worldmonitor"

        for tool_name in active_tools:
            if tool_name not in adapters:
                continue
            adapter = adapters[tool_name]

            # Run adapter
            if tool_name == "semgrep":
                run = adapter.run(
                    target_path=target_path,
                    output_dir=evidence_dir,
                    commit_sha=commit_sha,
                    build_id=build_id,
                    scope_id=self.manifest.scope_id,
                    profile_config=profile,
                    custom_rules_dir=custom_semgrep_dir,
                )
            elif tool_name == "zap":
                run = adapter.run(
                    target_path=target_path,
                    output_dir=evidence_dir,
                    commit_sha=commit_sha,
                    build_id=build_id,
                    scope_id=self.manifest.scope_id,
                    profile_config=profile,
                )
            else:
                run = adapter.run(
                    target_path=target_path,
                    output_dir=evidence_dir,
                    commit_sha=commit_sha,
                    build_id=build_id,
                    scope_id=self.manifest.scope_id,
                    profile_config=profile,
                )

            raw_runs.append(run)

            # Record run in tool_runs table
            run_id = f"run-{uuid.uuid4().hex[:8]}"
            with self.db.get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO tool_runs (
                        run_id, scan_id, tool_name, tool_version, command_line,
                        exit_code, raw_output_path, raw_output_sha256, peak_ram_mb,
                        duration_seconds, created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        scan_id,
                        run.tool_name,
                        run.tool_version,
                        run.command_line,
                        run.exit_code,
                        run.raw_output_path,
                        run.raw_output_sha256,
                        run.peak_ram_mb,
                        run.duration_seconds,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )

            # Parse findings
            candidates = adapter.parse(run, target_path)
            all_candidates.extend(candidates)

        # Ingest and deduplicate findings into DB
        ingested = self.normalizer.ingest_findings(all_candidates)

        total_duration = time.time() - t0
        end_time = datetime.now(timezone.utc).isoformat()

        # Update scan status in DB
        metrics = {
            "duration_seconds": total_duration,
            "tools_executed": [r.tool_name for r in raw_runs],
            "total_candidates_found": len(all_candidates),
            "deduplicated_findings_count": len(ingested),
        }
        with self.db.get_connection() as conn:
            conn.execute(
                """
                UPDATE scans
                SET status = 'COMPLETED', end_time = ?, metrics_json = ?
                WHERE scan_id = ?
                """,
                (end_time, json.dumps(metrics), scan_id),
            )

        self.db.log_audit_event(
            event_type="scan_completed",
            actor_type="system",
            actor_id="wmsa_orchestrator",
            payload={"scan_id": scan_id, "profile": profile_name, "metrics": metrics},
        )

        return {
            "scan_id": scan_id,
            "profile": profile_name,
            "status": "COMPLETED",
            "duration_seconds": total_duration,
            "tool_runs": [r.model_dump() for r in raw_runs],
            "findings_count": len(ingested),
        }
