"""
Scan Orchestrator for WMSA.
Executes profiles ('lite', 'standard') with resource tracking, sequential tool runs,
and normalizer integration.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import yaml

from wmsa.adapters.base import CandidateFinding, RawRun
from wmsa.adapters.gemini_review import GeminiReviewAdapter
from wmsa.adapters.gitleaks import GitleaksAdapter
from wmsa.adapters.osv import OSVScannerAdapter
from wmsa.adapters.probes import ProbesAdapter
from wmsa.adapters.semgrep import SemgrepAdapter
from wmsa.adapters.zap import ZAPAdapter
from wmsa.db import Database
from wmsa.normalize import Finding, Normalizer
from wmsa.scope import ScopeManifest, load_scope_manifest
from wmsa.target import TargetManager


from wmsa.paths import get_base_dir


class Orchestrator:
    """Orchestrates security scanners with resource tracking and database persistence."""

    def __init__(
        self,
        db: Optional[Database] = None,
        scope_manifest: Optional[ScopeManifest] = None,
        profiles_path: Optional[Path] = None,
        base_dir: Optional[Path] = None,
    ):
        self.base_dir = base_dir or get_base_dir()
        self.db = db or Database(self.base_dir / "wmsa.db")
        self.manifest = scope_manifest or load_scope_manifest(self.base_dir / "config" / "scope.yaml")
        self.profiles_path = profiles_path or (self.base_dir / "config" / "profiles.yaml")
        self.normalizer = Normalizer(self.db)
        self.target_mgr = TargetManager(self.base_dir, db=self.db, scope_manifest=self.manifest)
        self.live_log: List[str] = []
        self._live_lock = threading.Lock()
        self.live: Dict[str, Any] = {
            "running": False,
            "scan_id": None,
            "current": "",
            "done": 0,
            "total": 0,
            "percent": 0,
        }

    def load_profile(self, profile_name: str = "lite") -> Dict[str, Any]:
        if not self.profiles_path.exists():
            return {"tools": ["review", "semgrep", "gitleaks", "osv", "probes"], "enable_zap": False}
        with open(self.profiles_path, "r", encoding="utf-8") as fp:
            data = yaml.safe_load(fp)
        return data.get("profiles", {}).get(profile_name, {})

    def run_scan(
        self,
        profile_name: str = "lite",
        selected_tools: Optional[List[str]] = None,
        output_base_dir: Optional[Path] = None,
        progress: Optional[Callable[[str, str, str], None]] = None,
        start_dynamic: Optional[threading.Event] = None,
    ) -> Dict[str, Any]:
        """
        Executes an end-to-end security assessment scan.
        Tracks peak RAM, duration, raw output hashes, and stores normalized findings.
        """
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"
        start_time = datetime.now(timezone.utc).isoformat()
        t0 = time.time()

        profile = self.load_profile(profile_name)
        active_tools = selected_tools or profile.get("tools", ["review", "semgrep", "gitleaks", "osv", "probes"])

        evidence_dir = output_base_dir or (self.base_dir / "evidence" / scan_id)
        evidence_dir.mkdir(parents=True, exist_ok=True)
        target_path = self.base_dir / self.manifest.local_path

        # Auto-setup target if not yet cloned
        if not target_path.exists() or not (target_path / ".git").exists():
            try:
                self.target_mgr.setup()
            except Exception:
                target_path.mkdir(parents=True, exist_ok=True)

        commit_sha = self.manifest.commit_sha
        build_id = f"build-{commit_sha[:8]}"

        selected_names = [t for t in active_tools if t in (
            "review", "gitleaks", "osv", "semgrep", "zap", "probes"
        )]
        with self._live_lock:
            self.live = {
                "running": True,
                "scan_id": scan_id,
                "current": "starting",
                "done": 0,
                "total": len(selected_names) or 1,
                "percent": 0,
            }
        self.live_log = [f"[scan {scan_id}] RUNNING tools: {', '.join(active_tools)}"]

        def emit(tool: str, status: str, detail: str) -> None:
            line = f"[{tool}] {status}" + (f": {detail}" if detail else "")
            with self._live_lock:
                self.live_log.append(line)
                if status == "running":
                    self.live["current"] = tool
                elif status in ("done", "failed"):
                    self.live["done"] = int(self.live["done"]) + 1
                    total = int(self.live["total"]) or 1
                    self.live["percent"] = min(99, round(100 * int(self.live["done"]) / total))
                    self.live["current"] = tool
            if progress:
                progress(tool, status, detail)

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
        tool_errors: Dict[str, str] = {}
        all_candidates: List[CandidateFinding] = []

        # Tool mapping
        adapters: Dict[str, Any] = {
            "review": GeminiReviewAdapter(base_dir=self.base_dir),
            "gitleaks": GitleaksAdapter(),
            "osv": OSVScannerAdapter(),
            "semgrep": SemgrepAdapter(),
            "zap": ZAPAdapter(scope_manifest=self.manifest, base_dir=self.base_dir),
            "probes": ProbesAdapter(scope_manifest=self.manifest, base_dir=self.base_dir),
        }

        custom_semgrep_dir = self.base_dir / "rules" / "semgrep" / "worldmonitor"

        dynamic_tools = {"zap", "probes"}

        def execute(tool_name: str):
            """Run + parse one tool. Thread-safe: touches no database."""
            if tool_name in dynamic_tools and start_dynamic is not None:
                start_dynamic.wait()
            adapter = adapters[tool_name]
            emit(tool_name, "running", "")
            kwargs = dict(
                target_path=target_path,
                output_dir=evidence_dir,
                commit_sha=commit_sha,
                build_id=build_id,
                scope_id=self.manifest.scope_id,
                profile_config=profile,
            )
            if tool_name == "semgrep":
                kwargs["custom_rules_dir"] = custom_semgrep_dir
            try:
                run = adapter.run(**kwargs)
                candidates = adapter.parse(run, target_path)
            except Exception as e:
                emit(tool_name, "failed", str(e)[:300])
                return tool_name, None, [], str(e)
            emit(tool_name, "done", f"{len(candidates)} candidate(s) in {run.duration_seconds:.0f}s")
            return tool_name, run, candidates, None

        # All scanners share one pool. ZAP and probes wait on start_dynamic when the
        # pipeline still has to boot the local target; static tools do not.
        selected = [t for t in active_tools if t in adapters]
        results: Dict[str, Any] = {}
        if selected:
            with ThreadPoolExecutor(max_workers=16) as pool:
                for res in pool.map(execute, selected):
                    results[res[0]] = res

        for tool_name in selected:  # keep the caller's tool order for recording
            _, run, candidates, error = results[tool_name]
            if error or run is None:
                tool_errors[tool_name] = error or "unknown error"
                continue
            raw_runs.append(run)
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
                        run_id, scan_id, run.tool_name, run.tool_version, run.command_line,
                        run.exit_code, run.raw_output_path, run.raw_output_sha256, run.peak_ram_mb,
                        run.duration_seconds, datetime.now(timezone.utc).isoformat(),
                    ),
                )
            all_candidates.extend(candidates)

        # Ingest and deduplicate findings into DB
        ingested = self.normalizer.ingest_findings(all_candidates)

        total_duration = time.time() - t0
        end_time = datetime.now(timezone.utc).isoformat()

        # Update scan status in DB
        metrics = {
            "duration_seconds": total_duration,
            "tools_executed": [r.tool_name for r in raw_runs],
            "tools_failed": tool_errors,
            "total_candidates_found": len(all_candidates),
            "deduplicated_findings_count": len(ingested),
        }
        with self.db.get_connection() as conn:
            conn.execute(
                """
                UPDATE scans
                SET status = ?, end_time = ?, metrics_json = ?
                WHERE scan_id = ?
                """,
                ("COMPLETED_WITH_ERRORS" if tool_errors else "COMPLETED", end_time, json.dumps(metrics), scan_id),
            )

        self.db.log_audit_event(
            event_type="scan_completed",
            actor_type="system",
            actor_id="wmsa_orchestrator",
            payload={"scan_id": scan_id, "profile": profile_name, "metrics": metrics},
        )

        with self._live_lock:
            self.live["running"] = False
            self.live["percent"] = 100
            self.live["current"] = "done"

        return {
            "scan_id": scan_id,
            "profile": profile_name,
            "status": "COMPLETED_WITH_ERRORS" if tool_errors else "COMPLETED",
            "tool_errors": tool_errors,
            "duration_seconds": total_duration,
            "tool_runs": [r.model_dump() for r in raw_runs],
            "findings_count": len(ingested),
        }
