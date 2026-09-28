"""
OWASP ZAP DAST Adapter for WMSA.
Executes scoped Automation Framework plans within Docker isolation on loopback.
Applies health-check gating and applicability filtering; emits CANDIDATE findings only.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import jinja2

from wmsa.adapters.base import (
    CandidateFinding,
    PreflightResult,
    RawRun,
    compute_file_sha256,
)
from wmsa.scope import ScopeGuard, ScopeManifest, load_scope_manifest
from wmsa.target import TargetManager


class ZAPAdapter:
    name: str = "zap"

    def __init__(
        self,
        template_path: Optional[Path] = None,
        scope_manifest: Optional[ScopeManifest] = None,
        base_dir: Optional[Path] = None,
        docker_image: str = "zaproxy/zap-stable:latest",
    ):
        self.base_dir = base_dir or Path.cwd()
        self.template_path = template_path or (self.base_dir / "rules" / "zap" / "plan.template.yaml")
        self.manifest = scope_manifest or load_scope_manifest(self.base_dir / "config" / "scope.yaml")
        self.docker_image = docker_image
        self.target_mgr = TargetManager(self.base_dir, scope_manifest=self.manifest)

    def version(self) -> str:
        return "stable-docker"

    def preflight(self, target_path: Path, target_base_url: str = "http://127.0.0.1:3000") -> PreflightResult:
        # Check docker availability
        docker_present = shutil.which("docker") is not None
        if not docker_present:
            return PreflightResult(
                tool_name=self.name,
                tool_present=False,
                tool_version=self.version(),
                target_accessible=False,
                in_scope=True,
                message="Docker not found on system",
            )

        # Non-negotiable: Target health check gates every DAST run
        healthy, msg = self.target_mgr.check_health(target_base_url)
        if not healthy:
            return PreflightResult(
                tool_name=self.name,
                tool_present=True,
                tool_version=self.version(),
                target_accessible=False,
                in_scope=True,
                message="SKIPPED (target unavailable)",
            )

        return PreflightResult(
            tool_name=self.name,
            tool_present=True,
            tool_version=self.version(),
            target_accessible=True,
            in_scope=True,
            message="ZAP and target ready",
        )

    def generate_plan(
        self,
        target_host: str,
        target_port: int,
        report_filename: str,
        profile_config: Dict[str, Any],
    ) -> str:
        """Generates ZAP Automation Framework plan strictly constrained by ScopeManifest."""
        # Scope enforcement
        if target_host not in self.manifest.allowed_hosts:
            raise ValueError(f"Target host '{target_host}' violates scope manifest allowed_hosts.")
        if target_port not in self.manifest.allowed_ports:
            raise ValueError(f"Target port {target_port} violates scope manifest allowed_ports.")

        with open(self.template_path, "r", encoding="utf-8") as fp:
            tmpl_str = fp.read()

        zap_cfg = profile_config.get("zap", {})
        spider_mins = zap_cfg.get("max_spider_duration_mins", 2)
        spider_depth = zap_cfg.get("max_spider_depth", 2)
        scan_mins = zap_cfg.get("max_scan_duration_mins", 5)
        rule_mins = zap_cfg.get("max_rule_duration_mins", 1)

        template = jinja2.Template(tmpl_str)
        rendered = template.render(
            TARGET_HOST=target_host,
            TARGET_PORT=target_port,
            ALLOWED_PREFIXES=self.manifest.allowed_route_prefixes,
            SPIDER_MAX_MINS=spider_mins,
            SPIDER_MAX_DEPTH=spider_depth,
            ACTIVE_SCAN_MAX_MINS=scan_mins,
            ACTIVE_RULE_MAX_MINS=rule_mins,
            REPORT_FILE=report_filename,
        )
        return rendered

    def run(
        self,
        target_path: Path,
        output_dir: Path,
        commit_sha: str,
        build_id: str,
        scope_id: str,
        profile_config: Dict[str, Any],
        target_host: str = "127.0.0.1",
        target_port: int = 3000,
    ) -> RawRun:
        output_dir.mkdir(parents=True, exist_ok=True)
        report_filename = f"zap_raw_{commit_sha[:8]}.json"
        report_path = output_dir / report_filename

        # First check health
        pre = self.preflight(target_path, f"http://{target_host}:{target_port}")
        start_time = datetime.now(timezone.utc).isoformat()

        if not pre.target_accessible:
            # Cleanly skip if target unavailable
            with open(report_path, "w", encoding="utf-8") as fp:
                json.dump({
                    "status": "SKIPPED",
                    "reason": "target unavailable",
                    "site": [],
                }, fp, indent=2)
            sha = compute_file_sha256(report_path)
            return RawRun(
                tool_name=self.name,
                tool_version=self.version(),
                command_line="zap (skipped - target unavailable)",
                start_time=start_time,
                end_time=datetime.now(timezone.utc).isoformat(),
                exit_code=0,
                raw_output_path=str(report_path),
                raw_output_sha256=sha,
                peak_ram_mb=0.0,
                duration_seconds=0.0,
            )

        # Generate scoped plan
        plan_content = self.generate_plan(target_host, target_port, report_filename, profile_config)
        plan_file = self.base_dir / "rules" / "zap" / "plan.active.yaml"
        plan_file.parent.mkdir(parents=True, exist_ok=True)
        with open(plan_file, "w", encoding="utf-8") as fp:
            fp.write(plan_content)

        # Docker execution
        cmd = [
            "docker", "run", "--rm",
            "--network=host",
            "-v", f"{plan_file.parent}:/zap/wrk:ro",
            "-v", f"{output_dir}:/zap/reports:rw",
            self.docker_image,
            "zap.sh", "-cmd", "-autorun", f"/zap/wrk/{plan_file.name}",
        ]

        t0 = time.time()
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            exit_code = res.returncode
        except Exception as e:
            exit_code = 1

        duration = time.time() - t0
        end_time = datetime.now(timezone.utc).isoformat()

        if not report_path.exists():
            with open(report_path, "w", encoding="utf-8") as fp:
                json.dump({"site": []}, fp)

        sha = compute_file_sha256(report_path)

        return RawRun(
            tool_name=self.name,
            tool_version=self.version(),
            command_line=" ".join(cmd),
            start_time=start_time,
            end_time=end_time,
            exit_code=exit_code,
            raw_output_path=str(report_path),
            raw_output_sha256=sha,
            peak_ram_mb=120.0,
            duration_seconds=duration,
        )

    def parse(
        self,
        raw: RawRun,
        target_path: Path,
        repo: str = "https://github.com/koala73/worldmonitor",
        commit_sha: str = "",
        build_id: str = "",
        scope_id: str = "worldmonitor-local-assessment-001",
    ) -> List[CandidateFinding]:
        report_path = Path(raw.raw_output_path)
        if not report_path.exists():
            return []

        with open(report_path, "r", encoding="utf-8") as fp:
            try:
                data = json.load(fp)
            except json.JSONDecodeError:
                return []

        findings: List[CandidateFinding] = []
        sites = data.get("site", [])
        if not isinstance(sites, list):
            sites = [sites]

        risk_map = {
            "0": "INFO",
            "1": "LOW",
            "2": "MEDIUM",
            "3": "HIGH",
            "4": "CRITICAL",
        }

        static_exts = (".png", ".jpg", ".jpeg", ".svg", ".css", ".ico", ".woff", ".woff2", ".js.map")

        for site in sites:
            alerts = site.get("alerts", [])
            for alert_item in alerts:
                plugin_id = alert_item.get("pluginid", "zap-alert")
                alert_name = alert_item.get("alert", "ZAP Runtime Alert")
                risk_code = str(alert_item.get("riskcode", "1"))
                severity = risk_map.get(risk_code, "LOW")
                cwe_id = f"CWE-{alert_item.get('cweid')}" if alert_item.get("cweid") else "CWE-699"
                desc = alert_item.get("desc", alert_name)
                solution = alert_item.get("solution", "")

                instances = alert_item.get("instances", [])
                for inst in instances:
                    uri = inst.get("uri", "")
                    method = inst.get("method", "GET")
                    param = inst.get("param", "")
                    evidence = inst.get("evidence", "")

                    # Applicability filter: skip injection alerts on static assets
                    if any(uri.lower().endswith(ext) for ext in static_exts):
                        continue

                    # Category determination
                    alert_lower = alert_name.lower()
                    if any(w in alert_lower for w in ["header", "cookie", "cors", "tls", "cache", "clickjacking"]):
                        category = "configuration"
                    else:
                        category = "dast_io"

                    finding = CandidateFinding(
                        title=f"DAST: {alert_name}",
                        category=category,
                        status="CANDIDATE",  # STRICT: never above CANDIDATE
                        severity=severity,
                        confidence_label="UNVERIFIED",
                        repo=repo,
                        commit_sha=commit_sha,
                        build_id=build_id,
                        scope_id=scope_id,
                        tool=self.name,
                        tool_version=raw.tool_version,
                        rule_id=str(plugin_id),
                        endpoint=uri,
                        method=method,
                        cwe=[cwe_id] if cwe_id != "CWE-0" else [],
                        description=f"{desc}\n\nEndpoint: {method} {uri}\nParam: {param}\nEvidence: {evidence[:200]}",
                        raw_result_ref=f"{raw.raw_output_path}#{plugin_id}:{uri}",
                        remediation_proposal=solution or "Apply defense-in-depth headers or input validation.",
                    )
                    finding.compute_fingerprint()
                    findings.append(finding)

        return findings
