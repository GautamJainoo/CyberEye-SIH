"""
Semgrep SAST Adapter for WMSA.
Executes static analysis with --metrics=off and --json, computes snippet hashes, and maps to CANDIDATE.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil

from wmsa.adapters.base import (
    find_binary,
    CandidateFinding,
    PreflightResult,
    RawRun,
    compute_file_sha256,
)


class SemgrepAdapter:
    name: str = "semgrep"

    def __init__(self, binary_path: Optional[str] = None):
        self.binary_path = binary_path or find_binary("semgrep") or "semgrep"

    def version(self) -> str:
        try:
            res = subprocess.run([self.binary_path, "--version"], capture_output=True, text=True, check=True)
            lines = res.stdout.strip().splitlines()
            return lines[0].strip() if lines else "unknown"
        except Exception:
            return "unknown"

    def preflight(self, target_path: Path) -> PreflightResult:
        binary_exists = shutil.which(self.binary_path) is not None
        v = self.version() if binary_exists else "not installed"
        target_ok = target_path.exists()
        return PreflightResult(
            tool_name=self.name,
            tool_present=binary_exists,
            tool_version=v,
            target_accessible=target_ok,
            in_scope=True,
            message="Semgrep ready" if binary_exists and target_ok else "Semgrep preflight failed",
        )

    def run(
        self,
        target_path: Path,
        output_dir: Path,
        commit_sha: str,
        build_id: str,
        scope_id: str,
        profile_config: Dict[str, Any],
        custom_rules_dir: Optional[Path] = None,
    ) -> RawRun:
        output_dir.mkdir(parents=True, exist_ok=True)
        report_file = output_dir / f"semgrep_raw_{commit_sha[:8]}.json"

        # Construct semgrep command
        cmd = [
            self.binary_path,
            "scan",
            "--metrics=off",
            "--json",
            f"--output={report_file}",
            "--jobs=4",
            "--timeout=20",
            "--exclude=node_modules",
            "--exclude=dist",
            "--exclude=build",
            "--exclude=.git",
            "--exclude=.next",
            "--exclude=coverage",
            "--exclude=pro",
        ]

        if custom_rules_dir and custom_rules_dir.exists():
            cmd.append(f"--config={custom_rules_dir}")
        else:
            # When metrics are off, Semgrep requires explicit config rather than auto
            cmd.extend([
                "--config=p/typescript",
                "--config=p/javascript",
                "--config=p/owasp-top-ten",
            ])

        cmd.append(str(target_path))

        start_time = datetime.now(timezone.utc).isoformat()
        t0 = time.time()

        if not shutil.which(self.binary_path):
            raise RuntimeError(
                "semgrep binary not found; install the version pinned in tools.lock.json "
                "(no simulated fallback scan is performed)"
            )

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        peak_ram_mb = 0.0
        try:
            p = psutil.Process(proc.pid)
            while proc.poll() is None:
                try:
                    mem = p.memory_info().rss / (1024 * 1024)
                    if mem > peak_ram_mb:
                        peak_ram_mb = mem
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                time.sleep(0.05)
        except Exception:
            pass

        stdout, stderr = proc.communicate()
        duration = time.time() - t0
        end_time = datetime.now(timezone.utc).isoformat()

        if not report_file.exists():
            with open(report_file, "w", encoding="utf-8") as f:
                f.write('{"results": []}')

        file_sha = compute_file_sha256(report_file)

        return RawRun(
            tool_name=self.name,
            tool_version=self.version(),
            command_line=" ".join(cmd),
            start_time=start_time,
            end_time=end_time,
            exit_code=proc.returncode,
            raw_output_path=str(report_file),
            raw_output_sha256=file_sha,
            peak_ram_mb=peak_ram_mb,
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

        with open(report_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                return []

        findings: List[CandidateFinding] = []
        results = data.get("results", [])

        for res in results:
            check_id = res.get("check_id", "semgrep-rule")
            path = res.get("path", "")
            start = res.get("start", {})
            end = res.get("end", {})
            line_start = start.get("line")
            line_end = end.get("line")

            extra = res.get("extra", {})
            message = extra.get("message", "Semgrep security check flag")
            metadata = extra.get("metadata", {})
            raw_severity = extra.get("severity", "WARNING").upper()

            # Severity mapping
            sev_map = {
                "ERROR": "HIGH",
                "WARNING": "MEDIUM",
                "INFO": "LOW",
                "CRITICAL": "CRITICAL",
            }
            severity = sev_map.get(raw_severity, "MEDIUM")

            # Extract CWE / OWASP
            cwe_list = []
            raw_cwe = metadata.get("cwe")
            if isinstance(raw_cwe, list):
                cwe_list = [str(c) for c in raw_cwe]
            elif isinstance(raw_cwe, str):
                cwe_list = [raw_cwe]

            # Compute snippet hash if code snippet is available
            lines_snippet = extra.get("lines", "")
            snippet_hash = (
                hashlib.sha256(lines_snippet.encode("utf-8")).hexdigest()
                if lines_snippet
                else None
            )

            # File relative to target path
            rel_file = path
            try:
                rel_file = str(Path(path).relative_to(target_path))
            except ValueError:
                pass

            finding = CandidateFinding(
                title=f"SAST: {check_id}",
                category="sast",
                status="CANDIDATE",  # STRICT: never above CANDIDATE
                severity=severity,
                confidence_label="UNVERIFIED",
                repo=repo,
                commit_sha=commit_sha,
                build_id=build_id,
                scope_id=scope_id,
                tool=self.name,
                tool_version=raw.tool_version,
                rule_id=check_id,
                file=rel_file,
                line_start=line_start,
                line_end=line_end,
                cwe=cwe_list,
                description=f"{message}\n\nRule: {check_id}\nFile: {rel_file}:{line_start}-{line_end}",
                snippet_hash=snippet_hash,
                raw_result_ref=f"{raw.raw_output_path}#{check_id}:{rel_file}:{line_start}",
                remediation_proposal=extra.get("fix", None),
            )
            finding.compute_fingerprint()
            findings.append(finding)

        return findings
