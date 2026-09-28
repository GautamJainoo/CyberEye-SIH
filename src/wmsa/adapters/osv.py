"""
OSV-Scanner SCA Adapter for WMSA.
Detects dependencies, parses lockfiles, extracts OSV/GHSA/CVE advisories, and links KEV.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import psutil

from wmsa.adapters.base import (
    CandidateFinding,
    PreflightResult,
    RawRun,
    compute_file_sha256,
)


class OSVScannerAdapter:
    name: str = "osv-scanner"

    def __init__(self, binary_path: Optional[str] = None):
        self.binary_path = binary_path or shutil.which("osv-scanner") or "osv-scanner"

    def version(self) -> str:
        try:
            res = subprocess.run([self.binary_path, "--version"], capture_output=True, text=True, check=True)
            lines = res.stdout.strip().splitlines()
            return lines[0].replace("osv-scanner version:", "").strip() if lines else "unknown"
        except Exception:
            return "unknown"

    def preflight(self, target_path: Path) -> PreflightResult:
        binary_exists = shutil.which(self.binary_path) is not None
        v = self.version() if binary_exists else "not installed"
        lockfiles = list(target_path.glob("**/package-lock.json")) + list(target_path.glob("**/yarn.lock")) + list(target_path.glob("**/pnpm-lock.yaml"))
        target_ok = target_path.exists() and len(lockfiles) > 0
        return PreflightResult(
            tool_name=self.name,
            tool_present=binary_exists,
            tool_version=v,
            target_accessible=target_ok,
            in_scope=True,
            message=f"OSV-Scanner ready (found {len(lockfiles)} lockfiles)" if binary_exists and target_ok else "OSV-Scanner preflight failed",
        )

    def run(
        self,
        target_path: Path,
        output_dir: Path,
        commit_sha: str,
        build_id: str,
        scope_id: str,
        profile_config: Dict[str, Any],
    ) -> RawRun:
        output_dir.mkdir(parents=True, exist_ok=True)
        report_file = output_dir / f"osv_raw_{commit_sha[:8]}.json"

        cmd = [
            self.binary_path,
            "scan",
            "source",
            "--no-ignore",
            "-r",
            str(target_path),
            "--format=json",
            f"--output-file={report_file}",
        ]

        start_time = datetime.now(timezone.utc).isoformat()
        t0 = time.time()

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
        known_kev_cves: Optional[Set[str]] = None,
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
        kev_set = known_kev_cves or set()

        for res in results:
            source_path = res.get("source", {}).get("path", "")
            # relative path from target
            rel_file = source_path
            try:
                rel_file = str(Path(source_path).relative_to(target_path))
            except ValueError:
                pass

            packages = res.get("packages", [])
            for pkg_wrapper in packages:
                pkg = pkg_wrapper.get("package", {})
                pkg_name = pkg.get("name", "unknown")
                pkg_version = pkg.get("version", "unknown")
                ecosystem = pkg.get("ecosystem", "npm")

                vulnerabilities = pkg_wrapper.get("vulnerabilities", [])
                for vuln in vulnerabilities:
                    vuln_id = vuln.get("id", "")
                    summary = vuln.get("summary", "") or f"Vulnerability in {pkg_name}"
                    aliases = vuln.get("aliases", [])

                    cve_ids = [a for a in aliases if a.startswith("CVE-")]
                    if vuln_id.startswith("CVE-") and vuln_id not in cve_ids:
                        cve_ids.append(vuln_id)

                    ghsa_ids = [a for a in aliases if a.startswith("GHSA-")]
                    if vuln_id.startswith("GHSA-") and vuln_id not in ghsa_ids:
                        ghsa_ids.append(vuln_id)

                    # Check CISA KEV match
                    kev_matched = any(cve in kev_set for cve in cve_ids)

                    # Severity calculation from CVSS or database
                    severity_label = "MEDIUM"
                    cvss_score: Optional[float] = None
                    database_specific = vuln.get("database_specific", {})
                    if "severity" in database_specific:
                        raw_sev = str(database_specific["severity"]).upper()
                        if raw_sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                            severity_label = raw_sev

                    # Check fixed version if present in affected
                    fixed_versions = []
                    for affected in vuln.get("affected", []):
                        for r in affected.get("ranges", []):
                            for event in r.get("events", []):
                                if "fixed" in event:
                                    fixed_versions.append(event["fixed"])

                    remediation = (
                        f"Upgrade {pkg_name} to version {fixed_versions[0]} or later."
                        if fixed_versions
                        else f"Review dependency {pkg_name} advisory {vuln_id}."
                    )

                    finding = CandidateFinding(
                        title=f"SCA: {pkg_name}@{pkg_version} - {vuln_id}",
                        category="sca",
                        status="CANDIDATE",  # STRICT: never above CANDIDATE
                        severity=severity_label,
                        confidence_label="UNVERIFIED",
                        repo=repo,
                        commit_sha=commit_sha,
                        build_id=build_id,
                        scope_id=scope_id,
                        tool=self.name,
                        tool_version=raw.tool_version,
                        rule_id=vuln_id,
                        file=rel_file,
                        package=pkg_name,
                        package_version=pkg_version,
                        cve=cve_ids,
                        ghsa=ghsa_ids,
                        cvss_score=cvss_score,
                        kev_match=kev_matched,
                        description=(
                            f"{summary}\n\nPackage: {pkg_name}@{pkg_version} ({ecosystem})\n"
                            f"Manifest: {rel_file}\nAdvisory ID: {vuln_id}\n"
                            f"Aliases: {', '.join(aliases)}\nReachability: unknown"
                        ),
                        raw_result_ref=f"{raw.raw_output_path}#{vuln_id}",
                        remediation_proposal=remediation,
                    )
                    finding.compute_fingerprint()
                    findings.append(finding)

        return findings
