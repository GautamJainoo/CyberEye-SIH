"""
Gitleaks Secret Scanner Adapter for WMSA.
Enforces --redact, zero secret persistence, salted fingerprinting, and helper redact().
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil

from wmsa.paths import get_base_dir

from wmsa.adapters.base import (
    find_binary,
    CandidateFinding,
    PreflightResult,
    RawRun,
    compute_file_sha256,
)

# Common regex patterns for tokens, keys, and credentials
SECRET_REDACT_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|secret|token|password|auth|jwt)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{8,})['\"]?"),
    re.compile(r"(?i)bearer\s+([a-zA-Z0-9_\-\.]{8,})"),
    re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    re.compile(r"github_pat_[a-zA-Z0-9_]{82}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"sk-[a-zA-Z0-9]{20,T3BlbkFJ[a-zA-Z0-9]{20,}"),
    re.compile(r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"),
]


def redact(text: str) -> str:
    """Redacts secrets and sensitive credentials from strings."""
    if not text:
        return text
    redacted = text
    for pattern in SECRET_REDACT_PATTERNS:
        def _repl(match):
            full = match.group(0)
            if len(match.groups()) > 1:
                secret_part = match.group(2)
                return full.replace(secret_part, "[REDACTED_SECRET]")
            return "[REDACTED_SECRET]"
        redacted = pattern.sub(_repl, redacted)
    return redacted


def compute_salted_secret_fingerprint(secret_value: str, salt: str = "wmsa-secret-salt-v1") -> str:
    """Computes a one-way salted hash so duplicate occurrences collapse without storing the secret."""
    combined = f"{salt}:{secret_value}".encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


class GitleaksAdapter:
    name: str = "gitleaks"

    def __init__(self, binary_path: Optional[str] = None):
        self.binary_path = binary_path or find_binary("gitleaks") or "gitleaks"

    def version(self) -> str:
        try:
            res = subprocess.run([self.binary_path, "version"], capture_output=True, text=True, check=True)
            return res.stdout.strip()
        except Exception:
            return "unknown"

    def preflight(self, target_path: Path) -> PreflightResult:
        binary_exists = shutil.which(self.binary_path) is not None
        v = self.version() if binary_exists else "not installed"
        target_ok = target_path.exists() and (target_path / ".git").exists()
        return PreflightResult(
            tool_name=self.name,
            tool_present=binary_exists,
            tool_version=v,
            target_accessible=target_ok,
            in_scope=True,
            message="Gitleaks ready" if binary_exists and target_ok else "Gitleaks preflight failed",
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
        report_file = output_dir / f"gitleaks_raw_{commit_sha[:8]}.json"

        config_path = get_base_dir() / "rules" / "gitleaks" / "worldmonitor.toml"
        cmd = [
            self.binary_path,
            "detect",
            f"--source={target_path}",
            "--redact",
            "--report-format=json",
            f"--report-path={report_file}",
            "--log-level=warn",
            "--no-git",
        ]
        if config_path.exists():
            cmd.append(f"--config={config_path}")

        start_time = datetime.now(timezone.utc).isoformat()
        t0 = time.time()

        if not shutil.which(self.binary_path):
            raise RuntimeError(
                "gitleaks binary not found; install the version pinned in tools.lock.json "
                "(no simulated fallback scan is performed)"
            )

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Measure peak RAM
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

        # If no leaks found, Gitleaks might not create an empty file
        if not report_file.exists():
            with open(report_file, "w", encoding="utf-8") as f:
                f.write("[]")

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
                leaks = json.load(f)
            except json.JSONDecodeError:
                return []

        findings: List[CandidateFinding] = []
        if not isinstance(leaks, list):
            return findings

        for item in leaks:
            rule_id = item.get("RuleID", "generic-secret")
            desc = item.get("Description", "Potential secret detected in repository")
            file_rel = item.get("File", "")
            line_start = item.get("StartLine")
            line_end = item.get("EndLine")
            commit = item.get("Commit", commit_sha)
            entropy = item.get("Entropy", 0.0)

            # Extract raw secret string to compute salted fingerprint ONLY, NEVER STORE RAW VALUE
            secret_val = item.get("Secret", "") or item.get("Match", "")
            salted_fp = compute_salted_secret_fingerprint(secret_val) if secret_val else ""

            finding = CandidateFinding(
                title=f"Potential Secret: {desc} ({rule_id})",
                category="secret",
                status="CANDIDATE",  # STRICT: never above CANDIDATE
                severity="HIGH",
                confidence_label="UNVERIFIED",
                repo=repo,
                commit_sha=commit or commit_sha,
                build_id=build_id,
                scope_id=scope_id,
                tool=self.name,
                tool_version=raw.tool_version,
                rule_id=rule_id,
                file=file_rel,
                line_start=line_start,
                line_end=line_end,
                cwe=["CWE-798"],
                description=f"Gitleaks detected rule '{rule_id}' with entropy {entropy:.2f}. "
                            f"Location: {file_rel}:{line_start}. Salted fingerprint: {salted_fp[:16]}...",
                snippet_hash=salted_fp,
                raw_result_ref=f"{raw.raw_output_path}#{rule_id}:{file_rel}:{line_start}",
                remediation_proposal="Remove secret from git history, rotate credentials immediately, and migrate to environment variables.",
            )
            finding.compute_fingerprint()
            findings.append(finding)

        return findings
