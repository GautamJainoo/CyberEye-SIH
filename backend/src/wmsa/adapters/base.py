"""
Base Adapter interfaces and data contracts for WMSA.
Enforces that every adapter output is strictly a CANDIDATE.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Protocol

from pydantic import BaseModel, Field

CategoryType = Literal[
    "authorization",
    "dast_io",
    "sast",
    "sca",
    "secret",
    "configuration",
]


class PreflightResult(BaseModel):
    tool_name: str
    tool_present: bool
    tool_version: str
    target_accessible: bool
    in_scope: bool
    message: str


class RawRun(BaseModel):
    tool_name: str
    tool_version: str
    command_line: str
    start_time: str
    end_time: str
    exit_code: int
    raw_output_path: str
    raw_output_sha256: str
    peak_ram_mb: float = 0.0
    duration_seconds: float = 0.0


class CandidateFinding(BaseModel):
    schema_version: str = "1.0"
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    stable_fingerprint: str = ""
    title: str
    category: CategoryType
    status: Literal["CANDIDATE"] = "CANDIDATE"  # MUST NEVER BE ABOVE CANDIDATE
    severity: str = "INFO"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence_label: str = "UNVERIFIED"
    repo: str
    commit_sha: str
    build_id: str
    scope_id: str
    tool: str
    tool_version: str
    rule_id: str
    timestamp_utc: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    file: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None
    package: Optional[str] = None
    package_version: Optional[str] = None
    cwe: List[str] = Field(default_factory=list)
    cve: List[str] = Field(default_factory=list)
    ghsa: List[str] = Field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    severity_source: Optional[str] = None
    kev_match: bool = False
    description: str
    snippet_hash: Optional[str] = None
    raw_result_ref: Optional[str] = None
    remediation_proposal: Optional[str] = None

    def compute_fingerprint(self, salt: str = "wmsa-salt-2026") -> str:
        loc = self.file or f"{self.method or ''}:{self.endpoint or ''}"
        rule_or_cwe = self.cwe[0] if self.cwe else self.rule_id
        pkg = f"{self.package or ''}@{self.package_version or ''}"
        norm_tuple = f"{self.category}|{loc}|{rule_or_cwe}|{pkg}|{salt}"
        self.stable_fingerprint = hashlib.sha256(norm_tuple.encode("utf-8")).hexdigest()
        return self.stable_fingerprint


def compute_file_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


class ToolAdapter(Protocol):
    name: str

    def version(self) -> str: ...

    def preflight(self, target_path: Path) -> PreflightResult: ...

    def run(
        self,
        target_path: Path,
        output_dir: Path,
        commit_sha: str,
        build_id: str,
        scope_id: str,
        profile_config: Dict[str, Any],
    ) -> RawRun: ...

    def parse(self, raw: RawRun, target_path: Path) -> List[CandidateFinding]: ...
