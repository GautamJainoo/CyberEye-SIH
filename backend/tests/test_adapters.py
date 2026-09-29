"""
Unit tests for SAST (Semgrep), Secret (Gitleaks), and SCA (OSV-Scanner) adapters.
Enforces:
1. Status is strictly CANDIDATE.
2. Zero secret leaks in parsed outputs or fingerprints.
3. Accurate advisory, CVE, and KEV correlation.
"""

import json
from pathlib import Path
import pytest

from wmsa.adapters.base import RawRun
from wmsa.adapters.gitleaks import GitleaksAdapter, redact, compute_salted_secret_fingerprint
from wmsa.adapters.osv import OSVScannerAdapter
from wmsa.adapters.semgrep import SemgrepAdapter


@pytest.fixture
def fixtures_dir():
    return Path(__file__).parent / "fixtures"


def test_gitleaks_zero_secret_leak_guarantee(fixtures_dir, tmp_path):
    raw_fixture = fixtures_dir / "gitleaks_sample.json"
    planted_secret = "dummy_secret_do_not_leak_1234567890abcdef"

    adapter = GitleaksAdapter()
    raw_run = RawRun(
        tool_name="gitleaks",
        tool_version="8.30.1",
        command_line="gitleaks detect",
        start_time="2026-09-28T00:00:00Z",
        end_time="2026-09-28T00:00:01Z",
        exit_code=1,
        raw_output_path=str(raw_fixture),
        raw_output_sha256="dummy_sha",
    )

    findings = adapter.parse(raw_run, target_path=tmp_path)
    assert len(findings) == 1
    f = findings[0]

    # Verify status is CANDIDATE
    assert f.status == "CANDIDATE"
    assert f.category == "secret"

    # NON-NEGOTIABLE: Planted raw secret MUST NOT appear anywhere in the model
    finding_dict = f.model_dump()
    finding_str = json.dumps(finding_dict)
    assert planted_secret not in finding_str
    assert planted_secret not in f.description
    assert planted_secret not in f.title

    # Salted fingerprint exists and is not raw secret
    assert f.snippet_hash != planted_secret
    assert len(f.snippet_hash) == 64  # SHA-256


def test_gitleaks_redact_helper():
    sample = "Authorization: Bearer my_secret_token_123456789 and API_KEY='super_secret_api_key_xyz'"
    redacted = redact(sample)
    assert "my_secret_token_123456789" not in redacted
    assert "super_secret_api_key_xyz" not in redacted
    assert "[REDACTED_SECRET]" in redacted


def test_osv_scanner_parsing_and_kev(fixtures_dir, tmp_path):
    raw_fixture = fixtures_dir / "osv_sample.json"
    adapter = OSVScannerAdapter()
    raw_run = RawRun(
        tool_name="osv-scanner",
        tool_version="2.6.0",
        command_line="osv-scanner scan source",
        start_time="2026-09-28T00:00:00Z",
        end_time="2026-09-28T00:00:01Z",
        exit_code=0,
        raw_output_path=str(raw_fixture),
        raw_output_sha256="dummy_sha",
    )

    # Test without KEV match
    findings_no_kev = adapter.parse(raw_run, target_path=tmp_path, known_kev_cves=set())
    assert len(findings_no_kev) == 1
    f1 = findings_no_kev[0]
    assert f1.status == "CANDIDATE"
    assert f1.category == "sca"
    assert f1.package == "lodash"
    assert f1.package_version == "4.17.15"
    assert "CVE-2021-23337" in f1.cve
    assert "GHSA-35jh-r3h4-6jhm" in f1.ghsa
    assert f1.kev_match is False
    assert "4.17.21" in f1.remediation_proposal

    # Test with KEV match
    findings_with_kev = adapter.parse(raw_run, target_path=tmp_path, known_kev_cves={"CVE-2021-23337"})
    assert findings_with_kev[0].kev_match is True


def test_semgrep_parsing(fixtures_dir, tmp_path):
    raw_fixture = fixtures_dir / "semgrep_sample.json"
    adapter = SemgrepAdapter()
    raw_run = RawRun(
        tool_name="semgrep",
        tool_version="1.176.0",
        command_line="semgrep scan",
        start_time="2026-09-28T00:00:00Z",
        end_time="2026-09-28T00:00:01Z",
        exit_code=0,
        raw_output_path=str(raw_fixture),
        raw_output_sha256="dummy_sha",
    )

    findings = adapter.parse(raw_run, target_path=tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.status == "CANDIDATE"
    assert f.category == "sast"
    assert f.rule_id == "javascript.browser.security.insecure-inner-html.insecure-inner-html"
    assert f.file == "src/components/Renderer.tsx"
    assert f.line_start == 42
    assert "CWE-79" in f.cwe
    assert f.severity == "HIGH"
    assert f.snippet_hash is not None
    assert len(f.stable_fingerprint) == 64


def test_adapter_preflights(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "package-lock.json").touch()

    gitleaks = GitleaksAdapter()
    osv = OSVScannerAdapter()
    semgrep = SemgrepAdapter()

    res_git = gitleaks.preflight(tmp_path)
    assert isinstance(res_git.tool_present, bool)
    assert res_git.target_accessible is True

    res_osv = osv.preflight(tmp_path)
    assert isinstance(res_osv.tool_present, bool)
    assert res_osv.target_accessible is True

    res_sem = semgrep.preflight(tmp_path)
    assert isinstance(res_sem.tool_present, bool)
    assert res_sem.target_accessible is True
