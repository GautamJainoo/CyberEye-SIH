"""
Unit tests for OWASP ZAP adapter and Automation Framework plan generation.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from wmsa.adapters.base import RawRun
from wmsa.adapters.zap import ZAPAdapter
from wmsa.scope import ScopeManifest


@pytest.fixture
def manifest():
    return ScopeManifest(
        scope_id="test-scope",
        repo_url="https://github.com/koala73/worldmonitor",
        commit_sha="0d5c618e4307414546a9be84a482ac06b7d56749",
        local_path="target",
        allowed_hosts=["127.0.0.1", "localhost"],
        allowed_ports=[3000, 8080],
        allowed_route_prefixes=["/", "/api/", "/docs/"],
        approved_by="Tester",
        approved_at="2026-09-28T00:00:00Z",
    )


@pytest.fixture
def zap_adapter(manifest):
    return ZAPAdapter(scope_manifest=manifest)


def test_zap_plan_generation_within_scope(zap_adapter):
    plan_yaml = zap_adapter.generate_plan(
        target_host="127.0.0.1",
        target_port=3000,
        report_filename="test_zap.json",
        profile_config={"zap": {"max_spider_depth": 2, "max_scan_duration_mins": 5}},
    )

    assert "http://127.0.0.1:3000" in plan_yaml
    assert "http://127.0.0.1:3000/api/.*" in plan_yaml
    assert "test_zap.json" in plan_yaml
    assert "logout" in plan_yaml  # Exclude path


def test_zap_plan_generation_blocks_out_of_scope_target(zap_adapter):
    with pytest.raises(ValueError, match="violates scope manifest"):
        zap_adapter.generate_plan(
            target_host="worldmonitor.app",
            target_port=3000,
            report_filename="test_zap.json",
            profile_config={},
        )

    with pytest.raises(ValueError, match="violates scope manifest"):
        zap_adapter.generate_plan(
            target_host="127.0.0.1",
            target_port=9999,
            report_filename="test_zap.json",
            profile_config={},
        )


def test_zap_preflight_target_offline_skips_cleanly(zap_adapter, tmp_path):
    # Port 3000 offline in unit test
    pre = zap_adapter.preflight(target_path=tmp_path, target_base_url="http://127.0.0.1:3000")
    assert pre.target_accessible is False
    assert "SKIPPED (target unavailable)" in pre.message


def test_zap_parse_alerts_and_applicability_filter(zap_adapter, tmp_path):
    fixture_path = Path(__file__).parent / "fixtures" / "zap_sample.json"
    raw_run = RawRun(
        tool_name="zap",
        tool_version="stable",
        command_line="zap.sh",
        start_time="2026-09-28T00:00:00Z",
        end_time="2026-09-28T00:00:05Z",
        exit_code=0,
        raw_output_path=str(fixture_path),
        raw_output_sha256="dummy_sha",
    )

    findings = zap_adapter.parse(raw_run, tmp_path)
    # Total instances in sample = 3 (1 CSP, 2 SQLi instances, 1 on logo.png)
    # logo.png should be skipped by the static asset applicability filter -> 2 findings left
    assert len(findings) == 2

    # Check CSP finding
    csp = next(f for f in findings if "CSP" in f.title)
    assert csp.status == "CANDIDATE"
    assert csp.category == "configuration"
    assert csp.severity == "MEDIUM"

    # Check SQLi finding
    sqli = next(f for f in findings if "SQL Injection" in f.title)
    assert sqli.status == "CANDIDATE"
    assert sqli.category == "dast_io"
    assert sqli.severity == "HIGH"
    assert "CWE-89" in sqli.cwe
    assert "/api/search" in sqli.endpoint
