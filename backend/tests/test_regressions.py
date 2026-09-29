"""Regression tests for the assessment-integrity fixes (honest verdicts, no fake scanning)."""

import json
from pathlib import Path

import httpx
import pytest

from wmsa.adapters.base import RawRun
from wmsa.adapters.gitleaks import GitleaksAdapter
from wmsa.adapters.osv import OSVScannerAdapter
from wmsa.adapters.probes import ProbesAdapter
from wmsa.adapters.semgrep import SemgrepAdapter
from wmsa.adapters.zap import ZAPAdapter


def _resp(status=200, headers=None, body=None):
    return httpx.Response(status, headers=headers or {}, json=body if body is not None else {})


def test_status_mismatch_is_a_violation():
    assert ProbesAdapter._evaluate_step({"expected_status": 403}, _resp(404))
    assert not ProbesAdapter._evaluate_step({"expected_status": 403}, _resp(403))


def test_expected_status_accepts_a_list():
    assert not ProbesAdapter._evaluate_step({"expected_status": [200, 301]}, _resp(301))
    assert ProbesAdapter._evaluate_step({"expected_status": [200, 301]}, _resp(500))


def test_forbidden_header_reflection_is_detected():
    step = {"assert_header_not": "Access-Control-Allow-Origin: https://attacker.evil.com"}
    assert ProbesAdapter._evaluate_step(step, _resp(headers={"access-control-allow-origin": "https://attacker.evil.com"}))
    assert not ProbesAdapter._evaluate_step(step, _resp(headers={"access-control-allow-origin": "http://localhost"}))


def test_field_assertion():
    step = {"assert_field": "error", "expected_value": "unauthenticated"}
    assert not ProbesAdapter._evaluate_step(step, _resp(401, body={"error": "unauthenticated"}))
    assert ProbesAdapter._evaluate_step(step, _resp(401, body={"error": "other"}))


def test_headers_variants_expand_into_requests():
    steps = ProbesAdapter._expand_steps(
        [{"name": "s", "path": "/x", "headers_variants": ["cf-connecting-ip: 1.1.1.1", "cf-connecting-ip: 2.2.2.2"]}]
    )
    assert [s["headers"]["cf-connecting-ip"] for s in steps] == ["1.1.1.1", "2.2.2.2"]


@pytest.mark.parametrize("adapter_cls", [SemgrepAdapter, GitleaksAdapter, OSVScannerAdapter])
def test_missing_scanner_binary_fails_loudly(adapter_cls, tmp_path):
    adapter = adapter_cls(binary_path="definitely-not-installed-xyz")
    with pytest.raises(RuntimeError, match="binary not found"):
        adapter.run(
            target_path=tmp_path, output_dir=tmp_path / "out", commit_sha="0" * 40,
            build_id="b", scope_id="s", profile_config={},
        )


def test_zap_collapses_instances_into_one_finding_per_alert(tmp_path):
    report = tmp_path / "zap.json"
    report.write_text(json.dumps({"site": [{"alerts": [{
        "pluginid": "10027", "alert": "Suspicious Comments", "riskcode": "0", "cweid": "615",
        "desc": "d", "solution": "s",
        "instances": [{"uri": f"http://127.0.0.1:3000/a{i}.js", "method": "GET", "evidence": "TODO"} for i in range(30)],
    }]}]}))
    raw = RawRun(tool_name="zap", tool_version="s", command_line="x", start_time="a", end_time="b", exit_code=0,
                 raw_output_path=str(report), raw_output_sha256="0")
    found = ZAPAdapter().parse(raw, Path("."))
    assert len(found) == 1
    assert "Affected URLs (30)" in found[0].description


def test_zap_empty_report_is_not_reported_as_clean(tmp_path, monkeypatch):
    """A ZAP run that produced no report must raise instead of returning zero alerts."""
    import subprocess
    from wmsa.scope import ScopeManifest

    manifest = ScopeManifest(
        scope_id="t", repo_url="https://github.com/koala73/worldmonitor", commit_sha="0" * 40, local_path="target",
        allowed_hosts=["127.0.0.1"], allowed_ports=[3000], allowed_route_prefixes=["/"],
        approved_by="t", approved_at="2026-09-28T00:00:00Z",
    )
    from wmsa.paths import get_base_dir

    adapter = ZAPAdapter(scope_manifest=manifest, base_dir=get_base_dir())
    monkeypatch.setattr(adapter, "preflight", lambda *a, **k: type("P", (), {"target_accessible": True})())
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 1, stdout="", stderr="Failed to start the main proxy"),
    )
    with pytest.raises(RuntimeError, match="ZAP scan failed"):
        adapter.run(target_path=tmp_path, output_dir=tmp_path / "o", commit_sha="0" * 40, build_id="b",
                    scope_id="s", profile_config={})
