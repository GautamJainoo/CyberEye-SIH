"""
Unit tests for World Monitor Specific Probes and Recipe Runners.
"""

from pathlib import Path
import pytest

from wmsa.adapters.probes import ProbesAdapter
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
        allowed_route_prefixes=["/", "/api/"],
        approved_by="Tester",
        approved_at="2026-09-28T00:00:00Z",
    )


@pytest.fixture
def adapter(manifest):
    return ProbesAdapter(scope_manifest=manifest)


def test_probe_recipes_all_valid(adapter):
    recipes = adapter.list_recipes()
    assert len(recipes) >= 5
    ids = {r["id"] for r in recipes}
    expected_ids = {
        "wm-probe-auth-01",
        "wm-probe-ssrf-01",
        "wm-probe-cors-01",
        "wm-probe-ratelimit-01",
        "wm-probe-oauth-grant-01",
    }
    assert expected_ids.issubset(ids)

    for r in recipes:
        assert "id" in r
        assert "title" in r
        assert "source_refs" in r
        assert len(r["source_refs"]) > 0
        assert "expected_safe_behavior" in r
        assert "verdict_rules" in r
        assert r["max_requests"] <= 20


def test_probe_oauth_grant_execution(adapter, tmp_path):
    recipes = adapter.list_recipes()
    oauth_recipe = next(r for r in recipes if r["id"] == "wm-probe-oauth-grant-01")

    res = adapter.execute_recipe(
        recipe=oauth_recipe,
        target_base_url="http://127.0.0.1:3000",
        output_dir=tmp_path,
        commit_sha="0d5c618e",
        build_id="b-1",
    )
    # Offline simulation never exercises the target, so it must not claim the expectation was met.
    assert res.verdict == "INCONCLUSIVE"
    assert res.finding is None
    assert res.evidence_artifact_path is not None
    assert Path(res.evidence_artifact_path).exists()
    assert len(res.evidence_sha256) == 64


def test_probe_scope_guard_blocks_external_target(manifest, tmp_path):
    adapter = ProbesAdapter(scope_manifest=manifest)
    recipes = adapter.list_recipes()
    auth_recipe = next(r for r in recipes if r["id"] == "wm-probe-auth-01")

    # Target URL is forbidden public domain
    res = adapter.execute_recipe(
        recipe=auth_recipe,
        target_base_url="https://worldmonitor.app",
        output_dir=tmp_path,
        commit_sha="0d5c618e",
        build_id="b-1",
    )
    # Blocked by scope guard
    assert res.verdict in ("EXPECTATION_MET", "INCONCLUSIVE")
    evidence_file = Path(res.evidence_artifact_path)
    content = evidence_file.read_text()
    assert "Blocked by scope guard" in content


def test_probes_run_all(adapter, tmp_path):
    raw_run = adapter.run(
        target_path=Path("target"),
        output_dir=tmp_path,
        commit_sha="0d5c618e",
        build_id="b-1",
        scope_id="s-1",
        profile_config={},
    )
    assert raw_run.exit_code == 0
    assert Path(raw_run.raw_output_path).exists()
    assert len(raw_run.raw_output_sha256) == 64

    findings = adapter.parse(raw_run, Path("target"))
    for f in findings:
        assert f.status == "CANDIDATE"
