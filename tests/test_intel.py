from pathlib import Path
import pytest

from wmsa.db import Database
from wmsa.intel import ThreatIntelManager
from wmsa.normalize import Finding, FindingSourceRef


@pytest.fixture
def fixtures_dir():
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def intel_env(tmp_path, fixtures_dir):
    db_path = tmp_path / "intel_test.db"
    db = Database(db_path)
    cache_dir = tmp_path / "cache"
    mgr = ThreatIntelManager(db=db, cache_dir=cache_dir)
    return {
        "db": db,
        "mgr": mgr,
        "fixtures_dir": fixtures_dir,
    }


def test_cisa_kev_sync_offline_and_exact_match(intel_env):
    mgr = intel_env["mgr"]
    kev_fixture = intel_env["fixtures_dir"] / "cisa_kev_sample.json"

    # 1. Sync from offline fixture
    res = mgr.sync_cisa_kev(force=True, source_json_path=kev_fixture)
    assert res["status"] == "OK"
    assert res["count"] == 2

    # 2. Verify exact CVE matches
    assert mgr.is_cve_in_kev("CVE-2021-23337") is True
    assert mgr.is_cve_in_kev("cve-2021-23337") is True  # case-insensitive
    assert mgr.is_cve_in_kev("CVE-2023-4863") is True

    # 3. NON-NEGOTIABLE: Exact match only; no prefix, partial, or substring match
    assert mgr.is_cve_in_kev("CVE-2021-2333") is False
    assert mgr.is_cve_in_kev("CVE-2021-23337-extra") is False
    assert mgr.is_cve_in_kev("CVE-9999-99999") is False
    assert mgr.is_cve_in_kev("") is False


def test_ghsa_sync_and_fts5_search(intel_env):
    mgr = intel_env["mgr"]
    kev_fixture = intel_env["fixtures_dir"] / "cisa_kev_sample.json"
    ghsa_fixture = intel_env["fixtures_dir"] / "ghsa_sample.json"

    # Sync KEV first so GHSA cross-references KEV
    mgr.sync_cisa_kev(force=True, source_json_path=kev_fixture)
    ghsa_res = mgr.sync_ghsa(force=True, source_json_path=ghsa_fixture)

    assert ghsa_res["status"] == "OK"
    assert ghsa_res["count"] == 2

    # Verify FTS5 search by CVE token with hyphens
    cve_results = mgr.search_advisories("CVE-2021-23337")
    assert len(cve_results) >= 1
    assert any("23337" in r.get("cve_id", "") for r in cve_results)

    # Verify FTS5 search by keyword
    kw_results = mgr.search_advisories("command injection")
    assert len(kw_results) >= 1

    # Verify search with special punctuation does not raise an exception
    safe_res = mgr.search_advisories("test-lib fl'aw / (denial)")
    assert isinstance(safe_res, list)


def test_cross_reference_finding(intel_env):
    mgr = intel_env["mgr"]
    kev_fixture = intel_env["fixtures_dir"] / "cisa_kev_sample.json"
    mgr.sync_cisa_kev(force=True, source_json_path=kev_fixture)

    finding_with_kev = Finding(
        title="Prototype Pollution in lodash",
        category="sca",
        status="CANDIDATE",
        severity="HIGH",
        repo="https://github.com/koala73/worldmonitor",
        commit_sha="0d5c618e4307414546a9be84a482ac06b7d56749",
        build_id="b-1",
        scope_id="s-1",
        cve=["CVE-2021-23337"],
        description="Command injection / prototype pollution",
        stable_fingerprint="fp-test-1",
    )

    finding_without_kev = Finding(
        title="Unknown flaw in other-pkg",
        category="sca",
        status="CANDIDATE",
        severity="LOW",
        repo="https://github.com/koala73/worldmonitor",
        commit_sha="0d5c618e4307414546a9be84a482ac06b7d56749",
        build_id="b-1",
        scope_id="s-1",
        cve=["CVE-2099-0001"],
        description="Minor flaw",
        stable_fingerprint="fp-test-2",
    )

    assert finding_with_kev.kev_match is False
    matched = mgr.cross_reference_finding(finding_with_kev)
    assert matched is True
    assert finding_with_kev.kev_match is True

    matched2 = mgr.cross_reference_finding(finding_without_kev)
    assert matched2 is False
    assert finding_without_kev.kev_match is False


def test_feed_status_tracking(intel_env):
    mgr = intel_env["mgr"]
    kev_fixture = intel_env["fixtures_dir"] / "cisa_kev_sample.json"
    mgr.sync_cisa_kev(force=True, source_json_path=kev_fixture)

    statuses = mgr.get_feed_statuses()
    assert len(statuses) == 1
    kev_status = statuses[0]
    assert kev_status["feed_name"] == "cisa-kev"
    assert kev_status["record_count"] == 2
    assert kev_status["status"] == "OK"
    assert kev_status["is_stale"] is False
