"""Dashboard aggregates must come from real stored data only: empty DB means zeros, never placeholders."""

from wmsa import dashboard, webaudit
from wmsa.adapters.base import CandidateFinding
from wmsa.cdp import _cookie_status, _storage_entries
from wmsa.copilot_chat import recommendations
from wmsa.db import Database
from wmsa.normalize import Normalizer


def _cand(title, category, severity, **kw):
    c = CandidateFinding(
        title=title, category=category, severity=severity, repo="r", commit_sha="0" * 40, build_id="b",
        scope_id="s", tool=kw.pop("tool", "semgrep"), tool_version="1", rule_id=kw.pop("rule_id", "r1"),
        description="d", **kw,
    )
    c.compute_fingerprint()
    return c


def test_empty_database_yields_zeros_not_placeholders(tmp_path):
    db = Database(tmp_path / "t.db")
    s = dashboard.build_summary(db, "http://127.0.0.1:3000", True, "ok")
    assert s["findings"]["total"] == 0
    assert s["risk"]["score"] == 0 and s["risk"]["level"] == "None"
    assert s["endpoints_tested"] == 0
    # Only real Lighthouse audits (stored outside the DB) may appear when no scan has run.
    assert all(a["message"].startswith("Web audit") for a in s["activity"])
    assert s["notifications"] == []
    assert s["web_audit"] is None or isinstance(s["web_audit"], dict)  # only real audits, never invented
    assert dashboard.attack_surface(db)["nodes"] == []
    assert all(a["value"] == 100 and a["findings"] == 0 for a in dashboard.radar(db)["radar"])
    assert recommendations(db) == []  # no invented fallback recommendations


def test_risk_counts_verified_more_than_candidates_and_is_monotonic():
    cand = [{"severity": "HIGH", "status": "CANDIDATE"}] * 3
    ver = [{"severity": "HIGH", "status": "VERIFIED"}] * 3
    assert 0 < dashboard.risk_score(cand) < dashboard.risk_score(ver) <= 100
    assert dashboard.risk_score(cand + cand) > dashboard.risk_score(cand)


def test_attack_surface_groups_by_real_area(tmp_path):
    db = Database(tmp_path / "t.db")
    Normalizer(db).ingest_findings([
        _cand("XSS sink", "sast", "HIGH", file="target/api/a.ts", line_start=3, cwe=["CWE-79"]),
        _cand("Old lodash", "sca", "MEDIUM", package="lodash", package_version="4.17.15", rule_id="GHSA-x", tool="osv-scanner"),
        _cand("Leaked key", "secret", "HIGH", file="config/.env", line_start=1, rule_id="k", tool="gitleaks"),
    ])
    nodes = {n["id"]: n for n in dashboard.attack_surface(db)["nodes"]}
    assert set(nodes) == {"src:api", "deps", "secrets"}
    assert nodes["deps"]["max_severity"] == "MEDIUM" and nodes["deps"]["status"] == "warning"
    assert nodes["src:api"]["status"] == "vulnerable"
    radar = {r["label"]: r for r in dashboard.radar(db)["radar"]}
    assert radar["Dependencies"]["findings"] == 1 and radar["Dependencies"]["value"] < 100
    assert radar["Input validation & injection"]["findings"] == 1


def test_recommendations_use_real_findings(tmp_path):
    db = Database(tmp_path / "t.db")
    Normalizer(db).ingest_findings([_cand("Real issue", "sast", "HIGH", file="a.ts", line_start=1)])
    recs = recommendations(db)
    assert len(recs) == 1 and recs[0]["title"] == "Real issue"


def test_lighthouse_result_is_compacted_from_the_report_only():
    raw = {
        "lighthouseVersion": "13.0.0",
        "categories": {"performance": {"score": 0.78, "auditRefs": [{"id": "lcp"}]}, "seo": {"score": None, "auditRefs": []}},
        "audits": {
            "largest-contentful-paint": {"numericValue": 2700.4},
            "lcp": {"title": "LCP", "score": 0.4, "scoreDisplayMode": "numeric", "displayValue": "2.7 s", "description": "Slow. [Learn](x)"},
        },
    }
    out = webaudit._compact(raw, "http://127.0.0.1:3000")
    assert out["categories"]["performance"] == 78 and out["categories"]["seo"] is None
    assert out["metrics"]["lcp_ms"] == 2700.4 and out["metrics"]["cls"] is None  # unmeasured stays None
    assert out["issues"][0]["id"] == "lcp"


def test_external_urls_cannot_be_audited():
    import pytest
    with pytest.raises(Exception):
        webaudit.run_audit("https://example.com/")


def test_storage_values_that_look_like_credentials_are_redacted():
    entries = {e["key"]: e for e in _storage_entries({"auth_token": "eyJhbGciOi.eyJzdWIi.sig", "theme": "dark"})}
    assert entries["auth_token"]["isSensitive"] and entries["auth_token"]["value"] == "[REDACTED]"
    assert not entries["theme"]["isSensitive"] and entries["theme"]["value"] == "dark"


def test_cookie_flags_are_reported_as_observed():
    c = _cookie_status({"name": "sid", "domain": "x", "httpOnly": False, "secure": False})
    assert "Missing HttpOnly" in c["status"] and "Missing Secure" in c["status"]
