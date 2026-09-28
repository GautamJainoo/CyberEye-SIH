import json
from pathlib import Path
import pytest

from wmsa.adapters.base import CandidateFinding
from wmsa.db import Database
from wmsa.evidence import EvidenceManager
from wmsa.lifecycle import LifecycleManager
from wmsa.normalize import Normalizer
from wmsa.report import ReportExporter
from wmsa.scope import ScopeManifest


@pytest.fixture
def test_env(tmp_path):
    db_path = tmp_path / "wmsa.db"
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    db = Database(db_path)
    evidence_mgr = EvidenceManager(db=db, evidence_dir=evidence_dir)
    lifecycle_mgr = LifecycleManager(db=db, evidence_mgr=evidence_mgr)
    normalizer = Normalizer(db=db)

    manifest = ScopeManifest(
        version="1.0",
        scope_id="wm-local-sih-2026",
        repo_url="https://github.com/koala73/worldmonitor",
        commit_sha="0d5c618e4307414546a9be84a482ac06b7d56749",
        allowed_hosts=["127.0.0.1", "localhost"],
        allowed_ports=[3000],
        allowed_schemes=["http"],
        kill_switch=False,
        approved_by="security-lead",
        approved_at="2026-09-28T00:00:00Z",
    )

    # Ingest candidate finding
    cand = CandidateFinding(
        title="Unauthenticated RSS Proxy SSRF",
        category="dast_io",
        status="CANDIDATE",
        severity="HIGH",
        confidence_label="CONFIRMED",
        description="RSS Proxy allows arbitrary loopback fetching",
        remediation="Validate URL against allowed RSS feeds",
        tool="worldmonitor-probes",
        tool_version="1.0.0",
        rule_id="wm-probe-ssrf-01",
        file="api/rss-proxy.js",
        line_start=15,
        line_end=40,
        cwe=["CWE-918"],
        owasp=["A10:2021"],
        repo="https://github.com/koala73/worldmonitor",
        commit_sha="0d5c618e4307414546a9be84a482ac06b7d56749",
        build_id="build-local",
        scope_id="wm-local-sih-2026",
        impact="Allows internal network probing and metadata exfiltration",
    )
    findings = normalizer.ingest_findings([cand])
    f = findings[0]

    # Attach evidence and promote to TRIAGED
    ev = evidence_mgr.create_evidence_artifact(
        finding_id=f.finding_id,
        recipe_id="wm-probe-ssrf-01",
        artifact_type="http_traffic",
        data={"request": "GET /api/rss-proxy?url=http://127.0.0.1:3000 HTTP/1.1", "status": 200},
        metadata={"collected_by": "analyst-1"},
    )
    lifecycle_mgr.transition(
        finding_id=f.finding_id,
        to_status="TRIAGED",
        actor_type="analyst",
        actor_id="analyst-1",
        reason="Reproduced SSRF in local environment",
    )

    exporter = ReportExporter(
        db=db,
        evidence_mgr=evidence_mgr,
        scope_manifest=manifest,
        base_dir=tmp_path,
    )

    return {
        "db": db,
        "evidence_mgr": evidence_mgr,
        "lifecycle_mgr": lifecycle_mgr,
        "exporter": exporter,
        "tmp_path": tmp_path,
        "finding": f,
        "evidence": ev,
    }


def test_export_json(test_env):
    exporter = test_env["exporter"]
    json_path = test_env["tmp_path"] / "report.json"
    data = exporter.export_json(json_path)

    assert json_path.exists()
    assert data["report_version"] == "1.0"
    assert data["target"]["commit_sha"] == "0d5c618e4307414546a9be84a482ac06b7d56749"
    assert data["summary"]["total_findings"] == 1
    assert data["summary"]["by_status"]["TRIAGED"] == 1
    assert len(data["findings"]) == 1

    f0 = data["findings"][0]
    assert f0["finding_id"] == test_env["finding"].finding_id
    assert f0["status"] == "TRIAGED"
    assert len(f0["evidence_items"]) == 1
    assert f0["evidence_items"][0]["sha256_hash"] == test_env["evidence"]["sha256_hash"]

    # Verify mandatory limitations and disclosure
    assert len(data["limitations"]) >= 3
    assert "disclosure_notice" in data
    assert "advisories/new" in data["disclosure_notice"]


def test_export_html(test_env):
    exporter = test_env["exporter"]
    html_path = test_env["tmp_path"] / "report.html"
    html_out = exporter.export_html(html_path)

    assert html_path.exists()
    assert "World Monitor Security Assessment Report" in html_out
    assert "0d5c618e4307414546a9be84a482ac06b7d56749" in html_out
    assert test_env["finding"].finding_id in html_out
    assert test_env["evidence"]["sha256_hash"] in html_out
    assert "Mandatory Limitations & Integrity Note" in html_out
    assert "Coordinated Responsible Disclosure" in html_out
    assert "https://github.com/koala73/worldmonitor/security/advisories/new" in html_out
