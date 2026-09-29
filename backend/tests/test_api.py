from fastapi.testclient import TestClient
import pytest

from wmsa.adapters.base import CandidateFinding
from wmsa.api import api_app, db, evidence_mgr, lifecycle_mgr
from wmsa.normalize import Normalizer


@pytest.fixture
def client():
    return TestClient(api_app)


@pytest.fixture
def sample_finding():
    import uuid
    uid = uuid.uuid4().hex[:6]
    normalizer = Normalizer(db=db)
    cand = CandidateFinding(
        title=f"Test API Finding {uid}",
        category="sast",
        status="CANDIDATE",
        severity="HIGH",
        confidence_label="CONFIRMED",
        description="Testing API lifecycle endpoints",
        remediation="Ensure proper sanitization",
        tool="semgrep",
        tool_version="1.176.0",
        rule_id=f"wm-test-rule-{uid}",
        file=f"src/utils_{uid}.js",
        line_start=10,
        line_end=15,
        repo="https://github.com/koala73/worldmonitor",
        commit_sha="0d5c618e4307414546a9be84a482ac06b7d56749",
        build_id="build-test",
        scope_id="wm-local-sih-2026",
        impact="Test impact description here",
    )
    findings = normalizer.ingest_findings([cand])
    return findings[0]


def test_api_health(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"
    assert data["target_commit"] == "0d5c618e4307414546a9be84a482ac06b7d56749"
    assert data["environment"] == "local-isolated"


def test_api_scope(client):
    res = client.get("/api/scope")
    assert res.status_code == 200
    data = res.json()
    assert data["scope_id"] == "worldmonitor-local-assessment-001"
    assert "127.0.0.1" in data["allowed_hosts"]


def test_api_findings_list(client, sample_finding):
    res = client.get("/api/findings")
    assert res.status_code == 200
    data = res.json()
    assert "findings" in data
    assert any(f["finding_id"] == sample_finding.finding_id for f in data["findings"])


def test_api_finding_detail_and_lifecycle(client, sample_finding):
    f_id = sample_finding.finding_id

    # 1. Detail endpoint
    res = client.get(f"/api/findings/{f_id}")
    assert res.status_code == 200
    data = res.json()
    assert data["finding"]["finding_id"] == f_id
    assert "timeline" in data
    assert "evidence" in data

    # 2. Triage action
    res = client.post(
        f"/api/triage/{f_id}",
        json={"actor_id": "analyst-test", "reason": "Confirmed preliminary vulnerability in local code"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "TRIAGED"

    # 3. Verify action without evidence should fail (evidence gate)
    res = client.post(
        f"/api/verify/{f_id}",
        json={
            "actor_id": "analyst-test",
            "reason": "Trying to verify without evidence",
            "impact": "High impact exploitability",
        },
    )
    assert res.status_code == 400
    assert "evidence" in res.json()["detail"].lower()

    # 4. Attach evidence and verify again
    evidence_mgr.create_evidence_artifact(
        finding_id=f_id,
        recipe_id="semgrep-rule",
        artifact_type="sast_snippet",
        data={"code": "dangerous_function(input)"},
        metadata={"reviewer": "analyst-test"},
    )

    res = client.post(
        f"/api/verify/{f_id}",
        json={
            "actor_id": "analyst-test",
            "reason": "Verified with attached sanitized source snippet",
            "impact": "High impact exploitability verified",
        },
    )
    assert res.status_code == 200
    assert res.json()["status"] == "VERIFIED"


def test_api_report_export(client, sample_finding):
    # JSON export
    res_json = client.get("/api/report/export?format=json")
    assert res_json.status_code == 200
    json_data = res_json.json()
    assert json_data["report_version"] == "1.0"
    assert "summary" in json_data
    assert "limitations" in json_data

    # HTML export
    res_html = client.get("/api/report/export?format=html")
    assert res_html.status_code == 200
    assert "text/html" in res_html.headers["content-type"]
    assert "World Monitor Security Assessment Report" in res_html.text


def test_api_intel_endpoints(client):
    res_status = client.get("/api/intel/status")
    assert res_status.status_code == 200
    assert "feeds" in res_status.json()

    res_search = client.get("/api/intel/search?q=lodash")
    assert res_search.status_code == 200
    data = res_search.json()
    assert "results" in data
    assert data["query"] == "lodash"


def test_api_devtools_endpoints(client):
    res_net = client.get("/api/devtools/network")
    assert res_net.status_code == 200
    assert "requests" in res_net.json()
    assert len(res_net.json()["requests"]) > 0

    res_sec = client.get("/api/devtools/security")
    assert res_sec.status_code == 200
    assert "security_headers" in res_sec.json()

    res_perf = client.get("/api/devtools/performance")
    assert res_perf.status_code == 200
    assert "metrics" in res_perf.json()

    res_store = client.get("/api/devtools/storage")
    assert res_store.status_code == 200
    assert "local_storage" in res_store.json()

    res_cmd = client.post("/api/devtools/console/exec", json={"command": "status"})
    assert res_cmd.status_code == 200
    assert "Target URL" in res_cmd.json()["output"]


def test_api_network_inspect(client):
    res_inspect = client.get("/api/network/inspect")
    assert res_inspect.status_code == 200
    data = res_inspect.json()
    assert "summary" in data
    assert "metrics" in data
    assert len(data["metrics"]) > 0

    res_probe = client.post("/api/network/probe", json={"url_or_path": "/api/news"})
    assert res_probe.status_code == 200


def test_api_copilot_and_telemetry(client):
    # Copilot chat
    res_chat = client.post("/api/copilot/chat", json={"prompt": "How to fix SSRF?"})
    assert res_chat.status_code == 200
    data = res_chat.json()
    assert "reply" in data
    assert "SSRF" in data["reply"]

    # Copilot recommendations
    res_recs = client.get("/api/copilot/recommendations")
    assert res_recs.status_code == 200
    assert "recommendations" in res_recs.json()

    # Attack surface telemetry
    res_surface = client.get("/api/telemetry/attack-surface")
    assert res_surface.status_code == 200
    assert "nodes" in res_surface.json()

    # Radar telemetry
    res_radar = client.get("/api/telemetry/radar")
    assert res_radar.status_code == 200
    assert "radar" in res_radar.json()




def test_api_custom_target_findings_and_storage(client):
    # Test any external target URL findings (live scan — returns real findings)
    res_amz = client.get("/api/findings?target_url=https://www.amazon.in/")
    assert res_amz.status_code == 200
    data_amz = res_amz.json()
    assert data_amz["target"] == "www.amazon.in"
    # Live scan must return at least some findings (even if target is hardened)
    # or return 0 if all headers pass — both are valid
    assert "total" in data_amz
    assert "findings" in data_amz
    assert data_amz.get("live_scan") is True
    # All findings should have required fields
    for f in data_amz["findings"]:
        assert "title" in f
        assert "severity" in f
        assert "live_scan" in f

    # Test storage audit (cookies from real HTTP response)
    res_store = client.get("/api/devtools/storage?target_url=https://www.amazon.in/")
    assert res_store.status_code == 200
    store_data = res_store.json()
    # Cookies list should be present (may be empty if no Set-Cookie returned)
    assert "cookies" in store_data
    assert store_data.get("live") is True
    # Each cookie should have the required fields
    for c in store_data["cookies"]:
        assert "name" in c
        assert "httpOnly" in c
        assert "secure" in c
        assert "sameSite" in c

    # Test default World Monitor target — serves DB findings
    res_wm = client.get("/api/findings?target_url=https://worldmonitor.app")
    assert res_wm.status_code == 200
    data_wm = res_wm.json()
    assert data_wm["target"] == "worldmonitor.app"
    # WM should serve from DB (may be empty if DB not seeded)
    assert "findings" in data_wm

    # Test security analysis is live
    res_sec = client.get("/api/devtools/security?target_url=https://httpbin.org")
    assert res_sec.status_code == 200
    sec_data = res_sec.json()
    assert "security_headers" in sec_data
    assert sec_data.get("live") is True
    assert "score" in sec_data
