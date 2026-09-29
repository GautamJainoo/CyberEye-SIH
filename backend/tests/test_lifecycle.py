"""
Unit tests for Finding Normalization, Stable Fingerprints, Deduplication,
Lifecycle State Machine, and Evidence Gates.
"""

from pathlib import Path
import pytest

from wmsa.adapters.base import CandidateFinding
from wmsa.db import Database
from wmsa.evidence import EvidenceManager
from wmsa.lifecycle import LifecycleManager, LifecycleViolation
from wmsa.normalize import Normalizer


@pytest.fixture
def test_db(tmp_path):
    return Database(tmp_path / "lifecycle_test.db")


@pytest.fixture
def evidence_mgr(test_db, tmp_path):
    return EvidenceManager(db=test_db, evidence_dir=tmp_path / "evidence")


@pytest.fixture
def lifecycle_mgr(test_db, evidence_mgr):
    return LifecycleManager(db=test_db, evidence_mgr=evidence_mgr)


@pytest.fixture
def normalizer(test_db):
    return Normalizer(db=test_db)


def test_fingerprint_convergence_and_deduplication(normalizer, test_db):
    cand1 = CandidateFinding(
        title="Prototype Pollution in lodash",
        category="sca",
        status="CANDIDATE",
        severity="HIGH",
        repo="https://github.com/koala73/worldmonitor",
        commit_sha="0d5c618e4307414546a9be84a482ac06b7d56749",
        build_id="b-1",
        scope_id="s-1",
        tool="osv-scanner",
        tool_version="2.6.0",
        rule_id="GHSA-35jh-r3h4-6jhm",
        package="lodash",
        package_version="4.17.15",
        file="package-lock.json",
        cwe=["CWE-1321"],
        description="Prototype pollution vulnerability",
    )

    # Ingest first scan
    findings1 = normalizer.ingest_findings([cand1])
    assert len(findings1) == 1
    f1_id = findings1[0].finding_id
    fp1 = findings1[0].stable_fingerprint

    # Second scan with another tool or repeated run detecting same issue
    cand2 = CandidateFinding(
        title="Lodash Prototype Pollution Alert",
        category="sca",
        status="CANDIDATE",
        severity="HIGH",
        repo="https://github.com/koala73/worldmonitor",
        commit_sha="0d5c618e4307414546a9be84a482ac06b7d56749",
        build_id="b-2",
        scope_id="s-1",
        tool="semgrep",
        tool_version="1.176.0",
        rule_id="npm.lodash.prototype-pollution",
        package="lodash",
        package_version="4.17.15",
        file="package-lock.json",
        cwe=["CWE-1321"],
        description="Duplicate alert from second tool",
    )

    findings2 = normalizer.ingest_findings([cand2])
    assert len(findings2) == 1
    f2 = findings2[0]

    # Must converge onto identical finding ID and fingerprint
    assert f2.finding_id == f1_id
    assert f2.stable_fingerprint == fp1

    # Database check: only 1 finding in findings table, but 2 sources in finding_sources
    with test_db.get_connection() as conn:
        f_count = conn.execute("SELECT count(*) as c FROM findings").fetchone()["c"]
        s_count = conn.execute("SELECT count(*) as c FROM finding_sources WHERE finding_id = ?", (f1_id,)).fetchone()["c"]
        assert f_count == 1
        assert s_count == 2

    # A later scan from the same tool must not add another finding or another source row.
    again = normalizer.ingest_findings([cand2])
    assert again[0].finding_id == f1_id
    with test_db.get_connection() as conn:
        assert conn.execute("SELECT count(*) as c FROM findings").fetchone()["c"] == 1
        assert conn.execute(
            "SELECT count(*) as c FROM finding_sources WHERE finding_id = ?", (f1_id,)
        ).fetchone()["c"] == 2


def test_actor_restrictions_tool_and_llm_cannot_promote(normalizer, lifecycle_mgr):
    cand = CandidateFinding(
        title="Unescaped HTML in feed title",
        category="sast",
        status="CANDIDATE",
        severity="HIGH",
        repo="worldmonitor",
        commit_sha="0d5c618e",
        build_id="b-1",
        scope_id="s-1",
        tool="semgrep",
        tool_version="1.176.0",
        rule_id="wm-sast-innerhtml",
        file="src/components/Feed.tsx",
        line_start=15,
        description="Direct innerHTML assignment",
    )
    findings = normalizer.ingest_findings([cand])
    f_id = findings[0].finding_id

    # Tool cannot set TRIAGED
    with pytest.raises(LifecycleViolation, match="Actor type 'tool' is strictly forbidden"):
        lifecycle_mgr.transition(
            finding_id=f_id,
            to_status="TRIAGED",
            actor_type="tool",
            actor_id="semgrep",
            reason="Automated rule flag",
        )

    # LLM cannot set TRIAGED or VERIFIED
    with pytest.raises(LifecycleViolation, match="Actor type 'llm' is strictly forbidden"):
        lifecycle_mgr.transition(
            finding_id=f_id,
            to_status="TRIAGED",
            actor_type="llm",
            actor_id="gpt-4o",
            reason="Model believes this is real",
        )


def test_evidence_gate_blocks_verified_without_evidence_artifacts(normalizer, lifecycle_mgr):
    cand = CandidateFinding(
        title="Missing auth check",
        category="authorization",
        status="CANDIDATE",
        severity="HIGH",
        repo="worldmonitor",
        commit_sha="0d5c618e",
        build_id="b-1",
        scope_id="s-1",
        tool="worldmonitor-probes",
        tool_version="1.0.0",
        rule_id="wm-probe-auth-01",
        endpoint="/api/user/mcp-quota",
        method="GET",
        description="Probe observed unauth response",
    )
    findings = normalizer.ingest_findings([cand])
    f_id = findings[0].finding_id

    # Triage by analyst
    lifecycle_mgr.transition(
        finding_id=f_id,
        to_status="TRIAGED",
        actor_type="analyst",
        actor_id="analyst_alice",
        reason="Reviewed probe telemetry",
    )

    # Attempt VERIFIED without evidence artifact in DB -> must fail
    with pytest.raises(LifecycleViolation, match="requires at least one cryptographically hashed evidence"):
        lifecycle_mgr.transition(
            finding_id=f_id,
            to_status="VERIFIED",
            actor_type="analyst",
            actor_id="analyst_alice",
            reason="Analyst confirms finding",
            impact="Unauthorized user could observe other user usage counters",
        )


def test_successful_verified_transition_with_hashed_evidence(normalizer, lifecycle_mgr, evidence_mgr):
    cand = CandidateFinding(
        title="SSRF vector via RSS proxy",
        category="dast_io",
        status="CANDIDATE",
        severity="HIGH",
        repo="worldmonitor",
        commit_sha="0d5c618e",
        build_id="b-1",
        scope_id="s-1",
        tool="worldmonitor-probes",
        tool_version="1.0.0",
        rule_id="wm-probe-ssrf-01",
        endpoint="/api/rss-proxy",
        method="GET",
        description="Probe testing allowed domain redirects",
    )
    findings = normalizer.ingest_findings([cand])
    f_id = findings[0].finding_id

    # Attach hashed evidence artifact
    evidence_mgr.create_evidence_artifact(
        finding_id=f_id,
        recipe_id="wm-probe-ssrf-01",
        artifact_type="http_exchange",
        data={
            "request": "GET /api/rss-proxy?url=http://127.0.0.1:3000",
            "response_status": 403,
            "response_body": '{"error":"Domain not allowed"}',
        },
    )

    # Triage by analyst
    lifecycle_mgr.transition(
        finding_id=f_id,
        to_status="TRIAGED",
        actor_type="analyst",
        actor_id="analyst_alice",
        reason="Initial review of SSRF guard behavior",
    )

    # Promote to VERIFIED with analyst reasoning and impact
    updated = lifecycle_mgr.transition(
        finding_id=f_id,
        to_status="VERIFIED",
        actor_type="analyst",
        actor_id="analyst_alice",
        reason="Verified that redirect SSRF boundary is properly enforced under local conditions",
        impact="Low risk in tested configuration due to domain allowlist",
    )

    assert updated.status == "VERIFIED"
    assert updated.impact is not None
