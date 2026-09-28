"""
Unit tests for Patch Management, Branching, and Exact Recipe Retest Workflow.
"""

import subprocess
from pathlib import Path
import pytest

from wmsa.adapters.base import CandidateFinding
from wmsa.adapters.probes import ProbesAdapter
from wmsa.db import Database
from wmsa.evidence import EvidenceManager
from wmsa.lifecycle import LifecycleManager
from wmsa.normalize import Normalizer
from wmsa.patching import PatchManager
from wmsa.retest import RetestEngine
from wmsa.scope import ScopeManifest


@pytest.fixture
def manifest():
    return ScopeManifest(
        scope_id="test-scope",
        repo_url="https://github.com/koala73/worldmonitor",
        commit_sha="0d5c618e4307414546a9be84a482ac06b7d56749",
        local_path="target",
        allowed_hosts=["127.0.0.1", "localhost"],
        allowed_ports=[3000],
        allowed_route_prefixes=["/"],
        approved_by="Tester",
        approved_at="2026-09-28T00:00:00Z",
    )


@pytest.fixture
def test_env(tmp_path, manifest):
    db = Database(tmp_path / "test_retest.db")
    ev_mgr = EvidenceManager(db=db, evidence_dir=tmp_path / "evidence")
    lc_mgr = LifecycleManager(db=db, evidence_mgr=ev_mgr)
    norm = Normalizer(db=db)

    # Initialize a mock target git repository
    target_repo = tmp_path / "target"
    target_repo.mkdir()
    subprocess.run(["git", "init", str(target_repo)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(target_repo), "config", "user.email", "test@test.com"], check=True)
    subprocess.run(["git", "-C", str(target_repo), "config", "user.name", "Tester"], check=True)
    (target_repo / "server.js").write_text("const vulnerable = true;\n")
    subprocess.run(["git", "-C", str(target_repo), "add", "server.js"], check=True)
    subprocess.run(["git", "-C", str(target_repo), "commit", "-m", "initial"], check=True)

    patch_mgr = PatchManager(db=db, lifecycle_mgr=lc_mgr, target_dir=target_repo)
    probes_adapter = ProbesAdapter(
        recipes_dir=Path.cwd() / "probes" / "recipes",
        scope_manifest=manifest,
        base_dir=Path.cwd(),
    )
    retest_engine = RetestEngine(
        db=db,
        lifecycle_mgr=lc_mgr,
        evidence_mgr=ev_mgr,
        probes_adapter=probes_adapter,
        target_dir=target_repo,
        base_dir=Path.cwd(),
    )

    return {
        "db": db,
        "ev_mgr": ev_mgr,
        "lc_mgr": lc_mgr,
        "norm": norm,
        "target_repo": target_repo,
        "patch_mgr": patch_mgr,
        "retest_engine": retest_engine,
    }


def test_patch_proposal_and_branch_application(test_env):
    norm = test_env["norm"]
    lc_mgr = test_env["lc_mgr"]
    ev_mgr = test_env["ev_mgr"]
    patch_mgr = test_env["patch_mgr"]
    target_repo = test_env["target_repo"]

    # 1. Create finding
    cand = CandidateFinding(
        title="Flawed server logic",
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
        description="Observed authorization flaw",
    )
    findings = norm.ingest_findings([cand])
    f_id = findings[0].finding_id

    # 2. Add evidence and promote to VERIFIED
    ev_mgr.create_evidence_artifact(
        finding_id=f_id,
        recipe_id="wm-probe-auth-01",
        artifact_type="telemetry",
        data={"check": "failed"},
    )
    lc_mgr.transition(f_id, "TRIAGED", "analyst", "analyst_1", "Initial review")
    lc_mgr.transition(f_id, "VERIFIED", "analyst", "analyst_1", "Confirmed", impact="High security impact on system")

    # 3. Propose minimal patch diff
    diff = """--- a/server.js
+++ b/server.js
@@ -1,1 +1,1 @@
-const vulnerable = true;
+const vulnerable = false;
"""
    patch_info = patch_mgr.propose_patch(finding_id=f_id, diff_content=diff, created_by="analyst_1")
    assert patch_info["branch_name"] == f"assess/{f_id[:8]}"

    # Verify state is PATCH_PROPOSED
    f_after_propose = lc_mgr.get_finding(f_id)
    assert f_after_propose.status == "PATCH_PROPOSED"

    # 4. Apply patch to branch
    apply_res = patch_mgr.apply_patch(finding_id=f_id, patch_id=patch_info["patch_id"])
    assert apply_res["status"] == "RETEST_PENDING"
    assert len(apply_res["patch_commit_sha"]) == 40

    # Verify branch was created in git
    branch_check = subprocess.run(
        ["git", "-C", str(target_repo), "branch", "--show-current"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert branch_check.stdout.strip() == f"assess/{f_id[:8]}"

    # Verify file content updated
    content = (target_repo / "server.js").read_text()
    assert "const vulnerable = false;" in content


def test_retest_execution_and_fixed_transition(test_env):
    norm = test_env["norm"]
    lc_mgr = test_env["lc_mgr"]
    ev_mgr = test_env["ev_mgr"]
    retest_engine = test_env["retest_engine"]

    # Ingest grant probe finding
    cand = CandidateFinding(
        title="HMAC grant token verification",
        category="authorization",
        status="CANDIDATE",
        severity="HIGH",
        repo="worldmonitor",
        commit_sha="0d5c618e",
        build_id="b-1",
        scope_id="s-1",
        tool="worldmonitor-probes",
        tool_version="1.0.0",
        rule_id="wm-probe-oauth-grant-01",
        description="HMAC verification check",
    )
    findings = norm.ingest_findings([cand])
    f_id = findings[0].finding_id

    ev_mgr.create_evidence_artifact(
        finding_id=f_id,
        recipe_id="wm-probe-oauth-grant-01",
        artifact_type="telemetry",
        data={"check": "initial"},
    )
    lc_mgr.transition(f_id, "TRIAGED", "analyst", "analyst_1", "Initial review")
    lc_mgr.transition(f_id, "VERIFIED", "analyst", "analyst_1", "Confirmed", impact="Medium")
    lc_mgr.transition(f_id, "PATCH_PROPOSED", "analyst", "analyst_1", "Proposed")
    lc_mgr.transition(f_id, "PATCH_APPLIED", "analyst", "analyst_1", "Applied")
    lc_mgr.transition(f_id, "RETEST_PENDING", "system", "wmsa", "Retest queued")

    # Run retest with identical recipe
    retest_res = retest_engine.retest_finding(
        finding_id=f_id,
        recipe_id="wm-probe-oauth-grant-01",
        analyst_id="analyst_1",
    )

    assert retest_res["outcome"] == "FIXED"
    assert len(retest_res["retest_evidence_hash"]) == 64

    # Verify finding status is now FIXED
    f_fixed = lc_mgr.get_finding(f_id)
    assert f_fixed.status == "FIXED"
