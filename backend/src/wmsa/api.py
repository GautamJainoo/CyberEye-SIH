"""
Thin FastAPI local backend for WMSA dashboard.
Binds strictly to loopback (127.0.0.1) and interfaces directly with SQLite database,
lifecycle state machine, and report generator.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from wmsa.db import Database
from wmsa.evidence import EvidenceManager
from wmsa.intel import ThreatIntelManager
from wmsa.lifecycle import LifecycleManager, LifecycleViolation
from wmsa.orchestrator import Orchestrator
from wmsa.patching import PatchManager
from wmsa.report import ReportExporter
from wmsa.retest import RetestEngine
from wmsa.scope import ScopeGuard, load_scope_manifest
from wmsa.target import TargetManager

api_app = FastAPI(
    title="WMSA Local Assessment API",
    version="1.0.0",
    description="Local-first, evidence-gated security assessment dashboard API for World Monitor",
)

# CORS restricted to local dashboard origins
api_app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "http://127.0.0.1:5174",
        "http://localhost:5174",
        "http://127.0.0.1:3000",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

db = Database()
evidence_mgr = EvidenceManager(db)
lifecycle_mgr = LifecycleManager(db, evidence_mgr)
orchestrator = Orchestrator(db=db)
target_mgr = TargetManager(db=db)
patch_mgr = PatchManager(db=db, lifecycle_mgr=lifecycle_mgr)
retest_engine = RetestEngine(db=db, lifecycle_mgr=lifecycle_mgr, evidence_mgr=evidence_mgr)
report_exporter = ReportExporter(db=db, evidence_mgr=evidence_mgr)
intel_mgr = ThreatIntelManager(db=db)


class ScanTriggerRequest(BaseModel):
    profile: str = "lite"
    tools: Optional[List[str]] = None


class LifecycleActionRequest(BaseModel):
    actor_id: str = "analyst"
    reason: str
    impact: Optional[str] = None


class PatchProposeRequest(BaseModel):
    diff: str
    created_by: str = "analyst"


class RetestTriggerRequest(BaseModel):
    recipe_id: str
    analyst_id: str = "analyst"


@api_app.get("/api/health")
def api_health():
    healthy, msg = target_mgr.check_health()
    manifest = load_scope_manifest()
    return {
        "status": "online",
        "target_commit": manifest.commit_sha,
        "target_healthy": healthy,
        "target_message": msg,
        "environment": "local-isolated",
    }


@api_app.get("/api/scope")
def get_scope():
    manifest = load_scope_manifest()
    return manifest.model_dump()


@api_app.get("/api/findings")
def list_findings(
    status: Optional[str] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
):
    query = "SELECT * FROM findings WHERE 1=1"
    params = []
    if status:
        query += " AND status = ?"
        params.append(status.upper())
    if category:
        query += " AND category = ?"
        params.append(category.lower())
    if severity:
        query += " AND severity = ?"
        params.append(severity.upper())

    query += " ORDER BY created_at DESC"

    with db.get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
        findings = []
        for r in rows:
            data = json.loads(r["data_json"])
            data["status"] = r["status"]
            data["sources"] = [
                dict(s)
                for s in conn.execute(
                    "SELECT tool_name, tool_version, rule_id, snippet_hash, raw_ref FROM finding_sources WHERE finding_id = ?",
                    (r["finding_id"],),
                ).fetchall()
            ]
            data["evidence_count"] = conn.execute(
                "SELECT count(*) as c FROM evidence WHERE finding_id = ?",
                (r["finding_id"],),
            ).fetchone()["c"]
            findings.append(data)

    return {"total": len(findings), "findings": findings}


@api_app.get("/api/findings/{finding_id}")
def get_finding_detail(finding_id: str):
    f = lifecycle_mgr.get_finding(finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")

    ev_list = evidence_mgr.list_evidence(finding_id)
    with db.get_connection() as conn:
        transitions = [
            dict(t)
            for t in conn.execute(
                "SELECT from_status, to_status, actor_type, actor_id, reason, timestamp FROM state_transitions WHERE finding_id = ? ORDER BY timestamp ASC",
                (finding_id,),
            ).fetchall()
        ]
        patches = [
            dict(p)
            for p in conn.execute(
                "SELECT patch_id, branch_name, diff_content, patch_commit_sha, created_by, created_at FROM patches WHERE finding_id = ?",
                (finding_id,),
            ).fetchall()
        ]
        retests = [
            dict(rt)
            for rt in conn.execute(
                "SELECT retest_id, outcome, original_evidence_hash, retest_evidence_hash, timestamp FROM retests WHERE finding_id = ?",
                (finding_id,),
            ).fetchall()
        ]

    return {
        "finding": f.model_dump(),
        "evidence": ev_list,
        "timeline": transitions,
        "patches": patches,
        "retests": retests,
    }


@api_app.post("/api/scan")
def trigger_scan(req: ScanTriggerRequest):
    res = orchestrator.run_scan(profile_name=req.profile, selected_tools=req.tools)
    return res


@api_app.post("/api/triage/{finding_id}")
def triage_finding(finding_id: str, req: LifecycleActionRequest):
    try:
        updated = lifecycle_mgr.transition(
            finding_id=finding_id,
            to_status="TRIAGED",
            actor_type="analyst",
            actor_id=req.actor_id,
            reason=req.reason,
        )
        return updated.model_dump()
    except LifecycleViolation as e:
        raise HTTPException(status_code=400, detail=str(e))


@api_app.post("/api/verify/{finding_id}")
def verify_finding(finding_id: str, req: LifecycleActionRequest):
    try:
        updated = lifecycle_mgr.transition(
            finding_id=finding_id,
            to_status="VERIFIED",
            actor_type="analyst",
            actor_id=req.actor_id,
            reason=req.reason,
            impact=req.impact,
        )
        return updated.model_dump()
    except LifecycleViolation as e:
        raise HTTPException(status_code=400, detail=str(e))


@api_app.post("/api/reject/{finding_id}")
def reject_finding(finding_id: str, req: LifecycleActionRequest):
    try:
        updated = lifecycle_mgr.transition(
            finding_id=finding_id,
            to_status="REJECTED",
            actor_type="analyst",
            actor_id=req.actor_id,
            reason=req.reason,
        )
        return updated.model_dump()
    except LifecycleViolation as e:
        raise HTTPException(status_code=400, detail=str(e))


@api_app.post("/api/patch/{finding_id}/propose")
def propose_patch(finding_id: str, req: PatchProposeRequest):
    res = patch_mgr.propose_patch(finding_id, req.diff, req.created_by)
    return res


@api_app.post("/api/retest/{finding_id}")
def run_retest(finding_id: str, req: RetestTriggerRequest):
    try:
        res = retest_engine.retest_finding(
            finding_id=finding_id,
            recipe_id=req.recipe_id,
            analyst_id=req.analyst_id,
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@api_app.get("/api/report/export")
def export_report(format: str = Query("json", pattern="^(json|html)$")):
    if format == "html":
        html_content = report_exporter.export_html()
        return Response(content=html_content, media_type="text/html")
    else:
        json_data = report_exporter.export_json()
        return json_data


@api_app.get("/api/intel/status")
def get_intel_status():
    statuses = intel_mgr.get_feed_statuses()
    return {"feeds": statuses}


@api_app.post("/api/intel/sync")
def sync_intel(force: bool = False):
    res = intel_mgr.sync_all(force=force)
    return res


@api_app.get("/api/intel/search")
def search_intel(q: str = Query(..., min_length=1), limit: int = 50):
    results = intel_mgr.search_advisories(q, limit=limit)
    return {"query": q, "total": len(results), "results": results}

