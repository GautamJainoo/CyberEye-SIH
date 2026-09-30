"""
Thin FastAPI local backend for WMSA dashboard.
Binds strictly to loopback (127.0.0.1) and interfaces directly with SQLite database,
lifecycle state machine, and report generator.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, Response
from fastapi.responses import FileResponse, PlainTextResponse
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
from wmsa.scope import DEFAULT_WEBSITE_URL, ScopeGuard, load_scope_manifest
from wmsa.target import TargetManager
from wmsa.devtools import DevToolsEngine
from wmsa import dashboard as dashboard_mod, enrich as enrich_mod, pipeline as pipeline_mod, proof as proof_mod, webaudit as webaudit_mod
from wmsa.paths import get_base_dir

api_app = FastAPI(
    title="WMSA Local Assessment API",
    version="1.0.0",
    description="Local-first, evidence-gated security assessment dashboard API for World Monitor",
)
app = api_app

# CORS origins (defaults to local dashboard origins, override via CORS_ALLOWED_ORIGINS)
cors_env = os.getenv("CORS_ALLOWED_ORIGINS")
if cors_env and cors_env.strip() == "*":
    cors_origins = ["*"]
elif cors_env:
    cors_origins = [o.strip() for o in cors_env.split(",") if o.strip()]
else:
    cors_origins = [
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "http://127.0.0.1:5174",
        "http://127.0.0.1:3100",
        "http://localhost:3100",
        "http://localhost:5174",
        "http://127.0.0.1:3000",
        "http://localhost:3000",
    ]

api_app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
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
devtools_engine = DevToolsEngine(db=db)


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


class TargetConfigRequest(BaseModel):
    repo_url: str
    website_url: Optional[str] = DEFAULT_WEBSITE_URL
    commit_sha: Optional[str] = None
    reset_db: bool = True


class DevToolsConsoleRequest(BaseModel):
    command: str


class CopilotChatRequest(BaseModel):
    prompt: str
    finding_id: Optional[str] = None


class NetworkProbeRequest(BaseModel):
    url_or_path: str


@api_app.get("/api/health")
def api_health():
    healthy, msg = target_mgr.check_health()
    manifest = load_scope_manifest()
    with db.get_connection() as conn:
        count = conn.execute("SELECT count(*) as c FROM findings").fetchone()["c"]
    return {
        "status": "online",
        "repo_url": manifest.repo_url,
        "website_url": manifest.website_url,
        "target_commit": manifest.commit_sha,
        "target_healthy": healthy,
        "target_message": msg,
        "environment": "local-isolated",
        "findings_count": count,
    }


@api_app.post("/api/target/configure")
def configure_target_endpoint(req: TargetConfigRequest):
    global orchestrator, target_mgr
    try:
        conf = target_mgr.configure(
            repo_url=req.repo_url,
            website_url=req.website_url,
            commit_sha=req.commit_sha,
        )
        if req.reset_db:
            db.purge_assessment_data()

        # Reload orchestrator with updated scope
        orchestrator = Orchestrator(db=db)
        healthy, msg = target_mgr.check_health()
        return {
            "status": "configured",
            "repo_url": conf["repo_url"],
            "website_url": conf["website_url"],
            "commit_sha": conf["commit_sha"],
            "target_healthy": healthy,
            "target_message": msg,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@api_app.post("/api/db/reset")
def reset_db_endpoint():
    res = db.purge_assessment_data()
    return {"status": "purged", **res}


@api_app.get("/api/scope")
def get_scope():
    manifest = load_scope_manifest()
    return manifest.model_dump()


@api_app.get("/api/findings")
def list_findings(
    status: Optional[str] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    target_url: Optional[str] = None,
):
    target_label = load_scope_manifest().website_url
    if target_url:
        from wmsa.live_scanner import _normalize_url
        host = _host_of(target_url)
        target_label = target_url
        if host in {"127.0.0.1", "localhost"}:
            _require_in_scope(target_url)  # external scanning is out of scope
            clean_url, domain = _normalize_url(target_url)
            if not devtools_engine._is_worldmonitor(domain):
                custom_findings = devtools_engine.get_custom_target_findings(target_url)
                filtered = custom_findings
                if status:
                    filtered = [f for f in filtered if f.get("status", "").upper() == status.upper()]
                if category:
                    filtered = [f for f in filtered if f.get("category", "").lower() == category.lower()]
                if severity:
                    filtered = [f for f in filtered if f.get("severity", "").upper() == severity.upper()]
                return {"total": len(filtered), "findings": filtered, "target": domain, "live_scan": True}

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

    return {"total": len(findings), "findings": findings, "target": target_label}


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

    enrich_mod.ensure_table(db)
    with db.get_connection() as conn:
        arow = conn.execute(
            "SELECT analysis_json, model FROM finding_analysis WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        sources = [
            dict(x)
            for x in conn.execute(
                "SELECT tool_name, tool_version, rule_id, snippet_hash, raw_ref FROM finding_sources WHERE finding_id = ?",
                (finding_id,),
            ).fetchall()
        ]
        runs = {
            r["tool_name"]: dict(r)
            for r in conn.execute(
                "SELECT run_id, tool_name, tool_version, command_line, exit_code, raw_output_sha256, duration_seconds, created_at FROM tool_runs ORDER BY created_at"
            ).fetchall()
        }
    fd = f.model_dump()
    base = get_base_dir()
    ctx = enrich_mod.code_context(base / "target", fd.get("file"), fd.get("line_start"), fd.get("line_end"), radius=12)
    proof_file = base / "evidence" / "proof" / f"{finding_id}.png"
    return {
        "finding": fd,
        "evidence": ev_list,
        "timeline": transitions,
        "patches": patches,
        "retests": retests,
        "sources": sources,
        "analysis": json.loads(arow["analysis_json"]) if arow else None,
        "analysis_model": arow["model"] if arow else None,
        "code_context": ctx,
        "tool_run": runs.get(sources[0]["tool_name"]) if sources else None,
        "proof_url": f"/api/proof/{finding_id}.png" if proof_file.exists() else None,
    }



# ── Pipeline, enrichment, proofs and admin data ─────────────────────────────

class PipelineRequest(BaseModel):
    fresh: bool = False
    setup: bool = True


@api_app.post("/api/pipeline/start")
def pipeline_start(req: PipelineRequest):
    if not pipeline_mod.start(db, orchestrator, fresh=req.fresh, do_setup=req.setup):
        raise HTTPException(status_code=409, detail="A pipeline run is already in progress")
    return {"status": "started"}


@api_app.get("/api/pipeline/status")
def pipeline_status():
    return pipeline_mod.get_state()


@api_app.post("/api/enrich")
def run_enrichment(background: BackgroundTasks, force: bool = False):
    background.add_task(enrich_mod.enrich_findings, db, None, None, force)
    return {"status": "started"}


@api_app.post("/api/proof/build")
def run_proof_build(background: BackgroundTasks, force: bool = False):
    background.add_task(proof_mod.build_proofs, db, None, force)
    return {"status": "started"}


@api_app.get("/api/proof/{finding_id}.png")
def get_proof_image(finding_id: str):
    if not finding_id.replace("-", "").replace("_", "").isalnum():
        raise HTTPException(status_code=400, detail="bad id")
    path = get_base_dir() / "evidence" / "proof" / f"{finding_id}.png"
    if not path.exists():
        raise HTTPException(status_code=404, detail="proof image not generated yet")
    return FileResponse(path, media_type="image/png")


@api_app.get("/api/admin/overview")
def admin_overview():
    enrich_mod.ensure_table(db)
    base = get_base_dir()
    with db.get_connection() as conn:
        scans = [dict(r) for r in conn.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT 20").fetchall()]
        runs = [dict(r) for r in conn.execute("SELECT * FROM tool_runs ORDER BY created_at DESC LIMIT 60").fetchall()]
        by_tool = [dict(r) for r in conn.execute(
            "SELECT s.tool_name, count(distinct s.finding_id) AS findings FROM finding_sources s GROUP BY s.tool_name"
        ).fetchall()]
        by_sev = [dict(r) for r in conn.execute("SELECT severity, count(*) AS n FROM findings GROUP BY severity").fetchall()]
        by_status = [dict(r) for r in conn.execute("SELECT status, count(*) AS n FROM findings GROUP BY status").fetchall()]
        total = conn.execute("SELECT count(*) AS c FROM findings").fetchone()["c"]
        analysed = conn.execute("SELECT count(*) AS c FROM finding_analysis").fetchone()["c"]
        audit = [dict(r) for r in conn.execute("SELECT event_type, actor_type, actor_id, timestamp FROM audit_events ORDER BY timestamp DESC LIMIT 40").fetchall()]
    for r in runs:
        r["raw_output_path"] = Path(r["raw_output_path"]).name
        try:
            r["metrics"] = None
        except Exception:
            pass
    proofs = len(list((base / "evidence" / "proof").glob("*.png"))) if (base / "evidence" / "proof").exists() else 0
    healthy, msg = target_mgr.check_health()
    return {
        "scans": scans, "tool_runs": runs, "findings_by_tool": by_tool, "findings_by_severity": by_sev,
        "findings_by_status": by_status, "findings_total": total, "findings_analysed": analysed,
        "proof_images": proofs, "audit": audit, "target_healthy": healthy, "target_message": msg,
        "pipeline": pipeline_mod.get_state(),
    }


@api_app.get("/api/admin/runs/{run_id}/raw", response_class=PlainTextResponse)
def admin_raw_output(run_id: str):
    from wmsa.adapters.gitleaks import redact
    with db.get_connection() as conn:
        row = conn.execute("SELECT raw_output_path FROM tool_runs WHERE run_id = ?", (run_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="run not found")
    path = Path(row["raw_output_path"])
    evidence_root = (get_base_dir() / "evidence").resolve()
    if not path.exists() or evidence_root not in path.resolve().parents:
        raise HTTPException(status_code=404, detail="raw output unavailable")
    return redact(path.read_text(encoding="utf-8", errors="replace")[:200_000])


@api_app.get("/api/admin/review-notes", response_class=PlainTextResponse)
def admin_review_notes():
    files = sorted((get_base_dir() / "evidence").glob("**/gemini_review_*.md"), key=lambda p: p.stat().st_mtime)
    return files[-1].read_text(encoding="utf-8") if files else "No Gemini review has been run yet."


@api_app.post("/api/scan")
def trigger_scan(req: ScanTriggerRequest):
    with orchestrator._live_lock:
        if orchestrator.live.get("running"):
            return {"status": "already_running", **orchestrator.live, "lines": list(orchestrator.live_log)}
        orchestrator.live["running"] = True
        orchestrator.live["current"] = "starting"
        orchestrator.live["percent"] = 0

    def job() -> None:
        try:
            orchestrator.run_scan(profile_name=req.profile, selected_tools=req.tools)
        except Exception as exc:
            orchestrator.live_log.append(f"[scan] failed: {exc}")
        finally:
            with orchestrator._live_lock:
                orchestrator.live["running"] = False
                if int(orchestrator.live.get("percent") or 0) < 100:
                    orchestrator.live["current"] = "failed"

    threading.Thread(target=job, daemon=True).start()
    return {"status": "started"}


@api_app.get("/api/scan/live")
def scan_live():
    with orchestrator._live_lock:
        return {"lines": list(orchestrator.live_log), **orchestrator.live}


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
def export_report(format: str = Query("json", pattern="^(json|html|pdf)$")):
    if format == "pdf":
        pdf = proof_mod.html_to_pdf(report_exporter.export_html())
        if pdf is None:
            raise HTTPException(status_code=503, detail="PDF rendering needs Chrome/Chromium on the server")
        return Response(content=pdf, media_type="application/pdf",
                        headers={"Content-Disposition": "attachment; filename=worldmonitor_security_report.pdf"})
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


# --- Chrome DevTools Suite Endpoints ---

def _host_of(url: str) -> str:
    from urllib.parse import urlparse
    raw = url if "://" in url else f"https://{url}"
    return (urlparse(raw).hostname or "").lower()


def _require_in_scope(url: str) -> str:
    """Only loopback / manifest-approved targets may be inspected (no external scanning)."""
    try:
        return ScopeGuard(load_scope_manifest()).guard(url)
    except Exception as e:
        raise HTTPException(status_code=403, detail=f"Out of scope: {e}")


# Public website is a label. Live DevTools load the isolated clone, never production.
ISOLATED_CAPTURE_URL = "http://127.0.0.1:3000"


def _live_capture_url(target_url: str) -> str:
    host = _host_of(target_url)
    if host in {"127.0.0.1", "localhost"}:
        return _require_in_scope(target_url)
    if host and host == _host_of(load_scope_manifest().website_url):
        return _require_in_scope(ISOLATED_CAPTURE_URL)
    raise HTTPException(status_code=403, detail="Live capture is limited to the isolated target")


def _annotate_page(page: Any, target_url: str, capture_url: str) -> Any:
    if not isinstance(page, dict):
        return page
    page["captured_from"] = capture_url
    if _host_of(target_url) not in {"127.0.0.1", "localhost"}:
        page["note"] = "Public site is not opened. This capture is the isolated clone."
    return page


@api_app.get("/api/devtools/network")
def get_devtools_network(target_url: str = DEFAULT_WEBSITE_URL, refresh: bool = False):
    capture_url = _live_capture_url(target_url)
    if refresh:
        devtools_engine.get_page_info(capture_url, refresh=True)
    page = _annotate_page(devtools_engine.get_page_info(capture_url), target_url, capture_url)
    return {"requests": devtools_engine.get_network_requests(capture_url), "page": page}


@api_app.get("/api/devtools/page")
def get_devtools_page(target_url: str = DEFAULT_WEBSITE_URL):
    capture_url = _live_capture_url(target_url)
    return _annotate_page(devtools_engine.get_page_info(capture_url), target_url, capture_url)


@api_app.get("/api/devtools/security")
def get_devtools_security(target_url: str = DEFAULT_WEBSITE_URL):
    return devtools_engine.get_security_analysis(_live_capture_url(target_url))


@api_app.get("/api/devtools/performance")
def get_devtools_performance(target_url: str = DEFAULT_WEBSITE_URL):
    return devtools_engine.get_performance_telemetry(_live_capture_url(target_url))


@api_app.get("/api/devtools/storage")
def get_devtools_storage(target_url: str = DEFAULT_WEBSITE_URL):
    return devtools_engine.get_storage_audit(_live_capture_url(target_url))


@api_app.get("/api/devtools/console-log")
def get_devtools_console_log(target_url: str = DEFAULT_WEBSITE_URL):
    return devtools_engine.get_console_log(_live_capture_url(target_url))


@api_app.post("/api/devtools/console/exec")
def exec_devtools_console(req: DevToolsConsoleRequest):
    return devtools_engine.execute_console_command(req.command)


# --- Network Inspect View Endpoints ---

@api_app.get("/api/network/inspect")
def get_network_inspect(target_url: str = DEFAULT_WEBSITE_URL):
    capture_url = _live_capture_url(target_url)
    requests = devtools_engine.get_network_requests(capture_url)
    metrics = [
        {
            "id": r["id"], "name": r["name"], "path": r["path"],
            "type": "API Endpoint" if r["path"].startswith("/api") else r["type"],
            "latencyMs": r["time"], "startMs": round(r["offsetPct"]),
            "pageSize": r["size"],
            "httpStatus": r["status"], "protocol": r.get("protocol"),
            "securityStatus": "Flagged" if r.get("isVuln") else "No finding",
            "findingTag": r.get("vulnTag"), "findingDesc": r.get("vulnDesc"),
            "backendFindingId": r.get("backendFindingId"),
        }
        for r in requests
    ]
    timed = [r["time"] for r in requests if r["time"] is not None]
    perf = devtools_engine.get_performance_telemetry(capture_url)
    ttfb_val = perf.get("metrics", {}).get("ttfb", {}).get("value")
    doc = next((r for r in requests if r["type"] == "Doc"), None)
    total_kb = sum(float(r["size"].split()[0]) for r in requests if r.get("size"))
    summary = {
        "averageLatency": f"{round(sum(timed) / len(timed))} ms" if timed else "--",
        "ttfb": f"{ttfb_val} ms" if ttfb_val is not None else "--",
        "totalRequests": len(requests),
        "totalTransferSize": f"{total_kb:.1f} kB" if requests else "--",
        "httpProtocol": (doc or {}).get("protocol") or "--",
        "failedRequests": sum(1 for r in requests if r.get("failed")),
        "live": True,
        "capturedFrom": capture_url,
        "note": None if _host_of(target_url) in {"127.0.0.1", "localhost"} else "Public site is not opened. This capture is the isolated clone.",
    }
    return {"summary": summary, "metrics": metrics}


@api_app.post("/api/network/probe")
def probe_network_endpoint(req: NetworkProbeRequest):
    res = devtools_engine.execute_console_command(f"probe {req.url_or_path}")
    return res


# --- AI Security Copilot (RAG + NLP) Endpoints ---

@api_app.post("/api/copilot/chat")
def copilot_chat(req: CopilotChatRequest):
    from wmsa import copilot_chat as copilot_mod
    return copilot_mod.answer(db, req.prompt, req.finding_id)


@api_app.get("/api/copilot/recommendations")
def get_copilot_recommendations():
    from wmsa import copilot_chat as copilot_mod
    return {"recommendations": copilot_mod.recommendations(db)}


# --- Attack Surface & Threat Radar Telemetry Endpoints ---

@api_app.get("/api/telemetry/attack-surface")
def get_attack_surface():
    return dashboard_mod.attack_surface(db)


@api_app.get("/api/telemetry/radar")
def get_telemetry_radar():
    return dashboard_mod.radar(db)


DEFAULT_TARGET_URL = "http://127.0.0.1:3000"


@api_app.get("/api/dashboard/summary")
def dashboard_summary():
    healthy, msg = target_mgr.check_health()
    return dashboard_mod.build_summary(db, DEFAULT_TARGET_URL, healthy, msg)


class WebAuditRequest(BaseModel):
    url: Optional[str] = None


@api_app.post("/api/webaudit/run")
def webaudit_run(req: WebAuditRequest):
    if not webaudit_mod.start_background(req.url or DEFAULT_TARGET_URL):
        raise HTTPException(status_code=409, detail="A web audit is already running")
    return {"status": "started"}


@api_app.get("/api/webaudit/status")
def webaudit_status():
    return {**webaudit_mod.get_status(), "latest": webaudit_mod.latest()}
