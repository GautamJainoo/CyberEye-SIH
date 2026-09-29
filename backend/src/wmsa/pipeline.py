"""
End-to-end assessment pipeline: setup -> Gemini review -> Semgrep -> Gitleaks -> OSV -> ZAP -> probes
-> Groq enrichment -> proof images. Runs in a background thread; state is polled via the API.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from wmsa.db import Database

STEPS = [
    ("setup", "Set up target locally (Gemini-planned, guard-checked)"),
    ("review", "Manual code review (Gemini)"),
    ("semgrep", "Semgrep SAST"),
    ("gitleaks", "Gitleaks secrets"),
    ("osv", "OSV-Scanner dependencies"),
    ("zap", "OWASP ZAP DAST"),
    ("probes", "World Monitor probes"),
    ("audit", "Web audit: performance, accessibility, SEO (Lighthouse)"),
    ("enrich", "Normalize + explain findings (Groq)"),
    ("proof", "Generate proof images"),
]
SCAN_TOOLS = ["review", "semgrep", "gitleaks", "osv", "zap", "probes"]

_state: Dict[str, Any] = {"running": False, "steps": [], "started_at": None, "finished_at": None, "log": []}
_lock = threading.Lock()


def get_state() -> Dict[str, Any]:
    with _lock:
        return {**_state, "steps": [dict(s) for s in _state["steps"]], "log": list(_state["log"][-80:])}


def _set(step: str, status: str, detail: str = "") -> None:
    with _lock:
        for s in _state["steps"]:
            if s["id"] == step:
                s["status"], s["detail"] = status, detail
                if status == "running":
                    s["started_at"] = datetime.now(timezone.utc).isoformat()
                if status in ("done", "failed", "skipped"):
                    s["finished_at"] = datetime.now(timezone.utc).isoformat()
        _state["log"].append(f"{datetime.now(timezone.utc).strftime('%H:%M:%S')} {step}: {status} {detail}".strip())


def start(db: Database, orchestrator, fresh: bool = True, do_setup: bool = True) -> bool:
    with _lock:
        if _state["running"]:
            return False
        _state.update(
            running=True, started_at=datetime.now(timezone.utc).isoformat(), finished_at=None, log=[],
            steps=[{"id": i, "label": l, "status": "pending", "detail": ""} for i, l in STEPS],
        )
    threading.Thread(target=_run, args=(db, orchestrator, fresh, do_setup), daemon=True).start()
    return True


def _run(db: Database, orchestrator, fresh: bool, do_setup: bool) -> None:
    from wmsa import enrich, proof, setup_assistant

    try:
        if fresh:
            db.purge_assessment_data()
            from wmsa.paths import get_base_dir
            for old in (get_base_dir() / "evidence" / "proof").glob("*.png"):
                old.unlink(missing_ok=True)  # stale proofs of purged findings
        if do_setup:
            _set("setup", "running")
            try:
                plan = setup_assistant.plan_setup()
                result = setup_assistant.apply_setup(plan)
                _state["setup"] = {"plan": plan, "result": result}
                _set("setup", "done" if result["healthy"] else "failed",
                     f"plan by {plan['source']}; healthy={result['healthy']}; rejected={len(result['rejected_by_guard'])}")
            except Exception as e:
                _set("setup", "failed", str(e)[:200])
        else:
            _set("setup", "skipped")

        def on_progress(tool: str, status: str, detail: str) -> None:
            _set(tool, status, detail)

        result = orchestrator.run_scan("standard", selected_tools=SCAN_TOOLS, progress=on_progress)
        with _lock:
            _state["scan"] = {k: v for k, v in result.items() if k != "tool_runs"}
            for tool in SCAN_TOOLS:
                if any(s["id"] == tool and s["status"] in ("pending", "running") for s in _state["steps"]):
                    _set(tool, "skipped", "not executed")

        _set("audit", "running")
        try:
            from wmsa import webaudit
            res = webaudit.run_audit("http://127.0.0.1:3000")
            _set("audit", "done", "scores " + ", ".join(f"{k}={v}" for k, v in res["categories"].items()))
        except Exception as e:
            _set("audit", "failed", str(e)[:200])

        _set("enrich", "running")
        try:
            stats = enrich.enrich_findings(db=db, progress=lambda m: _set("enrich", "running", m))
            _set("enrich", "done", str(stats))
        except Exception as e:
            _set("enrich", "failed", str(e)[:200])

        _set("proof", "running")
        try:
            stats = proof.build_proofs(db=db)
            _set("proof", "done" if not stats.get("error") else "failed", str(stats))
        except Exception as e:
            _set("proof", "failed", str(e)[:200])
    finally:
        with _lock:
            _state["running"] = False
            _state["finished_at"] = datetime.now(timezone.utc).isoformat()
