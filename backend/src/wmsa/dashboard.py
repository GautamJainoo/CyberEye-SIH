"""
Dashboard aggregates computed from REAL stored data only (findings, tool runs, audit log, raw outputs).

Nothing here is invented: when there is no data the values are zero / empty and the UI says so.
"""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from wmsa import webaudit
from wmsa.db import Database
from wmsa.paths import get_base_dir

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_WEIGHT = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 3, "LOW": 1, "INFO": 0}
# A finding only counts fully once an analyst verified it; unverified scanner output counts less.
STATUS_FACTOR = {"VERIFIED": 1.0, "PATCH_PROPOSED": 1.0, "PATCH_APPLIED": 1.0, "RETEST_PENDING": 1.0,
                 "NOT_FIXED": 1.0, "REGRESSION": 1.0, "TRIAGED": 0.6, "NEEDS_REVIEW": 0.6,
                 "CANDIDATE": 0.3, "INCONCLUSIVE": 0.3, "ACCEPTED_RISK": 0.1}
TOOL_LABEL = {"semgrep": "Semgrep (SAST)", "gitleaks": "Gitleaks (secrets)", "osv-scanner": "OSV-Scanner (SCA)",
              "zap": "OWASP ZAP (DAST)", "worldmonitor-probes": "World Monitor probes",
              "gemini-review": "Gemini code review"}
EXPECTED_TOOLS = list(TOOL_LABEL)

RISK_FORMULA = ("risk = 100 * (1 - exp(-x / 150)), x = sum(severity_weight * status_factor) with weights "
                "CRITICAL 25, HIGH 10, MEDIUM 3, LOW 1 and factors VERIFIED 1.0, TRIAGED 0.6, CANDIDATE 0.3. "
                "Unverified scanner output therefore counts less than analyst-verified findings.")

RADAR_AXES = ["Authentication & sessions", "Authorization & access control", "Input validation & injection",
              "API security", "Client-side controls", "Secure communication", "Secrets & data storage",
              "Dependencies"]


def _weighted(rows: List[Dict[str, Any]]) -> float:
    return sum(SEV_WEIGHT.get(str(r["severity"]).upper(), 0) * STATUS_FACTOR.get(r["status"], 0.0) for r in rows)


def risk_score(rows: List[Dict[str, Any]]) -> int:
    return round(100 * (1 - math.exp(-_weighted(rows) / 150))) if rows else 0


def risk_level(score: int) -> str:
    return "None" if score == 0 else "Low" if score < 25 else "Medium" if score < 50 else "High" if score < 75 else "Critical"


def _load_findings(db: Database) -> List[Dict[str, Any]]:
    with db.get_connection() as conn:
        rows = conn.execute(
            "SELECT f.finding_id, f.status, f.severity, f.category, f.data_json, f.created_at, "
            "(SELECT s.tool_name FROM finding_sources s WHERE s.finding_id = f.finding_id LIMIT 1) AS tool "
            "FROM findings f"
        ).fetchall()
    out = []
    for r in rows:
        d = json.loads(r["data_json"])
        out.append({"finding_id": r["finding_id"], "status": r["status"], "severity": str(r["severity"]).upper(),
                    "category": r["category"], "tool": r["tool"], "created_at": r["created_at"], **{
                        k: d.get(k) for k in ("title", "file", "endpoint", "cwe", "package", "line_start")}})
    return out


def area_of(f: Dict[str, Any]) -> Dict[str, str]:
    tool, cat = f.get("tool"), f.get("category")
    if cat == "sca":
        return {"id": "deps", "label": "Dependencies (lockfiles)", "kind": "dependencies"}
    if cat == "secret":
        return {"id": "secrets", "label": "Secrets & configuration", "kind": "secrets"}
    if tool in ("zap", "worldmonitor-probes") or (f.get("endpoint") and not f.get("file")):
        return {"id": "runtime", "label": "Running application (HTTP)", "kind": "runtime"}
    path = (f.get("file") or "").replace("target/", "", 1)
    top = path.split("/")[0] if "/" in path else (path or "unknown")
    return {"id": f"src:{top}", "label": f"{top}/ (source)" if "/" in path else top, "kind": "source"}


def attack_surface(db: Database) -> Dict[str, Any]:
    nodes: Dict[str, Dict[str, Any]] = {}
    for f in _load_findings(db):
        a = area_of(f)
        n = nodes.setdefault(a["id"], {**a, "findings": 0, "max_severity": "INFO", "top": []})
        n["findings"] += 1
        if SEVERITIES.index(f["severity"]) < SEVERITIES.index(n["max_severity"]):
            n["max_severity"] = f["severity"]
        n["top"].append({"finding_id": f["finding_id"], "title": f["title"], "severity": f["severity"]})
    for n in nodes.values():
        n["top"].sort(key=lambda t: SEVERITIES.index(t["severity"]))
        n["top"] = n["top"][:4]
        n["status"] = "vulnerable" if n["max_severity"] in ("CRITICAL", "HIGH") else "warning"
    ordered = sorted(nodes.values(), key=lambda n: (SEVERITIES.index(n["max_severity"]), -n["findings"]))
    return {"nodes": ordered}


def _axis(f: Dict[str, Any]) -> str:
    text = " ".join([f.get("title") or "", " ".join(f.get("cwe") or []), f.get("file") or "", f.get("endpoint") or ""]).lower()
    cwes = " ".join(f.get("cwe") or [])
    if f.get("category") == "secret":
        return RADAR_AXES[6]
    if f.get("category") == "sca":
        return RADAR_AXES[7]
    if any(k in text for k in ("oauth", "session", "login", "jwt", "token", "cwe-287", "cwe-290", "cwe-347")):
        return RADAR_AXES[0]
    if any(k in text for k in ("authoriz", "access control", "entitle", "premium", "tenant", "cwe-285", "cwe-862", "cwe-639")):
        return RADAR_AXES[1]
    if any(k in text for k in ("xss", "innerhtml", "inject", "sanitiz", "ssrf", "cwe-79", "cwe-918", "cwe-89", "cwe-116")):
        return RADAR_AXES[2]
    if any(k in text for k in ("csp", "content security", "x-frame", "clickjack", "sub resource", "cross-domain javascript")):
        return RADAR_AXES[4]
    if any(k in text for k in ("hsts", "tls", "https", "strict-transport", "cwe-319")):
        return RADAR_AXES[5]
    if any(k in text for k in ("cors", "rate", "api", "webhook", "proxy", "cwe-942", "cwe-770")) or f.get("endpoint"):
        return RADAR_AXES[3]
    if "cwe-1021" in cwes:
        return RADAR_AXES[4]
    return RADAR_AXES[3]


def radar(db: Database) -> Dict[str, Any]:
    by_axis: Dict[str, List[Dict[str, Any]]] = {a: [] for a in RADAR_AXES}
    for f in _load_findings(db):
        by_axis[_axis(f)].append(f)
    return {
        "radar": [{"label": a, "value": round(100 * math.exp(-_weighted(rows) / 60)) if rows else 100,
                   "maxValue": 100, "findings": len(rows)} for a, rows in by_axis.items()],
        "method": "value = 100 * exp(-x / 60) per SIH scope area, x = severity-weighted, status-weighted findings "
                  "mapped by CWE / keywords. 100 means no findings recorded in that area (not proof of safety).",
    }


def _distinct_urls(db: Database) -> int:
    urls = set()
    with db.get_connection() as conn:
        runs = conn.execute("SELECT tool_name, raw_output_path FROM tool_runs").fetchall()
    for r in runs:
        p = Path(r["raw_output_path"])
        try:
            data = json.loads(p.read_text())
        except Exception:
            continue
        if r["tool_name"] == "zap":
            for site in data.get("site", []):
                for alert in site.get("alerts", []):
                    urls.update(i.get("uri") for i in alert.get("instances", []) if i.get("uri"))
        elif r["tool_name"] == "worldmonitor-probes":
            for entry in data.get("results", []):
                try:
                    recs = json.loads(Path(entry["evidence_path"]).read_text())["records"]
                    urls.update(x.get("url") for x in recs if x.get("url"))
                except Exception:
                    continue
    return len(urls)


def activity(db: Database, limit: int = 12) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    with db.get_connection() as conn:
        runs = conn.execute("SELECT tool_name, tool_version, duration_seconds, created_at, exit_code FROM tool_runs").fetchall()
        counts = {r["tool_name"]: r["n"] for r in conn.execute(
            "SELECT tool_name, count(distinct finding_id) AS n FROM finding_sources GROUP BY tool_name").fetchall()}
        live_ids = {r["finding_id"] for r in conn.execute("SELECT finding_id FROM findings").fetchall()}
        events = conn.execute("SELECT event_type, actor_type, actor_id, payload_json, timestamp FROM audit_events "
                              "WHERE event_type IN ('state_transition','unauthorized_transition_attempt','patch_proposed','retest_completed') "
                              "ORDER BY timestamp DESC LIMIT 30").fetchall()
    latest_run: Dict[str, Any] = {}
    for r in sorted(runs, key=lambda x: x["created_at"]):
        latest_run[r["tool_name"]] = r  # counts are per tool, so only the newest run of each is accurate
    for r in latest_run.values():
        items.append({"type": "scan", "message": f"{TOOL_LABEL.get(r['tool_name'], r['tool_name'])} finished",
                      "detail": f"{counts.get(r['tool_name'], 0)} finding(s) in {round(r['duration_seconds'] or 0)}s",
                      "timestamp": r["created_at"]})
    for e in events:
        try:
            p = json.loads(e["payload_json"])
        except Exception:
            p = {}
        # The audit log is append-only; hide events about findings that no longer exist (e.g. purged data).
        if p.get("finding_id") and p["finding_id"] not in live_ids:
            continue
        if e["event_type"] == "state_transition":
            msg, typ = f"Finding moved {p.get('from_status')} -> {p.get('to_status')}", "fix" if p.get("to_status") == "FIXED" else "vuln"
        elif e["event_type"] == "unauthorized_transition_attempt":
            msg, typ = f"Blocked: {e['actor_type']} tried to set {p.get('target_status')}", "vuln"
        else:
            msg, typ = e["event_type"].replace("_", " ").capitalize(), "report"
        items.append({"type": typ, "message": msg, "detail": f"by {e['actor_type']}:{e['actor_id']}", "timestamp": e["timestamp"]})
    for a in webaudit.history(limit=5):
        items.append({"type": "report", "message": "Web audit (Lighthouse) completed",
                      "detail": f"Performance {a['categories'].get('performance')}, Accessibility "
                                f"{a['categories'].get('accessibility')}", "timestamp": a["finished_at"]})
    items.sort(key=lambda i: i["timestamp"], reverse=True)
    return items[:limit]


def notifications(db: Database, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    severe = sorted([f for f in findings if f["severity"] in ("CRITICAL", "HIGH")],
                    key=lambda f: (SEVERITIES.index(f["severity"]), f["created_at"] or ""))[:5]
    for f in severe:
        out.append({"id": f["finding_id"], "type": "vuln", "title": f"{f['severity']}: {f['title']}",
                    "detail": f"{TOOL_LABEL.get(f['tool'], f['tool'])} - unverified candidate", "timestamp": f["created_at"],
                    "finding_id": f["finding_id"]})
    with db.get_connection() as conn:
        scan = conn.execute("SELECT scan_id, end_time, metrics_json FROM scans ORDER BY created_at DESC LIMIT 1").fetchone()
    if scan and scan["metrics_json"]:
        failed = json.loads(scan["metrics_json"]).get("tools_failed") or {}
        for tool, err in failed.items():
            out.append({"id": f"fail-{tool}", "type": "scan", "title": f"{TOOL_LABEL.get(tool, tool)} did not complete",
                        "detail": str(err)[:140], "timestamp": scan["end_time"]})
    return out


def build_summary(db: Database, target_url: str, target_healthy: bool, target_message: str) -> Dict[str, Any]:
    findings = _load_findings(db)
    by_sev = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    by_status: Dict[str, int] = {}
    by_tool: Dict[str, int] = {}
    for f in findings:
        by_status[f["status"]] = by_status.get(f["status"], 0) + 1
        by_tool[f["tool"] or "unknown"] = by_tool.get(f["tool"] or "unknown", 0) + 1
    with db.get_connection() as conn:
        runs = conn.execute("SELECT tool_name, MAX(created_at) AS last FROM tool_runs GROUP BY tool_name").fetchall()
        last_scan = conn.execute("SELECT scan_id, status, end_time FROM scans ORDER BY created_at DESC LIMIT 1").fetchone()
    tools_run = sorted(r["tool_name"] for r in runs)
    score = risk_score(findings)
    return {
        "target": {"url": target_url, "healthy": target_healthy, "message": target_message},
        "findings": {"total": len(findings), "by_severity": by_sev, "by_status": by_status, "by_tool": by_tool},
        "risk": {"score": score, "level": risk_level(score), "security_score": 100 - score, "formula": RISK_FORMULA},
        "coverage": {"tools_run": tools_run, "tools_expected": EXPECTED_TOOLS,
                     "tools_missing": [t for t in EXPECTED_TOOLS if t not in tools_run],
                     "last_scan": dict(last_scan) if last_scan else None,
                     "last_run_at": max((r["last"] for r in runs), default=None)},
        "endpoints_tested": _distinct_urls(db),
        "activity": activity(db),
        "notifications": notifications(db, findings),
        "web_audit": webaudit.latest(),
        "web_audit_history": [{"finished_at": a["finished_at"], **a["categories"]} for a in webaudit.history(limit=12)],
    }
