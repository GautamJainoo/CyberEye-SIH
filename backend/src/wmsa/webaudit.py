"""
Real web-quality audit (Lighthouse) of the in-scope target.

Replaces every invented Performance / Accessibility / Best-Practices / SEO / Core-Web-Vitals number
on the dashboard. Runs the Lighthouse CLI against the loopback target (checked by the scope guard),
stores the compact result as JSON under evidence/audits/, and keeps a history so trends are real too.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from wmsa.paths import get_base_dir
from wmsa.scope import ScopeGuard, load_scope_manifest

LIGHTHOUSE_SPEC = "lighthouse@13"
CATEGORIES = ["performance", "accessibility", "best-practices", "seo"]

_state: Dict[str, Any] = {"running": False, "error": None, "started_at": None}
_lock = threading.Lock()


def audits_dir(base: Optional[Path] = None) -> Path:
    d = (base or get_base_dir()) / "evidence" / "audits"
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_status() -> Dict[str, Any]:
    with _lock:
        return dict(_state)


def _compact(raw: Dict[str, Any], url: str) -> Dict[str, Any]:
    audits = raw.get("audits", {})

    def num(key: str) -> Optional[float]:
        v = audits.get(key, {}).get("numericValue")
        return round(v, 3) if isinstance(v, (int, float)) else None

    cats = {k.replace("-", "_"): (round(v["score"] * 100) if v.get("score") is not None else None)
            for k, v in raw.get("categories", {}).items()}

    # What Lighthouse says needs work, grouped by category (real "how to improve" content).
    issues: List[Dict[str, Any]] = []
    for cat_id, cat in raw.get("categories", {}).items():
        for ref in cat.get("auditRefs", []):
            a = audits.get(ref.get("id"), {})
            score = a.get("score")
            if score is None or score >= 0.9 or a.get("scoreDisplayMode") in ("notApplicable", "informative", "manual"):
                continue
            issues.append({
                "category": cat_id.replace("-", "_"), "id": ref["id"], "title": a.get("title"),
                "score": round(score, 2), "display": a.get("displayValue"),
                "description": (a.get("description") or "").split(" [")[0][:240],
            })
    issues.sort(key=lambda i: (i["score"], i["category"]))

    main_thread = [
        {"group": i.get("group"), "label": i.get("groupLabel"), "ms": round(i.get("duration", 0))}
        for i in audits.get("mainthread-work-breakdown", {}).get("details", {}).get("items", [])
    ]
    requests = audits.get("network-requests", {}).get("details", {}).get("items", [])
    return {
        "audit_id": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S"),
        "url": url,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "lighthouse_version": raw.get("lighthouseVersion"),
        "categories": cats,
        "metrics": {
            "fcp_ms": num("first-contentful-paint"), "lcp_ms": num("largest-contentful-paint"),
            "cls": num("cumulative-layout-shift"), "tbt_ms": num("total-blocking-time"),
            "speed_index_ms": num("speed-index"), "tti_ms": num("interactive"),
            "ttfb_ms": num("server-response-time"),
        },
        "page": {
            "requests": len(requests),
            "transfer_kb": round(sum(r.get("transferSize", 0) for r in requests) / 1024, 1),
        },
        "main_thread": main_thread,
        "issues": issues[:25],
    }


def run_audit(url: str, base_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Run Lighthouse against an in-scope URL; raises on any failure (never returns invented data)."""
    base = base_dir or get_base_dir()
    ScopeGuard(load_scope_manifest(base / "config" / "scope.yaml"), base).guard(url)  # loopback only

    npx = shutil.which("npx")
    if not npx:
        raise RuntimeError("npx not found; Node.js is required to run Lighthouse")
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "lh.json"
        cmd = [
            npx, "--yes", LIGHTHOUSE_SPEC, url, "--quiet", "--output=json", f"--output-path={out}",
            f"--only-categories={','.join(CATEGORIES)}",
            "--chrome-flags=--headless=new --no-sandbox --disable-gpu",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if not out.exists():
            raise RuntimeError(f"Lighthouse produced no report (exit {res.returncode}): {(res.stderr or res.stdout)[-300:]}")
        raw = json.loads(out.read_text())
    if raw.get("runtimeError"):
        raise RuntimeError(f"Lighthouse runtime error: {raw['runtimeError'].get('message', '')[:200]}")

    result = _compact(raw, url)
    (audits_dir(base) / f"{result['audit_id']}.json").write_text(json.dumps(result, indent=2))
    return result


def start_background(url: str) -> bool:
    with _lock:
        if _state["running"]:
            return False
        _state.update(running=True, error=None, started_at=datetime.now(timezone.utc).isoformat())

    def work() -> None:
        try:
            run_audit(url)
        except Exception as e:
            with _lock:
                _state["error"] = str(e)[:300]
        finally:
            with _lock:
                _state["running"] = False

    threading.Thread(target=work, daemon=True).start()
    return True


def history(base: Optional[Path] = None, limit: int = 20) -> List[Dict[str, Any]]:
    files = sorted(audits_dir(base).glob("*.json"))[-limit:]
    out = []
    for f in files:
        try:
            out.append(json.loads(f.read_text()))
        except Exception:
            continue
    return out


def latest(base: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    h = history(base, limit=1)
    return h[-1] if h else None
