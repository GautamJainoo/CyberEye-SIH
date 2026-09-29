"""
Real browser capture via the Chrome DevTools Protocol (headless Chrome, loopback targets only).

Records what a browser actually does when it loads the page: every network request with its true
status, size and timing, cookies with their real flags, localStorage / sessionStorage, service
workers and console output. This replaces any assumed or hardcoded DevTools data.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from websockets.sync.client import connect

from wmsa.adapters.gitleaks import redact
from wmsa.paths import get_base_dir
from wmsa.scope import ScopeGuard, load_scope_manifest

_CACHE: Dict[str, Any] = {}
_LOCK = threading.Lock()
CACHE_TTL = 90.0

_SENSITIVE_KEY = ("token", "secret", "jwt", "auth", "password", "passwd", "apikey", "api_key", "session", "credential")


def _chrome() -> Optional[str]:
    for n in ("google-chrome", "google-chrome-stable", "chromium-browser", "chromium"):
        p = shutil.which(n)
        if p:
            return p
    return None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Session:
    def __init__(self, ws):
        self.ws, self._id, self.events = ws, 0, []

    def call(self, method: str, params: Optional[Dict[str, Any]] = None, timeout: float = 20.0) -> Dict[str, Any]:
        self._id += 1
        mid = self._id
        self.ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                msg = json.loads(self.ws.recv(timeout=max(0.1, deadline - time.time())))
            except TimeoutError:
                break
            if msg.get("id") == mid:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error'].get('message')}")
                return msg.get("result", {})
            if "method" in msg:
                self.events.append(msg)
        raise TimeoutError(f"CDP call {method} timed out")

    def drain(self, seconds: float) -> None:
        end = time.time() + seconds
        while time.time() < end:
            try:
                msg = json.loads(self.ws.recv(timeout=max(0.05, end - time.time())))
            except TimeoutError:
                break
            if "method" in msg:
                self.events.append(msg)


def _cookie_status(c: Dict[str, Any]) -> Dict[str, Any]:
    issues = []
    if not c.get("httpOnly"):
        issues.append("Missing HttpOnly")
    if not c.get("secure"):
        issues.append("Missing Secure")
    ss = c.get("sameSite")
    if not ss:
        issues.append("No SameSite attribute")
    elif ss == "None" and not c.get("secure"):
        issues.append("SameSite=None without Secure")
    return {
        "name": c.get("name"), "domain": c.get("domain"), "path": c.get("path", "/"),
        "httpOnly": bool(c.get("httpOnly")), "secure": bool(c.get("secure")), "sameSite": ss or "Not Set",
        "status": "Secure" if not issues else f"Warning ({', '.join(issues)})",
    }


def _storage_entries(raw: Dict[str, str]) -> List[Dict[str, Any]]:
    out = []
    for k, v in (raw or {}).items():
        looks_jwt = isinstance(v, str) and v.count(".") == 2 and v.startswith("ey")
        sensitive = looks_jwt or any(w in k.lower() for w in _SENSITIVE_KEY)
        shown = redact(v)[:60] + ("..." if len(v) > 60 else "")
        out.append({
            "key": k, "value": "[REDACTED]" if sensitive else shown, "isSensitive": sensitive,
            "cwe": "CWE-922" if sensitive else None, "risk": "Review" if sensitive else "None",
            "description": ("Credential-like data persisted in web storage - readable by any script on the page (XSS impact)"
                            if sensitive else "Non-sensitive preference or cache entry"),
            "fix": "Keep session credentials in HttpOnly, Secure, SameSite cookies" if sensitive else None, "live": True,
        })
    return out


def capture_page(url: str, settle_seconds: float = 5.0, use_cache: bool = True) -> Dict[str, Any]:
    base = get_base_dir()
    ScopeGuard(load_scope_manifest(base / "config" / "scope.yaml"), base).guard(url)  # loopback only

    with _LOCK:
        hit = _CACHE.get(url)
        if use_cache and hit and time.time() - hit[0] < CACHE_TTL:
            return hit[1]

    chrome = _chrome()
    if not chrome:
        raise RuntimeError("Chrome/Chromium not found")
    port = _free_port()
    with tempfile.TemporaryDirectory() as tmp:
        proc = subprocess.Popen(
            [chrome, "--headless=new", "--no-sandbox", "--disable-gpu", f"--remote-debugging-port={port}",
             f"--user-data-dir={tmp}", "about:blank"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            ws_url = None
            for _ in range(60):
                try:
                    targets = httpx.get(f"http://127.0.0.1:{port}/json/list", timeout=1).json()
                    page = next((t for t in targets if t.get("type") == "page"), None)
                    if page:
                        ws_url = page["webSocketDebuggerUrl"]
                        break
                except Exception:
                    pass
                time.sleep(0.25)
            if not ws_url:
                raise RuntimeError("Chrome DevTools endpoint did not start")

            with connect(ws_url, max_size=None, open_timeout=10) as ws:
                s = _Session(ws)
                for m in ("Network.enable", "Page.enable", "Runtime.enable", "Log.enable", "Performance.enable"):
                    s.call(m)
                s.call("Network.setCacheDisabled", {"cacheDisabled": True})
                s.call("Page.navigate", {"url": url})
                load_ts = None
                t_end = time.time() + 25
                while time.time() < t_end and load_ts is None:
                    s.drain(0.5)
                    for e in s.events:
                        if e["method"] == "Page.loadEventFired":
                            load_ts = e["params"]["timestamp"]
                s.drain(settle_seconds)  # late XHR / fetch after load

                cookies = s.call("Network.getAllCookies").get("cookies", [])
                perf_metrics = {m["name"]: m["value"] for m in s.call("Performance.getMetrics").get("metrics", [])}

                def evaluate(expr: str, await_promise: bool = False) -> Any:
                    r = s.call("Runtime.evaluate", {"expression": expr, "returnByValue": True, "awaitPromise": await_promise})
                    return r.get("result", {}).get("value")

                local = evaluate("JSON.stringify(Object.fromEntries(Object.entries(localStorage)))") or "{}"
                session = evaluate("JSON.stringify(Object.fromEntries(Object.entries(sessionStorage)))") or "{}"
                workers = evaluate(
                    "navigator.serviceWorker ? navigator.serviceWorker.getRegistrations().then(rs => JSON.stringify(rs.map(r => "
                    "({scope: r.scope, script: (r.active||r.waiting||r.installing||{}).scriptURL, state: (r.active||{}).state})))) : '[]'",
                    await_promise=True) or "[]"
                title = evaluate("document.title")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()

    # ---- assemble the real waterfall ----
    reqs: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    console: List[Dict[str, str]] = []
    first_ts = None
    dcl_ts = None
    for e in s.events:
        m, p = e["method"], e.get("params", {})
        if m == "Network.requestWillBeSent":
            rid = p["requestId"]
            if rid in reqs:  # redirect hop: keep the latest URL
                reqs[rid]["url"] = p["request"]["url"]
                continue
            first_ts = p["timestamp"] if first_ts is None else first_ts
            init = p.get("initiator", {})
            reqs[rid] = {"id": rid, "url": p["request"]["url"], "method": p["request"]["method"], "type": p.get("type", "Other"),
                         "start": p["timestamp"], "initiator": (init.get("url") or init.get("type") or "other"),
                         "initiator_line": init.get("lineNumber"), "status": None, "mime": None, "protocol": None,
                         "transfer": None, "end": None, "failed": None}
            order.append(rid)
        elif m == "Network.responseReceived" and p["requestId"] in reqs:
            r = reqs[p["requestId"]]
            r.update(status=p["response"]["status"], mime=p["response"].get("mimeType"), protocol=p["response"].get("protocol"))
        elif m == "Network.loadingFinished" and p["requestId"] in reqs:
            reqs[p["requestId"]].update(transfer=p.get("encodedDataLength"), end=p["timestamp"])
        elif m == "Network.loadingFailed" and p["requestId"] in reqs:
            reqs[p["requestId"]].update(failed=p.get("errorText"), end=p["timestamp"])
        elif m == "Page.domContentEventFired":
            dcl_ts = p["timestamp"]
        elif m == "Runtime.consoleAPICalled":
            console.append({"level": p.get("type", "log"), "text": " ".join(str(a.get("value", a.get("description", ""))) for a in p.get("args", []))[:300]})
        elif m == "Runtime.exceptionThrown":
            console.append({"level": "error", "text": (p.get("exceptionDetails", {}).get("text") or "exception")[:300]})
        elif m == "Log.entryAdded":
            console.append({"level": p["entry"].get("level", "info"), "text": p["entry"].get("text", "")[:300]})

    t0 = first_ts or 0.0
    requests_out = []
    for rid in order:
        r = reqs[rid]
        pu = urllib.parse.urlparse(r["url"])
        requests_out.append({
            "id": rid, "url": r["url"], "name": pu.path.rsplit("/", 1)[-1] or pu.netloc, "path": pu.path or "/",
            "host": pu.netloc, "method": r["method"], "status": r["status"], "type": r["type"], "mime": r["mime"],
            "protocol": r["protocol"], "transfer_bytes": r["transfer"], "failed": r["failed"],
            "start_ms": round((r["start"] - t0) * 1000), "duration_ms": round((r["end"] - r["start"]) * 1000) if r["end"] else None,
            "initiator": r["initiator"], "initiator_line": r["initiator_line"],
        })

    result = {
        "page_url": url, "title": title, "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "load_ms": round((load_ts - t0) * 1000) if load_ts and first_ts else None,
        "dcl_ms": round((dcl_ts - t0) * 1000) if dcl_ts and first_ts else None,
        "span_ms": max([r["start_ms"] + (r["duration_ms"] or 0) for r in requests_out] + [0]),
        "memory": {
            "js_heap_used_mb": round(perf_metrics.get("JSHeapUsedSize", 0) / 1048576, 1),
            "js_heap_total_mb": round(perf_metrics.get("JSHeapTotalSize", 0) / 1048576, 1),
            "dom_nodes": int(perf_metrics.get("Nodes", 0)), "documents": int(perf_metrics.get("Documents", 0)),
            "frames": int(perf_metrics.get("Frames", 0)), "js_event_listeners": int(perf_metrics.get("JSEventListeners", 0)),
            "layout_count": int(perf_metrics.get("LayoutCount", 0)), "script_duration_ms": round(perf_metrics.get("ScriptDuration", 0) * 1000),
            "layout_duration_ms": round(perf_metrics.get("LayoutDuration", 0) * 1000),
            "recalc_style_ms": round(perf_metrics.get("RecalcStyleDuration", 0) * 1000),
        },
        "requests": requests_out,
        "cookies": [_cookie_status(c) for c in cookies],
        "local_storage": _storage_entries(json.loads(local)),
        "session_storage": _storage_entries(json.loads(session)),
        "service_workers": json.loads(workers),
        "console": console[:200],
    }
    with _LOCK:
        _CACHE[url] = (time.time(), result)
    return result
