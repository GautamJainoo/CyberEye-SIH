"""
Chrome DevTools & Network Telemetry Diagnostic Engine for WMSA.

All methods perform REAL live scanning of the given target URL using the
LiveScanner module.  No domain-specific branching (is_amazon / is_wm).
World Monitor (SIH 26163) findings remain in the database and are served
directly from it.  Any other URL gets live scanning results.
"""

from __future__ import annotations

import json
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from wmsa.db import Database
from wmsa import webaudit
from wmsa.cdp import capture_page
from wmsa.live_scanner import LiveScanner, _normalize_url
from wmsa.scope import ScopeGuard, ScopeManifest, load_scope_manifest


def _rate(value: Optional[float], good: float, poor: float) -> str:
    if value is None:
        return "Not measured"
    return "Good" if value <= good else "Needs Improvement" if value <= poor else "Poor"


def _lighthouse_metrics() -> Dict[str, Any]:
    """Core Web Vitals from the latest real Lighthouse run. INP is a field metric and cannot be lab-measured."""
    a = webaudit.latest()
    m = (a or {}).get("metrics", {})
    lcp = None if m.get("lcp_ms") is None else round(m["lcp_ms"] / 1000, 2)
    fcp = None if m.get("fcp_ms") is None else round(m["fcp_ms"] / 1000, 2)
    cls = m.get("cls")
    tbt = m.get("tbt_ms")
    return {
        "lcp": {"value": lcp, "unit": "s", "status": _rate(lcp, 2.5, 4.0), "threshold": 2.5, "score": None},
        "cls": {"value": cls, "unit": "", "status": _rate(cls, 0.1, 0.25), "threshold": 0.1, "score": None},
        "fcp": {"value": fcp, "unit": "s", "status": _rate(fcp, 1.8, 3.0), "threshold": 1.8, "score": None},
        "tbt": {"value": None if tbt is None else round(tbt), "unit": "ms", "status": _rate(tbt, 200, 600), "threshold": 200, "score": None},
        "inp": {"value": None, "unit": "ms", "status": "Not measurable in lab (needs real user input)", "threshold": 200, "score": None},
        "lighthouse_at": (a or {}).get("finished_at"),
    }


class DevToolsEngine:
    """Engine providing live telemetry for Chrome DevTools Suite and Network Inspect views."""

    def __init__(
        self,
        db: Optional[Database] = None,
        scope_manifest: Optional[ScopeManifest] = None,
    ):
        self.db = db or Database()
        self.manifest = scope_manifest or load_scope_manifest()
        self._scanner = LiveScanner()

    # ──────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────

    def _is_worldmonitor(self, domain: str) -> bool:
        """Return True only for the SIH 26163 primary target."""
        return (
            "worldmonitor" in domain.lower()
            or "127.0.0.1" in domain
            or "localhost" in domain
        )

    def _classify_asset(self, path: str) -> str:
        lower = path.lower()
        if lower.endswith(".js"):
            return "JS"
        if lower.endswith(".css"):
            return "CSS"
        if any(lower.endswith(x) for x in (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico")):
            return "Img"
        if lower.endswith(".woff") or lower.endswith(".woff2") or lower.endswith(".ttf"):
            return "Font"
        if "/api/" in lower or lower.endswith(".json"):
            return "Fetch/XHR"
        return "Doc"

    # ──────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────

    def get_network_requests(
        self, target_url: str = "http://127.0.0.1:3000"
    ) -> List[Dict[str, Any]]:
        """Real network waterfall recorded from headless Chrome (status, size and timing are measured)."""
        clean_url, domain = _normalize_url(target_url)
        cap = capture_page(clean_url)
        page_host = urllib.parse.urlparse(clean_url).netloc

        # Real findings keyed by route, so runtime requests link to what the scanners actually reported.
        findings_by_route: Dict[str, Dict] = {}
        with self.db.get_connection() as conn:
            for row in conn.execute("SELECT finding_id, title, category, severity, data_json FROM findings").fetchall():
                try:
                    data = json.loads(row["data_json"])
                    ep = data.get("endpoint") or ""
                    if ep:
                        findings_by_route[urllib.parse.urlparse(ep).path or ep] = dict(row) | data
                except Exception:
                    pass

        span = max([r["start_ms"] + (r["duration_ms"] or 0) for r in cap["requests"]] + [1])
        type_map = {"Document": "Doc", "Script": "JS", "Stylesheet": "CSS", "Image": "Img", "Font": "Font",
                    "XHR": "Fetch/XHR", "Fetch": "Fetch/XHR"}
        out: List[Dict[str, Any]] = []
        for i, r in enumerate(cap["requests"], 1):
            is_vuln, tag, desc, fid = False, None, None, None
            fb = findings_by_route.get(r["path"])
            if fb:
                is_vuln, tag, desc, fid = True, f"{fb.get('category', '').upper()} ({fb.get('severity', '')})", fb.get("title"), fb.get("finding_id")
            elif r["type"] == "Script" and r["host"] != page_host:
                is_vuln, tag = True, "Third-party script"
                desc = f"Script loaded from {r['host']} (outside the assessed origin)"
            out.append({
                "id": f"req-{i}", "name": r["name"], "path": r["path"], "status": r["status"],
                "type": type_map.get(r["type"], r["type"]), "initiator": r["initiator"].rsplit("/", 1)[-1] or "other",
                "size": f"{r['transfer_bytes'] / 1024:.1f} kB" if r["transfer_bytes"] is not None else None,
                "time": r["duration_ms"], "waterfallPct": max(1, round((r["duration_ms"] or 0) / span * 100)),
                "offsetPct": min(99, round(r["start_ms"] / span * 100)), "isVuln": is_vuln, "vulnTag": tag,
                "vulnDesc": desc, "backendFindingId": fid, "method": r["method"], "failed": r["failed"],
                "protocol": r["protocol"], "live": True,
            })
        return out

    def get_security_analysis(
        self, target_url: str = "http://127.0.0.1:3000"
    ) -> Dict[str, Any]:
        """
        Real TLS + security header analysis for any target URL.
        """
        clean_url, domain = _normalize_url(target_url)
        is_wm = self._is_worldmonitor(domain)

        resp = self._scanner.fetch(clean_url)
        ssl_data = self._scanner.scan_ssl(domain)
        header_list, score = self._scanner.scan_security_headers(resp, domain)
        fp = self._scanner.fingerprint_server(resp)
        http_redirect = self._scanner.check_http_redirect(domain)

        # Determine protocol
        protocol: str
        if ssl_data.get("tls_version"):
            protocol = f"HTTP/{'2' if resp and str(resp.http_version) == '2' else '1.1'} ({ssl_data['tls_version']})"
        elif resp is not None:
            protocol = f"HTTP/{resp.http_version}"
        else:
            protocol = "--"

        connection_secure = not ssl_data.get("error") and clean_url.startswith("https://")

        # Build certificate dict (real values or None)
        cert = {
            "subject": f"CN={ssl_data['subject']}" if ssl_data.get("subject") else None,
            "issuer": ssl_data.get("issuer"),
            "valid_from": ssl_data.get("valid_from"),
            "valid_to": ssl_data.get("valid_to"),
            "san": ssl_data.get("sans") or [],
            "key_exchange": ssl_data.get("key_exchange"),
            "cipher": ssl_data.get("cipher"),
            "tls_error": ssl_data.get("error"),
        }

        # Status label
        fail_count = sum(1 for h in header_list if h["status"] == "FAIL")
        warn_count = sum(1 for h in header_list if h["status"] == "WARN")
        if fail_count > 0:
            overall_status = f"Vulnerable — {fail_count} Critical Header(s) Missing"
        elif warn_count > 0:
            overall_status = f"Needs Attention — {warn_count} Header Warning(s)"
        else:
            overall_status = "Hardened — All Headers Present"

        return {
            "origin": clean_url,
            "domain": domain,
            "protocol": protocol,
            "connection_secure": connection_secure,
            "http_redirects_to_https": http_redirect,
            "server_fingerprint": fp,
            "certificate": cert,
            "security_headers": header_list,
            "score": score,
            "overall_status": overall_status,
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "live": True,
        }

    def get_performance_telemetry(
        self, target_url: str = "http://127.0.0.1:3000"
    ) -> Dict[str, Any]:
        """
        Real HTTP performance measurement for any target URL.
        LCP/INP/CLS cannot be measured server-side — returned as None (shown as '--' in UI).
        """
        clean_url, domain = _normalize_url(target_url)
        perf = self._scanner.measure_performance(clean_url)

        ttfb = perf.get("ttfb_ms")
        total = perf.get("total_load_ms")
        size_kb = perf.get("content_size_kb")

        def _rate_ttfb(ms: Optional[float]) -> Dict:
            if ms is None:
                return {"value": None, "unit": "ms", "status": "--", "threshold": 800, "score": None}
            status = "Good" if ms < 800 else ("Needs Improvement" if ms < 1800 else "Poor")
            score = max(0, round(100 - ms / 20))
            return {"value": round(ms, 1), "unit": "ms", "status": status, "threshold": 800, "score": score}

        def _rate_load(ms: Optional[float]) -> Dict:
            if ms is None:
                return {"value": None, "unit": "ms", "status": "--", "threshold": 3000, "score": None}
            status = "Good" if ms < 3000 else "Needs Improvement"
            score = max(0, round(100 - ms / 50))
            return {"value": round(ms, 1), "unit": "ms", "status": status, "threshold": 3000, "score": score}

        overall_score = None
        if ttfb is not None:
            overall_score = max(0, round(100 - ttfb / 15))

        return {
            "target": clean_url,
            "domain": domain,
            "reachable": perf.get("reachable", False),
            "scan_error": perf.get("error"),
            "metrics": {
                "ttfb": _rate_ttfb(ttfb),
                "total_load": _rate_load(total),
                **_lighthouse_metrics(),
            },
            "summary": {
                "overall_score": overall_score,
                "total_transfer_kb": size_kb,
                "total_requests": perf.get("redirect_count", 0) + 1,
                "redirect_count": perf.get("redirect_count"),
                "status_code": perf.get("status_code"),
            },
            "live": True,
            "scan_time": datetime.now(timezone.utc).isoformat(),
        }

    def get_storage_audit(
        self, target_url: str = "http://127.0.0.1:3000"
    ) -> Dict[str, Any]:
        """Cookies, web storage and service workers as observed in a real browser session."""
        clean_url, domain = _normalize_url(target_url)
        cap = capture_page(clean_url)
        return {
            "domain": domain,
            "cookies": cap["cookies"],
            "cookies_from_live_scan": True,
            "local_storage": cap["local_storage"] + [{**e, "key": f"[session] {e['key']}"} for e in cap["session_storage"]],
            "service_workers": [
                {"scope": w.get("scope"), "script": w.get("script"), "status": w.get("state") or "registered",
                 "cache_storage_kb": None, "live": True} for w in cap["service_workers"]
            ],
            "scan_time": cap["captured_at"],
            "live": True,
        }

    def get_page_info(self, target_url: str = "http://127.0.0.1:3000", refresh: bool = False) -> Dict[str, Any]:
        """Real page-level timings and browser memory metrics from the captured session."""
        clean_url, _ = _normalize_url(target_url)
        cap = capture_page(clean_url, use_cache=not refresh)
        reqs = cap["requests"]
        return {
            "captured_at": cap["captured_at"], "title": cap["title"], "load_ms": cap["load_ms"], "dcl_ms": cap["dcl_ms"],
            "span_ms": cap["span_ms"], "request_count": len(reqs),
            "transfer_kb": round(sum(r["transfer_bytes"] or 0 for r in reqs) / 1024, 1),
            "failed_count": sum(1 for r in reqs if r["failed"]),
            "memory": cap["memory"],
            "console_counts": {lvl: sum(1 for m in cap["console"] if m["level"] in grp)
                               for lvl, grp in (("errors", ("error",)), ("warnings", ("warning", "warn")))},
        }

    def get_console_log(self, target_url: str = "http://127.0.0.1:3000") -> Dict[str, Any]:
        """Console / log messages emitted by the page during a real load."""
        clean_url, _ = _normalize_url(target_url)
        cap = capture_page(clean_url)
        return {"messages": cap["console"], "captured_at": cap["captured_at"], "page_title": cap["title"],
                "load_ms": cap["load_ms"], "request_count": len(cap["requests"])}

    def get_custom_target_findings(self, target_url: str) -> List[Dict[str, Any]]:
        """
        Perform a full live security scan of any target URL and return findings.
        Findings are 100% grounded in real scan data — no fabrication.
        """
        clean_url, domain = _normalize_url(target_url)

        # Run all scans
        resp, elapsed_s = self._scanner.fetch_timed(clean_url)
        ssl_data = self._scanner.scan_ssl(domain)
        header_list, _ = self._scanner.scan_security_headers(resp, domain)
        cookies = self._scanner.scan_cookies(resp, domain)
        http_redirect = self._scanner.check_http_redirect(domain)
        perf = self._scanner.measure_performance(clean_url)

        # Generate findings from real data
        findings = self._scanner.generate_findings(
            domain=domain,
            base_url=clean_url,
            headers_data=header_list,
            ssl_data=ssl_data,
            cookies_data=cookies,
            http_redirects=http_redirect,
            perf_data=perf,
        )

        return findings

    def execute_console_command(self, cmd_line: str) -> Dict[str, Any]:
        """
        Processes interactive developer console commands from the Chrome DevTools console panel.
        """
        parts = cmd_line.strip().split()
        if not parts:
            return {"type": "log", "output": ""}

        cmd = parts[0].lower()
        args = parts[1:]

        if cmd == "help":
            return {
                "type": "log",
                "output": (
                    "Available DevTools Commands:\n"
                    "  status              Show target loopback health and DB findings\n"
                    "  probe <url>         Probe an in-scope (loopback) URL\n"
                    "  headers <url>       Audit security headers of an in-scope URL\n"
                    "  findings            List summary of candidate and verified findings\n"
                    "  clear               Clear console log buffer\n"
                    "  version             Display WMSA platform version"
                ),
            }

        if cmd == "version":
            return {"type": "log", "output": "SecureLens DevTools Inspector v2.0.0 (SIH 2026 PS 26163 — Live Scanner Edition)"}

        if cmd == "status":
            with self.db.get_connection() as conn:
                count = conn.execute("SELECT count(*) as c FROM findings").fetchone()["c"]
                open_count = conn.execute(
                    "SELECT count(*) as c FROM findings WHERE status = 'CANDIDATE'"
                ).fetchone()["c"]
            return {
                "type": "log",
                "output": (
                    f"Source repo: {self.manifest.repo_url}\n"
                    f"Commit SHA: {self.manifest.commit_sha[:8]}\n"
                    f"Findings Total: {count} ({open_count} unverified candidates)\n"
                    f"Scope: loopback only (127.0.0.1)"
                ),
            }

        if cmd == "findings":
            with self.db.get_connection() as conn:
                rows = conn.execute(
                    "SELECT finding_id, title, category, severity, status FROM findings LIMIT 10"
                ).fetchall()
            if not rows:
                return {"type": "warn", "output": "No active findings in database. Run a scan via Admin Panel."}
            lines = [
                f"[{r['severity']}] {r['finding_id']} - {r['title']} ({r['status']})"
                for r in rows
            ]
            return {"type": "log", "output": "\n".join(lines)}

        if cmd == "headers":
            url = args[0] if args else "http://127.0.0.1:3000"
            clean_url, domain = _normalize_url(url)
            try:
                ScopeGuard(self.manifest).guard(clean_url)
            except Exception as e:
                return {"type": "error", "output": f"Scope violation: {e}"}
            resp = self._scanner.fetch(clean_url)
            header_list, score = self._scanner.scan_security_headers(resp, domain)
            fails = [h for h in header_list if h["status"] == "FAIL"]
            warns = [h for h in header_list if h["status"] == "WARN"]
            passes = [h for h in header_list if h["status"] == "PASS"]
            return {
                "type": "warn" if fails else "log",
                "output": (
                    f"Live Header Audit for {domain} | Score: {score}/100\n"
                    f"  {len(passes)} Pass  |  {len(warns)} Warn  |  {len(fails)} Fail\n"
                    + "\n".join([f"  FAIL: {f['name']} → {f.get('risk', '')}" for f in fails])
                    + ("\n" if warns else "")
                    + "\n".join([f"  WARN: {w['name']}" for w in warns])
                ),
            }

        if cmd == "ssl":
            return {"type": "warn", "output": "TLS scanning is disabled: only the loopback target (plain HTTP) is in scope."}

        if cmd == "probe":
            if not args:
                return {"type": "error", "output": "Usage: probe <url>  (e.g. probe https://example.com/api/health)"}
            url = args[0]
            if not url.startswith("http"):
                url = "https://" + url

            # For WM loopback probes, use scope guard
            parsed = urllib.parse.urlparse(url)
            if "127.0.0.1" in parsed.netloc or "localhost" in parsed.netloc:
                guard = ScopeGuard(self.manifest)
                try:
                    canonical = guard.guard(url)
                except Exception as e:
                    return {"type": "error", "output": f"Scope violation: {e}"}
                try:
                    t0 = time.time()
                    with httpx.Client(timeout=2.0) as client:
                        resp = client.get(canonical)
                        elapsed = (time.time() - t0) * 1000
                        return {
                            "type": "log",
                            "output": f"HTTP {resp.status_code} {resp.reason_phrase} - {elapsed:.1f}ms - {len(resp.content)} bytes",
                        }
                except Exception:
                    return {
                        "type": "warn",
                        "output": f"Loopback probe for {url}: target not running or port closed",
                    }

            return {"type": "error", "output": "Scope violation: only loopback targets (127.0.0.1 / localhost) may be probed."}

        return {"type": "error", "output": f"Unknown command: {cmd}. Type help."}
