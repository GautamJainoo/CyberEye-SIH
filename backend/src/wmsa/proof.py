"""
Proof-image generator.

Renders one evidence card (PNG) per finding using headless Chrome, built only from REAL scanner
output: the code excerpt with the flagged lines highlighted, or the recorded HTTP request/response
transcript, plus tool, exact command, raw-output hash and location. Web findings also embed a live
screenshot of the local target taken at generation time.
"""

from __future__ import annotations

import base64
import html
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from wmsa.db import Database
from wmsa.enrich import METHOD_TEMPLATES, code_context, ensure_table
from wmsa.paths import get_base_dir

SEV_COLOR = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#3b82f6", "INFO": "#94a3b8"}


def chrome_binary() -> Optional[str]:
    for name in ("google-chrome", "google-chrome-stable", "chromium-browser", "chromium"):
        path = shutil.which(name)
        if path:
            return path
    return None


def render_png(html_text: str, out_png: Path, width: int = 1200, height: int = 900) -> bool:
    chrome = chrome_binary()
    if not chrome:
        return False
    out_png.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        page = Path(tmp) / "card.html"
        page.write_text(html_text, encoding="utf-8")
        cmd = [
            chrome, "--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
            f"--user-data-dir={tmp}/profile", f"--window-size={width},{height}",
            f"--screenshot={out_png}", f"file://{page}",
        ]
        try:
            subprocess.run(cmd, capture_output=True, timeout=60)
        except Exception:
            return False
    return out_png.exists() and out_png.stat().st_size > 0


def html_to_pdf(html_text: str) -> Optional[bytes]:
    """Print an HTML document to PDF with headless Chrome (no extra dependencies)."""
    chrome = chrome_binary()
    if not chrome:
        return None
    with tempfile.TemporaryDirectory() as tmp:
        page = Path(tmp) / "report.html"
        out = Path(tmp) / "report.pdf"
        page.write_text(html_text, encoding="utf-8")
        cmd = [chrome, "--headless=new", "--no-sandbox", "--disable-gpu", "--no-pdf-header-footer",
               f"--user-data-dir={tmp}/profile", f"--print-to-pdf={out}", f"file://{page}"]
        try:
            subprocess.run(cmd, capture_output=True, timeout=90)
        except Exception:
            return None
        return out.read_bytes() if out.exists() else None


def capture_live_screenshot(url: str, out_png: Path) -> bool:
    """Real screenshot of the running target (loopback only)."""
    if not url.startswith(("http://127.0.0.1", "http://localhost")):
        return False
    chrome = chrome_binary()
    if not chrome:
        return False
    out_png.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        cmd = [
            chrome, "--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
            f"--user-data-dir={tmp}/profile", "--window-size=1200,700", "--virtual-time-budget=8000",
            f"--screenshot={out_png}", url,
        ]
        try:
            subprocess.run(cmd, capture_output=True, timeout=60)
        except Exception:
            return False
    return out_png.exists() and out_png.stat().st_size > 0


def _esc(s: Any) -> str:
    return html.escape(str(s if s is not None else ""))


def _read_raw(raw_ref: Optional[str]) -> Tuple[Optional[Path], str]:
    if not raw_ref:
        return None, ""
    path, _, frag = raw_ref.partition("#")
    p = Path(path)
    return (p if p.exists() else None), frag


def _proof_block(f: Dict[str, Any], tool: str, raw_ref: Optional[str], ctx: Optional[Dict[str, Any]]) -> Tuple[str, str]:
    """Return (title, html) for the evidence section."""
    raw_path, frag = _read_raw(raw_ref)

    if tool == "worldmonitor-probes" and raw_path:
        try:
            recs = json.loads(raw_path.read_text())["records"]
        except Exception:
            recs = []
        rows = []
        for r in recs:
            if "status_code" not in r:
                continue
            viol = r.get("violations")
            rows.append(
                f'<div class="req"><div class="reqhead">{_esc(r.get("method", "GET"))} {_esc(r.get("url"))}</div>'
                f'<div class="mono dim">{_esc(r.get("sent_headers") or "")}</div>'
                f'<div class="resp">HTTP {_esc(r["status_code"])} &mdash; {_esc((r.get("response_snippet") or "")[:160])}</div>'
                + (f'<div class="viol">Expectation violated: {_esc("; ".join(viol))}</div>' if viol else '<div class="ok">Matched expected safe behaviour</div>')
                + "</div>"
            )
        return "HTTP request / response transcript", "".join(rows) or "<div class='dim'>No transcript recorded.</div>"

    if tool == "zap" and raw_path:
        plugin, _, uri = frag.partition(":")
        detail = ""
        try:
            for site in json.loads(raw_path.read_text()).get("site", []):
                for a in site.get("alerts", []):
                    if str(a.get("pluginid")) != plugin:
                        continue
                    for inst in a.get("instances", []):
                        if inst.get("uri") == uri:
                            detail = (
                                f'<div class="req"><div class="reqhead">{_esc(inst.get("method"))} {_esc(inst.get("uri"))}</div>'
                                f'<div class="mono dim">param: {_esc(inst.get("param") or "-")}</div>'
                                f'<div class="resp">Evidence: {_esc((inst.get("evidence") or "-")[:300])}</div>'
                                f'<div class="ok">ZAP rule {_esc(plugin)} &middot; confidence {_esc(a.get("confidence"))} &middot; risk {_esc(a.get("riskdesc"))}</div></div>'
                            )
                            raise StopIteration
        except StopIteration:
            pass
        except Exception:
            pass
        return "Runtime evidence recorded by ZAP", detail or "<div class='dim'>Instance detail not found in raw report.</div>"

    if ctx:
        hl_lo, hl_hi = ctx["highlight_start"], ctx["highlight_end"]
        out = []
        for i, line in enumerate(ctx["lines"]):
            n = ctx["start"] + i
            cls = "hl" if hl_lo <= n <= hl_hi else ""
            out.append(f'<div class="code {cls}"><span class="ln">{n}</span>{_esc(line) or "&nbsp;"}</div>')
        return f'Source code &mdash; {_esc(ctx["file"])}:{hl_lo}-{hl_hi}', "".join(out)

    if tool == "osv-scanner":
        return "Vulnerable dependency", (
            f'<div class="req"><div class="reqhead">{_esc(f.get("package"))} @ {_esc(f.get("package_version"))}</div>'
            f'<div class="resp">Advisories: {_esc(", ".join((f.get("ghsa") or []) + (f.get("cve") or [])) or "see description")}</div>'
            f'<div class="dim">{_esc((f.get("description") or "")[:400])}</div></div>'
        )
    if tool == "gitleaks":
        return "Secret detection (value redacted)", (
            f'<div class="req"><div class="reqhead">{_esc(f.get("file"))}:{_esc(f.get("line_start"))}</div>'
            '<div class="resp mono">secret = [REDACTED]</div></div>'
        )
    return "Evidence", f'<div class="dim">{_esc((f.get("description") or "")[:500])}</div>'


def build_card_html(f: Dict[str, Any], tool: str, rule: Optional[str], run: Dict[str, Any], raw_ref: Optional[str],
                    ctx: Optional[Dict[str, Any]], analysis: Optional[Dict[str, Any]], live_png: Optional[Path]) -> str:
    sev = str(f.get("severity", "INFO")).upper()
    color = SEV_COLOR.get(sev, "#94a3b8")
    ptitle, pbody = _proof_block(f, tool, raw_ref, ctx)
    method = METHOD_TEMPLATES.get(tool, "Automated scanner detection.").format(rule=rule or "n/a")
    where = f.get("file") and f"{f['file']}:{f.get('line_start')}" or f.get("endpoint") or f.get("package") or "-"
    live = ""
    if live_png and live_png.exists() and tool in ("zap", "worldmonitor-probes"):
        b64 = base64.b64encode(live_png.read_bytes()).decode()
        live = f'<h3>Live target at time of test (127.0.0.1:3000)</h3><img class="live" src="data:image/png;base64,{b64}"/>'
    impact = _esc((analysis or {}).get("impact", ""))
    fixes = "".join(f"<li>{_esc(x)}</li>" for x in (analysis or {}).get("fix_steps", [])[:4])
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>
body{{margin:0;background:#0b0f1a;color:#e2e8f0;font:14px/1.5 Inter,system-ui,sans-serif;padding:28px;width:1144px}}
.badge{{background:{color};color:#0b0f1a;font-weight:700;padding:2px 10px;border-radius:6px;font-size:12px}}
h1{{font-size:22px;margin:10px 0 4px}} h3{{font-size:13px;letter-spacing:.06em;text-transform:uppercase;color:#94a3b8;margin:22px 0 8px}}
.meta{{color:#94a3b8;font-size:12px}} .box{{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:14px}}
.mono{{font-family:'JetBrains Mono',ui-monospace,monospace}} .dim{{color:#94a3b8}}
.code{{font-family:ui-monospace,monospace;font-size:12.5px;white-space:pre-wrap;padding:1px 8px;color:#cbd5e1}}
.code.hl{{background:rgba(239,68,68,.22);border-left:3px solid #ef4444;color:#fff}} .ln{{display:inline-block;width:46px;color:#64748b}}
.req{{border-left:3px solid #334155;padding:6px 12px;margin:8px 0}} .reqhead{{font-family:ui-monospace,monospace;color:#7dd3fc}}
.resp{{margin-top:4px}} .viol{{color:#fca5a5;font-weight:600;margin-top:4px}} .ok{{color:#86efac;margin-top:4px}}
.live{{width:100%;border-radius:8px;border:1px solid #1f2937}} ul{{margin:4px 0 0 18px;padding:0}}
.foot{{margin-top:18px;font-size:11px;color:#64748b;word-break:break-all}}
</style></head><body>
<span class="badge">{_esc(sev)}</span> <span class="meta">&nbsp;{_esc(f.get("status", "CANDIDATE"))} &middot; {_esc(f.get("category"))} &middot; {_esc(", ".join(f.get("cwe") or []))}</span>
<h1>{_esc(f.get("title"))}</h1><div class="meta">Where: <b class="mono">{_esc(where)}</b></div>
<h3>How the tool found it</h3><div class="box">{_esc(method)}<div class="meta mono" style="margin-top:8px">$ {_esc(run.get("command_line", "")[:260])}</div></div>
<h3>{ptitle}</h3><div class="box">{pbody}</div>{live}
<h3>Impact</h3><div class="box">{impact or "See analysis."}</div>
<h3>Recommended fix</h3><div class="box"><ul>{fixes or "<li>See remediation guidance.</li>"}</ul></div>
<div class="foot">tool: {_esc(tool)} {_esc(run.get("tool_version", ""))} &middot; raw output sha256: {_esc(run.get("raw_output_sha256", ""))} &middot; commit {_esc(f.get("commit_sha", ""))[:12]} &middot; finding {_esc(f.get("finding_id"))}</div>
</body></html>"""


def build_proofs(db: Optional[Database] = None, base_dir: Optional[Path] = None, force: bool = False,
                 target_url: str = "http://127.0.0.1:3000") -> Dict[str, int]:
    base = base_dir or get_base_dir()
    db = db or Database()
    ensure_table(db)
    out_dir = base / "evidence" / "proof"
    live_png = out_dir / "_target_live.png"
    stats = {"built": 0, "failed": 0, "skipped": 0}
    if not chrome_binary():
        return {"built": 0, "failed": 0, "skipped": 0, "error": "no headless chrome found"}
    capture_live_screenshot(target_url, live_png)

    with db.get_connection() as conn:
        rows = conn.execute("SELECT finding_id, data_json FROM findings").fetchall()
        srcs = {}
        for r in conn.execute("SELECT finding_id, tool_name, rule_id, raw_ref FROM finding_sources").fetchall():
            srcs.setdefault(r["finding_id"], r)
        runs = {}
        for r in conn.execute("SELECT * FROM tool_runs ORDER BY created_at").fetchall():
            runs[r["tool_name"]] = dict(r)
        analyses = {r["finding_id"]: json.loads(r["analysis_json"]) for r in
                    conn.execute("SELECT finding_id, analysis_json FROM finding_analysis").fetchall()}

    for r in rows:
        fid = r["finding_id"]
        out = out_dir / f"{fid}.png"
        if out.exists() and not force:
            stats["skipped"] += 1
            continue
        f = json.loads(r["data_json"])
        src = srcs.get(fid)
        tool = src["tool_name"] if src else "unknown"
        run = runs.get(tool) or {}
        ctx = code_context(base / "target", f.get("file"), f.get("line_start"), f.get("line_end"))
        page = build_card_html(f, tool, src["rule_id"] if src else None, run, src["raw_ref"] if src else None,
                               ctx, analyses.get(fid), live_png)
        height = 1000 + (len(ctx["lines"]) * 20 if ctx else 0) + (620 if live_png.exists() and tool in ("zap", "worldmonitor-probes") else 0)
        if render_png(page, out, height=height):
            stats["built"] += 1
        else:
            stats["failed"] += 1
    return stats
