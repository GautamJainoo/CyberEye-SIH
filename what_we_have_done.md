# Project Progress & Implementation Status: SecureLens (WMSA)
**World Monitor Security Assessment Workflow — Smart India Hackathon (SIH 2026, PS 26163)**

_Last updated: 29 Sep 2026. Everything below was verified by running it against the real pinned World Monitor build; where something is not done or not verified it says so._

---

## 1. Executive Summary

SecureLens (WMSA) assesses the open-source **World Monitor** application (`koala73/worldmonitor`, pinned commit `0d5c618e…`) running in an isolated Docker environment on loopback. It runs six assessment methods, normalizes their output into evidence-gated findings, explains each one with an LLM, renders a proof image per finding, and shows everything in a Next.js dashboard and admin panel.

Guiding rule (from the research report): **deterministic tools detect, the AI only explains, and nothing is shown as verified without evidence.** Every scanner result is a `CANDIDATE` until an analyst verifies it.

**Current state:** the pipeline runs end to end in about 9 minutes (dominated by a 5-minute ZAP scan) and produced **85 candidate findings** in the last run. The dashboard shows only measured or stored data; anywhere data is missing it says "not measured" instead of showing a placeholder.

### Honest scope note
- Only **one** finding has been reproduced by hand against the live target: the `/api/rss-proxy` endpoint in Docker/local-api mode has **no domain allowlist** (it relays any public URL such as `google.com`; private IPs, metadata addresses and non-HTTP schemes are correctly blocked, and HTTPS redirects are not followed). It is an open relay, low-to-medium severity — **not** the internal-network SSRF the old seed data claimed.
- The 5 Gemini code-review findings are grounded in real code locations but their **titles over-claim** (e.g. "Unauthenticated RCE or SSRF" was attached to the SSRF guard function itself). They are candidates to review, not confirmed vulnerabilities.
- The retest/patch flow is implemented and unit-tested but was **not** exercised end to end against the real target in this pass.

---

## 2. What the SIH statement asks for → where it lives

| PS 26163 requirement | Where |
|---|---|
| Review source + test the live instance | Gemini code review, Semgrep, Gitleaks, OSV (source); ZAP, probes, Lighthouse, browser capture (running app) |
| Per finding: title, component, CVSS, reproduction, safe PoC, impact, remediation | `/findings/[id]` page and the PDF/HTML/JSON report; proof image per finding |
| Testing only the authorized target, PoC-only exploitation | Loopback scope guard on every endpoint, kill switch, allowlisted setup commands |
| At least one valid documented vulnerability | RSS-proxy allowlist gap (above), with request/response transcript as evidence |

---

## 3. Architecture & Directory Layout

```
Secure-Lens-SIH/
├── backend/                       # Python + FastAPI engine
│   ├── config/                    # scope.yaml (loopback allowlist), profiles.yaml, tools.lock.json
│   ├── docker/                    # compose.target.yaml (isolated World Monitor), compose.zap.yaml
│   ├── probes/recipes/            # 5 World Monitor probe recipes (auth, cors, oauth-grant, ratelimit, ssrf)
│   ├── rules/                     # Semgrep rules (taint), Gitleaks config, ZAP plan template
│   ├── src/wmsa/
│   │   ├── adapters/              # semgrep, gitleaks, osv, zap, probes, gemini_review
│   │   ├── pipeline.py            # one-click pipeline: setup → review → scans → audit → explain → proofs
│   │   ├── orchestrator.py        # runs tools (static + ZAP concurrently, probes after), records tool runs
│   │   ├── enrich.py, llm/groq.py # Groq explanations, one call per (tool, rule) group
│   │   ├── proof.py               # proof PNG per finding (headless Chrome) + HTML→PDF
│   │   ├── cdp.py                 # real browser capture via Chrome DevTools Protocol
│   │   ├── webaudit.py            # Lighthouse audit (history kept)
│   │   ├── dashboard.py           # dashboard aggregates: risk, attack surface, radar, activity, notifications
│   │   ├── copilot_chat.py        # copilot grounded in stored findings
│   │   ├── setup_assistant.py     # Gemini-planned local setup, allowlisted execution
│   │   ├── api.py, devtools.py    # REST API (127.0.0.1:8000) and DevTools engine
│   │   ├── scope.py, lifecycle.py, evidence.py, normalize.py, retest.py, patching.py, intel.py, report.py, db.py …
│   └── tests/                     # 79 tests
├── frontend/                      # Next.js (App Router) + Tailwind + Redux Toolkit, port 3100
│   └── src/{app,views,components,store,lib,services}
├── Makefile, README.md, docker-compose.yml, what_we_have_done.md
```

Data stores: SQLite by default (`backend/wmsa.db`, override with `WMSA_DB_PATH`); PostgreSQL is supported via `DATABASE_URL` (`pip install -e "backend[postgres]"`) but the Postgres path was **not** exercised in this pass. The audit log and state transitions are append-only (DB triggers refuse UPDATE/DELETE).

---

## 4. The six assessment methods (as tested on the real target)

Run order in the pipeline: **Gemini review → Semgrep → Gitleaks → OSV → ZAP → probes**, then Lighthouse, Groq explanations and proof images.

| # | Method | Result in the last run | What was wrong before, and the fix |
|---|---|---|---|
| 1 | **Gemini code review** (`gemini-3.8-flash`, fallbacks) | 5 grounded candidates | New. Findings are kept only if the file exists and the quoted code really appears in it — a weaker model's hallucinated finding was correctly dropped. |
| 2 | **Semgrep** (custom World Monitor rules) | 14 unique findings (22 raw) | `wm-ssrf-unvalidated-fetch` matched every `fetch()` (670 hits). Rewritten as taint tracking (request-controlled URL → fetch, allowlist as sanitizer). |
| 3 | **Gitleaks** | 14 unique candidates (33 raw); planted fixture secret still detected | Custom config had **no rules** so it detected nothing. Now extends the defaults and allowlists docs/tests/header-name false positives (200 raw hits → 11 locations). |
| 4 | **OSV-Scanner** (dependencies) | 42 findings | Works. Planted lodash 4.17.15 fixture detected. |
| 5 | **OWASP ZAP** (DAST, ~5 min) | 9 findings (one per alert) | Failed silently when port 8080 was busy and reported "0 alerts". Now binds a free port and raises on a failed run. Instances collapsed to one finding per alert (63 → 9). |
| 6 | **World Monitor probes** | 1 finding (SSRF allowlist gap); auth and CORS expectations held; oauth-grant and rate-limit are INCONCLUSIVE by design | Verdicts were fail-open (blocked steps, kill switch and status mismatches all said "met"). Now status/header/field assertions are evaluated and blocked or unobservable steps are INCONCLUSIVE. |

Cross-cutting fixes: the Semgrep/Gitleaks/OSV adapters used to **silently fall back to a home-made regex scanner** when a binary was missing and labelled it with the real tool's name — removed; a missing tool now fails loudly, and failed tools are recorded in the scan metrics instead of swallowed.

Additional real-data collectors: **Lighthouse** (Performance/Accessibility/Best Practices/SEO and Core Web Vitals) and a **headless-Chrome DevTools-Protocol capture** (network waterfall, cookies, storage, service workers, console, JS heap/DOM metrics).

---

## 5. AI assistance (and its guardrails)

- **Gemini** — manual code-structure review and a planned local setup. Source is redacted and fenced as untrusted; output is grounded against the repo; setup commands are checked against an allowlist and only the vetted loopback compose file is ever run. Model order: `gemini-3.8-flash`, then `gemini-3.5-flash`, `gemini-3.1-pro-preview`, `gemini-flash-latest`, `gemini-3.5-flash-lite`. Quota (429) skips to the next model; calls have time budgets. `gemini-2.5-*` is retired for new keys.
- **Groq** (`openai/gpt-oss-120b`) — normalizes each finding into one explanation: summary, root cause, how detected, exploitation scenario, impact, fix steps, false-positive risk. One call per (tool, rule) group, 2 in parallel, rate-limit aware, deterministic template fallback. The prompt forbids claiming more than the evidence shows.
- **Copilot chat** — Groq answers built only from stored findings; if the provider is down it says so. It never marks anything verified.
- API keys live only in the environment or the gitignored `backend/.env` (template: `backend/.env.example`).

---

## 6. Real-data policy — fabricated data that was removed

A full audit found many hardcoded or invented values presented as real. All were removed:

- **Backend:** `seed.py` (12 fake "authentic" findings, five marked VERIFIED, e.g. "SSRF: Redis keys exposed — HTTP 200", which the live target contradicts) and its auto-seed in `/api/health`; a hardcoded "CORS `*` FAIL" injected into every security analysis; three fake network routes (SSRF/CORS/SQLi); a fake JWT in localStorage and a fake 1240 KB service worker; invented recommendations when the DB was empty; canned copilot text asserting vulnerabilities that were never found.
- **Frontend:** invented Accessibility/SEO scores, "+2" deltas and decorative sparklines; "12 vulns / 8 APIs / 231 active users / Risk 68"; "Medium Risk (68/100)"; a fake attack-surface map (Cloudflare, Kong, ClickHouse, invented IPs); fake activity times and notifications; a fake heap snapshot; a "Baseline Mode" toggle that hid real findings; a scan modal whose fallback simulated a fake scan; simulated copilot answers; a fake profile/e-mail/"sign out"; invented default CVSS scores, impact and remediation text.
- **Scope:** external targets (Amazon presets, arbitrary URLs in console commands) were out of scope; every `target_url` endpoint now returns 403 for non-loopback hosts.

Now: empty DB ⇒ zeros/empty states; unmeasured values render as `--` / "Not measured"; trends appear only with 2+ real audits.

Risk score formula (also returned by the API): `risk = 100·(1 − exp(−x/150))`, `x = Σ severity_weight × status_factor` (CRITICAL 25, HIGH 10, MEDIUM 3, LOW 1; VERIFIED 1.0, TRIAGED 0.6, CANDIDATE 0.3). Unverified scanner output counts less than analyst-verified findings.

---

## 7. Frontend (Next.js)

- `/` — dashboard (deep-link tabs with `?tab=inspect|vulns|ai-chat|reports|admin`): measured Lighthouse cards, Core Web Vitals, activity, recommendations, posture/radar/distribution, findings table, attack surface by area, copilot, reports.
- `/admin` — full pipeline runner (live step status + log), findings with filters and proof thumbnails, per-tool runs with method + command + raw hash + redacted raw output, Gemini review notes, audit log.
- `/findings/[id]` — where found, how the tool found it, proof image (click to enlarge with the method), highlighted code, cause, impact, safe exploitation walkthrough, fix, lifecycle/evidence.
- Runs on **127.0.0.1:3100** (Next's default 3000 is the target).

---

## 8. Verification

- **Tests:** `79 passed` (`backend/.venv/bin/pytest backend/tests`). Tests use an isolated temp DB (`tests/conftest.py`); tests that need a live target skip when none is running. New regression tests cover the honest-verdict, no-fake-fallback, ZAP-collapse, scope-enforcement, redaction and real-data-aggregate behaviour.
- **Live run:** full pipeline on the pinned commit: 85 findings, 6/6 scanners, 64 endpoints with recorded results, 85 proof images, Lighthouse 73 / 96 / 96 / 92 (performance varies run to run), risk 61 (High, candidate-weighted).
- **UI:** dashboard, Inspect (all six DevTools tabs), admin and finding pages were loaded in headless Chrome with zero uncaught exceptions.
- **Secrets:** no API key appears in any commit or tracked file.

---

## 9. How to run

```bash
# 1. Backend environment
cd backend
uv venv .venv && uv pip install --python .venv/bin/python -e ".[dev,postgres,scanners]"
# gitleaks 8.30.1 and osv-scanner 2.6.0 binaries into ~/.local/bin (see tools.lock.json)
cp .env.example .env         # add GEMINI_API_KEY and GROQ_API_KEY (never commit .env)

# 2. Target: clone the pinned commit and start it isolated on 127.0.0.1:3000
.venv/bin/python -m wmsa.cli target setup
docker compose -f docker/compose.target.yaml up -d --build

# 3. API (127.0.0.1:8000) and dashboard (127.0.0.1:3100)
.venv/bin/python -m uvicorn wmsa.api:api_app --host 127.0.0.1 --port 8000
cd ../frontend && npm ci && npm run build && npm start

# 4. In the browser: http://127.0.0.1:3100/admin → "Run all 6 scans"
```

---

## 10. Status against the architecture diagram

| Diagram item | Status |
|---|---|
| Pinned local clone, isolated Docker target | Done (loopback only) |
| Test accounts & seed data for the target | **Not done** |
| Target allowlist | Done; note `allowed_route_prefixes: ["/"]` permits every path and `[::1]` raises a raw `ValueError` (still fails closed) |
| Manual review → World Monitor probes | Done (5 recipes; `REVIEW_NOTES.md` still mentions `wm-probe-entitlement-01` / `wm-probe-cache-01`, which do not exist) |
| Semgrep, Gitleaks, OSV, ZAP | Done and verified |
| Findings normalizer, dedupe | Done |
| CWE/CVSS mapping | Partial: CWE from tools; CVSS only where a tool/Gemini provides a vector — no scoring engine |
| Code + runtime correlation | Partial: runtime requests link to matching findings; no automatic probe trigger from a static finding |
| Threat intel (KEV, GHSA, OSV) | Done for KEV and GHSA sync; **NVD not implemented** |
| Evidence & verification, state machine | Done; caveat: a static scan's own output counts as "evidence", so an analyst can verify with a 5-character reason and no reproduction — the gate should require a reproduced PoC |
| Fix & retest | Implemented and unit-tested; **not exercised on the real target in this pass** |
| Optional AI assistant | Done with **Groq + Gemini** (a local Ollama provider still exists in `llm/provider.py`) |
| Dashboard, reports (PDF/HTML/JSON) | Done (PDF rendered with headless Chrome) |
| Scheduler/cron, AWS deployment | **Not done** (optional in the diagram) |
| Video proof | **Not done** (images only) |

### Known limitations
- Gemini/Groq free-tier quotas and overloads are real: reviews can fall back across models, and a few explanations can drop to the template text until enrichment is rerun.
- ZAP's active scan takes about 5 minutes.
- The Gemini findings need manual triage (see the scope note above).
- INP is a field metric and cannot be measured in a lab; Total Blocking Time is shown as its lab proxy.
- Prompt-injection resistance was covered by unit tests only, not against a live model.

---

## 11. Change log for this update (git history)

1. `fix(scanners)` — honest, working Semgrep/Gitleaks/OSV/ZAP/probes.
2. `feat(pipeline)` — Gemini review, Groq explanations, proof images, Lighthouse step, one-click pipeline.
3. `feat(api)` — real-data API, browser capture, dashboard aggregates, grounded copilot, scope enforcement, seed removal.
4. `chore(git)` — stop ignoring `frontend/src/lib`.
5. `feat(frontend)` — Next.js migration, admin + finding pages, all placeholders removed.
6. `docs` — this document and stale README lines.
