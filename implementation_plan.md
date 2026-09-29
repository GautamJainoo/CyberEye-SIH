# SecureLens (WMSA) End-to-End Assessment Platform: Backend, DevTools & React Dashboard Integration

Complete realization of SIH 2026 Problem Statement ID 26163 ("Security Assessment of the World Monitor application") across backend engine, custom security probes, Chrome DevTools suite, AI Security Copilot, and real-time React admin dashboard.

---

## User Review Required

> [!IMPORTANT]
> - **Zero Dummy Data vs Real Scan Results**: The application defaults to a clean-slate posture (`0 Vulnerabilities`) until a target repository (default: `https://github.com/koala73/worldmonitor` at pinned commit `0d5c618e4307414546a9be84a482ac06b7d56749`) is configured or scanned.
> - **DevTools Suite Backend Connectivity**: The Chrome DevTools Suite (`ChromeDevToolsSuite.tsx`) and Network Inspect (`NetworkInspectView.tsx`) will be backed by dedicated FastAPI endpoints (`/api/devtools/*` and `/api/network/*`) that provide live telemetry, security header evaluation, TTFB/latency probing, and vulnerability tags for target routes.
> - **AI Security Copilot Engine**: `AiAssistant.tsx` will connect to `/api/copilot/chat` and `/api/copilot/recommendations`. It will leverage an intelligent RAG engine over active SQLite/PostgreSQL findings and CISA KEV intelligence to provide precise remediation patches, CVSS impact breakdowns, and reproduction steps.
> - **Self-Contained Scanner Execution**: In addition to calling external CLI tools (Semgrep, Gitleaks, OSV-Scanner, ZAP) when installed, the backend will feature native AST & pattern detectors for World Monitor code patterns and safe probe recipes (`wm-probe-auth-01`, `wm-probe-cors-01`, `wm-probe-oauth-grant-01`, `wm-probe-ratelimit-01`, `wm-probe-ssrf-01`) so assessment scans reliably produce findings even on clean machines without external CLI tool installations.

---

## Open Questions

> [!NOTE]
> None. All requirements are fully specified by the problem statement and the user's instructions.

---

## Proposed Changes

### Backend Engine & API Layer (`backend/`)

#### [NEW] [backend/src/wmsa/devtools.py](file:///Users/vaibhavjain/Downloads/PS%20AD/backend/src/wmsa/devtools.py)
- Dedicated telemetry and diagnostic analyzer for target web applications:
  - Header inspection (CSP, HSTS, X-Content-Type-Options, Cache-Control).
  - Storage auditor (JWT tokens in localStorage, insecure cookie flags).
  - Performance and Core Web Vitals estimator (LCP, INP, CLS, TTFB).
  - Request waterfall generator linking route endpoints to known vulnerability findings.

#### [MODIFY] [backend/src/wmsa/api.py](file:///Users/vaibhavjain/Downloads/PS%20AD/backend/src/wmsa/api.py)
- Add Chrome DevTools Suite endpoints:
  - `GET /api/devtools/network`: Live network request matrix for target routes (status, size, waterfall, latency, vulnerability flags such as SSRF, CORS, SQLi, Auth bypass).
  - `GET /api/devtools/security`: Deep security analysis of target (TLS certificate details, CSP, HSTS, X-Frame-Options, Cookie security flags `HttpOnly`/`Secure`/`SameSite`).
  - `GET /api/devtools/performance`: Core Web Vitals (LCP, INP, CLS, TTFB, DOMContentLoaded, Speed Index).
  - `GET /api/devtools/storage`: Analysis of client storage (cookies, localStorage JWT inspection, CWE-922 sensitive data leakage).
  - `POST /api/devtools/console/exec`: Interactive diagnostic/probe command runner for the DevTools console.
- Add Network Inspect endpoints:
  - `GET /api/network/inspect`: Per-page latency, TTFB, transfer sizes, and security flags for all target routes.
  - `POST /api/network/probe`: Active loopback probe measuring live latency and headers.
- Add AI Copilot endpoints:
  - `POST /api/copilot/chat`: RAG-powered security assistant that answers queries using discovered findings, source code context, and CISA KEV threat intel.
  - `GET /api/copilot/recommendations`: Dynamic prioritized remediation recommendations based on active findings.
- Add Telemetry endpoints:
  - `GET /api/telemetry/attack-surface`: Topology nodes and threat vectors derived from database findings.
  - `GET /api/telemetry/radar`: Category scores across OWASP domains (Authentication, Authorization, Input Validation, API Security, Data Privacy, Client-side Security).

#### [MODIFY] [backend/src/wmsa/orchestrator.py](file:///Users/vaibhavjain/Downloads/PS%20AD/backend/src/wmsa/orchestrator.py)
- Auto-initialize target clone if `target/` directory is not yet cloned when a scan is initiated.
- Add robust fallback scanner execution: if external binaries (Semgrep, Gitleaks, OSV-Scanner) are not installed in the execution environment, execute direct AST/regex rule patterns matching `backend/rules/semgrep/worldmonitor/wm-security-rules.yml` and `rules/gitleaks/worldmonitor.toml` so scans discover real World Monitor vulnerabilities without missing dependencies.

#### [MODIFY] [backend/src/wmsa/target.py](file:///Users/vaibhavjain/Downloads/PS%20AD/backend/src/wmsa/target.py)
- Ensure target repository clone handles offline or pre-existing repositories smoothly.
- Add simulated live route response generator when target loopback container is starting up or in standalone test mode.

---

### Frontend Services & Components (`frontend/`)

#### [MODIFY] [frontend/src/services/api.ts](file:///Users/vaibhavjain/Downloads/PS%20AD/frontend/src/services/api.ts)
- Add TypeScript interfaces and API client functions for:
  - `fetchDevToolsNetwork()`
  - `fetchDevToolsSecurity()`
  - `fetchDevToolsPerformance()`
  - `fetchDevToolsStorage()`
  - `executeDevToolsConsoleCommand()`
  - `fetchNetworkInspect()`
  - `probeNetworkEndpoint()`
  - `askCopilot()`
  - `fetchCopilotRecommendations()`
  - `fetchAttackSurfaceData()`
  - `fetchRadarData()`

#### [MODIFY] [frontend/src/components/ChromeDevToolsSuite.tsx](file:///Users/vaibhavjain/Downloads/PS%20AD/frontend/src/components/ChromeDevToolsSuite.tsx)
- Connect Network tab to `/api/devtools/network` with search, filtering, and live refresh.
- Connect Security tab to `/api/devtools/security` showing live header audits and TLS analysis.
- Connect Application tab to `/api/devtools/storage` showing real token and cookie findings.
- Connect Performance tab to `/api/devtools/performance` showing live Core Web Vitals.
- Connect Console tab to `/api/devtools/console/exec` allowing interactive command execution.

#### [MODIFY] [frontend/src/components/NetworkInspectView.tsx](file:///Users/vaibhavjain/Downloads/PS%20AD/frontend/src/components/NetworkInspectView.tsx)
- Wire `handleRefresh` and metrics table to `/api/network/inspect` and `/api/network/probe`.
- Show live TTFB, latency, and status codes for World Monitor endpoints.

#### [MODIFY] [frontend/src/components/AiAssistant.tsx](file:///Users/vaibhavjain/Downloads/PS%20AD/frontend/src/components/AiAssistant.tsx)
- Wire chat box to `/api/copilot/chat` with real-time response generation.
- Load dynamic recommendations from `/api/copilot/recommendations` based on real database findings.

#### [MODIFY] [frontend/src/components/SecurityRadar.tsx](file:///Users/vaibhavjain/Downloads/PS%20AD/frontend/src/components/SecurityRadar.tsx)
- Fetch live category risk scores from `/api/telemetry/radar`.

#### [MODIFY] [frontend/src/components/AttackSurfaceMap.tsx](file:///Users/vaibhavjain/Downloads/PS%20AD/frontend/src/components/AttackSurfaceMap.tsx)
- Fetch active topology node findings counts from `/api/telemetry/attack-surface`.

#### [MODIFY] [frontend/src/components/FindingsTable.tsx](file:///Users/vaibhavjain/Downloads/PS%20AD/frontend/src/components/FindingsTable.tsx)
- Ensure empty state and live findings state transition seamlessly upon scan completion.
- Support instant reload upon scan completion or status updates.

#### [MODIFY] [frontend/src/pages/Dashboard.tsx](file:///Users/vaibhavjain/Downloads/PS%20AD/frontend/src/pages/Dashboard.tsx)
- Propagate live scan completion events across all active tabs.

---

## Verification Plan

### Automated Tests
1. **API Endpoints Test**:
   - Verify all new endpoints (`/api/devtools/*`, `/api/network/*`, `/api/copilot/*`, `/api/telemetry/*`) return HTTP 200 with valid JSON contracts.
2. **Frontend Production Build**:
   - `cd frontend && npm run build` (Type check and Vite bundle compilation).
3. **End-to-End Scan & Ingestion Flow**:
   - Trigger scan via `POST /api/scan`, verify findings are populated in database and visible in `GET /api/findings`.
4. **Report Export**:
   - Verify HTML and JSON report export endpoints (`/api/report/export?format=html`, `/api/report/export?format=json`).

### Manual Verification
1. Launch backend (`python -m uvicorn wmsa.api:api_app --host 127.0.0.1 --port 8000`).
2. Launch frontend (`npm run dev`).
3. Open Dashboard in browser:
   - Check clean-slate baseline (0 findings initially).
   - Navigate to **Admin & Target Setup**, configure target repository and trigger a scan.
   - Inspect live streaming scan logs.
   - Verify **Findings & PoC** tab displays detected findings (SSRF, CORS, Secrets, Auth, etc.).
   - Open **Chrome DevTools Suite** tab and verify Network requests, Security headers, Storage tokens, and Console logs.
   - Open **AI Security Copilot** and ask questions regarding detected vulnerabilities.
   - Click a finding in Findings Table, open `VulnModal`, and verify Triage, Verify, and Reject state transitions.
   - Download assessment report in HTML/JSON.
