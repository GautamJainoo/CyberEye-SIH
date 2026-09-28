# Project Progress & Implementation Status: SecureLens (WMSA)
**World Monitor Security Assessment Workflow — Smart India Hackathon (SIH 2026, PS 26163)**

---

## 1. Executive Summary

SecureLens (WMSA) is an enterprise-grade, high-assurance Application Security Assessment & Vulnerability Management platform. It combines automated multi-modal security scanners (SAST, SCA, Secrets, DAST), manual review probes, CISA Known Exploited Vulnerabilities (KEV) threat intelligence, an append-only cryptographic evidence gate, and an interactive real-time analyst dashboard.

The system is engineered strictly for safe, isolated, and reproducible vulnerability auditing, adhering to strict loopback constraints (`127.0.0.1:3000`), zero external data leakage, and tamper-evident audit trails.

---

## 2. Directory Architecture (Two-Folder Layout)

Per architectural requirements, the entire repository is consolidated into strictly two primary operational directories with root-level orchestration:

```
Secure-Lens-SIH/
├── backend/                  # Complete Python 3.14 + FastAPI + PostgreSQL engine
│   ├── config/               # Assessment scope & scanner definitions (scope.yaml, tools.lock.json)
│   ├── docker/               # Isolated Docker environments (OWASP ZAP DAST container)
│   ├── probes/               # Custom vulnerability probe recipes, runners & review notes
│   ├── rules/                # Curated Semgrep SAST rules for target stack
│   ├── src/wmsa/             # Core WMSA framework source modules
│   │   ├── adapters/         # Semgrep, Gitleaks, OSV-Scanner, and OWASP ZAP adapters
│   │   ├── api.py            # FastAPI REST API endpoints (bound to 127.0.0.1:8000)
│   │   ├── calibration.py    # Ground truth validation & metric benchmarking
│   │   ├── cli.py            # CLI management commands (wmsa)
│   │   ├── db.py             # PostgreSQL 15 engine + SQLite fallback & PL/pgSQL triggers
│   │   ├── evidence.py       # Cryptographic evidence capture (SHA-256)
│   │   ├── intel.py          # Threat intelligence sync (OSV, GHSA, CISA KEV)
│   │   ├── lifecycle.py      # Append-only state machine & actor permission gate
│   │   ├── llm.py            # Redacted local LLM Copilot (prompt injection immune)
│   │   ├── orchestrator.py   # Multi-scanner execution & pipeline coordinator
│   │   ├── patching.py       # Git worktree patch sandbox manager
│   │   ├── report.py         # Tamper-evident HTML/JSON audit report generator
│   │   ├── retest.py         # Deterministic exact recipe replay engine
│   │   ├── scope.py          # Fail-closed scope guard & emergency kill switch
│   │   └── target.py         # Dynamic target repository cloner & endpoint inspector
│   └── tests/                # 56 automated test suites across all subsystems
├── frontend/                 # Modern React 19 + TypeScript + Vite + Tailwind dashboard
│   ├── src/
│   │   ├── components/       # UI components (AdminPanel, FindingsTable, ScanModal, etc.)
│   │   ├── pages/            # View pages (Dashboard.tsx)
│   │   ├── services/         # Real-time API bridge to backend (services/api.ts)
│   │   ├── types.ts          # Strongly typed vulnerability & finding definitions
│   │   └── data.ts           # Clean baseline initial state (zero dummy data)
│   ├── package.json          # Frontend dependencies & scripts
│   └── vite.config.ts        # Vite development server configuration
├── Makefile                  # Project-wide build, test, and run automation
├── README.md                 # Complete system documentation & quickstart guide
├── pyproject.toml            # Backend dependencies & metadata
└── what_we_have_done.md      # This detailed progress and status record
```

---

## 3. Key Completed Capabilities

### 3.1. Strict Scope Guard & Kill Switch (`backend/src/wmsa/scope.py`)
- **Fail-Closed Enforcement**: Blocks all out-of-scope network traffic, private IP ranges (except explicitly allowed loopback), and public internet endpoints.
- **DNS Rebinding Protection & Canonicalization**: Validates all targets against loopback (`127.0.0.1:3000`).
- **Emergency Kill Switch**: Capable of halting all running scans and container processes immediately upon scope violation.

### 3.2. Multi-Scanner Security Adapter Pipeline (`backend/src/wmsa/adapters/`)
- **Semgrep (SAST)**:
  - Executes offline custom rules (`rules/semgrep/worldmonitor/`) with telemetry strictly disabled (`--metrics=off`).
  - Snippet hashing and normalization into standard canonical findings.
- **Gitleaks (Secrets)**:
  - Scans Git history and filesystem with `--redact` enabled to prevent secrets from being printed to logs.
  - Generates salted HMAC fingerprints to track credentials across commits without persisting raw secrets.
- **OSV-Scanner (SCA)**:
  - Extracts and analyzes dependencies from lockfiles (`package-lock.json`, `pnpm-lock.yaml`, etc.).
  - Cross-references packages against Google OSV database and Github Security Advisories.
- **OWASP ZAP (DAST)**:
  - Runs in an isolated Docker container with pre-configured network restrictions.
  - Dynamically constructs automation plans targeting only verified loopback routes.

### 3.3. Target Setup & Admin Panel (Custom Target Scanning)
- **Interactive Admin Panel (`frontend/src/components/AdminPanel.tsx`)**:
  - Allows entering custom **GitHub Repository URL** (e.g. `https://github.com/koala73/worldmonitor`).
  - Allows entering custom **Website Endpoint URL** (e.g. `http://127.0.0.1:3000`).
  - Supports specifying custom Git commit SHAs or branches (auto-resolves `HEAD`).
  - Features a **"Configure & Clone Target"** button that dynamically clones and pins the target repository.
  - Live target health indicator showing whether the web application is actively responding on loopback.
  - **"Run Security Audit Now"** trigger with live streaming execution logs in the console panel.
  - **"Purge All Findings"** button to reset assessment state.

### 3.4. Clean-Slate Baseline (Zero Dummy Data)
- **Elimination of Mock Data**:
  - Removed all 12 hardcoded mock vulnerabilities, simulated telemetry metrics, and fake attack maps from `frontend/src/data.ts`.
  - App opens with a clean slate (`0 Total Vulnerabilities`, empty findings table, zeroed metrics) until a real target is configured and scanned.
  - Added clean empty-state UI views informing analysts when no vulnerabilities have yet been detected.

### 3.5. Enterprise PostgreSQL Database Migration (`backend/src/wmsa/db.py`)
- **Active PostgreSQL 15 Engine**:
  - Migrated from local SQLite file storage to PostgreSQL 15 (`postgresql://localhost:5432/wmsa`).
  - Complete relational DDL schema with primary keys, foreign keys, and indexes.
  - **Tamper-Evident Append-Only Triggers**: Written in PL/pgSQL (`prevent_modifications_transitions()`, `prevent_modifications_audit()`) to disallow updating or deleting historical transitions or audit records.
  - **Transparent Adapter Wrapper (`PostgresConnectionWrapper`)**: Automatically translates SQLite-style `?` parameter placeholders to PostgreSQL `%s`, handles `INSERT ... ON CONFLICT DO UPDATE`, and resolves auto-increment `RETURNING` clauses.
  - Seamless fallback mechanism to SQLite for offline fixture testing when PostgreSQL service is unavailable.

### 3.6. Cryptographic Evidence Gate & Lifecycle State Machine (`backend/src/wmsa/lifecycle.py`)
- **Lifecycle States**: `DISCOVERED` → `TRIAGED` → `VERIFIED` → `PATCH_PROPOSED` → `FIXED` (or `REJECTED`).
- **Actor Authorization Policy**:
  - Automated tools and LLMs are strictly forbidden from promoting findings to `VERIFIED` or `FIXED`.
  - Only human analysts with valid cryptographic evidence hashes (SHA-256 of raw tool output or retest diff) can transition state.
- **Audit Log**: Immutable append-only log of every state transition, actor ID, and rationale.

### 3.7. Patch Management & Exact Retest Engine (`backend/src/wmsa/retest.py`)
- **Isolated Worktrees**: Creates temporary Git worktrees to apply prospective security patches.
- **Exact Recipe Replay**: Automatically re-runs the exact probe or scanner recipe that originally triggered the vulnerability.
- **Diff Verification**: Validates that the patch eliminates the vulnerability without causing regressions.

### 3.8. Threat Intelligence & CISA KEV Sync (`backend/src/wmsa/intel.py`)
- **CISA KEV Integration**: Synchronizes the CISA Known Exploited Vulnerabilities catalog.
- **Advisory Indexing**: Indexes CVEs and GHSAs with full-text search capability.
- **Automatic Matching**: Flags any finding matching an active in-the-wild exploit catalog entry.

### 3.9. Guarded Local LLM Copilot (`backend/src/wmsa/llm.py`)
- **Local Ollama / vLLM Support**: Supports local LLM inference without sending sensitive code to third-party APIs.
- **Pre-Context Redaction**: Automatically scrubs secrets, IP addresses, credentials, and PII before prompting.
- **Prompt Injection Defense**: Strictly isolates untrusted source code snippets within XML fences and rejects unauthorized instruction modifications.

### 3.10. Frontend-Backend Real-Time Integration
- **Live REST Client (`frontend/src/services/api.ts`)**:
  - Connected to FastAPI at `http://127.0.0.1:8000/api`.
  - Polling and live updating of backend health, findings count, target commit, and scan progress.
- **Analyst Workflow Actions**:
  - Vulnerability detail modal with one-click actions: Triage, Verify, Reject.
  - Export audit report in HTML or JSON formats directly from the dashboard.

---

## 4. Test Verification & Calibration

- **Test Suite**: 56 out of 56 unit and integration tests passing (`pytest backend/tests`):
  - `test_adapters.py`: Semgrep, Gitleaks, OSV-Scanner fixture parsing.
  - `test_api.py`: FastAPI route contracts, CORS, and response models.
  - `test_calibration.py`: Planted vulnerability ground truth verification (100% precision & recall).
  - `test_db.py`: Database schema, append-only triggers, and query wrappers.
  - `test_intel.py`: Threat intel sync, CISA KEV matching, and cache freshness.
  - `test_lifecycle.py`: State transition rules, actor gates, and rejection logic.
  - `test_llm.py`: Redaction filter and prompt injection resistance.
  - `test_probes.py`: Safe probe execution within loopback.
  - `test_report.py`: HTML/PDF/JSON report generator.
  - `test_retest.py`: Patch retest engine and regression verification.
  - `test_scope.py`: Scope guard allow/block matrix and kill switch triggers.
  - `test_target.py`: Target setup, git cloning, and health check.
  - `test_zap.py`: DAST plan generation and alert parsing.

---

## 5. Implementation Roadmap Status

| Phase | Milestone Description | Status |
|---|---|:---:|
| **Phase 0** | Foundations, Scope Guard (`127.0.0.1:3000`), Kill Switch, Target Setup | **Complete** |
| **Phase 1** | SAST (Semgrep), Secrets (Gitleaks), SCA (OSV-Scanner) Adapters | **Complete** |
| **Phase 2** | Custom World Monitor Probes, Runners, and Review Notes | **Complete** |
| **Phase 2b** | DAST (OWASP ZAP) Docker Adapter & Automated Plan Builder | **Complete** |
| **Phase 3** | Canonical Pydantic Schema, Deduplication, Cryptographic Evidence Gate | **Complete** |
| **Phase 4** | Patch Manager & Exact Retest Workflow Engine | **Complete** |
| **Phase 5** | Audit Reporting (HTML, PDF, JSON) & FastAPI Backend Layer | **Complete** |
| **Phase 6** | Threat Intelligence Sync & CISA KEV Vulnerability Matcher | **Complete** |
| **Phase 7** | Guarded Local LLM Copilot (PII Redaction & Injection Defense) | **Complete** |
| **Phase 8** | Calibration Fixtures & Ground-Truth Verification (56/56 Tests) | **Complete** |
| **Structure** | Repository Consolidation into Strict Two-Folder Structure (`frontend/` & `backend/`) | **Complete** |
| **Phase 9** | Full Frontend-Backend Live Connection & Real-Time Dashboard Bridge | **Complete** |
| **Phase 10** | Clean-Slate Zero Dummy Data & Custom Target Admin Panel (GitHub + URL) | **Complete** |
| **Phase 11** | PostgreSQL 15 Enterprise DB Migration & Documentation | **Complete** |

---

## 6. How to Run the Project

### 6.1. Start Database
```bash
# Ensure PostgreSQL 15 is running locally
brew services start postgresql@15
# (Database 'wmsa' is pre-created and configured)
```

### 6.2. Start Backend API
```bash
# From repository root
.venv/bin/python -m uvicorn wmsa.api:api_app --host 127.0.0.1 --port 8000
```

### 6.3. Start Frontend Dashboard
```bash
# In another terminal from repository root
cd frontend && npm run dev -- --host 127.0.0.1 --port 5173
```

### 6.4. Access Application
- **Frontend Dashboard**: Open [http://127.0.0.1:5173](http://127.0.0.1:5173) in your browser.
- **Admin Panel**: Click on the **Admin** tab in the sidebar to configure any target GitHub repository or website URL, run a scan, or purge findings.
- **Backend API & Swagger Docs**: Available at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).
