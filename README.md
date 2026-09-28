# Secure-Lens-SIH
> **Problem Statement ID**: 26163  
> **Problem Statement Title**: Security Assessment of the World Monitor application  
> **Target Application**: [worldmonitor.app](https://worldmonitor.app) | **Source Code**: [github.com/koala73/worldmonitor](https://github.com/koala73/worldmonitor)  
> **Theme**: Smart Automation  

An end-to-end Automated Security Assessment & Real-Time Performance Monitoring Platform featuring multi-scanner orchestration, vulnerability proof-of-concept (PoC) validation, full Chrome DevTools Inspect telemetry, and an AI Security Copilot (NLP + RAG).

---

## 🗂️ Project Structure

```text
Secure-Lens-SIH/
├── .gitignore                   # Root gitignore (node_modules, venv, secrets, logs)
├── README.md                    # Project documentation
│
├── frontend/                    # React + Vite + Tailwind CSS Frontend
│   ├── .gitignore
│   ├── package.json
│   ├── tailwind.config.js
│   ├── vite.config.ts
│   ├── public/
│   └── src/
│       ├── components/          # HeroBanner, DevToolsSuite, StatCards, VulnModal, etc.
│       ├── pages/               # Dashboard (Overview, Inspect & Speed, Scanner, Reports)
│       ├── types.ts             # Shared TypeScript schemas
│       └── data.ts              # Telemetry & SIH vulnerability dataset
│
└── backend/                     # FastAPI + Celery / Scanners Backend
    ├── .gitignore
    ├── requirements.txt
    ├── main.py                  # API layer (Scan orchestration, findings, AI chat)
    └── README.md
```

---

## 🚀 Getting Started

### 1. Frontend Setup (React + Vite)
```bash
cd frontend
npm install
npm run dev
```
Open **`http://localhost:5173`** in your browser.

### 2. Backend Setup (FastAPI)
```bash
cd backend
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```
Open **`http://localhost:8000/docs`** for interactive Swagger API documentation.

---

## 🛡️ SIH PS 26163 Key Features

1. **Multi-Module Automated Scanning Pipeline**:
   - **6.1 SAST (Semgrep)**: Code-level vulnerability analysis (SQL injection, XSS, input validation).
   - **6.2 Secret Scanning (Gitleaks)**: API keys, tokens, hardcoded production credentials.
   - **6.3 SCA (OSV-Scanner)**: Dependency analysis and third-party CVE lookups.
   - **6.4 DAST (OWASP ZAP)**: Dynamic runtime application probes and security headers review.

2. **Vulnerability Documentation & Evidence (Deliverables)**:
   - Each vulnerability includes: CVSS v3.1 score, affected components, step-by-step reproduction guide in controlled environments, **Safe Proof of Concept (PoC)** payloads, business impact, and remediation code snippets.

3. **Chrome DevTools Inspect Suite**:
   - **Network Tab**: Waterfall timeline, request size, latency, TTFB, and vulnerability highlighting.
   - **Performance Tab**: Core Web Vitals (LCP 0.78s with element breakdown, CLS 0.00, INP 45ms), flamegraph breakdown, and throttling toggles.
   - **Memory Tab**: Heap snapshot profiling, VM instance memory tree (`110 MB` total JS heap).
   - **Application & Storage Tab**: Cookies, LocalStorage security inspection (CWE-922 JWT storage alert), and Service Workers.
   - **Security Tab**: Valid HTTPS overview, Amazon RSA 2048 certificate viewer, TLS 1.3 settings, and security headers.

4. **AI Security Chatbot (NLP + RAG)**:
   - Understands user queries and retrieves relevant context from CVE databases, project code, and automated scan results.
   - Instant remediation generation and patch snippets.

5. **Multi-Format Executive Reporting**:
   - 1-click export to **PDF**, **JSON**, and **HTML**.

---

## 📄 License
MIT License
