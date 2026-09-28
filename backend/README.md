# Secure-Lens-SIH Backend API (FastAPI)

FastAPI backend implementing automated scanning orchestration, vulnerability correlation, and AI Security Copilot (NLP + RAG) for **SIH Problem Statement ID 26163: Security Assessment of the World Monitor application**.

## Prerequisites
- Python 3.9+
- pip

## Quickstart

1. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the development server:
```bash
uvicorn main:app --reload --port 8000
```

4. Open API Documentation:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## API Endpoints Overview
- `POST /api/scan`: Trigger automated scan across SAST (Semgrep), Secrets (Gitleaks), SCA (OSV-Scanner), and DAST (OWASP ZAP).
- `GET /api/findings`: Normalized vulnerabilities list with CVSS 3.1 ratings and safe PoCs.
- `POST /api/chat`: AI Security Chatbot query engine with RAG knowledge retrieval.
- `GET /api/inspect`: Chrome DevTools network, latency, and performance metrics.
