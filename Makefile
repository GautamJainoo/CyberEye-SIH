# WMSA (World Monitor Security Assessment) Makefile
# SIH 2026, Problem Statement ID 26163

VENV ?= backend/.venv
PYTHON ?= $(VENV)/bin/python
PYTEST ?= $(VENV)/bin/pytest
WMSA ?= $(PYTHON) -m wmsa.cli

.PHONY: all help install check scan report server dashboard clean target-up target-down scope-validate

help:
	@echo "WMSA - World Monitor Security Assessment Platform"
	@echo "Available targets:"
	@echo "  make install        Create backend/.venv and install dependencies (uv if available)"
	@echo "  make check          Run the full test suite (79 tests: unit, lifecycle, calibration, regressions)"
	@echo "  make scan           Run orchestrated multi-scanner assessment (lite profile)"
	@echo "  make report         Export canonical JSON and HTML assessment reports"
	@echo "  make server         Launch local FastAPI assessment API (127.0.0.1:8000)"
	@echo "  make dashboard      Build and serve the Next.js dashboard (127.0.0.1:3100)"
	@echo "  make target-up      Start isolated World Monitor target build on loopback"
	@echo "  make target-down    Stop isolated World Monitor target build"
	@echo "  make scope-validate Validate active scope manifest strictly against loopback"
	@echo "  make clean          Clean test caches, logs, and temporary artifacts"

install:
	@if command -v uv >/dev/null 2>&1; then \
		uv venv $(VENV) && uv pip install --python $(PYTHON) -e "backend[dev,postgres,scanners]"; \
	else \
		python3 -m venv $(VENV) && $(PYTHON) -m pip install -e "backend[dev,postgres,scanners]"; \
	fi

check:
	$(PYTEST) -v backend/tests

scan:
	$(WMSA) scan --profile lite

report:
	$(WMSA) report export --format json --out backend/reports/worldmonitor_security_report.json
	$(WMSA) report export --format html --out backend/reports/worldmonitor_security_report.html

server:
	$(WMSA) server --port 8000

dashboard:
	cd frontend && npm ci && npm run build && npm start

target-up:
	$(WMSA) target up

target-down:
	$(WMSA) target down

scope-validate:
	$(WMSA) scope validate

clean:
	rm -rf .pytest_cache .coverage data/intel_cache/*.tmp __pycache__
