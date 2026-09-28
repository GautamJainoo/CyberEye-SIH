# WMSA (World Monitor Security Assessment) Makefile
# SIH 2026, Problem Statement ID 26163

PYTHON ?= .venv/bin/python
PYTEST ?= .venv/bin/pytest
WMSA ?= .venv/bin/python -m wmsa.cli

.PHONY: all help install check scan report server clean target-up target-down scope-validate

help:
	@echo "WMSA - World Monitor Security Assessment Platform"
	@echo "Available targets:"
	@echo "  make install        Install Python dependencies into .venv"
	@echo "  make check          Run full test suite (56+ tests, unit, lifecycle, calibration)"
	@echo "  make scan           Run orchestrated multi-scanner assessment (lite profile)"
	@echo "  make report         Export canonical JSON and HTML assessment reports"
	@echo "  make server         Launch local FastAPI assessment API (127.0.0.1:8000)"
	@echo "  make target-up      Start isolated World Monitor target build on loopback"
	@echo "  make target-down    Stop isolated World Monitor target build"
	@echo "  make scope-validate Validate active scope manifest strictly against loopback"
	@echo "  make clean          Clean test caches, logs, and temporary artifacts"

install:
	$(PYTHON) -m pip install -e .

check:
	$(PYTEST) -v

scan:
	$(WMSA) scan --profile lite

report:
	$(WMSA) report export --format json --out reports/worldmonitor_security_report.json
	$(WMSA) report export --format html --out reports/worldmonitor_security_report.html

server:
	$(WMSA) server --port 8000

target-up:
	$(WMSA) target up

target-down:
	$(WMSA) target down

scope-validate:
	$(WMSA) scope validate

clean:
	rm -rf .pytest_cache .coverage data/intel_cache/*.tmp __pycache__
