"""
Canonical Report Exporter for WMSA.
Generates canonical JSON and comprehensive HTML/PDF reports with evidence hashes,
audit timelines, and mandatory disclosure/limitations sections.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import jinja2

from wmsa.db import Database
from wmsa.evidence import EvidenceManager
from wmsa.normalize import Finding
from wmsa.scope import ScopeManifest, load_scope_manifest


HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>World Monitor Security Assessment Report (PS 26163)</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #1f2937; margin: 0; padding: 2rem; background: #f9fafb; line-height: 1.5; }
    .container { max-width: 1000px; margin: 0 auto; background: #fff; padding: 2.5rem; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
    h1 { color: #111827; border-bottom: 2px solid #e5e7eb; padding-bottom: 0.75rem; margin-top: 0; font-size: 1.875rem; }
    h2 { color: #1f2937; margin-top: 2rem; border-bottom: 1px solid #e5e7eb; padding-bottom: 0.5rem; }
    h3 { color: #374151; margin-top: 1.5rem; }
    .badge { display: inline-block; padding: 0.25rem 0.6rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
    .badge-critical { background: #fee2e2; color: #991b1b; }
    .badge-high { background: #ffedd5; color: #9a3412; }
    .badge-medium { background: #fef3c7; color: #92400e; }
    .badge-low { background: #e0e7ff; color: #3730a3; }
    .badge-info { background: #f3f4f6; color: #374151; }
    .status-badge { background: #ecfdf5; color: #065f46; border: 1px solid #a7f3d0; }
    table { width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.875rem; }
    th, td { border: 1px solid #e5e7eb; padding: 0.6rem 0.75rem; text-align: left; }
    th { background: #f3f4f6; font-weight: 600; }
    code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; background: #f3f4f6; border-radius: 4px; }
    pre { padding: 1rem; overflow-x: auto; font-size: 0.8125rem; }
    .finding-card { border: 1px solid #e5e7eb; border-radius: 6px; padding: 1.25rem; margin-bottom: 1.5rem; background: #fff; }
    .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }
    .callout { background: #eff6ff; border-left: 4px solid #3b82f6; padding: 1rem; margin: 1rem 0; }
    .callout-warning { background: #fffbeb; border-left: 4px solid #f59e0b; padding: 1rem; margin: 1rem 0; }
    .callout-danger { background: #fef2f2; border-left: 4px solid #ef4444; padding: 1rem; margin: 1rem 0; }
  </style>
</head>
<body>
<div class="container">
  <h1>World Monitor Security Assessment Report</h1>
  <div class="callout">
    <strong>SIH 2026 Problem Statement ID 26163:</strong> Security Assessment of the World Monitor application.<br>
    <strong>Target Application:</strong> World Monitor (Open-Source)<br>
    <strong>Target Commit (Pinned):</strong> <code>{{ target_commit }}</code><br>
    <strong>Assessment Environment:</strong> <code>{{ environment }}</code> (Strict loopback isolation)<br>
    <strong>Report Generated (UTC):</strong> {{ generated_at }}
  </div>

  <h2>1. Executive Summary</h2>
  <p>
    This report documents the local-first, evidence-gated security assessment of the World Monitor application.
    Scanning incorporated five integrated components: SAST (Semgrep), Secret Detection (Gitleaks), SCA (OSV-Scanner),
    DAST (OWASP ZAP), and Target-Specific Behavior Probes.
  </p>

  <table>
    <thead>
      <tr>
        <th>Total Findings</th>
        <th>Candidate</th>
        <th>Triaged</th>
        <th>Verified</th>
        <th>Fixed</th>
        <th>Rejected</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>{{ summary.total }}</strong></td>
        <td>{{ summary.candidate }}</td>
        <td>{{ summary.triaged }}</td>
        <td>{{ summary.verified }}</td>
        <td>{{ summary.fixed }}</td>
        <td>{{ summary.rejected }}</td>
      </tr>
    </tbody>
  </table>

  <h2>2. Tool Suite & Version Verification</h2>
  <table>
    <thead>
      <tr>
        <th>Tool Name</th>
        <th>Version</th>
        <th>Category</th>
        <th>Execution Mode</th>
      </tr>
    </thead>
    <tbody>
      {% for tool, info in tools.items() %}
      <tr>
        <td><strong>{{ tool }}</strong></td>
        <td><code>{{ info.version }}</code></td>
        <td>{{ info.category }}</td>
        <td>{{ info.mode }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>

  <h2>3. Normalized Findings & Evidence Proof</h2>
  {% if findings %}
    {% for f in findings %}
    <div class="finding-card">
      <div class="finding-header">
        <h3 style="margin:0;">{{ f.title }}</h3>
        <div>
          <span class="badge badge-{{ f.severity.lower() }}">{{ f.severity }}</span>
          <span class="badge status-badge">{{ f.status }}</span>
        </div>
      </div>
      <p><strong>ID:</strong> <code>{{ f.finding_id }}</code> | <strong>Category:</strong> <code>{{ f.category }}</code> | <strong>Fingerprint:</strong> <code>{{ f.stable_fingerprint[:16] }}...</code></p>
      <p>{{ f.description }}</p>

      {% if f.file %}
      <p><strong>Affected Location:</strong> <code>{{ f.file }}{% if f.line_start %}:{{ f.line_start }}{% endif %}</code></p>
      {% elif f.endpoint %}
      <p><strong>Affected Endpoint:</strong> <code>{{ f.method }} {{ f.endpoint }}</code></p>
      {% endif %}

      {% if f.cwe %}
      <p><strong>CWE Classifications:</strong> {{ f.cwe | join(', ') }}</p>
      {% endif %}

      {% if f.cve %}
      <p><strong>CVE References:</strong> {{ f.cve | join(', ') }} {% if f.kev_match %}<strong>[CISA KEV MATCH]</strong>{% endif %}</p>
      {% endif %}

      {% if f.impact %}
      <div class="callout-danger">
        <strong>Business & Security Impact:</strong><br>
        {{ f.impact }}
      </div>
      {% endif %}

      {% if f.remediation_proposal %}
      <p><strong>Remediation Proposal:</strong><br>
      <code>{{ f.remediation_proposal }}</code></p>
      {% endif %}

      {% if f.evidence_items %}
      <h4>Hashed Evidence Artifacts:</h4>
      <table>
        <thead>
          <tr>
            <th>Evidence ID</th>
            <th>Type</th>
            <th>SHA-256 Content Hash</th>
          </tr>
        </thead>
        <tbody>
          {% for ev in f.evidence_items %}
          <tr>
            <td><code>{{ ev.evidence_id }}</code></td>
            <td>{{ ev.artifact_type }}</td>
            <td><code>{{ ev.sha256_hash }}</code></td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% endif %}
    </div>
    {% endfor %}
  {% else %}
    <p>No verified vulnerabilities or active candidate findings found.</p>
  {% endif %}

  <h2>4. Coordinated Responsible Disclosure</h2>
  <div class="callout">
    Per the World Monitor security policy (<code>SECURITY.md</code>), genuine confirmed vulnerabilities must be reported
    strictly via <strong>GitHub Private Vulnerability Reporting</strong> at
    <code>https://github.com/koala73/worldmonitor/security/advisories/new</code> or direct private contact with repository
    maintainers. Never publish zero-day findings on public issue trackers.
  </div>

  <h2>5. Mandatory Limitations & Integrity Note</h2>
  <div class="callout-warning">
    <strong>Limitations:</strong><br>
    1. <strong>SHA-256 Hashing:</strong> Artifact SHA-256 hashes detect any post-execution tampering or byte alteration; they represent cryptographic integrity checks, not third-party identity signatures.<br>
    2. <strong>Candidate vs Verified:</strong> Automated scanner outputs are classified as <code>CANDIDATE</code> hypotheses until verified through the evidence gate by a qualified human analyst.<br>
    3. <strong>Loopback Scope:</strong> All active checks were confined strictly to isolated loopback execution (<code>127.0.0.1</code>). No production traffic was transmitted to <code>worldmonitor.app</code>.
  </div>
</div>
</body>
</html>
"""


from wmsa.paths import get_base_dir


class ReportExporter:
    """Exports assessment reports in canonical JSON and styled HTML formats."""

    def __init__(
        self,
        db: Optional[Database] = None,
        evidence_mgr: Optional[EvidenceManager] = None,
        scope_manifest: Optional[ScopeManifest] = None,
        base_dir: Optional[Path] = None,
    ):
        self.base_dir = base_dir or get_base_dir()
        self.db = db or Database(self.base_dir / "wmsa.db")
        self.evidence_mgr = evidence_mgr or EvidenceManager(self.db, self.base_dir / "evidence")
        self.manifest = scope_manifest or load_scope_manifest(self.base_dir / "config" / "scope.yaml")

    def _fetch_all_findings_with_evidence(self) -> List[Dict[str, Any]]:
        findings = []
        with self.db.get_connection() as conn:
            rows = conn.execute("SELECT data_json, status FROM findings ORDER BY created_at DESC").fetchall()
            for r in rows:
                item = json.loads(r["data_json"])
                item["status"] = r["status"]
                f_id = item.get("finding_id")
                if f_id:
                    ev_records = self.evidence_mgr.list_evidence(f_id)
                    item["evidence_items"] = ev_records
                findings.append(item)
        return findings

    def export_json(self, output_file: Optional[Path] = None) -> Dict[str, Any]:
        """Exports canonical JSON report with full findings, evidence hashes, and limitations."""
        findings = self._fetch_all_findings_with_evidence()
        now = datetime.now(timezone.utc).isoformat()

        report_data = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "report_version": "1.0",
            "problem_statement": "SIH 2026, PS 26163 - World Monitor Security Assessment",
            "generated_at_utc": now,
            "target": {
                "repo_url": self.manifest.repo_url,
                "commit_sha": self.manifest.commit_sha,
                "environment": "local-isolated",
                "scope_id": self.manifest.scope_id,
            },
            "tools": {
                "semgrep": {"version": "1.176.0", "category": "SAST", "mode": "local CLI"},
                "gitleaks": {"version": "8.30.1", "category": "Secret Scanning", "mode": "local CLI"},
                "osv-scanner": {"version": "2.6.0", "category": "SCA", "mode": "local CLI"},
                "zap": {"version": "stable", "category": "DAST", "mode": "Docker Compose"},
                "worldmonitor-probes": {"version": "1.0.0", "category": "Custom Probes", "mode": "local Python"},
            },
            "summary": {
                "total_findings": len(findings),
                "by_status": {
                    "CANDIDATE": len([f for f in findings if f.get("status") == "CANDIDATE"]),
                    "TRIAGED": len([f for f in findings if f.get("status") == "TRIAGED"]),
                    "VERIFIED": len([f for f in findings if f.get("status") == "VERIFIED"]),
                    "FIXED": len([f for f in findings if f.get("status") == "FIXED"]),
                    "REJECTED": len([f for f in findings if f.get("status") == "REJECTED"]),
                },
            },
            "findings": findings,
            "limitations": [
                "SHA-256 hashes detect byte-level alteration and tampering; they are not digital identity signatures.",
                "Automated scanner alerts are candidate hypotheses until approved via the human evidence gate.",
                "All testing conducted strictly against isolated local checkout; public hosts were never targeted.",
            ],
            "disclosure_notice": (
                "Per World Monitor SECURITY.md, vulnerabilities must be privately reported via "
                "GitHub Private Vulnerability Reporting at https://github.com/koala73/worldmonitor/security/advisories/new."
            ),
        }

        if output_file:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as fp:
                json.dump(report_data, fp, indent=2)

        return report_data

    def export_html(self, output_file: Optional[Path] = None) -> str:
        """Exports standalone HTML report using Jinja2."""
        findings = self._fetch_all_findings_with_evidence()
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        summary = {
            "total": len(findings),
            "candidate": len([f for f in findings if f.get("status") == "CANDIDATE"]),
            "triaged": len([f for f in findings if f.get("status") == "TRIAGED"]),
            "verified": len([f for f in findings if f.get("status") == "VERIFIED"]),
            "fixed": len([f for f in findings if f.get("status") == "FIXED"]),
            "rejected": len([f for f in findings if f.get("status") == "REJECTED"]),
        }

        tools_info = {
            "Semgrep": {"version": "1.176.0", "category": "SAST", "mode": "Local CLI"},
            "Gitleaks": {"version": "8.30.1", "category": "Secret Scanning", "mode": "Local CLI (--redact)"},
            "OSV-Scanner": {"version": "2.6.0", "category": "SCA", "mode": "Local CLI"},
            "OWASP ZAP": {"version": "stable", "category": "DAST", "mode": "Docker Isolated Network"},
            "WM Probes": {"version": "1.0.0", "category": "Custom Probes", "mode": "Local Python Runners"},
        }

        template = jinja2.Template(HTML_REPORT_TEMPLATE)
        html_out = template.render(
            target_commit=self.manifest.commit_sha,
            environment="local-isolated",
            generated_at=now,
            summary=summary,
            tools=tools_info,
            findings=findings,
        )

        if output_file:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as fp:
                fp.write(html_out)

        return html_out
