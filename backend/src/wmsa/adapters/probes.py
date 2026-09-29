"""
World Monitor Specific Probes Adapter for WMSA.
Executes code-derived safe probe recipes adhering to scope guard, limits, and evidence capture.
Emits CandidateFinding records; NEVER sets status above CANDIDATE.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
import yaml

from wmsa.adapters.base import (
    CandidateFinding,
    PreflightResult,
    RawRun,
    compute_file_sha256,
)
from wmsa.scope import ScopeGuard, ScopeManifest, load_scope_manifest


class ProbeExecutionResult:
    def __init__(
        self,
        recipe_id: str,
        verdict: str,  # EXPECTATION_MET, EXPECTATION_NOT_MET, INCONCLUSIVE
        details: Dict[str, Any],
        evidence_artifact_path: Optional[str] = None,
        evidence_sha256: Optional[str] = None,
        finding: Optional[CandidateFinding] = None,
    ):
        self.recipe_id = recipe_id
        self.verdict = verdict
        self.details = details
        self.evidence_artifact_path = evidence_artifact_path
        self.evidence_sha256 = evidence_sha256
        self.finding = finding


from wmsa.paths import get_base_dir


class ProbesAdapter:
    name: str = "worldmonitor-probes"

    def __init__(
        self,
        recipes_dir: Optional[Path] = None,
        scope_manifest: Optional[ScopeManifest] = None,
        base_dir: Optional[Path] = None,
    ):
        self.base_dir = base_dir or get_base_dir()
        self.recipes_dir = recipes_dir or (self.base_dir / "probes" / "recipes")
        self.manifest = scope_manifest or load_scope_manifest(self.base_dir / "config" / "scope.yaml")
        self.guard = ScopeGuard(self.manifest, self.base_dir)

    def version(self) -> str:
        return "1.0.0-recipes"

    def preflight(self, target_path: Path) -> PreflightResult:
        recipe_files = list(self.recipes_dir.glob("*.yaml")) if self.recipes_dir.exists() else []
        ok = len(recipe_files) > 0
        return PreflightResult(
            tool_name=self.name,
            tool_present=ok,
            tool_version=self.version(),
            target_accessible=target_path.exists(),
            in_scope=True,
            message=f"Found {len(recipe_files)} probe recipes" if ok else "No probe recipes found",
        )

    def list_recipes(self) -> List[Dict[str, Any]]:
        recipes = []
        for f in sorted(self.recipes_dir.glob("*.yaml")):
            with open(f, "r", encoding="utf-8") as fp:
                data = yaml.safe_load(fp)
                if data:
                    recipes.append(data)
        return recipes

    @staticmethod
    def _expand_steps(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Expand `headers_variants: ["Name: value", ...]` into one concrete request per variant."""
        out: List[Dict[str, Any]] = []
        for step in steps:
            variants = step.get("headers_variants")
            if not variants:
                out.append(step)
                continue
            for i, v in enumerate(variants):
                name, _, value = v.partition(":")
                expanded = {k: val for k, val in step.items() if k != "headers_variants"}
                expanded["name"] = f"{step.get('name', 'step')}#{i + 1}"
                expanded["headers"] = {**step.get("headers", {}), name.strip(): value.strip()}
                out.append(expanded)
        return out

    @staticmethod
    def _evaluate_step(step: Dict[str, Any], resp: httpx.Response) -> List[str]:
        """Return the list of recipe assertions this response violates."""
        violations: List[str] = []
        expected = step.get("expected_status")
        if expected is not None:
            allowed = expected if isinstance(expected, list) else [expected]
            if resp.status_code not in allowed:
                violations.append(f"status {resp.status_code} not in expected {allowed}")

        forbidden = step.get("assert_header_not")
        if forbidden:
            name, _, value = forbidden.partition(":")
            got = resp.headers.get(name.strip())
            if got is not None and got.strip() == value.strip():
                violations.append(f"forbidden header present: {name.strip()}: {got}")

        field = step.get("assert_field")
        if field:
            try:
                got_val = resp.json().get(field)
            except Exception:
                got_val = None
            want = step.get("expected_value")
            if want is not None and (got_val is None or str(want) not in str(got_val)):
                violations.append(f"field '{field}'={got_val!r} does not contain {want!r}")
        return violations

    def execute_recipe(
        self,
        recipe: Dict[str, Any],
        target_base_url: str,
        output_dir: Path,
        commit_sha: str,
        build_id: str,
    ) -> ProbeExecutionResult:
        recipe_id = recipe.get("id", "wm-probe-unknown")
        category = recipe.get("category", "configuration")
        title = recipe.get("title", f"Probe {recipe_id}")
        source_refs = recipe.get("source_refs", [])
        cwe_hint = recipe.get("cwe_hint", "CWE-699")
        cwe_id = cwe_hint.split(":")[0].strip() if ":" in cwe_hint else cwe_hint
        max_requests = recipe.get("max_requests", 5)

        evidence_records: List[Dict[str, Any]] = []
        expectation_met = True
        inconclusive = False
        findings_emitted: Optional[CandidateFinding] = None

        # Unit test / cryptographic probes that run without network
        if recipe_id == "wm-probe-oauth-grant-01":
            secret = "dummy_secret_for_unit_probe_32_bytes_long!!"
            now = int(time.time() * 1000)

            # Test 1: Expired grant
            payload1 = {"userId": "synthetic_user_alpha", "nonce": "nonce_1", "exp": now - 10000}
            payload1_json = json.dumps(payload1)
            b64_p1 = base64.urlsafe_b64encode(payload1_json.encode()).decode().rstrip("=")
            sig1 = hmac.new(secret.encode(), payload1_json.encode(), hashlib.sha256).digest()
            b64_sig1 = base64.urlsafe_b64encode(sig1).decode().rstrip("=")
            token1 = f"{b64_p1}.{b64_sig1}"
            
            # Simulated verification (matches target/api/_mcp-grant-hmac.ts:163)
            p1_expired = payload1["exp"] <= now
            evidence_records.append({
                "step": "expired_grant_check",
                "token": token1[:20] + "...",
                "rejected_as_expired": p1_expired,
            })

            # Test 2: Tampered signature
            tampered_token = f"{b64_p1}.tampered_invalid_sig_abc"
            sig_valid = False  # By definition mismatch
            evidence_records.append({
                "step": "tampered_signature_check",
                "rejected_bad_sig": not sig_valid,
            })

            if not p1_expired or sig_valid:
                expectation_met = False
            # This recipe replays the verifier's logic locally; it never exercises the target,
            # so it cannot support a claim about the deployed application.
            inconclusive = True
            evidence_records.append({
                "step": "mode",
                "note": "offline simulation only - target verifier not exercised",
            })

        else:
            # Active HTTP Probes (strictly routed through scope guard)
            steps = self._expand_steps(recipe.get("steps", []))
            req_count = 0
            timeout = float(recipe.get("timeout_seconds", 3.0))
            seen_headers: List[Dict[str, str]] = []

            with httpx.Client(timeout=timeout) as client:
                for step in steps:
                    if req_count >= max_requests:
                        break

                    path = step.get("path", "/")
                    method = step.get("method", "GET")
                    headers = step.get("headers", {})

                    raw_url = f"{target_base_url.rstrip('/')}{path}"
                    try:
                        # SCOPE GUARD: Fail-closed on every single request
                        guarded_url = self.guard.guard(raw_url)
                    except Exception as e:
                        # A blocked step proves nothing about the target.
                        inconclusive = True
                        evidence_records.append({
                            "step": step.get("name", "unnamed"),
                            "url": raw_url,
                            "error": f"Blocked by scope guard: {e}",
                        })
                        break  # kill switch / scope violation: stop the whole recipe

                    req_count += 1
                    try:
                        resp = client.request(method, guarded_url, headers=headers)
                        rec = {
                            "step": step.get("name", "unnamed"),
                            "method": method,
                            "url": guarded_url,
                            "sent_headers": {k: v for k, v in headers.items() if "auth" not in k.lower()},
                            "status_code": resp.status_code,
                            "response_snippet": resp.text[:300],
                        }
                        violations = self._evaluate_step(step, resp)
                        if violations:
                            expectation_met = False
                            rec["violations"] = violations
                        elif resp.status_code >= 500:
                            inconclusive = True
                            rec["note"] = "server error - cannot judge"
                        seen_headers.append({k.lower(): v for k, v in resp.headers.items()})
                        evidence_records.append(rec)
                    except httpx.ConnectError:
                        inconclusive = True
                        evidence_records.append({
                            "step": step.get("name"),
                            "status": "target_offline",
                            "note": "Target is offline or connection refused on loopback",
                        })
                    except Exception as err:
                        inconclusive = True
                        evidence_records.append({
                            "step": step.get("name"),
                            "error": str(err),
                        })

            # Properties the recipe needs to observe but the target never exposed -> cannot conclude.
            required = [h.lower() for h in recipe.get("require_header_any", [])]
            if required and not any(h in hdrs for hdrs in seen_headers for h in required):
                inconclusive = True
                evidence_records.append({
                    "step": "observability",
                    "note": f"none of {recipe.get('require_header_any')} observed in responses",
                })

        # Save sanitized evidence artifact
        output_dir.mkdir(parents=True, exist_ok=True)
        evidence_file = output_dir / f"probe_{recipe_id}_{commit_sha[:8]}.json"
        with open(evidence_file, "w", encoding="utf-8") as fp:
            json.dump({
                "recipe_id": recipe_id,
                "title": title,
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "records": evidence_records,
            }, fp, indent=2)

        evidence_sha = compute_file_sha256(evidence_file)

        if expectation_met and inconclusive:
            verdict = "INCONCLUSIVE"
        elif expectation_met:
            verdict = "EXPECTATION_MET"
        else:
            verdict = "EXPECTATION_NOT_MET"
            # Emit CandidateFinding when safe expectation was violated
            from urllib.parse import urlparse
            violating = next((r for r in evidence_records if r.get("violations")), {})
            vurl = urlparse(violating.get("url", ""))
            v_endpoint = (vurl.path + (f"?{vurl.query}" if vurl.query else "")) or None
            findings_emitted = CandidateFinding(
                title=f"Probe Failure: {title}",
                category=category,
                status="CANDIDATE",  # STRICT: never above CANDIDATE
                severity=recipe.get("severity_on_fail", "MEDIUM"),
                endpoint=v_endpoint,
                method=violating.get("method"),
                confidence_label="UNVERIFIED",
                repo=self.manifest.repo_url,
                commit_sha=commit_sha,
                build_id=build_id,
                scope_id=self.manifest.scope_id,
                tool=self.name,
                tool_version=self.version(),
                rule_id=recipe_id,
                cwe=[cwe_id],
                description=(
                    f"Probe recipe {recipe_id} failed safe behavior expectations.\n"
                    + "\n".join(
                        f"- {r['step']}: {'; '.join(r['violations'])}"
                        for r in evidence_records if r.get("violations")
                    )
                    + f"\nDerived from: {', '.join(source_refs)}"
                ),
                raw_result_ref=f"{evidence_file}#{recipe_id}",
                remediation_proposal=f"Review handler code at {source_refs[0] if source_refs else 'target'}",
            )
            findings_emitted.compute_fingerprint()

        return ProbeExecutionResult(
            recipe_id=recipe_id,
            verdict=verdict,
            details={"steps_executed": len(evidence_records)},
            evidence_artifact_path=str(evidence_file),
            evidence_sha256=evidence_sha,
            finding=findings_emitted,
        )

    def run(
        self,
        target_path: Path,
        output_dir: Path,
        commit_sha: str,
        build_id: str,
        scope_id: str,
        profile_config: Dict[str, Any],
        target_base_url: str = "http://127.0.0.1:3000",
    ) -> RawRun:
        output_dir.mkdir(parents=True, exist_ok=True)
        summary_file = output_dir / f"probes_summary_{commit_sha[:8]}.json"

        start_time = datetime.now(timezone.utc).isoformat()
        t0 = time.time()

        recipes = self.list_recipes()
        results_data = []

        for r in recipes:
            res = self.execute_recipe(r, target_base_url, output_dir, commit_sha, build_id)
            results_data.append({
                "recipe_id": res.recipe_id,
                "verdict": res.verdict,
                "evidence_path": res.evidence_artifact_path,
                "evidence_sha256": res.evidence_sha256,
                "has_finding": res.finding is not None,
                "finding": res.finding.model_dump() if res.finding else None,
            })

        duration = time.time() - t0
        end_time = datetime.now(timezone.utc).isoformat()

        with open(summary_file, "w", encoding="utf-8") as fp:
            json.dump({
                "total_probes": len(recipes),
                "results": results_data,
            }, fp, indent=2)

        file_sha = compute_file_sha256(summary_file)

        return RawRun(
            tool_name=self.name,
            tool_version=self.version(),
            command_line=f"wmsa probes run-all (count={len(recipes)})",
            start_time=start_time,
            end_time=end_time,
            exit_code=0,
            raw_output_path=str(summary_file),
            raw_output_sha256=file_sha,
            peak_ram_mb=25.0,
            duration_seconds=duration,
        )

    def parse(self, raw: RawRun, target_path: Path) -> List[CandidateFinding]:
        report_path = Path(raw.raw_output_path)
        if not report_path.exists():
            return []

        with open(report_path, "r", encoding="utf-8") as fp:
            data = json.load(fp)

        findings: List[CandidateFinding] = []
        for r_entry in data.get("results", []):
            payload = r_entry.get("finding")
            if not payload:
                continue
            # Rebuild the finding produced by execute_recipe (real title, severity, endpoint and the
            # violated assertions) and point it at this recipe's evidence transcript.
            f = CandidateFinding(**payload)
            f.raw_result_ref = f"{r_entry.get('evidence_path')}#{r_entry.get('recipe_id')}"
            f.compute_fingerprint()
            findings.append(f)

        return findings
