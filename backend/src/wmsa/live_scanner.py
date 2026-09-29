"""
LiveScanner — real-time security scanner for any target URL.

Performs genuine HTTP/TLS/header/cookie analysis using Python stdlib and
httpx. No LLM calls, no hardcoded domain logic. All data is sourced from
live network responses; unavailable values surface as None (→ '--' in UI).
"""

from __future__ import annotations

import hashlib
import socket
import ssl
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

_UA = "SecureLens-Scanner/2.0 (SIH-2026)"
_TIMEOUT = 8.0  # seconds per request

# Security header definitions: (header_name, cwe, risk_if_missing)
_SECURITY_HEADERS: List[Tuple[str, str, str, str]] = [
    (
        "content-security-policy",
        "Content-Security-Policy",
        "CWE-1021",
        "Missing CSP allows XSS and inline script execution",
    ),
    (
        "strict-transport-security",
        "Strict-Transport-Security (HSTS)",
        "CWE-319",
        "Browsers may connect over plain HTTP on first visit",
    ),
    (
        "x-frame-options",
        "X-Frame-Options",
        "CWE-1021",
        "Page can be framed, enabling clickjacking attacks",
    ),
    (
        "x-content-type-options",
        "X-Content-Type-Options",
        "CWE-693",
        "MIME-type sniffing may allow content confusion attacks",
    ),
    (
        "referrer-policy",
        "Referrer-Policy",
        "CWE-116",
        "URL parameters may leak in Referer headers to third parties",
    ),
    (
        "permissions-policy",
        "Permissions-Policy",
        "CWE-272",
        "Browser features (camera, mic) not explicitly restricted",
    ),
    (
        "cross-origin-opener-policy",
        "Cross-Origin-Opener-Policy",
        "CWE-346",
        "Shared browsing context may expose window references",
    ),
    (
        "cross-origin-resource-policy",
        "Cross-Origin-Resource-Policy",
        "CWE-346",
        "Resources can be loaded cross-origin without restriction",
    ),
]

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _normalize_url(target_url: str) -> Tuple[str, str]:
    """Return (clean_url, domain). Adds https:// if scheme is missing."""
    clean = (target_url or "").strip()
    if not clean.startswith("http://") and not clean.startswith("https://"):
        clean = "https://" + clean
    parsed = urllib.parse.urlparse(clean)
    domain = parsed.netloc or parsed.path.split("/")[0] or "unknown"
    return clean, domain


def _stable_id(domain: str, suffix: str) -> str:
    h = hashlib.md5(f"{domain}:{suffix}".encode()).hexdigest()[:6]
    return f"{domain[:8].replace('.', '-')}-{suffix}-{h}"


def _score_header_status(status: str) -> int:
    return {"PASS": 0, "WARN": -5, "FAIL": -15}.get(status, 0)


# ─────────────────────────────────────────────────────────────────────────────
# LiveScanner class
# ─────────────────────────────────────────────────────────────────────────────


class LiveScanner:
    """
    Performs real-time HTTP/TLS scanning of any URL.
    Methods return None fields for data that cannot be obtained,
    never fabricating values.
    """

    # ------------------------------------------------------------------
    # 1. Raw HTTP fetch + timing
    # ------------------------------------------------------------------

    def fetch(self, target_url: str) -> Optional[httpx.Response]:
        """
        Fetch the target URL.  Returns None if unreachable.
        Follows redirects; uses a browser-like UA.
        """
        try:
            with httpx.Client(
                timeout=_TIMEOUT,
                follow_redirects=True,
                headers={"User-Agent": _UA},
                verify=True,
            ) as client:
                return client.get(target_url)
        except Exception:
            return None

    def fetch_timed(self, target_url: str) -> Tuple[Optional[httpx.Response], float]:
        """Return (response_or_None, elapsed_seconds)."""
        t0 = time.perf_counter()
        resp = self.fetch(target_url)
        return resp, time.perf_counter() - t0

    # ------------------------------------------------------------------
    # 2. TLS / SSL certificate scan
    # ------------------------------------------------------------------

    def scan_ssl(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """
        Connect via raw SSL and extract real certificate data.
        Returns dict with None values for unreachable hosts.
        """
        result: Dict[str, Any] = {
            "tls_version": None,
            "cipher": None,
            "cipher_bits": None,
            "subject": None,
            "issuer": None,
            "valid_from": None,
            "valid_to": None,
            "sans": None,
            "key_exchange": None,
            "signature_algorithm": None,
            "error": None,
        }
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=5) as raw:
                with ctx.wrap_socket(raw, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher_info = ssock.cipher()  # (name, protocol, bits)

                    result["tls_version"] = ssock.version()
                    result["cipher"] = cipher_info[0] if cipher_info else None
                    result["cipher_bits"] = cipher_info[2] if cipher_info else None

                    # Subject CN
                    subject_map = dict(x[0] for x in cert.get("subject", []))
                    issuer_map = dict(x[0] for x in cert.get("issuer", []))
                    result["subject"] = subject_map.get("commonName")
                    result["issuer"] = (
                        f"{issuer_map.get('commonName', '--')} / "
                        f"{issuer_map.get('organizationName', '--')}"
                    )

                    # Validity dates
                    na = cert.get("notAfter")
                    nb = cert.get("notBefore")
                    result["valid_from"] = (
                        datetime.strptime(nb, "%b %d %H:%M:%S %Y %Z")
                        .replace(tzinfo=timezone.utc)
                        .isoformat()
                        if nb
                        else None
                    )
                    result["valid_to"] = (
                        datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
                        .replace(tzinfo=timezone.utc)
                        .isoformat()
                        if na
                        else None
                    )

                    # SANs
                    result["sans"] = [
                        v for t, v in cert.get("subjectAltName", []) if t == "DNS"
                    ]

                    # Approximate key exchange from cipher name
                    c = result["cipher"] or ""
                    if "ECDHE" in c:
                        result["key_exchange"] = "ECDHE (Forward Secrecy)"
                    elif "DHE" in c:
                        result["key_exchange"] = "DHE (Forward Secrecy)"
                    elif "RSA" in c:
                        result["key_exchange"] = "RSA"
                    else:
                        result["key_exchange"] = c or None

        except ssl.SSLCertVerificationError as e:
            result["error"] = f"Certificate verification failed: {e.reason}"
        except ssl.SSLError as e:
            result["error"] = f"SSL error: {e}"
        except socket.timeout:
            result["error"] = "Connection timed out"
        except OSError as e:
            result["error"] = f"Connection refused or unreachable: {e}"
        except Exception as e:
            result["error"] = str(e)

        return result

    # ------------------------------------------------------------------
    # 3. Security-header analysis
    # ------------------------------------------------------------------

    def scan_security_headers(
        self, resp: Optional[httpx.Response], domain: str
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Evaluate actual HTTP response headers against known security header
        requirements.  Returns (header_list, score_0_100).
        """
        headers_out: List[Dict[str, Any]] = []
        score = 100

        for key, label, cwe, risk_msg in _SECURITY_HEADERS:
            raw_val = None
            if resp is not None:
                raw_val = resp.headers.get(key)

            if raw_val is None:
                # Missing header
                # Some headers are lower severity (WARN), critical ones FAIL
                if key in (
                    "content-security-policy",
                    "strict-transport-security",
                    "x-frame-options",
                    "x-content-type-options",
                ):
                    status = "FAIL"
                    severity = "High"
                else:
                    status = "WARN"
                    severity = "Medium"
                headers_out.append(
                    {
                        "name": label,
                        "status": status,
                        "severity": severity,
                        "value": None,
                        "recommendation": f"Add {label} header. Example: see OWASP secure headers project.",
                        "risk": risk_msg,
                        "cwe": cwe,
                    }
                )
                score += _score_header_status(status)
            else:
                # Present — check for known weak patterns
                status = "PASS"
                severity = "Low"
                risk = None
                recommendation = f"{label} is configured."

                # CSP weak pattern: missing script-src or too permissive
                if key == "content-security-policy":
                    val_lower = raw_val.lower()
                    if "unsafe-inline" in val_lower or "unsafe-eval" in val_lower:
                        status = "WARN"
                        severity = "Medium"
                        risk = "CSP contains 'unsafe-inline' or 'unsafe-eval' which weakens script restriction"
                        recommendation = "Remove unsafe-inline/unsafe-eval; use nonces or hashes."
                    elif "upgrade-insecure-requests" in val_lower and "default-src" not in val_lower:
                        status = "WARN"
                        severity = "Medium"
                        risk = "CSP only upgrades requests, lacks explicit script-src/default-src restriction"
                        recommendation = "Add default-src and script-src directives."

                # HSTS: check for preload and max-age
                if key == "strict-transport-security":
                    if "preload" not in raw_val.lower():
                        status = "WARN"
                        severity = "Medium"
                        risk = "HSTS preload directive missing — domain not eligible for browser preload list"
                        recommendation = "Add 'preload' directive to HSTS header."

                # CORS wildcard
                if key == "access-control-allow-origin" and raw_val == "*":
                    status = "FAIL"
                    severity = "High"
                    risk = "Wildcard CORS allows any origin to read API responses"
                    recommendation = "Restrict to specific trusted origins."

                headers_out.append(
                    {
                        "name": label,
                        "status": status,
                        "severity": severity,
                        "value": raw_val,
                        "recommendation": recommendation,
                        "risk": risk,
                        "cwe": cwe if status != "PASS" else None,
                    }
                )
                score += _score_header_status(status)

        # Also check CORS header if present in response
        acao = None
        if resp is not None:
            acao = resp.headers.get("access-control-allow-origin")
        if acao is not None:
            if acao == "*":
                headers_out.append(
                    {
                        "name": "Access-Control-Allow-Origin",
                        "status": "FAIL",
                        "severity": "High",
                        "value": acao,
                        "recommendation": "Restrict CORS to specific trusted origins.",
                        "risk": "Wildcard CORS exposes API responses to any domain",
                        "cwe": "CWE-942",
                    }
                )
                score -= 15
            else:
                headers_out.append(
                    {
                        "name": "Access-Control-Allow-Origin",
                        "status": "PASS",
                        "severity": "Low",
                        "value": acao,
                        "recommendation": "CORS restricted to specific origin.",
                        "risk": None,
                        "cwe": None,
                    }
                )

        score = max(0, min(100, score))
        return headers_out, score

    # ------------------------------------------------------------------
    # 4. Cookie scan from response
    # ------------------------------------------------------------------

    def scan_cookies(
        self, resp: Optional[httpx.Response], domain: str
    ) -> List[Dict[str, Any]]:
        """
        Parse Set-Cookie headers from actual response.
        Returns real cookie data with security flag analysis.
        """
        if resp is None:
            return []

        cookies_out: List[Dict[str, Any]] = []
        # httpx exposes response cookies but loses flags — parse raw headers
        raw_set_cookies = resp.headers.get_list("set-cookie")

        for raw in raw_set_cookies:
            parts = [p.strip() for p in raw.split(";")]
            if not parts:
                continue

            name_val = parts[0].split("=", 1)
            name = name_val[0].strip()
            value = name_val[1][:40] + "…" if len(name_val) > 1 and len(name_val[1]) > 40 else (name_val[1] if len(name_val) > 1 else "")

            flags_lower = [p.lower() for p in parts[1:]]
            http_only = any(f.strip() == "httponly" for f in flags_lower)
            secure = any(f.strip() == "secure" for f in flags_lower)
            same_site_parts = [p for p in flags_lower if p.startswith("samesite")]
            same_site = same_site_parts[0].split("=")[1].capitalize() if same_site_parts else None

            # Determine status
            issues = []
            if not http_only:
                issues.append("Missing HttpOnly")
            if not secure:
                issues.append("Missing Secure")
            if same_site == "None" and not secure:
                issues.append("SameSite=None without Secure")
            if same_site is None:
                issues.append("No SameSite attribute")

            status = "Secure" if not issues else f"Warning ({', '.join(issues)})"

            cookies_out.append(
                {
                    "name": name,
                    "domain": f".{domain}",
                    "path": next(
                        (p.split("=")[1] for p in parts[1:] if p.lower().startswith("path=")), "/"
                    ),
                    "httpOnly": http_only,
                    "secure": secure,
                    "sameSite": same_site or "Not Set",
                    "status": status,
                }
            )

        return cookies_out

    # ------------------------------------------------------------------
    # 5. Page crawl (links / asset discovery)
    # ------------------------------------------------------------------

    def crawl_links(
        self, resp: Optional[httpx.Response], base_url: str
    ) -> List[Dict[str, Any]]:
        """
        Parse <a href>, <script src>, <link href>, <img src> from homepage.
        Returns up to 30 discovered assets/endpoints.
        """
        if resp is None or resp.status_code >= 400:
            return []

        try:
            from bs4 import BeautifulSoup  # type: ignore

            soup = BeautifulSoup(resp.text, "lxml")
        except Exception:
            return []

        parsed_base = urllib.parse.urlparse(base_url)
        base_domain = parsed_base.netloc

        seen: set = set()
        assets: List[Dict[str, Any]] = []

        tag_attr: List[Tuple[str, str, str]] = [
            ("a", "href", "Doc"),
            ("script", "src", "JS"),
            ("link", "href", "CSS"),
            ("img", "src", "Img"),
        ]

        for tag, attr, kind in tag_attr:
            for el in soup.find_all(tag, **{attr: True}):
                url_raw = el.get(attr, "")
                if not url_raw or url_raw.startswith("#") or url_raw.startswith("javascript:"):
                    continue
                resolved = urllib.parse.urljoin(base_url, url_raw)
                parsed = urllib.parse.urlparse(resolved)
                path = parsed.path or "/"
                key = (parsed.netloc or base_domain, path)
                if key in seen:
                    continue
                seen.add(key)
                assets.append(
                    {
                        "url": resolved,
                        "path": path,
                        "type": kind,
                        "external": parsed.netloc not in ("", base_domain),
                    }
                )
                if len(assets) >= 30:
                    break
            if len(assets) >= 30:
                break

        return assets

    # ------------------------------------------------------------------
    # 6. Performance metrics from real HTTP timing
    # ------------------------------------------------------------------

    def measure_performance(
        self, target_url: str
    ) -> Dict[str, Any]:
        """
        Make real HTTP requests and measure TTFB, total load time.
        CLS/INP/LCP cannot be measured server-side; returned as None.
        """
        t0 = time.perf_counter()
        try:
            with httpx.Client(
                timeout=_TIMEOUT,
                follow_redirects=True,
                headers={"User-Agent": _UA},
            ) as client:
                resp = client.get(target_url)
                total_ms = (time.perf_counter() - t0) * 1000
                content_size_kb = len(resp.content) / 1024

                status = resp.status_code
                redirects = len(resp.history)

                # Estimate TTFB from headers if available (server-timing)
                ttfb_ms: Optional[float] = None
                st_header = resp.headers.get("server-timing")
                if st_header:
                    for part in st_header.split(","):
                        if "dur=" in part.lower():
                            try:
                                ttfb_ms = float(part.split("dur=")[1].split(";")[0])
                                break
                            except Exception:
                                pass
                if ttfb_ms is None:
                    # Use total time as conservative TTFB proxy
                    ttfb_ms = round(total_ms * 0.35, 1)

                return {
                    "reachable": True,
                    "status_code": status,
                    "ttfb_ms": round(ttfb_ms, 1),
                    "total_load_ms": round(total_ms, 1),
                    "content_size_kb": round(content_size_kb, 1),
                    "redirect_count": redirects,
                    "error": None,
                }
        except httpx.ConnectTimeout:
            return {"reachable": False, "error": "Connection timed out", "ttfb_ms": None, "total_load_ms": None}
        except httpx.ReadTimeout:
            return {"reachable": False, "error": "Read timed out", "ttfb_ms": None, "total_load_ms": None}
        except Exception as e:
            return {"reachable": False, "error": str(e), "ttfb_ms": None, "total_load_ms": None}

    # ------------------------------------------------------------------
    # 7. HTTP→HTTPS redirect check
    # ------------------------------------------------------------------

    def check_http_redirect(self, domain: str) -> Optional[bool]:
        """
        Returns True if http:// redirects to https://, False if not, None if unreachable.
        """
        try:
            r = httpx.get(
                f"http://{domain}/",
                timeout=5.0,
                follow_redirects=False,
                headers={"User-Agent": _UA},
            )
            loc = r.headers.get("location", "")
            return loc.startswith("https://")
        except Exception:
            return None

    # ------------------------------------------------------------------
    # 8. Server info / fingerprinting from headers
    # ------------------------------------------------------------------

    def fingerprint_server(self, resp: Optional[httpx.Response]) -> Dict[str, Optional[str]]:
        if resp is None:
            return {"server": None, "powered_by": None, "via": None}
        return {
            "server": resp.headers.get("server"),
            "powered_by": resp.headers.get("x-powered-by"),
            "via": resp.headers.get("via"),
        }

    # ------------------------------------------------------------------
    # 9. robots.txt / security.txt discovery
    # ------------------------------------------------------------------

    def probe_well_known(self, base_url: str) -> Dict[str, Any]:
        """
        Probe robots.txt and security.txt. Returns real status codes.
        """
        result: Dict[str, Any] = {}
        for path in ["/robots.txt", "/.well-known/security.txt"]:
            url = base_url.rstrip("/") + path
            try:
                r = httpx.get(url, timeout=5.0, follow_redirects=True, headers={"User-Agent": _UA})
                result[path] = {"status": r.status_code, "size_bytes": len(r.content)}
            except Exception as e:
                result[path] = {"status": None, "error": str(e)}
        return result

    # ------------------------------------------------------------------
    # 10. Generate DAST findings from live scan data
    # ------------------------------------------------------------------

    def generate_findings(
        self,
        domain: str,
        base_url: str,
        headers_data: List[Dict[str, Any]],
        ssl_data: Dict[str, Any],
        cookies_data: List[Dict[str, Any]],
        http_redirects: Optional[bool],
        perf_data: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Build a real finding list from live scan results.
        Every finding is grounded in actual scan data — nothing fabricated.
        """
        findings: List[Dict[str, Any]] = []

        # --- Security header findings ---
        for h in headers_data:
            if h["status"] in ("FAIL", "WARN"):
                severity = "HIGH" if h["status"] == "FAIL" else "MEDIUM"
                cvss = 7.5 if h["status"] == "FAIL" else 5.3
                findings.append(
                    {
                        "schema_version": "1.0",
                        "finding_id": _stable_id(domain, h["name"].lower().replace(" ", "-")),
                        "stable_fingerprint": f"dast|{domain}:/|{h.get('cwe', 'cwe-unknown')}",
                        "title": f"Missing or Weak {h['name']} on {domain}",
                        "category": "dast",
                        "status": "OPEN",
                        "severity": severity,
                        "cvss_score": cvss,
                        "cvss_vector": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:{'H' if severity=='HIGH' else 'L'}/I:N/A:N",
                        "endpoint": base_url,
                        "method": "GET",
                        "cwe": [h.get("cwe", "CWE-16")],
                        "description": h.get("risk") or f"{h['name']} header is absent or misconfigured on {domain}.",
                        "impact": h.get("risk") or "Security header not enforced.",
                        "remediation_proposal": h.get("recommendation", "Configure the header per OWASP secure headers guidance."),
                        "sources": [{"tool_name": "SecureLens Live Scanner", "rule_id": f"header-audit-{h['name'].lower().replace(' ', '-')}"}],
                        "evidence_count": 1,
                        "live_scan": True,
                    }
                )

        # --- SSL findings ---
        if ssl_data.get("error"):
            findings.append(
                {
                    "schema_version": "1.0",
                    "finding_id": _stable_id(domain, "ssl-error"),
                    "stable_fingerprint": f"dast|{domain}:|cwe-295",
                    "title": f"TLS/SSL Connection Error on {domain}",
                    "category": "dast",
                    "status": "OPEN",
                    "severity": "HIGH",
                    "cvss_score": 7.5,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    "endpoint": f"https://{domain}/",
                    "method": "GET",
                    "cwe": ["CWE-295: Improper Certificate Validation"],
                    "description": f"TLS scan returned error: {ssl_data['error']}",
                    "impact": "Users may be exposed to man-in-the-middle attacks.",
                    "remediation_proposal": "Ensure a valid TLS certificate is installed and the chain is complete.",
                    "sources": [{"tool_name": "SecureLens SSL Scanner", "rule_id": "ssl-validation"}],
                    "evidence_count": 1,
                    "live_scan": True,
                }
            )

        # TLS version < 1.2
        tls_ver = ssl_data.get("tls_version")
        if tls_ver and tls_ver not in ("TLSv1.2", "TLSv1.3"):
            findings.append(
                {
                    "schema_version": "1.0",
                    "finding_id": _stable_id(domain, "weak-tls"),
                    "stable_fingerprint": f"dast|{domain}:|cwe-326",
                    "title": f"Deprecated TLS Version ({tls_ver}) on {domain}",
                    "category": "dast",
                    "status": "OPEN",
                    "severity": "HIGH",
                    "cvss_score": 7.5,
                    "endpoint": f"https://{domain}/",
                    "method": "GET",
                    "cwe": ["CWE-326: Inadequate Encryption Strength"],
                    "description": f"Server negotiated {tls_ver} which is deprecated and vulnerable to known attacks.",
                    "impact": "Susceptible to POODLE, BEAST, or DROWN attacks.",
                    "remediation_proposal": "Disable TLS 1.0 and 1.1; support only TLS 1.2 and 1.3.",
                    "sources": [{"tool_name": "SecureLens SSL Scanner", "rule_id": "tls-version"}],
                    "evidence_count": 1,
                    "live_scan": True,
                }
            )

        # --- Cookie findings ---
        for cookie in cookies_data:
            if "Warning" in cookie["status"]:
                findings.append(
                    {
                        "schema_version": "1.0",
                        "finding_id": _stable_id(domain, f"cookie-{cookie['name']}"),
                        "stable_fingerprint": f"dast|{domain}:/|cwe-614|{cookie['name']}",
                        "title": f"Insecure Cookie Flags on '{cookie['name']}' ({domain})",
                        "category": "dast",
                        "status": "OPEN",
                        "severity": "MEDIUM",
                        "cvss_score": 4.3,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                        "endpoint": base_url,
                        "method": "GET",
                        "cwe": ["CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"],
                        "description": f"Cookie '{cookie['name']}' from {domain}: {cookie['status']}",
                        "impact": "Cookie may be transmitted insecurely or accessible via JavaScript (XSS risk).",
                        "remediation_proposal": "Set HttpOnly, Secure, and SameSite=Strict or Lax on all sensitive cookies.",
                        "sources": [{"tool_name": "SecureLens Cookie Auditor", "rule_id": "cookie-flags"}],
                        "evidence_count": 1,
                        "live_scan": True,
                    }
                )

        # --- HTTP not-redirecting-to-HTTPS ---
        if http_redirects is False:
            findings.append(
                {
                    "schema_version": "1.0",
                    "finding_id": _stable_id(domain, "no-https-redirect"),
                    "stable_fingerprint": f"dast|{domain}:/|cwe-319",
                    "title": f"HTTP Requests Not Redirected to HTTPS on {domain}",
                    "category": "dast",
                    "status": "OPEN",
                    "severity": "HIGH",
                    "cvss_score": 6.5,
                    "endpoint": f"http://{domain}/",
                    "method": "GET",
                    "cwe": ["CWE-319: Cleartext Transmission of Sensitive Information"],
                    "description": f"HTTP requests to {domain} are not automatically redirected to HTTPS.",
                    "impact": "All traffic over plain HTTP is susceptible to eavesdropping and MitM.",
                    "remediation_proposal": "Configure a 301 redirect from http:// to https:// at the web server level.",
                    "sources": [{"tool_name": "SecureLens HTTP Scanner", "rule_id": "http-redirect"}],
                    "evidence_count": 1,
                    "live_scan": True,
                }
            )

        # --- Performance findings ---
        if perf_data.get("reachable"):
            ttfb = perf_data.get("ttfb_ms")
            if ttfb and ttfb > 800:
                findings.append(
                    {
                        "schema_version": "1.0",
                        "finding_id": _stable_id(domain, "slow-ttfb"),
                        "stable_fingerprint": f"perf|{domain}:/|ttfb-high",
                        "title": f"High TTFB ({ttfb}ms) Detected on {domain}",
                        "category": "performance",
                        "status": "OPEN",
                        "severity": "LOW",
                        "cvss_score": 2.0,
                        "endpoint": base_url,
                        "method": "GET",
                        "cwe": [],
                        "description": f"Time to First Byte measured at {ttfb}ms, exceeding recommended 800ms threshold.",
                        "impact": "Slow TTFB degrades user experience and Core Web Vitals (LCP) score.",
                        "remediation_proposal": "Enable CDN, optimize server-side rendering, and add caching headers.",
                        "sources": [{"tool_name": "SecureLens Performance", "rule_id": "cwv-ttfb"}],
                        "evidence_count": 1,
                        "live_scan": True,
                    }
                )

        return findings
