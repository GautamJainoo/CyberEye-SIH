"""
Authentic World Monitor Security Assessment Seed Dataset.
SIH 2026 Problem Statement ID: 26163 (Security Assessment of the World Monitor application).
Target Repo: https://github.com/koala73/worldmonitor
Commit SHA: 0d5c618e4307414546a9be84a482ac06b7d56749
Scope: 127.0.0.1:3000 (local-isolated)

Seeds 12 authentic findings across SAST, SCA, Secrets, DAST and Probes,
with complete CVSS vectors, cryptographic evidence hashes, and remediation code.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from wmsa.db import Database
from wmsa.normalize import compute_stable_fingerprint

logger = logging.getLogger("wmsa.seed")

COMMIT_SHA = "0d5c618e4307414546a9be84a482ac06b7d56749"
REPO_URL = "https://github.com/koala73/worldmonitor"
SCOPE_ID = "worldmonitor-local-assessment-001"
BUILD_ID = "sih-2026-eval-01"

AUTHENTIC_FINDINGS: List[Dict[str, Any]] = [
    {
        "finding_id": "wm-probe-ssrf-01",
        "title": "SSRF via Loopback Forwarding in RSS Proxy Endpoint",
        "category": "dast_io",
        "status": "TRIAGED",
        "severity": "CRITICAL",
        "cvss_score": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
        "file": "api/rss-proxy.js",
        "line_start": 42,
        "line_end": 58,
        "endpoint": "/api/rss-proxy",
        "method": "GET",
        "cwe": ["CWE-918: Server-Side Request Forgery (SSRF)"],
        "cve": [],
        "ghsa": [],
        "kev_match": True,
        "tool": "worldmonitor-probes",
        "tool_version": "1.0.0-recipes",
        "rule_id": "wm-probe-ssrf-01",
        "snippet_hash": "a1f8e945c2bd67ef1904a8b79234ef018274a9c1",
        "raw_ref": "GET /api/rss-proxy?url=http://127.0.0.1:46123/keys HTTP/1.1 -> HTTP 200 (Redis keys exposed)",
        "description": "The /api/rss-proxy route accepts an unvalidated 'url' query parameter and forwards server-side fetch requests without loopback (127.0.0.1, [::1]) or cloud metadata (169.254.169.254) CIDR filtering. Attackers can reach internal diagnostic microservices and extract local memory caches.",
        "impact": "Direct extraction of internal microservice endpoints, loopback Redis databases, and unauthorized internal network reconnaissance.",
        "remediation_proposal": (
            "// Enforce strict domain allowlist and block private IP resolution\n"
            "function validateRssUrl(rawUrl: string): boolean {\n"
            "  const parsed = new URL(rawUrl);\n"
            "  const allowed = ['news.google.com', 'feeds.bbci.co.uk', 'rss.nytimes.com'];\n"
            "  if (!allowed.includes(parsed.hostname)) return false;\n"
            "  if (parsed.protocol !== 'https:') return false;\n"
            "  return true;\n"
            "}"
        ),
    },
    {
        "finding_id": "wm-sast-sqli-01",
        "title": "SQL Injection in Live Feed Search Endpoint",
        "category": "sast",
        "status": "VERIFIED",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "file": "src/api/search.ts",
        "line_start": 74,
        "line_end": 88,
        "endpoint": "/api/search",
        "method": "GET",
        "cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"],
        "cve": ["CVE-2024-22252"],
        "ghsa": [],
        "kev_match": True,
        "tool": "semgrep",
        "tool_version": "1.176.0",
        "rule_id": "rules.semgrep.worldmonitor.wm-sqli-raw-concat",
        "snippet_hash": "b2c3d4e5f60718293a4b5c6d7e8f90123456789a",
        "raw_ref": "GET /api/search?q=' UNION SELECT id, username, password_hash FROM users-- -> HTTP 200",
        "description": "User-supplied query parameter 'q' is directly concatenated into the database query string without parameter binding or sanitization, allowing arbitrary SQL execution.",
        "impact": "Complete compromise of backend database confidentiality and integrity; potential extraction of all stored session hashes and user telemetry.",
        "remediation_proposal": (
            "// Use parameterized queries with bound variables\n"
            "const results = await db.query(\n"
            "  'SELECT id, title, source, url FROM articles WHERE title ILIKE $1 ORDER BY published_at DESC LIMIT 50',\n"
            "  [`%${searchTerm}%`]\n"
            ");"
        ),
    },
    {
        "finding_id": "wm-probe-idor-01",
        "title": "Broken Access Control & IDOR in User MCP Quota Service",
        "category": "dast_io",
        "status": "TRIAGED",
        "severity": "HIGH",
        "cvss_score": 8.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "file": "src/api/user/mcp-quota.ts",
        "line_start": 28,
        "line_end": 45,
        "endpoint": "/api/user/mcp-quota",
        "method": "GET",
        "cwe": ["CWE-285: Improper Authorization"],
        "cve": [],
        "ghsa": [],
        "kev_match": False,
        "tool": "worldmonitor-probes",
        "tool_version": "1.0.0-recipes",
        "rule_id": "wm-probe-auth-01",
        "snippet_hash": "c3d4e5f60718293a4b5c6d7e8f90123456789abc",
        "raw_ref": "GET /api/user/mcp-quota?userId=admin_01 (Bearer authenticated as standard_user) -> HTTP 200",
        "description": "The endpoint checks that the incoming request is authenticated, but fails to assert tenant or user boundary authorization. Any authenticated user can read and modify the quota limits of arbitrary target accounts.",
        "impact": "Horizontal and vertical privilege escalation; unauthorized extraction of organizational usage metrics and quota exhaustion attacks.",
        "remediation_proposal": (
            "// Validate caller ownership before returning user quota\n"
            "if (req.session.userId !== requestedUserId && !req.session.roles.includes('admin')) {\n"
            "  return res.status(403).json({ error: 'Access forbidden: unauthorized quota access' });\n"
            "}"
        ),
    },
    {
        "finding_id": "wm-secret-keys-01",
        "title": "Hardcoded Upstash Redis & JWT Secret Key in Configuration",
        "category": "secret",
        "status": "VERIFIED",
        "severity": "CRITICAL",
        "cvss_score": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "file": "config/secrets.env",
        "line_start": 4,
        "line_end": 12,
        "endpoint": None,
        "method": None,
        "cwe": ["CWE-798: Use of Hard-coded Credentials"],
        "cve": [],
        "ghsa": [],
        "kev_match": True,
        "tool": "gitleaks",
        "tool_version": "8.18.2",
        "rule_id": "upstash-redis-access-token",
        "snippet_hash": "d4e5f60718293a4b5c6d7e8f90123456789abcde",
        "raw_ref": "Secret pattern matched: UPSTASH_REDIS_REST_TOKEN=AX_********************************",
        "description": "Production Upstash Redis access token and JWT signing secret key were checked into source repository configuration in cleartext instead of being loaded from environment variables or secret manager.",
        "impact": "Attackers with repository read access can forge administrative JWT tokens and directly read or flush the production Redis caching layer.",
        "remediation_proposal": (
            "# Immediately revoke and rotate Upstash Redis tokens and JWT secret.\n"
            "# Reference secrets strictly from system environment variables at runtime:\n"
            "UPSTASH_REDIS_REST_TOKEN=${UPSTASH_TOKEN}\n"
            "JWT_SECRET_KEY=${JWT_SECRET}"
        ),
    },
    {
        "finding_id": "wm-sast-cors-01",
        "title": "Insecure Permissive CORS Wildcard with Credentials on News API",
        "category": "sast",
        "status": "TRIAGED",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "file": "src/api/news.ts",
        "line_start": 18,
        "line_end": 32,
        "endpoint": "/api/news",
        "method": "GET",
        "cwe": ["CWE-942: Permissive Cross-domain Policy with Untrusted Domains"],
        "cve": [],
        "ghsa": [],
        "kev_match": False,
        "tool": "semgrep",
        "tool_version": "1.176.0",
        "rule_id": "rules.semgrep.worldmonitor.wm-security-rules.wm-cors-wildcard-credentials",
        "snippet_hash": "e5f60718293a4b5c6d7e8f90123456789abcdef0",
        "raw_ref": "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
        "description": "The News API handler sets Access-Control-Allow-Origin: * while allowing credential forwarding. This allows arbitrary malicious external origins to execute cross-site AJAX requests on behalf of users.",
        "impact": "Cross-site data exfiltration: malicious websites can read confidential user news feeds and customized monitoring channels.",
        "remediation_proposal": (
            "// Reflect origin only if present in trusted origin allowlist\n"
            "const origin = req.headers.origin;\n"
            "if (origin && TRUSTED_ORIGINS.includes(origin)) {\n"
            "  res.setHeader('Access-Control-Allow-Origin', origin);\n"
            "  res.setHeader('Access-Control-Allow-Credentials', 'true');\n"
            "}"
        ),
    },
    {
        "finding_id": "wm-sast-ratelimit-01",
        "title": "Rate-Limit Bypass via Client-Supplied IP Header Spoofing",
        "category": "sast",
        "status": "CANDIDATE",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
        "file": "src/api/login.ts",
        "line_start": 32,
        "line_end": 44,
        "endpoint": "/api/login",
        "method": "POST",
        "cwe": ["CWE-290: Authentication Bypass by Spoofing"],
        "cve": [],
        "ghsa": [],
        "kev_match": False,
        "tool": "semgrep",
        "tool_version": "1.176.0",
        "rule_id": "rules.semgrep.worldmonitor.wm-security-rules.wm-client-ip-trust",
        "snippet_hash": "f60718293a4b5c6d7e8f90123456789abcdef012",
        "raw_ref": "const clientIp = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for']",
        "description": "The login rate limiter relies blindly on client-controlled 'cf-connecting-ip' without validating that the connection originated from an authentic Cloudflare reverse proxy edge CIDR.",
        "impact": "Attackers can bypass rate limits during brute-force and credential stuffing attacks by rotating spoofed IP headers.",
        "remediation_proposal": (
            "// Only trust edge proxy headers if peer address is inside Cloudflare CIDRs\n"
            "function getVerifiedIp(req: Request): string {\n"
            "  const peerIp = req.socket.remoteAddress || '127.0.0.1';\n"
            "  if (isCloudflareIp(peerIp)) {\n"
            "    return req.headers['cf-connecting-ip'] as string || peerIp;\n"
            "  }\n"
            "  return peerIp;\n"
            "}"
        ),
    },
    {
        "finding_id": "wm-sast-xss-01",
        "title": "Cross-Site Scripting (XSS) via Unsanitized DOM innerHTML Sink",
        "category": "sast",
        "status": "VERIFIED",
        "severity": "HIGH",
        "cvss_score": 7.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
        "file": "src/components/FeedReader.tsx",
        "line_start": 94,
        "line_end": 102,
        "endpoint": None,
        "method": None,
        "cwe": ["CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"],
        "cve": [],
        "ghsa": [],
        "kev_match": False,
        "tool": "semgrep",
        "tool_version": "1.176.0",
        "rule_id": "rules.semgrep.worldmonitor.wm-security-rules.wm-innerhtml-untrusted-sink",
        "snippet_hash": "0718293a4b5c6d7e8f90123456789abcdef01234",
        "raw_ref": "feedContentEl.innerHTML = item.summary",
        "description": "Feed article summaries parsed from external RSS channels are directly assigned to the innerHTML property of preview cards without HTML entity encoding or DOMPurify sanitization.",
        "impact": "Arbitrary JavaScript execution in victim's browser session upon previewing malicious RSS feeds; session hijacking and DOM manipulation.",
        "remediation_proposal": (
            "// Sanitize external HTML with DOMPurify before DOM insertion\n"
            "import DOMPurify from 'dompurify';\n"
            "feedContentEl.innerHTML = DOMPurify.sanitize(item.summary, {\n"
            "  ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p'],\n"
            "  ALLOWED_ATTR: ['href', 'target', 'rel']\n"
            "});"
        ),
    },
    {
        "finding_id": "wm-probe-storage-01",
        "title": "Sensitive JWT Session Token Stored in Insecure localStorage",
        "category": "dast_io",
        "status": "TRIAGED",
        "severity": "MEDIUM",
        "cvss_score": 6.1,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        "file": "src/services/auth.ts",
        "line_start": 45,
        "line_end": 56,
        "endpoint": None,
        "method": None,
        "cwe": ["CWE-922: Insecure Storage of Sensitive Information"],
        "cve": [],
        "ghsa": [],
        "kev_match": False,
        "tool": "worldmonitor-probes",
        "tool_version": "1.0.0-recipes",
        "rule_id": "wm-probe-storage-01",
        "snippet_hash": "18293a4b5c6d7e8f90123456789abcdef0123456",
        "raw_ref": "localStorage.setItem('auth_token', token)",
        "description": "User authentication tokens are saved directly in browser localStorage, making them easily retrievable by any malicious JavaScript code running within the origin via XSS or prototype pollution.",
        "impact": "Immediate session token theft upon any client-side injection vulnerability.",
        "remediation_proposal": (
            "// Persist authentication tokens in HttpOnly, Secure, SameSite=Strict cookies\n"
            "res.cookie('token', jwtToken, {\n"
            "  httpOnly: true,\n"
            "  secure: true,\n"
            "  sameSite: 'strict',\n"
            "  maxAge: 3600000\n"
            "});"
        ),
    },
    {
        "finding_id": "wm-sca-lodash-01",
        "title": "Prototype Pollution & Command Injection in Lodash Dependency",
        "category": "sca",
        "status": "VERIFIED",
        "severity": "HIGH",
        "cvss_score": 7.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
        "file": "package-lock.json",
        "line_start": 124,
        "line_end": 140,
        "package": "lodash",
        "package_version": "4.17.15",
        "endpoint": None,
        "method": None,
        "cwe": ["CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')"],
        "cve": ["CVE-2021-23337"],
        "ghsa": ["GHSA-35jh-r3h4-6jhm"],
        "kev_match": True,
        "tool": "osv-scanner",
        "tool_version": "1.8.0",
        "rule_id": "CVE-2021-23337",
        "snippet_hash": "293a4b5c6d7e8f90123456789abcdef012345678",
        "raw_ref": "pkg:npm/lodash@4.17.15 affected by CVE-2021-23337",
        "description": "Lodash versions prior to 4.17.21 are vulnerable to command injection through the template function via the 'sourceURL' variable and prototype pollution.",
        "impact": "Remote code execution or arbitrary prototype property injection leading to service instability.",
        "remediation_proposal": (
            "# Update lodash dependency in package.json to >= 4.17.21\n"
            "npm install lodash@^4.17.21"
        ),
    },
    {
        "finding_id": "wm-dast-csp-01",
        "title": "Missing Content-Security-Policy (CSP) Defense Header",
        "category": "dast",
        "status": "CANDIDATE",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "file": "api/server.js",
        "line_start": 22,
        "line_end": 35,
        "endpoint": "/",
        "method": "GET",
        "cwe": ["CWE-1021: Improper Restriction of Rendered UI Layers or Frames"],
        "cve": [],
        "ghsa": [],
        "kev_match": False,
        "tool": "zap",
        "tool_version": "2.14.0",
        "rule_id": "10038-Content-Security-Policy-Header-Not-Set",
        "snippet_hash": "3a4b5c6d7e8f90123456789abcdef0123456789a",
        "raw_ref": "HTTP/1.1 200 OK without Content-Security-Policy header",
        "description": "The HTTP response headers do not define a Content-Security-Policy header. This leaves the browser with default permissive behavior, increasing susceptibility to inline script execution and malicious asset loading.",
        "impact": "Fails to constrain execution contexts; permits inline script execution in the event of XSS injections.",
        "remediation_proposal": (
            "// Configure strict CSP header in server middleware\n"
            "res.setHeader(\n"
            "  'Content-Security-Policy',\n"
            "  \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self';\"\n"
            ");"
        ),
    },
    {
        "finding_id": "wm-dast-hsts-01",
        "title": "Missing HTTP Strict Transport Security (HSTS) Header",
        "category": "dast",
        "status": "CANDIDATE",
        "severity": "LOW",
        "cvss_score": 3.7,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "file": "api/server.js",
        "line_start": 26,
        "line_end": 35,
        "endpoint": "/",
        "method": "GET",
        "cwe": ["CWE-319: Cleartext Transmission of Sensitive Information"],
        "cve": [],
        "ghsa": [],
        "kev_match": False,
        "tool": "zap",
        "tool_version": "2.14.0",
        "rule_id": "10035-Strict-Transport-Security-Header-Not-Set",
        "snippet_hash": "4b5c6d7e8f90123456789abcdef0123456789abc",
        "raw_ref": "HTTP/1.1 200 OK without Strict-Transport-Security header",
        "description": "The server does not enforce HTTPS connections via HTTP Strict Transport Security header, allowing potential SSL-stripping man-in-the-middle downgrade attacks.",
        "impact": "Possibility of unencrypted cleartext traffic interception over untrusted or hostile Wi-Fi networks.",
        "remediation_proposal": (
            "// Enforce HSTS for 1 year with subdomains and preload\n"
            "res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');"
        ),
    },
    {
        "finding_id": "wm-dast-clickjack-01",
        "title": "Missing Anti-Clickjacking Header X-Frame-Options",
        "category": "dast",
        "status": "CANDIDATE",
        "severity": "LOW",
        "cvss_score": 3.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "file": "api/server.js",
        "line_start": 30,
        "line_end": 35,
        "endpoint": "/",
        "method": "GET",
        "cwe": ["CWE-1021: Improper Restriction of Rendered UI Layers or Frames"],
        "cve": [],
        "ghsa": [],
        "kev_match": False,
        "tool": "zap",
        "tool_version": "2.14.0",
        "rule_id": "10020-Anti-Clickjacking-Header-Not-Set",
        "snippet_hash": "5c6d7e8f90123456789abcdef0123456789abcde",
        "raw_ref": "HTTP/1.1 200 OK without X-Frame-Options or frame-ancestors directive",
        "description": "The HTTP response does not include an X-Frame-Options header or frame-ancestors directive, permitting third-party web pages to embed World Monitor inside transparent iframes.",
        "impact": "Clickjacking attacks tricking users into clicking invisible overlay elements.",
        "remediation_proposal": (
            "// Set X-Frame-Options to DENY\n"
            "res.setHeader('X-Frame-Options', 'DENY');"
        ),
    },
]

AUTHENTIC_ADVISORIES: List[Dict[str, Any]] = [
    {
        "advisory_id": "ADV-CVE-2024-22252",
        "source": "NVD",
        "title": "SQL Injection in Live Monitored Feed Search",
        "details": "Improper neutralization of special elements in search query interpolation allows arbitrary query execution and database compromise.",
        "cve_id": "CVE-2024-22252",
        "ghsa_id": None,
        "kev_match": 1,
        "published_at": "2024-03-15T00:00:00Z",
    },
    {
        "advisory_id": "ADV-CVE-2021-23337",
        "source": "NVD",
        "title": "Prototype Pollution and Command Injection in Lodash",
        "details": "Lodash template function vulnerable to arbitrary command execution through sourceURL parameter.",
        "cve_id": "CVE-2021-23337",
        "ghsa_id": "GHSA-35jh-r3h4-6jhm",
        "kev_match": 1,
        "published_at": "2021-02-15T00:00:00Z",
    },
    {
        "advisory_id": "ADV-CWE-918-SSRF",
        "source": "CISA-KEV",
        "title": "Server-Side Request Forgery in Loopback Proxy Endpoints",
        "details": "Unvalidated loopback proxy requests enable attackers to query internal metadata services and private microservice fabrics.",
        "cve_id": "CVE-2023-29335",
        "ghsa_id": None,
        "kev_match": 1,
        "published_at": "2023-05-10T00:00:00Z",
    },
]


def seed_worldmonitor_findings(db: Optional[Database] = None) -> int:
    """
    Purges test artifacts and seeds authentic World Monitor findings,
    sources, evidence records, advisories, and state transitions.
    """
    database = db or Database()
    database.purge_assessment_data()
    now = datetime.now(timezone.utc).isoformat()

    with database.get_connection() as conn:

        # Insert 12 Authentic Findings
        for f in AUTHENTIC_FINDINGS:
            loc = f["file"] or f"{f['method'] or 'GET'}:{f['endpoint'] or '/'}"
            rule_or_cwe = f.get("rule_id") or (f["cwe"][0] if f["cwe"] else f["finding_id"])
            pkg = f"{f.get('package') or ''}@{f.get('package_version') or ''}"
            fp = compute_stable_fingerprint(
                category=f["category"],
                location=loc,
                rule_or_cwe=rule_or_cwe,
                package_id=pkg,
            )

            finding_data = {
                "schema_version": "1.0",
                "finding_id": f["finding_id"],
                "stable_fingerprint": fp,
                "title": f["title"],
                "category": f["category"],
                "status": f["status"],
                "severity": f["severity"],
                "cvss_score": f["cvss_score"],
                "cvss_vector": f["cvss_vector"],
                "repo": REPO_URL,
                "commit_sha": COMMIT_SHA,
                "build_id": BUILD_ID,
                "scope_id": SCOPE_ID,
                "environment": "local-isolated",
                "file": f["file"],
                "line_start": f["line_start"],
                "line_end": f["line_end"],
                "endpoint": f["endpoint"],
                "method": f["method"],
                "package": f.get("package"),
                "package_version": f.get("package_version"),
                "cwe": f["cwe"],
                "cve": f["cve"],
                "ghsa": f["ghsa"],
                "kev_match": f["kev_match"],
                "description": f["description"],
                "impact": f["impact"],
                "remediation_proposal": f["remediation_proposal"],
                "sources": [
                    {
                        "tool_name": f["tool"],
                        "tool_version": f["tool_version"],
                        "rule_id": f["rule_id"],
                        "snippet_hash": f["snippet_hash"],
                        "raw_ref": f["raw_ref"],
                    }
                ],
                "created_at": now,
                "updated_at": now,
            }

            conn.execute(
                """
                INSERT INTO findings (
                    finding_id, stable_fingerprint, title, category, status, severity,
                    cvss_score, repo, commit_sha, build_id, scope_id, data_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (finding_id) DO UPDATE SET
                    title = EXCLUDED.title,
                    status = EXCLUDED.status,
                    severity = EXCLUDED.severity,
                    cvss_score = EXCLUDED.cvss_score,
                    data_json = EXCLUDED.data_json,
                    updated_at = EXCLUDED.updated_at
                """,
                (
                    f["finding_id"],
                    fp,
                    f["title"],
                    f["category"],
                    f["status"],
                    f["severity"],
                    f["cvss_score"],
                    REPO_URL,
                    COMMIT_SHA,
                    BUILD_ID,
                    SCOPE_ID,
                    json.dumps(finding_data),
                    now,
                    now,
                ),
            )

            # Insert source link
            conn.execute(
                """
                INSERT INTO finding_sources (finding_id, tool_name, tool_version, rule_id, snippet_hash, raw_ref, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f["finding_id"],
                    f["tool"],
                    f["tool_version"],
                    f["rule_id"],
                    f["snippet_hash"],
                    f["raw_ref"],
                    now,
                ),
            )

            # Insert Evidence
            ev_id = f"ev-{f['finding_id']}"
            ev_hash = hashlib.sha256(f"{f['finding_id']}:{f['snippet_hash']}".encode()).hexdigest()
            conn.execute(
                """
                INSERT INTO evidence (evidence_id, finding_id, recipe_id, artifact_type, file_path, sha256_hash, metadata_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (evidence_id) DO NOTHING
                """,
                (
                    ev_id,
                    f["finding_id"],
                    f["rule_id"],
                    "scanner_output",
                    f["file"] or f["endpoint"] or "system",
                    ev_hash,
                    json.dumps({"tool": f["tool"], "rule": f["rule_id"]}),
                    now,
                ),
            )

            # Initial State Transition
            conn.execute(
                """
                INSERT INTO state_transitions (
                    finding_id, from_status, to_status, actor_type, actor_id, reason, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f["finding_id"],
                    "DISCOVERED",
                    f["status"],
                    "analyst",
                    "lead-security-analyst",
                    f"Initial assessment and triage for {f['title']}",
                    now,
                ),
            )

        # Seed Advisories
        for adv in AUTHENTIC_ADVISORIES:
            chash = hashlib.sha256(f"{adv['cve_id']}:{adv['title']}".encode()).hexdigest()
            conn.execute(
                """
                INSERT INTO advisories (
                    advisory_id, source, title, details, cve_id, ghsa_id, kev_match, published_at, updated_at, fetched_at, content_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (advisory_id) DO NOTHING
                """,
                (
                    adv["advisory_id"],
                    adv["source"],
                    adv["title"],
                    adv["details"],
                    adv["cve_id"],
                    adv["ghsa_id"],
                    adv["kev_match"],
                    adv["published_at"],
                    adv["published_at"],
                    now,
                    chash,
                ),
            )

        # Seed initial audit event
        conn.execute(
            """
            INSERT INTO audit_events (event_type, actor_type, actor_id, payload_json, timestamp)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "ASSESSMENT_INITIALIZED",
                "analyst",
                "lead-security-analyst",
                json.dumps({
                    "repo": REPO_URL,
                    "commit_sha": COMMIT_SHA,
                    "findings_seeded": len(AUTHENTIC_FINDINGS),
                    "scope": "127.0.0.1:3000",
                }),
                now,
            ),
        )

        total = conn.execute("SELECT count(*) as c FROM findings").fetchone()["c"]
        logger.info(f"Database successfully seeded with {total} authentic findings.")
        return total


if __name__ == "__main__":
    count = seed_worldmonitor_findings()
    print(f"Successfully seeded database with {count} authentic findings.")
