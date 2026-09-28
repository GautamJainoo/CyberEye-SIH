# World Monitor Manual Code Review Notes (SIH 2026, PS 26163)

Manual security analysis backing custom Semgrep rules and target-specific safe probe recipes.
Source Repository: `https://github.com/koala73/worldmonitor` (pinned commit `0d5c618e4307414546a9be84a482ac06b7d56749`).

---

## Candidate Area 1: Authorization & Object Ownership
- **Trust Boundary**: Client requests carrying Bearer JWTs or session identifiers.
- **Handler / Source Reference**: `target/api/user/mcp-quota.ts:119-129`, `target/server/_shared/auth-session.ts:40-85`.
- **Data Source**: Incoming `Authorization: Bearer <token>` header or `Cookie: wm-session=<wms_...>`.
- **Expected Control**: Server calls `resolveSessionUserId(req)`. Unauthenticated or invalid sessions return 401 unauthenticated. A user cannot read another user's quota or private settings.
- **Review Question**: Can a synthetic user without valid authentication access the quota or user-specific telemetry?
- **Status / Verdict**: `APPLICABLE` → Covered by Probe Recipe `wm-probe-auth-01`.

---

## Candidate Area 2: Premium & Access Gating
- **Trust Boundary**: Anonymous session tokens (`wms_` prefix) vs paying/enterprise credentials (`forceKey=true`).
- **Handler / Source Reference**: `target/api/_api-key.js:27-40`, `target/api/_api-key.js:98-136`.
- **Data Source**: `X-WorldMonitor-Key`, `X-Api-Key`, or `Cookie: wm-session`.
- **Expected Control**: `isSessionTokenShape(key)` validates anonymous token. When `forceKey=true` (tier-gated endpoints), anonymous tokens are explicitly rejected with `{ valid: false, required: true, error: 'Pro authentication required' }`.
- **Review Question**: Can an anonymous session token minted freely via `/api/wm-session` bypass server-side entitlement checks on Pro-gated endpoints?
- **Status / Verdict**: `APPLICABLE` → Covered by Probe Recipe `wm-probe-entitlement-01`.

---

## Candidate Area 3: Cache Isolation & Tenant Dimensions
- **Trust Boundary**: Edge CDN caching (Vercel Edge / Cloudflare) vs per-user response data.
- **Handler / Source Reference**: `target/api/_cors.js:176-192`, `target/api/user/mcp-quota.ts:106-107`, `target/api/_redis-key-ownership.js:26-44`.
- **Data Source**: User-specific quota responses, dynamic news queries, and Redis cache keys.
- **Expected Control**: Sensitive/per-user endpoints strictly set `Cache-Control: no-store`. Public endpoints setting `Access-Control-Allow-Origin: *` must only serve non-personalized, static seeded payloads.
- **Review Question**: Do personalized or authenticated endpoints omit `no-store`, allowing intermediate proxy cache poisoning across sessions?
- **Status / Verdict**: `APPLICABLE` → Covered by Probe Recipe `wm-probe-cache-01`.

---

## Candidate Area 4: HTML Escaping & XSS Sink Protection
- **Trust Boundary**: External untrusted RSS feed data and third-party news sources rendered in client views.
- **Handler / Source Reference**: `target/scripts/enforce-safe-html.mjs:1-90`, `target/src/components/`, `target/api/rss-proxy.js:43-93`.
- **Data Source**: RSS channel titles, item descriptions, and source labels.
- **Expected Control**: CI enforcement prohibits unescaped HTML sinks (`innerHTML`, `dangerouslySetInnerHTML`) unless explicitly sanitized. RSS proxy parses XML elements and truncates oversized payloads safely.
- **Review Question**: Does the application render external feed content via raw DOM innerHTML sinks without context-aware HTML encoding?
- **Status / Verdict**: `APPLICABLE` → Covered by Custom Semgrep Rule `wm-sast-innerhtml` and probe validation.

---

## Candidate Area 5: URL & SSRF Policy (RSS Proxy)
- **Trust Boundary**: Caller-supplied `url` parameter to `/api/rss-proxy`.
- **Handler / Source Reference**: `target/api/rss-proxy.js:225-239`, `target/api/rss-proxy.js:283-291`, `target/api/_rss-allowed-domain-match.js:31-40`.
- **Data Source**: User query string `?url=<feedUrl>`.
- **Expected Control**:
  1. `assertHttpProtocol`: Enforces scheme is strictly `http:` or `https:`.
  2. `isAllowedDomain`: Validates hostname against `RSS_ALLOWED_DOMAINS` registry.
  3. `assertAllowedRedirect`: Validates redirect locations (301/302/307/308) against `isAllowedDomain`.
  4. Local loopback, private IP ranges (RFC 1918), and AWS/cloud metadata (`169.254.169.254`) must be rejected.
- **Review Question**: Does `/api/rss-proxy` prevent loopback access (`http://127.0.0.1`), metadata access (`http://169.254.169.254`), and open redirect SSRF?
- **Status / Verdict**: `APPLICABLE` → Covered by Probe Recipe `wm-probe-ssrf-01`.

---

## Candidate Area 6: Cross-Origin Resource Sharing (CORS) Policy
- **Trust Boundary**: Browser requests originating from arbitrary web origins.
- **Handler / Source Reference**: `target/api/_cors.js:3-25`, `target/api/_cors.js:135-147`, `target/api/_cors.js:194-198`.
- **Data Source**: HTTP `Origin` header.
- **Expected Control**:
  1. Allowlist regex strictly matches `worldmonitor.app` subdomains, `tauri.localhost`, and `*.vercel.app` under the specific `eliewm` team scope.
  2. Disallowed origins do not receive permissive reflection with credentials.
  3. In production mode, bare `localhost` and `127.0.0.1` are excluded from `ALLOWED_ORIGIN_PATTERNS`.
- **Review Question**: Can an arbitrary malicious origin (e.g. `https://attacker.evil.com`) make credentialed cross-origin API calls and receive valid CORS headers?
- **Status / Verdict**: `APPLICABLE` → Covered by Probe Recipe `wm-probe-cors-01`.

---

## Candidate Area 7: Rate-Limit Identity & Header Spoofing
- **Trust Boundary**: Client-supplied IP identification headers (`cf-connecting-ip`, `x-forwarded-for`).
- **Handler / Source Reference**: `target/api/_client-ip.js:137-160`, `target/api/_client-ip.js:200-218`.
- **Data Source**: `cf-connecting-ip`, `x-real-ip`, `x-wm-edge-proof`.
- **Expected Control**: Direct client hits to the origin cannot rotate `cf-connecting-ip` to bypass rate limits unless `x-wm-edge-proof` matches `CF_EDGE_PROOF_SECRET`. Otherwise falls back to `x-real-ip` or `UNKNOWN_CLIENT_IP`.
- **Review Question**: Does supplying arbitrary `cf-connecting-ip` headers reset or circumvent local rate limiting without transit proof?
- **Status / Verdict**: `APPLICABLE` → Covered by Probe Recipe `wm-probe-ratelimit-01`.

---

## Candidate Area 8: OAuth & Cross-Subdomain Grant Tokens
- **Trust Boundary**: Cross-subdomain grant tokens exchanged during Pro authorization.
- **Handler / Source Reference**: `target/api/_mcp-grant-hmac.ts:99-166`.
- **Data Source**: Token format `<base64url(payload)>.<base64url(sig)>`.
- **Expected Control**: HMAC-SHA-256 signature verification over exact payload bytes. Strict rejection of expired tokens (`exp <= now`), malformed formats, and signature tampering.
- **Review Question**: Are unsigned, tampered, or expired grant tokens accepted by `verifyGrant`?
- **Status / Verdict**: `APPLICABLE` → Covered by Probe Recipe `wm-probe-oauth-grant-01`.

---

## Candidate Area 9: RSS Stream Bounding & Memory DoS
- **Trust Boundary**: Size and structure of upstream XML RSS feeds.
- **Handler / Source Reference**: `target/api/rss-proxy.js:38-46`, `target/api/rss-proxy.js:140-180`.
- **Data Source**: Upstream feed response body.
- **Expected Control**: Caps items at `MAX_FEED_ITEMS = 20`, caps bytes at `MAX_FEED_BYTES = 5MB`, closes dangling XML tags via `closeOpenElements`.
- **Review Question**: Does an upstream feed with huge payloads or unbounded items cause memory exhaustion or hang the reader?
- **Status / Verdict**: `APPLICABLE` → Covered by Custom Semgrep Rule `wm-sast-feed-boundary`.

---

## Candidate Area 10: Quota Invariants & Nonce Consumption
- **Trust Boundary**: Pro MCP daily quota reservations.
- **Handler / Source Reference**: `target/api/user/mcp-quota.ts:169-218`, `target/api/mcp/quota.ts`.
- **Data Source**: Redis counter `mcp:pro-usage:<userId>:<YYYY-MM-DD>`.
- **Expected Control**: Atomic Redis INCR, daily UTC midnight reset, clamping displayed count to plan limit.
- **Review Question**: Does quota tracking allow integer underflow, rollback, or manipulation by synthetic users?
- **Status / Verdict**: `APPLICABLE` → Covered by Probe Recipe `wm-probe-quota-01`.
