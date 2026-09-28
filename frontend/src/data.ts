import {
  Vulnerability,
  ActivityItem,
  RadarDataPoint,
  CoreWebVitalMetric,
  RecommendedFixItem,
  PageSpeedMetric,
} from './types'

export interface CountryThreat {
  code: string
  country: string
  attacksBlocked: number
  threatLevel: 'Critical' | 'High' | 'Medium' | 'Low'
  flag: string
  topVector: string
  trend: string
}

export const countryThreats: CountryThreat[] = [
  { code: 'US', country: 'United States', attacksBlocked: 1420, threatLevel: 'Medium', flag: '🇺🇸', topVector: 'Credential Stuffing', trend: '+4%' },
  { code: 'DE', country: 'Germany', attacksBlocked: 890, threatLevel: 'Low', flag: '🇩🇪', topVector: 'Automated Bot Probes', trend: '-2%' },
  { code: 'SG', country: 'Singapore', attacksBlocked: 640, threatLevel: 'Low', flag: '🇸🇬', topVector: 'API Rate Flooding', trend: '+1%' },
  { code: 'BR', country: 'Brazil', attacksBlocked: 1120, threatLevel: 'High', flag: '🇧🇷', topVector: 'Brute Force SSH', trend: '+12%' },
  { code: 'IN', country: 'India', attacksBlocked: 1850, threatLevel: 'High', flag: '🇮🇳', topVector: 'SQLi & Probe Scanners', trend: '+8%' },
  { code: 'NL', country: 'Netherlands', attacksBlocked: 510, threatLevel: 'Low', flag: '🇳🇱', topVector: 'Port Reconnaissance', trend: '-5%' },
]

export const coreWebVitalsData: CoreWebVitalMetric[] = [
  {
    key: 'lcp',
    title: 'LCP',
    fullTitle: 'Largest Contentful Paint',
    value: '1.8 s',
    status: 'Good',
    statusColor: 'text-emerald-500 dark:text-emerald-400',
    thresholds: ['0s', '2.5s', '4.0s'],
    currentPercent: 45,
    description: 'Measures loading performance. Renders main content in under 2.5s.',
  },
  {
    key: 'inp',
    title: 'INP',
    fullTitle: 'Interaction to Next Paint',
    value: '60 ms',
    status: 'Good',
    statusColor: 'text-emerald-500 dark:text-emerald-400',
    thresholds: ['0ms', '200ms', '500ms'],
    currentPercent: 24,
    description: 'Measures responsiveness to user interactions. Excellent under 200ms.',
  },
  {
    key: 'cls',
    title: 'CLS',
    fullTitle: 'Cumulative Layout Shift',
    value: '0.00',
    status: 'Good',
    statusColor: 'text-emerald-500 dark:text-emerald-400',
    thresholds: ['0', '0.1', '0.25'],
    currentPercent: 4,
    description: 'Measures visual stability. Zero unexpected layout shifts detected.',
  },
]

export const recommendedFixesData: RecommendedFixItem[] = [
  {
    id: 'fix-1',
    iconType: 'code',
    title: 'Reduce unused JavaScript',
    description: 'Remove unused JS to improve load time and reduce bandwidth.',
    priority: 'High',
    benefit: 'Potential savings 562 KiB',
    timeToFix: '~15 min',
    actionUrl: 'https://worldmonitor.app/bundles',
  },
  {
    id: 'fix-2',
    iconType: 'doc',
    title: 'Add a meta description',
    description: 'Improve click-through rates and SEO visibility.',
    priority: 'Medium',
    benefit: 'Quick win ~1 min',
    timeToFix: '~1 min',
    actionUrl: 'https://worldmonitor.app/seo',
  },
  {
    id: 'fix-3',
    iconType: 'globe',
    title: 'Set a language attribute',
    description: 'Help search engines and assistive technologies understand your content.',
    priority: 'Low',
    benefit: 'Quick win ~1 min',
    timeToFix: '~1 min',
    actionUrl: 'https://worldmonitor.app/a11y',
  },
]

export const pageSpeedMetrics: PageSpeedMetric[] = [
  {
    id: 'page-1',
    path: '/',
    name: 'Landing Page & Overview',
    type: 'HTML Page',
    speedIndex: '1.1s',
    latencyMs: 38,
    ttfbMs: 24,
    transferSize: '340 KB',
    statusCode: 200,
    securityStatus: 'Secure',
  },
  {
    id: 'page-2',
    path: '/dashboard',
    name: 'SEC-OPS Main Dashboard',
    type: 'HTML Page',
    speedIndex: '1.4s',
    latencyMs: 45,
    ttfbMs: 30,
    transferSize: '520 KB',
    statusCode: 200,
    securityStatus: 'Secure',
  },
  {
    id: 'page-3',
    path: '/api/search',
    name: 'Vulnerability / CVE Search API',
    type: 'API Endpoint',
    speedIndex: '0.4s',
    latencyMs: 85,
    ttfbMs: 78,
    transferSize: '12.4 KB',
    statusCode: 200,
    securityStatus: 'Vulnerable',
    findingTag: 'SQLi CVE-2024-22252',
  },
  {
    id: 'page-4',
    path: '/auth/login',
    name: 'User Authentication Gateway',
    type: 'HTML Page',
    speedIndex: '0.9s',
    latencyMs: 32,
    ttfbMs: 20,
    transferSize: '180 KB',
    statusCode: 200,
    securityStatus: 'Secure',
  },
  {
    id: 'page-5',
    path: '/api/users/:id',
    name: 'User Profile & Identity Service',
    type: 'API Endpoint',
    speedIndex: '0.3s',
    latencyMs: 92,
    ttfbMs: 85,
    transferSize: '8.2 KB',
    statusCode: 200,
    securityStatus: 'Vulnerable',
    findingTag: 'IDOR CWE-639',
  },
  {
    id: 'page-6',
    path: '/analytics',
    name: 'Telemetry & Chart Analytics',
    type: 'HTML Page',
    speedIndex: '1.6s',
    latencyMs: 60,
    ttfbMs: 42,
    transferSize: '850 KB',
    statusCode: 200,
    securityStatus: 'Secure',
  },
  {
    id: 'page-7',
    path: '/api/auth/reset',
    name: 'Password Recovery Endpoint',
    type: 'API Endpoint',
    speedIndex: '0.5s',
    latencyMs: 68,
    ttfbMs: 60,
    transferSize: '4.1 KB',
    statusCode: 200,
    securityStatus: 'Warning',
    findingTag: 'Missing Rate Limiting',
  },
]

export const networkInspectSummary = {
  averageLatency: '42 ms',
  ttfb: '28 ms',
  totalRequests: 34,
  totalTransferSize: '1.2 MB',
  uncompressedSize: '3.8 MB',
  httpProtocol: 'HTTP/2 (TLS 1.3)',
  dnsLookup: '12 ms',
  sslHandshake: '18 ms',
}

export const vulnerabilities: Vulnerability[] = [
  {
    id: 1,
    name: 'SQL Injection via search param',
    description: 'User input in /api/search is concatenated directly into SQL query builder without parameter binding.',
    severity: 'Critical',
    component: 'API / Data Service (worldmonitor/api/search.py)',
    cvss: 9.8,
    status: 'Open',
    cve: 'CVE-2024-22252',
    cwe: 'CWE-89',
    toolDetected: 'Semgrep (SAST)',
    stepsToReproduce: [
      'Send GET request to https://worldmonitor.app/api/search?q=\' OR 1=1--',
      'Observe unrestricted data exfiltration of internal database records in JSON response.',
      'Confirm sleep delay: /api/search?q=\' UNION SELECT pg_sleep(5)-- responds in >5000ms.',
    ],
    pocPayload: "curl -X GET 'https://worldmonitor.app/api/search?q=%27%20OR%201=1--' -H 'Accept: application/json'",
    businessImpact: 'Complete database compromise, unauthorized exfiltration of customer credentials, and potential host takeover.',
    remediationCode: `// Secure Parameterized Query
const query = 'SELECT * FROM security_findings WHERE query_text ILIKE $1 AND org_id = $2';
const results = await db.query(query, ['%' + searchParam + '%', user.orgId]);`,
  },
  {
    id: 2,
    name: 'Broken Access Control & IDOR',
    description: 'Admin endpoints and user profile routes (/api/users/:id) permit arbitrary ID fetching without ownership checks.',
    severity: 'High',
    component: 'Backend API / Users (worldmonitor/routes/users.js)',
    cvss: 8.3,
    status: 'Open',
    cve: 'CVE-2024-31102',
    cwe: 'CWE-639',
    toolDetected: 'OWASP ZAP (DAST)',
    stepsToReproduce: [
      'Log in as unprivileged user (UID: 1044).',
      'Change request parameter to GET /api/users/1 (SuperAdmin).',
      'Server returns full PII, API tokens, and internal email address without authorization rejection.',
    ],
    pocPayload: "curl -X GET 'https://worldmonitor.app/api/users/1' -H 'Authorization: Bearer <unprivileged_jwt>'",
    businessImpact: 'Unauthorized horizontal & vertical privilege escalation; leakage of executive credentials.',
    remediationCode: `// Enforce ownership & role verification
if (req.user.id !== requestedUserId && !req.user.roles.includes('ADMIN')) {
  return res.status(403).json({ error: 'Access forbidden: Insufficient privileges' });
}`,
  },
  {
    id: 3,
    name: 'Hardcoded Production Secret Key',
    description: 'AWS Secret Access Key and JWT signing secret hardcoded in repo configuration files.',
    severity: 'Critical',
    component: 'Source Code (config/secrets.env)',
    cvss: 9.1,
    status: 'Open',
    cve: 'CWE-798',
    toolDetected: 'Gitleaks (Secrets)',
    stepsToReproduce: [
      'Run Gitleaks on repository commit tree.',
      'Detected pattern match for AWS_SECRET_ACCESS_KEY at commit 4f981a2.',
      'Key verified active against S3 bucket telemetry storage.',
    ],
    pocPayload: "gitleaks detect --source=. --verbose --report-format=json",
    businessImpact: 'Direct cloud infrastructure takeover, unauthorized bucket modification, severe data leak.',
    remediationCode: `// Retrieve credentials from Cloud Vault / Environment variable
const jwtSecret = process.env.JWT_SIGNING_KEY;
if (!jwtSecret) throw new Error('JWT_SIGNING_KEY must be injected via secure secret store');`,
  },
  {
    id: 4,
    name: 'Outdated Lodash Dependency (Prototype Pollution)',
    description: 'Lodash version 4.17.15 contains known prototype pollution vulnerability CVE-2021-23337.',
    severity: 'Medium',
    component: 'Frontend / Dependencies (package.json)',
    cvss: 6.8,
    status: 'In Progress',
    cve: 'CVE-2021-23337',
    cwe: 'CWE-1321',
    toolDetected: 'OSV-Scanner (SCA)',
    stepsToReproduce: [
      'Inspect package-lock.json dependency tree for lodash versions < 4.17.21.',
      'Inject payload: Object.prototype.polluted = true via _.template or deep merge functions.',
    ],
    pocPayload: "osv-scanner --lockfile=package-lock.json",
    businessImpact: 'Denial of service and remote code execution if parsed templates handle untrusted objects.',
    remediationCode: `npm install lodash@^4.17.21
# Verify update
npm audit --production`,
  },
  {
    id: 5,
    name: 'Missing Rate Limiting on Password Reset',
    description: 'Endpoint /api/auth/reset has no throttling, permitting distributed brute-force attacks.',
    severity: 'High',
    component: 'Authentication Service (/api/auth/reset)',
    cvss: 7.5,
    status: 'Open',
    cve: 'CWE-307',
    toolDetected: 'OWASP ZAP (DAST)',
    stepsToReproduce: [
      'Send 500 consecutive POST requests with sequential reset token guesses in 10 seconds.',
      'Endpoint accepts all requests with HTTP 200 without triggering 429 Too Many Requests.',
    ],
    pocPayload: "for i in {1..100}; do curl -s -X POST https://worldmonitor.app/api/auth/reset -d 'email=target@org.com'; done",
    businessImpact: 'Targeted account takeover via OTP brute-forcing and email inbox flood denial-of-service.',
    remediationCode: `import rateLimit from 'express-rate-limit';
export const resetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit to 5 attempts per IP
  message: 'Too many reset requests. Please retry in 15 minutes.'
});`,
  },
]

export const radarData: RadarDataPoint[] = [
  { label: 'Authentication', value: 72, maxValue: 100 },
  { label: 'Authorization', value: 65, maxValue: 100 },
  { label: 'Input Validation', value: 58, maxValue: 100 },
  { label: 'API Security', value: 70, maxValue: 100 },
  { label: 'Data Privacy', value: 80, maxValue: 100 },
  { label: 'Client-side Security', value: 68, maxValue: 100 },
]

export const recentActivity: ActivityItem[] = [
  {
    id: 1,
    message: 'Health check completed',
    detail: 'Score improved to 92/100',
    type: 'scan',
    timeAgo: '2h ago',
  },
  {
    id: 2,
    message: 'Report downloaded',
    detail: 'health-report-28-09-2026.pdf',
    type: 'report',
    timeAgo: '3h ago',
  },
  {
    id: 3,
    message: 'New suggestion available',
    detail: '3 optimizations found',
    type: 'vuln',
    timeAgo: '5h ago',
  },
  {
    id: 4,
    message: 'System check',
    detail: 'All services operational',
    type: 'fix',
    timeAgo: '6h ago',
  },
]

export const vulnDistribution = [
  { label: 'Critical', count: 2, pct: 16, color: '#ef4444' },
  { label: 'High', count: 5, pct: 42, color: '#f97316' },
  { label: 'Medium', count: 8, pct: 33, color: '#f59e0b' },
  { label: 'Low', count: 11, pct: 9, color: '#10b981' },
]

export const zeroCountryThreats: CountryThreat[] = [
  { code: 'US', country: 'United States', attacksBlocked: 0, threatLevel: 'Low', flag: '🇺🇸', topVector: 'None Detected', trend: '0%' },
  { code: 'DE', country: 'Germany', attacksBlocked: 0, threatLevel: 'Low', flag: '🇩🇪', topVector: 'None Detected', trend: '0%' },
]

export const zeroVulnerabilities: Vulnerability[] = []

export const zeroRadarData: RadarDataPoint[] = [
  { label: 'Authentication', value: 0, maxValue: 100 },
  { label: 'Authorization', value: 0, maxValue: 100 },
  { label: 'Input Validation', value: 0, maxValue: 100 },
  { label: 'API Security', value: 0, maxValue: 100 },
  { label: 'Data Privacy', value: 0, maxValue: 100 },
  { label: 'Client-side Security', value: 0, maxValue: 100 },
]

export const zeroRecentActivity: ActivityItem[] = [
  {
    id: 1,
    message: 'Security baseline verified',
    detail: 'Clean perimeter audit complete — 0 issues identified',
    type: 'scan',
    timeAgo: 'Just now',
  },
]

export const zeroVulnDistribution = [
  { label: 'Critical', count: 0, pct: 0, color: '#ef4444' },
  { label: 'High', count: 0, pct: 0, color: '#f97316' },
  { label: 'Medium', count: 0, pct: 0, color: '#f59e0b' },
  { label: 'Low', count: 0, pct: 0, color: '#10b981' },
]
