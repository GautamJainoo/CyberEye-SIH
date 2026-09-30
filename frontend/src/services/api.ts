import { Vulnerability, Severity, Status } from '../types'

// Backend API. Supports direct AWS backend URL and relative /api proxy on HTTPS (e.g. Netlify)
function resolveApiBase(): string {
  if (typeof window !== 'undefined') {
    // If running in browser on HTTPS (Netlify/CloudFront/Vercel) and backend is HTTP,
    // route via relative '/api' proxy to avoid browser Mixed Content blocking.
    if (window.location.protocol === 'https:') {
      return '/api'
    }
  }
  return process.env.NEXT_PUBLIC_API_BASE || 'http://13.201.10.69:8000/api'
}

export const API_BASE = resolveApiBase()
export const API_ORIGIN = API_BASE.replace(/\/api$/, '')

export interface BackendHealth {
  status: string
  repo_url?: string
  website_url?: string
  target_commit: string
  target_healthy: boolean
  target_message: string
  environment: string
  findings_count?: number
}

export interface TargetConfigPayload {
  repo_url: string
  website_url?: string
  commit_sha?: string
  reset_db?: boolean
}

export interface TargetConfigResponse {
  status: string
  repo_url: string
  website_url: string
  commit_sha: string
  target_healthy: boolean
  target_message: string
}

export interface BackendFinding {
  schema_version: string
  finding_id: string
  stable_fingerprint: string
  title: string
  category: string
  status: string
  severity: string
  cvss_score?: number | null
  cvss_vector?: string | null
  file?: string | null
  line_start?: number | null
  line_end?: number | null
  endpoint?: string | null
  method?: string | null
  package?: string | null
  package_version?: string | null
  cwe?: string[]
  cve?: string[]
  ghsa?: string[]
  kev_match?: boolean
  description: string
  impact?: string | null
  remediation_proposal?: string | null
  sources?: Array<{
    tool_name: string
    tool_version?: string
    rule_id?: string
    snippet_hash?: string
    raw_ref?: string
  }>
  evidence_count?: number
  created_at?: string
  updated_at?: string
}

export interface FindingsResponse {
  total: number
  findings: BackendFinding[]
}

// Convert Backend Finding to Frontend Vulnerability format
export function mapBackendFinding(bf: BackendFinding, index: number): Vulnerability {
  let sev: Severity = 'Low'
  const upperSev = (bf.severity || '').toUpperCase()
  if (upperSev === 'CRITICAL') sev = 'Critical'
  else if (upperSev === 'HIGH') sev = 'High'
  else if (upperSev === 'MEDIUM') sev = 'Medium'
  else sev = 'Low'

  let status: Status = 'Open'
  const upperStatus = (bf.status || '').toUpperCase()
  if (upperStatus === 'FIXED' || upperStatus === 'REJECTED' || upperStatus === 'CLOSED') {
    status = 'Fixed'
  } else if (upperStatus === 'TRIAGED' || upperStatus === 'VERIFIED' || upperStatus === 'PATCH_PROPOSED') {
    status = 'In Progress'
  } else {
    status = 'Open'
  }

  // The real tool that reported this finding (first source), not a guess from the category.
  const TOOL_LABELS: Record<string, string> = {
    semgrep: 'Semgrep (SAST)', gitleaks: 'Gitleaks (Secrets)', 'osv-scanner': 'OSV-Scanner (SCA)',
    zap: 'OWASP ZAP (DAST)', 'worldmonitor-probes': 'World Monitor probe', 'gemini-review': 'Gemini code review',
  }
  const srcTool = bf.sources?.[0]?.tool_name
  const toolDetected = srcTool ? TOOL_LABELS[srcTool] || srcTool : undefined

  const component = bf.file
    ? `${bf.file}${bf.line_start ? `:${bf.line_start}` : ''}`
    : bf.endpoint
    ? `${bf.method || 'GET'} ${bf.endpoint}`
    : bf.package
    ? `${bf.package}@${bf.package_version || '*'}`
    : 'unspecified location'

  const cveStr = bf.cve && bf.cve.length > 0 ? bf.cve[0] : undefined
  const cweStr = bf.cwe && bf.cwe.length > 0 ? bf.cwe[0] : undefined

  return {
    id: index + 1,
    backendId: bf.finding_id,
    name: bf.title,
    description: bf.description,
    severity: sev,
    component,
    cvss: bf.cvss_score ?? null, // never invented: shown as "--" when the source provides no CVSS
    status,
    rawStatus: bf.status,
    cve: cveStr,
    cwe: cweStr,
    toolDetected,
    stepsToReproduce: bf.file
      ? [
          `Open ${bf.file}${bf.line_start ? ` at line ${bf.line_start}` : ''}`,
          ...(bf.sources?.[0]?.rule_id ? [`Detector / rule: ${bf.sources[0].rule_id}`] : []),
          ...(bf.sources?.[0]?.snippet_hash ? [`Snippet hash: ${bf.sources[0].snippet_hash}`] : []),
        ]
      : undefined,
    pocPayload: bf.sources?.[0]?.raw_ref || undefined,
    businessImpact: bf.impact || undefined,
    remediationCode: bf.remediation_proposal || undefined,
    evidenceCount: bf.evidence_count ?? 0,
    kevMatch: bf.kev_match ?? false,
    file: bf.file || undefined,
    lineStart: bf.line_start ?? undefined,
  }
}

export async function fetchHealth(): Promise<BackendHealth | null> {
  try {
    const res = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(3000) })
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

export async function fetchFindings(targetUrl?: string): Promise<FindingsResponse | null> {
  try {
    const url = targetUrl
      ? `${API_BASE}/findings?target_url=${encodeURIComponent(targetUrl)}`
      : `${API_BASE}/findings`
    const res = await fetch(url, { signal: AbortSignal.timeout(6000) })
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

export interface ScanLive {
  running: boolean
  scan_id: string | null
  current: string
  done: number
  total: number
  percent: number
  lines: string[]
  status?: string
}

export async function fetchScanLive(): Promise<ScanLive | null> {
  try {
    const res = await fetch(`${API_BASE}/scan/live`)
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

export async function triggerScan(profile: string = 'lite', tools?: string[]): Promise<{ status: string } | null> {
  try {
    const res = await fetch(`${API_BASE}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ profile, tools }),
    })
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

export async function triageFinding(findingId: string, reason: string): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/triage/${findingId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ actor_id: 'analyst', reason }),
    })
    return res.ok
  } catch {
    return false
  }
}

export async function verifyFinding(findingId: string, reason: string, impact?: string): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/verify/${findingId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ actor_id: 'analyst', reason, impact }),
    })
    return res.ok
  } catch {
    return false
  }
}

export async function rejectFinding(findingId: string, reason: string): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/reject/${findingId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ actor_id: 'analyst', reason }),
    })
    return res.ok
  } catch {
    return false
  }
}

export function getExportUrl(format: 'json' | 'html'): string {
  return `${API_BASE}/report/export?format=${format}`
}

export async function configureTarget(payload: TargetConfigPayload): Promise<TargetConfigResponse | null> {
  try {
    const res = await fetch(`${API_BASE}/target/configure`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

export async function resetDatabase(): Promise<{ status: string; purged_findings: number } | null> {
  try {
    const res = await fetch(`${API_BASE}/db/reset`, { method: 'POST' })
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

// --- DevTools Suite API Types & Functions ---

export interface DevToolsNetworkRequest {
  id: string
  name: string
  path?: string
  status: number
  type: string
  initiator: string
  size: string
  time: number
  waterfallPct: number
  offsetPct: number
  isVuln: boolean
  vulnTag?: string
  vulnDesc?: string
  backendFindingId?: string
  method?: string
}

export interface DevToolsSecurityHeader {
  name: string
  status: 'PASS' | 'WARN' | 'FAIL'
  severity: string
  value: string | null
  recommendation: string
  risk: string | null
}

export interface DevToolsSecurityAnalysis {
  origin: string
  protocol: string
  connection_secure: boolean
  certificate: {
    subject: string
    issuer: string
    valid_from: string
    valid_to: string
    san: string[]
    key_exchange: string
    cipher: string
    signature_algorithm: string
  }
  security_headers: DevToolsSecurityHeader[]
  score: number
  overall_status: string
}

export interface DevToolsPerformanceMetric {
  value: number
  unit: string
  status: string
  threshold: number
  score: number
}

export interface DevToolsPerformance {
  target: string
  metrics: {
    lcp: DevToolsPerformanceMetric
    inp: DevToolsPerformanceMetric
    cls: DevToolsPerformanceMetric
    ttfb: DevToolsPerformanceMetric
    fcp: DevToolsPerformanceMetric
    speed_index: DevToolsPerformanceMetric
  }
  summary: {
    overall_score: number
    total_transfer_kb: number
    uncompressed_kb: number
    total_requests: number
    dom_content_loaded_ms: number
    load_time_ms: number
  }
}

export interface DevToolsStorageItem {
  key: string
  value: string
  isSensitive: boolean
  cwe: string | null
  risk: string
  description: string
  fix: string | null
}

export interface DevToolsCookieItem {
  name: string
  domain: string
  path: string
  httpOnly: boolean
  secure: boolean
  sameSite: string
  status: string
}

export interface DevToolsStorage {
  local_storage: DevToolsStorageItem[]
  cookies: DevToolsCookieItem[]
  service_workers: Array<{
    scope: string
    script: string
    status: string
    cache_storage_kb: number
  }>
}

export interface NetworkInspectMetric {
  id: string
  name: string
  path: string
  type: 'API Endpoint' | 'HTML Page'
  latencyMs: number
  speedIndex: string
  pageSize: string
  httpStatus: number
  securityStatus: 'Vulnerable' | 'Secure'
  findingTag?: string
  findingDesc?: string
}

export interface NetworkInspectResponse {
  summary: {
    averageLatency: string
    ttfb: string
    totalRequests: number
    totalTransferSize: string
    uncompressedSize: string
    httpProtocol: string
    dnsLookup: string
    sslHandshake: string
  }
  metrics: NetworkInspectMetric[]
}

export interface CopilotChatResponse {
  reply: string
  codeSnippet?: string | null
  model: string
  timestamp: string
}

export interface CopilotRecommendation {
  id: number
  finding_id: string
  priority: string
  color: string
  bg: string
  border: string
  dot: string
  title: string
  impact: string
  fix: string
  codeSnippet?: string | null
}

export interface TelemetryAttackSurfaceNode {
  id: string
  label: string
  kind: 'source' | 'dependencies' | 'secrets' | 'runtime'
  status: 'warning' | 'vulnerable'
  max_severity: string
  findings: number
  top: { finding_id: string; title: string; severity: string }[]
}

export async function fetchDevToolsNetwork(targetUrl?: string): Promise<DevToolsNetworkRequest[]> {
  try {
    const url = targetUrl ? `${API_BASE}/devtools/network?target_url=${encodeURIComponent(targetUrl)}` : `${API_BASE}/devtools/network`
    const res = await fetch(url)
    if (!res.ok) return []
    const data = await res.json()
    return data.requests || []
  } catch {
    return []
  }
}

export async function fetchDevToolsSecurity(targetUrl?: string): Promise<DevToolsSecurityAnalysis | null> {
  try {
    const url = targetUrl ? `${API_BASE}/devtools/security?target_url=${encodeURIComponent(targetUrl)}` : `${API_BASE}/devtools/security`
    const res = await fetch(url)
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

export async function fetchDevToolsPerformance(targetUrl?: string): Promise<DevToolsPerformance | null> {
  try {
    const url = targetUrl ? `${API_BASE}/devtools/performance?target_url=${encodeURIComponent(targetUrl)}` : `${API_BASE}/devtools/performance`
    const res = await fetch(url)
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

export async function fetchDevToolsStorage(targetUrl?: string): Promise<DevToolsStorage | null> {
  try {
    const url = targetUrl
      ? `${API_BASE}/devtools/storage?target_url=${encodeURIComponent(targetUrl)}`
      : `${API_BASE}/devtools/storage`
    const res = await fetch(url)
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

export async function executeDevToolsConsole(command: string): Promise<{ type: 'log' | 'warn' | 'error'; output: string } | null> {
  try {
    const res = await fetch(`${API_BASE}/devtools/console/exec`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ command }),
    })
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

export async function fetchNetworkInspect(targetUrl?: string): Promise<NetworkInspectResponse | null> {
  try {
    const url = targetUrl ? `${API_BASE}/network/inspect?target_url=${encodeURIComponent(targetUrl)}` : `${API_BASE}/network/inspect`
    const res = await fetch(url)
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

export async function probeNetworkEndpoint(urlOrPath: string): Promise<any> {
  try {
    const res = await fetch(`${API_BASE}/network/probe`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url_or_path: urlOrPath }),
    })
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

export async function askCopilot(prompt: string, findingId?: string): Promise<CopilotChatResponse | null> {
  try {
    const res = await fetch(`${API_BASE}/copilot/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt, finding_id: findingId }),
    })
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

export async function fetchCopilotRecommendations(): Promise<CopilotRecommendation[]> {
  try {
    const res = await fetch(`${API_BASE}/copilot/recommendations`)
    if (!res.ok) return []
    const data = await res.json()
    return data.recommendations || []
  } catch {
    return []
  }
}

export async function fetchAttackSurface(): Promise<TelemetryAttackSurfaceNode[]> {
  try {
    const res = await fetch(`${API_BASE}/telemetry/attack-surface`)
    if (!res.ok) return []
    const data = await res.json()
    return data.nodes || []
  } catch {
    return []
  }
}

export async function fetchRadarData(): Promise<Array<{ label: string; value: number; maxValue: number }>> {
  try {
    const res = await fetch(`${API_BASE}/telemetry/radar`)
    if (!res.ok) return []
    const data = await res.json()
    return data.radar || []
  } catch {
    return []
  }
}


