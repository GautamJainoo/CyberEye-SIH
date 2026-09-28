import { Vulnerability, Severity, Status } from '../types'

const API_BASE = 'http://127.0.0.1:8000/api'

export interface BackendHealth {
  status: string
  target_commit: string
  target_healthy: boolean
  target_message: string
  environment: string
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

export interface ScanResponse {
  run_id: string
  profile: string
  findings_discovered: number
  findings_persisted: number
  duration_seconds: number
  scanner_status: Record<string, string>
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

  let toolDetected: 'Semgrep (SAST)' | 'Gitleaks (Secrets)' | 'OSV-Scanner (SCA)' | 'OWASP ZAP (DAST)' | undefined
  const cat = (bf.category || '').toLowerCase()
  if (cat === 'sast') toolDetected = 'Semgrep (SAST)'
  else if (cat === 'secret') toolDetected = 'Gitleaks (Secrets)'
  else if (cat === 'sca') toolDetected = 'OSV-Scanner (SCA)'
  else if (cat === 'dast') toolDetected = 'OWASP ZAP (DAST)'

  const component = bf.file
    ? `${bf.file}${bf.line_start ? `:${bf.line_start}` : ''}`
    : bf.endpoint
    ? `${bf.method || 'GET'} ${bf.endpoint}`
    : bf.package
    ? `${bf.package}@${bf.package_version || '*'}`
    : 'worldmonitor/core'

  const cveStr = bf.cve && bf.cve.length > 0 ? bf.cve[0] : undefined
  const cweStr = bf.cwe && bf.cwe.length > 0 ? bf.cwe[0] : undefined

  return {
    id: index + 1,
    backendId: bf.finding_id,
    name: bf.title,
    description: bf.description,
    severity: sev,
    component,
    cvss: bf.cvss_score ?? (sev === 'Critical' ? 9.2 : sev === 'High' ? 7.8 : sev === 'Medium' ? 5.4 : 3.1),
    status,
    rawStatus: bf.status,
    cve: cveStr,
    cwe: cweStr,
    toolDetected,
    stepsToReproduce: bf.file
      ? [
          `Inspect file location: ${bf.file}${bf.line_start ? ` at line ${bf.line_start}` : ''}`,
          `Rule / Detector ID: ${bf.sources?.[0]?.rule_id || 'wm-security-rule'}`,
          `Evidence hash: ${bf.sources?.[0]?.snippet_hash || 'verified-sha256'}`,
        ]
      : undefined,
    pocPayload: bf.sources?.[0]?.raw_ref || undefined,
    businessImpact: bf.impact || 'Potential integrity and confidentiality compromise within application boundary.',
    remediationCode: bf.remediation_proposal || '// Apply input sanitization and parameter binding per OWASP ASVS 4.0',
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

export async function fetchFindings(): Promise<FindingsResponse | null> {
  try {
    const res = await fetch(`${API_BASE}/findings`, { signal: AbortSignal.timeout(6000) })
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

export async function triggerScan(profile: string = 'lite', tools?: string[]): Promise<ScanResponse | null> {
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
