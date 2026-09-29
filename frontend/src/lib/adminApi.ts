import { API_BASE, API_ORIGIN } from '../services/api'

export interface Analysis {
  summary?: string
  root_cause?: string
  how_detected?: string
  exploitation_scenario?: string
  impact?: string
  fix_steps?: string[]
  fixed_code?: string
  false_positive_risk?: string
  ai_error?: string
}

export interface FindingRow {
  finding_id: string
  title: string
  category: string
  severity: string
  status: string
  file?: string | null
  line_start?: number | null
  endpoint?: string | null
  method?: string | null
  package?: string | null
  package_version?: string | null
  cwe?: string[]
  cvss_score?: number | null
  sources?: { tool_name: string; rule_id?: string | null }[]
  evidence_count?: number
  created_at?: string
}

export interface ToolRun {
  run_id: string
  scan_id: string
  tool_name: string
  tool_version?: string
  command_line: string
  exit_code: number
  raw_output_path: string
  raw_output_sha256: string
  duration_seconds?: number
  peak_ram_mb?: number
  created_at: string
}

export interface PipelineStep { id: string; label: string; status: 'pending' | 'running' | 'done' | 'failed' | 'skipped'; detail: string; started_at?: string; finished_at?: string }
export interface PipelineState { running: boolean; steps: PipelineStep[]; started_at: string | null; finished_at: string | null; log: string[]; scan?: Record<string, unknown>; setup?: { plan: { source: string; steps?: { command: string; purpose: string; allowed: boolean }[]; notes?: string[]; risks?: string[] }; result: { healthy: boolean; rejected_by_guard: string[] } } }

export interface Overview {
  scans: { scan_id: string; status: string; start_time: string; end_time?: string; metrics_json?: string }[]
  tool_runs: ToolRun[]
  findings_by_tool: { tool_name: string; findings: number }[]
  findings_by_severity: { severity: string; n: number }[]
  findings_by_status: { status: string; n: number }[]
  findings_total: number
  findings_analysed: number
  proof_images: number
  audit: { event_type: string; actor_type: string; actor_id: string; timestamp: string }[]
  target_healthy: boolean
  target_message: string
  pipeline: PipelineState
}

export interface FindingDetail {
  finding: Record<string, any>
  evidence: any[]
  timeline: { from_status: string; to_status: string; actor_type: string; actor_id: string; reason: string; timestamp: string }[]
  sources: { tool_name: string; tool_version?: string; rule_id?: string; raw_ref?: string }[]
  analysis: Analysis | null
  analysis_model: string | null
  code_context: { file: string; start: number; highlight_start: number; highlight_end: number; lines: string[] } | null
  tool_run: ToolRun | null
  proof_url: string | null
}

export interface WebAudit {
  audit_id: string
  url: string
  finished_at: string
  lighthouse_version: string
  categories: { performance: number | null; accessibility: number | null; best_practices: number | null; seo: number | null }
  metrics: { fcp_ms: number | null; lcp_ms: number | null; cls: number | null; tbt_ms: number | null; speed_index_ms: number | null; tti_ms: number | null; ttfb_ms: number | null }
  page: { requests: number; transfer_kb: number }
  main_thread: { group: string; label: string; ms: number }[]
  issues: { category: string; id: string; title: string; score: number; display?: string; description: string }[]
}

export interface ActivityEvent { type: 'scan' | 'vuln' | 'report' | 'fix'; message: string; detail: string; timestamp: string }
export interface NotificationItem { id: string; type: string; title: string; detail: string; timestamp: string; finding_id?: string }

export interface DashboardSummary {
  target: { url: string; healthy: boolean; message: string }
  findings: { total: number; by_severity: Record<string, number>; by_status: Record<string, number>; by_tool: Record<string, number> }
  risk: { score: number; level: string; security_score: number; formula: string }
  coverage: { tools_run: string[]; tools_expected: string[]; tools_missing: string[]; last_scan: { scan_id: string; status: string; end_time: string } | null; last_run_at: string | null }
  endpoints_tested: number
  activity: ActivityEvent[]
  notifications: NotificationItem[]
  web_audit: WebAudit | null
  web_audit_history: { finished_at: string; performance: number | null; accessibility: number | null; best_practices: number | null; seo: number | null }[]
}

export interface WebAuditStatus { running: boolean; error: string | null; started_at: string | null; latest: WebAudit | null }

async function j<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, init)
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status} ${(await res.text()).slice(0, 160)}`)
  return res.json() as Promise<T>
}

export const adminApi = {
  overview: () => j<Overview>('/admin/overview'),
  findings: () => j<{ findings: FindingRow[] }>('/findings').then((r) => r.findings),
  finding: (id: string) => j<FindingDetail>(`/findings/${id}`),
  pipelineStatus: () => j<PipelineState>('/pipeline/status'),
  startPipeline: (fresh: boolean, setup: boolean) =>
    j<{ status: string }>('/pipeline/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ fresh, setup }) }),
  enrich: (force = false) => j('/enrich?force=' + force, { method: 'POST' }),
  buildProofs: (force = false) => j('/proof/build?force=' + force, { method: 'POST' }),
  rawOutput: async (runId: string) => (await fetch(`${API_BASE}/admin/runs/${runId}/raw`)).text(),
  reviewNotes: async () => (await fetch(`${API_BASE}/admin/review-notes`)).text(),
  summary: () => j<DashboardSummary>('/dashboard/summary'),
  webAuditRun: () => j<{ status: string }>('/webaudit/run', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) }),
  webAuditStatus: () => j<WebAuditStatus>('/webaudit/status'),
  consoleLog: (target: string) => j<{ messages: { level: string; text: string }[]; captured_at: string; page_title: string; load_ms: number | null; request_count: number }>(`/devtools/console-log?target_url=${encodeURIComponent(target)}`),
  proofSrc: (url: string) => `${API_ORIGIN}${url}`,
}

export const TOOL_LABEL: Record<string, string> = {
  semgrep: 'Semgrep (SAST)',
  gitleaks: 'Gitleaks (Secrets)',
  'osv-scanner': 'OSV-Scanner (SCA)',
  zap: 'OWASP ZAP (DAST)',
  'worldmonitor-probes': 'WM Probes',
  'gemini-review': 'Gemini Code Review',
}

export const TOOL_METHOD: Record<string, string[]> = {
  semgrep: ['Load the World Monitor rule pack (custom taint + pattern rules).', 'Parse every JS/TS file into an AST.', 'Follow request-controlled values (taint) to dangerous sinks such as fetch() and innerHTML.', 'Report each match with file, line range and the exact code.'],
  gitleaks: ['Walk the repository files and git history.', 'Match built-in secret rules plus World Monitor allowlists.', 'Redact every value so raw secrets never reach logs or the database.', 'Report file, line and rule.'],
  'osv-scanner': ['Locate lockfiles (package-lock.json).', 'Extract exact package versions.', 'Query the OSV database for known advisories per version.', 'Report package, version and advisory IDs.'],
  zap: ['Spider the running local target to discover URLs.', 'Run passive rules on every response (headers, CSP, cookies, info leaks).', 'Run scoped active scans within the approved loopback scope.', 'Report each alert with URL, parameter and evidence.'],
  'worldmonitor-probes': ['Read the recipe derived from the manual review.', 'Send the scoped requests to 127.0.0.1 through the scope guard.', 'Compare every response with the expected safe behaviour.', 'Emit a finding only when an expectation is violated.'],
  'gemini-review': ['Select the security-relevant source files.', 'Redact secrets and send the code to Gemini as untrusted data.', 'Ask for structure review and candidate flaws by SIH scope area.', 'Keep only findings whose quoted code really exists in the repo.'],
}

export const sevClass = (s: string) =>
  ({ CRITICAL: 'bg-red-600 text-white', HIGH: 'bg-orange-500 text-white', MEDIUM: 'bg-yellow-500 text-slate-900', LOW: 'bg-blue-500 text-white', INFO: 'bg-slate-500 text-white' } as Record<string, string>)[s?.toUpperCase()] || 'bg-slate-500 text-white'

export function relativeTime(iso?: string | null): string {
  if (!iso) return '--'
  const secs = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000))
  if (secs < 60) return `${secs}s ago`
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`
  if (secs < 86400) return `${Math.round(secs / 3600)}h ago`
  return `${Math.round(secs / 86400)}d ago`
}

export function formatDateTime(iso?: string | null): string {
  if (!iso) return 'Never'
  return new Date(iso).toLocaleString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}
