// Shared types used across the dashboard and security assessment tool (SIH PS 26163)
export type Severity = 'Critical' | 'High' | 'Medium' | 'Low'
export type Status = 'Open' | 'In Progress' | 'Fixed'

export interface Vulnerability {
  id: number
  name: string
  description: string
  severity: Severity
  component: string
  cvss: number
  status: Status
  cve?: string
  cwe?: string
  toolDetected?: 'Semgrep (SAST)' | 'Gitleaks (Secrets)' | 'OSV-Scanner (SCA)' | 'OWASP ZAP (DAST)'
  stepsToReproduce?: string[]
  pocPayload?: string
  businessImpact?: string
  remediationCode?: string
}

export interface RadarDataPoint {
  label: string
  value: number
  maxValue: number
}

export interface ActivityItem {
  id: number
  message: string
  detail?: string
  type: 'scan' | 'vuln' | 'report' | 'fix'
  timeAgo: string
}

export interface PageSpeedMetric {
  id: string
  path: string
  name: string
  type: 'HTML Page' | 'API Endpoint' | 'Asset'
  speedIndex: string
  latencyMs: number
  ttfbMs: number
  transferSize: string
  statusCode: number
  securityStatus: 'Secure' | 'Vulnerable' | 'Warning'
  findingTag?: string
}

export interface CoreWebVitalMetric {
  key: string
  title: string
  fullTitle: string
  value: string
  status: 'Good' | 'Needs Improvement' | 'Poor'
  statusColor: string
  thresholds: [string, string, string]
  currentPercent: number // 0 to 100 for visual progress bar
  description: string
}

export interface RecommendedFixItem {
  id: string
  iconType: 'code' | 'doc' | 'globe'
  title: string
  description: string
  priority: 'High' | 'Medium' | 'Low'
  benefit: string
  timeToFix: string
  actionUrl?: string
}
