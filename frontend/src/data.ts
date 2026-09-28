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

export const countryThreats: CountryThreat[] = []

export const coreWebVitalsData: CoreWebVitalMetric[] = [
  {
    key: 'lcp',
    title: 'LCP',
    fullTitle: 'Largest Contentful Paint',
    value: '0.0 s',
    status: 'Good',
    statusColor: 'text-emerald-500 dark:text-emerald-400',
    thresholds: ['0s', '2.5s', '4.0s'],
    currentPercent: 0,
    description: 'Target baseline performance waiting for live target benchmark.',
  },
  {
    key: 'inp',
    title: 'INP',
    fullTitle: 'Interaction to Next Paint',
    value: '0 ms',
    status: 'Good',
    statusColor: 'text-emerald-500 dark:text-emerald-400',
    thresholds: ['0ms', '200ms', '500ms'],
    currentPercent: 0,
    description: 'Target responsiveness baseline.',
  },
  {
    key: 'cls',
    title: 'CLS',
    fullTitle: 'Cumulative Layout Shift',
    value: '0.00',
    status: 'Good',
    statusColor: 'text-emerald-500 dark:text-emerald-400',
    thresholds: ['0', '0.1', '0.25'],
    currentPercent: 0,
    description: 'Target layout shift baseline.',
  },
]

export const recommendedFixesData: RecommendedFixItem[] = []

export const pageSpeedMetrics: PageSpeedMetric[] = []

export const networkInspectSummary = {
  averageLatency: '0 ms',
  ttfb: '0 ms',
  totalRequests: 0,
  totalTransferSize: '0 KB',
  uncompressedSize: '0 KB',
  httpProtocol: 'HTTP/2 (Loopback)',
  dnsLookup: '0 ms',
  sslHandshake: '0 ms',
}

// Clean baseline: zero dummy vulnerabilities
export const vulnerabilities: Vulnerability[] = []

export const zeroCountryThreats: CountryThreat[] = []

export const zeroVulnerabilities: Vulnerability[] = []

export const zeroRadarData: RadarDataPoint[] = [
  { label: 'Authentication', value: 0, maxValue: 100 },
  { label: 'Authorization', value: 0, maxValue: 100 },
  { label: 'Input Validation', value: 0, maxValue: 100 },
  { label: 'API Security', value: 0, maxValue: 100 },
  { label: 'Data Privacy', value: 0, maxValue: 100 },
  { label: 'Client-side Security', value: 0, maxValue: 100 },
]

export const radarData: RadarDataPoint[] = zeroRadarData

export const zeroRecentActivity: ActivityItem[] = []

export const recentActivity: ActivityItem[] = zeroRecentActivity

export const zeroVulnDistribution = [
  { label: 'Critical', count: 0, pct: 0, color: '#ef4444' },
  { label: 'High', count: 0, pct: 0, color: '#f97316' },
  { label: 'Medium', count: 0, pct: 0, color: '#f59e0b' },
  { label: 'Low', count: 0, pct: 0, color: '#10b981' },
]

export const vulnDistribution = zeroVulnDistribution
