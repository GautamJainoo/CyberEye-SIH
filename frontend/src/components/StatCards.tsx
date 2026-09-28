import { ShieldAlert, Globe, Users, AlertTriangle, ArrowRight, ShieldCheck } from 'lucide-react'
import { useToast } from './Toast'

interface StatCardsProps {
  onSelectMetric?: (metric: string) => void
  isZeroData?: boolean
}

export default function StatCards({ onSelectMetric, isZeroData = false }: StatCardsProps) {
  const { toast } = useToast()

  const stats = [
    {
      id: 'vulns',
      icon: isZeroData ? ShieldCheck : ShieldAlert,
      iconBg: isZeroData
        ? 'bg-emerald-50 dark:bg-emerald-950/60'
        : 'bg-red-50 dark:bg-red-950/60',
      iconColor: isZeroData
        ? 'text-emerald-600 dark:text-emerald-400'
        : 'text-red-500 dark:text-red-400',
      label: 'Vulnerabilities Found',
      value: isZeroData ? '0' : '12',
      sub: isZeroData ? 'Clean baseline (0 findings)' : '↑ 3 since last scan',
      subColor: isZeroData
        ? 'text-emerald-600 dark:text-emerald-400'
        : 'text-red-500 dark:text-red-400',
      toastTitle: 'Vulnerabilities Metric',
      toastMsg: isZeroData
        ? '0 active vulnerabilities. No CVEs detected on current target.'
        : '12 active findings: 2 Critical, 5 High, 3 Medium, 2 Low.',
    },
    {
      id: 'apis',
      icon: Globe,
      iconBg: 'bg-blue-50 dark:bg-blue-950/60',
      iconColor: 'text-blue-500 dark:text-blue-400',
      label: 'APIs Tested',
      value: isZeroData ? '0' : '8',
      sub: isZeroData ? 'Awaiting target scan' : 'All endpoints audited',
      subColor: 'text-slate-400 dark:text-slate-500',
      toastTitle: 'API Surface Audit',
      toastMsg: isZeroData
        ? '0 endpoints scanned. Trigger "Scan Again" to probe endpoints.'
        : '8 endpoints audited: /api/search, /api/auth, /api/users, /api/metrics, etc.',
    },
    {
      id: 'users',
      icon: Users,
      iconBg: 'bg-violet-50 dark:bg-violet-950/60',
      iconColor: 'text-violet-500 dark:text-violet-400',
      label: 'Active Users',
      value: isZeroData ? '0' : '231',
      sub: isZeroData ? 'No active sessions' : '● No suspicious activity',
      subColor: isZeroData
        ? 'text-slate-400 dark:text-slate-500'
        : 'text-emerald-500 dark:text-emerald-400',
      toastTitle: 'User Telemetry',
      toastMsg: isZeroData
        ? '0 concurrent sessions currently connected.'
        : '231 concurrent active sessions. Zero anomalous attempts in 60m.',
    },
    {
      id: 'risk',
      icon: isZeroData ? ShieldCheck : AlertTriangle,
      iconBg: isZeroData
        ? 'bg-emerald-50 dark:bg-emerald-950/60'
        : 'bg-amber-50 dark:bg-amber-950/60',
      iconColor: isZeroData
        ? 'text-emerald-600 dark:text-emerald-400'
        : 'text-amber-500 dark:text-amber-400',
      label: 'Risk Score',
      value: isZeroData ? '0' : '68',
      valueSuffix: '/100',
      sub: isZeroData ? 'Zero Risk (Clean)' : 'Medium Risk',
      subColor: isZeroData
        ? 'text-emerald-700 dark:text-emerald-300'
        : 'text-amber-700 dark:text-amber-300',
      subBg: isZeroData
        ? 'bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800'
        : 'bg-amber-50 dark:bg-amber-950/60 border border-amber-200 dark:border-amber-800',
      toastTitle: isZeroData ? 'Risk Index: 0/100 (Clean)' : 'Risk Index: 68/100',
      toastMsg: isZeroData
        ? 'Calculated CVSS score is 0. No exploit vectors detected.'
        : 'Score calculated via CVSS 3.1 base metrics, exploit ease, and exposure.',
    },
  ]

  const handleCardClick = (s: typeof stats[0]) => {
    toast('info', s.toastTitle, s.toastMsg)
    onSelectMetric?.(s.id)
  }

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
      {stats.map((s) => {
        const Icon = s.icon
        return (
          <button
            key={s.label}
            onClick={() => handleCardClick(s)}
            className="stat-card h-full flex flex-col justify-between group text-left cursor-pointer transition-all duration-200 hover:-translate-y-0.5"
            title={`Click for ${s.label} breakdown`}
          >
            <div>
              <div className="flex items-start justify-between mb-2.5">
                <div className={`p-2 rounded-lg ${s.iconBg} transition-transform group-hover:scale-110`}>
                  <Icon size={18} className={s.iconColor} />
                </div>
                <ArrowRight size={14} className="text-slate-300 dark:text-slate-600 group-hover:text-indigo-600 dark:group-hover:text-indigo-400 group-hover:translate-x-0.5 transition-all mt-0.5" />
              </div>
              <p className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1">{s.label}</p>
              <div className="flex items-baseline gap-1">
                <span className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">{s.value}</span>
                {s.valueSuffix && (
                  <span className="text-xs font-medium text-slate-400 dark:text-slate-500">{s.valueSuffix}</span>
                )}
              </div>
            </div>

            <div className="mt-3 pt-2.5 border-t border-slate-100 dark:border-slate-800/80">
              {s.subBg ? (
                <span className={`inline-block text-[11px] font-semibold px-2 py-0.5 rounded ${s.subBg} ${s.subColor}`}>
                  {s.sub}
                </span>
              ) : (
                <p className={`text-[11px] font-medium ${s.subColor}`}>{s.sub}</p>
              )}
            </div>
          </button>
        )
      })}
    </div>
  )
}
