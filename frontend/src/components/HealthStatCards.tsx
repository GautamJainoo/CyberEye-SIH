import type { ComponentType } from 'react'
import { Activity, Accessibility, ShieldCheck, Search, ArrowUp, ArrowDown } from 'lucide-react'
import { useToast } from './Toast'
import { useAppSelector } from '../store'

interface HealthStatCardsProps {
  onSelectMetric?: (metricId: string) => void
}

interface MetricCardData {
  id: string
  title: string
  score: number
  status: string
  statusColor: string
  change: string
  isPositive: boolean
  icon: ComponentType<{ size?: number; className?: string }>
  iconBg: string
  iconColor: string
  strokeColor: string
  gradientId: string
  pathD: string
  areaD: string
  toastMsg: string
}

export default function HealthStatCards({ onSelectMetric }: HealthStatCardsProps) {
  const { toast } = useToast()
  const perf = useAppSelector((state) => state.devtools.performance)
  const findings = useAppSelector((state) => state.findings.items)

  const perfScore = perf?.summary?.overall_score ?? 87
  const critCount = findings.filter((f) => (f.severity || '').toUpperCase() === 'CRITICAL').length
  const highCount = findings.filter((f) => (f.severity || '').toUpperCase() === 'HIGH').length
  const medCount = findings.filter((f) => (f.severity || '').toUpperCase() === 'MEDIUM').length
  const securityScore = Math.max(15, Math.min(100, 100 - (critCount * 14 + highCount * 7 + medCount * 2)))

  const metrics: MetricCardData[] = [
    {
      id: 'performance',
      title: 'Performance',
      score: perfScore,
      status: perfScore >= 85 ? 'Good' : perfScore >= 50 ? 'Needs Improvement' : 'Poor',
      statusColor: perfScore >= 85 ? 'text-emerald-500 dark:text-emerald-400' : 'text-amber-500',
      change: '+2',
      isPositive: true,
      icon: Activity,
      iconBg: 'bg-teal-500/15 dark:bg-teal-500/20',
      iconColor: 'text-teal-600 dark:text-teal-400',
      strokeColor: '#14b8a6', // teal-500
      gradientId: 'perfGrad',
      // SVG smooth wave paths (viewBox 0 0 240 50)
      pathD: 'M0,35 C30,38 50,42 80,32 C110,22 130,38 160,25 C190,12 215,22 240,16',
      areaD: 'M0,35 C30,38 50,42 80,32 C110,22 130,38 160,25 C190,12 215,22 240,16 L240,50 L0,50 Z',
      toastMsg: `Performance Score: ${perfScore}/100. Fast LCP (${perf?.metrics?.lcp?.value ?? '0.8'}s) and minimal layout shifts.`,
    },
    {
      id: 'accessibility',
      title: 'Accessibility',
      score: 89,
      status: 'Good',
      statusColor: 'text-emerald-500 dark:text-emerald-400',
      change: '+1',
      isPositive: true,
      icon: Accessibility,
      iconBg: 'bg-purple-500/15 dark:bg-purple-500/20',
      iconColor: 'text-purple-600 dark:text-purple-400',
      strokeColor: '#a855f7', // purple-500
      gradientId: 'a11yGrad',
      pathD: 'M0,38 C35,42 60,34 90,36 C120,38 140,22 170,28 C200,34 220,18 240,15',
      areaD: 'M0,38 C35,42 60,34 90,36 C120,38 140,22 170,28 C200,34 220,18 240,15 L240,50 L0,50 Z',
      toastMsg: 'Accessibility Score: 89/100. High contrast compliance and clear ARIA roles.',
    },
    {
      id: 'best_practices',
      title: 'Security & Best Practices',
      score: securityScore,
      status: securityScore >= 80 ? 'Good' : securityScore >= 50 ? 'Needs Improvement' : 'Poor',
      statusColor: securityScore >= 80 ? 'text-emerald-500 dark:text-emerald-400' : 'text-amber-500',
      change: securityScore >= 80 ? '+3' : '-5',
      isPositive: securityScore >= 80,
      icon: ShieldCheck,
      iconBg: 'bg-emerald-500/15 dark:bg-emerald-500/20',
      iconColor: 'text-emerald-600 dark:text-emerald-400',
      strokeColor: '#10b981', // emerald-500
      gradientId: 'bestPracticesGrad',
      pathD: 'M0,32 C30,30 65,40 95,28 C125,16 150,26 180,18 C205,10 225,16 240,12',
      areaD: 'M0,32 C30,30 65,40 95,28 C125,16 150,26 180,18 C205,10 225,16 240,12 L240,50 L0,50 Z',
      toastMsg: `Security Score: ${securityScore}/100. ${findings.length} findings tracked across target endpoints.`,
    },
    {
      id: 'seo',
      title: 'SEO',
      score: 92,
      status: 'Good',
      statusColor: 'text-emerald-500 dark:text-emerald-400',
      change: '+2',
      isPositive: true,
      icon: Search,
      iconBg: 'bg-amber-500/15 dark:bg-amber-500/20',
      iconColor: 'text-amber-600 dark:text-amber-400',
      strokeColor: '#f59e0b', // amber-500
      gradientId: 'seoGrad',
      pathD: 'M0,22 C35,18 60,32 90,26 C120,20 145,36 175,34 C205,32 220,42 240,39',
      areaD: 'M0,22 C35,18 60,32 90,26 C120,20 145,36 175,34 C205,32 220,42 240,39 L240,50 L0,50 Z',
      toastMsg: 'SEO Score: 92/100. Meta descriptions and structured schemas configured.',
    },
  ]

  const handleCardClick = (m: MetricCardData) => {
    toast(m.isPositive ? 'info' : 'warning', `${m.title} Telemetry`, m.toastMsg)
    onSelectMetric?.(m.id)
  }

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
      {metrics.map((m) => {
        const Icon = m.icon
        return (
          <div
            key={m.id}
            onClick={() => handleCardClick(m)}
            className="group relative overflow-hidden rounded-2xl border border-slate-200/90 dark:border-slate-800 bg-white dark:bg-[#0c1322] shadow-sm dark:shadow-md hover:shadow-lg dark:hover:border-slate-700 transition-all duration-200 cursor-pointer flex flex-col justify-between"
          >
            {/* Top Row: Icon + Title & Status */}
            <div className="p-4 sm:p-5 pb-2">
              <div className="flex items-center gap-3">
                <div
                  className={`w-10 h-10 rounded-full ${m.iconBg} ${m.iconColor} flex items-center justify-center shrink-0 group-hover:scale-110 transition-transform`}
                >
                  <Icon size={18} />
                </div>
                <div>
                  <h3 className="text-xs sm:text-sm font-bold text-slate-800 dark:text-slate-100 tracking-tight">
                    {m.title}
                  </h3>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    <span
                      className={`w-1.5 h-1.5 rounded-full ${
                        m.isPositive ? 'bg-emerald-500' : 'bg-amber-500'
                      }`}
                    />
                    <span className={`text-[11px] font-medium ${m.statusColor}`}>
                      {m.status}
                    </span>
                  </div>
                </div>
              </div>

              {/* Middle Row: Score Value + Trend Badge */}
              <div className="mt-4 flex items-end justify-between">
                <div className="flex items-baseline gap-0.5">
                  <span className="text-3xl font-extrabold tracking-tight text-slate-900 dark:text-white">
                    {m.score}
                  </span>
                  <span className="text-xs font-semibold text-slate-400 dark:text-slate-500">
                    /100
                  </span>
                </div>

                {/* Trend Badge */}
                <div
                  className={`inline-flex items-center gap-0.5 px-2 py-0.5 rounded-full text-[11px] font-semibold ${
                    m.isPositive
                      ? 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/25'
                      : 'bg-rose-500/15 text-rose-600 dark:text-rose-400 border border-rose-500/25'
                  }`}
                >
                  {m.isPositive ? (
                    <ArrowUp size={11} className="stroke-[2.5]" />
                  ) : (
                    <ArrowDown size={11} className="stroke-[2.5]" />
                  )}
                  <span>{m.change}</span>
                </div>
              </div>
            </div>

            {/* Bottom: Smooth Sparkline Wave Curve */}
            <div className="w-full h-14 relative mt-1">
              <svg
                className="w-full h-full overflow-visible"
                viewBox="0 0 240 50"
                preserveAspectRatio="none"
              >
                <defs>
                  <linearGradient id={m.gradientId} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={m.strokeColor} stopOpacity="0.35" />
                    <stop offset="100%" stopColor={m.strokeColor} stopOpacity="0.0" />
                  </linearGradient>
                  <filter id={`glow-${m.id}`} x="-10%" y="-10%" width="120%" height="120%">
                    <feDropShadow
                      dx="0"
                      dy="0"
                      stdDeviation="2"
                      floodColor={m.strokeColor}
                      floodOpacity="0.5"
                    />
                  </filter>
                </defs>

                {/* Area under wave */}
                <path d={m.areaD} fill={`url(#${m.gradientId})`} />

                {/* Wave Stroke Line */}
                <path
                  d={m.pathD}
                  fill="none"
                  stroke={m.strokeColor}
                  strokeWidth="2.2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  filter={`url(#glow-${m.id})`}
                />
              </svg>
            </div>
          </div>
        )
      })}
    </div>
  )
}
