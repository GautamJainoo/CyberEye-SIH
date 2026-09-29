import { useState, useEffect } from 'react'
import { HelpCircle, ChevronRight, Gauge, MousePointerClick, Layers } from 'lucide-react'
import { coreWebVitalsData as defaultVitals } from '../data'
import { useToast } from './Toast'
import { fetchDevToolsPerformance } from '../services/api'
import { CoreWebVitalMetric } from '../types'

interface CoreWebVitalsProps {
  onViewAll?: () => void
}

export default function CoreWebVitals({ onViewAll }: CoreWebVitalsProps) {
  const { toast } = useToast()
  const [vitals, setVitals] = useState<CoreWebVitalMetric[]>(defaultVitals)

  useEffect(() => {
    let isMounted = true
    const loadVitals = async () => {
      try {
        const perf = await fetchDevToolsPerformance()
        if (isMounted && perf && perf.metrics) {
          const lcpVal = perf.metrics.lcp.value
          const inpVal = perf.metrics.inp.value
          const clsVal = perf.metrics.cls.value

          setVitals([
            {
              key: 'lcp',
              title: 'LCP',
              fullTitle: 'Largest Contentful Paint',
              value: `${lcpVal} s`,
              status: lcpVal <= 2.5 ? 'Good' : lcpVal <= 4.0 ? 'Needs Improvement' : 'Poor',
              statusColor: lcpVal <= 2.5 ? 'text-emerald-500 dark:text-emerald-400' : 'text-amber-500',
              thresholds: ['0s', '2.5s', '4.0s'],
              currentPercent: Math.min(100, Math.round((lcpVal / 4.0) * 100)),
              description: 'Measures loading performance. For a good user experience, LCP should occur within 2.5 seconds.',
            },
            {
              key: 'inp',
              title: 'INP',
              fullTitle: 'Interaction to Next Paint',
              value: `${inpVal} ms`,
              status: inpVal <= 200 ? 'Good' : inpVal <= 500 ? 'Needs Improvement' : 'Poor',
              statusColor: inpVal <= 200 ? 'text-emerald-500 dark:text-emerald-400' : 'text-amber-500',
              thresholds: ['0ms', '200ms', '500ms'],
              currentPercent: Math.min(100, Math.round((inpVal / 500) * 100)),
              description: 'Measures responsiveness. An INP below 200 milliseconds indicates good responsiveness.',
            },
            {
              key: 'cls',
              title: 'CLS',
              fullTitle: 'Cumulative Layout Shift',
              value: `${clsVal}`,
              status: clsVal <= 0.1 ? 'Good' : clsVal <= 0.25 ? 'Needs Improvement' : 'Poor',
              statusColor: clsVal <= 0.1 ? 'text-emerald-500 dark:text-emerald-400' : 'text-amber-500',
              thresholds: ['0', '0.1', '0.25'],
              currentPercent: Math.min(100, Math.round((clsVal / 0.25) * 100)),
              description: 'Measures visual stability. For a good user experience, pages should maintain a CLS of 0.1. or less.',
            },
          ])
        }
      } catch {
        // Fallback
      }
    }
    loadVitals()
    return () => { isMounted = false }
  }, [])

  const handleCardClick = (title: string, desc: string) => {
    toast('info', `${title} Metric Guide`, desc)
  }

  const icons = {
    lcp: Gauge,
    inp: MousePointerClick,
    cls: Layers,
  }

  return (
    <div className="rounded-2xl border border-slate-200/90 dark:border-slate-800 bg-white dark:bg-[#0c1322] shadow-sm p-5 flex flex-col justify-between transition-all duration-200">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-teal-500 animate-pulse" />
          <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
            Core Web Vitals
          </h2>
        </div>
        <button
          onClick={onViewAll}
          className="text-xs font-medium text-slate-400 hover:text-teal-600 dark:hover:text-teal-400 flex items-center gap-1 transition-colors cursor-pointer"
        >
          <span>View all</span>
          <ChevronRight size={13} />
        </button>
      </div>

      {/* 3 Metric Sub-Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
        {vitals.map((m) => {
          const Icon = icons[m.key as keyof typeof icons] || Gauge
          return (
            <div
              key={m.key}
              onClick={() => handleCardClick(m.title, m.description)}
              className="p-3.5 rounded-xl border border-slate-100 dark:border-slate-800/80 bg-slate-50/70 dark:bg-slate-900/60 hover:border-teal-300 dark:hover:border-teal-700/60 transition-all duration-200 cursor-pointer flex flex-col justify-between group"
            >
              {/* Top: Icon + Title & Tooltip */}
              <div>
                <div className="flex items-center gap-2">
                  <div className="w-7 h-7 rounded-lg bg-teal-500/15 text-teal-600 dark:text-teal-400 flex items-center justify-center shrink-0 group-hover:scale-105 transition-transform">
                    <Icon size={14} />
                  </div>
                  <div className="flex items-center gap-1">
                    <span className="text-xs font-bold text-slate-800 dark:text-slate-100">
                      {m.title}
                    </span>
                    <span
                      title={m.description}
                      className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-help"
                    >
                      <HelpCircle size={11} />
                    </span>
                  </div>
                </div>

                <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1 font-medium truncate">
                  {m.fullTitle}
                </p>

                {/* Score Value + Good Badge */}
                <div className="mt-3 flex items-baseline justify-between">
                  <span className="text-2xl font-extrabold tracking-tight text-slate-900 dark:text-white">
                    {m.value}
                  </span>
                  <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/25">
                    {m.status}
                  </span>
                </div>
              </div>

              {/* Threshold Progress Bar */}
              <div className="mt-3 pt-2 border-t border-slate-200/60 dark:border-slate-800/80">
                <div className="w-full bg-slate-200 dark:bg-slate-800 h-1.5 rounded-full overflow-hidden relative">
                  <div
                    className="bg-gradient-to-r from-teal-400 to-emerald-500 h-full rounded-full transition-all duration-700"
                    style={{ width: `${m.currentPercent}%` }}
                  />
                </div>
                <div className="flex justify-between text-[9px] text-slate-400 font-mono mt-1">
                  <span>{m.thresholds[0]}</span>
                  <span>{m.thresholds[1]}</span>
                  <span>{m.thresholds[2]}</span>
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
