'use client'

import { HelpCircle, ChevronRight, Gauge, MousePointerClick, Layers } from 'lucide-react'
import { useToast } from './Toast'
import { useAppSelector } from '../store'
import { relativeTime } from '../lib/adminApi'

interface CoreWebVitalsProps {
  onViewAll?: () => void
}

interface Vital {
  key: string
  title: string
  fullTitle: string
  value: string
  status: 'Good' | 'Needs improvement' | 'Poor' | 'Not measured'
  percent: number
  thresholds: [string, string, string]
  description: string
  icon: typeof Gauge
}

function rate(v: number | null, good: number, poor: number): Vital['status'] {
  if (v === null) return 'Not measured'
  return v <= good ? 'Good' : v <= poor ? 'Needs improvement' : 'Poor'
}

const badge: Record<Vital['status'], string> = {
  Good: 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/25',
  'Needs improvement': 'bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/25',
  Poor: 'bg-rose-500/15 text-rose-600 dark:text-rose-400 border-rose-500/25',
  'Not measured': 'bg-slate-500/15 text-slate-500 border-slate-500/25',
}
const bar: Record<Vital['status'], string> = {
  Good: 'from-teal-400 to-emerald-500',
  'Needs improvement': 'from-amber-400 to-orange-500',
  Poor: 'from-rose-400 to-red-600',
  'Not measured': 'from-slate-300 to-slate-400',
}

export default function CoreWebVitals({ onViewAll }: CoreWebVitalsProps) {
  const { toast } = useToast()
  const audit = useAppSelector((s) => s.summary.data?.web_audit)
  const m = audit?.metrics

  const lcp = m?.lcp_ms != null ? m.lcp_ms / 1000 : null
  const cls = m?.cls ?? null
  const tbt = m?.tbt_ms ?? null

  const vitals: Vital[] = [
    {
      key: 'lcp', title: 'LCP', fullTitle: 'Largest Contentful Paint', icon: Gauge,
      value: lcp === null ? '--' : `${lcp.toFixed(2)} s`, status: rate(lcp, 2.5, 4.0),
      percent: lcp === null ? 0 : Math.min(100, (lcp / 4.0) * 100), thresholds: ['0s', '2.5s', '4.0s'],
      description: 'Time until the largest element is rendered. Good is 2.5 s or less.',
    },
    {
      key: 'tbt', title: 'TBT', fullTitle: 'Total Blocking Time (lab proxy for INP)', icon: MousePointerClick,
      value: tbt === null ? '--' : `${Math.round(tbt)} ms`, status: rate(tbt, 200, 600),
      percent: tbt === null ? 0 : Math.min(100, (tbt / 600) * 100), thresholds: ['0ms', '200ms', '600ms'],
      description: 'INP is a field metric that needs real user input, so it cannot be measured in a lab. Lighthouse reports Total Blocking Time as the lab proxy for responsiveness.',
    },
    {
      key: 'cls', title: 'CLS', fullTitle: 'Cumulative Layout Shift', icon: Layers,
      value: cls === null ? '--' : cls.toFixed(3), status: rate(cls, 0.1, 0.25),
      percent: cls === null ? 0 : Math.min(100, (cls / 0.25) * 100), thresholds: ['0', '0.1', '0.25'],
      description: 'Visual stability while loading. Good is 0.1 or less.',
    },
  ]

  return (
    <div className="rounded-2xl border border-slate-200/90 dark:border-slate-800 bg-white dark:bg-[#0c1322] shadow-sm p-5 flex flex-col justify-between">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${audit ? 'bg-teal-500' : 'bg-slate-400'}`} />
          <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">Core Web Vitals</h2>
          <span className="text-[11px] text-slate-400">{audit ? `lab, measured ${relativeTime(audit.finished_at)}` : 'run a web audit to measure'}</span>
        </div>
        <button
          onClick={onViewAll}
          className="text-xs font-medium text-slate-400 hover:text-teal-600 dark:hover:text-teal-400 flex items-center gap-1 transition-colors cursor-pointer"
        >
          <span>View all</span>
          <ChevronRight size={13} />
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
        {vitals.map((v) => {
          const Icon = v.icon
          return (
            <div
              key={v.key}
              onClick={() => toast('info', `${v.title}: ${v.fullTitle}`, v.description)}
              className="p-3.5 rounded-xl border border-slate-100 dark:border-slate-800/80 bg-slate-50/70 dark:bg-slate-900/60 hover:border-teal-300 dark:hover:border-teal-700/60 transition-all cursor-pointer flex flex-col justify-between group"
            >
              <div>
                <div className="flex items-center gap-2">
                  <div className="w-7 h-7 rounded-lg bg-teal-500/15 text-teal-600 dark:text-teal-400 flex items-center justify-center shrink-0">
                    <Icon size={14} />
                  </div>
                  <span className="text-xs font-bold text-slate-800 dark:text-slate-100">{v.title}</span>
                  <span title={v.description} className="text-slate-400 cursor-help"><HelpCircle size={11} /></span>
                </div>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1 font-medium truncate">{v.fullTitle}</p>
                <div className="mt-3 flex items-baseline justify-between">
                  <span className="text-2xl font-extrabold tracking-tight text-slate-900 dark:text-white">{v.value}</span>
                  <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold border ${badge[v.status]}`}>{v.status}</span>
                </div>
              </div>
              <div className="mt-3 pt-2 border-t border-slate-200/60 dark:border-slate-800/80">
                <div className="w-full bg-slate-200 dark:bg-slate-800 h-1.5 rounded-full overflow-hidden">
                  <div className={`bg-gradient-to-r ${bar[v.status]} h-full rounded-full transition-all duration-700`} style={{ width: `${v.percent}%` }} />
                </div>
                <div className="flex justify-between text-[9px] text-slate-400 font-mono mt-1">
                  <span>{v.thresholds[0]}</span><span>{v.thresholds[1]}</span><span>{v.thresholds[2]}</span>
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
