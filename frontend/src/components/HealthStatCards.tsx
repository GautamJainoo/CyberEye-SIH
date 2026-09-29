'use client'

import type { ComponentType } from 'react'
import { Activity, Accessibility, ShieldCheck, Search, ArrowUp, ArrowDown, Loader2, Play, Lock } from 'lucide-react'
import { useAppDispatch, useAppSelector } from '../store'
import { runWebAuditAsync } from '../store/slices/summarySlice'
import { formatDateTime, relativeTime } from '../lib/adminApi'

interface HealthStatCardsProps {
  onSelectMetric?: (metricId: string) => void
}

type Cat = 'performance' | 'accessibility' | 'best_practices' | 'seo'

interface Card {
  id: string
  title: string
  subtitle: string
  score: number | null
  history: (number | null)[]
  icon: ComponentType<{ size?: number; className?: string }>
  iconBg: string
  iconColor: string
  stroke: string
}

function tone(score: number | null) {
  if (score === null) return { label: 'Not measured', text: 'text-slate-400', dot: 'bg-slate-400' }
  if (score >= 90) return { label: 'Good', text: 'text-emerald-500 dark:text-emerald-400', dot: 'bg-emerald-500' }
  if (score >= 50) return { label: 'Needs improvement', text: 'text-amber-500', dot: 'bg-amber-500' }
  return { label: 'Poor', text: 'text-rose-500', dot: 'bg-rose-500' }
}

// Real sparkline: one point per stored audit; needs at least two audits to draw a trend.
function Spark({ values, color }: { values: (number | null)[]; color: string }) {
  const pts = values.filter((v): v is number => v !== null)
  if (pts.length < 2) {
    return <div className="h-14 flex items-end px-5 pb-2 text-[10px] text-slate-400">Run another audit to see a trend</div>
  }
  const w = 240
  const h = 50
  const step = w / (pts.length - 1)
  const path = pts.map((v, i) => `${i === 0 ? 'M' : 'L'}${(i * step).toFixed(1)},${(h - (v / 100) * (h - 6) - 3).toFixed(1)}`).join(' ')
  return (
    <svg className="w-full h-14 overflow-visible" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none">
      <path d={path} fill="none" stroke={color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
      {pts.map((v, i) => (
        <circle key={i} cx={i * step} cy={h - (v / 100) * (h - 6) - 3} r="2.4" fill={color} />
      ))}
    </svg>
  )
}

export default function HealthStatCards({ onSelectMetric }: HealthStatCardsProps) {
  const dispatch = useAppDispatch()
  const summary = useAppSelector((s) => s.summary.data)
  const { auditRunning, auditError } = useAppSelector((s) => s.summary)

  const audit = summary?.web_audit ?? null
  const hist = summary?.web_audit_history ?? []
  const cats = audit?.categories

  const lh = (key: Cat) => ({ score: cats?.[key] ?? null, history: hist.map((h) => h[key]) })

  const cards: Card[] = [
    { id: 'performance', title: 'Performance', subtitle: 'Lighthouse', ...lh('performance'), icon: Activity, iconBg: 'bg-teal-500/15', iconColor: 'text-teal-600 dark:text-teal-400', stroke: '#14b8a6' },
    { id: 'accessibility', title: 'Accessibility', subtitle: 'Lighthouse', ...lh('accessibility'), icon: Accessibility, iconBg: 'bg-purple-500/15', iconColor: 'text-purple-600 dark:text-purple-400', stroke: '#a855f7' },
    { id: 'best_practices', title: 'Best Practices', subtitle: 'Lighthouse', ...lh('best_practices'), icon: ShieldCheck, iconBg: 'bg-emerald-500/15', iconColor: 'text-emerald-600 dark:text-emerald-400', stroke: '#10b981' },
    { id: 'seo', title: 'SEO', subtitle: 'Lighthouse', ...lh('seo'), icon: Search, iconBg: 'bg-amber-500/15', iconColor: 'text-amber-600 dark:text-amber-400', stroke: '#f59e0b' },
    {
      id: 'security', title: 'Security posture', subtitle: summary ? `derived from ${summary.findings.total} findings` : 'derived from findings',
      score: summary ? summary.risk.security_score : null, history: [], icon: Lock, iconBg: 'bg-rose-500/15',
      iconColor: 'text-rose-600 dark:text-rose-400', stroke: '#f43f5e',
    },
  ]

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 dark:text-slate-400">
        <span>
          {audit
            ? `Lighthouse ${audit.lighthouse_version} audit of ${audit.url} · ${formatDateTime(audit.finished_at)} (${relativeTime(audit.finished_at)})`
            : 'No web audit has been run yet. Scores below are measured by Lighthouse - nothing is estimated.'}
        </span>
        <button
          onClick={() => dispatch(runWebAuditAsync())}
          disabled={auditRunning}
          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-60 cursor-pointer"
        >
          {auditRunning ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} />}
          {auditRunning ? 'Auditing (about 30-60s)…' : audit ? 'Re-run web audit' : 'Run web audit'}
        </button>
      </div>
      {auditError && <div className="text-xs text-red-500">Web audit failed: {auditError}</div>}

      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-4">
        {cards.map((m) => {
          const Icon = m.icon
          const t = tone(m.score)
          const series = m.history.filter((v): v is number => v !== null)
          const delta = series.length >= 2 ? series[series.length - 1] - series[series.length - 2] : null
          return (
            <div
              key={m.id}
              onClick={() => onSelectMetric?.(m.id)}
              className="group relative overflow-hidden rounded-2xl border border-slate-200/90 dark:border-slate-800 bg-white dark:bg-[#0c1322] shadow-sm hover:shadow-lg dark:hover:border-slate-700 transition-all cursor-pointer flex flex-col justify-between"
            >
              <div className="p-4 sm:p-5 pb-2">
                <div className="flex items-center gap-3">
                  <div className={`w-10 h-10 rounded-full ${m.iconBg} ${m.iconColor} flex items-center justify-center shrink-0`}>
                    <Icon size={18} />
                  </div>
                  <div className="min-w-0">
                    <h3 className="text-xs sm:text-sm font-bold text-slate-800 dark:text-slate-100 tracking-tight truncate">{m.title}</h3>
                    <div className="flex items-center gap-1.5 mt-0.5">
                      <span className={`w-1.5 h-1.5 rounded-full ${t.dot}`} />
                      <span className={`text-[11px] font-medium ${t.text}`}>{t.label}</span>
                    </div>
                  </div>
                </div>

                <div className="mt-4 flex items-end justify-between">
                  <div className="flex items-baseline gap-0.5">
                    <span className="text-3xl font-extrabold tracking-tight text-slate-900 dark:text-white">{m.score ?? '--'}</span>
                    <span className="text-xs font-semibold text-slate-400 dark:text-slate-500">/100</span>
                  </div>
                  {delta !== null && delta !== 0 && (
                    <div
                      className={`inline-flex items-center gap-0.5 px-2 py-0.5 rounded-full text-[11px] font-semibold border ${
                        delta > 0
                          ? 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/25'
                          : 'bg-rose-500/15 text-rose-600 dark:text-rose-400 border-rose-500/25'
                      }`}
                      title="Change since the previous audit"
                    >
                      {delta > 0 ? <ArrowUp size={11} /> : <ArrowDown size={11} />}
                      <span>{Math.abs(delta)}</span>
                    </div>
                  )}
                </div>
                <p className="mt-1 text-[10px] text-slate-400 truncate">{m.subtitle}</p>
              </div>
              {m.history.length > 0 ? <Spark values={m.history} color={m.stroke} /> : <div className="h-14" />}
            </div>
          )
        })}
      </div>
    </div>
  )
}
