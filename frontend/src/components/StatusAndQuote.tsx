'use client'

import { ArrowRight, BarChart2 } from 'lucide-react'
import { useAppSelector } from '../store'

interface StatusAndQuoteProps {
  onRunNewCheck?: () => void
}

export default function StatusAndQuote({ onRunNewCheck }: StatusAndQuoteProps) {
  const findings = useAppSelector((st) => st.findings.items)
  const count = (sev: string) => findings.filter((f) => (f.severity || '').toUpperCase() === sev).length
  const crit = count('CRITICAL')
  const high = count('HIGH')
  const headline = findings.length === 0 ? 'No findings yet' : crit > 0 ? `${crit} critical issue${crit > 1 ? 's' : ''}` : high > 0 ? `${high} high-severity issue${high > 1 ? 's' : ''}` : `${findings.length} open candidate${findings.length > 1 ? 's' : ''}`
  const sub = findings.length === 0 ? 'Run the assessment pipeline in the Admin panel.' : 'Unverified candidates - review them in the Admin panel.'
  const ringColor = crit > 0 ? '#ef4444' : findings.length > 0 ? '#f59e0b' : '#10b981'

  const summary = useAppSelector((st) => st.summary.data)
  const handleRun = () => onRunNewCheck?.()

  return (
    <div className="space-y-4 flex flex-col justify-between">
      {/* ─── Status Ring Card ─── */}
      <div className="rounded-2xl border border-slate-200/90 dark:border-slate-800 bg-white dark:bg-[#0c1322] shadow-sm p-5 text-center flex flex-col items-center justify-center transition-all">
        {/* Glowing Ring SVG */}
        <div className="relative w-20 h-20 flex items-center justify-center mb-3">
          <svg className="w-full h-full transform -rotate-90" viewBox="0 0 80 80">
            <circle
              cx="40"
              cy="40"
              r="30"
              fill="transparent"
              stroke="currentColor"
              strokeWidth="5"
              className="text-slate-100 dark:text-slate-800"
            />
            <circle
              cx="40"
              cy="40"
              r="30"
              fill="transparent"
              stroke={ringColor}
              strokeWidth="5"
              strokeDasharray="188.4"
              strokeDashoffset="28"
              strokeLinecap="round"
              className="filter drop-shadow-[0_0_8px_rgba(16,185,129,0.5)]"
            />
          </svg>
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="w-3 h-3 rounded-full bg-emerald-500 animate-pulse" />
          </div>
        </div>

        <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
          {headline}
        </h3>
        <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
          {sub}
        </p>

        <button
          onClick={handleRun}
          className="mt-4 w-full py-2 px-3 rounded-xl bg-teal-500 hover:bg-teal-600 text-white text-xs font-semibold flex items-center justify-center gap-1.5 transition-all shadow-sm cursor-pointer"
        >
          <span>Run assessment</span>
          <ArrowRight size={13} />
        </button>
      </div>

      {/* ─── Coverage Card (real numbers from stored runs) ─── */}
      <div className="rounded-2xl border border-slate-200/90 dark:border-slate-800 bg-white dark:bg-[#0c1322] shadow-sm p-5 flex flex-col justify-between">
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-bold text-slate-800 dark:text-slate-100">Assessment coverage</span>
          <BarChart2 size={16} className="text-teal-500" />
        </div>
        {summary ? (
          <dl className="space-y-2 text-xs">
            <div className="flex justify-between" title={summary.risk.formula}>
              <dt className="text-slate-500 dark:text-slate-400">Risk score</dt>
              <dd className="font-semibold text-slate-800 dark:text-slate-100">{summary.risk.score}/100 ({summary.risk.level})</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-slate-500 dark:text-slate-400">Endpoints with results</dt>
              <dd className="font-semibold text-slate-800 dark:text-slate-100">{summary.endpoints_tested}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-slate-500 dark:text-slate-400">Scanners run</dt>
              <dd className="font-semibold text-slate-800 dark:text-slate-100">{summary.coverage.tools_run.length}/{summary.coverage.tools_expected.length}</dd>
            </div>
            {summary.coverage.tools_missing.length > 0 && (
              <p className="text-[11px] text-amber-600 dark:text-amber-400">Not run: {summary.coverage.tools_missing.join(', ')}</p>
            )}
          </dl>
        ) : (
          <p className="text-xs text-slate-400">Backend unreachable. Start it with: make server</p>
        )}
      </div>
    </div>
  )
}
