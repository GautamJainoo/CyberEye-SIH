import { ArrowRight, BarChart2 } from 'lucide-react'
import { useToast } from './Toast'

interface StatusAndQuoteProps {
  onRunNewCheck?: () => void
}

export default function StatusAndQuote({ onRunNewCheck }: StatusAndQuoteProps) {
  const { toast } = useToast()

  const handleRun = () => {
    toast('info', 'Refreshing Health & Security Audit', 'Auditing Core Web Vitals, API security & latency.')
    onRunNewCheck?.()
  }

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
              stroke="#10b981"
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
          Everything looks good!
        </h3>
        <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
          No critical issues found.
        </p>

        <button
          onClick={handleRun}
          className="mt-4 w-full py-2 px-3 rounded-xl bg-teal-500 hover:bg-teal-600 text-white text-xs font-semibold flex items-center justify-center gap-1.5 transition-all shadow-sm cursor-pointer"
        >
          <span>Run New Check</span>
          <ArrowRight size={13} />
        </button>
      </div>

      {/* ─── Quote Card ─── */}
      <div className="rounded-2xl border border-slate-200/90 dark:border-slate-800 bg-white dark:bg-[#0c1322] shadow-sm p-5 flex flex-col justify-between relative overflow-hidden">
        <div>
          <span className="text-3xl font-serif text-teal-500/70 leading-none">“</span>
          <p className="text-xs text-slate-600 dark:text-slate-300 font-medium leading-relaxed mt-1">
            Good web performance leads to better user experience and higher conversions.
          </p>
        </div>

        <div className="mt-4 flex items-center justify-between text-slate-400 dark:text-slate-500 pt-2 border-t border-slate-100 dark:border-slate-800/80">
          <span className="text-[10px] font-mono">Lighthouse 11.4</span>
          <BarChart2 size={16} className="text-teal-500" />
        </div>
      </div>
    </div>
  )
}
