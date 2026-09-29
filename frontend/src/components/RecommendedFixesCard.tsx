'use client'

import { ShieldAlert, ChevronRight, Wrench } from 'lucide-react'
import { useToast } from './Toast'
import { useAppSelector } from '../store'
import { useRouter } from 'next/navigation'

interface RecommendedFixesCardProps {
  onSelectFix?: (fixId: string) => void
}

export default function RecommendedFixesCard({ onSelectFix }: RecommendedFixesCardProps) {
  const { toast } = useToast()
  const recommendations = useAppSelector((state) => state.copilot.recommendations)
  const router = useRouter()

  const handleClickFix = (title: string, fix: string, id: string | number, findingId?: string) => {
    toast('info', `Remediation: ${title}`, fix)
    onSelectFix?.(String(id))
    if (findingId) router.push(`/findings/${findingId}`)
  }

  return (
    <div className="rounded-2xl border border-slate-200/90 dark:border-slate-800 bg-white dark:bg-[#0c1322] shadow-sm p-5 flex flex-col justify-between transition-all duration-200">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Wrench size={15} className="text-teal-600 dark:text-teal-400" />
          <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
            Recommended Security Fixes
          </h2>
          <ChevronRight size={14} className="text-slate-400" />
        </div>
        <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-teal-500/15 text-teal-700 dark:text-teal-300 border border-teal-500/30">
          {recommendations.length} recommendations from stored findings
        </span>
      </div>

      {/* Fixes List */}
      <div className="space-y-2.5">
        {recommendations.length === 0 ? (
          <div className="py-8 text-center text-slate-400 text-xs font-mono">
            No findings to remediate yet. Run the assessment first.
          </div>
        ) : (
          recommendations.map((item) => {
            const isCrit = item.priority.toLowerCase().includes('critical')
            const isHigh = item.priority.toLowerCase().includes('high')
            const badgeClass = isCrit
              ? 'bg-rose-500/15 text-rose-600 dark:text-rose-400 border-rose-500/25'
              : isHigh
              ? 'bg-orange-500/15 text-orange-600 dark:text-orange-400 border-orange-500/25'
              : 'bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/25'

            return (
              <div
                key={item.id}
                onClick={() => handleClickFix(item.title, item.fix, item.id, item.finding_id)}
                className="flex items-center justify-between p-3 rounded-xl border border-slate-100 dark:border-slate-800/80 bg-slate-50/70 dark:bg-slate-900/60 hover:bg-slate-100/80 dark:hover:bg-slate-850 hover:border-slate-300 dark:hover:border-slate-700 transition-all cursor-pointer group"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div
                    className={`w-9 h-9 rounded-xl ${item.bg || 'bg-teal-500/15'} flex items-center justify-center shrink-0 group-hover:scale-105 transition-transform`}
                  >
                    <ShieldAlert size={17} className={item.color || 'text-teal-600'} />
                  </div>
                  <div className="min-w-0">
                    <p className="text-xs sm:text-sm font-semibold text-slate-800 dark:text-slate-100 truncate group-hover:text-teal-600 dark:group-hover:text-teal-400 transition-colors">
                      {item.title}
                    </p>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400 truncate">
                      {item.impact}
                    </p>
                  </div>
                </div>

                {/* Right side: Priority pill, fix hint, and chevron */}
                <div className="flex items-center gap-3 shrink-0 ml-2">
                  <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${badgeClass}`}>
                    {item.priority}
                  </span>

                  <div className="text-right hidden sm:block max-w-[200px]">
                    <p className="text-[11px] font-mono text-slate-600 dark:text-slate-400 truncate">
                      {item.fix}
                    </p>
                  </div>

                  <ChevronRight
                    size={14}
                    className="text-slate-400 group-hover:text-teal-500 group-hover:translate-x-0.5 transition-all"
                  />
                </div>
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}
