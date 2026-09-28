import { Code2, FileText, Globe, ChevronRight, Wrench } from 'lucide-react'
import { recommendedFixesData } from '../data'
import { useToast } from './Toast'

interface RecommendedFixesCardProps {
  onSelectFix?: (fixId: string) => void
}

export default function RecommendedFixesCard({ onSelectFix }: RecommendedFixesCardProps) {
  const { toast } = useToast()

  const iconMap = {
    code: { icon: Code2, bg: 'bg-rose-500/15 text-rose-600 dark:text-rose-400' },
    doc: { icon: FileText, bg: 'bg-amber-500/15 text-amber-600 dark:text-amber-400' },
    globe: { icon: Globe, bg: 'bg-sky-500/15 text-sky-600 dark:text-sky-400' },
  }

  const priorityStyles = {
    High: 'bg-rose-500/15 text-rose-600 dark:text-rose-400 border-rose-500/25',
    Medium: 'bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/25',
    Low: 'bg-sky-500/15 text-sky-600 dark:text-sky-400 border-sky-500/25',
  }

  const handleClickFix = (title: string, benefit: string, id: string) => {
    toast('info', `Optimization: ${title}`, `${benefit}. Automated patch recipe generated.`)
    onSelectFix?.(id)
  }

  return (
    <div className="rounded-2xl border border-slate-200/90 dark:border-slate-800 bg-white dark:bg-[#0c1322] shadow-sm p-5 flex flex-col justify-between transition-all duration-200">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Wrench size={15} className="text-teal-600 dark:text-teal-400" />
          <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
            Recommended Fixes
          </h2>
          <ChevronRight size={14} className="text-slate-400" />
        </div>
        <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-sky-500/15 text-sky-700 dark:text-sky-300 border border-sky-500/30">
          3 suggestions
        </span>
      </div>

      {/* Fixes List */}
      <div className="space-y-2.5">
        {recommendedFixesData.map((item) => {
          const { icon: Icon, bg } = iconMap[item.iconType]
          return (
            <div
              key={item.id}
              onClick={() => handleClickFix(item.title, item.benefit, item.id)}
              className="flex items-center justify-between p-3 rounded-xl border border-slate-100 dark:border-slate-800/80 bg-slate-50/70 dark:bg-slate-900/60 hover:bg-slate-100/80 dark:hover:bg-slate-850 hover:border-slate-300 dark:hover:border-slate-700 transition-all cursor-pointer group"
            >
              <div className="flex items-center gap-3 min-w-0">
                <div
                  className={`w-9 h-9 rounded-xl ${bg} flex items-center justify-center shrink-0 group-hover:scale-105 transition-transform`}
                >
                  <Icon size={17} />
                </div>
                <div className="min-w-0">
                  <p className="text-xs sm:text-sm font-semibold text-slate-800 dark:text-slate-100 truncate group-hover:text-teal-600 dark:group-hover:text-teal-400 transition-colors">
                    {item.title}
                  </p>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400 truncate">
                    {item.description}
                  </p>
                </div>
              </div>

              {/* Right side: Priority pill, savings, and chevron */}
              <div className="flex items-center gap-3 shrink-0 ml-2">
                <span
                  className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${
                    priorityStyles[item.priority]
                  }`}
                >
                  {item.priority}
                </span>

                <div className="text-right hidden sm:block">
                  <p className="text-[11px] font-medium text-slate-700 dark:text-slate-300">
                    {item.benefit}
                  </p>
                </div>

                <ChevronRight
                  size={14}
                  className="text-slate-400 group-hover:text-teal-500 group-hover:translate-x-0.5 transition-all"
                />
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
