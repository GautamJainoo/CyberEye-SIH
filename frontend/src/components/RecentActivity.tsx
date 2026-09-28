import { useState } from 'react'
import { recentActivity, zeroRecentActivity } from '../data'
import { CheckCircle2, Bug, FileText, Wrench, ArrowUpRight } from 'lucide-react'
import { useToast } from './Toast'

function ActivityIcon({ type }: { type: string }) {
  switch (type) {
    case 'scan':   return <CheckCircle2 size={13} className="text-emerald-500" />
    case 'vuln':   return <Bug size={13} className="text-red-500" />
    case 'report': return <FileText size={13} className="text-blue-500" />
    case 'fix':    return <Wrench size={13} className="text-violet-500" />
    default:       return <CheckCircle2 size={13} className="text-slate-400" />
  }
}

function iconBg(type: string) {
  switch (type) {
    case 'scan':   return 'bg-emerald-50 dark:bg-emerald-950/60'
    case 'vuln':   return 'bg-red-50 dark:bg-red-950/60'
    case 'report': return 'bg-blue-50 dark:bg-blue-950/60'
    case 'fix':    return 'bg-violet-50 dark:bg-violet-950/60'
    default:       return 'bg-slate-50 dark:bg-slate-800'
  }
}

interface RecentActivityProps {
  isZeroData?: boolean
}

export default function RecentActivity({ isZeroData = false }: RecentActivityProps) {
  const { toast } = useToast()
  const [showAll, setShowAll] = useState(false)

  const activeData = isZeroData ? zeroRecentActivity : recentActivity
  const items = showAll ? activeData : activeData.slice(0, 4)

  const handleItemClick = (item: typeof recentActivity[0]) => {
    toast('info', item.message, `${item.detail || 'Audit entry'} (${item.timeAgo})`)
  }

  const handleViewAll = () => {
    setShowAll(!showAll)
    toast('info', showAll ? 'Filtered Activity' : 'Audit Trail Opened', `Viewing ${activeData.length} recent system events`)
  }

  return (
    <div className="card p-5 flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-800 dark:text-slate-100">Recent Activity</h2>
        {!isZeroData && (
          <button
            onClick={handleViewAll}
            className="flex items-center gap-0.5 text-xs text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-300 font-medium transition-colors cursor-pointer"
          >
            {showAll ? 'Show Less' : 'View All'} <ArrowUpRight size={12} />
          </button>
        )}
      </div>

      <div className="space-y-2.5">
        {items.map(item => (
          <button
            key={item.id}
            onClick={() => handleItemClick(item)}
            className="w-full text-left flex items-start gap-3 p-1.5 -mx-1.5 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-800/60 transition-colors group cursor-pointer"
            title="Click to view audit log details"
          >
            <div className={`mt-0.5 w-6 h-6 rounded-lg flex items-center justify-center shrink-0 ${iconBg(item.type)} transition-transform group-hover:scale-110`}>
              <ActivityIcon type={item.type} />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-medium text-slate-800 dark:text-slate-200 leading-snug group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition-colors">
                {item.message}
              </p>
              {item.detail && (
                <p className="text-[11px] text-slate-400 dark:text-slate-500 mt-0.5 leading-relaxed truncate">{item.detail}</p>
              )}
            </div>
            <span className="text-[10px] text-slate-400 dark:text-slate-500 shrink-0 mt-0.5 font-mono">{item.timeAgo}</span>
          </button>
        ))}
      </div>
    </div>
  )
}
