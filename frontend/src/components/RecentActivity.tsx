import { useState, useMemo } from 'react'
import { CheckCircle2, Bug, FileText, Wrench, ArrowUpRight } from 'lucide-react'
import { useToast } from './Toast'
import { useAppSelector } from '../store'
import { ActivityItem } from '../types'

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

export default function RecentActivity({ isZeroData: propZero }: RecentActivityProps) {
  const { toast } = useToast()
  const [showAll, setShowAll] = useState(false)
  const findingsState = useAppSelector((state) => state.findings)
  const isZeroData = propZero !== undefined ? propZero : findingsState.isZeroData
  const findings = findingsState.items

  const activeData: ActivityItem[] = useMemo(() => {
    if (isZeroData || findings.length === 0) return []

    const items: ActivityItem[] = []
    findings.slice(0, 8).forEach((f, idx) => {
      const minutesAgo = (idx + 1) * 3
      items.push({
        id: idx + 1,
        type: f.severity === 'Critical' || f.severity === 'High' ? 'vuln' : 'scan',
        message: `${f.severity} Alert: ${f.name}`,
        detail: f.component || 'Target route',
        timeAgo: `${minutesAgo}m ago`,
      })
    })

    items.push({
      id: 99,
      type: 'report',
      message: 'Scope verified on loopback (127.0.0.1:3000)',
      detail: 'Security baseline initialized',
      timeAgo: '35m ago',
    })

    return items
  }, [isZeroData, findings])

  const displayedItems = showAll ? activeData : activeData.slice(0, 4)

  const handleItemClick = (item: ActivityItem) => {
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
        {activeData.length > 0 && (
          <button
            onClick={handleViewAll}
            className="flex items-center gap-0.5 text-xs text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-300 font-medium transition-colors cursor-pointer"
          >
            {showAll ? 'Show Less' : 'View All'} <ArrowUpRight size={12} />
          </button>
        )}
      </div>

      <div className="space-y-2.5">
        {activeData.length === 0 ? (
          <div className="py-8 text-center text-slate-400 text-xs font-mono">
            No activity recorded. Target idle.
          </div>
        ) : (
          displayedItems.map((item) => (
            <div
              key={item.id}
              onClick={() => handleItemClick(item)}
              className="flex items-start gap-2.5 p-2 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-800/60 transition-colors cursor-pointer"
            >
              <span className={`p-1.5 rounded-full shrink-0 mt-0.5 ${iconBg(item.type)}`}>
                <ActivityIcon type={item.type} />
              </span>
              <div className="min-w-0 flex-1">
                <p className="text-xs font-medium text-slate-700 dark:text-slate-200 truncate">
                  {item.message}
                </p>
                {item.detail && (
                  <p className="text-[11px] text-slate-400 dark:text-slate-500 truncate">
                    {item.detail}
                  </p>
                )}
              </div>
              <span className="text-[10px] text-slate-400 dark:text-slate-500 whitespace-nowrap shrink-0">
                {item.timeAgo}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
