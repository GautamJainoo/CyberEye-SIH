import { useEffect, useRef, useState } from 'react'
import { Bell, X, CheckCircle2, Bug, FileText, AlertTriangle, Check } from 'lucide-react'
import { useToast } from './Toast'

interface NotificationItem {
  id: number
  icon: typeof Bug
  iconBg: string
  iconColor: string
  title: string
  detail: string
  time: string
  unread: boolean
}

const initialNotifications: NotificationItem[] = [
  {
    id: 1,
    icon: Bug,
    iconBg: 'bg-red-50 dark:bg-red-950/60',
    iconColor: 'text-red-500 dark:text-red-400',
    title: 'Critical vulnerability detected',
    detail: 'SQL Injection in /api/search endpoint',
    time: '5 mins ago',
    unread: true,
  },
  {
    id: 2,
    icon: CheckCircle2,
    iconBg: 'bg-emerald-50 dark:bg-emerald-950/60',
    iconColor: 'text-emerald-500 dark:text-emerald-400',
    title: 'Scan completed',
    detail: 'Full perimeter scan finished',
    time: '12 mins ago',
    unread: true,
  },
  {
    id: 3,
    icon: AlertTriangle,
    iconBg: 'bg-amber-50 dark:bg-amber-950/60',
    iconColor: 'text-amber-500 dark:text-amber-400',
    title: 'Risk score changed',
    detail: 'Telemetry updated with latest threat intel',
    time: '1 hr ago',
    unread: false,
  },
  {
    id: 4,
    icon: FileText,
    iconBg: 'bg-blue-50 dark:bg-blue-950/60',
    iconColor: 'text-blue-500 dark:text-blue-400',
    title: 'Report exported',
    detail: 'PDF security compliance summary exported',
    time: '2 hrs ago',
    unread: false,
  },
]

interface Props {
  open: boolean
  onClose: () => void
}

export default function NotificationDropdown({ open, onClose }: Props) {
  const ref = useRef<HTMLDivElement>(null)
  const { toast } = useToast()
  const [items, setItems] = useState<NotificationItem[]>(initialNotifications)

  useEffect(() => {
    if (!open) return
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose()
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open, onClose])

  if (!open) return null

  const unreadCount = items.filter(n => n.unread).length

  const handleMarkAllRead = () => {
    setItems(prev => prev.map(item => ({ ...item, unread: false })))
    toast('success', 'Notifications updated', 'All notifications marked as read')
  }

  const handleItemClick = (n: NotificationItem) => {
    setItems(prev => prev.map(item => item.id === n.id ? { ...item, unread: false } : item))
    toast('info', n.title, n.detail)
    onClose()
  }

  return (
    <div
      ref={ref}
      className="absolute top-full right-0 mt-2 w-80 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xl z-50 overflow-hidden animate-dropdown-in"
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-100 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/40">
        <div className="flex items-center gap-2">
          <Bell size={14} className="text-slate-600 dark:text-slate-300" />
          <span className="text-xs font-semibold text-slate-800 dark:text-slate-100">Notifications</span>
          {unreadCount > 0 && (
            <span className="text-[10px] font-bold px-1.5 py-0.5 bg-indigo-600 text-white rounded-full">
              {unreadCount} new
            </span>
          )}
        </div>
        <button
          onClick={onClose}
          className="p-1 rounded hover:bg-slate-200/60 dark:hover:bg-slate-800 transition-colors text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer"
        >
          <X size={13} />
        </button>
      </div>

      {/* Items */}
      <div className="divide-y divide-slate-50 dark:divide-slate-800/80 max-h-72 overflow-y-auto">
        {items.map(n => {
          const Icon = n.icon
          return (
            <button
              key={n.id}
              onClick={() => handleItemClick(n)}
              className={`w-full text-left flex items-start gap-3 px-4 py-3 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors cursor-pointer ${
                n.unread ? 'bg-indigo-50/30 dark:bg-indigo-950/20' : ''
              }`}
            >
              <div className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 mt-0.5 ${n.iconBg}`}>
                <Icon size={13} className={n.iconColor} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-1.5">
                  <p className="text-xs font-medium text-slate-800 dark:text-slate-200 leading-snug truncate">{n.title}</p>
                  {n.unread && <span className="w-1.5 h-1.5 rounded-full bg-indigo-500 shrink-0" />}
                </div>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 leading-relaxed">{n.detail}</p>
              </div>
              <span className="text-[10px] text-slate-400 dark:text-slate-500 shrink-0 mt-0.5 font-mono">{n.time}</span>
            </button>
          )
        })}
      </div>

      {/* Footer */}
      <div className="px-4 py-2.5 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between bg-slate-50/50 dark:bg-slate-800/40">
        <button
          onClick={handleMarkAllRead}
          disabled={unreadCount === 0}
          className="text-xs text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-300 font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1 cursor-pointer"
        >
          <Check size={12} />
          Mark all as read
        </button>
        <span className="text-[10px] text-slate-400 dark:text-slate-500">Security Feed</span>
      </div>
    </div>
  )
}
