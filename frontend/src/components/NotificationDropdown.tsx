'use client'

import { useEffect, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import { Bell, X, Bug, AlertTriangle, Check } from 'lucide-react'
import { useAppSelector } from '../store'
import { relativeTime } from '../lib/adminApi'

interface Props {
  open: boolean
  onClose: () => void
}

// Notifications are computed by the backend from real data: the most severe stored findings and
// any scanner that failed in the latest scan. Nothing here is a canned message.
export default function NotificationDropdown({ open, onClose }: Props) {
  const ref = useRef<HTMLDivElement>(null)
  const router = useRouter()
  const items = useAppSelector((s) => s.summary.data?.notifications ?? [])
  const [read, setRead] = useState<Set<string>>(new Set())

  useEffect(() => {
    if (!open) return
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose()
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open, onClose])

  if (!open) return null

  const unread = items.filter((n) => !read.has(n.id)).length

  const openItem = (id: string, findingId?: string) => {
    setRead((prev) => new Set(prev).add(id))
    onClose()
    if (findingId) router.push(`/findings/${findingId}`)
  }

  return (
    <div ref={ref} className="absolute top-full right-0 mt-2 w-80 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xl z-50 overflow-hidden animate-dropdown-in">
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-100 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/40">
        <div className="flex items-center gap-2">
          <Bell size={14} className="text-slate-600 dark:text-slate-300" />
          <span className="text-xs font-semibold text-slate-800 dark:text-slate-100">Notifications</span>
          {unread > 0 && <span className="text-[10px] font-bold px-1.5 py-0.5 bg-indigo-600 text-white rounded-full">{unread} new</span>}
        </div>
        <button onClick={onClose} className="p-1 rounded text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer" aria-label="Close">
          <X size={13} />
        </button>
      </div>

      <div className="divide-y divide-slate-50 dark:divide-slate-800/80 max-h-72 overflow-y-auto">
        {items.length === 0 && <p className="px-4 py-6 text-center text-xs text-slate-400">Nothing to report. No severe findings or failed scanners.</p>}
        {items.map((n) => {
          const Icon = n.type === 'vuln' ? Bug : AlertTriangle
          const isRead = read.has(n.id)
          return (
            <button
              key={n.id}
              onClick={() => openItem(n.id, n.finding_id)}
              className={`w-full text-left flex items-start gap-3 px-4 py-3 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors cursor-pointer ${isRead ? '' : 'bg-indigo-50/30 dark:bg-indigo-950/20'}`}
            >
              <div className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 mt-0.5 ${n.type === 'vuln' ? 'bg-red-50 dark:bg-red-950/60' : 'bg-amber-50 dark:bg-amber-950/60'}`}>
                <Icon size={13} className={n.type === 'vuln' ? 'text-red-500' : 'text-amber-500'} />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium text-slate-800 dark:text-slate-200 leading-snug">{n.title}</p>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 leading-relaxed">{n.detail}</p>
              </div>
              <span className="text-[10px] text-slate-400 shrink-0 mt-0.5 font-mono">{relativeTime(n.timestamp)}</span>
            </button>
          )
        })}
      </div>

      <div className="px-4 py-2.5 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between bg-slate-50/50 dark:bg-slate-800/40">
        <button
          onClick={() => setRead(new Set(items.map((n) => n.id)))}
          disabled={unread === 0}
          className="text-xs text-indigo-600 dark:text-indigo-400 font-medium disabled:opacity-50 flex items-center gap-1 cursor-pointer"
        >
          <Check size={12} />
          Mark all as read
        </button>
        <span className="text-[10px] text-slate-400">From stored findings</span>
      </div>
    </div>
  )
}
