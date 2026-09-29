'use client'

import { useState, useMemo } from 'react'
import Link from 'next/link'
import { Activity, Clock, HardDrive, Wifi, ShieldAlert, RefreshCw } from 'lucide-react'
import { useAppDispatch, useAppSelector } from '../store'
import { fetchNetworkInspectAsync } from '../store/slices/telemetrySlice'

interface NetworkInspectViewProps {
  targetUrl?: string
  onInspectVuln?: (findingTag?: string) => void
}

type Filter = 'All' | 'API' | 'Flagged' | 'Failed'

// Rows are the requests a real headless-Chrome session made when loading the target (see the DevTools
// panel above). Latency, status and size are measured; nothing is estimated.
export default function NetworkInspectView({ targetUrl = 'http://127.0.0.1:3000' }: NetworkInspectViewProps) {
  const dispatch = useAppDispatch()
  const data = useAppSelector((s) => s.telemetry.networkInspect) as any
  const [filter, setFilter] = useState<Filter>('API')
  const [loading, setLoading] = useState(false)

  const summary = data?.summary
  const rows: any[] = data?.metrics ?? []

  const filtered = useMemo(
    () =>
      rows.filter((r) => {
        if (filter === 'API') return r.type === 'API Endpoint'
        if (filter === 'Flagged') return r.securityStatus === 'Flagged'
        if (filter === 'Failed') return r.httpStatus === null || r.httpStatus >= 400
        return true
      }),
    [rows, filter],
  )

  const refresh = async () => {
    setLoading(true)
    await dispatch(fetchNetworkInspectAsync(targetUrl))
    setLoading(false)
  }

  const cards = [
    { label: 'Average latency', value: summary?.averageLatency ?? '--', icon: Activity },
    { label: 'Server response (TTFB)', value: summary?.ttfb ?? '--', icon: Clock },
    { label: 'Requests', value: summary ? `${summary.totalRequests} (${summary.failedRequests} failed)` : '--', icon: Wifi },
    { label: 'Transferred', value: summary?.totalTransferSize ?? '--', icon: HardDrive },
  ]

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {cards.map((c) => (
          <div key={c.label} className="card p-4">
            <div className="flex items-center justify-between text-slate-500 dark:text-slate-400">
              <span className="text-xs font-medium">{c.label}</span>
              <c.icon size={16} className="text-teal-500" />
            </div>
            <div className="mt-2 text-xl font-extrabold text-slate-900 dark:text-white">{c.value}</div>
            {c.label === 'Requests' && <p className="text-[10px] text-slate-400 mt-1">Protocol: {summary?.httpProtocol ?? '--'}</p>}
          </div>
        ))}
      </div>

      <div className="card overflow-hidden">
        <div className="p-4 flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 dark:border-slate-800">
          <div>
            <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-100">Per-request measurements</h3>
            <p className="text-[11px] text-slate-500">{filtered.length} of {rows.length} requests · target {targetUrl}</p>
          </div>
          <div className="flex items-center gap-1.5 text-xs">
            {(['API', 'Flagged', 'Failed', 'All'] as Filter[]).map((f) => (
              <button key={f} onClick={() => setFilter(f)} className={`px-2.5 py-1 rounded-lg cursor-pointer ${filter === f ? 'bg-teal-500 text-white font-semibold' : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'}`}>{f}</button>
            ))}
            <button onClick={refresh} disabled={loading} className="p-1.5 rounded-lg border border-slate-300 dark:border-slate-700 cursor-pointer" aria-label="Refresh"><RefreshCw size={13} className={loading ? 'animate-spin' : ''} /></button>
          </div>
        </div>

        <div className="overflow-x-auto max-h-[420px] overflow-y-auto">
          <table className="w-full text-left text-xs">
            <thead className="text-[10px] uppercase text-slate-500 bg-slate-50 dark:bg-slate-900/50 sticky top-0">
              <tr><th className="py-2 px-3">Request</th><th className="px-2">Type</th><th className="px-2">Status</th><th className="px-2">Latency</th><th className="px-2">Started at</th><th className="px-2">Size</th><th className="px-2">Finding</th></tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800 font-mono text-[11px]">
              {filtered.slice(0, 200).map((r) => (
                <tr key={r.id} className={r.securityStatus === 'Flagged' ? 'bg-rose-500/5' : ''}>
                  <td className="py-1.5 px-3 max-w-xs truncate" title={r.path}>{r.path}</td>
                  <td className="px-2 text-slate-500">{r.type}</td>
                  <td className={`px-2 font-semibold ${r.httpStatus >= 400 || r.httpStatus === null ? 'text-amber-500' : 'text-emerald-600 dark:text-emerald-400'}`}>{r.httpStatus ?? '--'}</td>
                  <td className="px-2">{r.latencyMs === null ? '--' : `${r.latencyMs} ms`}</td>
                  <td className="px-2">{r.startMs}%</td>
                  <td className="px-2">{r.pageSize ?? '--'}</td>
                  <td className="px-2 font-sans">
                    {r.securityStatus === 'Flagged' ? (
                      <span className="inline-flex items-center gap-1 text-rose-600 dark:text-rose-400">
                        <ShieldAlert size={11} />
                        {r.backendFindingId ? <Link href={`/findings/${r.backendFindingId}`} className="underline">{r.findingTag}</Link> : r.findingTag}
                      </span>
                    ) : ''}
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && <tr><td colSpan={7} className="p-6 text-center text-slate-400 font-sans">{data ? 'No requests match this filter.' : 'No capture loaded. Is the target running?'}</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
