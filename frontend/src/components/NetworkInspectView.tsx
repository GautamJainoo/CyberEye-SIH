import { useState } from 'react'
import {
  Activity, Clock, HardDrive, Wifi, ShieldAlert,
  CheckCircle2, AlertTriangle, ExternalLink, RefreshCw
} from 'lucide-react'
import { pageSpeedMetrics, networkInspectSummary } from '../data'
import { PageSpeedMetric } from '../types'
import { useToast } from './Toast'

interface NetworkInspectViewProps {
  targetUrl?: string
  onInspectVuln?: (findingTag?: string) => void
}

export default function NetworkInspectView({
  targetUrl = 'https://worldmonitor.app',
  onInspectVuln,
}: NetworkInspectViewProps) {
  const { toast } = useToast()
  const [filterType, setFilterType] = useState<'All' | 'HTML Page' | 'API Endpoint' | 'Warnings'>('All')
  const [isRefreshing, setIsRefreshing] = useState(false)

  const handleRefresh = () => {
    setIsRefreshing(true)
    toast('info', 'Probing Endpoints', `Measuring TTFB, HTTP/2 latency & bandwidth across ${targetUrl}...`)
    setTimeout(() => {
      setIsRefreshing(false)
      toast('success', 'Telemetry Updated', 'Network speed & inspection matrix updated.')
    }, 1000)
  }

  const filteredMetrics = pageSpeedMetrics.filter((m) => {
    if (filterType === 'HTML Page') return m.type === 'HTML Page'
    if (filterType === 'API Endpoint') return m.type === 'API Endpoint'
    if (filterType === 'Warnings') return m.securityStatus !== 'Secure'
    return true
  })

  const handleRowClick = (metric: PageSpeedMetric) => {
    if (metric.securityStatus === 'Vulnerable') {
      toast('warning', `Vulnerability Alert: ${metric.name}`, `${metric.findingTag} detected on endpoint ${metric.path}. Click to view PoC.`)
      onInspectVuln?.(metric.findingTag)
    } else {
      toast('info', `Endpoint Telemetry: ${metric.name}`, `Path: ${metric.path} | Latency: ${metric.latencyMs}ms | Speed Index: ${metric.speedIndex}`)
    }
  }

  return (
    <div className="space-y-5 animate-fade-in">
      {/* ─── Top Telemetry Cards ─── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {/* Latency */}
        <div className="card p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400">
            <span className="text-xs font-medium">Avg Latency</span>
            <Activity size={16} className="text-teal-500" />
          </div>
          <div className="mt-2 flex items-baseline gap-1.5">
            <span className="text-2xl font-extrabold text-slate-900 dark:text-white">
              {networkInspectSummary.averageLatency}
            </span>
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          </div>
          <p className="text-[10px] text-slate-400 mt-1">DNS: {networkInspectSummary.dnsLookup} • SSL: {networkInspectSummary.sslHandshake}</p>
        </div>

        {/* TTFB */}
        <div className="card p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400">
            <span className="text-xs font-medium">Time to First Byte</span>
            <Clock size={16} className="text-sky-500" />
          </div>
          <div className="mt-2 flex items-baseline gap-1.5">
            <span className="text-2xl font-extrabold text-slate-900 dark:text-white">
              {networkInspectSummary.ttfb}
            </span>
            <span className="text-xs font-semibold text-emerald-500">Fast</span>
          </div>
          <p className="text-[10px] text-slate-400 mt-1">Edge Cache Hit Ratio: 94.2%</p>
        </div>

        {/* Total Transfer Size */}
        <div className="card p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400">
            <span className="text-xs font-medium">Transfer Size</span>
            <HardDrive size={16} className="text-purple-500" />
          </div>
          <div className="mt-2 flex items-baseline gap-1.5">
            <span className="text-2xl font-extrabold text-slate-900 dark:text-white">
              {networkInspectSummary.totalTransferSize}
            </span>
            <span className="text-xs text-slate-400 font-mono">({networkInspectSummary.totalRequests} reqs)</span>
          </div>
          <p className="text-[10px] text-slate-400 mt-1">Uncompressed: {networkInspectSummary.uncompressedSize}</p>
        </div>

        {/* Protocol & SSL */}
        <div className="card p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400">
            <span className="text-xs font-medium">Connection Security</span>
            <Wifi size={16} className="text-emerald-500" />
          </div>
          <div className="mt-2">
            <span className="text-sm font-bold text-slate-900 dark:text-white font-mono">
              {networkInspectSummary.httpProtocol}
            </span>
          </div>
          <p className="text-[10px] text-emerald-600 dark:text-emerald-400 mt-1 font-medium">HTTP/2 Multiplexing Active</p>
        </div>
      </div>

      {/* ─── Per-Page Speed & Inspect Table ─── */}
      <div className="card overflow-hidden">
        {/* Table Toolbar */}
        <div className="p-4 border-b border-slate-100 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight flex items-center gap-2">
              <span>Website Speed &amp; Endpoint Telemetry</span>
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-teal-500/15 text-teal-700 dark:text-teal-300 font-mono">
                {targetUrl}
              </span>
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Live load times, latency diagnostics, and vulnerability markers across all routes
            </p>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {/* Filter buttons */}
            <div className="flex items-center bg-slate-100 dark:bg-slate-800 p-0.5 rounded-lg text-xs">
              {(['All', 'HTML Page', 'API Endpoint', 'Warnings'] as const).map((t) => (
                <button
                  key={t}
                  onClick={() => setFilterType(t)}
                  className={`px-2.5 py-1 rounded-md transition-colors cursor-pointer font-medium ${
                    filterType === t
                      ? 'bg-white dark:bg-slate-700 text-slate-900 dark:text-white shadow-sm'
                      : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>

            <button
              onClick={handleRefresh}
              disabled={isRefreshing}
              className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors cursor-pointer"
              title="Refresh network inspection"
            >
              <RefreshCw size={14} className={isRefreshing ? 'animate-spin' : ''} />
            </button>
          </div>
        </div>

        {/* Table Body */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-100 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-900/50 text-slate-400 dark:text-slate-500 uppercase font-mono text-[10px] tracking-wider">
                <th className="py-3 px-4">Endpoint / Route</th>
                <th className="py-3 px-3">Type</th>
                <th className="py-3 px-3">Speed Index</th>
                <th className="py-3 px-3">Latency</th>
                <th className="py-3 px-3">TTFB</th>
                <th className="py-3 px-3">Transfer</th>
                <th className="py-3 px-3">Status</th>
                <th className="py-3 px-4">Security Assessment</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
              {filteredMetrics.map((row) => (
                <tr
                  key={row.id}
                  onClick={() => handleRowClick(row)}
                  className="hover:bg-slate-50/80 dark:hover:bg-slate-800/40 transition-colors cursor-pointer group"
                >
                  {/* Route & Name */}
                  <td className="py-3 px-4">
                    <div className="font-semibold text-slate-900 dark:text-slate-100 group-hover:text-teal-600 dark:group-hover:text-teal-400 transition-colors">
                      {row.name}
                    </div>
                    <div className="font-mono text-[11px] text-slate-400 mt-0.5 flex items-center gap-1">
                      <span>{row.path}</span>
                      <ExternalLink size={10} className="opacity-0 group-hover:opacity-100 transition-opacity" />
                    </div>
                  </td>

                  {/* Type */}
                  <td className="py-3 px-3">
                    <span className="text-[11px] font-medium text-slate-600 dark:text-slate-400">
                      {row.type}
                    </span>
                  </td>

                  {/* Speed Index */}
                  <td className="py-3 px-3 font-semibold text-slate-800 dark:text-slate-200">
                    {row.speedIndex}
                  </td>

                  {/* Latency with visual bar */}
                  <td className="py-3 px-3">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-medium text-slate-800 dark:text-slate-200">
                        {row.latencyMs} ms
                      </span>
                      <div className="w-12 h-1.5 bg-slate-200 dark:bg-slate-800 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${
                            row.latencyMs < 50
                              ? 'bg-emerald-500'
                              : row.latencyMs < 80
                              ? 'bg-amber-500'
                              : 'bg-rose-500'
                          }`}
                          style={{ width: `${Math.min(100, (row.latencyMs / 100) * 100)}%` }}
                        />
                      </div>
                    </div>
                  </td>

                  {/* TTFB */}
                  <td className="py-3 px-3 font-mono text-slate-500 dark:text-slate-400">
                    {row.ttfbMs} ms
                  </td>

                  {/* Size */}
                  <td className="py-3 px-3 font-mono text-slate-500 dark:text-slate-400">
                    {row.transferSize}
                  </td>

                  {/* HTTP Status Code */}
                  <td className="py-3 px-3">
                    <span className="px-2 py-0.5 rounded font-mono text-[10px] font-bold bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800">
                      {row.statusCode} OK
                    </span>
                  </td>

                  {/* Security Status & Finding Tag */}
                  <td className="py-3 px-4">
                    {row.securityStatus === 'Secure' ? (
                      <span className="inline-flex items-center gap-1 text-[11px] font-medium text-emerald-600 dark:text-emerald-400">
                        <CheckCircle2 size={12} />
                        Clean
                      </span>
                    ) : row.securityStatus === 'Vulnerable' ? (
                      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-500/15 text-rose-600 dark:text-rose-400 border border-rose-500/30">
                        <ShieldAlert size={12} />
                        {row.findingTag}
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/15 text-amber-600 dark:text-amber-400 border border-amber-500/30">
                        <AlertTriangle size={12} />
                        {row.findingTag}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
