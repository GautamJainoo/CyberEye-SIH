import { useState } from 'react'
import {
  Globe, Shield, HardDrive,
  CheckCircle2, AlertTriangle, AlertOctagon,
  RefreshCw, Play, Circle, Lock,
  ChevronRight, Database, Cookie, Layers,
  Trash2, ShieldAlert, Cpu
} from 'lucide-react'
import { useToast } from './Toast'

interface ChromeDevToolsSuiteProps {
  targetUrl?: string
  onInspectVuln?: (tag?: string) => void
}

type DevToolTab = 'network' | 'performance' | 'memory' | 'application' | 'security' | 'console'

export default function ChromeDevToolsSuite({
  targetUrl = 'https://worldmonitor.app',
  onInspectVuln,
}: ChromeDevToolsSuiteProps) {
  const { toast } = useToast()
  const [activeTab, setActiveTab] = useState<DevToolTab>('network')

  // Network tab states
  const [networkFilter, setNetworkFilter] = useState('All')
  const [networkSearch, setNetworkSearch] = useState('')
  const [throttling, setThrottling] = useState('No throttling')
  const [disableCache, setDisableCache] = useState(false)
  const [isRecording, setIsRecording] = useState(true)

  // Memory tab states
  const [memoryMode, setMemoryMode] = useState<'heap' | 'timeline' | 'sampling' | 'detached'>('heap')
  const [isSnapshotting, setIsSnapshotting] = useState(false)

  // Application tab states
  const [appTreeSelection, setAppTreeSelection] = useState<'cookies' | 'localstorage' | 'workers'>('cookies')

  // Security tab modal
  const [certModalOpen, setCertModalOpen] = useState(false)

  // Console tab states
  const [consoleInput, setConsoleInput] = useState('')
  const [consoleLogs, setConsoleLogs] = useState<Array<{ type: 'log' | 'warn' | 'error'; text: string; time: string }>>([
    { type: 'log', text: '[WorldMonitor SEC-OPS] Initialized live telemetry observer v2.4', time: '12:52:01' },
    { type: 'warn', text: '[Security Policy] Missing Content-Security-Policy header on /api/search response', time: '12:52:03' },
    { type: 'error', text: '[Vulnerability Probe] Potential SQL injection detected on endpoint /api/search (CVE-2024-22252)', time: '12:52:04' },
    { type: 'warn', text: '[Storage Auditor] Sensitive JWT auth_token detected in localStorage (CWE-922)', time: '12:52:05' },
    { type: 'log', text: '[Performance] Local LCP candidate 0.78s rendered by <img.hero-banner>', time: '12:52:06' },
  ])

  // Network Requests Dataset matching Amazon & World Monitor Inspect screenshots
  const networkRequests = [
    {
      id: 'req-1',
      name: 'worldmonitor.app',
      status: 200,
      type: 'Doc',
      initiator: 'other',
      size: '85.2 kB',
      time: 38,
      waterfallPct: 15,
      offsetPct: 0,
      isVuln: false,
    },
    {
      id: 'req-2',
      name: '/api/search?q=\' OR 1=1--',
      status: 200,
      type: 'Fetch/XHR',
      initiator: 'index:142',
      size: '12.4 kB',
      time: 85,
      waterfallPct: 35,
      offsetPct: 18,
      isVuln: true,
      vulnTag: 'SQLi CVE-2024-22252',
    },
    {
      id: 'req-3',
      name: '/api/users/1',
      status: 200,
      type: 'Fetch/XHR',
      initiator: 'users.js:68',
      size: '8.2 kB',
      time: 92,
      waterfallPct: 38,
      offsetPct: 25,
      isVuln: true,
      vulnTag: 'IDOR CWE-639',
    },
    {
      id: 'req-4',
      name: 'index-C69G0sdD.css',
      status: 200,
      type: 'CSS',
      initiator: '(index):18',
      size: '68.1 kB',
      time: 14,
      waterfallPct: 8,
      offsetPct: 10,
      isVuln: false,
    },
    {
      id: 'req-5',
      name: 'index-ClX8h1ji.js',
      status: 200,
      type: 'JS',
      initiator: '(index):24',
      size: '385 kB',
      time: 42,
      waterfallPct: 22,
      offsetPct: 12,
      isVuln: false,
    },
    {
      id: 'req-6',
      name: 'hero.png',
      status: 200,
      type: 'Img',
      initiator: 'style.css:44',
      size: '145 kB',
      time: 22,
      waterfallPct: 12,
      offsetPct: 20,
      isVuln: false,
    },
    {
      id: 'req-7',
      name: 'favicon.svg',
      status: 200,
      type: 'Img',
      initiator: '(index):8',
      size: '(disk cache)',
      time: 1,
      waterfallPct: 2,
      offsetPct: 8,
      isVuln: false,
    },
    {
      id: 'req-8',
      name: '/api/auth/reset',
      status: 200,
      type: 'Fetch/XHR',
      initiator: 'auth.js:210',
      size: '4.1 kB',
      time: 68,
      waterfallPct: 28,
      offsetPct: 30,
      isVuln: true,
      vulnTag: 'Missing Rate Limit',
    },
    {
      id: 'req-9',
      name: 'wss://worldmonitor.app/telemetry',
      status: 101,
      type: 'WS',
      initiator: 'pubsub:88',
      size: '1.2 kB',
      time: 5,
      waterfallPct: 90,
      offsetPct: 5,
      isVuln: false,
    },
  ]

  // Filter requests
  const filteredRequests = networkRequests.filter((r) => {
    if (networkFilter !== 'All' && r.type !== networkFilter) return false
    if (networkSearch && !r.name.toLowerCase().includes(networkSearch.toLowerCase())) return false
    return true
  })

  const handleTakeSnapshot = () => {
    setIsSnapshotting(true)
    toast('info', 'Taking Heap Snapshot', 'Capturing JS heap allocation profile across VM instances...')
    setTimeout(() => {
      setIsSnapshotting(false)
      toast('success', 'Heap Snapshot 1 Captured', 'Total heap size: 110.4 MB | 42,890 JS objects mapped.')
    }, 1200)
  }

  const handleConsoleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!consoleInput.trim()) return
    const input = consoleInput.trim()
    setConsoleLogs((prev) => [
      ...prev,
      { type: 'log', text: `> ${input}`, time: new Date().toLocaleTimeString() },
      { type: 'log', text: `< 'Evaluated successfully in isolated sandbox'`, time: new Date().toLocaleTimeString() },
    ])
    setConsoleInput('')
  }

  return (
    <div className="card overflow-hidden border border-slate-300 dark:border-slate-800 bg-[#f8fafc] dark:bg-[#0e1626] font-sans shadow-xl">
      {/* ─── Chrome DevTools Top Tab Bar ─── */}
      <div className="bg-[#e2e8f0] dark:bg-[#0a1120] border-b border-slate-300 dark:border-slate-800 flex items-center justify-between px-2 text-xs select-none">
        <div className="flex items-center overflow-x-auto scrollbar-none">
          {[
            { id: 'network', label: 'Network' },
            { id: 'performance', label: 'Performance' },
            { id: 'memory', label: 'Memory' },
            { id: 'application', label: 'Application' },
            { id: 'security', label: 'Security' },
            { id: 'console', label: 'Console' },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as DevToolTab)}
              className={`px-3.5 py-2 font-medium border-b-2 transition-colors cursor-pointer whitespace-nowrap text-xs ${
                activeTab === tab.id
                  ? 'border-sky-500 text-sky-600 dark:text-sky-400 bg-white dark:bg-[#0e1626] font-bold'
                  : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-200/60 dark:hover:bg-slate-800/60'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Right DevTools Status (Error/Warn badges like Chrome) */}
        <div className="flex items-center gap-2 px-2 shrink-0">
          <span className="flex items-center gap-1 text-[11px] font-semibold text-rose-600 dark:text-rose-400 bg-rose-50 dark:bg-rose-950/60 px-1.5 py-0.5 rounded border border-rose-200 dark:border-rose-900">
            <AlertOctagon size={11} /> 2
          </span>
          <span className="flex items-center gap-1 text-[11px] font-semibold text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/60 px-1.5 py-0.5 rounded border border-amber-200 dark:border-amber-900">
            <AlertTriangle size={11} /> 3
          </span>
          <span className="text-[11px] font-mono text-slate-400">DevTools 128.0</span>
        </div>
      </div>

      {/* ─── TAB 1: NETWORK ─── */}
      {activeTab === 'network' && (
        <div className="flex flex-col">
          {/* Sub-toolbar */}
          <div className="p-2 bg-slate-100 dark:bg-[#0b1322] border-b border-slate-200 dark:border-slate-800 flex items-center justify-between flex-wrap gap-2 text-xs">
            <div className="flex items-center gap-2 flex-wrap">
              <button
                onClick={() => setIsRecording(!isRecording)}
                className={`p-1 rounded cursor-pointer ${
                  isRecording ? 'text-rose-500' : 'text-slate-400'
                }`}
                title={isRecording ? 'Stop recording network log' : 'Record network log'}
              >
                <Circle size={13} className={isRecording ? 'fill-current' : ''} />
              </button>
              <button
                onClick={() => toast('info', 'Network Log Cleared', 'All network requests flushed.')}
                className="p-1 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer"
                title="Clear network log"
              >
                <Trash2 size={13} />
              </button>

              <div className="h-4 w-px bg-slate-300 dark:bg-slate-700" />

              {/* Filter search */}
              <input
                type="text"
                placeholder="Filter (e.g. api, js, css)"
                value={networkSearch}
                onChange={(e) => setNetworkSearch(e.target.value)}
                className="px-2 py-0.5 text-xs rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-100 placeholder-slate-400 w-36 sm:w-48"
              />

              {/* Invert & Disable cache */}
              <label className="flex items-center gap-1 text-[11px] text-slate-600 dark:text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={disableCache}
                  onChange={(e) => setDisableCache(e.target.checked)}
                  className="rounded text-sky-500"
                />
                <span>Disable cache</span>
              </label>

              {/* Throttling Dropdown */}
              <select
                value={throttling}
                onChange={(e) => {
                  setThrottling(e.target.value)
                  toast('info', 'Network Throttling', `Simulating profile: ${e.target.value}`)
                }}
                className="px-2 py-0.5 text-xs rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-200"
              >
                <option value="No throttling">No throttling</option>
                <option value="Fast 4G">Fast 4G (1.5 MB/s, 40ms)</option>
                <option value="Slow 3G">Slow 3G (400 kB/s, 400ms)</option>
                <option value="Offline">Offline</option>
              </select>
            </div>

            {/* Filter Chips */}
            <div className="flex items-center gap-1 overflow-x-auto text-[11px]">
              {['All', 'Fetch/XHR', 'Doc', 'CSS', 'JS', 'Img', 'WS'].map((f) => (
                <button
                  key={f}
                  onClick={() => setNetworkFilter(f)}
                  className={`px-2 py-0.5 rounded transition-colors cursor-pointer ${
                    networkFilter === f
                      ? 'bg-sky-500 text-white font-semibold'
                      : 'text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-800'
                  }`}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>

          {/* Waterfall Timeline Ruler Bar */}
          <div className="bg-slate-50 dark:bg-[#0a0f1d] border-b border-slate-200 dark:border-slate-800 px-4 py-1.5 flex justify-between font-mono text-[10px] text-slate-400">
            <span>0 ms</span>
            <span>400 ms</span>
            <span>800 ms</span>
            <span>1,200 ms</span>
            <span>1,600 ms</span>
            <span>2,000 ms</span>
            <span>2,400 ms</span>
          </div>

          {/* Requests Table */}
          <div className="overflow-x-auto max-h-[380px] overflow-y-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-100/70 dark:bg-slate-900/60 font-mono text-[10px] text-slate-500 dark:text-slate-400 uppercase">
                  <th className="py-2 px-3">Name</th>
                  <th className="py-2 px-2">Status</th>
                  <th className="py-2 px-2">Type</th>
                  <th className="py-2 px-2">Initiator</th>
                  <th className="py-2 px-2">Size</th>
                  <th className="py-2 px-2">Time</th>
                  <th className="py-2 px-3 w-48">Waterfall</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80 font-mono text-[11px]">
                {filteredRequests.map((req) => (
                  <tr
                    key={req.id}
                    onClick={() => {
                      if (req.isVuln) {
                        toast('warning', `Vulnerability Alert: ${req.vulnTag}`, `Exploitation payload detected on ${req.name}`)
                        onInspectVuln?.(req.vulnTag)
                      } else {
                        toast('info', `Network Request`, `${req.name} | ${req.size} | ${req.time}ms`)
                      }
                    }}
                    className={`hover:bg-sky-50/50 dark:hover:bg-slate-800/40 cursor-pointer transition-colors ${
                      req.isVuln ? 'bg-rose-500/5' : ''
                    }`}
                  >
                    <td className="py-2 px-3 font-semibold text-slate-800 dark:text-slate-200 flex items-center gap-1.5 truncate max-w-xs">
                      {req.isVuln && <ShieldAlert size={12} className="text-rose-500 shrink-0" />}
                      <span className="truncate">{req.name}</span>
                    </td>
                    <td className="py-2 px-2">
                      <span className={`font-semibold ${req.status === 200 ? 'text-emerald-600 dark:text-emerald-400' : 'text-sky-500'}`}>
                        {req.status}
                      </span>
                    </td>
                    <td className="py-2 px-2 text-slate-500 dark:text-slate-400">{req.type}</td>
                    <td className="py-2 px-2 text-sky-600 dark:text-sky-400 underline truncate max-w-[100px]">
                      {req.initiator}
                    </td>
                    <td className="py-2 px-2 text-slate-600 dark:text-slate-300">{req.size}</td>
                    <td className="py-2 px-2 text-slate-600 dark:text-slate-300">{req.time} ms</td>
                    <td className="py-2 px-3">
                      <div className="w-full bg-slate-200 dark:bg-slate-800 h-2 rounded-full overflow-hidden relative">
                        <div
                          className={`h-full rounded-full ${
                            req.isVuln ? 'bg-rose-500' : 'bg-teal-500'
                          }`}
                          style={{
                            marginLeft: `${req.offsetPct}%`,
                            width: `${req.waterfallPct}%`,
                          }}
                        />
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

            {/* Bottom Status Bar matching Image 1 */}
            <div className="px-4 py-2 bg-slate-100 dark:bg-[#0a0f1d] border-t border-slate-200 dark:border-slate-800 text-[11px] font-mono text-slate-500 dark:text-slate-400 flex items-center justify-between flex-wrap gap-2">
            <div>
              <span>122 requests</span> • <span>4.5 MB transferred</span> • <span>11.4 MB resources</span>
            </div>
            <div>
              <span>Finish: 2.19 s</span> • <span className="text-sky-600 dark:text-sky-400">DOMContentLoaded: 1.19 s</span> • <span className="text-rose-500">Load: 1.71 s</span>
            </div>
          </div>
        </div>
      )}

      {/* ─── TAB 2: PERFORMANCE (Matching Image 2) ─── */}
      {activeTab === 'performance' && (
        <div className="p-5 space-y-6">
          {/* Top Performance Settings Bar */}
          <div className="flex items-center justify-between pb-4 border-b border-slate-200 dark:border-slate-800 text-xs">
            <div className="flex items-center gap-3">
              <button
                onClick={() => toast('info', 'Performance Profiling', 'Recording timeline flamegraph...')}
                className="btn-primary text-xs flex items-center gap-1.5 bg-teal-600 hover:bg-teal-700"
              >
                <Play size={12} className="fill-current" />
                <span>Record</span>
              </button>
              <button
                onClick={() => toast('info', 'Reload & Record', 'Capturing full page load performance...')}
                className="btn-secondary text-xs flex items-center gap-1.5"
              >
                <RefreshCw size={12} />
                <span>Reload</span>
              </button>
            </div>

            <div className="flex items-center gap-3 text-slate-500 text-xs">
              <label className="flex items-center gap-1 cursor-pointer">
                <input type="checkbox" defaultChecked className="rounded text-sky-500" />
                <span>Screenshots</span>
              </label>
              <label className="flex items-center gap-1 cursor-pointer">
                <input type="checkbox" defaultChecked className="rounded text-sky-500" />
                <span>Memory</span>
              </label>
            </div>
          </div>

          {/* Local Web Vitals Metrics (Directly matching Image 2 screenshot!) */}
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">
              Local Metrics
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* LCP Card */}
              <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0b1322] shadow-sm">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                    Largest Contentful Paint (LCP)
                  </span>
                  <span className="text-slate-400">?</span>
                </div>
                <div className="mt-2 flex items-baseline gap-2">
                  <span className="text-3xl font-extrabold text-emerald-600 dark:text-emerald-400">
                    0.78 s
                  </span>
                </div>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
                  Your local LCP value of <strong className="text-emerald-500">0.78 s</strong> is good.
                </p>
                <p className="text-[10px] font-mono text-sky-600 dark:text-sky-400 mt-2 bg-sky-50 dark:bg-sky-950/40 p-1.5 rounded border border-sky-200 dark:border-sky-900/50 truncate">
                  LCP element: img.a-worldmonitor-hero-image
                </p>
              </div>

              {/* CLS Card */}
              <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0b1322] shadow-sm">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                    Cumulative Layout Shift (CLS)
                  </span>
                  <span className="text-slate-400">?</span>
                </div>
                <div className="mt-2 flex items-baseline gap-2">
                  <span className="text-3xl font-extrabold text-emerald-600 dark:text-emerald-400">
                    0
                  </span>
                </div>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
                  Your local CLS value of <strong className="text-emerald-500">0</strong> is good.
                </p>
                <p className="text-[10px] font-mono text-slate-400 mt-2 p-1.5 rounded bg-slate-100 dark:bg-slate-800">
                  Zero unexpected shift clusters
                </p>
              </div>

              {/* INP Card */}
              <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0b1322] shadow-sm">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                    Interaction to Next Paint (INP)
                  </span>
                  <span className="text-slate-400">?</span>
                </div>
                <div className="mt-2 flex items-baseline gap-2">
                  <span className="text-3xl font-extrabold text-emerald-600 dark:text-emerald-400">
                    45 ms
                  </span>
                </div>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
                  Input response latency is optimal under 200ms.
                </p>
                <p className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 mt-2 p-1.5 rounded bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-900/50">
                  Pointerdown &amp; keypress verified
                </p>
              </div>
            </div>
          </div>

          {/* Performance Flamechart / Activity breakdown */}
          <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0b1322]">
            <h4 className="text-xs font-bold text-slate-800 dark:text-slate-200 mb-2">
              Performance Activity Breakdown (1,210 ms total)
            </h4>
            <div className="w-full h-4 rounded-full overflow-hidden flex font-mono text-[9px] text-white font-bold">
              <div style={{ width: '7%' }} className="bg-sky-500 flex items-center justify-center" title="Loading 85ms">
                Load
              </div>
              <div style={{ width: '26%' }} className="bg-amber-500 flex items-center justify-center" title="Scripting 320ms">
                Script
              </div>
              <div style={{ width: '10%' }} className="bg-purple-500 flex items-center justify-center" title="Rendering 110ms">
                Render
              </div>
              <div style={{ width: '4%' }} className="bg-emerald-500 flex items-center justify-center" title="Painting 45ms">
                Paint
              </div>
              <div style={{ width: '53%' }} className="bg-slate-400 flex items-center justify-center" title="Idle 650ms">
                Idle
              </div>
            </div>
            <div className="flex gap-4 text-[11px] text-slate-500 mt-3 flex-wrap">
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-sky-500" /> Loading: 85 ms
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500" /> Scripting: 320 ms
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-purple-500" /> Rendering: 110 ms
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" /> Painting: 45 ms
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-slate-400" /> Idle: 650 ms
              </span>
            </div>
          </div>
        </div>
      )}

      {/* ─── TAB 3: MEMORY (Matching Image 3) ─── */}
      {activeTab === 'memory' && (
        <div className="p-5 space-y-5">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">
              Select Profiling Type
            </h3>
            <div className="space-y-2.5">
              {[
                {
                  id: 'heap',
                  title: 'Heap snapshot',
                  desc: 'See the memory distribution of JavaScript objects and related DOM nodes.',
                },
                {
                  id: 'timeline',
                  title: 'Allocations on timeline',
                  desc: 'Record memory allocations over time and isolate memory leaks by selecting intervals.',
                },
                {
                  id: 'sampling',
                  title: 'Allocation sampling',
                  desc: 'Approximate memory allocations by sampling long operations with minimal overhead.',
                },
                {
                  id: 'detached',
                  title: 'Detached elements',
                  desc: 'Detached elements show objects retained by a JS reference.',
                },
              ].map((item) => (
                <label
                  key={item.id}
                  className={`flex items-start gap-3 p-3 rounded-xl border cursor-pointer transition-all ${
                    memoryMode === item.id
                      ? 'border-sky-500 bg-sky-50/50 dark:bg-sky-950/30'
                      : 'border-slate-200 dark:border-slate-800 hover:bg-slate-100/60 dark:hover:bg-slate-800/40'
                  }`}
                >
                  <input
                    type="radio"
                    name="memoryMode"
                    checked={memoryMode === item.id}
                    onChange={() => setMemoryMode(item.id as typeof memoryMode)}
                    className="mt-0.5 text-sky-500"
                  />
                  <div>
                    <p className="text-xs font-bold text-slate-800 dark:text-slate-200">{item.title}</p>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400">{item.desc}</p>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* Select JavaScript VM instance (Directly matching Image 3) */}
          <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0b1322]">
            <h4 className="text-xs font-bold text-slate-700 dark:text-slate-300 mb-2">
              Select JavaScript VM Instance
            </h4>
            <div className="space-y-1.5 font-mono text-xs">
              <div className="flex items-center justify-between p-2 rounded bg-sky-50 dark:bg-sky-950/40 border border-sky-200 dark:border-sky-900/50">
                <span className="font-bold text-slate-800 dark:text-slate-200">Main Instance</span>
                <span className="font-semibold text-rose-500">63.5 MB (↑ 1.5 MB/s)</span>
              </div>
              <div className="pl-4 space-y-1 text-slate-500 dark:text-slate-400 text-[11px]">
                <div className="flex justify-between py-0.5">
                  <span>background.js</span>
                  <span>3.4 MB</span>
                </div>
                <div className="flex justify-between py-0.5">
                  <span>www.worldmonitor.app: warmup.html</span>
                  <span>26.1 MB</span>
                </div>
                <div className="flex justify-between py-0.5">
                  <span>service-worker.js</span>
                  <span>4.4 MB</span>
                </div>
                <div className="flex justify-between py-0.5">
                  <span>telemetry-stream: audio-devices.html</span>
                  <span>7.3 MB</span>
                </div>
                <div className="flex justify-between py-0.5 text-emerald-500 font-medium">
                  <span>aax-worldmonitor-metric.com: iu3</span>
                  <span>5.0 MB (↓ 5.2 MB/s)</span>
                </div>
              </div>
            </div>

            <div className="mt-3 pt-3 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between font-mono text-xs">
              <span className="font-bold text-slate-800 dark:text-slate-200">Total JS Heap Size:</span>
              <span className="font-bold text-sky-600 dark:text-sky-400">110 MB (↑ 3.7 MB/s)</span>
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex items-center gap-3">
            <button
              onClick={handleTakeSnapshot}
              disabled={isSnapshotting}
              className="btn-primary text-xs px-4 py-2 bg-sky-600 hover:bg-sky-700"
            >
              {isSnapshotting ? 'Capturing Snapshot...' : 'Take Snapshot'}
            </button>
            <button
              onClick={() => toast('info', 'Memory Profile', 'Loaded previous heap profile.')}
              className="btn-secondary text-xs px-4 py-2"
            >
              Load Profile
            </button>
            <button
              onClick={() => toast('success', 'Garbage Collected', 'Freed 18.2 MB unreferenced objects.')}
              className="btn-secondary text-xs px-3 py-2 text-rose-600 dark:text-rose-400"
              title="Collect Garbage"
            >
              Collect Garbage (GC)
            </button>
          </div>
        </div>
      )}

      {/* ─── TAB 4: APPLICATION & STORAGE (Matching Image 4) ─── */}
      {activeTab === 'application' && (
        <div className="grid grid-cols-1 md:grid-cols-12 min-h-[380px]">
          {/* Left Tree Sidebar (Directly matching Image 4) */}
          <div className="md:col-span-4 p-3 bg-slate-100 dark:bg-[#0a0f1d] border-r border-slate-200 dark:border-slate-800 text-xs font-medium space-y-3">
            <div>
              <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 px-2 py-1">
                Application
              </p>
              <div className="space-y-0.5">
                <button className="w-full text-left px-2 py-1 rounded hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 flex items-center gap-2">
                  <Globe size={13} /> Manifest
                </button>
                <button
                  onClick={() => setAppTreeSelection('workers')}
                  className={`w-full text-left px-2 py-1 rounded flex items-center gap-2 ${
                    appTreeSelection === 'workers'
                      ? 'bg-sky-500 text-white font-bold'
                      : 'hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
                  }`}
                >
                  <Cpu size={13} /> Service workers
                </button>
                <button className="w-full text-left px-2 py-1 rounded hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 flex items-center gap-2">
                  <HardDrive size={13} /> Storage (8.4 MB)
                </button>
              </div>
            </div>

            <div>
              <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 px-2 py-1">
                Storage
              </p>
              <div className="space-y-0.5">
                <button
                  onClick={() => setAppTreeSelection('localstorage')}
                  className={`w-full text-left px-2 py-1 rounded flex items-center justify-between ${
                    appTreeSelection === 'localstorage'
                      ? 'bg-sky-500 text-white font-bold'
                      : 'hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
                  }`}
                >
                  <span className="flex items-center gap-2">
                    <Database size={13} /> Local storage
                  </span>
                  <span className="text-[10px] font-bold text-rose-400 bg-rose-950/60 px-1 rounded">!</span>
                </button>
                <button
                  onClick={() => setAppTreeSelection('cookies')}
                  className={`w-full text-left px-2 py-1 rounded flex items-center justify-between ${
                    appTreeSelection === 'cookies'
                      ? 'bg-sky-500 text-white font-bold'
                      : 'hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
                  }`}
                >
                  <span className="flex items-center gap-2">
                    <Cookie size={13} /> Cookies
                  </span>
                  <span className="text-[10px] text-slate-400">4</span>
                </button>
                <button className="w-full text-left px-2 py-1 rounded hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 flex items-center gap-2">
                  <Layers size={13} /> IndexedDB
                </button>
              </div>
            </div>
          </div>

          {/* Right Viewer Content */}
          <div className="md:col-span-8 p-4 bg-white dark:bg-[#0e1626] overflow-x-auto">
            {appTreeSelection === 'cookies' && (
              <div>
                <div className="flex items-center justify-between mb-3">
                  <h4 className="text-xs font-bold text-slate-800 dark:text-slate-200">
                    Cookies for {targetUrl}
                  </h4>
                  <span className="text-[11px] text-slate-400 font-mono">4 items</span>
                </div>
                <table className="w-full text-left text-xs font-mono border-collapse">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-800 text-[10px] text-slate-400 uppercase">
                      <th className="py-1.5 px-2">Name</th>
                      <th className="py-1.5 px-2">Value</th>
                      <th className="py-1.5 px-2">Domain</th>
                      <th className="py-1.5 px-2">Expires</th>
                      <th className="py-1.5 px-2">HttpOnly</th>
                      <th className="py-1.5 px-2">Secure</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-[11px]">
                    <tr className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                      <td className="py-2 px-2 font-bold text-sky-600 dark:text-sky-400">wm_session</td>
                      <td className="py-2 px-2 text-slate-500 truncate max-w-[120px]">s%3A7a9f82...</td>
                      <td className="py-2 px-2 text-slate-400">.worldmonitor.app</td>
                      <td className="py-2 px-2 text-slate-400">2026-12-31</td>
                      <td className="py-2 px-2 text-emerald-500 font-bold">✓</td>
                      <td className="py-2 px-2 text-emerald-500 font-bold">✓</td>
                    </tr>
                    <tr className="hover:bg-slate-50 dark:hover:bg-slate-800/40 bg-rose-500/5">
                      <td className="py-2 px-2 font-bold text-rose-500">csrf_token</td>
                      <td className="py-2 px-2 text-slate-500 truncate max-w-[120px]">e10adc3949...</td>
                      <td className="py-2 px-2 text-slate-400">.worldmonitor.app</td>
                      <td className="py-2 px-2 text-slate-400">Session</td>
                      <td className="py-2 px-2 text-rose-500 font-bold">✗ (CWE-352)</td>
                      <td className="py-2 px-2 text-emerald-500 font-bold">✓</td>
                    </tr>
                    <tr className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                      <td className="py-2 px-2 font-bold text-slate-700 dark:text-slate-300">wm_theme</td>
                      <td className="py-2 px-2 text-slate-500">dark</td>
                      <td className="py-2 px-2 text-slate-400">worldmonitor.app</td>
                      <td className="py-2 px-2 text-slate-400">2027-01-01</td>
                      <td className="py-2 px-2 text-slate-400">-</td>
                      <td className="py-2 px-2 text-slate-400">-</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            )}

            {appTreeSelection === 'localstorage' && (
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-xs font-bold text-slate-800 dark:text-slate-200">
                    LocalStorage: https://worldmonitor.app
                  </h4>
                  <span className="text-[11px] font-bold text-rose-500 bg-rose-500/10 px-2 py-0.5 rounded border border-rose-500/20">
                    ⚠️ Vulnerability Flagged
                  </span>
                </div>

                <div className="p-3 mb-3 rounded-lg bg-rose-500/10 border border-rose-500/25 text-xs text-rose-700 dark:text-rose-300">
                  <p className="font-bold flex items-center gap-1.5">
                    <ShieldAlert size={14} /> CWE-922: Sensitive JWT Auth Token Written to LocalStorage
                  </p>
                  <p className="text-[11px] mt-0.5 text-slate-600 dark:text-slate-300">
                    Tokens in localStorage can be stolen via XSS. Migrate to HttpOnly, Secure, SameSite=Strict cookies.
                  </p>
                </div>

                <table className="w-full text-left text-xs font-mono border-collapse">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-800 text-[10px] text-slate-400 uppercase">
                      <th className="py-1.5 px-2">Key</th>
                      <th className="py-1.5 px-2">Value</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-[11px]">
                    <tr className="bg-rose-500/10">
                      <td className="py-2 px-2 font-bold text-rose-500">auth_jwt</td>
                      <td className="py-2 px-2 text-rose-600 dark:text-rose-400 break-all select-all">
                        eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDQ0Iiwicm9sZSI6InVzZXIiLCJleHAiOjE3OTIwMDAwMDB9...
                      </td>
                    </tr>
                    <tr>
                      <td className="py-2 px-2 font-bold text-slate-700 dark:text-slate-300">wm-theme</td>
                      <td className="py-2 px-2 text-slate-500">dark</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            )}

            {appTreeSelection === 'workers' && (
              <div className="space-y-3">
                <h4 className="text-xs font-bold text-slate-800 dark:text-slate-200">
                  Active Service Workers
                </h4>
                <div className="p-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/60 font-mono text-xs">
                  <div className="flex items-center gap-2 text-emerald-500 font-bold">
                    <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                    <span>#4921 Activated and running</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1">
                    Origin: https://worldmonitor.app/sw.js
                  </p>
                  <p className="text-[10px] text-slate-500 mt-0.5">
                    Clients: 1 open tab • Push / Sync messaging supported
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ─── TAB 5: SECURITY (Matching Image 5) ─── */}
      {activeTab === 'security' && (
        <div className="grid grid-cols-1 md:grid-cols-12 min-h-[380px]">
          {/* Left Tree (Directly matching Image 5) */}
          <div className="md:col-span-4 p-3 bg-slate-100 dark:bg-[#0a0f1d] border-r border-slate-200 dark:border-slate-800 text-xs font-medium space-y-2">
            <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 px-2">
              Security Overview
            </p>
            <div className="space-y-0.5">
              <button className="w-full text-left px-2 py-1.5 rounded bg-sky-500 text-white font-bold flex items-center gap-2">
                <Lock size={13} /> Overview
              </button>
              <div className="pt-2">
                <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 px-2">
                  Main origin
                </p>
                <div className="px-2 py-1 text-slate-700 dark:text-slate-300 flex items-center gap-1.5 truncate">
                  <Lock size={12} className="text-emerald-500 shrink-0" />
                  <span className="truncate">https://worldmonitor.app</span>
                </div>
              </div>
              <div className="pt-2">
                <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 px-2">
                  Secure origins
                </p>
                <div className="px-2 py-1 text-slate-600 dark:text-slate-400 space-y-1 truncate text-[11px]">
                  <div className="flex items-center gap-1.5 truncate">
                    <Lock size={11} className="text-emerald-500 shrink-0" />
                    <span className="truncate">https://api.worldmonitor.app</span>
                  </div>
                  <div className="flex items-center gap-1.5 truncate">
                    <Lock size={11} className="text-emerald-500 shrink-0" />
                    <span className="truncate">https://cdn.worldmonitor.app</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Right Security Overview Panel (Directly matching Image 5) */}
          <div className="md:col-span-8 p-5 bg-white dark:bg-[#0e1626] space-y-5">
            {/* Status Banner */}
            <div className="pb-3 border-b border-slate-200 dark:border-slate-800">
              <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <CheckCircle2 size={16} className="text-emerald-500" />
                <span>This page is secure (valid HTTPS).</span>
              </h3>
            </div>

            {/* Certificate Section */}
            <div className="flex items-start gap-3">
              <div className="p-1.5 rounded-lg bg-emerald-500/15 text-emerald-500 mt-0.5">
                <Shield size={16} />
              </div>
              <div>
                <p className="text-xs font-bold text-slate-800 dark:text-slate-200">
                  Certificate - <span className="text-emerald-500 font-semibold">valid and trusted</span>
                </p>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 leading-relaxed">
                  The connection to this site is using a valid, trusted server certificate issued by Amazon RSA 2048 M01 / DigiCert.
                </p>
                <button
                  onClick={() => setCertModalOpen(true)}
                  className="mt-2 text-xs font-semibold text-sky-600 dark:text-sky-400 hover:underline cursor-pointer flex items-center gap-1"
                >
                  <span>View certificate</span>
                  <ChevronRight size={13} />
                </button>
              </div>
            </div>

            {/* Connection Section */}
            <div className="flex items-start gap-3">
              <div className="p-1.5 rounded-lg bg-sky-500/15 text-sky-500 mt-0.5">
                <Lock size={16} />
              </div>
              <div>
                <p className="text-xs font-bold text-slate-800 dark:text-slate-200">
                  Connection - <span className="text-emerald-500 font-semibold">secure connection settings</span>
                </p>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 leading-relaxed">
                  The connection to this site is encrypted and authenticated using TLS 1.3, QUIC, X25519MLKEM768, and AES_128_GCM.
                </p>
              </div>
            </div>

            {/* Resources Section */}
            <div className="flex items-start gap-3">
              <div className="p-1.5 rounded-lg bg-teal-500/15 text-teal-500 mt-0.5">
                <Globe size={16} />
              </div>
              <div>
                <p className="text-xs font-bold text-slate-800 dark:text-slate-200">
                  Resources - <span className="text-emerald-500 font-semibold">all served securely</span>
                </p>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                  All 122 resources on this page are served securely over HTTPS. Zero mixed content violations.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ─── TAB 6: CONSOLE ─── */}
      {activeTab === 'console' && (
        <div className="flex flex-col h-[380px] bg-slate-950 font-mono text-xs">
          <div className="flex-1 p-3 overflow-y-auto space-y-1.5 text-slate-300">
            {consoleLogs.map((log, idx) => (
              <div
                key={idx}
                className={`py-0.5 px-2 rounded flex items-start gap-2 ${
                  log.type === 'error'
                    ? 'bg-rose-950/40 text-rose-400 border border-rose-900/40'
                    : log.type === 'warn'
                    ? 'bg-amber-950/40 text-amber-300 border border-amber-900/40'
                    : 'text-slate-300'
                }`}
              >
                <span className="text-slate-500 text-[10px] shrink-0">{log.time}</span>
                <span className="break-all">{log.text}</span>
              </div>
            ))}
          </div>

          {/* Console Command Input */}
          <form onSubmit={handleConsoleSubmit} className="p-2 border-t border-slate-800 flex items-center gap-2">
            <span className="text-sky-400 font-bold">{'>'}</span>
            <input
              type="text"
              value={consoleInput}
              onChange={(e) => setConsoleInput(e.target.value)}
              placeholder="Type JavaScript or security audit expression (e.g., document.cookie, checkSecurityHeaders())..."
              className="flex-1 bg-transparent text-xs text-white placeholder-slate-500 focus:outline-none"
            />
          </form>
        </div>
      )}

      {/* Certificate Details Modal */}
      {certModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-fade-in">
          <div className="card w-full max-w-md p-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800">
              <h3 className="text-sm font-bold text-slate-800 dark:text-slate-100 flex items-center gap-2">
                <Lock size={15} className="text-emerald-500" />
                <span>Certificate Viewer: worldmonitor.app</span>
              </h3>
              <button onClick={() => setCertModalOpen(false)} className="text-slate-400 hover:text-slate-600">
                ✕
              </button>
            </div>
            <div className="py-3 space-y-2 text-xs font-mono">
              <div>
                <span className="text-slate-400">Common Name (CN):</span>
                <p className="font-semibold text-slate-800 dark:text-slate-200">*.worldmonitor.app</p>
              </div>
              <div>
                <span className="text-slate-400">Issuer:</span>
                <p className="font-semibold text-slate-800 dark:text-slate-200">Amazon RSA 2048 M01</p>
              </div>
              <div>
                <span className="text-slate-400">Validity:</span>
                <p className="text-slate-700 dark:text-slate-300">Issued Oct 1, 2025 • Expires Nov 28, 2026</p>
              </div>
              <div>
                <span className="text-slate-400">Public Key:</span>
                <p className="text-slate-700 dark:text-slate-300">RSA 2048 bits (SHA-256 with RSA Encryption)</p>
              </div>
              <div>
                <span className="text-slate-400">Fingerprint (SHA-256):</span>
                <p className="text-[10px] text-slate-500 break-all">
                  E8:5B:34:F1:0C:44:98:71:3F:8A:9D:61:C2:59:7E:11:90:3A:42:0E
                </p>
              </div>
            </div>
            <button
              onClick={() => setCertModalOpen(false)}
              className="mt-3 w-full btn-secondary text-xs py-1.5"
            >
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
