'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { RefreshCw, ShieldAlert, Loader2, Play } from 'lucide-react'
import { useAppDispatch, useAppSelector } from '../store'
import { runWebAuditAsync } from '../store/slices/summarySlice'
import { API_BASE } from '../services/api'
import { formatDateTime, relativeTime } from '../lib/adminApi'
import { DEFAULT_WEBSITE_URL } from '../lib/targets'

interface Req {
  id: string; name: string; path: string; status: number | null; type: string; initiator: string
  size: string | null; time: number | null; waterfallPct: number; offsetPct: number; isVuln: boolean
  vulnTag?: string | null; vulnDesc?: string | null; backendFindingId?: string | null; method: string
  failed?: string | null; protocol?: string | null
}
interface Page {
  captured_at: string; title: string; load_ms: number | null; dcl_ms: number | null; span_ms: number
  request_count: number; transfer_kb: number; failed_count: number
  memory: Record<string, number>
  console_counts: { errors: number; warnings: number }
  captured_from?: string
  note?: string
}
interface Header { name: string; status: 'PASS' | 'WARN' | 'FAIL'; severity: string; value: string | null; recommendation: string; risk: string | null; cwe?: string }
interface Security { origin: string; protocol: string; connection_secure: boolean; http_redirects_to_https: boolean | null; security_headers: Header[]; score: number; overall_status: string; certificate: { tls_error?: string | null } }
interface Storage { cookies: { name: string; domain: string; path: string; httpOnly: boolean; secure: boolean; sameSite: string; status: string }[]; local_storage: { key: string; value: string; isSensitive: boolean; cwe: string | null; description: string }[]; service_workers: { scope: string; script: string; status: string }[] }
interface ConsoleMsg { level: string; text: string }

type Tab = 'network' | 'performance' | 'memory' | 'application' | 'security' | 'console'
const TABS: { id: Tab; label: string }[] = [
  { id: 'network', label: 'Network' }, { id: 'performance', label: 'Performance' }, { id: 'memory', label: 'Memory' },
  { id: 'application', label: 'Application' }, { id: 'security', label: 'Security' }, { id: 'console', label: 'Console' },
]

async function get<T>(path: string, target: string, extra = ''): Promise<T> {
  const res = await fetch(`${API_BASE}${path}?target_url=${encodeURIComponent(target)}${extra}`)
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status} ${(await res.text()).slice(0, 120)}`)
  return res.json()
}

interface Props { targetUrl?: string; onInspectVuln?: (tag?: string) => void }

// Everything below comes from a real headless-Chrome session against the in-scope target (Chrome DevTools
// Protocol) or from the Lighthouse audit. There are no assumed numbers; unavailable values show "--".
export default function ChromeDevToolsSuite({ targetUrl = DEFAULT_WEBSITE_URL, onInspectVuln }: Props) {
  const dispatch = useAppDispatch()
  const { auditRunning, data: summary } = useAppSelector((s) => s.summary)
  const audit = summary?.web_audit ?? null

  const [tab, setTab] = useState<Tab>('network')
  const [reqs, setReqs] = useState<Req[]>([])
  const [page, setPage] = useState<Page | null>(null)
  const [sec, setSec] = useState<Security | null>(null)
  const [store, setStore] = useState<Storage | null>(null)
  const [logs, setLogs] = useState<ConsoleMsg[]>([])
  const [shell, setShell] = useState<{ type: string; text: string }[]>([])
  const [input, setInput] = useState('')
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)
  const [filter, setFilter] = useState('All')
  const [search, setSearch] = useState('')
  const [logLevel, setLogLevel] = useState('all')

  const load = useCallback(async (refresh = false) => {
    setLoading(true)
    setErr('')
    try {
      const net = await get<{ requests: Req[]; page: Page }>('/devtools/network', targetUrl, refresh ? '&refresh=true' : '')
      setReqs(net.requests)
      setPage(net.page)
      const [s, st, c] = await Promise.all([
        get<Security>('/devtools/security', targetUrl),
        get<Storage>('/devtools/storage', targetUrl),
        get<{ messages: ConsoleMsg[] }>('/devtools/console-log', targetUrl),
      ])
      setSec(s); setStore(st); setLogs(c.messages)
    } catch (e: any) {
      setErr(`${e.message}. Is the target running on ${targetUrl}?`)
    }
    setLoading(false)
  }, [targetUrl])

  useEffect(() => { load() }, [load])

  const types = useMemo(() => ['All', ...Array.from(new Set(reqs.map((r) => r.type)))], [reqs])
  const filtered = reqs.filter((r) => (filter === 'All' || r.type === filter) && (!search || r.name.toLowerCase().includes(search.toLowerCase()) || r.path.toLowerCase().includes(search.toLowerCase())))
  const span = Math.max(page?.span_ms ?? 0, 1)
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => Math.round(span * f))

  const runCommand = async (e: React.FormEvent) => {
    e.preventDefault()
    const cmd = input.trim()
    if (!cmd) return
    setInput('')
    setShell((p) => [...p, { type: 'log', text: `> ${cmd}` }])
    try {
      const res = await fetch(`${API_BASE}/devtools/console/exec`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ command: cmd }) })
      const j = await res.json()
      setShell((p) => [...p, { type: j.type, text: j.output }])
    } catch {
      setShell((p) => [...p, { type: 'error', text: 'Backend unreachable' }])
    }
  }

  const m = page?.memory
  const lh = audit?.metrics
  const na = (v: number | null | undefined, suffix = '') => (v === null || v === undefined ? '--' : `${v}${suffix}`)

  return (
    <div className="card overflow-hidden border border-slate-300 dark:border-slate-800 bg-[#f8fafc] dark:bg-[#0e1626] font-sans shadow-xl">
      <div className="bg-[#e2e8f0] dark:bg-[#0a1120] border-b border-slate-300 dark:border-slate-800 flex items-center justify-between px-2 text-xs select-none">
        <div className="flex items-center overflow-x-auto">
          {TABS.map((t) => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={`px-3.5 py-2 font-medium border-b-2 whitespace-nowrap cursor-pointer ${tab === t.id ? 'border-sky-500 text-sky-600 dark:text-sky-400 bg-white dark:bg-[#0e1626] font-bold' : 'border-transparent text-slate-600 dark:text-slate-400 hover:bg-slate-200/60 dark:hover:bg-slate-800/60'}`}>
              {t.label}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2 px-2 shrink-0 text-[11px]">
          <span className="font-semibold text-rose-600 dark:text-rose-400" title="Console errors during the real page load">{page ? page.console_counts.errors : '--'} errors</span>
          <span className="font-semibold text-amber-600 dark:text-amber-400" title="Console warnings during the real page load">{page ? page.console_counts.warnings : '--'} warnings</span>
          <button onClick={() => load(true)} disabled={loading} className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-slate-300 dark:border-slate-700 cursor-pointer disabled:opacity-60" title="Load the page again in headless Chrome and re-capture">
            {loading ? <Loader2 size={11} className="animate-spin" /> : <RefreshCw size={11} />}Re-capture
          </button>
        </div>
      </div>

      {err && <div className="p-3 text-xs text-red-500">{err}</div>}
      {page && <div className="px-4 py-1.5 text-[11px] text-slate-500 border-b border-slate-200 dark:border-slate-800">Captured {relativeTime(page.captured_at)} from {page.captured_from || targetUrl}{page.note ? ` · ${page.note}` : ''} · page title: {page.title || '--'}</div>}

      {tab === 'network' && (
        <div>
          <div className="p-2 bg-slate-100 dark:bg-[#0b1322] border-b border-slate-200 dark:border-slate-800 flex items-center justify-between flex-wrap gap-2 text-xs">
            <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Filter by name or path" className="px-2 py-0.5 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 w-48" />
            <div className="flex items-center gap-1 overflow-x-auto text-[11px]">
              {types.map((f) => (
                <button key={f} onClick={() => setFilter(f)} className={`px-2 py-0.5 rounded cursor-pointer ${filter === f ? 'bg-sky-500 text-white font-semibold' : 'text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-800'}`}>{f}</button>
              ))}
            </div>
          </div>
          <div className="px-4 py-1.5 flex justify-between font-mono text-[10px] text-slate-400 border-b border-slate-200 dark:border-slate-800">
            {ticks.map((t, i) => <span key={i}>{t.toLocaleString()} ms</span>)}
          </div>
          <div className="overflow-x-auto max-h-[380px] overflow-y-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-100/70 dark:bg-slate-900/60 font-mono text-[10px] text-slate-500 uppercase">
                  <th className="py-2 px-3">Name</th><th className="py-2 px-2">Status</th><th className="py-2 px-2">Type</th><th className="py-2 px-2">Initiator</th>
                  <th className="py-2 px-2">Size</th><th className="py-2 px-2">Time</th><th className="py-2 px-3 w-48">Waterfall</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80 font-mono text-[11px]">
                {filtered.map((r) => (
                  <tr key={r.id} onClick={() => r.isVuln && onInspectVuln?.(r.vulnTag ?? undefined)} title={r.vulnDesc ?? r.path}
                    className={`hover:bg-sky-50/50 dark:hover:bg-slate-800/40 ${r.isVuln ? 'bg-rose-500/5 cursor-pointer' : ''}`}>
                    <td className="py-1.5 px-3 font-semibold text-slate-800 dark:text-slate-200 max-w-xs">
                      <span className="flex items-center gap-1.5 truncate">{r.isVuln && <ShieldAlert size={12} className="text-rose-500 shrink-0" />}<span className="truncate">{r.name}</span></span>
                    </td>
                    <td className="py-1.5 px-2"><span className={r.failed ? 'text-rose-500 font-semibold' : (r.status ?? 0) >= 400 ? 'text-amber-500 font-semibold' : 'text-emerald-600 dark:text-emerald-400 font-semibold'}>{r.failed ? 'failed' : r.status ?? '--'}</span></td>
                    <td className="py-1.5 px-2 text-slate-500">{r.type}</td>
                    <td className="py-1.5 px-2 text-sky-600 dark:text-sky-400 truncate max-w-[100px]">{r.initiator}</td>
                    <td className="py-1.5 px-2">{r.size ?? '--'}</td>
                    <td className="py-1.5 px-2">{r.time === null ? '--' : `${r.time} ms`}</td>
                    <td className="py-1.5 px-3">
                      <div className="w-full bg-slate-200 dark:bg-slate-800 h-2 rounded-full overflow-hidden">
                        <div className={`h-full rounded-full ${r.isVuln ? 'bg-rose-500' : 'bg-teal-500'}`} style={{ marginLeft: `${r.offsetPct}%`, width: `${Math.min(r.waterfallPct, 100 - r.offsetPct)}%` }} />
                      </div>
                    </td>
                  </tr>
                ))}
                {filtered.length === 0 && <tr><td colSpan={7} className="p-6 text-center text-slate-400">{loading ? 'Capturing…' : 'No requests captured.'}</td></tr>}
              </tbody>
            </table>
          </div>
          <div className="px-4 py-2 bg-slate-100 dark:bg-[#0a0f1d] border-t border-slate-200 dark:border-slate-800 text-[11px] font-mono text-slate-500 flex items-center justify-between flex-wrap gap-2">
            <span>{page?.request_count ?? '--'} requests • {page ? `${(page.transfer_kb / 1024).toFixed(2)} MB` : '--'} transferred • {page?.failed_count ?? '--'} failed</span>
            <span>DOMContentLoaded: {page?.dcl_ms != null ? `${page.dcl_ms} ms` : '--'} • Load: {page?.load_ms != null ? `${page.load_ms} ms` : '--'} • Last request finished: {page ? `${page.span_ms} ms` : '--'}</span>
          </div>
        </div>
      )}

      {tab === 'performance' && (
        <div className="p-5 space-y-5 text-xs">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <span className="text-slate-500">{audit ? `Lighthouse ${audit.lighthouse_version} · ${formatDateTime(audit.finished_at)}` : 'No Lighthouse audit yet. Run one to measure these values.'}</span>
            <button onClick={() => dispatch(runWebAuditAsync())} disabled={auditRunning} className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded border border-slate-300 dark:border-slate-700 disabled:opacity-60 cursor-pointer">
              {auditRunning ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} />}{auditRunning ? 'Auditing…' : 'Run Lighthouse audit'}
            </button>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              ['DOMContentLoaded', page?.dcl_ms != null ? `${page.dcl_ms} ms` : '--'],
              ['Load', page?.load_ms != null ? `${page.load_ms} ms` : '--'],
              ['Last request', page ? `${page.span_ms} ms` : '--'],
              ['Captured transfer', page ? `${page.transfer_kb.toFixed(1)} kB / ${page.request_count} req` : '--'],
              ['First Contentful Paint', lh?.fcp_ms != null ? `${(lh.fcp_ms / 1000).toFixed(2)} s` : '--'],
              ['Largest Contentful Paint', lh?.lcp_ms != null ? `${(lh.lcp_ms / 1000).toFixed(2)} s` : '--'],
              ['Total Blocking Time', na(lh?.tbt_ms != null ? Math.round(lh.tbt_ms) : null, ' ms')],
              ['Cumulative Layout Shift', lh?.cls != null ? lh.cls.toFixed(3) : '--'],
              ['Speed Index', lh?.speed_index_ms != null ? `${(lh.speed_index_ms / 1000).toFixed(2)} s` : '--'],
              ['Time to Interactive', lh?.tti_ms != null ? `${(lh.tti_ms / 1000).toFixed(2)} s` : '--'],
              ['Server response (TTFB)', na(lh?.ttfb_ms != null ? Math.round(lh.ttfb_ms) : null, ' ms')],
              ['Page weight', audit ? `${(audit.page.transfer_kb / 1024).toFixed(2)} MB / ${audit.page.requests} req` : '--'],
            ].map(([k, v]) => (
              <div key={k} className="rounded-lg border border-slate-200 dark:border-slate-800 p-3"><div className="text-slate-500">{k}</div><div className="text-lg font-bold mt-1">{v}</div></div>
            ))}
          </div>
          {audit && audit.main_thread.length > 0 && (
            <div>
              <div className="font-semibold mb-1.5">Main-thread work (measured)</div>
              {(() => {
                const total = audit.main_thread.reduce((a, b) => a + b.ms, 0) || 1
                const colors = ['bg-sky-500', 'bg-amber-500', 'bg-purple-500', 'bg-emerald-500', 'bg-rose-500', 'bg-slate-400']
                return (
                  <>
                    <div className="flex h-5 rounded overflow-hidden">
                      {audit.main_thread.map((g, i) => <div key={g.group} className={colors[i % colors.length]} style={{ width: `${(g.ms / total) * 100}%` }} title={`${g.label}: ${g.ms} ms`} />)}
                    </div>
                    <div className="flex flex-wrap gap-x-4 gap-y-1 mt-1.5 text-[11px] text-slate-500">
                      {audit.main_thread.map((g, i) => <span key={g.group}><span className={`inline-block w-2 h-2 rounded-sm mr-1 ${colors[i % colors.length]}`} />{g.label} {g.ms} ms</span>)}
                    </div>
                  </>
                )
              })()}
            </div>
          )}
          {audit && audit.issues.filter((i) => i.category === 'performance').length > 0 && (
            <div>
              <div className="font-semibold mb-1.5">Lighthouse performance findings</div>
              <ul className="space-y-1">{audit.issues.filter((i) => i.category === 'performance').slice(0, 8).map((i) => <li key={i.id}><b>{i.title}</b>{i.display ? ` (${i.display})` : ''} <span className="text-slate-500">- {i.description}</span></li>)}</ul>
            </div>
          )}
          <p className="text-[11px] text-slate-400">INP is a field metric that needs real user input, so a lab audit cannot report it; Total Blocking Time is its lab proxy.</p>
        </div>
      )}

      {tab === 'memory' && (
        <div className="p-5 space-y-3 text-xs">
          <p className="text-slate-500">Browser metrics from the captured page session (Chrome DevTools Protocol <code>Performance.getMetrics</code>).</p>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              ['JS heap used', m ? `${m.js_heap_used_mb} MB` : '--'], ['JS heap total', m ? `${m.js_heap_total_mb} MB` : '--'],
              ['DOM nodes', m ? m.dom_nodes.toLocaleString() : '--'], ['Event listeners', m ? m.js_event_listeners.toLocaleString() : '--'],
              ['Documents', m ? String(m.documents) : '--'], ['Frames', m ? String(m.frames) : '--'],
              ['Script time', m ? `${m.script_duration_ms} ms` : '--'], ['Layout / style time', m ? `${m.layout_duration_ms + m.recalc_style_ms} ms (${m.layout_count} layouts)` : '--'],
            ].map(([k, v]) => <div key={k} className="rounded-lg border border-slate-200 dark:border-slate-800 p-3"><div className="text-slate-500">{k}</div><div className="text-lg font-bold mt-1">{v}</div></div>)}
          </div>
        </div>
      )}

      {tab === 'application' && (
        <div className="p-5 space-y-5 text-xs">
          <section>
            <div className="font-semibold mb-1.5">Cookies ({store?.cookies.length ?? 0})</div>
            {store && store.cookies.length === 0 ? <p className="text-slate-500">The page set no cookies during the capture.</p> : (
              <table className="w-full text-left"><thead className="text-[10px] uppercase text-slate-500"><tr><th>Name</th><th>Domain</th><th>HttpOnly</th><th>Secure</th><th>SameSite</th><th>Status</th></tr></thead>
                <tbody className="font-mono">{store?.cookies.map((c) => <tr key={c.name} className="border-t border-slate-100 dark:border-slate-800"><td>{c.name}</td><td>{c.domain}</td><td>{String(c.httpOnly)}</td><td>{String(c.secure)}</td><td>{c.sameSite}</td><td>{c.status}</td></tr>)}</tbody></table>
            )}
          </section>
          <section>
            <div className="font-semibold mb-1.5">Web storage ({store?.local_storage.length ?? 0} entries)</div>
            <table className="w-full text-left"><thead className="text-[10px] uppercase text-slate-500"><tr><th>Key</th><th>Value</th><th>Note</th></tr></thead>
              <tbody className="font-mono">{store?.local_storage.map((e) => <tr key={e.key} className={`border-t border-slate-100 dark:border-slate-800 ${e.isSensitive ? 'bg-rose-500/5' : ''}`}><td className="pr-3">{e.key}</td><td className="pr-3 truncate max-w-[220px]">{e.value}</td><td>{e.isSensitive ? `${e.cwe}: ${e.description}` : ''}</td></tr>)}</tbody></table>
          </section>
          <section>
            <div className="font-semibold mb-1.5">Service workers ({store?.service_workers.length ?? 0})</div>
            {store?.service_workers.length ? store.service_workers.map((w) => <div key={w.scope} className="font-mono">{w.script} <span className="text-slate-500">scope {w.scope} · {w.status}</span></div>) : <p className="text-slate-500">None registered.</p>}
          </section>
        </div>
      )}

      {tab === 'security' && (
        <div className="p-5 space-y-4 text-xs">
          {sec && (
            <>
              <div className="flex flex-wrap gap-x-6 gap-y-1">
                <span>Origin: <b className="font-mono">{sec.origin}</b></span>
                <span>Protocol: <b>{sec.protocol}</b></span>
                <span>Transport: <b>{sec.connection_secure ? 'HTTPS' : 'Plain HTTP (loopback test target, no TLS)'}</b></span>
                <span>Header score: <b>{sec.score}/100</b></span>
              </div>
              <p className="text-slate-500">{sec.overall_status}</p>
              <table className="w-full text-left"><thead className="text-[10px] uppercase text-slate-500"><tr><th>Header</th><th>Result</th><th>Value observed</th><th>Recommendation</th></tr></thead>
                <tbody>{sec.security_headers.map((h) => (
                  <tr key={h.name} className="border-t border-slate-100 dark:border-slate-800 align-top">
                    <td className="py-1.5 pr-3 font-semibold">{h.name}</td>
                    <td className={`pr-3 font-semibold ${h.status === 'PASS' ? 'text-emerald-600' : h.status === 'WARN' ? 'text-amber-500' : 'text-rose-500'}`}>{h.status}</td>
                    <td className="pr-3 font-mono truncate max-w-[220px]">{h.value ?? 'not set'}</td>
                    <td className="text-slate-500">{h.status === 'PASS' ? '' : h.recommendation}</td>
                  </tr>))}</tbody></table>
            </>
          )}
          {!sec && !loading && <p className="text-slate-500">No security data.</p>}
        </div>
      )}

      {tab === 'console' && (
        <div className="p-3 text-xs">
          <div className="flex items-center gap-2 mb-2">
            <span className="font-semibold">Page console ({logs.length})</span>
            {['all', 'error', 'warning', 'log'].map((l) => <button key={l} onClick={() => setLogLevel(l)} className={`px-2 py-0.5 rounded cursor-pointer ${logLevel === l ? 'bg-sky-500 text-white' : 'text-slate-500 hover:bg-slate-200 dark:hover:bg-slate-800'}`}>{l}</button>)}
          </div>
          <div className="bg-slate-950 text-slate-200 font-mono text-[11px] rounded p-2 max-h-72 overflow-auto space-y-0.5">
            {logs.filter((l) => logLevel === 'all' || l.level === logLevel || (logLevel === 'warning' && l.level === 'warn')).map((l, i) => (
              <div key={i} className={l.level === 'error' ? 'text-rose-400' : l.level.startsWith('warn') ? 'text-amber-300' : ''}>[{l.level}] {l.text}</div>
            ))}
            {logs.length === 0 && <div className="text-slate-500">No console output was captured.</div>}
            {shell.map((l, i) => <div key={`s${i}`} className={l.type === 'error' ? 'text-rose-400' : l.type === 'warn' ? 'text-amber-300' : 'text-emerald-300'}>{l.text}</div>)}
          </div>
          <form onSubmit={runCommand} className="mt-2 flex items-center gap-2">
            <span className="text-slate-400">&gt;</span>
            <input value={input} onChange={(e) => setInput(e.target.value)} placeholder="help | status | findings | headers <url> | probe <url>  (loopback only)" className="flex-1 bg-transparent border-b border-slate-300 dark:border-slate-700 focus:outline-none py-1" />
          </form>
        </div>
      )}
    </div>
  )
}
