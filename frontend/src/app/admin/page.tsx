'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import Link from 'next/link'
import { Activity, CheckCircle2, Circle, Loader2, Play, RefreshCw, XCircle, MinusCircle, ImageIcon, Sparkles } from 'lucide-react'
import { adminApi, FindingRow, Overview, PipelineState, sevClass, TOOL_LABEL, TOOL_METHOD, ToolRun } from '../../lib/adminApi'
import ProofLightbox from '../../components/ProofLightbox'
import { API_ORIGIN } from '../../services/api'

type Tab = 'overview' | 'findings' | 'tools' | 'review' | 'audit'
const TABS: { id: Tab; label: string }[] = [
  { id: 'overview', label: 'Overview & pipeline' },
  { id: 'findings', label: 'Findings' },
  { id: 'tools', label: 'Tool runs & methods' },
  { id: 'review', label: 'Code review (Gemini)' },
  { id: 'audit', label: 'Audit log' },
]
const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

function StepIcon({ s }: { s: string }) {
  if (s === 'running') return <Loader2 className="w-4 h-4 animate-spin text-blue-500" />
  if (s === 'done') return <CheckCircle2 className="w-4 h-4 text-green-500" />
  if (s === 'failed') return <XCircle className="w-4 h-4 text-red-500" />
  if (s === 'skipped') return <MinusCircle className="w-4 h-4 text-slate-400" />
  return <Circle className="w-4 h-4 text-slate-400" />
}

function Stat({ label, value, sub }: { label: string; value: React.ReactNode; sub?: string }) {
  return (
    <div className="card p-4">
      <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
      <div className="text-2xl font-semibold mt-1">{value}</div>
      {sub && <div className="text-xs text-slate-500 mt-0.5">{sub}</div>}
    </div>
  )
}

function Bars({ rows }: { rows: { label: string; n: number; cls?: string }[] }) {
  const max = Math.max(1, ...rows.map((r) => r.n))
  return (
    <div className="space-y-1.5">
      {rows.map((r) => (
        <div key={r.label} className="flex items-center gap-2 text-xs">
          <div className="w-32 shrink-0 truncate">{r.label}</div>
          <div className="flex-1 h-3 rounded bg-slate-200 dark:bg-slate-800 overflow-hidden">
            <div className={`h-full ${r.cls || 'bg-blue-500'}`} style={{ width: `${(r.n / max) * 100}%` }} />
          </div>
          <div className="w-8 text-right tabular-nums">{r.n}</div>
        </div>
      ))}
    </div>
  )
}

export default function AdminPage() {
  const [tab, setTab] = useState<Tab>('overview')
  const [ov, setOv] = useState<Overview | null>(null)
  const [pipe, setPipe] = useState<PipelineState | null>(null)
  const [findings, setFindings] = useState<FindingRow[]>([])
  const [err, setErr] = useState('')
  const [fresh, setFresh] = useState(true)
  const [doSetup, setDoSetup] = useState(true)
  const [busy, setBusy] = useState('')
  const [q, setQ] = useState('')
  const [fSev, setFSev] = useState('')
  const [fTool, setFTool] = useState('')
  const [fStatus, setFStatus] = useState('')
  const [raw, setRaw] = useState<{ run: ToolRun; text: string } | null>(null)
  const [notes, setNotes] = useState('')
  const [zoom, setZoom] = useState<{ src: string; title: string; method?: string[] } | null>(null)
  const timer = useRef<ReturnType<typeof setInterval> | null>(null)

  const refresh = useCallback(async () => {
    try {
      const [o, f] = await Promise.all([adminApi.overview(), adminApi.findings()])
      setOv(o); setPipe(o.pipeline); setFindings(f); setErr('')
    } catch (e: any) {
      setErr(`Backend unreachable: ${e.message}. Start it with: make server`)
    }
  }, [])

  useEffect(() => { refresh() }, [refresh])
  useEffect(() => { if (tab === 'review') adminApi.reviewNotes().then(setNotes) }, [tab])

  // Poll while a pipeline run is active
  useEffect(() => {
    if (timer.current) clearInterval(timer.current)
    if (pipe?.running) {
      timer.current = setInterval(async () => {
        try {
          const s = await adminApi.pipelineStatus()
          setPipe(s)
          if (!s.running) refresh()
        } catch { /* keep polling */ }
      }, 2000)
    }
    return () => { if (timer.current) clearInterval(timer.current) }
  }, [pipe?.running, refresh])

  const start = async () => {
    if (fresh && !window.confirm('Start a fresh assessment? This clears existing findings first.')) return
    setBusy('start')
    try { await adminApi.startPipeline(fresh, doSetup); setPipe(await adminApi.pipelineStatus()) }
    catch (e: any) { setErr(e.message) }
    setBusy('')
  }

  const act = async (name: string, fn: () => Promise<unknown>) => {
    setBusy(name)
    try { await fn(); setTimeout(refresh, 4000) } catch (e: any) { setErr(e.message) }
    setBusy('')
  }

  const toolOf = (f: FindingRow) => f.sources?.[0]?.tool_name || 'unknown'
  const filtered = useMemo(() => findings.filter((f) => {
    if (fSev && f.severity?.toUpperCase() !== fSev) return false
    if (fTool && toolOf(f) !== fTool) return false
    if (fStatus && f.status !== fStatus) return false
    if (q) {
      const hay = `${f.title} ${f.file || ''} ${f.endpoint || ''} ${f.package || ''} ${(f.cwe || []).join(' ')}`.toLowerCase()
      if (!hay.includes(q.toLowerCase())) return false
    }
    return true
  }).sort((a, b) => SEVS.indexOf(a.severity?.toUpperCase()) - SEVS.indexOf(b.severity?.toUpperCase())), [findings, q, fSev, fTool, fStatus])

  const sevRows = SEVS.map((s) => ({ label: s, n: ov?.findings_by_severity.find((x) => x.severity?.toUpperCase() === s)?.n || 0,
    cls: { CRITICAL: 'bg-red-600', HIGH: 'bg-orange-500', MEDIUM: 'bg-yellow-500', LOW: 'bg-blue-500', INFO: 'bg-slate-500' }[s] }))
  const toolRows = (ov?.findings_by_tool || []).map((t) => ({ label: TOOL_LABEL[t.tool_name] || t.tool_name, n: t.findings }))

  const showRaw = async (run: ToolRun) => {
    setRaw({ run, text: 'Loading…' })
    setRaw({ run, text: await adminApi.rawOutput(run.run_id) })
  }
  const latestRuns = useMemo(() => {
    const m = new Map<string, ToolRun>()
    ;(ov?.tool_runs || []).forEach((r) => { if (!m.has(r.tool_name)) m.set(r.tool_name, r) })
    return [...m.values()]
  }, [ov])

  return (
    <main className="max-w-7xl mx-auto p-4 md:p-6 space-y-4">
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-xl font-semibold">SecureLens Admin</h1>
          <p className="text-xs text-slate-500">World Monitor security assessment · every finding with where, how and proof</p>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span className={`px-2 py-1 rounded ${ov?.target_healthy ? 'bg-green-500/15 text-green-600' : 'bg-red-500/15 text-red-500'}`}>
            Target {ov?.target_healthy ? 'online' : 'offline'}
          </span>
          <Link href="/" className="px-2 py-1 rounded border border-slate-300 dark:border-slate-700">Dashboard</Link>
          <button onClick={refresh} className="p-1.5 rounded border border-slate-300 dark:border-slate-700" aria-label="Refresh"><RefreshCw className="w-4 h-4" /></button>
        </div>
      </header>

      {err && <div className="card p-3 text-sm text-red-500">{err}</div>}

      <nav className="flex flex-wrap gap-1 border-b border-slate-200 dark:border-slate-800">
        {TABS.map((t) => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`px-3 py-2 text-sm -mb-px border-b-2 ${tab === t.id ? 'border-blue-500 font-semibold' : 'border-transparent text-slate-500'}`}>{t.label}</button>
        ))}
      </nav>

      {tab === 'overview' && ov && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Stat label="Findings" value={ov.findings_total} sub="all CANDIDATE until an analyst verifies" />
            <Stat label="Explained" value={`${ov.findings_analysed}/${ov.findings_total}`} sub="normalized by Groq" />
            <Stat label="Proof images" value={ov.proof_images} />
            <Stat label="Tool runs" value={ov.tool_runs.length} />
          </div>

          <section className="card p-4">
            <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
              <h2 className="font-semibold flex items-center gap-2"><Activity className="w-4 h-4" />Full assessment pipeline</h2>
              <div className="flex flex-wrap items-center gap-3 text-xs">
                <label className="flex items-center gap-1"><input type="checkbox" checked={fresh} onChange={(e) => setFresh(e.target.checked)} />Fresh (clear old findings)</label>
                <label className="flex items-center gap-1"><input type="checkbox" checked={doSetup} onChange={(e) => setDoSetup(e.target.checked)} />Gemini-guided local setup</label>
                <button onClick={start} disabled={pipe?.running || busy === 'start'}
                  className="inline-flex items-center gap-1 px-3 py-1.5 rounded bg-blue-600 text-white disabled:opacity-50"><Play className="w-3.5 h-3.5" />{pipe?.running ? 'Running…' : 'Run all 6 scans'}</button>
              </div>
            </div>
            <ol className="space-y-1.5">
              {(pipe?.steps || []).map((s) => (
                <li key={s.id} className="flex items-start gap-2 text-sm">
                  <StepIcon s={s.status} /><div><span className="font-medium">{s.label}</span>
                    {s.detail && <span className="text-xs text-slate-500"> — {s.detail}</span>}</div>
                </li>
              ))}
              {(!pipe || pipe.steps.length === 0) && <li className="text-sm text-slate-500">No run yet. Press “Run all 6 scans”.</li>}
            </ol>
            {pipe?.setup && (
              <details className="mt-3 text-xs"><summary className="cursor-pointer">Gemini setup plan ({pipe.setup.plan.source}) — guard rejected {pipe.setup.result.rejected_by_guard.length} command(s)</summary>
                <ul className="mt-1 space-y-1">{(pipe.setup.plan.steps || []).map((s, i) => (
                  <li key={i}><code>{s.command}</code> — {s.purpose} <b className={s.allowed ? 'text-green-600' : 'text-red-500'}>{s.allowed ? 'allowed' : 'blocked by guard'}</b></li>
                ))}</ul></details>
            )}
            {pipe && pipe.log.length > 0 && <pre className="mt-3 p-2 rounded bg-slate-950 text-slate-300 text-[11px] max-h-40 overflow-auto">{pipe.log.join('\n')}</pre>}
            <div className="mt-3 flex flex-wrap gap-2 text-xs">
              <button onClick={() => act('enrich', () => adminApi.enrich(true))} disabled={!!busy} className="inline-flex items-center gap-1 px-2 py-1 rounded border border-slate-300 dark:border-slate-700"><Sparkles className="w-3.5 h-3.5" />Re-explain findings (Groq)</button>
              <button onClick={() => act('proof', () => adminApi.buildProofs(true))} disabled={!!busy} className="inline-flex items-center gap-1 px-2 py-1 rounded border border-slate-300 dark:border-slate-700"><ImageIcon className="w-3.5 h-3.5" />Build proof images</button>
            </div>
          </section>

          <div className="grid md:grid-cols-2 gap-4">
            <section className="card p-4"><h3 className="text-sm font-semibold mb-2">By severity</h3><Bars rows={sevRows} /></section>
            <section className="card p-4"><h3 className="text-sm font-semibold mb-2">By tool</h3>{toolRows.length ? <Bars rows={toolRows} /> : <p className="text-sm text-slate-500">No findings yet.</p>}</section>
          </div>
        </div>
      )}

      {tab === 'findings' && (
        <section className="space-y-3">
          <div className="flex flex-wrap gap-2 text-sm">
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search title, file, endpoint, package, CWE…" className="flex-1 min-w-52 px-3 py-1.5 rounded border border-slate-300 dark:border-slate-700 bg-transparent" />
            <select value={fSev} onChange={(e) => setFSev(e.target.value)} className="px-2 py-1.5 rounded border border-slate-300 dark:border-slate-700 bg-transparent"><option value="">All severities</option>{SEVS.map((s) => <option key={s}>{s}</option>)}</select>
            <select value={fTool} onChange={(e) => setFTool(e.target.value)} className="px-2 py-1.5 rounded border border-slate-300 dark:border-slate-700 bg-transparent"><option value="">All tools</option>{Object.keys(TOOL_LABEL).map((t) => <option key={t} value={t}>{TOOL_LABEL[t]}</option>)}</select>
            <select value={fStatus} onChange={(e) => setFStatus(e.target.value)} className="px-2 py-1.5 rounded border border-slate-300 dark:border-slate-700 bg-transparent"><option value="">All statuses</option>{[...new Set(findings.map((f) => f.status))].map((s) => <option key={s}>{s}</option>)}</select>
          </div>
          <div className="text-xs text-slate-500">{filtered.length} of {findings.length} findings</div>
          <div className="card overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-xs uppercase text-slate-500"><tr className="text-left"><th className="p-2">Sev</th><th className="p-2">Finding</th><th className="p-2">Found by</th><th className="p-2">Where</th><th className="p-2">Status</th><th className="p-2">Proof</th></tr></thead>
              <tbody>
                {filtered.map((f) => (
                  <tr key={f.finding_id} className="border-t border-slate-200 dark:border-slate-800 align-top">
                    <td className="p-2"><span className={`px-1.5 py-0.5 rounded text-[11px] font-bold ${sevClass(f.severity)}`}>{f.severity}</span></td>
                    <td className="p-2 max-w-md"><Link href={`/findings/${f.finding_id}`} className="font-medium hover:underline">{f.title}</Link></td>
                    <td className="p-2 text-xs">{TOOL_LABEL[toolOf(f)] || toolOf(f)}</td>
                    <td className="p-2 text-xs font-mono break-all max-w-xs">{f.file ? `${f.file}:${f.line_start ?? ''}` : f.endpoint || (f.package ? `${f.package}@${f.package_version}` : '-')}</td>
                    <td className="p-2 text-xs">{f.status}</td>
                    <td className="p-2">
                      {/* eslint-disable-next-line @next/next/no-img-element */}
                      <img src={`${API_ORIGIN}/api/proof/${f.finding_id}.png`} alt="" loading="lazy" className="h-10 w-16 object-cover object-top rounded border border-slate-700 cursor-zoom-in"
                        onClick={() => setZoom({ src: `${API_ORIGIN}/api/proof/${f.finding_id}.png`, title: f.title, method: TOOL_METHOD[toolOf(f)] })}
                        onError={(e) => ((e.currentTarget.style.display = 'none'))} />
                    </td>
                  </tr>
                ))}
                {filtered.length === 0 && <tr><td colSpan={6} className="p-6 text-center text-slate-500">No findings match. Run the pipeline to scan the target.</td></tr>}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {tab === 'tools' && (
        <section className="grid md:grid-cols-2 gap-4">
          {latestRuns.length === 0 && <p className="text-sm text-slate-500">No tool has run yet.</p>}
          {latestRuns.map((r) => (
            <article key={r.run_id} className="card p-4 space-y-2">
              <div className="flex items-center justify-between"><h3 className="font-semibold">{TOOL_LABEL[r.tool_name] || r.tool_name}</h3>
                <span className={`text-xs px-2 py-0.5 rounded ${r.exit_code === 0 ? 'bg-green-500/15 text-green-600' : 'bg-amber-500/15 text-amber-600'}`}>exit {r.exit_code}</span></div>
              <div className="text-xs text-slate-500">v{r.tool_version} · {r.duration_seconds?.toFixed(1)}s · {(ov?.findings_by_tool.find((t) => t.tool_name === r.tool_name)?.findings) ?? 0} findings</div>
              <div><div className="text-xs font-semibold uppercase tracking-wide text-slate-500">Method</div>
                <ol className="list-decimal ml-5 text-xs space-y-0.5">{(TOOL_METHOD[r.tool_name] || []).map((m, i) => <li key={i}>{m}</li>)}</ol></div>
              <pre className="p-2 rounded bg-slate-100 dark:bg-slate-900 text-[11px] whitespace-pre-wrap break-all">$ {r.command_line}</pre>
              <div className="text-[11px] text-slate-500 break-all">raw sha256 {r.raw_output_sha256}</div>
              <button onClick={() => showRaw(r)} className="text-xs underline">View raw output (redacted)</button>
            </article>
          ))}
        </section>
      )}

      {tab === 'review' && (
        <section className="card p-4"><h2 className="font-semibold mb-2">Gemini code-structure review</h2>
          <pre className="text-xs whitespace-pre-wrap">{notes}</pre></section>
      )}

      {tab === 'audit' && ov && (
        <section className="card overflow-x-auto"><table className="w-full text-sm"><thead className="text-xs uppercase text-slate-500"><tr className="text-left"><th className="p-2">Time</th><th className="p-2">Event</th><th className="p-2">Actor</th></tr></thead>
          <tbody>{ov.audit.map((a, i) => <tr key={i} className="border-t border-slate-200 dark:border-slate-800"><td className="p-2 text-xs">{a.timestamp.slice(0, 19)}</td><td className="p-2">{a.event_type}</td><td className="p-2 text-xs">{a.actor_type}:{a.actor_id}</td></tr>)}</tbody></table></section>
      )}

      {raw && (
        <div className="fixed inset-0 z-50 bg-black/70 p-4 overflow-auto" onClick={() => setRaw(null)}>
          <div className="max-w-5xl mx-auto card p-4" onClick={(e) => e.stopPropagation()}>
            <div className="flex justify-between mb-2"><h3 className="font-semibold text-sm">{TOOL_LABEL[raw.run.tool_name]} raw output</h3><button onClick={() => setRaw(null)}>Close</button></div>
            <pre className="text-[11px] whitespace-pre-wrap break-all max-h-[75vh] overflow-auto">{raw.text}</pre>
          </div>
        </div>
      )}
      {zoom && <ProofLightbox {...zoom} onClose={() => setZoom(null)} />}
    </main>
  )
}
