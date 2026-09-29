'use client'

import { use, useEffect, useState } from 'react'
import Link from 'next/link'
import { ArrowLeft, MapPin, Wrench, ShieldAlert, Bug, ListChecks, Code2, FileSearch, History } from 'lucide-react'
import { adminApi, FindingDetail, sevClass, TOOL_LABEL, TOOL_METHOD } from '../../../lib/adminApi'
import ProofLightbox from '../../../components/ProofLightbox'

function Section({ icon, title, children }: { icon: React.ReactNode; title: string; children: React.ReactNode }) {
  return (
    <section className="card p-4">
      <h2 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-slate-500 mb-2">{icon}{title}</h2>
      <div className="text-sm leading-relaxed">{children}</div>
    </section>
  )
}

export default function FindingPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params)
  const [d, setD] = useState<FindingDetail | null>(null)
  const [err, setErr] = useState('')
  const [zoom, setZoom] = useState(false)

  useEffect(() => {
    adminApi.finding(id).then(setD).catch((e) => setErr(String(e.message || e)))
  }, [id])

  if (err) return <main className="p-6"><Link href="/admin" className="text-sm underline">Back</Link><p className="mt-4 text-red-500">{err}</p></main>
  if (!d) return <main className="p-6 text-sm text-slate-500">Loading finding…</main>

  const f = d.finding
  const tool = d.sources[0]?.tool_name || 'unknown'
  const a = d.analysis
  const method = TOOL_METHOD[tool] || []
  const where = f.file ? `${f.file}:${f.line_start ?? ''}` : f.endpoint ? `${f.method || 'GET'} ${f.endpoint}` : f.package ? `${f.package}@${f.package_version}` : '-'

  return (
    <main className="max-w-6xl mx-auto p-4 md:p-6 space-y-4">
      <Link href="/admin" className="inline-flex items-center gap-1 text-sm text-slate-500 hover:underline"><ArrowLeft className="w-4 h-4" />Admin panel</Link>

      <header className="card p-4">
        <div className="flex flex-wrap items-center gap-2 mb-2">
          <span className={`px-2 py-0.5 rounded text-xs font-bold ${sevClass(f.severity)}`}>{f.severity}</span>
          <span className="text-xs px-2 py-0.5 rounded border border-slate-300 dark:border-slate-700">{f.status}</span>
          <span className="text-xs text-slate-500">{f.category} · {(f.cwe || []).join(', ') || 'no CWE'} · CVSS {f.cvss_score ?? 'n/a'}</span>
        </div>
        <h1 className="text-xl font-semibold">{f.title}</h1>
        {a?.summary && <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">{a.summary}</p>}
        <p className="mt-2 text-xs text-amber-600 dark:text-amber-400">Candidate finding from an automated tool. It only becomes VERIFIED after an analyst attaches evidence.</p>
      </header>

      <div className="grid md:grid-cols-2 gap-4">
        <Section icon={<MapPin className="w-4 h-4" />} title="Where it was found">
          <div className="font-mono text-xs break-all">{where}</div>
          <div className="mt-1 text-xs text-slate-500">Commit {String(f.commit_sha || '').slice(0, 12)} · scope {f.scope_id}</div>
        </Section>
        <Section icon={<Wrench className="w-4 h-4" />} title="How the tool found it">
          <div className="font-medium">{TOOL_LABEL[tool] || tool} {d.sources[0]?.tool_version}</div>
          {a?.how_detected && <p className="mt-1">{a.how_detected}</p>}
          {method.length > 0 && <ol className="list-decimal ml-5 mt-2 text-xs space-y-0.5">{method.map((m, i) => <li key={i}>{m}</li>)}</ol>}
          {d.tool_run && (
            <pre className="mt-2 p-2 rounded bg-slate-100 dark:bg-slate-900 text-[11px] whitespace-pre-wrap break-all">$ {d.tool_run.command_line}{'\n'}exit {d.tool_run.exit_code} · {d.tool_run.duration_seconds?.toFixed(1)}s · sha256 {d.tool_run.raw_output_sha256.slice(0, 16)}…</pre>
          )}
        </Section>
      </div>

      <Section icon={<FileSearch className="w-4 h-4" />} title="Proof (click to enlarge)">
        {d.proof_url ? (
          // eslint-disable-next-line @next/next/no-img-element
          <img src={adminApi.proofSrc(d.proof_url)} alt="Proof evidence card" className="w-full rounded-lg border border-slate-800 cursor-zoom-in" onClick={() => setZoom(true)} />
        ) : (
          <p className="text-slate-500">Proof image not generated yet. Run the pipeline or “Build proof images” in the admin panel.</p>
        )}
      </Section>

      {d.code_context && (
        <Section icon={<Code2 className="w-4 h-4" />} title={`Code · ${d.code_context.file}`}>
          <div className="rounded bg-slate-950 text-slate-200 overflow-x-auto py-2">
            {d.code_context.lines.map((ln, i) => {
              const n = d.code_context!.start + i
              const hl = n >= d.code_context!.highlight_start && n <= d.code_context!.highlight_end
              return (
                <div key={n} className={`flex font-mono text-xs px-3 ${hl ? 'bg-red-500/25 border-l-2 border-red-500' : ''}`}>
                  <span className="w-10 shrink-0 text-slate-500 select-none">{n}</span><span className="whitespace-pre">{ln}</span>
                </div>
              )
            })}
          </div>
        </Section>
      )}

      {a ? (
        <div className="grid md:grid-cols-2 gap-4">
          <Section icon={<Bug className="w-4 h-4" />} title="What is causing it">{a.root_cause}</Section>
          <Section icon={<ShieldAlert className="w-4 h-4" />} title="Impact">{a.impact}</Section>
          <Section icon={<Bug className="w-4 h-4" />} title="How it could be exploited (safe walkthrough)">{a.exploitation_scenario}</Section>
          <Section icon={<ListChecks className="w-4 h-4" />} title="How to fix it">
            <ol className="list-decimal ml-5 space-y-1">{(a.fix_steps || []).map((s, i) => <li key={i}>{s}</li>)}</ol>
            {a.fixed_code && <pre className="mt-2 p-2 rounded bg-slate-100 dark:bg-slate-900 text-xs overflow-x-auto">{a.fixed_code}</pre>}
            {a.false_positive_risk && <p className="mt-2 text-xs text-slate-500">False-positive risk: {a.false_positive_risk}</p>}
          </Section>
        </div>
      ) : (
        <Section icon={<Bug className="w-4 h-4" />} title="Analysis"><span className="text-slate-500">Not generated yet.</span></Section>
      )}
      {d.analysis_model && <p className="text-xs text-slate-500">Explanation normalized by {d.analysis_model} from sanitized scanner output; it never changes status or severity.</p>}

      <Section icon={<History className="w-4 h-4" />} title="Lifecycle & evidence">
        <div className="text-xs">{d.evidence.length} hashed evidence record(s).</div>
        {d.timeline.length === 0 ? <div className="text-xs text-slate-500 mt-1">No analyst actions yet.</div> : (
          <ul className="text-xs mt-1 space-y-0.5">{d.timeline.map((t, i) => <li key={i}>{t.timestamp.slice(0, 19)} · {t.from_status} → {t.to_status} by {t.actor_type}:{t.actor_id} — {t.reason}</li>)}</ul>
        )}
      </Section>

      {zoom && d.proof_url && <ProofLightbox src={adminApi.proofSrc(d.proof_url)} title={f.title} method={method} onClose={() => setZoom(false)} />}
    </main>
  )
}
