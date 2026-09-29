'use client'

import { useState } from 'react'
import Link from 'next/link'
import { AlertTriangle, XCircle, Code2, Package, KeyRound, Globe2 } from 'lucide-react'
import { useAppSelector } from '../store'
import { sevClass } from '../lib/adminApi'
import type { TelemetryAttackSurfaceNode } from '../services/api'

const KIND_ICON = { source: Code2, dependencies: Package, secrets: KeyRound, runtime: Globe2 } as const
const KIND_HINT: Record<TelemetryAttackSurfaceNode['kind'], string> = {
  source: 'Findings reported in this directory of the World Monitor source tree (Semgrep, Gemini review).',
  dependencies: 'Vulnerable packages reported by OSV-Scanner from the lockfiles.',
  secrets: 'Credential-like strings reported by Gitleaks (values are always redacted).',
  runtime: 'Issues observed on the running application by OWASP ZAP and the probes.',
}

function style(s: TelemetryAttackSurfaceNode['status']) {
  return s === 'vulnerable'
    ? 'bg-red-50 dark:bg-red-950/40 border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 hover:bg-red-100/60 dark:hover:bg-red-900/50'
    : 'bg-amber-50 dark:bg-amber-950/40 border-amber-200 dark:border-amber-800 text-amber-700 dark:text-amber-300 hover:bg-amber-100/60 dark:hover:bg-amber-900/50'
}

// Attack surface = the places where scanners actually reported something, grouped by area of the target.
// Nothing here describes infrastructure that was not observed.
export default function AttackSurfaceMap() {
  const nodes = Object.values(useAppSelector((s) => s.telemetry.attackSurfaceNodes))
  const [selected, setSelected] = useState<TelemetryAttackSurfaceNode | null>(null)
  const active = selected ? nodes.find((n) => n.id === selected.id) ?? null : null

  return (
    <div className="card p-5">
      <div className="flex items-center justify-between mb-3">
        <div>
          <h2 className="text-sm font-semibold text-slate-800 dark:text-slate-100">Attack Surface by Area</h2>
          <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">Where the scanners found something, grouped by part of the target</p>
        </div>
        <div className="flex items-center gap-3 text-[10px] text-slate-500">
          <span className="flex items-center gap-1"><XCircle size={11} className="text-red-500" />Critical/High present</span>
          <span className="flex items-center gap-1"><AlertTriangle size={11} className="text-amber-500" />Medium or lower</span>
        </div>
      </div>

      {nodes.length === 0 ? (
        <div className="py-10 text-center text-xs text-slate-400 font-mono">No findings stored, so no attack surface has been mapped yet.</div>
      ) : (
        <div className="grid grid-cols-2 md:grid-cols-3 gap-2.5">
          {nodes.map((n) => {
            const Icon = KIND_ICON[n.kind]
            return (
              <button
                key={n.id}
                onClick={() => setSelected(n)}
                className={`text-left rounded-xl border p-3 transition-colors cursor-pointer ${style(n.status)} ${active?.id === n.id ? 'ring-2 ring-indigo-400' : ''}`}
              >
                <div className="flex items-center justify-between">
                  <Icon size={15} />
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${sevClass(n.max_severity)}`}>{n.max_severity}</span>
                </div>
                <p className="mt-2 text-xs font-semibold truncate">{n.label}</p>
                <p className="text-[11px] opacity-80">{n.findings} finding{n.findings === 1 ? '' : 's'}</p>
              </button>
            )
          })}
        </div>
      )}

      {active && (
        <div className="mt-4 rounded-xl border border-slate-200 dark:border-slate-800 p-3.5 text-xs">
          <p className="font-semibold text-slate-800 dark:text-slate-100">{active.label}</p>
          <p className="text-slate-500 dark:text-slate-400 mt-0.5">{KIND_HINT[active.kind]}</p>
          <ul className="mt-2 space-y-1">
            {active.top.map((t) => (
              <li key={t.finding_id} className="flex items-start gap-2">
                <span className={`mt-0.5 px-1.5 py-0.5 rounded text-[10px] font-bold ${sevClass(t.severity)}`}>{t.severity}</span>
                <Link href={`/findings/${t.finding_id}`} className="hover:underline text-slate-700 dark:text-slate-200">{t.title}</Link>
              </li>
            ))}
            {active.findings > active.top.length && (
              <li className="text-slate-400">+ {active.findings - active.top.length} more in the Findings table</li>
            )}
          </ul>
        </div>
      )}
    </div>
  )
}
