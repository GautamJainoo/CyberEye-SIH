'use client'

import { useEffect, useRef, useState } from 'react'
import { X, Shield, Play, CheckCircle2, Circle, Loader2, XCircle, MinusCircle } from 'lucide-react'
import { useToast } from './Toast'
import { adminApi, PipelineState } from '../lib/adminApi'
import { useAppSelector } from '../store'

interface ScanModalProps {
  isOpen: boolean
  onClose: () => void
  onScanComplete?: () => void
  embedded?: boolean
}

// Matches standard profile: spider 2 min + active scan 5 min + 3 min startup buffer.
const ZAP_BUDGET_S = 600

function clock(sec: number) {
  const s = Math.max(0, Math.floor(sec))
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`
}

function StepIcon({ s }: { s: string }) {
  if (s === 'running') return <Loader2 size={14} className="animate-spin text-blue-500" />
  if (s === 'done') return <CheckCircle2 size={14} className="text-emerald-500" />
  if (s === 'failed') return <XCircle size={14} className="text-red-500" />
  if (s === 'skipped') return <MinusCircle size={14} className="text-slate-400" />
  return <Circle size={14} className="text-slate-300" />
}

// Runs the REAL assessment pipeline (/api/pipeline/*). Every line shown is reported by the backend;
// if the backend is unreachable the modal says so instead of simulating a scan.
export default function ScanModal({ isOpen, onClose, onScanComplete, embedded = false }: ScanModalProps) {
  const { toast } = useToast()
  const targetUrl = useAppSelector((s) => s.assessment.targetUrl)
  const [fresh, setFresh] = useState(false)
  const [setup, setSetup] = useState(false)
  const [state, setState] = useState<PipelineState | null>(null)
  const [error, setError] = useState('')
  const [now, setNow] = useState(() => Date.now())
  const timer = useRef<ReturnType<typeof setInterval> | null>(null)
  const wasRunning = useRef(false)

  const poll = async () => {
    try {
      const s = await adminApi.pipelineStatus()
      setState(s)
      setError('')
      if (wasRunning.current && !s.running) {
        wasRunning.current = false
        const failed = s.steps.filter((x) => x.status === 'failed').length
        toast(failed ? 'warning' : 'success', failed ? 'Assessment finished with errors' : 'Assessment complete',
          failed ? `${failed} step(s) failed - see the log.` : 'All steps completed. Dashboard data refreshed.')
        onScanComplete?.()
      }
      if (s.running) wasRunning.current = true
    } catch (e: any) {
      setError(`Backend unreachable: ${e.message}. Start it with: make server`)
    }
  }

  useEffect(() => {
    if (!isOpen) return
    poll()
    timer.current = setInterval(poll, 2000)
    return () => { if (timer.current) clearInterval(timer.current) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen])

  const running = !!state?.running

  useEffect(() => {
    if (!isOpen || !running) return
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [isOpen, running])

  if (!isOpen) return null

  const elapsed = state?.started_at ? (now - Date.parse(state.started_at)) / 1000 : 0
  const zap = state?.steps.find((s) => s.id === 'zap')
  const zapElapsed = zap?.started_at ? (now - Date.parse(zap.started_at)) / 1000 : 0
  const zapLeft = zap?.status === 'running' ? ZAP_BUDGET_S - zapElapsed : zap?.status === 'pending' ? ZAP_BUDGET_S : null

  const start = async () => {
    if (fresh && !window.confirm('This clears all existing findings before scanning. Continue?')) return
    try {
      await adminApi.startPipeline(fresh, setup)
      wasRunning.current = true
      await poll()
    } catch (e: any) {
      setError(String(e.message || e))
    }
  }

  const card = (
      <div className={`card w-full overflow-hidden shadow-2xl bg-white dark:bg-slate-900 ${embedded ? '' : 'max-w-2xl'}`}>
        <div className="p-5 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-xl bg-teal-500/15 text-teal-600 dark:text-teal-400 flex items-center justify-center"><Shield size={18} /></div>
            <div>
              <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100">Run security assessment</h2>
              <p className="text-[11px] text-slate-400">Website: {targetUrl}</p>
              {running && (
                <p className="text-[11px] font-mono text-teal-700 dark:text-teal-300" aria-live="polite">
                  Elapsed {clock(elapsed)}
                  {zapLeft !== null ? ` · ZAP left ${clock(zapLeft)}` : ''}
                </p>
              )}
            </div>
          </div>
          <button onClick={onClose} className="p-1 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200" aria-label="Close"><X size={16} /></button>
        </div>

        <div className="p-5 space-y-4 max-h-[75vh] overflow-y-auto">
          {error && <div className="text-xs text-red-500">{error}</div>}

          <div className="flex flex-wrap items-center gap-4 text-xs">
            <label className="flex items-center gap-1.5"><input type="checkbox" checked={fresh} onChange={(e) => setFresh(e.target.checked)} disabled={running} />Clear and scan fresh</label>
            <label className="flex items-center gap-1.5"><input type="checkbox" checked={setup} onChange={(e) => setSetup(e.target.checked)} disabled={running} />Gemini-guided target start-up</label>
          </div>

          <ol className="space-y-1.5">
            {(state?.steps ?? []).map((s) => (
              <li key={s.id} className="flex items-start gap-2 text-sm">
                <span className="mt-0.5"><StepIcon s={s.status} /></span>
                <div>
                  <span className="font-medium">{s.label}</span>
                  {s.id === 'zap' && s.status === 'running' && (
                    <span className="text-xs font-mono text-teal-700 dark:text-teal-300"> - {clock(zapElapsed)} elapsed, {clock(zapLeft ?? 0)} left of 10:00</span>
                  )}
                  {s.detail && <span className="text-xs text-slate-500"> - {s.detail}</span>}
                </div>
              </li>
            ))}
            {(!state || state.steps.length === 0) && <li className="text-sm text-slate-500">Nothing has run in this session. Press start to run all scanners.</li>}
          </ol>

          {state && state.log.length > 0 && (
            <pre className="p-2 rounded bg-slate-950 text-slate-300 text-[11px] max-h-40 overflow-auto">{state.log.join('\n')}</pre>
          )}
        </div>

        <div className="p-4 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between">
          <span className="text-[11px] text-slate-400">{running ? 'Running side by side. Leave this page; it continues in the background.' : 'Static scans start immediately. ZAP, probes, and Lighthouse start together once the local target is up. Groq runs next, then proof images.'}</span>
          <button onClick={start} disabled={running} className="btn-primary text-xs flex items-center gap-1.5 bg-teal-600 hover:bg-teal-700 disabled:opacity-60">
            {running ? <Loader2 size={13} className="animate-spin" /> : <Play size={13} />}
            {running ? 'Running…' : 'Start assessment'}
          </button>
        </div>
      </div>
  )

  if (embedded) return card
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      {card}
    </div>
  )
}
