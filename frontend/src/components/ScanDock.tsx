'use client'

import { useEffect, useRef, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { fetchScanLive, ScanLive } from '../services/api'
import { adminApi, PipelineState } from '../lib/adminApi'
import { useAppDispatch, useAppSelector } from '../store'
import { fetchFindingsAsync } from '../store/slices/findingsSlice'
import { fetchSummaryAsync } from '../store/slices/summarySlice'
import { fetchRecommendationsAsync } from '../store/slices/copilotSlice'
import { fetchRadarAsync, fetchAttackSurfaceAsync, fetchNetworkInspectAsync } from '../store/slices/telemetrySlice'

const ZAP_BUDGET_S = 600

function clock(sec: number) {
  const s = Math.max(0, Math.floor(sec))
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`
}

export default function ScanDock() {
  const [live, setLive] = useState<ScanLive | null>(null)
  const [pipe, setPipe] = useState<PipelineState | null>(null)
  const [now, setNow] = useState(() => Date.now())
  const dispatch = useAppDispatch()
  const targetUrl = useAppSelector((s) => s.assessment.targetUrl)
  const sawScan = useRef(false)

  useEffect(() => {
    let stop = false
    const tick = async () => {
      const [data, pipeline] = await Promise.all([
        fetchScanLive(),
        adminApi.pipelineStatus().catch(() => null),
      ])
      if (stop) return
      setLive(data)
      setPipe(pipeline)
      if (data?.running) sawScan.current = true
      if (data && !data.running && sawScan.current) {
        sawScan.current = false
        dispatch(fetchFindingsAsync(targetUrl))
        dispatch(fetchNetworkInspectAsync(targetUrl))
        dispatch(fetchSummaryAsync())
        dispatch(fetchRecommendationsAsync())
        dispatch(fetchRadarAsync())
        dispatch(fetchAttackSurfaceAsync())
      }
    }
    tick()
    const timer = setInterval(tick, 1500)
    return () => {
      stop = true
      clearInterval(timer)
    }
  }, [dispatch, targetUrl])

  const scanning = !!(live?.running || pipe?.running)
  useEffect(() => {
    if (!scanning) return
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [scanning])

  if (!scanning) return null

  const tool = pipe?.running
    ? (pipe.steps.find((s) => s.status === 'running')?.label || live?.current || 'starting')
    : (live?.current || 'starting')
  const percent = Math.max(0, Math.min(100, live?.percent || 0))
  const started = pipe?.started_at ? Date.parse(pipe.started_at) : null
  const elapsed = started ? (now - started) / 1000 : 0
  const zap = pipe?.steps.find((s) => s.id === 'zap')
  const zapLeft = zap?.status === 'running' && zap.started_at
    ? ZAP_BUDGET_S - (now - Date.parse(zap.started_at)) / 1000
    : zap?.status === 'pending' ? ZAP_BUDGET_S : null

  return (
    <div
      className="fixed bottom-4 right-4 z-50 w-72 rounded-xl border border-slate-200 dark:border-slate-700 bg-white/95 dark:bg-slate-900/95 shadow-lg px-3 py-2.5"
      role="status"
      aria-live="polite"
    >
      <div className="flex items-center gap-2 text-xs font-semibold text-slate-800 dark:text-slate-100">
        <Loader2 size={14} className="animate-spin text-teal-600 shrink-0" aria-hidden />
        <span className="truncate">Scanning {tool}</span>
        <span className="ml-auto font-mono text-teal-700 dark:text-teal-300">{percent}%</span>
      </div>
      <div
        className="mt-2 h-1.5 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden"
        role="progressbar"
        aria-valuenow={percent}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={`Scan progress, ${tool}`}
      >
        <div className="h-full bg-teal-600" style={{ width: `${percent}%` }} />
      </div>
      <p className="mt-1 text-[10px] text-slate-500 font-mono">
        {started ? `Elapsed ${clock(elapsed)}` : ''}
        {zapLeft !== null ? `${started ? ' · ' : ''}ZAP left ${clock(zapLeft)}` : ''}
        {live ? `${started || zapLeft !== null ? ' · ' : ''}${live.done}/${live.total} tools` : ''}
      </p>
    </div>
  )
}
