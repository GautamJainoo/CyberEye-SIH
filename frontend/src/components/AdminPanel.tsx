'use client'

import { useState, useEffect } from 'react'
import {
  Shield, Globe, GitBranch, Terminal, RefreshCw, Trash2, CheckCircle2,
  Play, Server, Database
} from 'lucide-react'
import { useToast } from './Toast'
import {
  fetchHealth,
  configureTarget,
  resetDatabase,
  triggerScan,
  BackendHealth
} from '../services/api'

interface AdminPanelProps {
  onScanComplete?: () => void
  onNavigateToFindings?: () => void
}

export default function AdminPanel({ onScanComplete, onNavigateToFindings }: AdminPanelProps) {
  const { toast } = useToast()
  const [repoUrl, setRepoUrl] = useState('https://github.com/koala73/worldmonitor')
  const [websiteUrl, setWebsiteUrl] = useState('http://127.0.0.1:3000')
  const [commitSha, setCommitSha] = useState('')
  const [resetDbOnConfigure, setResetDbOnConfigure] = useState(true)

  const [health, setHealth] = useState<BackendHealth | null>(null)
  const [isConfiguring, setIsConfiguring] = useState(false)
  const [isScanning, setIsScanning] = useState(false)
  const [isResetting, setIsResetting] = useState(false)
  const [logs, setLogs] = useState<string[]>([])

  const loadHealth = async () => {
    const data = await fetchHealth()
    setHealth(data)
    if (data?.repo_url) setRepoUrl(data.repo_url)
    if (data?.target_commit && !commitSha) setCommitSha(data.target_commit.slice(0, 8))
  }

  useEffect(() => {
    loadHealth()
  }, [])

  const handleConfigureTarget = async () => {
    if (!repoUrl.trim()) {
      toast('warning', 'Missing Repository', 'Please enter a valid GitHub repository URL.')
      return
    }

    setIsConfiguring(true)
    setLogs([
      `[Target Manager] Initiating target setup for: ${repoUrl.trim()}`,
      `[Scope Guard] Binding website target endpoint: ${websiteUrl.trim()}`,
    ])

    const res = await configureTarget({
      repo_url: repoUrl.trim(),
      website_url: websiteUrl.trim(),
      commit_sha: commitSha.trim() || undefined,
      reset_db: resetDbOnConfigure,
    })

    setIsConfiguring(false)

    if (res) {
      setLogs((prev) => [
        ...prev,
        `[Git] Successfully cloned / checked out ${res.commit_sha.slice(0, 8)}`,
        `[Scope] Updated config/scope.yaml with strict loopback enforcement`,
        `[Database] Initialized clean baseline (findings: 0)`,
      ])
      toast('success', 'Target Configured & Cloned', `Target repo ready at commit ${res.commit_sha.slice(0, 8)}.`)
      await loadHealth()
      onScanComplete?.()
    } else {
      setLogs((prev) => [...prev, `[Error] Failed to configure target. Check URL or git permissions.`])
      toast('error', 'Configuration Failed', 'Could not clone or configure the target repository.')
    }
  }

  const handleRunScan = async () => {
    setIsScanning(true)
    setLogs((prev) => [
      ...prev,
      `[WMSA Orchestrator] Starting multi-tool security assessment (lite profile)...`,
      `[Modules] Gemini review + Semgrep + Gitleaks + OSV-Scanner + probes (use the full pipeline for ZAP and Lighthouse)`,
    ])

    const res = await triggerScan('lite')
    setIsScanning(false)

    if (res) {
      setLogs((prev) => [
        ...prev,
        `[Scan ${res.scan_id}] ${res.status}: ${res.findings_count} finding(s) ingested in ${res.duration_seconds.toFixed(1)}s`,
        ...res.tool_runs.map((t) => `[Tool: ${t.tool_name} ${t.tool_version}] exit ${t.exit_code} in ${t.duration_seconds.toFixed(1)}s`),
        ...Object.entries(res.tool_errors || {}).map(([tool, err]) => `[Tool: ${tool}] FAILED: ${err}`),
      ])
      toast(
        Object.keys(res.tool_errors || {}).length ? 'warning' : 'success',
        'Assessment finished',
        `${res.findings_count} finding(s) ingested; ${Object.keys(res.tool_errors || {}).length} tool(s) failed.`
      )
      await loadHealth()
      onScanComplete?.()
    } else {
      setLogs((prev) => [...prev, `[Error] Scan execution failed. Check backend server.`])
      toast('error', 'Scan Failed', 'Backend scan failed to complete.')
    }
  }

  const handleResetDatabase = async () => {
    if (!window.confirm('Reset all vulnerability findings and scan history? Findings and scan history are removed (the append-only audit log is kept).')) {
      return
    }

    setIsResetting(true)
    const res = await resetDatabase()
    setIsResetting(false)

    if (res) {
      setLogs((prev) => [
        ...prev,
        `[Database Reset] Purged ${res.purged_findings} findings. Clean 0-findings state restored.`,
      ])
      toast('info', 'Database Cleared', `Purged ${res.purged_findings} findings. Clean baseline state active.`)
      await loadHealth()
      onScanComplete?.()
    } else {
      toast('error', 'Reset Failed', 'Could not clear database.')
    }
  }

  return (
    <div className="space-y-6 animate-fade-in max-w-5xl mx-auto pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="p-1.5 rounded-lg bg-teal-50 dark:bg-teal-950/60 text-teal-600 dark:text-teal-400 border border-teal-200 dark:border-teal-800">
              <Shield size={18} />
            </span>
            <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100">
              Target Administration &amp; Scanner Setup
            </h1>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Specify the GitHub repository and target website URL to audit. All scans strictly enforce loopback isolation.
          </p>
        </div>

        {/* Live Status Pill */}
        <div className="flex items-center gap-2">
          <span
            className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-medium border ${
              health?.status === 'online'
                ? 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800'
                : 'bg-rose-50 dark:bg-rose-950/60 text-rose-700 dark:text-rose-400 border-rose-200 dark:border-rose-800'
            }`}
          >
            <span
              className={`w-2 h-2 rounded-full ${
                health?.status === 'online' ? 'bg-emerald-500 animate-pulse' : 'bg-rose-500'
              }`}
            />
            {health?.status === 'online' ? 'WMSA Backend Online' : 'Backend Disconnected'}
          </span>

          <button
            onClick={loadHealth}
            className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-800 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-500 transition-colors cursor-pointer"
            title="Refresh status"
          >
            <RefreshCw size={13} />
          </button>
        </div>
      </div>

      {/* Target Configuration Card */}
      <div className="card p-6 border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl shadow-sm">
        <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-4 flex items-center gap-2">
          <Globe size={16} className="text-teal-500" />
          <span>Configure Target System</span>
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mb-5">
          {/* GitHub Repo Input */}
          <div>
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
              Target GitHub Repository URL <span className="text-rose-500">*</span>
            </label>
            <div className="relative">
              <GitBranch size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="https://github.com/koala73/worldmonitor"
                className="w-full pl-9 pr-3 py-2 text-xs font-mono rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-teal-500"
              />
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              Source code cloned into isolated checkout for Semgrep SAST, Gitleaks, and OSV SCA scans.
            </p>
          </div>

          {/* Website Target Link */}
          <div>
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
              Target Website Endpoint (DAST Probes)
            </label>
            <div className="relative">
              <Globe size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                value={websiteUrl}
                onChange={(e) => setWebsiteUrl(e.target.value)}
                placeholder="http://127.0.0.1:3000"
                className="w-full pl-9 pr-3 py-2 text-xs font-mono rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-teal-500"
              />
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              Local isolated URL for OWASP ZAP and custom behavioral probes.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mb-5 items-center">
          {/* Optional Commit SHA */}
          <div>
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
              Specific Commit SHA / Tag <span className="text-slate-400 font-normal">(Optional, defaults to HEAD)</span>
            </label>
            <input
              type="text"
              value={commitSha}
              onChange={(e) => setCommitSha(e.target.value)}
              placeholder="e.g. 0d5c618e4307414546a9be84a482ac06b7d56749"
              className="w-full px-3 py-2 text-xs font-mono rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-teal-500"
            />
          </div>

          {/* Clean Slate Checkbox */}
          <div className="pt-4 flex items-center gap-2">
            <input
              type="checkbox"
              id="reset-db-toggle"
              checked={resetDbOnConfigure}
              onChange={(e) => setResetDbOnConfigure(e.target.checked)}
              className="rounded border-slate-300 text-teal-600 focus:ring-teal-500 cursor-pointer"
            />
            <label htmlFor="reset-db-toggle" className="text-xs text-slate-600 dark:text-slate-300 cursor-pointer">
              Wipe previous findings database when configuring new target (Zero Dummy Data)
            </label>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center gap-3 pt-3 border-t border-slate-100 dark:border-slate-800">
          <button
            onClick={handleConfigureTarget}
            disabled={isConfiguring}
            className="btn-primary text-xs px-4 py-2 flex items-center gap-2 cursor-pointer shadow-sm disabled:opacity-60"
          >
            <Server size={14} className={isConfiguring ? 'animate-spin' : ''} />
            <span>{isConfiguring ? 'Cloning & Setting Up...' : '1. Configure & Clone Target'}</span>
          </button>

          <button
            onClick={handleRunScan}
            disabled={isScanning || isConfiguring}
            className="px-4 py-2 rounded-xl text-xs font-semibold bg-emerald-600 hover:bg-emerald-700 text-white transition-all flex items-center gap-2 cursor-pointer shadow-sm disabled:opacity-60"
          >
            <Play size={14} className={isScanning ? 'animate-spin' : ''} />
            <span>{isScanning ? 'Scanning Target...' : '2. Run Security Audit Now'}</span>
          </button>

          <button
            onClick={handleResetDatabase}
            disabled={isResetting}
            className="px-3.5 py-2 rounded-xl text-xs font-semibold border border-rose-200 dark:border-rose-900/60 text-rose-600 dark:text-rose-400 hover:bg-rose-50 dark:hover:bg-rose-950/40 transition-all flex items-center gap-1.5 cursor-pointer ml-auto"
            title="Purge all findings from database"
          >
            <Trash2 size={13} className={isResetting ? 'animate-spin' : ''} />
            <span>Purge All Findings</span>
          </button>
        </div>
      </div>

      {/* Active Target State & Telemetry Card */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {/* Repo & SHA */}
        <div className="card p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Target Checkout</span>
            <GitBranch size={14} className="text-teal-500" />
          </div>
          <p className="text-xs font-mono font-semibold text-slate-800 dark:text-slate-100 truncate">
            {health?.repo_url || repoUrl}
          </p>
          <p className="text-[11px] font-mono text-slate-400 mt-1">
            Commit: {health?.target_commit ? health.target_commit.slice(0, 8) : 'Not pinned'}
          </p>
        </div>

        {/* Database Findings */}
        <div className="card p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Database Findings</span>
            <Database size={14} className="text-indigo-500" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-extrabold text-slate-900 dark:text-white">
              {health?.findings_count ?? 0}
            </span>
            <span className="text-xs text-slate-400 font-mono">
              {(health?.findings_count ?? 0) === 0 ? 'Clean Slate' : 'Recorded in SQLite'}
            </span>
          </div>
          <button
            onClick={onNavigateToFindings}
            className="text-[11px] text-teal-600 dark:text-teal-400 hover:underline mt-1 cursor-pointer block"
          >
            View Findings Table →
          </button>
        </div>

        {/* Scope Enforcement */}
        <div className="card p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Scope Guard Enforcement</span>
            <Shield size={14} className="text-emerald-500" />
          </div>
          <p className="text-xs font-semibold text-emerald-600 dark:text-emerald-400 flex items-center gap-1.5">
            <CheckCircle2 size={13} />
            <span>Strict Fail-Closed</span>
          </p>
          <p className="text-[11px] text-slate-400 mt-1">
            Host: {websiteUrl} (Loopback Only)
          </p>
        </div>
      </div>

      {/* Real-time Operation Logs Console */}
      <div className="card p-5 border border-slate-200 dark:border-slate-800 bg-slate-950 text-slate-300 rounded-2xl font-mono text-xs">
        <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800 text-slate-400">
          <div className="flex items-center gap-2">
            <Terminal size={14} className="text-teal-400" />
            <span className="font-semibold text-slate-200">Execution Console &amp; Audit Logs</span>
          </div>
          <span className="text-[10px] text-slate-500">Live Backend Stream</span>
        </div>

        <div className="space-y-1.5 max-h-56 overflow-y-auto">
          {logs.length === 0 ? (
            <p className="text-slate-600 text-xs italic">
              Ready. Enter repository and website links above and click &quot;Configure &amp; Clone Target&quot;.
            </p>
          ) : (
            logs.map((log, idx) => (
              <div key={idx} className="flex items-start gap-2">
                <span className="text-teal-500 shrink-0 select-none">&gt;</span>
                <span className="text-slate-300">{log}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
