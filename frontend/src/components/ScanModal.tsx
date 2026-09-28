import { useState } from 'react'
import {
  X, Shield, Play, GitBranch, Upload, Globe, CheckCircle2,
  Terminal, Sparkles
} from 'lucide-react'
import { useToast } from './Toast'

interface ScanModalProps {
  isOpen: boolean
  onClose: () => void
  onScanComplete?: () => void
}

export default function ScanModal({ isOpen, onClose, onScanComplete }: ScanModalProps) {
  const { toast } = useToast()
  const [sourceType, setSourceType] = useState<'url' | 'github' | 'zip'>('url')
  const [targetUrl, setTargetUrl] = useState('https://worldmonitor.app')
  const [githubRepo, setGithubRepo] = useState('https://github.com/koala73/worldmonitor')
  const [zipFileName, setZipFileName] = useState<string | null>(null)

  // Module Toggles (Box 6 in Image 2)
  const [modules, setModules] = useState({
    sast: true,      // Semgrep
    secrets: true,   // Gitleaks
    sca: true,       // OSV-Scanner
    dast: true,      // OWASP ZAP
  })

  const [isScanning, setIsScanning] = useState(false)
  const [progress, setProgress] = useState(0)
  const [currentStep, setCurrentStep] = useState<string>('')
  const [logs, setLogs] = useState<string[]>([])

  if (!isOpen) return null

  const handleStartScan = () => {
    setIsScanning(true)
    setProgress(5)
    setLogs(['[Celery Worker] Initialized isolated container worker #4'])
    setCurrentStep('Queueing Scan Job in Redis...')

    const steps = [
      { p: 20, step: 'Cloning target & validating inputs', log: '[File Handler] Loaded codebase from https://github.com/koala73/worldmonitor' },
      { p: 40, step: 'Running Semgrep SAST & Rule Pattern Matching', log: '[Semgrep] Scanning AST trees... Detected SQL injection pattern in api/search.py' },
      { p: 65, step: 'Executing Gitleaks Secret Scanning', log: '[Gitleaks] Analyzing git commit history... Flagged AWS access token pattern' },
      { p: 85, step: 'Running OSV-Scanner SCA & OWASP ZAP DAST', log: '[OSV-Scanner] Flagged lodash 4.17.15 (CVE-2021-23337) | [ZAP] Active probe complete' },
      { p: 100, step: 'Correlating findings & generating CVSS scores', log: '[Analysis Engine] Completed security audit. 12 vulnerabilities classified.' },
    ]

    steps.forEach((s, idx) => {
      setTimeout(() => {
        setProgress(s.p)
        setCurrentStep(s.step)
        setLogs(prev => [...prev, s.log])

        if (idx === steps.length - 1) {
          setTimeout(() => {
            setIsScanning(false)
            toast('success', 'Security Assessment Completed', 'Scan completed across all 4 modules. Findings table updated.')
            onScanComplete?.()
            onClose()
          }, 600)
        }
      }, (idx + 1) * 700)
    })
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-fade-in">
      <div className="card w-full max-w-2xl overflow-hidden shadow-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
        {/* Header */}
        <div className="p-5 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-xl bg-teal-500/15 text-teal-600 dark:text-teal-400 flex items-center justify-center">
              <Shield size={18} />
            </div>
            <div>
              <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                Launch Automated Security Assessment
              </h2>
              <p className="text-[11px] text-slate-400">
                SIH Problem Statement 26163 — Multi-module Orchestration Pipeline
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            disabled={isScanning}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors"
          >
            <X size={16} />
          </button>
        </div>

        {/* Body */}
        <div className="p-5 space-y-5 max-h-[75vh] overflow-y-auto">
          {!isScanning ? (
            <>
              {/* Step 1: Input Source */}
              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2">
                  1. Select Target Input (Box 1 in Architecture)
                </label>
                <div className="grid grid-cols-3 gap-2.5">
                  <button
                    type="button"
                    onClick={() => setSourceType('url')}
                    className={`p-3 rounded-xl border flex flex-col items-center gap-1.5 transition-all text-xs font-medium cursor-pointer ${
                      sourceType === 'url'
                        ? 'border-teal-500 bg-teal-50/50 dark:bg-teal-950/40 text-teal-700 dark:text-teal-300'
                        : 'border-slate-200 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-400'
                    }`}
                  >
                    <Globe size={18} />
                    <span>Target URL</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setSourceType('github')}
                    className={`p-3 rounded-xl border flex flex-col items-center gap-1.5 transition-all text-xs font-medium cursor-pointer ${
                      sourceType === 'github'
                        ? 'border-teal-500 bg-teal-50/50 dark:bg-teal-950/40 text-teal-700 dark:text-teal-300'
                        : 'border-slate-200 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-400'
                    }`}
                  >
                    <GitBranch size={18} />
                    <span>GitHub Repo</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setSourceType('zip')}
                    className={`p-3 rounded-xl border flex flex-col items-center gap-1.5 transition-all text-xs font-medium cursor-pointer ${
                      sourceType === 'zip'
                        ? 'border-teal-500 bg-teal-50/50 dark:bg-teal-950/40 text-teal-700 dark:text-teal-300'
                        : 'border-slate-200 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-400'
                    }`}
                  >
                    <Upload size={18} />
                    <span>Upload ZIP</span>
                  </button>
                </div>

                <div className="mt-3">
                  {sourceType === 'url' && (
                    <input
                      type="text"
                      value={targetUrl}
                      onChange={(e) => setTargetUrl(e.target.value)}
                      placeholder="https://worldmonitor.app"
                      className="w-full px-3 py-2 text-xs font-mono rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-800 dark:text-slate-200"
                    />
                  )}
                  {sourceType === 'github' && (
                    <input
                      type="text"
                      value={githubRepo}
                      onChange={(e) => setGithubRepo(e.target.value)}
                      placeholder="https://github.com/koala73/worldmonitor"
                      className="w-full px-3 py-2 text-xs font-mono rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-800 dark:text-slate-200"
                    />
                  )}
                  {sourceType === 'zip' && (
                    <div className="border-2 border-dashed border-slate-200 dark:border-slate-800 rounded-xl p-4 text-center">
                      <p className="text-xs text-slate-500 dark:text-slate-400">
                        {zipFileName ? zipFileName : 'Click to select worldmonitor-main.zip'}
                      </p>
                      <button
                        type="button"
                        onClick={() => setZipFileName('worldmonitor-main-v2.4.zip (4.8 MB)')}
                        className="mt-2 text-xs font-semibold text-teal-600 dark:text-teal-400"
                      >
                        {zipFileName ? 'File Attached' : 'Attach Demo Source Code ZIP'}
                      </button>
                    </div>
                  )}
                </div>
              </div>

              {/* Step 2: Scanning Modules */}
              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2">
                  2. Select Scanning Modules (Box 6 in Architecture)
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  {[
                    { key: 'sast', label: '6.1 SAST (Semgrep)', sub: 'Code pattern matching & SQLi/XSS checks' },
                    { key: 'secrets', label: '6.2 Secret Scanning (Gitleaks)', sub: 'API keys, credentials, token leaks' },
                    { key: 'sca', label: '6.3 SCA (OSV-Scanner)', sub: 'Dependency analysis & CVE lookup' },
                    { key: 'dast', label: '6.4 DAST (OWASP ZAP)', sub: 'Runtime tests & security headers' },
                  ].map((mod) => (
                    <label
                      key={mod.key}
                      className="flex items-start gap-2.5 p-3 rounded-xl border border-slate-200 dark:border-slate-800 hover:bg-slate-50/60 dark:hover:bg-slate-800/40 cursor-pointer"
                    >
                      <input
                        type="checkbox"
                        checked={modules[mod.key as keyof typeof modules]}
                        onChange={(e) =>
                          setModules({ ...modules, [mod.key]: e.target.checked })
                        }
                        className="mt-0.5 rounded text-teal-600 focus:ring-teal-500"
                      />
                      <div>
                        <p className="text-xs font-bold text-slate-800 dark:text-slate-200">
                          {mod.label}
                        </p>
                        <p className="text-[10px] text-slate-400 mt-0.5">{mod.sub}</p>
                      </div>
                    </label>
                  ))}
                </div>
              </div>
            </>
          ) : (
            /* Live Scan Progress Animation */
            <div className="space-y-4 py-4">
              <div>
                <div className="flex items-center justify-between text-xs mb-1.5">
                  <span className="font-semibold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                    <Sparkles size={14} className="text-teal-500 animate-spin" />
                    {currentStep}
                  </span>
                  <span className="font-mono text-teal-600 dark:text-teal-400 font-bold">{progress}%</span>
                </div>
                <div className="w-full bg-slate-100 dark:bg-slate-800 h-2.5 rounded-full overflow-hidden">
                  <div
                    className="bg-gradient-to-r from-teal-500 to-emerald-400 h-full rounded-full transition-all duration-300"
                    style={{ width: `${progress}%` }}
                  />
                </div>
              </div>

              {/* Console Logs */}
              <div className="bg-slate-950 rounded-xl p-3.5 border border-slate-800 font-mono text-[11px] space-y-1.5 text-slate-300 max-h-48 overflow-y-auto">
                <div className="text-teal-400 flex items-center gap-1 pb-1 border-b border-slate-800">
                  <Terminal size={12} /> Live Scan Orchestrator Telemetry
                </div>
                {logs.map((log, idx) => (
                  <div key={idx} className="flex items-center gap-2">
                    <span className="text-slate-500">{'>'}</span>
                    <span>{log}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-100 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/50 flex items-center justify-between">
          <span className="text-[11px] text-slate-400 flex items-center gap-1">
            <CheckCircle2 size={12} className="text-emerald-500" />
            Isolated Sandbox Environment
          </span>

          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              disabled={isScanning}
              className="btn-secondary text-xs px-3 py-1.5"
            >
              Cancel
            </button>
            <button
              onClick={handleStartScan}
              disabled={isScanning}
              className="btn-primary text-xs px-4 py-1.5 flex items-center gap-1.5 bg-teal-600 hover:bg-teal-700"
            >
              <Play size={13} className="fill-current" />
              <span>{isScanning ? 'Orchestrating...' : 'Start Scan Job'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
