import { useEffect, useRef, useState } from 'react'
import {
  X, Shield, Copy, Check, Tag,
  Terminal, AlertOctagon, Code2, Wrench
} from 'lucide-react'
import { Vulnerability, Status } from '../types'
import { severityClass, statusClass } from '../utils'
import { useToast } from './Toast'

interface Props {
  vuln: Vulnerability | null
  onClose: () => void
  onStatusChange?: (id: number, newStatus: Status) => void
}

export default function VulnModal({ vuln, onClose, onStatusChange }: Props) {
  const overlayRef = useRef<HTMLDivElement>(null)
  const { toast } = useToast()
  const [copied, setCopied] = useState(false)
  const [copiedPoc, setCopiedPoc] = useState(false)
  const [copiedFix, setCopiedFix] = useState(false)
  const [currentStatus, setCurrentStatus] = useState<Status>(vuln?.status || 'Open')
  const [activeTab, setActiveTab] = useState<'overview' | 'poc' | 'remediation'>('overview')

  useEffect(() => {
    if (vuln) {
      setCurrentStatus(vuln.status)
      setActiveTab('overview')
    }
  }, [vuln])

  useEffect(() => {
    if (!vuln) return
    const handleKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', handleKey)
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', handleKey)
      document.body.style.overflow = ''
    }
  }, [vuln, onClose])

  if (!vuln) return null

  const riskMap = { Critical: 95, High: 75, Medium: 50, Low: 25 }
  const riskPct = riskMap[vuln.severity]

  const handleCopyCve = () => {
    const text = vuln.cve || vuln.name
    navigator.clipboard?.writeText(text)
    setCopied(true)
    toast('success', 'Identifier Copied', `${text} copied to clipboard`)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleCopyPoc = () => {
    if (vuln.pocPayload) {
      navigator.clipboard?.writeText(vuln.pocPayload)
      setCopiedPoc(true)
      toast('success', 'PoC Payload Copied', 'Reproduction command copied')
      setTimeout(() => setCopiedPoc(false), 2000)
    }
  }

  const handleCopyFix = () => {
    if (vuln.remediationCode) {
      navigator.clipboard?.writeText(vuln.remediationCode)
      setCopiedFix(true)
      toast('success', 'Remediation Code Copied', 'Patch snippet copied')
      setTimeout(() => setCopiedFix(false), 2000)
    }
  }

  const handleStatusToggle = (newStatus: Status) => {
    setCurrentStatus(newStatus)
    onStatusChange?.(vuln.id, newStatus)
    toast('info', 'Status Updated', `Vulnerability marked as "${newStatus}"`)
  }

  return (
    <div
      ref={overlayRef}
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm animate-fade-in"
      onClick={(e) => { if (e.target === overlayRef.current) onClose() }}
    >
      {/* Panel */}
      <div className="relative w-full max-w-xl bg-white dark:bg-slate-900 rounded-2xl shadow-2xl border border-slate-200 dark:border-slate-800 overflow-hidden animate-modal-in flex flex-col max-h-[85vh]">
        {/* Header */}
        <div className="px-6 pt-5 pb-4 border-b border-slate-100 dark:border-slate-800 flex items-start gap-3">
          <div className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800 shrink-0">
            <Shield size={18} className="text-slate-600 dark:text-slate-300" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1.5 flex-wrap">
              <span className={severityClass(vuln.severity)}>{vuln.severity}</span>
              <span className={statusClass(currentStatus)}>{currentStatus}</span>
              {vuln.toolDetected && (
                <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-teal-50 dark:bg-teal-950/60 text-teal-700 dark:text-teal-300 border border-teal-200 dark:border-teal-800 font-mono">
                  {vuln.toolDetected}
                </span>
              )}
              {vuln.cve && (
                <button
                  onClick={handleCopyCve}
                  className="flex items-center gap-1 text-[10px] font-mono text-slate-500 dark:text-slate-400 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 px-2 py-0.5 rounded transition-colors cursor-pointer"
                  title="Click to copy CVE"
                >
                  <Tag size={10} />
                  {vuln.cve}
                  {copied ? <Check size={10} className="text-emerald-600 dark:text-emerald-400" /> : <Copy size={10} className="text-slate-400" />}
                </button>
              )}
            </div>
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100 leading-snug">{vuln.name}</h2>
          </div>
          <button
            onClick={onClose}
            className="shrink-0 p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors cursor-pointer"
          >
            <X size={15} />
          </button>
        </div>

        {/* SIH Navigation Tabs inside modal */}
        <div className="px-6 border-b border-slate-100 dark:border-slate-800 flex items-center gap-4 bg-slate-50/50 dark:bg-slate-900/50 text-xs">
          <button
            onClick={() => setActiveTab('overview')}
            className={`py-2.5 font-semibold border-b-2 transition-colors cursor-pointer ${
              activeTab === 'overview'
                ? 'border-teal-500 text-teal-600 dark:text-teal-400'
                : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            Overview &amp; Impact
          </button>
          <button
            onClick={() => setActiveTab('poc')}
            className={`py-2.5 font-semibold border-b-2 transition-colors cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'poc'
                ? 'border-teal-500 text-teal-600 dark:text-teal-400'
                : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            <Terminal size={12} />
            <span>Proof of Concept (PoC)</span>
          </button>
          <button
            onClick={() => setActiveTab('remediation')}
            className={`py-2.5 font-semibold border-b-2 transition-colors cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'remediation'
                ? 'border-teal-500 text-teal-600 dark:text-teal-400'
                : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            <Code2 size={12} />
            <span>Remediation Patch</span>
          </button>
        </div>

        {/* Body content based on activeTab */}
        <div className="px-6 py-5 space-y-4 overflow-y-auto flex-1">
          {activeTab === 'overview' && (
            <>
              {/* Description */}
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-wide text-slate-400 dark:text-slate-500 mb-1">
                  Vulnerability Description
                </p>
                <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed bg-slate-50 dark:bg-slate-800/60 p-3 rounded-lg border border-slate-100 dark:border-slate-800">
                  {vuln.description}
                </p>
              </div>

              {/* Business Impact Assessment (SIH PS 26163) */}
              {vuln.businessImpact && (
                <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/20">
                  <div className="flex items-center gap-1.5 text-xs font-bold text-amber-700 dark:text-amber-400 mb-1">
                    <AlertOctagon size={13} />
                    <span>Business Impact Assessment</span>
                  </div>
                  <p className="text-xs text-slate-700 dark:text-slate-300">
                    {vuln.businessImpact}
                  </p>
                </div>
              )}

              {/* Meta grid */}
              <div className="grid grid-cols-2 gap-3">
                <MetaBox label="Affected Component" value={vuln.component} />
                <MetaBox label="CVSS v3.1 Score" value={`${vuln.cvss} / 10.0`} mono />
              </div>

              {/* Risk bar */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <p className="text-[11px] font-semibold uppercase tracking-wide text-slate-400 dark:text-slate-500">
                    Exploitability Index
                  </p>
                  <span className="text-xs font-bold text-slate-700 dark:text-slate-300">{riskPct}%</span>
                </div>
                <div className="h-2 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{
                      width: `${riskPct}%`,
                      background: vuln.severity === 'Critical' ? '#ef4444' :
                                  vuln.severity === 'High'     ? '#f97316' :
                                  vuln.severity === 'Medium'   ? '#f59e0b' : '#10b981',
                    }}
                  />
                </div>
              </div>
            </>
          )}

          {activeTab === 'poc' && (
            <div className="space-y-4">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-wide text-slate-400 dark:text-slate-500 mb-1">
                  Controlled Environment Steps to Reproduce
                </p>
                {vuln.stepsToReproduce && vuln.stepsToReproduce.length > 0 ? (
                  <ol className="list-decimal list-inside space-y-1.5 text-xs text-slate-700 dark:text-slate-300 bg-slate-50 dark:bg-slate-800/60 p-3 rounded-lg border border-slate-100 dark:border-slate-800">
                    {vuln.stepsToReproduce.map((step, idx) => (
                      <li key={idx} className="leading-relaxed">{step}</li>
                    ))}
                  </ol>
                ) : (
                  <p className="text-xs text-slate-500 italic">No automated steps logged for this test.</p>
                )}
              </div>

              {vuln.pocPayload && (
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[11px] font-semibold uppercase tracking-wide text-slate-400 dark:text-slate-500">
                      Proof of Concept Command / Payload
                    </span>
                    <button
                      onClick={handleCopyPoc}
                      className="text-[11px] font-medium text-teal-600 dark:text-teal-400 flex items-center gap-1 cursor-pointer"
                    >
                      {copiedPoc ? <Check size={11} /> : <Copy size={11} />}
                      <span>{copiedPoc ? 'Copied' : 'Copy PoC'}</span>
                    </button>
                  </div>
                  <pre className="p-3 bg-slate-950 text-emerald-400 font-mono text-[11px] rounded-xl overflow-x-auto border border-slate-800">
                    {vuln.pocPayload}
                  </pre>
                </div>
              )}
            </div>
          )}

          {activeTab === 'remediation' && (
            <div className="space-y-4">
              <div className="p-3.5 rounded-xl bg-teal-500/10 border border-teal-500/20">
                <p className="text-xs font-semibold text-teal-800 dark:text-teal-300 mb-1 flex items-center gap-1.5">
                  <Wrench size={13} /> Practical Remediation Strategy
                </p>
                <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                  Adopt secure coding standards, input sanitation, and continuous automated pipeline scanning.
                </p>
              </div>

              {vuln.remediationCode && (
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[11px] font-semibold uppercase tracking-wide text-slate-400 dark:text-slate-500">
                      Recommended Patch Code Snippet
                    </span>
                    <button
                      onClick={handleCopyFix}
                      className="text-[11px] font-medium text-teal-600 dark:text-teal-400 flex items-center gap-1 cursor-pointer"
                    >
                      {copiedFix ? <Check size={11} /> : <Copy size={11} />}
                      <span>{copiedFix ? 'Copied' : 'Copy Code'}</span>
                    </button>
                  </div>
                  <pre className="p-3 bg-slate-950 text-sky-300 font-mono text-[11px] rounded-xl overflow-x-auto border border-slate-800">
                    {vuln.remediationCode}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between gap-3 bg-slate-50/50 dark:bg-slate-800/40">
          <div className="flex items-center gap-1 text-xs">
            <span className="text-slate-400">Triage:</span>
            {(['Open', 'In Progress', 'Fixed'] as Status[]).map((st) => (
              <button
                key={st}
                onClick={() => handleStatusToggle(st)}
                className={`px-2 py-0.5 rounded text-[10px] font-semibold border transition-all cursor-pointer ${
                  currentStatus === st
                    ? 'bg-teal-50 dark:bg-teal-950/60 border-teal-300 dark:border-teal-700 text-teal-700 dark:text-teal-300'
                    : 'border-slate-200 dark:border-slate-700 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800'
                }`}
              >
                {st}
              </button>
            ))}
          </div>

          <div className="flex gap-2">
            <button
              onClick={onClose}
              className="px-3 py-1.5 text-xs font-medium text-slate-600 dark:text-slate-300 rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-white dark:hover:bg-slate-800 transition-colors cursor-pointer"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

function MetaBox({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-100 dark:border-slate-800">
      <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-400 dark:text-slate-500 mb-0.5">{label}</p>
      <p className={`text-xs font-semibold text-slate-800 dark:text-slate-200 ${mono ? 'font-mono' : ''}`}>{value}</p>
    </div>
  )
}
