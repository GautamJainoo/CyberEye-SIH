import { useState } from 'react'
import { FileDown, FileText, Code2, Loader2, ShieldCheck, Download } from 'lucide-react'
import { useToast } from './Toast'
import { vulnerabilities } from '../data'

interface ReportSummaryProps {
  onSelectSeverity?: (sev: string) => void
  targetUrl?: string
  isZeroData?: boolean
}

export default function ReportSummary({
  onSelectSeverity,
  targetUrl = 'https://worldmonitor.app',
  isZeroData = false,
}: ReportSummaryProps) {
  const { toast } = useToast()
  const [downloadingFormat, setDownloadingFormat] = useState<string | null>(null)

  const handleDownload = (format: 'PDF' | 'JSON' | 'HTML') => {
    setDownloadingFormat(format)
    toast('info', `Preparing ${format} Export`, `Compiling SIH PS 26163 Security Assessment...`)

    setTimeout(() => {
      let content = ''
      let mimeType = 'text/plain'
      let fileExt = 'txt'

      if (format === 'JSON') {
        mimeType = 'application/json'
        fileExt = 'json'
        content = JSON.stringify(
          {
            reportId: 'SIH-PS26163-AUDIT',
            title: 'Security Assessment of the World Monitor application',
            target: targetUrl,
            sourceCode: 'https://github.com/koala73/worldmonitor',
            generatedAt: new Date().toISOString(),
            overallPosture: isZeroData ? 'Clean (0 findings)' : 'Medium Risk (68/100)',
            scanTools: ['Semgrep (SAST)', 'Gitleaks (Secrets)', 'OSV-Scanner (SCA)', 'OWASP ZAP (DAST)'],
            findingsCount: isZeroData ? 0 : vulnerabilities.length,
            findings: isZeroData ? [] : vulnerabilities,
          },
          null,
          2
        )
      } else if (format === 'HTML') {
        mimeType = 'text/html'
        fileExt = 'html'
        content = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>World Monitor Security Assessment Report</title>
  <style>
    body { font-family: system-ui, sans-serif; padding: 32px; max-width: 900px; margin: auto; background: #0b0f1a; color: #e2e8f0; }
    h1 { color: #14b8a6; }
    .badge { padding: 4px 8px; border-radius: 4px; font-weight: bold; }
    .critical { background: rgba(239,68,68,0.2); color: #f87171; border: 1px solid #ef4444; }
    pre { background: #020617; padding: 12px; border-radius: 8px; overflow-x: auto; color: #38bdf8; }
  </style>
</head>
<body>
  <h1>World Monitor Security Assessment Report (SIH PS 26163)</h1>
  <p><strong>Target:</strong> ${targetUrl} | <strong>Source:</strong> https://github.com/koala73/worldmonitor</p>
  <p><strong>Status:</strong> ${isZeroData ? 'CLEAN (Zero Active Findings)' : 'Vulnerabilities Identified'}</p>
  <hr/>
  <h2>Documented Vulnerabilities & Proof of Concept</h2>
  ${(isZeroData ? [] : vulnerabilities)
    .map(
      (v) => `
    <div>
      <h3>${v.name} <span class="badge critical">${v.severity} - CVSS ${v.cvss}</span></h3>
      <p><strong>Component:</strong> ${v.component}</p>
      <p>${v.description}</p>
      ${v.pocPayload ? `<p><strong>Safe PoC:</strong></p><pre>${v.pocPayload}</pre>` : ''}
    </div>`
    )
    .join('')}
</body>
</html>`
      } else {
        // PDF / Plain text format
        mimeType = 'text/plain'
        fileExt = 'pdf.txt'
        content = `WORLD MONITOR SECURITY ASSESSMENT REPORT (SIH PS 26163)
Generated: ${new Date().toLocaleString()}
Target: ${targetUrl}
Source Code: https://github.com/koala73/worldmonitor
Theme: Smart Automation
--------------------------------------------------
Risk Level: ${isZeroData ? 'Clean (0)' : 'Medium (68/100)'}
Critical Issues: ${isZeroData ? 0 : 2}
High Issues: ${isZeroData ? 0 : 2}
Total Findings: ${isZeroData ? 0 : vulnerabilities.length}
--------------------------------------------------
Scanning Modules Applied:
• 6.1 SAST (Semgrep)
• 6.2 Secret Scanning (Gitleaks)
• 6.3 SCA (OSV-Scanner)
• 6.4 DAST (OWASP ZAP)

Executive Summary:
Authorized security audit of the World Monitor platform completed.
Key identified vulnerabilities documented with CVSS ratings,
controlled environment reproduction steps, proof of concept payloads,
and mitigation recommendations.`
      }

      const blob = new Blob([content], { type: mimeType })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `WorldMonitor_Security_Report_${new Date().toISOString().split('T')[0]}.${fileExt}`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)

      setDownloadingFormat(null)
      toast('success', `${format} Export Ready`, `Assessment report downloaded successfully.`)
    }, 900)
  }

  return (
    <div className="card px-5 py-4 flex flex-wrap items-center justify-between gap-4">
      {/* Title */}
      <div className="flex items-center gap-2">
        {isZeroData ? (
          <ShieldCheck size={16} className="text-emerald-500" />
        ) : (
          <FileText size={16} className="text-teal-600 dark:text-teal-400" />
        )}
        <span className="text-xs font-semibold text-slate-800 dark:text-slate-100">
          Executive Compliance &amp; Assessment Reports
        </span>
      </div>

      {/* Meta indicators */}
      <div className="flex items-center gap-6 flex-wrap text-xs text-slate-600 dark:text-slate-300">
        <div>
          <span className="text-slate-400 dark:text-slate-500 mr-1.5">Application:</span>
          <span className="font-semibold text-slate-800 dark:text-slate-200 font-mono text-[11px]">
            {targetUrl.replace(/^https?:\/\//, '').replace(/\/.*$/, '')}
          </span>
        </div>
        <div>
          <span className="text-slate-400 dark:text-slate-500 mr-1.5">Risk Level:</span>
          {isZeroData ? (
            <span className="inline-block px-2 py-0.5 rounded text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 font-semibold text-[11px]">
              Clean (0)
            </span>
          ) : (
            <span className="inline-block px-2 py-0.5 rounded text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/60 border border-amber-200 dark:border-amber-800 font-semibold text-[11px]">
              Medium (68)
            </span>
          )}
        </div>
        <button
          onClick={() => {
            onSelectSeverity?.('Critical')
            toast('info', 'Filter: Critical', `Showing critical priority security vulnerabilities`)
          }}
          className="flex items-center hover:bg-slate-100 dark:hover:bg-slate-800 px-2 py-1 rounded transition-colors cursor-pointer"
        >
          <span className="text-slate-400 dark:text-slate-500 mr-1.5">Critical:</span>
          <span className={`font-bold ${isZeroData ? 'text-slate-500 dark:text-slate-400' : 'text-red-600 dark:text-red-400'}`}>
            {isZeroData ? 0 : 2}
          </span>
        </button>
        <button
          onClick={() => {
            onSelectSeverity?.('High')
            toast('info', 'Filter: High', `Showing high priority security vulnerabilities`)
          }}
          className="flex items-center hover:bg-slate-100 dark:hover:bg-slate-800 px-2 py-1 rounded transition-colors cursor-pointer"
        >
          <span className="text-slate-400 dark:text-slate-500 mr-1.5">High:</span>
          <span className={`font-bold ${isZeroData ? 'text-slate-500 dark:text-slate-400' : 'text-orange-600 dark:text-orange-400'}`}>
            {isZeroData ? 0 : 2}
          </span>
        </button>
        <div>
          <span className="text-slate-400 dark:text-slate-500 mr-1.5">Total Findings:</span>
          <span className="font-bold text-slate-800 dark:text-slate-200">
            {isZeroData ? 0 : vulnerabilities.length}
          </span>
        </div>
      </div>

      {/* Download Action Buttons (PDF, JSON, HTML) */}
      <div className="flex items-center gap-2 flex-wrap">
        <button
          onClick={() => handleDownload('PDF')}
          disabled={downloadingFormat !== null}
          className="btn-primary text-xs flex items-center gap-1.5 cursor-pointer disabled:opacity-50 bg-teal-600 hover:bg-teal-700"
        >
          {downloadingFormat === 'PDF' ? <Loader2 size={13} className="animate-spin" /> : <FileDown size={13} />}
          Export PDF
        </button>
        <button
          onClick={() => handleDownload('JSON')}
          disabled={downloadingFormat !== null}
          className="btn-secondary text-xs flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
        >
          {downloadingFormat === 'JSON' ? <Loader2 size={13} className="animate-spin" /> : <Download size={13} />}
          Export JSON
        </button>
        <button
          onClick={() => handleDownload('HTML')}
          disabled={downloadingFormat !== null}
          className="btn-secondary text-xs flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
        >
          {downloadingFormat === 'HTML' ? <Loader2 size={13} className="animate-spin" /> : <Code2 size={13} />}
          Export HTML
        </button>
      </div>
    </div>
  )
}
