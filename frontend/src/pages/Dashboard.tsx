import { useState } from 'react'
import Sidebar from '../components/Sidebar'
import Topbar from '../components/Topbar'
import HeroBanner from '../components/HeroBanner'
import HealthStatCards from '../components/HealthStatCards'
import CoreWebVitals from '../components/CoreWebVitals'
import RecommendedFixesCard from '../components/RecommendedFixesCard'
import StatusAndQuote from '../components/StatusAndQuote'
import NetworkInspectView from '../components/NetworkInspectView'
import ChromeDevToolsSuite from '../components/ChromeDevToolsSuite'
import ScanModal from '../components/ScanModal'
import SecurityPosture from '../components/SecurityPosture'
import SecurityRadar from '../components/SecurityRadar'
import VulnDistribution from '../components/VulnDistribution'
import FindingsTable from '../components/FindingsTable'
import AttackSurfaceMap from '../components/AttackSurfaceMap'
import AiAssistant from '../components/AiAssistant'
import RecentActivity from '../components/RecentActivity'
import ReportSummary from '../components/ReportSummary'
import { Severity } from '../types'
import { useToast } from '../components/Toast'
import { Shield, Sparkles, Terminal, Activity, ChevronRight } from 'lucide-react'

export default function Dashboard() {
  const { toast } = useToast()
  const [activeTab, setActiveTab] = useState('dashboard')
  const [scanModalOpen, setScanModalOpen] = useState(false)
  const [isZeroData, setIsZeroData] = useState(false)
  const [targetUrl, setTargetUrl] = useState('https://worldmonitor.app')
  const [lastScanTime, setLastScanTime] = useState('28 Sep 2026, 12:52 PM')
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | 'All'>('All')

  const handleScan = (url: string) => {
    setLastScanTime('28 Sep 2026, 12:52 PM')
    setTargetUrl(url)
  }

  const handleToggleZeroData = () => {
    const next = !isZeroData
    setIsZeroData(next)
    toast(
      next ? 'info' : 'success',
      next ? 'Zero Data Mode Activated' : 'Sample Data Loaded',
      next
        ? 'Displaying clean baseline state with 0 active vulnerabilities'
        : 'Loaded 12 sample CVE findings and threat telemetry'
    )
  }

  const handleFilterSeverity = (sev: string) => {
    if (sev === 'Critical' || sev === 'High' || sev === 'Medium' || sev === 'Low') {
      setSelectedSeverity(sev)
    } else {
      setSelectedSeverity('All')
    }

    const tableEl = document.getElementById('findings-table-section')
    if (tableEl) {
      tableEl.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
  }

  const handleSelectMetric = (metricId: string) => {
    if (metricId === 'vulns' || metricId === 'best_practices') {
      setActiveTab('vulns')
    } else if (metricId === 'performance') {
      setActiveTab('inspect')
    }
  }

  return (
    <div className="flex h-screen overflow-hidden bg-slate-50 dark:bg-slate-950 font-sans transition-colors duration-200">
      {/* Sidebar with Navigation Tabs */}
      <Sidebar
        isZeroData={isZeroData}
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        onOpenScanModal={() => setScanModalOpen(true)}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Topbar */}
        <Topbar
          targetUrl={targetUrl}
          onTargetUrlChange={setTargetUrl}
          onSearch={(q) => setSearchQuery(q)}
          onScan={handleScan}
          isZeroData={isZeroData}
          onToggleZeroData={handleToggleZeroData}
        />

        {/* View Switcher Header Bar */}
        <div className="px-5 lg:px-7 py-2.5 bg-white/70 dark:bg-slate-900/60 border-b border-slate-200/80 dark:border-slate-800/80 flex items-center justify-between text-xs backdrop-blur-sm z-10">
          <div className="flex items-center gap-1.5 overflow-x-auto py-0.5">
            <button
              onClick={() => setActiveTab('dashboard')}
              className={`px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer ${
                activeTab === 'dashboard'
                  ? 'bg-teal-500 text-white shadow-sm'
                  : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              Dashboard Overview
            </button>
            <button
              onClick={() => setActiveTab('inspect')}
              className={`px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer flex items-center gap-1.5 ${
                activeTab === 'inspect'
                  ? 'bg-teal-500 text-white shadow-sm'
                  : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              <Activity size={13} />
              <span>Inspect &amp; Page Speed</span>
            </button>
            <button
              onClick={() => setScanModalOpen(true)}
              className="px-3 py-1.5 rounded-lg font-semibold text-teal-700 dark:text-teal-300 bg-teal-50 dark:bg-teal-950/50 border border-teal-200 dark:border-teal-800/80 hover:bg-teal-100/70 dark:hover:bg-teal-900/60 transition-all cursor-pointer flex items-center gap-1.5"
            >
              <Terminal size={13} />
              <span>Run Automated Scanner</span>
            </button>
            <button
              onClick={() => setActiveTab('vulns')}
              className={`px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer ${
                activeTab === 'vulns'
                  ? 'bg-teal-500 text-white shadow-sm'
                  : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              Vulnerabilities &amp; PoC
            </button>
            <button
              onClick={() => setActiveTab('ai-chat')}
              className={`px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer ${
                activeTab === 'ai-chat'
                  ? 'bg-teal-500 text-white shadow-sm'
                  : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              AI Security Copilot
            </button>
          </div>

          <div className="hidden md:flex items-center gap-2 text-slate-400 font-mono text-[11px]">
            <span>SIH PS 26163</span>
            <span>•</span>
            <span className="text-emerald-500 font-semibold">Ready</span>
          </div>
        </div>

        {/* Scrollable Dashboard Body */}
        <main className="flex-1 overflow-y-auto px-5 lg:px-7 py-6 space-y-6">
          <div className="max-w-[1600px] mx-auto space-y-6">

            {/* TAB: DASHBOARD OVERVIEW (Complete Image 1 UI) */}
            {activeTab === 'dashboard' && (
              <>
                {/* 1. Hero Welcome Banner (Score 92/100) + Quick Actions */}
                <HeroBanner
                  onRunCheck={() => setScanModalOpen(true)}
                  onViewReport={() => {
                    const tableEl = document.getElementById('findings-table-section')
                    if (tableEl) tableEl.scrollIntoView({ behavior: 'smooth', block: 'start' })
                  }}
                  onDownloadPdf={() =>
                    toast(
                      'success',
                      'PDF Export Complete',
                      'World Monitor Health & Security Executive Report downloaded successfully.'
                    )
                  }
                  lastCheckedTime={lastScanTime}
                  overallScore={92}
                />

                {/* 2. 4-Column Metric Cards with Glowing Sparklines */}
                <HealthStatCards onSelectMetric={handleSelectMetric} />

                {/* 3. Middle Section: Core Web Vitals (LCP, INP, CLS) + Recent Activity */}
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
                  <div className="lg:col-span-8 flex flex-col justify-between">
                    <CoreWebVitals onViewAll={() => setActiveTab('inspect')} />
                  </div>
                  <div className="lg:col-span-4 flex flex-col justify-between">
                    <RecentActivity isZeroData={isZeroData} />
                  </div>
                </div>

                {/* 4. Lower Section: Recommended Fixes + Status & Quote Cards */}
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
                  <div className="lg:col-span-8 flex flex-col justify-between">
                    <RecommendedFixesCard onSelectFix={() => setActiveTab('inspect')} />
                  </div>
                  <div className="lg:col-span-4 flex flex-col justify-between">
                    <StatusAndQuote onRunNewCheck={() => setScanModalOpen(true)} />
                  </div>
                </div>

                {/* 5. Security Assessment Section Header (SIH PS 26163) */}
                <div className="pt-4 border-t border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                      <Shield size={18} className="text-teal-500" />
                      <span>Security Posture &amp; Threat Telemetry</span>
                    </h2>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                      Vulnerability assessment across OWASP Top 10, Semgrep SAST, Gitleaks Secrets, and DAST
                    </p>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setScanModalOpen(true)}
                      className="btn-primary text-xs flex items-center gap-1.5 bg-teal-600 hover:bg-teal-700"
                    >
                      <Terminal size={13} />
                      <span>Run Pipeline Scan</span>
                    </button>
                  </div>
                </div>

                {/* Radar + Posture + Vuln Distribution */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 items-stretch">
                  <div className="lg:col-span-1 h-full">
                    <SecurityPosture
                      onFilterSeverity={handleFilterSeverity}
                      isZeroData={isZeroData}
                    />
                  </div>
                  <div className="lg:col-span-1 h-full">
                    <SecurityRadar isZeroData={isZeroData} />
                  </div>
                  <div className="lg:col-span-1 h-full">
                    <VulnDistribution
                      onSelectSeverity={handleFilterSeverity}
                      isZeroData={isZeroData}
                    />
                  </div>
                </div>

                {/* Findings Table + Copilot */}
                <div className="grid grid-cols-1 xl:grid-cols-3 gap-5 items-start">
                  <div className="xl:col-span-2 space-y-5">
                    <div id="findings-table-section">
                      <FindingsTable
                        searchQuery={searchQuery}
                        selectedSeverity={selectedSeverity}
                        isZeroData={isZeroData}
                        onLoadSample={() => setIsZeroData(false)}
                        onTriggerScan={() => setScanModalOpen(true)}
                      />
                    </div>
                    <AttackSurfaceMap isZeroData={isZeroData} />
                  </div>

                  <div className="xl:col-span-1 space-y-5">
                    <AiAssistant />
                  </div>
                </div>

                {/* Report Summary */}
                <ReportSummary
                  targetUrl={targetUrl}
                  onSelectSeverity={handleFilterSeverity}
                  isZeroData={isZeroData}
                />
              </>
            )}

            {/* TAB: INSPECT & CHROME DEVTOOLS SUITE */}
            {activeTab === 'inspect' && (
              <div className="space-y-6">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                      <Terminal size={20} className="text-teal-500" />
                      <span>Chrome DevTools &amp; Network Inspect Suite</span>
                    </h1>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                      Complete Chrome Inspect panel (Network, Performance, Memory, Application, Security, Console) with live vulnerability telemetry
                    </p>
                  </div>
                  <button
                    onClick={() => setActiveTab('dashboard')}
                    className="btn-secondary text-xs flex items-center gap-1 shrink-0"
                  >
                    <span>Back to Overview</span>
                    <ChevronRight size={13} />
                  </button>
                </div>

                {/* The Full Chrome DevTools Suite (Matching 5 user screenshots) */}
                <ChromeDevToolsSuite
                  targetUrl={targetUrl}
                  onInspectVuln={() => setActiveTab('vulns')}
                />

                {/* Per-Page Speed & Route Matrix */}
                <NetworkInspectView
                  targetUrl={targetUrl}
                  onInspectVuln={() => setActiveTab('vulns')}
                />
              </div>
            )}

            {/* TAB: VULNERABILITIES & POC */}
            {activeTab === 'vulns' && (
              <div className="space-y-6">
                <div className="flex items-center justify-between">
                  <div>
                    <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                      <Shield size={20} className="text-teal-500" />
                      <span>Documented Vulnerabilities &amp; Proof-of-Concepts (PoC)</span>
                    </h1>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                      Deliverables for SIH Problem Statement 26163: CVSS ratings, reproduction steps, safe PoC payloads, and remediation patches
                    </p>
                  </div>
                  <button
                    onClick={() => setScanModalOpen(true)}
                    className="btn-primary text-xs flex items-center gap-1.5 bg-teal-600 hover:bg-teal-700"
                  >
                    <Terminal size={13} />
                    <span>Run New Scan</span>
                  </button>
                </div>

                <FindingsTable
                  searchQuery={searchQuery}
                  selectedSeverity={selectedSeverity}
                  isZeroData={isZeroData}
                  onLoadSample={() => setIsZeroData(false)}
                  onTriggerScan={() => setScanModalOpen(true)}
                />

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                  <AttackSurfaceMap isZeroData={isZeroData} />
                  <AiAssistant />
                </div>
              </div>
            )}

            {/* TAB: AI SECURITY COPILOT */}
            {activeTab === 'ai-chat' && (
              <div className="space-y-6 max-w-4xl mx-auto">
                <div className="text-center space-y-1">
                  <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100 flex items-center justify-center gap-2">
                    <Sparkles className="text-teal-500" size={20} />
                    <span>AI Security Chatbot (NLP + RAG)</span>
                  </h1>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Box 3 in Architecture Workflow: Knowledge retrieval from CVE databases, project code, and automated scan results
                  </p>
                </div>

                <AiAssistant />
              </div>
            )}

            {/* TAB: REPORTS */}
            {activeTab === 'reports' && (
              <div className="space-y-6">
                <ReportSummary
                  targetUrl={targetUrl}
                  onSelectSeverity={handleFilterSeverity}
                  isZeroData={isZeroData}
                />
              </div>
            )}
          </div>
        </main>
      </div>

      {/* Automated Scan Orchestration Modal (Image 2 Workflow) */}
      <ScanModal
        isOpen={scanModalOpen}
        onClose={() => setScanModalOpen(false)}
        onScanComplete={() => {
          setIsZeroData(false)
          setLastScanTime('28 Sep 2026, 12:52 PM')
        }}
      />
    </div>
  )
}
