import { useEffect } from 'react'
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
import AdminPanel from '../components/AdminPanel'
import { Severity } from '../types'
import { useToast } from '../components/Toast'
import { Shield, Sparkles, Terminal, Activity, ChevronRight, Settings } from 'lucide-react'
import { useAppDispatch, useAppSelector } from '../store'
import {
  toggleZeroData,
  setZeroData,
  setSeverityFilter,
  setSearchQuery,
  fetchFindingsAsync,
} from '../store/slices/findingsSlice'
import {
  setActiveTab,
  setTargetUrl,
  setLastScanTime,
  setScanModalOpen,
  fetchHealthAsync,
} from '../store/slices/assessmentSlice'
import { fetchDevToolsAllAsync } from '../store/slices/devtoolsSlice'
import { fetchRecommendationsAsync } from '../store/slices/copilotSlice'
import { fetchRadarAsync, fetchAttackSurfaceAsync, fetchNetworkInspectAsync } from '../store/slices/telemetrySlice'

export default function Dashboard() {
  const { toast } = useToast()
  const dispatch = useAppDispatch()

  const { targetUrl, activeTab, lastScanTime, scanModalOpen } = useAppSelector(
    (state) => state.assessment
  )
  const { isZeroData, searchQuery, severityFilter } = useAppSelector(
    (state) => state.findings
  )

  useEffect(() => {
    // Initial global background telemetry bootstrap
    dispatch(fetchFindingsAsync())
    dispatch(fetchHealthAsync())
    dispatch(fetchDevToolsAllAsync(targetUrl))
    dispatch(fetchRecommendationsAsync())
    dispatch(fetchRadarAsync())
    dispatch(fetchAttackSurfaceAsync())
    dispatch(fetchNetworkInspectAsync(targetUrl))
  }, [dispatch, targetUrl])

  const handleScan = (url: string) => {
    dispatch(setLastScanTime('28 Sep 2026, 12:52 PM'))
    dispatch(setTargetUrl(url))
  }

  const handleToggleZeroData = () => {
    dispatch(toggleZeroData())
    const next = !isZeroData
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
      dispatch(setSeverityFilter(sev as Severity))
    } else {
      dispatch(setSeverityFilter('All'))
    }

    const tableEl = document.getElementById('findings-table-section')
    if (tableEl) {
      tableEl.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
  }

  const handleSelectMetric = (metricId: string) => {
    if (metricId === 'vulns' || metricId === 'best_practices') {
      dispatch(setActiveTab('vulns'))
    } else if (metricId === 'performance') {
      dispatch(setActiveTab('inspect'))
    }
  }

  return (
    <div className="flex h-screen overflow-hidden bg-slate-50 dark:bg-slate-950 font-sans transition-colors duration-200">
      {/* Sidebar with Navigation Tabs */}
      <Sidebar
        isZeroData={isZeroData}
        activeTab={activeTab}
        onSelectTab={(tab) => dispatch(setActiveTab(tab))}
        onOpenScanModal={() => dispatch(setScanModalOpen(true))}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Topbar */}
        <Topbar
          targetUrl={targetUrl}
          onTargetUrlChange={(url) => dispatch(setTargetUrl(url))}
          onSearch={(q) => dispatch(setSearchQuery(q))}
          onScan={handleScan}
          isZeroData={isZeroData}
          onToggleZeroData={handleToggleZeroData}
        />

        {/* View Switcher Header Bar */}
        <div className="px-5 lg:px-7 py-2.5 bg-white/70 dark:bg-slate-900/60 border-b border-slate-200/80 dark:border-slate-800/80 flex items-center justify-between text-xs backdrop-blur-sm z-10">
          <div className="flex items-center gap-1.5 overflow-x-auto py-0.5">
            <button
              onClick={() => dispatch(setActiveTab('dashboard'))}
              className={`px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer ${
                activeTab === 'dashboard'
                  ? 'bg-teal-500 text-white shadow-sm'
                  : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              Dashboard Overview
            </button>
            <button
              onClick={() => dispatch(setActiveTab('admin'))}
              className={`px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer flex items-center gap-1.5 ${
                activeTab === 'admin'
                  ? 'bg-teal-500 text-white shadow-sm'
                  : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              <Settings size={13} />
              <span>Admin &amp; Target Setup</span>
            </button>
            <button
              onClick={() => dispatch(setActiveTab('inspect'))}
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
              onClick={() => dispatch(setScanModalOpen(true))}
              className="px-3 py-1.5 rounded-lg font-semibold text-teal-700 dark:text-teal-300 bg-teal-50 dark:bg-teal-950/50 border border-teal-200 dark:border-teal-800/80 hover:bg-teal-100/70 dark:hover:bg-teal-900/60 transition-all cursor-pointer flex items-center gap-1.5"
            >
              <Terminal size={13} />
              <span>Run Automated Scanner</span>
            </button>
            <button
              onClick={() => dispatch(setActiveTab('vulns'))}
              className={`px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer ${
                activeTab === 'vulns'
                  ? 'bg-teal-500 text-white shadow-sm'
                  : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              Vulnerabilities &amp; PoC
            </button>
            <button
              onClick={() => dispatch(setActiveTab('ai-chat'))}
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
                  onRunCheck={() => dispatch(setScanModalOpen(true))}
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
                    <CoreWebVitals onViewAll={() => dispatch(setActiveTab('inspect'))} />
                  </div>
                  <div className="lg:col-span-4 flex flex-col justify-between">
                    <RecentActivity isZeroData={isZeroData} />
                  </div>
                </div>

                {/* 4. Lower Section: Recommended Fixes + Status & Quote Cards */}
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
                  <div className="lg:col-span-8 flex flex-col justify-between">
                    <RecommendedFixesCard onSelectFix={() => dispatch(setActiveTab('inspect'))} />
                  </div>
                  <div className="lg:col-span-4 flex flex-col justify-between">
                    <StatusAndQuote onRunNewCheck={() => dispatch(setScanModalOpen(true))} />
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
                      onClick={() => dispatch(setScanModalOpen(true))}
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
                        selectedSeverity={severityFilter}
                        isZeroData={isZeroData}
                        onLoadSample={() => dispatch(setZeroData(false))}
                        onTriggerScan={() => dispatch(setScanModalOpen(true))}
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

            {/* TAB: ADMIN & TARGET SETUP */}
            {activeTab === 'admin' && (
              <AdminPanel
                onScanComplete={() => {
                  toast('success', 'Target Ready', 'Target configured and synchronized with live assessment engine.')
                }}
                onNavigateToFindings={() => dispatch(setActiveTab('vulns'))}
              />
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
                    onClick={() => dispatch(setActiveTab('dashboard'))}
                    className="btn-secondary text-xs flex items-center gap-1 shrink-0"
                  >
                    <span>Back to Overview</span>
                    <ChevronRight size={13} />
                  </button>
                </div>

                {/* The Full Chrome DevTools Suite (Matching 5 user screenshots) */}
                <ChromeDevToolsSuite
                  targetUrl={targetUrl}
                  onInspectVuln={() => dispatch(setActiveTab('vulns'))}
                />

                {/* Per-Page Speed & Route Matrix */}
                <NetworkInspectView
                  targetUrl={targetUrl}
                  onInspectVuln={() => dispatch(setActiveTab('vulns'))}
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
                    onClick={() => dispatch(setScanModalOpen(true))}
                    className="btn-primary text-xs flex items-center gap-1.5 bg-teal-600 hover:bg-teal-700"
                  >
                    <Terminal size={13} />
                    <span>Run New Scan</span>
                  </button>
                </div>

                <FindingsTable
                  searchQuery={searchQuery}
                  selectedSeverity={severityFilter}
                  isZeroData={isZeroData}
                  onLoadSample={() => dispatch(setZeroData(false))}
                  onTriggerScan={() => dispatch(setScanModalOpen(true))}
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
        onClose={() => dispatch(setScanModalOpen(false))}
        onScanComplete={() => {
          dispatch(toggleZeroData())
          dispatch(setLastScanTime('28 Sep 2026, 12:52 PM'))
        }}
      />
    </div>
  )
}
