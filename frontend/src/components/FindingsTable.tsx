import { useState, useMemo } from 'react'
import { Vulnerability, Severity, Status } from '../types'
import { severityClass, statusClass } from '../utils'
import { ArrowUpRight, ChevronRight, Filter, Download, ArrowUpDown, Search, ShieldCheck, RefreshCw } from 'lucide-react'
import VulnModal from './VulnModal'
import { useToast } from './Toast'
import { useAppDispatch, useAppSelector } from '../store'
import {
  fetchFindingsAsync,
  updateStatusOptimistic,
  setSeverityFilter,
  setStatusFilter,
  setSearchQuery,
} from '../store/slices/findingsSlice'

interface Props {
  searchQuery?: string
  selectedSeverity?: Severity | 'All'
  isZeroData?: boolean
  onLoadSample?: () => void
  onTriggerScan?: () => void
}

export default function FindingsTable({
  searchQuery: propSearchQuery,
  selectedSeverity: propSelectedSeverity,
  isZeroData: propIsZeroData,
  onLoadSample,
  onTriggerScan,
}: Props) {
  const { toast } = useToast()
  const dispatch = useAppDispatch()

  const storeFindings = useAppSelector((state) => state.findings)
  const vulns = storeFindings.items
  const isLiveBackend = storeFindings.isLiveBackend
  const loading = storeFindings.isLoading
  const isZeroData = propIsZeroData !== undefined ? propIsZeroData : storeFindings.isZeroData
  const severityFilter = propSelectedSeverity !== undefined ? propSelectedSeverity : storeFindings.severityFilter
  const statusFilter = storeFindings.statusFilter
  const activeSearch = propSearchQuery !== undefined ? propSearchQuery : storeFindings.searchQuery

  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null)
  const [localSearch, setLocalSearch] = useState('')
  const [sortAsc, setSortAsc] = useState(false)
  const [showAll, setShowAll] = useState(false)

  const reloadFindings = () => {
    dispatch(fetchFindingsAsync())
  }

  // When isZeroData is true, active findings list is empty []
  const activeVulnList = isZeroData ? [] : vulns

  const handleStatusChange = (id: number | string, newStatus: Status) => {
    // 0ms Optimistic UI update in Redux
    dispatch(updateStatusOptimistic({ id, status: newStatus }))
  }

  const filteredVulns = useMemo(() => {
    return activeVulnList
      .filter((v) => {
        if (severityFilter !== 'All' && v.severity !== severityFilter) return false
        if (statusFilter !== 'All' && v.status !== statusFilter) return false
        const q = (activeSearch || localSearch).toLowerCase().trim()
        if (!q) return true
        return (
          v.name.toLowerCase().includes(q) ||
          v.description.toLowerCase().includes(q) ||
          v.component.toLowerCase().includes(q) ||
          (v.cve && v.cve.toLowerCase().includes(q))
        )
      })
      .sort((a, b) => (sortAsc ? a.cvss - b.cvss : b.cvss - a.cvss))
  }, [activeVulnList, severityFilter, statusFilter, activeSearch, localSearch, sortAsc])

  const displayedVulns = showAll ? filteredVulns : filteredVulns.slice(0, 6)

  const handleExportCsv = () => {
    if (filteredVulns.length === 0) {
      toast('info', 'No Data to Export', 'There are zero vulnerabilities detected in the current view.')
      return
    }
    const headers = 'ID,Name,Severity,Component,CVSS,Status,CVE\n'
    const rows = filteredVulns.map(v => `"${v.id}","${v.name}","${v.severity}","${v.component}","${v.cvss}","${v.status}","${v.cve || ''}"`).join('\n')
    const blob = new Blob([headers + rows], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.setAttribute('download', `security_findings_${new Date().toISOString().split('T')[0]}.csv`)
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    toast('success', 'CSV Exported', `Exported ${filteredVulns.length} vulnerabilities`)
  }

  return (
    <div className="card flex flex-col">
      {/* Header & Controls */}
      <div className="px-5 py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 dark:border-slate-800">
        <div className="flex items-center gap-2">
          <span className="w-1.5 h-4 rounded-full bg-indigo-500" />
          <h2 className="text-sm font-semibold text-slate-800 dark:text-slate-100">Security Findings</h2>
          <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-full ${
            filteredVulns.length === 0
              ? 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400'
              : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300'
          }`}>
            {filteredVulns.length}
          </span>
          {isLiveBackend && (
            <span className="flex items-center gap-1 text-[10px] font-mono font-medium px-2 py-0.5 rounded-full bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              Live Backend
            </span>
          )}
          <button
            onClick={reloadFindings}
            disabled={loading}
            className="p-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors cursor-pointer"
            title="Reload from backend"
          >
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Quick inline search */}
          <div className="relative">
            <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              value={localSearch}
              onChange={(e) => {
                setLocalSearch(e.target.value)
                dispatch(setSearchQuery(e.target.value))
              }}
              placeholder="Filter findings..."
              className="pl-7 pr-2.5 py-1 text-xs rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80 text-slate-800 dark:text-slate-200 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-indigo-300 w-36"
            />
          </div>

          {/* Sort CVSS */}
          <button
            onClick={() => setSortAsc(!sortAsc)}
            className="flex items-center gap-1 px-2.5 py-1 text-xs rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 transition-colors cursor-pointer"
            title="Sort by CVSS score"
          >
            <ArrowUpDown size={11} />
            <span>CVSS {sortAsc ? '↑' : '↓'}</span>
          </button>

          {/* Export CSV */}
          <button
            onClick={handleExportCsv}
            className="flex items-center gap-1 px-2.5 py-1 text-xs rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 transition-colors cursor-pointer"
            title="Export findings to CSV"
          >
            <Download size={11} />
            <span className="hidden sm:inline">Export</span>
          </button>

          {/* View All toggle */}
          {!isZeroData && (
            <button
              onClick={() => setShowAll(!showAll)}
              className="flex items-center gap-1 text-xs text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-300 font-medium transition-colors px-2 py-1 rounded hover:bg-indigo-50 dark:hover:bg-indigo-950/40 cursor-pointer"
            >
              {showAll ? 'Show Top 6' : `View All (${filteredVulns.length})`} <ArrowUpRight size={12} />
            </button>
          )}
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="px-5 py-2.5 border-b border-slate-100 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/30 flex items-center justify-between gap-3 overflow-x-auto">
        <div className="flex items-center gap-1.5 shrink-0">
          <span className="text-[11px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider mr-1 flex items-center gap-1">
            <Filter size={10} /> Severity:
          </span>
          {(['All', 'Critical', 'High', 'Medium', 'Low'] as (Severity | 'All')[]).map((sev) => (
            <button
              key={sev}
              onClick={() => dispatch(setSeverityFilter(sev))}
              className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-all cursor-pointer ${
                severityFilter === sev
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-200/60 dark:hover:bg-slate-700/60'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-1.5 shrink-0">
          <span className="text-[11px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider mr-1">
            Status:
          </span>
          {(['All', 'Open', 'In Progress', 'Fixed'] as (Status | 'All')[]).map((st) => (
            <button
              key={st}
              onClick={() => dispatch(setStatusFilter(st))}
              className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                statusFilter === st
                  ? 'bg-slate-800 dark:bg-slate-700 text-white'
                  : 'text-slate-500 dark:text-slate-400 hover:bg-slate-200/50 dark:hover:bg-slate-800'
              }`}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {/* Table Content */}
      <div className="overflow-x-auto">
        {filteredVulns.length === 0 ? (
          <div className="py-12 px-6 flex flex-col items-center justify-center text-center">
            <div className="w-12 h-12 rounded-2xl bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 flex items-center justify-center mb-3 text-emerald-600 dark:text-emerald-400 shadow-sm">
              <ShieldCheck size={26} />
            </div>
            <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-100">
              {isZeroData ? 'Zero Vulnerabilities Detected' : 'No matching vulnerabilities'}
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 max-w-sm mt-1 mb-4 leading-relaxed">
              {isZeroData
                ? 'Current security audit reflects 0 active vulnerabilities or CVE exposures. System is in a clean baseline state.'
                : 'No findings match the selected filters or search query.'}
            </p>
            {isZeroData && (
              <div className="flex items-center gap-2">
                <button
                  onClick={onTriggerScan}
                  className="btn-primary text-xs flex items-center gap-1.5 cursor-pointer"
                >
                  <RefreshCw size={12} /> Run Target Scan
                </button>
                {onLoadSample && (
                  <button
                    onClick={onLoadSample}
                    className="btn-secondary text-xs flex items-center gap-1.5 cursor-pointer"
                  >
                    Load Sample Findings (12)
                  </button>
                )}
              </div>
            )}
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-100 dark:border-slate-800 bg-slate-50/20 dark:bg-slate-800/10">
                <th className="pl-5 pr-2 py-2.5 text-left text-[11px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wide w-8">#</th>
                <th className="px-2 py-2.5 text-left text-[11px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wide">Vulnerability</th>
                <th className="px-2 py-2.5 text-left text-[11px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wide">Severity</th>
                <th className="px-2 py-2.5 text-left text-[11px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wide hidden lg:table-cell">Affected Component</th>
                <th className="px-2 py-2.5 text-left text-[11px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wide">CVSS</th>
                <th className="px-2 py-2.5 text-left text-[11px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wide">Status</th>
                <th className="pr-3 py-2.5 w-6" />
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-50 dark:divide-slate-800/60">
              {displayedVulns.map((v) => (
                <tr
                  key={v.id}
                  onClick={() => setSelectedVuln(v)}
                  className="table-row-hover group cursor-pointer"
                  title="Click to view full vulnerability details & remediation"
                >
                  <td className="pl-5 pr-2 py-3 text-xs text-slate-400 dark:text-slate-500 font-mono">{v.id}</td>
                  <td className="px-2 py-3">
                    <p className="font-medium text-slate-800 dark:text-slate-200 text-xs leading-snug group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition-colors">
                      {v.name}
                    </p>
                    <p className="text-[11px] text-slate-400 dark:text-slate-500 mt-0.5 line-clamp-1">{v.description}</p>
                    {v.cve && (
                      <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500 mt-0.5 inline-block">{v.cve}</span>
                    )}
                  </td>
                  <td className="px-2 py-3">
                    <span className={severityClass(v.severity)}>{v.severity}</span>
                  </td>
                  <td className="px-2 py-3 hidden lg:table-cell">
                    <span className="text-xs text-slate-500 dark:text-slate-400 font-mono text-[11px]">{v.component}</span>
                  </td>
                  <td className="px-2 py-3">
                    <span className="text-xs font-mono font-semibold text-slate-700 dark:text-slate-300">{v.cvss}</span>
                  </td>
                  <td className="px-2 py-3">
                    <span className={statusClass(v.status)}>{v.status}</span>
                  </td>
                  <td className="pr-3 py-3">
                    <ChevronRight size={13} className="text-slate-300 dark:text-slate-600 group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition-transform group-hover:translate-x-0.5" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Row details modal */}
      <VulnModal
        vuln={selectedVuln ? vulns.find((v) => v.id === selectedVuln.id) || selectedVuln : null}
        onClose={() => setSelectedVuln(null)}
        onStatusChange={handleStatusChange}
      />
    </div>
  )
}
