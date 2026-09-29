'use client'

import { useState, useRef, useEffect } from 'react'
import {
  Bell, Search, RefreshCw, Globe, Copy, Check,
  ChevronDown, X, Sun, Moon, Activity
} from 'lucide-react'
import { useToast } from './Toast'
import { useTheme } from '../context/ThemeContext'
import NotificationDropdown from './NotificationDropdown'
import { useAppSelector } from '../store'

interface TopbarProps {
  targetUrl: string
  onTargetUrlChange: (url: string) => void
  onSearch?: (query: string) => void
  onScan?: (url: string) => void
}

// Only the isolated local target is in scope (loopback allowlist); external hosts are rejected by the backend.
const PRESET_TARGETS = [
  { label: 'World Monitor (local, isolated)', url: 'http://127.0.0.1:3000', status: 'In scope' },
]

export default function Topbar({
  targetUrl,
  onTargetUrlChange,
  onSearch,
  onScan,
}: TopbarProps) {
  const summary = useAppSelector((st) => st.summary.data)
  const findingCount = useAppSelector((st) => st.findings.items.length)
  const notificationCount = summary?.notifications.length ?? 0
  const { toast } = useToast()
  const { theme, toggleTheme } = useTheme()
  const [isScanning, setIsScanning] = useState(false)
  const [copied, setCopied] = useState(false)
  const [notifOpen, setNotifOpen] = useState(false)
  const [searchVal, setSearchVal] = useState('')
  const [inputUrl, setInputUrl] = useState(targetUrl)
  const [presetsOpen, setPresetsOpen] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)

  const targetDomain = (() => {
    try {
      const u = targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`
      return new URL(u).hostname.replace(/^www\./, '')
    } catch {
      return targetUrl
    }
  })()

  useEffect(() => {
    setInputUrl(targetUrl)
  }, [targetUrl])

  useEffect(() => {
    const handleOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setPresetsOpen(false)
      }
    }
    document.addEventListener('mousedown', handleOutside)
    return () => document.removeEventListener('mousedown', handleOutside)
  }, [])

  const triggerScan = (urlToScan: string) => {
    if (isScanning) return
    let cleanUrl = urlToScan.trim() || 'http://127.0.0.1:3000'
    if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
      cleanUrl = 'http://' + cleanUrl
    }

    onTargetUrlChange(cleanUrl)
    setInputUrl(cleanUrl)
    setIsScanning(true)
    // Refreshes the dashboard from stored results. Real scanning is started from "Run Automated Scanner".
    toast('info', 'Refreshing data', `Reloading stored findings and live telemetry for ${cleanUrl}`)
    onScan?.(cleanUrl)
    setTimeout(() => setIsScanning(false), 800)
  }

  const handleUrlKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      triggerScan(inputUrl)
    }
  }

  const handleSelectPreset = (url: string) => {
    setInputUrl(url)
    setPresetsOpen(false)
    triggerScan(url)
  }

  const handleCopyUrl = () => {
    navigator.clipboard?.writeText(inputUrl)
    setCopied(true)
    toast('success', 'URL Copied', `Copied ${inputUrl} to clipboard`)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value
    setSearchVal(val)
    onSearch?.(val)
  }

  return (
    <header className="h-16 shrink-0 bg-white dark:bg-slate-900 border-b border-slate-200/80 dark:border-slate-800 flex items-center justify-between px-5 gap-3.5 relative z-30 transition-colors duration-200">
      {/* Left: Search Input */}
      <div className="relative w-56 sm:w-64 lg:w-72 shrink-0">
        <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
        <input
          type="text"
          value={searchVal}
          onChange={handleSearchChange}
          placeholder="Search CVEs, endpoints, findings..."
          className="w-full pl-9 pr-7 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50/80 dark:bg-slate-800/80 text-slate-800 dark:text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-sky-500/20 focus:border-sky-500 focus:bg-white dark:focus:bg-slate-800 transition"
        />
        {searchVal && (
          <button
            onClick={() => { setSearchVal(''); onSearch?.('') }}
            className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 p-0.5 cursor-pointer"
            title="Clear search"
          >
            <X size={12} />
          </button>
        )}
      </div>

      {/* Middle & Right: Actions Bar */}
      <div className="flex items-center gap-2.5 flex-wrap justify-end">
        {/* Target status (real health check + stored findings) */}
        <div
          className={`flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded-lg border shadow-sm ${
            summary?.target.healthy
              ? 'bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800 text-emerald-700 dark:text-emerald-300'
              : 'bg-red-50 dark:bg-red-950/40 border-red-300 dark:border-red-800 text-red-700 dark:text-red-300'
          }`}
          title={summary?.target.message || 'Target status unknown'}
        >
          <Activity size={13} className={summary?.target.healthy ? 'animate-pulse' : ''} />
          <span>
            <strong className="font-semibold">{targetDomain}</strong> {summary ? (summary.target.healthy ? 'online' : 'offline') : '...'} · {findingCount} findings
          </span>
        </div>

        {/* Target URL Address Bar & Scanner */}
        <div ref={dropdownRef} className="relative flex items-center">
          <div className="flex items-center bg-slate-50/80 dark:bg-slate-800/80 hover:bg-slate-100/80 dark:hover:bg-slate-800 focus-within:bg-white dark:focus-within:bg-slate-800 border border-slate-200 dark:border-slate-700 focus-within:border-sky-500 focus-within:ring-2 focus-within:ring-sky-500/20 rounded-lg transition-all h-9 px-2.5 gap-2 shadow-sm">
            {/* Live Indicator + Globe */}
            <div className="flex items-center gap-1.5 shrink-0">
              <span className={`w-2 h-2 rounded-full ${summary?.target.healthy ? 'bg-emerald-500' : 'bg-red-500'} animate-pulse`} />
              <Globe size={13} className="text-slate-400" />
            </div>

            {/* Target URL Input */}
            <input
              type="text"
              value={inputUrl}
              onChange={(e) => setInputUrl(e.target.value)}
              onKeyDown={handleUrlKeyDown}
              placeholder="Enter target URL"
              className="w-40 sm:w-56 lg:w-64 text-xs font-mono text-slate-800 dark:text-slate-200 bg-transparent focus:outline-none placeholder-slate-400"
              title="Target URL for vulnerability assessment"
            />

            {/* Copy button */}
            <button
              onClick={handleCopyUrl}
              className="p-1 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 rounded transition-colors cursor-pointer"
              title="Copy Target URL"
            >
              {copied ? <Check size={12} className="text-emerald-600 dark:text-emerald-400" /> : <Copy size={12} />}
            </button>

            {/* Presets dropdown toggle */}
            <button
              onClick={() => setPresetsOpen(!presetsOpen)}
              className="p-1 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 rounded transition-colors border-l border-slate-200 dark:border-slate-700 pl-1.5 cursor-pointer"
              title="Select from configured targets"
            >
              <ChevronDown size={12} className={`transition-transform ${presetsOpen ? 'rotate-180' : ''}`} />
            </button>
          </div>

          {/* Presets Dropdown Menu */}
          {presetsOpen && (
            <div className="absolute top-full right-0 mt-1.5 w-72 bg-white dark:bg-slate-900 rounded-xl shadow-xl border border-slate-200 dark:border-slate-800 py-1.5 z-50 animate-dropdown-in">
              <div className="px-3 py-1.5 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between">
                <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                  Target Endpoints
                </span>
                <span className="text-[10px] text-sky-600 dark:text-sky-400 font-medium">In-scope target only</span>
              </div>
              <div className="divide-y divide-slate-50 dark:divide-slate-800">
                {PRESET_TARGETS.map(t => (
                  <button
                    key={t.url}
                    onClick={() => handleSelectPreset(t.url)}
                    className={`w-full px-3 py-2 text-left hover:bg-slate-50 dark:hover:bg-slate-800 flex items-center justify-between transition-colors cursor-pointer ${
                      targetUrl === t.url ? 'bg-sky-50/50 dark:bg-sky-950/40' : ''
                    }`}
                  >
                    <div>
                      <p className="text-xs font-semibold text-slate-800 dark:text-slate-200">{t.label}</p>
                      <p className="text-[11px] font-mono text-slate-400 mt-0.5">{t.url}</p>
                    </div>
                    <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-emerald-50 dark:bg-emerald-950/50 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800 font-medium">
                      {t.status}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Scan Button */}
        <button
          onClick={() => triggerScan(inputUrl)}
          disabled={isScanning}
          className="btn-primary text-xs h-9 px-3.5 flex items-center gap-1.5 shrink-0 cursor-pointer shadow-sm"
        >
          <RefreshCw size={13} className={isScanning ? 'animate-spin' : ''} />
          <span>{isScanning ? 'Refreshing...' : 'Refresh'}</span>
        </button>

        {/* Dark Mode Toggle */}
        <button
          onClick={toggleTheme}
          className="p-2 rounded-lg text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-700 transition-colors cursor-pointer"
          title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Mode`}
          aria-label="Toggle Dark Mode"
        >
          {theme === 'dark' ? (
            <Sun size={16} className="text-amber-400 hover:rotate-45 transition-transform" />
          ) : (
            <Moon size={16} className="text-slate-600 hover:-rotate-12 transition-transform" />
          )}
        </button>

        {/* Notifications bell */}
        <div className="relative shrink-0">
          <button
            onClick={() => setNotifOpen(!notifOpen)}
            className={`relative p-2 rounded-lg border border-slate-200 dark:border-slate-700 transition-colors cursor-pointer ${
              notifOpen
                ? 'bg-sky-50 dark:bg-sky-950/50 text-sky-600 dark:text-sky-400'
                : 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300'
            }`}
            title="Notifications"
            aria-label="Open notifications"
          >
            <Bell size={16} />
            {notificationCount > 0 && (
              <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full border-2 border-white dark:border-slate-900" />
            )}
          </button>

          <NotificationDropdown open={notifOpen} onClose={() => setNotifOpen(false)} />
        </div>
      </div>
    </header>
  )
}
