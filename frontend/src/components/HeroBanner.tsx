'use client'

import { useState } from 'react'
import { Zap, FileText, Download, ChevronRight, Clock, CheckCircle2, Globe } from 'lucide-react'
import { useToast } from './Toast'
import { useAppSelector } from '../store'
import { DEFAULT_WEBSITE_URL } from '../lib/targets'

interface HeroBannerProps {
  onRunCheck?: () => void
  onViewReport?: () => void
  onDownloadPdf?: () => void
  lastCheckedTime?: string
  overallScore?: number | null
  targetUrl?: string
}

export default function HeroBanner({
  onRunCheck,
  onViewReport,
  onDownloadPdf,
  lastCheckedTime = 'Never',
  overallScore = null,
  targetUrl = DEFAULT_WEBSITE_URL,
}: HeroBannerProps) {
  const { toast } = useToast()
  const heroFindings = useAppSelector((st) => st.findings.items)
  const heroCrit = heroFindings.filter((f) => (f.severity || '').toUpperCase() === 'CRITICAL').length
  const heroHeadline = heroFindings.length === 0 ? 'No findings yet' : heroCrit > 0 ? `${heroCrit} critical issue${heroCrit > 1 ? 's' : ''} need attention` : `${heroFindings.length} candidate findings to review`
  const summary = useAppSelector((st) => st.summary.data)

  const domain = (() => {
    try {
      const u = targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`
      return new URL(u).hostname.replace(/^www\./, '')
    } catch {
      return targetUrl
    }
  })()


  // Opens the real scan pipeline; nothing is simulated here.
  const handleRunCheck = () => onRunCheck?.()

  const handleViewReport = () => {
    onViewReport?.()
    const targetEl = document.getElementById('findings-table-section') || document.getElementById('report-summary-section')
    if (targetEl) {
      targetEl.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
  }

  const handleDownloadPdf = () => {
    onDownloadPdf?.()
  }

  // Calculate circular SVG stroke dash
  const radius = 46
  const circumference = 2 * Math.PI * radius
  const strokeDashoffset = circumference - ((overallScore ?? 0) / 100) * circumference
  const scoreLabel =
    overallScore === null ? 'Not measured' : overallScore >= 90 ? 'Excellent' : overallScore >= 75 ? 'Good' : overallScore >= 50 ? 'Needs work' : 'Poor'
  const scoreTone =
    overallScore === null
      ? 'bg-slate-500/15 border-slate-500/30 text-slate-600 dark:text-slate-300'
      : overallScore >= 75
        ? 'bg-emerald-500/15 dark:bg-emerald-500/20 border-emerald-500/30 text-emerald-700 dark:text-emerald-400'
        : overallScore >= 50
          ? 'bg-amber-500/15 border-amber-500/30 text-amber-700 dark:text-amber-400'
          : 'bg-red-500/15 border-red-500/30 text-red-700 dark:text-red-400'

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
      {/* ─── Hero Banner Card (Left ~70%) ─── */}
      <div className="lg:col-span-8 xl:col-span-9 relative overflow-hidden rounded-2xl border border-teal-500/20 dark:border-teal-500/30 bg-gradient-to-br from-emerald-50 via-teal-50/60 to-cyan-50 dark:from-[#081822] dark:via-[#09222c] dark:to-[#072d36] shadow-sm dark:shadow-xl dark:shadow-teal-950/20 p-6 sm:p-7 flex flex-col justify-between transition-all duration-300">
        
        {/* Artistic SVG Background with Mountains, Aurora glow waves, and Hiker Silhouette */}
        <div className="absolute inset-0 pointer-events-none select-none overflow-hidden">
          {/* Subtle aurora glow spotlight */}
          <div className="absolute top-0 right-1/4 w-96 h-96 bg-emerald-400/10 dark:bg-emerald-500/15 rounded-full blur-3xl -translate-y-1/2" />
          <div className="absolute bottom-0 right-10 w-80 h-80 bg-teal-400/15 dark:bg-teal-500/20 rounded-full blur-2xl translate-y-1/3" />

          {/* SVG Mountains & Nature Landscape (Image 2 aesthetic) */}
          <svg
            className="absolute right-0 bottom-0 w-full md:w-3/5 h-full opacity-40 dark:opacity-55 object-cover"
            viewBox="0 0 600 240"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
            preserveAspectRatio="none"
          >
            <defs>
              <linearGradient id="mountainGrad1" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#10b981" stopOpacity="0.3" />
                <stop offset="100%" stopColor="#042f2e" stopOpacity="0.8" />
              </linearGradient>
              <linearGradient id="mountainGrad2" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#14b8a6" stopOpacity="0.4" />
                <stop offset="100%" stopColor="#064e3b" stopOpacity="0.9" />
              </linearGradient>
              <linearGradient id="auroraWave" x1="0" y1="0" x2="1" y2="0">
                <stop offset="0%" stopColor="#2dd4bf" stopOpacity="0.1" />
                <stop offset="50%" stopColor="#34d399" stopOpacity="0.6" />
                <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.2" />
              </linearGradient>
            </defs>

            {/* Distant Mountain Range */}
            <path
              d="M100 240 L220 120 L290 160 L390 80 L480 150 L560 100 L600 130 L600 240 Z"
              fill="url(#mountainGrad1)"
              opacity="0.5"
            />

            {/* Mid Mountain Range */}
            <path
              d="M180 240 L300 140 L360 175 L460 110 L540 180 L600 145 L600 240 Z"
              fill="url(#mountainGrad2)"
              opacity="0.75"
            />

            {/* Foreground gentle hill */}
            <path
              d="M320 240 Q440 160 600 190 L600 240 Z"
              fill="#062e33"
              className="fill-teal-900/40 dark:fill-[#041a1e]"
            />

            {/* Glowing Aurora Wave Lines across the bottom */}
            <path
              d="M0 220 Q150 180 300 205 T600 185"
              stroke="url(#auroraWave)"
              strokeWidth="2.5"
              fill="none"
            />
            <path
              d="M0 230 Q180 195 350 215 T600 195"
              stroke="url(#auroraWave)"
              strokeWidth="1.5"
              strokeDasharray="4 2"
              fill="none"
              opacity="0.7"
            />

            {/* Silhouette of Hiker with pole on the right ridge */}
            <g transform="translate(435, 125) scale(0.75)" className="fill-slate-800 dark:fill-emerald-200/80">
              {/* Head */}
              <circle cx="20" cy="8" r="4.5" />
              {/* Hat brim */}
              <ellipse cx="20" cy="7" rx="7" ry="1.5" />
              {/* Torso & Backpack */}
              <path d="M16 13 L24 13 L23 28 L17 28 Z" />
              <path d="M12 15 Q10 20 12 25 L16 25 L16 15 Z" />
              {/* Legs walking */}
              <line x1="18" y1="28" x2="13" y2="44" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
              <line x1="22" y1="28" x2="28" y2="42" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
              {/* Arms & Trekking pole */}
              <line x1="17" y1="17" x2="28" y2="25" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              <line x1="27" y1="12" x2="33" y2="46" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </g>

            {/* Handwriting text styling "Better Health Brighter Future" with heart */}
            <g transform="translate(420, 185)" className="fill-teal-800/80 dark:fill-teal-200/70">
              <text
                x="0"
                y="0"
                fontSize="12"
                fontFamily="cursive, sans-serif"
                fontStyle="italic"
                fontWeight="500"
                letterSpacing="0.5"
              >
                Better Health
              </text>
              <text
                x="6"
                y="14"
                fontSize="12"
                fontFamily="cursive, sans-serif"
                fontStyle="italic"
                fontWeight="500"
                letterSpacing="0.5"
              >
                Brighter Future ♡
              </text>
            </g>
          </svg>
        </div>

        {/* Content: Left Greeting & Headline + Right Score Gauge */}
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          {/* Left Textual Details */}
          <div className="space-y-3 max-w-xl">
            <div className="flex items-center gap-1.5 text-sm font-medium text-teal-800/80 dark:text-teal-300/90">
              <span>Security assessment summary</span>
            </div>

            <h1 className="text-2xl sm:text-3xl lg:text-[2rem] font-extrabold tracking-tight text-slate-900 dark:text-white leading-tight">
              {heroHeadline}
            </h1>

            <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-300 font-normal leading-relaxed max-w-lg">
              Assessment of <strong className="font-semibold">{domain}</strong>:{' '}
              {summary
                ? `${summary.findings.total} unverified candidate finding(s) from ${summary.coverage.tools_run.length} of ${summary.coverage.tools_expected.length} scanners.`
                : 'waiting for the assessment backend.'}
            </p>

            {/* Last Checked & Target Status Pills */}
            <div className="pt-1 flex items-center gap-2 flex-wrap">
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/80 dark:bg-slate-900/60 backdrop-blur-md border border-teal-200 dark:border-teal-500/25 text-xs text-slate-700 dark:text-teal-200 shadow-sm">
                <Clock size={13} className="text-teal-600 dark:text-teal-400" />
                <span>Last checked: {lastCheckedTime}</span>
              </div>
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-teal-500/10 dark:bg-teal-400/10 backdrop-blur-md border border-teal-300 dark:border-teal-500/30 text-xs font-medium text-teal-800 dark:text-teal-200 shadow-sm">
                <Globe size={13} className="text-sky-600 dark:text-sky-400" />
                <span>Target: <strong className="font-semibold">{domain}</strong></span>
              </div>
            </div>
          </div>

          {/* Right Circular Progress Ring Score */}
          <div className="flex flex-col items-center justify-center shrink-0 pr-2 sm:pr-4">
            <div className="relative flex items-center justify-center">
              {/* Outer SVG Gauge Ring */}
              <svg width="128" height="128" className="transform -rotate-90">
                <defs>
                  <linearGradient id="gaugeGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" stopColor="#10b981" />
                    <stop offset="50%" stopColor="#14b8a6" />
                    <stop offset="100%" stopColor="#22d3ee" />
                  </linearGradient>
                  <filter id="gaugeGlow" x="-20%" y="-20%" width="140%" height="140%">
                    <feDropShadow dx="0" dy="0" stdDeviation="4" floodColor="#14b8a6" floodOpacity="0.4" />
                  </filter>
                </defs>

                {/* Track Circle */}
                <circle
                  cx="64"
                  cy="64"
                  r={radius}
                  fill="transparent"
                  stroke="currentColor"
                  strokeWidth="8"
                  className="text-slate-200 dark:text-slate-800/80"
                />

                {/* Animated Progress Circle */}
                <circle
                  cx="64"
                  cy="64"
                  r={radius}
                  fill="transparent"
                  stroke="url(#gaugeGradient)"
                  strokeWidth="8"
                  strokeDasharray={circumference}
                  strokeDashoffset={strokeDashoffset}
                  strokeLinecap="round"
                  filter="url(#gaugeGlow)"
                  className="transition-all duration-1000 ease-out"
                />
              </svg>

              {/* Inside Score Value */}
              <div className="absolute inset-0 flex flex-col items-center justify-center text-center select-none">
                <div className="flex items-baseline">
                  <span className="text-3xl font-extrabold tracking-tight text-slate-900 dark:text-white">
                    {overallScore ?? '--'}
                  </span>
                  <span className="text-xs font-semibold text-slate-500 dark:text-slate-400">
                    /100
                  </span>
                </div>
              </div>
            </div>

            {/* Score labels below */}
            <div className="mt-2 text-center">
              <p className="text-xs font-semibold text-slate-700 dark:text-slate-200">
                Overall score (measured)
              </p>
              <div className={`mt-1.5 inline-flex items-center gap-1 px-3 py-0.5 rounded-full border text-[11px] font-semibold ${scoreTone}`}>
                <CheckCircle2 size={11} />
                <span>{scoreLabel}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ─── Quick Actions Card (Right ~30%) ─── */}
      <div className="lg:col-span-4 xl:col-span-3 rounded-2xl border border-slate-200/90 dark:border-slate-800 bg-white dark:bg-[#0c1322] shadow-sm dark:shadow-xl p-5 sm:p-6 flex flex-col justify-between transition-all duration-300">
        <div>
          {/* Card Title */}
          <div className="flex items-center gap-2 mb-4">
            <div className="p-1.5 rounded-lg bg-sky-50 dark:bg-sky-500/15 text-sky-600 dark:text-sky-400">
              <Zap size={16} className="fill-current" />
            </div>
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
              Quick Actions
            </h2>
          </div>

          {/* Action List items */}
          <div className="space-y-3">
            {/* Action 1: Run Full Check */}
            <button
              onClick={handleRunCheck}
                            className="w-full flex items-center justify-between p-3 rounded-xl border border-slate-100 dark:border-slate-800/80 bg-slate-50/70 dark:bg-slate-900/60 hover:bg-emerald-50/60 dark:hover:bg-emerald-950/30 hover:border-emerald-200 dark:hover:border-emerald-800/60 transition-all duration-200 text-left group cursor-pointer"
            >
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-emerald-100 dark:bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 flex items-center justify-center shrink-0 group-hover:scale-105 transition-transform">
                  <CheckCircle2 size={18} />
                </div>
                <div>
                  <p className="text-xs sm:text-sm font-semibold text-slate-900 dark:text-slate-100 group-hover:text-emerald-600 dark:group-hover:text-emerald-400 transition-colors">
                    Run full assessment
                  </p>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    All scanners + web audit
                  </p>
                </div>
              </div>
              <ChevronRight size={15} className="text-slate-400 dark:text-slate-500 group-hover:text-emerald-600 dark:group-hover:text-emerald-400 group-hover:translate-x-0.5 transition-all" />
            </button>

            {/* Action 2: View Report */}
            <button
              onClick={handleViewReport}
              className="w-full flex items-center justify-between p-3 rounded-xl border border-slate-100 dark:border-slate-800/80 bg-slate-50/70 dark:bg-slate-900/60 hover:bg-sky-50/60 dark:hover:bg-sky-950/30 hover:border-sky-200 dark:hover:border-sky-800/60 transition-all duration-200 text-left group cursor-pointer"
            >
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-sky-100 dark:bg-sky-500/20 text-sky-600 dark:text-sky-400 flex items-center justify-center shrink-0 group-hover:scale-105 transition-transform">
                  <FileText size={18} />
                </div>
                <div>
                  <p className="text-xs sm:text-sm font-semibold text-slate-900 dark:text-slate-100 group-hover:text-sky-600 dark:group-hover:text-sky-400 transition-colors">
                    View Report
                  </p>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    Detailed analysis
                  </p>
                </div>
              </div>
              <ChevronRight size={15} className="text-slate-400 dark:text-slate-500 group-hover:text-sky-600 dark:group-hover:text-sky-400 group-hover:translate-x-0.5 transition-all" />
            </button>

            {/* Action 3: Download PDF */}
            <button
              onClick={handleDownloadPdf}
              className="w-full flex items-center justify-between p-3 rounded-xl border border-slate-100 dark:border-slate-800/80 bg-slate-50/70 dark:bg-slate-900/60 hover:bg-purple-50/60 dark:hover:bg-purple-950/30 hover:border-purple-200 dark:hover:border-purple-800/60 transition-all duration-200 text-left group cursor-pointer"
            >
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-purple-100 dark:bg-purple-500/20 text-purple-600 dark:text-purple-400 flex items-center justify-center shrink-0 group-hover:scale-105 transition-transform">
                  <Download size={18} />
                </div>
                <div>
                  <p className="text-xs sm:text-sm font-semibold text-slate-900 dark:text-slate-100 group-hover:text-purple-600 dark:group-hover:text-purple-400 transition-colors">
                    Download report
                  </p>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    PDF from stored findings
                  </p>
                </div>
              </div>
              <ChevronRight size={15} className="text-slate-400 dark:text-slate-500 group-hover:text-purple-600 dark:group-hover:text-purple-400 group-hover:translate-x-0.5 transition-all" />
            </button>
          </div>
        </div>

        {/* Small security verification note */}
        <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400 dark:text-slate-500">
          <span className="flex items-center gap-1.5">
            <span className={`w-1.5 h-1.5 rounded-full ${summary?.target.healthy ? 'bg-emerald-500 animate-pulse' : 'bg-red-500'}`} />
            {summary ? (summary.target.healthy ? 'Target online' : 'Target offline') : 'Backend unreachable'}
          </span>
          <span className="font-mono text-[10px]">{summary ? `${summary.coverage.tools_run.length}/${summary.coverage.tools_expected.length} scanners run` : ''}</span>
        </div>
      </div>
    </div>
  )
}
