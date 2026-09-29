'use client'

import { useState } from 'react'
import {
  LayoutDashboard, ShieldCheck, Bug, Activity,
  FileText, Globe, ChevronDown, KeyRound, LogOut, UserCheck, Sun, Moon, Bot, Settings
} from 'lucide-react'
import { useToast } from './Toast'
import { useTheme } from '../context/ThemeContext'

interface SidebarProps {
  isZeroData?: boolean
  activeTab?: string
  onSelectTab?: (tab: string) => void
  onOpenScanModal?: () => void
}

const navItems = [
  { id: 'dashboard',   icon: LayoutDashboard, label: 'Dashboard' },
  { id: 'admin',       icon: Settings,        label: 'Admin & Target Setup' },
  { id: 'inspect',     icon: Activity,        label: 'Inspect & Speed' },
  { id: 'scan',        icon: ShieldCheck,     label: 'Security Scan' },
  { id: 'vulns',       icon: Bug,             label: 'Vulnerabilities & PoC' },
  { id: 'ai-chat',     icon: Bot,             label: 'AI Copilot' },
  { id: 'reports',     icon: FileText,        label: 'Executive Reports' },
]

import Link from 'next/link'
import { useAppSelector } from '../store'

export default function Sidebar({
  isZeroData = false,
  activeTab = 'dashboard',
  onSelectTab,
  onOpenScanModal,
}: SidebarProps) {
  const findingsCount = useAppSelector((st) => st.findings.items.length)
  const { toast } = useToast()
  const { theme, toggleTheme } = useTheme()

  const handleNavClick = (id: string, _label: string) => {
    onSelectTab?.(id)
  }

  const handleAskAi = () => {
    onSelectTab?.('ai-chat')
    const aiInput = document.getElementById('ai-assistant-input')
    if (aiInput) {
      aiInput.scrollIntoView({ behavior: 'smooth', block: 'center' })
      aiInput.focus()
    }
  }

  return (
    <aside className="w-56 shrink-0 h-screen bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 flex flex-col relative z-20 transition-colors duration-200">
      {/* Brand */}
      <div className="px-4 py-4 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="sidebar-brand-bar w-8 h-8 rounded-lg flex items-center justify-center shadow-sm">
            <Globe size={16} className="text-white" />
          </div>
          <div>
            <p className="text-sm font-bold text-slate-900 dark:text-slate-100 leading-tight">
              World<span className="text-teal-600 dark:text-teal-400">Monitor</span>
            </p>
            <p className="text-[10px] text-slate-400 leading-tight mt-0.5 font-mono">SEC-OPS v2.4</p>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 flex flex-col gap-1 overflow-y-auto">
        {navItems.map(({ id, icon: Icon, label }) => {
          const isActive = activeTab === id
          return (
            <button
              key={id}
              onClick={() => handleNavClick(id, label)}
              className={`nav-item w-full text-left cursor-pointer transition-colors ${isActive ? 'active' : ''}`}
            >
              <Icon size={15} className="shrink-0" />
              <span className="text-xs font-medium truncate">{label}</span>
              {id === 'vulns' && (
                <span className={`ml-auto text-[10px] font-bold px-1.5 py-0.2 rounded-full ${
                  isZeroData
                    ? 'bg-emerald-100 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400'
                    : 'bg-red-100 dark:bg-red-950/60 text-red-600 dark:text-red-400'
                }`}>
                  {findingsCount}
                </span>
              )}
            </button>
          )
        })}
        <Link href="/admin" className="nav-item w-full text-left mt-2 border-t border-slate-100 dark:border-slate-800 pt-3">
          <Settings size={15} className="shrink-0" />
          <span className="text-xs font-medium truncate">Full Admin Panel</span>
        </Link>
      </nav>

      {/* AI Assistant Promo Box */}
      <div className="m-3 p-3 rounded-xl bg-gradient-to-br from-teal-50 to-emerald-50 dark:from-slate-800/80 dark:to-teal-950/40 border border-teal-100 dark:border-teal-900/50 shadow-sm">
        <div className="flex items-center gap-1.5 mb-1">
          <span className="w-2 h-2 rounded-full bg-teal-500 animate-pulse" />
          <p className="text-xs font-semibold text-teal-900 dark:text-teal-300">AI Security Copilot</p>
        </div>
        <p className="text-[11px] text-teal-700 dark:text-slate-400 leading-relaxed mb-2.5">
          Explains findings &amp; drafts fixes from stored scan results
        </p>
        <button
          onClick={handleAskAi}
          className="w-full py-1.5 rounded-lg bg-teal-600 hover:bg-teal-700 text-white text-xs font-medium transition-all shadow-sm cursor-pointer flex items-center justify-center gap-1"
        >
          Ask AI Copilot →
        </button>
      </div>

      {/* Theme quick switch & user profile */}
      <div className="border-t border-slate-100 dark:border-slate-800">
        <div className="px-3 py-2 flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 border-b border-slate-100 dark:border-slate-800/60">
          <span className="text-[11px]">Appearance</span>
          <button
            onClick={toggleTheme}
            className="flex items-center gap-1.5 px-2 py-1 rounded-md hover:bg-slate-100 dark:hover:bg-slate-800 text-[11px] font-medium transition-colors cursor-pointer text-slate-700 dark:text-slate-200"
          >
            {theme === 'dark' ? (
              <>
                <Sun size={12} className="text-amber-400" />
                <span>Dark</span>
              </>
            ) : (
              <>
                <Moon size={12} className="text-teal-600" />
                <span>Light</span>
              </>
            )}
          </button>
        </div>

        <div className="px-3 py-3 flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-full bg-teal-100 dark:bg-teal-950/80 border border-teal-200 dark:border-teal-800 flex items-center justify-center shrink-0">
            <span className="text-[11px] font-bold text-teal-700 dark:text-teal-400">SA</span>
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-xs font-semibold text-slate-800 dark:text-slate-200 truncate">Security Analyst</p>
            <p className="text-[10px] text-slate-400 truncate">Local session · loopback only, no login</p>
          </div>
        </div>
      </div>
    </aside>
  )
}
