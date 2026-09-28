import { useState } from 'react'
import { Bot, Send, Sparkles, Copy, Check, ChevronDown, ChevronUp } from 'lucide-react'
import { useToast } from './Toast'

interface Recommendation {
  id: number
  priority: string
  color: string
  bg: string
  border: string
  dot: string
  title: string
  impact: string
  fix: string
  codeSnippet?: string
}

const allRecommendations: Recommendation[] = [
  {
    id: 1,
    priority: 'Critical Priority',
    color: 'text-red-600 dark:text-red-400',
    bg: 'bg-red-50 dark:bg-red-950/30',
    border: 'border-red-200 dark:border-red-900/50',
    dot: 'bg-red-500',
    title: 'SQL Injection in /api/search.',
    impact: 'Full database exfiltration possible.',
    fix: 'Use parameterized queries with prepared statements.',
    codeSnippet: 'const rows = await db.query("SELECT * FROM items WHERE title = $1", [param]);',
  },
  {
    id: 2,
    priority: 'High Priority',
    color: 'text-orange-600 dark:text-orange-400',
    bg: 'bg-orange-50 dark:bg-orange-950/30',
    border: 'border-orange-200 dark:border-orange-900/50',
    dot: 'bg-orange-500',
    title: 'Detected insecure JWT storage in localStorage.',
    impact: 'Account takeover via XSS script execution.',
    fix: 'Store tokens in HttpOnly, Secure, SameSite=Strict cookies.',
    codeSnippet: 'res.cookie("token", jwt, { httpOnly: true, secure: true, sameSite: "strict" });',
  },
  {
    id: 3,
    priority: 'Medium Priority',
    color: 'text-amber-600 dark:text-amber-400',
    bg: 'bg-amber-50 dark:bg-amber-950/30',
    border: 'border-amber-200 dark:border-amber-900/50',
    dot: 'bg-amber-500',
    title: 'No rate limiting on /api/login.',
    impact: 'Brute-force credential stuffing feasible.',
    fix: 'Add exponential backoff after 5 attempts via Redis token bucket.',
    codeSnippet: 'limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });',
  },
  {
    id: 4,
    priority: 'Medium Priority',
    color: 'text-amber-600 dark:text-amber-400',
    bg: 'bg-amber-50 dark:bg-amber-950/30',
    border: 'border-amber-200 dark:border-amber-900/50',
    dot: 'bg-amber-500',
    title: 'Missing Content-Security-Policy (CSP) headers.',
    impact: 'Inline script injection possible on untrusted DOM nodes.',
    fix: "Set Content-Security-Policy: default-src 'self'; script-src 'self'.",
    codeSnippet: "app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: [\"'self'\"] } }));",
  },
]

export default function AiAssistant() {
  const { toast } = useToast()
  const [showAll, setShowAll] = useState(false)
  const [query, setQuery] = useState('')
  const [messages, setMessages] = useState<Array<{ sender: 'user' | 'ai'; text: string; code?: string }>>([])
  const [isTyping, setIsTyping] = useState(false)
  const [copiedId, setCopiedId] = useState<number | null>(null)

  const displayedRecs = showAll ? allRecommendations : allRecommendations.slice(0, 2)

  const handleCopy = (rec: Recommendation) => {
    if (rec.codeSnippet) {
      navigator.clipboard?.writeText(rec.codeSnippet)
    } else {
      navigator.clipboard?.writeText(rec.fix)
    }
    setCopiedId(rec.id)
    toast('success', 'Code Copied', 'Remediation snippet copied to clipboard')
    setTimeout(() => setCopiedId(null), 2000)
  }

  const handleAsk = (promptText?: string) => {
    const textToSend = promptText || query.trim()
    if (!textToSend) return

    setMessages(prev => [...prev, { sender: 'user', text: textToSend }])
    if (!promptText) setQuery('')
    setIsTyping(true)

    setTimeout(() => {
      setIsTyping(false)
      let reply = "Here is the recommended security patch for this issue."
      let code = undefined

      const lower = textToSend.toLowerCase()
      if (lower.includes('scan on my code') || lower.includes('security scan')) {
        reply = "Initiating multi-module scan job across World Monitor codebase. Launching Semgrep SAST for pattern matching, Gitleaks for exposed tokens, OSV-Scanner for third-party CVEs, and OWASP ZAP for runtime probes."
        code = "celery -A scan_orchestrator worker --concurrency=4 -l info"
      } else if (lower.includes('what vulnerabilities') || lower.includes('vulnerabilities were found')) {
        reply = "Scan results identified 5 high-priority findings on World Monitor:\n1. SQL Injection in /api/search (CVSS 9.8 Critical)\n2. Broken Access Control / IDOR on /api/users/:id (CVSS 8.3 High)\n3. Hardcoded Secret Key in config (CVSS 9.1 Critical)\n4. Outdated Lodash prototype pollution (CVSS 6.8 Medium)\n5. Missing Rate Limiting on password reset (CVSS 7.5 High)."
      } else if (lower.includes('sql') || lower.includes('explain the sql injection')) {
        reply = "In worldmonitor/api/search.py, query parameter `q` is concatenated directly into SQL without sanitization. An attacker can inject `' OR 1=1--` to bypass authentication and dump the entire database."
        code = "const query = 'SELECT * FROM findings WHERE query_text ILIKE $1';\nconst res = await db.query(query, ['%' + searchParam + '%']);"
      } else if (lower.includes('how to fix') || lower.includes('fix this issue')) {
        reply = "Remediation Strategy: 1. Replace raw SQL strings with prepared statement bindings. 2. Implement role-based access control (RBAC) middleware. 3. Rotate and vault all hardcoded keys."
        code = "// Secure Parameterized Query\ndb.query('SELECT * FROM accounts WHERE id = $1', [userId])"
      } else if (lower.includes('summary report') || lower.includes('give a summary')) {
        reply = "World Monitor Security Executive Summary: Overall Risk Score: 68/100 (Medium). 2 Critical, 2 High, 1 Medium vulnerabilities found. 100% of findings validated in controlled testing. Compliance rating: OWASP Top 10 Action Needed."
      } else if (lower.includes('jwt') || lower.includes('token')) {
        reply = "Never store JWTs in browser localStorage. Issue an HttpOnly, Secure, SameSite=Strict cookie:"
        code = "res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'strict' })"
      } else if (lower.includes('rate') || lower.includes('brute')) {
        reply = "Mount express-rate-limit middleware on authentication and password reset routes:"
        code = "app.use('/api/auth/reset', rateLimit({ windowMs: 15 * 60 * 1000, max: 5 }))"
      } else {
        reply = `RAG Analysis for "${textToSend}": Verify OWASP Top 10 vectors, enforce TLS 1.3, and run automated regression tests.`
      }

      setMessages(prev => [...prev, { sender: 'ai', text: reply, code }])
      toast('success', 'AI Recommendation Ready', 'Copilot generated fix analysis')
    }, 600)
  }

  return (
    <div className="card p-5 flex flex-col gap-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg bg-indigo-100 dark:bg-indigo-950/80 flex items-center justify-center">
            <Bot size={15} className="text-indigo-600 dark:text-indigo-400" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-slate-800 dark:text-slate-100">AI Security Copilot</h2>
            <p className="text-[10px] text-slate-400 dark:text-slate-500">Context-aware remediation engine</p>
          </div>
        </div>
        <span className="text-[10px] px-2 py-0.5 rounded-full bg-indigo-50 dark:bg-indigo-950/60 text-indigo-600 dark:text-indigo-400 border border-indigo-200 dark:border-indigo-800 font-semibold flex items-center gap-1">
          <Sparkles size={10} /> Active
        </span>
      </div>

      {/* Recommendations List */}
      <div className="space-y-3">
        {displayedRecs.map(rec => (
          <div key={rec.id} className={`rounded-xl border p-3 ${rec.bg} ${rec.border} transition-all`}>
            <div className="flex items-center justify-between mb-1.5">
              <div className="flex items-center gap-1.5">
                <span className={`w-1.5 h-1.5 rounded-full pulse-dot ${rec.dot}`} />
                <span className={`text-[11px] font-semibold ${rec.color}`}>{rec.priority}</span>
              </div>
              <button
                onClick={() => handleCopy(rec)}
                className="text-[10px] font-medium text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 flex items-center gap-1 px-1.5 py-0.5 rounded hover:bg-white/80 dark:hover:bg-slate-800/80 transition-colors cursor-pointer"
                title="Copy fix snippet"
              >
                {copiedId === rec.id ? (
                  <>
                    <Check size={10} className="text-emerald-600 dark:text-emerald-400" />
                    <span className="text-emerald-600 dark:text-emerald-400">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy size={10} />
                    <span>Copy Fix</span>
                  </>
                )}
              </button>
            </div>
            <p className="text-xs font-semibold text-slate-800 dark:text-slate-200">{rec.title}</p>
            <p className="text-[11px] text-slate-600 dark:text-slate-300 mt-0.5">
              <span className="font-semibold text-slate-700 dark:text-slate-200">Impact:</span> {rec.impact}
            </p>
            <p className="text-[11px] text-slate-600 dark:text-slate-300 mt-0.5">
              <span className="font-semibold text-slate-700 dark:text-slate-200">Fix:</span> {rec.fix}
            </p>
            {rec.codeSnippet && (
              <pre className="mt-2 p-2 bg-slate-900 dark:bg-slate-950 text-emerald-400 text-[10px] font-mono rounded-lg overflow-x-auto select-all border border-slate-800">
                {rec.codeSnippet}
              </pre>
            )}
          </div>
        ))}
      </div>

      {/* Show more toggle */}
      <button
        onClick={() => setShowAll(!showAll)}
        className="text-xs font-medium text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-300 flex items-center justify-center gap-1 py-1 transition-colors cursor-pointer"
      >
        {showAll ? (
          <>
            Show Less <ChevronUp size={13} />
          </>
        ) : (
          <>
            Show Full Recommendations ({allRecommendations.length}) <ChevronDown size={13} />
          </>
        )}
      </button>

      {/* Conversational AI Messages (if any) */}
      {messages.length > 0 && (
        <div className="space-y-2 border-t border-slate-100 dark:border-slate-800 pt-3 max-h-48 overflow-y-auto">
          {messages.map((m, idx) => (
            <div
              key={idx}
              className={`p-2.5 rounded-lg text-xs ${
                m.sender === 'user'
                  ? 'bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 ml-4 font-medium'
                  : 'bg-indigo-50 dark:bg-indigo-950/50 border border-indigo-100 dark:border-indigo-900/60 text-indigo-900 dark:text-indigo-200 mr-4'
              }`}
            >
              <p>{m.text}</p>
              {m.code && (
                <pre className="mt-1.5 p-1.5 bg-slate-900 dark:bg-slate-950 text-emerald-400 text-[10px] font-mono rounded border border-slate-800">
                  {m.code}
                </pre>
              )}
            </div>
          ))}
          {isTyping && (
            <div className="text-[11px] text-slate-400 dark:text-slate-500 flex items-center gap-1 italic">
              <Sparkles size={11} className="animate-spin" /> Copilot is drafting patch...
            </div>
          )}
        </div>
      )}

      {/* Quick Prompts (Image 2 Box 3 Architecture Queries) */}
      <div className="flex gap-1.5 flex-wrap">
        {[
          'Run a security scan on my code',
          'What vulnerabilities were found?',
          'Explain the SQL injection issue',
          'How to fix this issue?',
          'Give a summary report',
        ].map((chip) => (
          <button
            key={chip}
            onClick={() => handleAsk(chip)}
            className="text-[10px] bg-slate-100 dark:bg-slate-800 hover:bg-teal-50 dark:hover:bg-teal-950/60 hover:text-teal-600 dark:hover:text-teal-400 px-2.5 py-1 rounded-full text-slate-600 dark:text-slate-300 transition-colors cursor-pointer border border-slate-200/80 dark:border-slate-700/80 font-medium"
          >
            {chip}
          </button>
        ))}
      </div>

      {/* Input */}
      <div className="relative">
        <input
          id="ai-assistant-input"
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') handleAsk() }}
          placeholder="Ask copilot for code fixes or advice..."
          className="w-full pl-3 pr-8 py-2 text-xs rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80 text-slate-800 dark:text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/30 focus:border-indigo-500 focus:bg-white dark:focus:bg-slate-800 transition"
        />
        <button
          onClick={() => handleAsk()}
          className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-slate-400 hover:text-indigo-600 dark:hover:text-indigo-400 transition-colors cursor-pointer"
          title="Submit prompt"
        >
          <Send size={13} />
        </button>
      </div>
    </div>
  )
}
