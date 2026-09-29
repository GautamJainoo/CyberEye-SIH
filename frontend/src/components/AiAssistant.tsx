'use client'

import { useState } from 'react'
import { Bot, Send, Sparkles, Copy, Check, ChevronDown, ChevronUp } from 'lucide-react'
import { useToast } from './Toast'
import { useAppDispatch, useAppSelector } from '../store'
import {
  addUserMessageOptimistic,
  clearMessages,
  askCopilotAsync,
} from '../store/slices/copilotSlice'

export default function AiAssistant() {
  const { toast } = useToast()
  const dispatch = useAppDispatch()
  const { messages, recommendations: recs, isTyping } = useAppSelector((state) => state.copilot)
  const [showAll, setShowAll] = useState(false)
  const [query, setQuery] = useState('')
  const [copiedId, setCopiedId] = useState<number | string | null>(null)

  const displayedRecs = showAll ? recs : recs.slice(0, 2)

  const handleCopy = (rec: any) => {
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

    // 0ms instant Optimistic UI update in Redux store
    dispatch(addUserMessageOptimistic(textToSend))
    if (!promptText) setQuery('')

    // Asynchronous background AI query
    dispatch(askCopilotAsync({ prompt: textToSend }))
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
            <p className="text-[10px] text-slate-400 dark:text-slate-500">Answers grounded in your stored findings (Groq)</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {messages.length > 0 && (
            <button
              onClick={() => dispatch(clearMessages())}
              className="text-[10px] text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer"
            >
              Clear Chat
            </button>
          )}
          <span className="text-[10px] px-2 py-0.5 rounded-full bg-indigo-50 dark:bg-indigo-950/60 text-indigo-600 dark:text-indigo-400 border border-indigo-200 dark:border-indigo-800 font-semibold flex items-center gap-1">
            <Sparkles size={10} /> Active
          </span>
        </div>
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
            Show Full Recommendations ({recs.length}) <ChevronDown size={13} />
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
          'What are the most severe findings?',
          'Which findings are likely false positives?',
          'How do I fix the top finding?',
          'Summarize the assessment',
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
          placeholder="Ask about a finding, its cause or its fix..."
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
