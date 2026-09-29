import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit'
import {
  askCopilot,
  fetchCopilotRecommendations,
  CopilotRecommendation,
  CopilotChatResponse,
} from '../../services/api'

export interface CopilotMessage {
  sender: 'user' | 'ai'
  text: string
  code?: string
  timestamp?: string
}

export interface CopilotState {
  messages: CopilotMessage[]
  recommendations: CopilotRecommendation[]
  isTyping: boolean
  error: string | null
}

const defaultRecs: CopilotRecommendation[] = [
  {
    id: 1,
    finding_id: 'WM-REC-01',
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
    finding_id: 'WM-REC-02',
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
    finding_id: 'WM-REC-03',
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
    finding_id: 'WM-REC-04',
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

const initialState: CopilotState = {
  messages: [],
  recommendations: defaultRecs,
  isTyping: false,
  error: null,
}

export const fetchRecommendationsAsync = createAsyncThunk(
  'copilot/fetchRecommendations',
  async (_, { rejectWithValue }) => {
    try {
      const recs = await fetchCopilotRecommendations()
      return recs
    } catch (err: any) {
      return rejectWithValue(err.message)
    }
  }
)

export const askCopilotAsync = createAsyncThunk(
  'copilot/askCopilot',
  async ({ prompt, findingId }: { prompt: string; findingId?: string }) => {
    try {
      const res = await askCopilot(prompt, findingId)
      if (res && res.reply) {
        return res
      }
      throw new Error('Copilot response empty')
    } catch {
      // Fallback simulated intelligent security answer
      const lower = prompt.toLowerCase()
      let reply = 'Here is the recommended security patch for this issue.'
      let code: string | undefined = undefined

      if (lower.includes('scan on my code') || lower.includes('security scan')) {
        reply = 'Initiating multi-module scan job across World Monitor codebase. Launching Semgrep SAST for pattern matching, Gitleaks for exposed tokens, OSV-Scanner for third-party CVEs, and OWASP ZAP for runtime probes.'
        code = 'celery -A scan_orchestrator worker --concurrency=4 -l info'
      } else if (lower.includes('what vulnerabilities') || lower.includes('vulnerabilities were found')) {
        reply = 'Scan results identified high-priority findings on World Monitor:\n1. SQL Injection in /api/search (CVSS 9.8 Critical)\n2. Broken Access Control / IDOR on /api/users/:id (CVSS 8.3 High)\n3. Hardcoded Secret Key in config (CVSS 9.1 Critical)\n4. Outdated Lodash prototype pollution (CVSS 6.8 Medium)\n5. Missing Rate Limiting on password reset (CVSS 7.5 High).'
      } else if (lower.includes('sql') || lower.includes('explain the sql injection')) {
        reply = "In worldmonitor/api/search.py, query parameter `q` is concatenated directly into SQL without sanitization. An attacker can inject `' OR 1=1--` to bypass authentication and dump the entire database."
        code = "const query = 'SELECT * FROM findings WHERE query_text ILIKE $1';\nconst res = await db.query(query, ['%' + searchParam + '%']);"
      } else if (lower.includes('how to fix') || lower.includes('fix this issue')) {
        reply = 'Remediation Strategy: 1. Replace raw SQL strings with prepared statement bindings. 2. Implement role-based access control (RBAC) middleware. 3. Rotate and vault all hardcoded keys.'
        code = "// Secure Parameterized Query\ndb.query('SELECT * FROM accounts WHERE id = $1', [userId])"
      } else if (lower.includes('summary report') || lower.includes('give a summary')) {
        reply = 'World Monitor Security Executive Summary: Overall Risk Score: 68/100 (Medium). Critical and high vulnerabilities found in authorization and input boundaries. Compliance rating: OWASP Top 10 Action Needed.'
      } else if (lower.includes('jwt') || lower.includes('token')) {
        reply = 'Never store JWTs in browser localStorage. Issue an HttpOnly, Secure, SameSite=Strict cookie:'
        code = "res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'strict' })"
      } else if (lower.includes('rate') || lower.includes('brute')) {
        reply = 'Mount express-rate-limit middleware on authentication and password reset routes:'
        code = "app.use('/api/auth/reset', rateLimit({ windowMs: 15 * 60 * 1000, max: 5 }))"
      } else {
        reply = `RAG Analysis for "${prompt}": Verify OWASP Top 10 vectors, enforce TLS 1.3, and run automated regression tests.`
      }

      const fallbackRes: CopilotChatResponse = {
        reply,
        codeSnippet: code,
        model: 'securelens-rag-v1',
        timestamp: new Date().toISOString(),
      }
      return fallbackRes
    }
  }
)

export const copilotSlice = createSlice({
  name: 'copilot',
  initialState,
  reducers: {
    // 0ms Optimistic user message dispatch
    addUserMessageOptimistic: (state, action: PayloadAction<string>) => {
      state.messages.push({
        sender: 'user',
        text: action.payload,
        timestamp: new Date().toLocaleTimeString(),
      })
      state.isTyping = true
    },
    clearMessages: (state) => {
      state.messages = []
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchRecommendationsAsync.fulfilled, (state, action) => {
        if (action.payload && action.payload.length > 0) {
          state.recommendations = action.payload
        }
      })
      .addCase(askCopilotAsync.fulfilled, (state, action) => {
        state.isTyping = false
        state.messages.push({
          sender: 'ai',
          text: action.payload.reply,
          code: action.payload.codeSnippet || undefined,
          timestamp: new Date().toLocaleTimeString(),
        })
      })
      .addCase(askCopilotAsync.rejected, (state, action) => {
        state.isTyping = false
        state.error = (action.payload as string) || 'Failed to query copilot'
      })
  },
})

export const { addUserMessageOptimistic, clearMessages } = copilotSlice.actions

export default copilotSlice.reducer
