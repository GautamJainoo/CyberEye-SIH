import { useMemo, useState, type ReactNode } from 'react'
import {
  Activity,
  AlertTriangle,
  Bug,
  Globe,
  Menu,
  Search,
  Shield,
  ShieldAlert,
  X,
} from 'lucide-react'
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

type View = 'overview' | 'findings' | 'apis'
type Severity = 'Critical' | 'High' | 'Medium' | 'Low'

type Finding = {
  id: string
  title: string
  target: string
  severity: Severity
  status: 'Open' | 'Mitigated'
}

type ApiRoute = {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE'
  path: string
  auth: 'Missing' | 'Weak' | 'Ok'
  note: string
}

const TREND = [
  { day: 'Mon', open: 18 },
  { day: 'Tue', open: 16 },
  { day: 'Wed', open: 21 },
  { day: 'Thu', open: 19 },
  { day: 'Fri', open: 14 },
  { day: 'Sat', open: 12 },
  { day: 'Sun', open: 11 },
]

const FINDINGS: Finding[] = [
  { id: 'WL-1042', title: 'SQL injection on search', target: '/api/search', severity: 'Critical', status: 'Open' },
  { id: 'WL-1038', title: 'JWT accepted without expiry', target: '/api/auth/refresh', severity: 'High', status: 'Open' },
  { id: 'WL-1031', title: 'IDOR on invoice download', target: '/api/invoices/:id', severity: 'High', status: 'Open' },
  { id: 'WL-1019', title: 'Missing rate limit on login', target: '/api/auth/login', severity: 'Medium', status: 'Open' },
  { id: 'WL-1004', title: 'Verbose stack traces', target: '/api/users', severity: 'Low', status: 'Mitigated' },
]

const ROUTES: ApiRoute[] = [
  { method: 'POST', path: '/api/auth/login', auth: 'Weak', note: 'No lockout after failed attempts' },
  { method: 'GET', path: '/api/search', auth: 'Ok', note: 'Query string reaches SQL unsanitized' },
  { method: 'GET', path: '/api/invoices/:id', auth: 'Missing', note: 'Object id not scoped to caller' },
  { method: 'PUT', path: '/api/users/:id', auth: 'Ok', note: 'Role check present' },
]

const NAV: { id: View; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'findings', label: 'Findings' },
  { id: 'apis', label: 'API security' },
]

const SEVERITY_CLASS: Record<Severity, string> = {
  Critical: 'bg-red-500/15 text-red-300 ring-red-500/40',
  High: 'bg-orange-500/15 text-orange-300 ring-orange-500/40',
  Medium: 'bg-amber-500/15 text-amber-200 ring-amber-500/40',
  Low: 'bg-sky-500/15 text-sky-200 ring-sky-500/40',
}

const countSeverity = (severity: Severity) =>
  FINDINGS.filter((item) => item.severity === severity && item.status === 'Open').length

const App = () => {
  const [view, setView] = useState<View>('overview')
  const [query, setQuery] = useState('')
  const [menuOpen, setMenuOpen] = useState(false)

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase()
    if (!needle) return FINDINGS
    return FINDINGS.filter((item) =>
      `${item.id} ${item.title} ${item.target} ${item.severity}`.toLowerCase().includes(needle),
    )
  }, [query])

  const handleView = (next: View) => {
    setView(next)
    setMenuOpen(false)
  }

  return (
    <div className="min-h-screen md:grid md:grid-cols-[240px_1fr]">
      <aside className={`${menuOpen ? 'block' : 'hidden'} border-b border-slate-800 bg-slate-900/80 md:block md:border-b-0 md:border-r`}>
        <div className="flex items-center gap-3 px-5 py-5">
          <Shield className="h-6 w-6 text-indigo-400" aria-hidden="true" />
          <div>
            <p className="text-sm font-semibold tracking-tight">WorldMonitor</p>
            <p className="text-xs text-slate-400">Security assessment</p>
          </div>
        </div>
        <nav className="flex gap-2 overflow-x-auto px-3 pb-4 md:block md:space-y-1 md:px-3" aria-label="Primary">
          {NAV.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => handleView(item.id)}
              className={`cursor-pointer rounded-lg px-3 py-2.5 text-left text-sm font-medium transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-400 ${
                view === item.id ? 'bg-indigo-500/20 text-indigo-200' : 'text-slate-300 hover:bg-slate-800'
              }`}
              aria-current={view === item.id ? 'page' : undefined}
            >
              {item.label}
            </button>
          ))}
        </nav>
      </aside>

      <div className="min-w-0">
        <header className="flex items-center justify-between gap-4 border-b border-slate-800 px-4 py-4 sm:px-6">
          <div className="flex items-center gap-3">
            <button
              type="button"
              className="inline-flex h-11 w-11 cursor-pointer items-center justify-center rounded-lg text-slate-200 hover:bg-slate-800 focus-visible:outline focus-visible:outline-2 focus-visible:outline-indigo-400 md:hidden"
              aria-label={menuOpen ? 'Close menu' : 'Open menu'}
              aria-expanded={menuOpen}
              onClick={() => setMenuOpen((open) => !open)}
            >
              {menuOpen ? <X aria-hidden="true" /> : <Menu aria-hidden="true" />}
            </button>
            <div>
              <h1 className="text-lg font-semibold tracking-tight sm:text-xl">
                {NAV.find((item) => item.id === view)?.label}
              </h1>
              <p className="text-xs text-slate-400">Sample assessment. Not a live scan.</p>
            </div>
          </div>
          <p className="hidden font-mono text-xs text-slate-400 sm:block">Risk score 72 / 100</p>
        </header>

        <main className="space-y-6 px-4 py-6 sm:px-6">
          {view === 'overview' && <Overview onOpenFindings={() => handleView('findings')} />}
          {view === 'findings' && (
            <Findings query={query} onQuery={setQuery} rows={filtered} />
          )}
          {view === 'apis' && <ApiSecurity />}
        </main>
      </div>
    </div>
  )
}

const Overview = ({ onOpenFindings }: { onOpenFindings: () => void }) => (
  <>
    <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4" aria-label="Open findings by severity">
      <Metric icon={<ShieldAlert aria-hidden="true" />} label="Critical" value={countSeverity('Critical')} tone="text-red-300" />
      <Metric icon={<AlertTriangle aria-hidden="true" />} label="High" value={countSeverity('High')} tone="text-orange-300" />
      <Metric icon={<Bug aria-hidden="true" />} label="Medium" value={countSeverity('Medium')} tone="text-amber-200" />
      <Metric icon={<Activity aria-hidden="true" />} label="Open total" value={FINDINGS.filter((item) => item.status === 'Open').length} tone="text-indigo-300" />
    </section>

    <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-lg">
      <div className="mb-4 flex items-end justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold">Open findings this week</h2>
          <p className="text-sm text-slate-400">Static sample series for the demo dashboard.</p>
        </div>
        <button
          type="button"
          onClick={onOpenFindings}
          className="cursor-pointer rounded-lg bg-indigo-500 px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-indigo-400 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-300"
        >
          Review findings
        </button>
      </div>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={TREND} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
            <CartesianGrid stroke="#334155" strokeDasharray="3 3" />
            <XAxis dataKey="day" stroke="#94a3b8" tick={{ fill: '#94a3b8', fontSize: 12 }} />
            <YAxis stroke="#94a3b8" tick={{ fill: '#94a3b8', fontSize: 12 }} allowDecimals={false} />
            <Tooltip
              contentStyle={{ background: '#0f172a', border: '1px solid #475569', borderRadius: 8 }}
              labelStyle={{ color: '#f8fafc' }}
            />
            <Area type="monotone" dataKey="open" name="Open findings" stroke="#818cf8" fill="#6366f1" fillOpacity={0.25} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </section>
  </>
)

const Metric = ({
  icon,
  label,
  value,
  tone,
}: {
  icon: ReactNode
  label: string
  value: number
  tone: string
}) => (
  <article className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-lg">
    <div className={`mb-3 h-5 w-5 ${tone}`}>{icon}</div>
    <p className="text-sm text-slate-400">{label}</p>
    <p className="mt-1 font-mono text-3xl font-semibold">{value}</p>
  </article>
)

const Findings = ({
  query,
  onQuery,
  rows,
}: {
  query: string
  onQuery: (value: string) => void
  rows: Finding[]
}) => (
  <section className="space-y-4">
    <label className="relative block max-w-md">
      <span className="sr-only">Search findings</span>
      <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" aria-hidden="true" />
      <input
        value={query}
        onChange={(event) => onQuery(event.target.value)}
        placeholder="Search id, title, or path"
        className="w-full rounded-lg border border-slate-700 bg-slate-900 py-3 pl-10 pr-3 text-sm text-slate-100 placeholder:text-slate-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-indigo-400"
      />
    </label>
    {rows.length === 0 ? (
      <p className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 text-sm text-slate-300">
        No findings match “{query}”.
      </p>
    ) : (
      <ul className="space-y-3">
        {rows.map((item) => (
          <li key={item.id} className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-lg">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="font-mono text-xs text-slate-400">{item.id}</p>
                <h2 className="mt-1 text-base font-semibold">{item.title}</h2>
                <p className="mt-1 font-mono text-sm text-slate-300">{item.target}</p>
              </div>
              <div className="flex items-center gap-2">
                <span className={`rounded-full px-3 py-1 text-xs font-medium ring-1 ${SEVERITY_CLASS[item.severity]}`}>
                  {item.severity}
                </span>
                <span className="text-xs text-slate-400">{item.status}</span>
              </div>
            </div>
          </li>
        ))}
      </ul>
    )}
  </section>
)

const ApiSecurity = () => (
  <section className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/70 shadow-lg">
    <div className="flex items-center gap-2 border-b border-slate-800 px-6 py-4">
      <Globe className="h-5 w-5 text-indigo-300" aria-hidden="true" />
      <h2 className="text-base font-semibold">Route checks</h2>
    </div>
    <ul>
      {ROUTES.map((route) => (
        <li key={`${route.method}-${route.path}`} className="border-b border-slate-800 px-6 py-4 last:border-b-0">
          <div className="flex flex-wrap items-baseline gap-3">
            <span className="font-mono text-xs font-medium text-indigo-300">{route.method}</span>
            <span className="font-mono text-sm">{route.path}</span>
            <span className="text-xs text-slate-400">Auth: {route.auth}</span>
          </div>
          <p className="mt-1 text-sm text-slate-300">{route.note}</p>
        </li>
      ))}
    </ul>
  </section>
)

export default App
