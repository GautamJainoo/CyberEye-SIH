import { useState } from 'react'
import {
  CheckCircle2, AlertTriangle, XCircle, User, Server, ShieldCheck,
  Globe2, Network
} from 'lucide-react'
import { countryThreats, zeroCountryThreats, CountryThreat } from '../data'
import { useToast } from './Toast'
import { useAppSelector } from '../store'

type NodeStatus = 'secure' | 'warning' | 'vulnerable'

interface MapNode {
  id: string
  label: string
  status: NodeStatus
  icon: React.ElementType
  ip: string
  port: string
  findings: number
  description: string
}

function statusStyle(s: NodeStatus) {
  switch (s) {
    case 'secure':
      return 'bg-emerald-50 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-800 text-emerald-700 dark:text-emerald-300 hover:bg-emerald-100/60 dark:hover:bg-emerald-900/50'
    case 'warning':
      return 'bg-amber-50 dark:bg-amber-950/40 border-amber-200 dark:border-amber-800 text-amber-700 dark:text-amber-300 hover:bg-amber-100/60 dark:hover:bg-amber-900/50'
    case 'vulnerable':
      return 'bg-red-50 dark:bg-red-950/40 border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 hover:bg-red-100/60 dark:hover:bg-red-900/50'
  }
}

function StatusIcon({ s }: { s: NodeStatus }) {
  switch (s) {
    case 'secure':     return <CheckCircle2 size={11} className="text-emerald-500" />
    case 'warning':    return <AlertTriangle size={11} className="text-amber-500" />
    case 'vulnerable': return <XCircle size={11} className="text-red-500" />
  }
}

interface AttackSurfaceProps {
  isZeroData?: boolean
}

export default function AttackSurfaceMap({ isZeroData: propZero }: AttackSurfaceProps) {
  const { toast } = useToast()
  const [activeTab, setActiveTab] = useState<'topology' | 'countries'>('topology')
  const [selectedNode, setSelectedNode] = useState<MapNode | null>(null)
  const [selectedCountry, setSelectedCountry] = useState<CountryThreat | null>(null)
  const findingsZero = useAppSelector((state) => state.findings.isZeroData)
  const liveNodes = useAppSelector((state) => state.telemetry.attackSurfaceNodes)
  const isZeroData = propZero !== undefined ? propZero : findingsZero

  const activeCountries = isZeroData ? zeroCountryThreats : countryThreats

  const layer1: MapNode = {
    id: 'user',
    label: 'User Traffic',
    status: (isZeroData ? 'secure' : liveNodes['user']?.status || 'secure') as NodeStatus,
    icon: User,
    ip: 'Edge Anycast',
    port: '443 / HTTPS',
    findings: isZeroData ? 0 : (liveNodes['user']?.findings ?? 0),
    description: 'Public clients routed via Cloudflare SSL termination & TLS 1.3 encryption.'
  }

  const layer2: MapNode = {
    id: 'frontend',
    label: 'Frontend CDN',
    status: (isZeroData ? 'secure' : liveNodes['frontend']?.status || 'secure') as NodeStatus,
    icon: Server,
    ip: '104.21.58.12',
    port: '443 (Edge)',
    findings: isZeroData ? 0 : (liveNodes['frontend']?.findings ?? 1),
    description: isZeroData
      ? 'Vite React SPA hosted on AWS CloudFront. Zero header or asset findings.'
      : 'Vite React SPA hosted on AWS CloudFront. Minor CSP header recommendation.'
  }

  const layer3: MapNode = {
    id: 'gateway',
    label: 'API Gateway',
    status: (isZeroData ? 'secure' : liveNodes['gateway']?.status || 'warning') as NodeStatus,
    icon: ShieldCheck,
    ip: '10.0.1.15',
    port: '8080 (REST / GraphQL)',
    findings: isZeroData ? 0 : (liveNodes['gateway']?.findings ?? 3),
    description: isZeroData
      ? 'Kong Ingress Gateway. Active rate limiting and strict CORS headers applied.'
      : 'Kong Ingress Gateway. Rate limiting missing on /api/login and /api/search.'
  }

  const layer4: MapNode[] = [
    {
      id: 'auth',
      label: 'Auth Service',
      status: (isZeroData ? 'secure' : liveNodes['auth']?.status || 'secure') as NodeStatus,
      icon: ShieldCheck,
      ip: '10.0.2.10',
      port: '50051 (gRPC)',
      findings: isZeroData ? 0 : (liveNodes['auth']?.findings ?? 1),
      description: isZeroData
        ? 'OAuth2 / OIDC token provider. HttpOnly secure cookies configured.'
        : 'OAuth2 / OIDC token provider. JWT storage configuration needs review.'
    },
    {
      id: 'analytics',
      label: 'Analytics Svc',
      status: (isZeroData ? 'secure' : liveNodes['analytics']?.status || 'warning') as NodeStatus,
      icon: Server,
      ip: '10.0.2.14',
      port: '9090 (HTTP)',
      findings: isZeroData ? 0 : (liveNodes['analytics']?.findings ?? 2),
      description: isZeroData
        ? 'Clickhouse telemetry pipeline. Metric export endpoint secured behind VPC.'
        : 'Clickhouse telemetry pipeline. Unprotected metrics export endpoint found.'
    },
    {
      id: 'database',
      label: 'PostgreSQL DB',
      status: (isZeroData ? 'secure' : liveNodes['database']?.status || 'vulnerable') as NodeStatus,
      icon: Server,
      ip: '10.0.3.5',
      port: '5432 (Postgres)',
      findings: isZeroData ? 0 : (liveNodes['database']?.findings ?? 4),
      description: isZeroData
        ? 'PostgreSQL Cluster. Parameterized prepared queries enforced with 0 SQLi vectors.'
        : 'Critical SQLi vector reachable from public query builder without input sanitization.'
    },
  ]

  const legend: [NodeStatus, string][] = [
    ['secure',     'Secure'],
    ['warning',    'Warning'],
    ['vulnerable', 'Vulnerable'],
  ]

  const handleNodeClick = (node: MapNode) => {
    setSelectedNode(node)
    toast('info', `${node.label} Selected`, `${node.findings} potential security finding(s) detected`)
  }

  const handleCountryClick = (c: CountryThreat) => {
    setSelectedCountry(c)
    toast('info', `${c.flag} ${c.country}`, `${c.attacksBlocked.toLocaleString()} malicious requests mitigated. Vector: ${c.topVector}`)
  }

  return (
    <div className="card p-5 flex flex-col gap-3">
      {/* Header with Switcher */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="w-1.5 h-4 rounded-full bg-amber-400" />
          <h2 className="text-sm font-semibold text-slate-800 dark:text-slate-100">
            {activeTab === 'topology' ? 'Attack Surface Map' : 'Global Threat Feed (Countries)'}
          </h2>
        </div>

        {/* View Tabs */}
        <div className="flex items-center gap-1 bg-slate-100 dark:bg-slate-800 p-0.5 rounded-lg">
          <button
            onClick={() => setActiveTab('topology')}
            className={`flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded-md transition-all cursor-pointer ${
              activeTab === 'topology'
                ? 'bg-white dark:bg-slate-900 text-indigo-600 dark:text-indigo-400 shadow-sm'
                : 'text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            <Network size={12} />
            Architecture
          </button>
          <button
            onClick={() => setActiveTab('countries')}
            className={`flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded-md transition-all cursor-pointer ${
              activeTab === 'countries'
                ? 'bg-white dark:bg-slate-900 text-indigo-600 dark:text-indigo-400 shadow-sm'
                : 'text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            <Globe2 size={12} />
            Countries ({activeCountries.length})
          </button>
        </div>
      </div>

      {/* Topology Tab Content */}
      {activeTab === 'topology' ? (
        <>
          <div className="flex items-center justify-between text-xs text-slate-400 dark:text-slate-500 pt-1">
            <span className="text-[11px]">Click architectural nodes to inspect threat exposure</span>
            <div className="flex items-center gap-3">
              {legend.map(([s, lbl]) => (
                <div key={lbl} className="flex items-center gap-1">
                  <StatusIcon s={s} />
                  <span className="text-[10px] text-slate-500 dark:text-slate-400">{lbl}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Interactive Graph Map */}
          <div className="flex flex-col items-center py-2 select-none">
            <button
              onClick={() => handleNodeClick(layer1)}
              className={`attack-node border transition-transform hover:scale-105 cursor-pointer ${statusStyle(layer1.status)}`}
            >
              <User size={12} />
              <span>{layer1.label}</span>
              <StatusIcon s={layer1.status} />
            </button>

            <div className="w-px h-4 bg-slate-200 dark:bg-slate-700" />

            <button
              onClick={() => handleNodeClick(layer2)}
              className={`attack-node border transition-transform hover:scale-105 cursor-pointer ${statusStyle(layer2.status)}`}
            >
              <Server size={12} />
              <span>{layer2.label}</span>
              <StatusIcon s={layer2.status} />
            </button>

            <div className="w-px h-4 bg-slate-200 dark:bg-slate-700" />

            <button
              onClick={() => handleNodeClick(layer3)}
              className={`attack-node border transition-transform hover:scale-105 cursor-pointer ${statusStyle(layer3.status)}`}
            >
              <ShieldCheck size={12} />
              <span>{layer3.label}</span>
              <StatusIcon s={layer3.status} />
            </button>

            {/* Horizontal Branching SVG */}
            <div className="flex items-start justify-center" style={{ height: 24 }}>
              <svg width="240" height="24" viewBox="0 0 240 24">
                <line x1="120" y1="0" x2="120" y2="12" className="stroke-slate-300 dark:stroke-slate-700" strokeWidth="1.5" />
                <line x1="35" y1="12" x2="205" y2="12" className="stroke-slate-300 dark:stroke-slate-700" strokeWidth="1.5" />
                <line x1="35" y1="12" x2="35" y2="24" className="stroke-slate-300 dark:stroke-slate-700" strokeWidth="1.5" />
                <line x1="120" y1="12" x2="120" y2="24" className="stroke-slate-300 dark:stroke-slate-700" strokeWidth="1.5" />
                <line x1="205" y1="12" x2="205" y2="24" className="stroke-slate-300 dark:stroke-slate-700" strokeWidth="1.5" />
              </svg>
            </div>

            {/* Layer 4 Nodes */}
            <div className="grid grid-cols-3 gap-2 w-full max-w-sm">
              {layer4.map(n => {
                const Icon = n.icon
                return (
                  <button
                    key={n.id}
                    onClick={() => handleNodeClick(n)}
                    className={`attack-node border text-[11px] py-1.5 px-2 transition-transform hover:scale-105 cursor-pointer flex-col sm:flex-row ${statusStyle(n.status)}`}
                  >
                    <Icon size={11} />
                    <span className="truncate">{n.label}</span>
                    <StatusIcon s={n.status} />
                  </button>
                )
              })}
            </div>
          </div>

          {/* Node detail inspector panel */}
          {selectedNode && (
            <div className="mt-2 p-3 bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 rounded-xl flex flex-col gap-2 animate-fade-in">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-slate-800 dark:text-slate-100">{selectedNode.label} Inspection</span>
                  <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded uppercase ${
                    selectedNode.status === 'vulnerable' ? 'bg-red-100 dark:bg-red-950 text-red-700 dark:text-red-400' :
                    selectedNode.status === 'warning' ? 'bg-amber-100 dark:bg-amber-950 text-amber-700 dark:text-amber-400' : 'bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-400'
                  }`}>
                    {selectedNode.status}
                  </span>
                </div>
                <button
                  onClick={() => setSelectedNode(null)}
                  className="text-xs text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 px-1 cursor-pointer"
                >
                  ✕
                </button>
              </div>
              <p className="text-[11px] text-slate-600 dark:text-slate-300 leading-relaxed">{selectedNode.description}</p>
              <div className="grid grid-cols-3 gap-2 text-[10px] text-slate-500 dark:text-slate-400 bg-white dark:bg-slate-900 p-2 rounded-lg border border-slate-100 dark:border-slate-800">
                <div>
                  <span className="text-slate-400 dark:text-slate-500 block">IP / Host:</span>
                  <span className="font-mono text-slate-700 dark:text-slate-300 font-semibold">{selectedNode.ip}</span>
                </div>
                <div>
                  <span className="text-slate-400 dark:text-slate-500 block">Ports:</span>
                  <span className="font-mono text-slate-700 dark:text-slate-300 font-semibold">{selectedNode.port}</span>
                </div>
                <div>
                  <span className="text-slate-400 dark:text-slate-500 block">Open CVEs:</span>
                  <span className={`font-bold ${selectedNode.findings > 0 ? 'text-red-600 dark:text-red-400' : 'text-emerald-600 dark:text-emerald-400'}`}>
                    {selectedNode.findings} items
                  </span>
                </div>
              </div>
              <button
                onClick={() => toast('success', `Security Audit Triggered`, `Dispatching vulnerability probe to ${selectedNode.ip}`)}
                className="w-full py-1 text-xs bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors font-medium cursor-pointer"
              >
                Scan Node ({selectedNode.label})
              </button>
            </div>
          )}
        </>
      ) : (
        /* Countries & Geo Telemetry Tab */
        <div className="space-y-3 pt-1">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span>Inbound threat distribution by country:</span>
            <span className="text-[11px] font-mono font-semibold text-slate-700 dark:text-slate-300">
              {isZeroData ? '0 requests blocked / 24h' : '6,430 requests blocked / 24h'}
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {activeCountries.map((c) => (
              <button
                key={c.code}
                onClick={() => handleCountryClick(c)}
                className="flex items-center justify-between p-2.5 rounded-xl border border-slate-200 dark:border-slate-800 hover:border-indigo-300 dark:hover:border-indigo-700 hover:bg-indigo-50/30 dark:hover:bg-indigo-950/20 transition-all text-left group cursor-pointer"
              >
                <div className="flex items-center gap-2.5">
                  <span className="text-xl leading-none">{c.flag}</span>
                  <div>
                    <p className="text-xs font-semibold text-slate-800 dark:text-slate-200 group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition-colors">
                      {c.country}
                    </p>
                    <p className="text-[10px] text-slate-400 dark:text-slate-500 truncate max-w-[130px]">{c.topVector}</p>
                  </div>
                </div>

                <div className="text-right">
                  <span className="text-xs font-mono font-bold text-slate-800 dark:text-slate-200">
                    {c.attacksBlocked.toLocaleString()}
                  </span>
                  <div className="flex items-center justify-end gap-1">
                    <span className={`text-[10px] font-semibold ${
                      c.threatLevel === 'High' ? 'text-red-600 dark:text-red-400' :
                      c.threatLevel === 'Medium' ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400'
                    }`}>
                      {c.threatLevel}
                    </span>
                    <span className="text-[10px] text-slate-400 dark:text-slate-500 font-mono">({c.trend})</span>
                  </div>
                </div>
              </button>
            ))}
          </div>

          {selectedCountry && (
            <div className="p-3 bg-indigo-50/70 dark:bg-indigo-950/40 border border-indigo-200 dark:border-indigo-800 rounded-xl flex items-center justify-between text-xs animate-fade-in">
              <div className="flex items-center gap-2">
                <span className="text-xl">{selectedCountry.flag}</span>
                <div>
                  <span className="font-semibold text-indigo-900 dark:text-indigo-300">{selectedCountry.country} Firewall Filter</span>
                  <p className="text-[11px] text-indigo-700 dark:text-indigo-400">Vector: {selectedCountry.topVector}</p>
                </div>
              </div>
              <button
                onClick={() => toast('success', 'WAF Policy Enforced', `Enhanced challenge rate applied for traffic from ${selectedCountry.country}`)}
                className="px-2.5 py-1 bg-indigo-600 text-white rounded-lg text-xs font-medium hover:bg-indigo-700 transition-colors shadow-sm cursor-pointer"
              >
                Block Malicious Range
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
