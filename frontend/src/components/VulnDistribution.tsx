import { useState, useMemo } from 'react'
import { vulnDistribution, zeroVulnDistribution } from '../data'
import { useToast } from './Toast'
import { useAppSelector } from '../store'

interface Props {
  onSelectSeverity?: (sev: string) => void
  isZeroData?: boolean
}

export default function VulnDistribution({ onSelectSeverity, isZeroData: propZero }: Props) {
  const { toast } = useToast()
  const [activeItem, setActiveItem] = useState<string | null>(null)
  const findingsState = useAppSelector((state) => state.findings)
  const isZeroData = propZero !== undefined ? propZero : findingsState.isZeroData
  const items = findingsState.items

  const activeData = useMemo(() => {
    if (isZeroData) return zeroVulnDistribution
    let crit = 0, high = 0, med = 0, low = 0
    for (const f of items) {
      const s = (f.severity || '').toUpperCase()
      if (s === 'CRITICAL') crit++
      else if (s === 'HIGH') high++
      else if (s === 'MEDIUM') med++
      else low++
    }
    const tot = crit + high + med + low
    if (tot === 0) return vulnDistribution
    return [
      { label: 'Critical', count: crit, pct: Math.round((crit / tot) * 100), color: '#ef4444' },
      { label: 'High', count: high, pct: Math.round((high / tot) * 100), color: '#f97316' },
      { label: 'Medium', count: med, pct: Math.round((med / tot) * 100), color: '#f59e0b' },
      { label: 'Low', count: low, pct: Math.round((low / tot) * 100), color: '#10b981' },
    ]
  }, [isZeroData, items])

  const total = activeData.reduce((s, d) => s + d.count, 0)

  const handleRowClick = (label: string, count: number) => {
    setActiveItem(label)
    const pctStr = total > 0 ? `${Math.round((count / total) * 100)}%` : '0%'
    toast('info', `${label} Vulnerabilities`, `${count} issues account for ${pctStr} of total risk exposure`)
    onSelectSeverity?.(label)
  }

  return (
    <div className="card p-5 h-full flex flex-col justify-between gap-3">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-800 dark:text-slate-100">Vulnerability Distribution</h2>
        <span className="text-[10px] text-slate-400 dark:text-slate-500 font-mono">{total} Total</span>
      </div>

      {/* Mini donut + bars */}
      <div className="flex flex-col sm:flex-row items-center gap-5 my-auto">
        <MiniDonut total={total} data={activeData} />

        <div className="flex-1 w-full space-y-2.5">
          {activeData.map(d => {
            const isSelected = activeItem === d.label
            return (
              <button
                key={d.label}
                onClick={() => handleRowClick(d.label, d.count)}
                className={`w-full flex items-center gap-2 p-1.5 rounded-lg text-left transition-all cursor-pointer ${
                  isSelected
                    ? 'bg-indigo-50/80 dark:bg-indigo-950/60 ring-1 ring-indigo-200 dark:ring-indigo-800'
                    : 'hover:bg-slate-50 dark:hover:bg-slate-800/60'
                }`}
                title={`Filter by ${d.label}`}
              >
                <span className="w-2.5 h-2.5 rounded-xs shrink-0" style={{ backgroundColor: d.color }} />
                <span className="text-xs text-slate-600 dark:text-slate-300 font-medium w-14">{d.label}</span>
                {/* progress bar */}
                <div className="flex-1 h-1.5 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{ width: `${d.pct}%`, backgroundColor: d.color }}
                  />
                </div>
                <span className="text-xs font-semibold text-slate-700 dark:text-slate-200 w-4 text-right">{d.count}</span>
                <span className="text-[10px] text-slate-400 dark:text-slate-500 w-7 text-right">{d.pct}%</span>
              </button>
            )
          })}
        </div>
      </div>
    </div>
  )
}

function MiniDonut({ total, data }: { total: number; data: typeof vulnDistribution }) {
  const R = 30
  const CIRC = 2 * Math.PI * R
  let offset = 0

  return (
    <div className="relative shrink-0 flex flex-col items-center">
      <svg width="76" height="76" viewBox="0 0 76 76" className="select-none">
        <circle
          cx="38" cy="38" r={R}
          fill="none"
          className="stroke-slate-100 dark:stroke-slate-800"
          strokeWidth="10"
        />
        {total === 0 ? (
          <circle
            cx="38" cy="38" r={R}
            fill="none"
            stroke="#10b981"
            strokeWidth="10"
            strokeDasharray={`${CIRC} 0`}
            style={{ transform: 'rotate(-90deg)', transformOrigin: '38px 38px' }}
          />
        ) : (
          data.map((d, i) => {
            const dash = CIRC * (d.count / total)
            const el = (
              <circle
                key={i}
                cx="38" cy="38" r={R}
                fill="none"
                stroke={d.color}
                strokeWidth="10"
                strokeDasharray={`${Math.max(0, dash - 1.5)} ${CIRC - dash + 1.5}`}
                strokeDashoffset={-offset}
                style={{ transform: 'rotate(-90deg)', transformOrigin: '38px 38px' }}
              />
            )
            offset += dash
            return el
          })
        )}
        <text
          x="38" y="42"
          textAnchor="middle"
          fontSize="13"
          fontWeight="700"
          className="donut-label fill-slate-800 dark:fill-slate-100"
        >
          {total}
        </text>
      </svg>
      <p className="text-[9px] text-center text-slate-400 dark:text-slate-500 mt-0.5">Total</p>
    </div>
  )
}
