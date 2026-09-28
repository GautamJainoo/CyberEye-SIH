import { useState } from 'react'
import { useToast } from './Toast'

const RADIUS = 54
const CIRCUMFERENCE = 2 * Math.PI * RADIUS

interface Segment {
  label: string
  pct: number
  color: string
  count: number
}

const defaultSegments: Segment[] = [
  { label: 'Critical', pct: 0.16, color: '#ef4444', count: 2 },
  { label: 'High',     pct: 0.42, color: '#f97316', count: 5 },
  { label: 'Medium',   pct: 0.33, color: '#f59e0b', count: 8 },
  { label: 'Low',      pct: 0.09, color: '#10b981', count: 11 },
]

const zeroSegments: Segment[] = [
  { label: 'Critical', pct: 0, color: '#ef4444', count: 0 },
  { label: 'High',     pct: 0, color: '#f97316', count: 0 },
  { label: 'Medium',   pct: 0, color: '#f59e0b', count: 0 },
  { label: 'Low',      pct: 0, color: '#10b981', count: 0 },
]

interface Props {
  onFilterSeverity?: (severity: string) => void
  isZeroData?: boolean
}

export default function SecurityPosture({ onFilterSeverity, isZeroData = false }: Props) {
  const { toast } = useToast()
  const [hoveredSegment, setHoveredSegment] = useState<Segment | null>(null)

  const segments = isZeroData ? zeroSegments : defaultSegments
  let offset = CIRCUMFERENCE * 0.25
  const gap = 3

  const handleSeverityClick = (label: string, count: number) => {
    toast('info', `${label} Findings`, `Filtered view to ${count} ${label.toLowerCase()} priority issues`)
    onFilterSeverity?.(label)
  }

  return (
    <div className="card p-5 h-full flex flex-col justify-between gap-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-800 dark:text-slate-100">Overall Security Posture</h2>
        <button
          onClick={() => toast('info', isZeroData ? 'Clean Status' : 'Risk Rating: Medium', isZeroData ? 'Zero CVEs or exploit vectors detected.' : 'Based on 2 critical database vectors.')}
          className={`text-[11px] px-2 py-0.5 rounded-full font-semibold border transition-colors cursor-pointer ${
            isZeroData
              ? 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800'
              : 'bg-amber-100 dark:bg-amber-950/60 hover:bg-amber-200 dark:hover:bg-amber-900/60 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-800'
          }`}
        >
          {isZeroData ? 'Clean Baseline' : 'Medium Risk'}
        </button>
      </div>

      {/* Donut and details */}
      <div className="flex flex-col sm:flex-row items-center gap-5 my-auto">
        <div className="shrink-0 relative">
          <svg width="140" height="140" viewBox="0 0 140 140" className="cursor-pointer select-none">
            {/* Background ring */}
            <circle
              cx="70" cy="70" r={RADIUS}
              fill="none"
              className="stroke-slate-100 dark:stroke-slate-800"
              strokeWidth="14"
            />

            {/* If zero data: show full emerald clean ring */}
            {isZeroData ? (
              <circle
                cx="70" cy="70" r={RADIUS}
                fill="none"
                stroke="#10b981"
                strokeWidth="14"
                strokeDasharray={`${CIRCUMFERENCE} 0`}
                style={{
                  transform: 'rotate(-90deg)',
                  transformOrigin: '70px 70px',
                }}
              />
            ) : (
              segments.map((seg, i) => {
                const dash = Math.max(0, CIRCUMFERENCE * seg.pct - gap)
                const isHovered = hoveredSegment?.label === seg.label
                const el = (
                  <circle
                    key={i}
                    cx="70" cy="70" r={RADIUS}
                    fill="none"
                    stroke={seg.color}
                    strokeWidth={isHovered ? 18 : 14}
                    strokeDasharray={`${dash} ${CIRCUMFERENCE - dash}`}
                    strokeDashoffset={-offset}
                    strokeLinecap="round"
                    onMouseEnter={() => setHoveredSegment(seg)}
                    onMouseLeave={() => setHoveredSegment(null)}
                    onClick={() => handleSeverityClick(seg.label, seg.count)}
                    style={{
                      transform: 'rotate(-90deg)',
                      transformOrigin: '70px 70px',
                      transition: 'stroke-width 0.2s ease',
                    }}
                  />
                )
                offset += CIRCUMFERENCE * seg.pct
                return el
              })
            )}

            {/* Center label */}
            <text
              x="70" y="66"
              textAnchor="middle"
              className="donut-label fill-slate-800 dark:fill-slate-100"
              fontSize="22"
              fontWeight="700"
            >
              {hoveredSegment ? hoveredSegment.count : isZeroData ? '0' : '68'}
            </text>
            <text
              x="70" y="82"
              textAnchor="middle"
              className="donut-label fill-slate-400 dark:fill-slate-500"
              fontSize="11"
            >
              {hoveredSegment ? hoveredSegment.label : isZeroData ? 'Issues' : '/100'}
            </text>
          </svg>
        </div>

        <div className="flex-1 min-w-0">
          <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed mb-3">
            {isZeroData ? (
              <>
                Target infrastructure is currently verified with <strong className="text-emerald-600 dark:text-emerald-400 font-semibold">0 active vulnerabilities</strong>. Run a target scan anytime to evaluate new vectors.
              </>
            ) : (
              <>
                Your application has security issues requiring attention. Address{' '}
                <button
                  onClick={() => handleSeverityClick('Critical', 2)}
                  className="text-red-600 dark:text-red-400 font-semibold underline underline-offset-2 hover:text-red-800 dark:hover:text-red-300 cursor-pointer"
                >
                  critical
                </button>{' '}
                and{' '}
                <button
                  onClick={() => handleSeverityClick('High', 5)}
                  className="text-orange-600 dark:text-orange-400 font-semibold underline underline-offset-2 hover:text-orange-800 dark:hover:text-orange-300 cursor-pointer"
                >
                  high
                </button>{' '}
                severity findings first.
              </>
            )}
          </p>

          <div className="grid grid-cols-2 gap-1.5">
            {segments.map(b => (
              <button
                key={b.label}
                onClick={() => handleSeverityClick(b.label, b.count)}
                onMouseEnter={() => setHoveredSegment(b)}
                onMouseLeave={() => setHoveredSegment(null)}
                className="flex items-center justify-between px-2 py-1 rounded-md hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer group text-left border border-transparent hover:border-slate-200 dark:hover:border-slate-700"
                title={`Click to filter by ${b.label}`}
              >
                <div className="flex items-center gap-1.5 min-w-0">
                  <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: b.color }} />
                  <span className="text-[11px] text-slate-500 dark:text-slate-400 group-hover:text-slate-800 dark:group-hover:text-slate-200 truncate">{b.label}</span>
                </div>
                <span className="text-[11px] font-semibold text-slate-800 dark:text-slate-200 ml-1">{b.count}</span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
