'use client'

import { useState } from 'react'
import { RadarDataPoint } from '../types'
import { useToast } from './Toast'
import { useAppSelector } from '../store'

const SIZE = 200
const CENTER = SIZE / 2
const MAX_RADIUS = 74

function polarToCartesian(angle: number, radius: number) {
  const x = CENTER + radius * Math.sin(angle)
  const y = CENTER - radius * Math.cos(angle)
  return { x, y }
}

function buildPolygonPoints(values: number[], maxVal: number) {
  const n = values.length
  return values
    .map((v, i) => {
      const angle = (2 * Math.PI * i) / n
      const r = (v / maxVal) * MAX_RADIUS
      const { x, y } = polarToCartesian(angle, r)
      return `${x},${y}`
    })
    .join(' ')
}

function buildGridPoints(r: number, n: number) {
  return Array.from({ length: n }, (_, i) => {
    const angle = (2 * Math.PI * i) / n
    const { x, y } = polarToCartesian(angle, r)
    return `${x},${y}`
  }).join(' ')
}

const LABEL_OFFSET = 18

interface Props {
  isZeroData?: boolean
}

export default function SecurityRadar({ isZeroData: propZero }: Props) {
  const { toast } = useToast()
  const [selectedPoint, setSelectedPoint] = useState<RadarDataPoint | null>(null)
  const findingsZero = useAppSelector((state) => state.findings.isZeroData)
  const storeRadar = useAppSelector((state) => state.telemetry.radar)
  const isZeroData = propZero !== undefined ? propZero : findingsZero

  const activeRadar = storeRadar
  const n = Math.max(activeRadar.length, 3)
  const lowest = activeRadar.length ? activeRadar.reduce((a, b) => (b.value < a.value ? b : a)) : null
  const gridLevels = [0.25, 0.5, 0.75, 1]

  const handlePointClick = (d: RadarDataPoint) => {
    setSelectedPoint(d)
    toast('info', d.label, `${d.value}/100 from ${d.findings ?? 0} finding(s) mapped to this area. 100 means none recorded (not proof of safety).`)
  }

  return (
    <div className="card p-5 h-full flex flex-col justify-between gap-2">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-800 dark:text-slate-100">Security Radar</h2>
        <span className="text-[10px] text-slate-400 dark:text-slate-500 font-mono">{activeRadar.length} scope areas</span>
      </div>

      <div className="flex justify-center relative select-none my-auto py-1">
        <svg width={SIZE} height={SIZE} viewBox={`0 0 ${SIZE} ${SIZE}`} className="overflow-visible">
          {/* Grid rings */}
          {gridLevels.map((lvl) => (
            <polygon
              key={lvl}
              points={buildGridPoints(MAX_RADIUS * lvl, n)}
              fill="none"
              className="stroke-slate-200 dark:stroke-slate-800"
              strokeWidth="1"
            />
          ))}

          {/* Axis lines */}
          {activeRadar.map((_, i) => {
            const angle = (2 * Math.PI * i) / n
            const { x, y } = polarToCartesian(angle, MAX_RADIUS)
            return (
              <line
                key={i}
                x1={CENTER} y1={CENTER}
                x2={x} y2={y}
                className="stroke-slate-200 dark:stroke-slate-800"
                strokeWidth="1"
              />
            )
          })}

          {/* Data polygon */}
          <polygon
            points={buildPolygonPoints(
              activeRadar.map(d => d.value),
              100
            )}
            className="radar-polygon transition-all duration-300"
          />

          {/* Data dots */}
          {activeRadar.map((d, i) => {
            const angle = (2 * Math.PI * i) / n
            const r = (d.value / 100) * MAX_RADIUS
            const { x, y } = polarToCartesian(angle, r)
            const isSelected = selectedPoint?.label === d.label
            return (
              <g key={i} className="cursor-pointer" onClick={() => handlePointClick(d)}>
                <circle
                  cx={x} cy={y}
                  r={isSelected ? "5" : "3.5"}
                  fill={isSelected ? "#4338ca" : "#6366f1"}
                  stroke="white"
                  strokeWidth="1.5"
                  className="transition-all hover:scale-125"
                />
              </g>
            )
          })}

          {/* Labels */}
          {activeRadar.map((d, i) => {
            const angle = (2 * Math.PI * i) / n
            const { x, y } = polarToCartesian(angle, MAX_RADIUS + LABEL_OFFSET)
            const isSelected = selectedPoint?.label === d.label
            return (
              <text
                key={i}
                x={x}
                y={y}
                textAnchor="middle"
                dominantBaseline="central"
                onClick={() => handlePointClick(d)}
                className={`cursor-pointer transition-colors text-[9px] font-medium ${
                  isSelected
                    ? 'fill-indigo-600 dark:fill-indigo-400 font-bold'
                    : 'fill-slate-500 dark:fill-slate-400 hover:fill-indigo-600 dark:hover:fill-indigo-400'
                }`}
              >
                {d.label.split(' ')[0]}
              </text>
            )
          })}
        </svg>
      </div>

      {/* Selected metric footer */}
      <div className="pt-2 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between text-xs">
        <span className="text-slate-500 dark:text-slate-400">
          {selectedPoint ? selectedPoint.label : 'Weakest area:'}
        </span>
        <span className="font-semibold text-slate-800 dark:text-slate-200">
          {selectedPoint
            ? `${selectedPoint.value} / 100 (${selectedPoint.findings ?? 0} findings)`
            : lowest
              ? `${lowest.label} (${lowest.value}/100)`
              : 'No data'}
        </span>
      </div>
    </div>
  )
}
