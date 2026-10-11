'use client'
import type { Row } from '@/lib/prom'

// Compact single-series sparkline. One series → no legend (title names it).
// Flat low-opacity fill (no data gradient), 2px line, last-point marker.
export default function Sparkline({
  data,
  dataKey,
  color = '#34d399',
  height = 44,
  className = '',
}: {
  data: Row[]
  dataKey: string
  color?: string
  height?: number
  className?: string
}) {
  const W = 240
  const H = height
  const pad = 3
  const vals = data.map((d) => (typeof d[dataKey] === 'number' ? d[dataKey] : 0))
  const n = vals.length
  if (n < 2) {
    return <div className={className} style={{ height }} />
  }
  const max = Math.max(...vals, 1)
  const min = Math.min(...vals, 0)
  const span = max - min || 1
  const x = (i: number) => pad + (i / (n - 1)) * (W - pad * 2)
  const y = (val: number) => H - pad - ((val - min) / span) * (H - pad * 2)
  const pts = vals.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`)
  const line = `M${pts.join(' L')}`
  const area = `${line} L${x(n - 1).toFixed(1)},${H} L${x(0).toFixed(1)},${H} Z`
  const lastX = x(n - 1)
  const lastY = y(vals[n - 1])

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      preserveAspectRatio="none"
      className={className}
      style={{ width: '100%', height }}
    >
      <path d={area} fill={color} opacity={0.1} />
      <path d={line} fill="none" stroke={color} strokeWidth={1.8} vectorEffect="non-scaling-stroke" />
      <circle cx={lastX} cy={lastY} r={2.6} fill={color} vectorEffect="non-scaling-stroke">
        <animate attributeName="opacity" values="1;0.3;1" dur="1.6s" repeatCount="indefinite" />
      </circle>
    </svg>
  )
}
