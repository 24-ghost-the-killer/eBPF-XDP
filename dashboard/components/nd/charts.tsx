'use client'
import {
  AreaChart, Area, LineChart, Line, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from 'recharts'
import type { Row } from '@/lib/prom'
import { SERIES } from './ui'

// Theme-driven (globals.css .nd-dark / .nd-light); SVG takes var() colours.
const AXIS = { stroke: 'transparent', tick: { fill: 'var(--nd-dim)', fontSize: 11 } }
const GRID = 'var(--nd-grid)'

const timeTick = (spanMs: number) => (t: number) =>
  spanMs > 20 * 3600e3
    ? new Date(t).toLocaleString([], { weekday: 'short', hour: '2-digit' })
    : new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })

// Shared crosshair tooltip: every series at the hovered time, largest first.
function TipBox({ active, payload, label, yfmt, names }: {
  active?: boolean
  payload?: { dataKey: string; value: number; color: string }[]
  label?: number
  yfmt: (n: number) => string
  names: Record<string, string>
}) {
  if (!active || !payload?.length) return null
  const rows = [...payload].sort((a, b) => (b.value ?? 0) - (a.value ?? 0))
  return (
    <div className="min-w-[170px] rounded-xl border border-nd-line bg-nd-tip px-3 py-2.5 text-[12px] shadow-nd-lg backdrop-blur">
      <div className="mb-1.5 text-[11px] text-nd-dim">{new Date(Number(label)).toLocaleString([], { weekday: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit' })}</div>
      {rows.map((p) => (
        <div key={p.dataKey} className="flex items-center justify-between gap-4 py-0.5">
          <span className="flex items-center gap-2 text-nd-fg-3">
            <span className="h-2 w-2 rounded-full" style={{ background: p.color }} />
            {names[p.dataKey] ?? p.dataKey}
          </span>
          <span className="mono tabular-nums text-nd-fg">{p.value == null ? '—' : yfmt(p.value)}</span>
        </div>
      ))}
    </div>
  )
}

export interface SeriesDef { key: string; label: string; color?: string; dashed?: boolean }

// Time series chart. Colours follow the entity (passed per series, else slot
// order), a legend is shown for >=2 series, and one y-axis only.
export function TimeChart({ data, series, yfmt, kind = 'line', stacked = false, height = 240, spanMs, loading, yDomain }: {
  data: Row[]
  series: SeriesDef[]
  yfmt: (n: number) => string
  kind?: 'line' | 'area'
  stacked?: boolean
  height?: number
  spanMs: number
  // false once the query has answered: an empty result then says so instead of shimmering
  loading?: boolean
  // fixed y range, e.g. [0, 1] for scores (otherwise recharts picks one)
  yDomain?: [number, number]
}) {
  const defs = series.map((s, i) => ({ ...s, color: s.color ?? SERIES[i % SERIES.length] }))
  const names = Object.fromEntries(defs.map((d) => [d.key, d.label]))
  const common = {
    data,
    margin: { top: 6, right: 6, bottom: 0, left: 0 },
  }
  const axes = (
    <>
      <CartesianGrid stroke={GRID} vertical={false} />
      <XAxis dataKey="t" type="number" scale="time" domain={['dataMin', 'dataMax']} tickFormatter={timeTick(spanMs)} minTickGap={56} tickLine={false} axisLine={false} {...AXIS} />
      <YAxis tickFormatter={yfmt} width={76} tickLine={false} axisLine={false} domain={yDomain} allowDataOverflow={!!yDomain} {...AXIS} />
      <Tooltip cursor={{ stroke: 'var(--nd-cursor)', strokeWidth: 1 }} content={<TipBox yfmt={yfmt} names={names} />} />
    </>
  )
  return (
    <div>
      {defs.length >= 2 && (
        <div className="mb-3 flex flex-wrap gap-x-4 gap-y-1 text-[11.5px] text-nd-muted">
          {defs.map((d) => (
            <span key={d.key} className="flex items-center gap-1.5">
              <span className="h-0 w-3.5 border-t-[2.5px]" style={{ borderColor: d.color, borderTopStyle: d.dashed ? 'dashed' : 'solid' }} />
              {d.label}
            </span>
          ))}
        </div>
      )}
      {data.length < 2 ? (
        loading === false ? (
          <div className="flex items-center justify-center rounded-xl border border-dashed border-nd-line text-[12.5px] text-nd-dim" style={{ height }}>No data in this window</div>
        ) : (
          <div className="aa-skeleton rounded-xl" style={{ height }} aria-label="Loading chart" />
        )
      ) : (
        <ResponsiveContainer width="100%" height={height}>
          {kind === 'area' ? (
            <AreaChart {...common}>
              {axes}
              {defs.map((d) => (
                <Area
                  key={d.key}
                  type="monotone"
                  dataKey={d.key}
                  stackId={stacked ? 's' : undefined}
                  stroke={d.color}
                  strokeWidth={2}
                  fill={d.color}
                  fillOpacity={0.14}
                  dot={false}
                  activeDot={{ r: 4, stroke: 'var(--nd-card)', strokeWidth: 2 }}
                  isAnimationActive={false}
                />
              ))}
            </AreaChart>
          ) : (
            <LineChart {...common}>
              {axes}
              {defs.map((d) => (
                <Line
                  key={d.key}
                  type="monotone"
                  dataKey={d.key}
                  stroke={d.color}
                  strokeWidth={2}
                  strokeDasharray={d.dashed ? '5 4' : undefined}
                  dot={false}
                  activeDot={{ r: 4, stroke: 'var(--nd-card)', strokeWidth: 2 }}
                  isAnimationActive={false}
                />
              ))}
            </LineChart>
          )}
        </ResponsiveContainer>
      )}
    </div>
  )
}

// One bar per day (single series, so no legend — the card title names it).
export function DayBars({ data, height = 180 }: { data: { day: string; n: number; label: string }[]; height?: number }) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 6, right: 6, bottom: 0, left: 0 }} barCategoryGap={2}>
        <CartesianGrid stroke={GRID} vertical={false} />
        <XAxis dataKey="day" tickLine={false} axisLine={false} interval="preserveStartEnd" minTickGap={18} {...AXIS} />
        <YAxis allowDecimals={false} width={28} tickLine={false} axisLine={false} {...AXIS} />
        <Tooltip
          cursor={{ fill: 'var(--nd-track)' }}
          content={({ active, payload }) =>
            active && payload?.length ? (
              <div className="rounded-lg border border-nd-line bg-nd-tip px-3 py-2 text-[12px] shadow-xl">
                <div className="text-[11px] text-nd-dim">{(payload[0].payload as { label: string }).label}</div>
                <div className="mono mt-0.5 text-nd-fg">{payload[0].value as number} attack{payload[0].value === 1 ? '' : 's'}</div>
              </div>
            ) : null
          }
        />
        <Bar dataKey="n" fill={SERIES[1]} radius={[4, 4, 0, 0]} maxBarSize={28} isAnimationActive={false} />
      </BarChart>
    </ResponsiveContainer>
  )
}
