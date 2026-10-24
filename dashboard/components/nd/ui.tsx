'use client'
import { useState, type ReactNode } from 'react'
import Sparkline from '@/components/noc/Sparkline'
import type { Row } from '@/lib/prom'

// Building blocks for the analytics console (components/analytics/AnalyticsView.tsx): calm cards, KPI tiles with
// period-over-period deltas, bar lists, split bars and a status heat strip.

// Categorical series colours, as CSS variables so each theme supplies its own
// validated steps (globals.css .nd-dark / .nd-light). Assign in this fixed
// order, never cycled. Recharts and SVG accept var() colours directly.
export const SERIES = ['var(--s1)', 'var(--s2)', 'var(--s3)', 'var(--s4)', 'var(--s5)'] as const

// Status colours are reserved for state and always ship with a text label.
export const STATUS = {
  good: { dot: 'bg-st-good', text: 'text-st-good-fg', ring: 'ring-st-good/30', bg: 'bg-st-good/10' },
  warn: { dot: 'bg-st-warn', text: 'text-st-warn-fg', ring: 'ring-st-warn/30', bg: 'bg-st-warn/10' },
  serious: { dot: 'bg-st-serious', text: 'text-st-serious-fg', ring: 'ring-st-serious/30', bg: 'bg-st-serious/10' },
  crit: { dot: 'bg-st-crit', text: 'text-st-crit-fg', ring: 'ring-st-crit/30', bg: 'bg-st-crit/10' },
  neutral: { dot: 'bg-st-neutral', text: 'text-st-neutral-fg', ring: 'ring-nd-line', bg: 'bg-nd-fill' },
} as const
export type Status = keyof typeof STATUS

export function Card({ title, sub, right, className = '', children }: {
  title?: string
  sub?: string
  right?: ReactNode
  className?: string
  children: ReactNode
}) {
  return (
    <div className={`rounded-2xl border border-nd-line bg-nd-card p-5 ${className}`}>
      {(title || right) && (
        <div className="mb-4 flex items-start justify-between gap-3">
          <div className="min-w-0">
            {title && <h3 className="text-[13.5px] font-semibold text-nd-fg">{title}</h3>}
            {sub && <p className="mt-0.5 text-[12px] text-nd-dim">{sub}</p>}
          </div>
          {right}
        </div>
      )}
      {children}
    </div>
  )
}

export function Section({ id, title, sub, children }: { id: string; title: string; sub: string; children: ReactNode }) {
  return (
    <section id={id} className="mt-12 scroll-mt-24 first-of-type:mt-0">
      <div className="mb-4 flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h2 className="text-[19px] font-semibold tracking-tight text-nd-fg">{title}</h2>
        <span className="text-[12.5px] text-nd-dim">{sub}</span>
      </div>
      <div className="space-y-4">{children}</div>
    </section>
  )
}

export function Pill({ status, children }: { status: Status; children: ReactNode }) {
  const s = STATUS[status]
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11.5px] font-medium ring-1 ring-inset ${s.bg} ${s.text} ${s.ring}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
      {children}
    </span>
  )
}

// Period-over-period change, e.g. "▲ 12% vs prev 1h". Direction is carried by
// the glyph, so the text stays in neutral ink.
export function delta(cur: number | null | undefined, prev: number | null | undefined, label: string) {
  if (cur == null || prev == null || !Number.isFinite(cur) || !Number.isFinite(prev)) return undefined
  if (prev === 0) return cur === 0 ? `no change vs ${label}` : `new vs ${label}`
  const d = (cur - prev) / Math.abs(prev)
  if (Math.abs(d) < 0.005) return `no change vs ${label}`
  const p = Math.abs(d) >= 10 ? `${Math.round(d)}×` : `${Math.round(Math.abs(d) * 100)}%`
  return `${d > 0 ? '▲' : '▼'} ${p} vs ${label}`
}

export function Kpi({ label, value, sub, status, spark, sparkKey, color = SERIES[0], tip }: {
  label: string
  value: string
  sub?: string
  status?: Status
  spark?: Row[]
  sparkKey?: string
  color?: string
  tip?: string
}) {
  return (
    <div className="flex min-w-0 flex-col rounded-2xl border border-nd-line bg-nd-card p-4" title={tip}>
      <div className="flex items-center justify-between gap-2">
        <span className="truncate text-[12px] font-medium text-nd-muted">{label}</span>
        {status && status !== 'neutral' && (
          <span className={`inline-flex items-center gap-1 text-[10.5px] font-medium ${STATUS[status].text}`}>
            <span className={`h-1.5 w-1.5 rounded-full ${STATUS[status].dot}`} />
            {status === 'good' ? 'ok' : status === 'warn' ? 'watch' : status === 'serious' ? 'high' : 'critical'}
          </span>
        )}
      </div>
      <div className="mono mt-2 truncate text-[24px] font-semibold leading-tight tracking-tight text-nd-fg tabular-nums">{value}</div>
      {sub && <div className="mt-1 truncate text-[11.5px] text-nd-dim">{sub}</div>}
      {spark && sparkKey && <Sparkline data={spark} dataKey={sparkKey} color={color} height={34} className="mt-3" />}
    </div>
  )
}

export interface BarRow { label: string; v: number; sub?: string }

// Ranked horizontal bars — one hue (magnitude), value text in neutral ink.
export function BarList({ rows, fmt, empty = 'Nothing recorded in this range', color = SERIES[0], mono = false }: {
  rows: BarRow[]
  fmt: (n: number) => string
  empty?: string
  color?: string
  mono?: boolean
}) {
  const max = Math.max(...rows.map((r) => r.v), 0)
  if (rows.length === 0 || max <= 0) return <div className="py-6 text-center text-[12px] text-nd-faint">{empty}</div>
  return (
    <ul className="space-y-2.5">
      {rows.map((r) => (
        <li key={r.label} title={`${r.label}: ${fmt(r.v)}`}>
          <div className="mb-1 flex items-baseline justify-between gap-3 text-[12.5px]">
            <span className={`truncate text-nd-fg-3 ${mono ? 'mono' : ''}`}>
              {r.label}
              {r.sub && <span className="ml-2 text-[11px] text-nd-faint">{r.sub}</span>}
            </span>
            <span className="mono shrink-0 tabular-nums text-nd-fg-2">{fmt(r.v)}</span>
          </div>
          <div className="h-1.5 rounded-full bg-nd-track">
            <div className="h-full rounded-full" style={{ width: `${Math.max(1.5, (r.v / max) * 100)}%`, background: color }} />
          </div>
        </li>
      ))}
    </ul>
  )
}

export interface SplitRow { key: string; label: string; v: number; color: string }

// 100% stacked bar with 2px surface gaps and a legend carrying value + share.
export function SplitBar({ rows, fmt, empty = 'No traffic in this range' }: { rows: SplitRow[]; fmt: (n: number) => string; empty?: string }) {
  const total = rows.reduce((a, r) => a + (r.v > 0 ? r.v : 0), 0)
  if (total <= 0) return <div className="py-4 text-center text-[12px] text-nd-faint">{empty}</div>
  const shown = rows.filter((r) => r.v > 0)
  return (
    <div>
      <div className="flex h-3 gap-[2px] overflow-hidden rounded-full">
        {shown.map((r) => (
          <div
            key={r.key}
            title={`${r.label}: ${fmt(r.v)} (${((r.v / total) * 100).toFixed(1)}%)`}
            className="h-full first:rounded-l-full last:rounded-r-full"
            style={{ width: `${(r.v / total) * 100}%`, minWidth: 3, background: r.color }}
          />
        ))}
      </div>
      <ul className="mt-3 space-y-1.5">
        {shown.map((r) => (
          <li key={r.key} className="flex items-center justify-between gap-3 text-[12.5px]">
            <span className="flex min-w-0 items-center gap-2 text-nd-fg-3">
              <span className="h-2.5 w-2.5 shrink-0 rounded-[3px]" style={{ background: r.color }} />
              <span className="truncate">{r.label}</span>
            </span>
            <span className="mono shrink-0 tabular-nums text-nd-muted">
              {fmt(r.v)} <span className="ml-1.5 inline-block w-12 text-right text-nd-fg-2">{((r.v / total) * 100).toFixed(1)}%</span>
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

// Risk level (0–5) per time bucket. Colour = state, so every level has a
// legend label; hovering a cell reads out its time and level above the strip.
const LEVELS: { label: string; cls: string }[] = [
  { label: 'calm', cls: 'bg-lv0' },
  { label: 'low', cls: 'bg-lv1' },
  { label: 'guarded', cls: 'bg-lv2' },
  { label: 'elevated', cls: 'bg-lv3' },
  { label: 'high', cls: 'bg-lv4' },
  { label: 'critical', cls: 'bg-lv5' },
]
export const levelLabel = (l: number) => LEVELS[Math.max(0, Math.min(5, Math.round(l)))].label

export function HeatStrip({ cells }: { cells: { t: number; v: number | null }[] }) {
  const [hover, setHover] = useState<number | null>(null)
  const h = hover != null ? cells[hover] : null
  const fmtT = (t: number) => new Date(t).toLocaleString([], { weekday: 'short', hour: '2-digit', minute: '2-digit' })
  const peak = cells.reduce((m, c) => Math.max(m, c.v ?? 0), 0)
  return (
    <div>
      <div className="mb-2 flex h-5 items-center justify-between text-[12px]">
        <span className="text-nd-muted">
          {h ? (
            <>
              <span className="mono text-nd-fg-2">{fmtT(h.t)}</span> · level{' '}
              <span className="mono text-nd-fg">{h.v == null ? 'no data' : `${Math.round(h.v)} — ${levelLabel(h.v)}`}</span>
            </>
          ) : (
            <>Peak in range: <span className="mono text-nd-fg">{Math.round(peak)} — {levelLabel(peak)}</span></>
          )}
        </span>
      </div>
      <div className="flex h-9 gap-[2px]" onMouseLeave={() => setHover(null)}>
        {cells.map((c, i) => (
          <div
            key={c.t}
            onMouseEnter={() => setHover(i)}
            className={`h-full flex-1 rounded-[3px] transition-opacity ${c.v == null ? 'bg-lv-none' : LEVELS[Math.max(0, Math.min(5, Math.round(c.v)))].cls} ${hover != null && hover !== i ? 'opacity-60' : ''}`}
          />
        ))}
      </div>
      <div className="mt-2 flex justify-between text-[10.5px] text-nd-faint">
        <span>{cells[0] ? fmtT(cells[0].t) : ''}</span>
        <span>now</span>
      </div>
      <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5 text-[11px] text-nd-muted">
        {LEVELS.map((l, i) => (
          <span key={l.label} className="flex items-center gap-1.5">
            <span className={`h-2.5 w-2.5 rounded-[3px] ${l.cls}`} />
            {i} {l.label}
          </span>
        ))}
      </div>
    </div>
  )
}

// 0–1 score as a ring, with the number in the centre.
export function Ring({ value, label, status }: { value: number; label: string; status: Status }) {
  const r = 46
  const c = 2 * Math.PI * r
  const v = Math.max(0, Math.min(1, value))
  const stroke = `var(--st-${status})`
  return (
    <div className="relative h-[120px] w-[120px] shrink-0">
      <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90">
        <circle cx="60" cy="60" r={r} fill="none" stroke="var(--nd-track)" strokeWidth="9" />
        <circle cx="60" cy="60" r={r} fill="none" stroke={stroke} strokeWidth="9" strokeLinecap="round" strokeDasharray={`${c * v} ${c}`} className="transition-[stroke-dasharray] duration-700" />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="mono text-[26px] font-semibold leading-none text-nd-fg tabular-nums">{v.toFixed(2)}</span>
        <span className="mt-1 text-[10.5px] uppercase tracking-[0.14em] text-nd-dim">{label}</span>
      </div>
    </div>
  )
}

export function Fact({ label, value, status }: { label: string; value: string; status?: Status }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-nd-line-soft py-2 text-[12.5px] last:border-0">
      <span className="text-nd-muted">{label}</span>
      <span className="mono flex items-center gap-1.5 tabular-nums text-nd-fg">
        {status && <span className={`h-1.5 w-1.5 rounded-full ${STATUS[status].dot}`} />}
        {value}
      </span>
    </div>
  )
}
