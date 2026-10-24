'use client'
import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'
import { ArrowDownRight, ArrowUpRight, ChevronLeft, ChevronRight, Minus } from 'lucide-react'
import Sparkline from '@/components/noc/Sparkline'
import type { Row } from '@/lib/prom'

// UI kit for the analytics site. Everything reads the .nd-* theme tokens, so
// it renders correctly in both light and dark. Spacing sits on a 4/8px grid;
// surfaces are white (or near-black) cards with a hairline border and soft
// elevation; numbers use tabular figures.

export function Panel({ title, sub, icon: I, actions, children, className = '', bodyClass = 'px-5 pb-5' }: {
  title?: ReactNode
  sub?: ReactNode
  icon?: LucideIcon
  actions?: ReactNode
  children: ReactNode
  className?: string
  bodyClass?: string
}) {
  return (
    <section className={`aa-in min-w-0 rounded-2xl border border-nd-line bg-nd-card shadow-nd ${className}`}>
      {(title || actions) && (
        <header className="flex items-start justify-between gap-3 px-5 pb-3 pt-4">
          <div className="flex min-w-0 items-start gap-2.5">
            {I && (
              <span className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-nd-fill text-nd-muted">
                <I className="h-3.5 w-3.5" />
              </span>
            )}
            <div className="min-w-0">
              {title && <h3 className="truncate text-[14px] font-semibold tracking-[-0.01em] text-nd-fg">{title}</h3>}
              {sub && <p className="mt-0.5 truncate text-[12.5px] text-nd-dim">{sub}</p>}
            </div>
          </div>
          {actions && <div className="flex shrink-0 items-center gap-1.5">{actions}</div>}
        </header>
      )}
      <div className={bodyClass}>{children}</div>
    </section>
  )
}

export type Tone = 'good' | 'bad' | 'warn' | 'neutral' | 'brand'
const TONE: Record<Tone, string> = {
  good: 'bg-st-good/10 text-st-good-fg ring-st-good/20',
  bad: 'bg-st-crit/10 text-st-crit-fg ring-st-crit/20',
  warn: 'bg-st-warn/10 text-st-warn-fg ring-st-warn/25',
  neutral: 'bg-nd-fill text-nd-muted ring-nd-line',
  brand: 'bg-nd-brand-soft text-nd-brand ring-nd-brand/20',
}
export function Badge({ tone = 'neutral', icon: I, children, className = '' }: { tone?: Tone; icon?: LucideIcon; children: ReactNode; className?: string }) {
  return (
    <span className={`inline-flex items-center gap-1 whitespace-nowrap rounded-full px-2 py-0.5 text-[11.5px] font-medium ring-1 ring-inset ${TONE[tone]} ${className}`}>
      {I && <I className="h-3 w-3" />}
      {children}
    </span>
  )
}

// Change vs a previous value. `upIsBad` flips the colouring (more drops = bad).
export interface Trend { text: string; dir: 'up' | 'down' | 'flat'; tone: Tone }
export function trend(cur: number | null | undefined, prev: number | null | undefined, upIsBad = false): Trend | undefined {
  if (cur == null || prev == null || !Number.isFinite(cur) || !Number.isFinite(prev)) return undefined
  if (prev === 0) return cur === 0 ? { text: '0%', dir: 'flat', tone: 'neutral' } : { text: 'new', dir: 'up', tone: upIsBad ? 'bad' : 'neutral' }
  const d = (cur - prev) / Math.abs(prev)
  if (Math.abs(d) < 0.005) return { text: '0%', dir: 'flat', tone: 'neutral' }
  const text = Math.abs(d) >= 10 ? `${Math.round(Math.abs(d))}×` : `${Math.round(Math.abs(d) * 100)}%`
  const up = d > 0
  return { text, dir: up ? 'up' : 'down', tone: up === upIsBad ? 'bad' : 'good' }
}

export function Stat({ label, value, icon: I, trend: t, trendLabel, sub, spark, sparkKey = 'v', color = 'var(--s1)', loading }: {
  label: string
  value: ReactNode
  icon?: LucideIcon
  trend?: Trend
  trendLabel?: string
  sub?: ReactNode
  spark?: Row[]
  sparkKey?: string
  color?: string
  loading?: boolean
}) {
  const Arrow = t?.dir === 'up' ? ArrowUpRight : t?.dir === 'down' ? ArrowDownRight : Minus
  return (
    <div className="aa-in flex min-w-0 flex-col rounded-2xl border border-nd-line bg-nd-card p-4 shadow-nd">
      <div className="flex items-center gap-2">
        {I && (
          <span className="grid h-7 w-7 place-items-center rounded-lg bg-nd-fill text-nd-muted">
            <I className="h-3.5 w-3.5" />
          </span>
        )}
        <span className="truncate text-[12.5px] font-medium text-nd-muted">{label}</span>
      </div>
      {loading ? (
        <div className="aa-skeleton mt-3 h-7 w-28 rounded-md" />
      ) : (
        <div className="mono mt-2.5 truncate text-[26px] font-semibold leading-none tracking-[-0.02em] text-nd-fg tabular-nums">{value}</div>
      )}
      <div className="mt-2.5 flex min-h-[20px] items-center gap-1.5 text-[12px] text-nd-dim">
        {t && (
          <Badge tone={t.tone} className="!px-1.5">
            <Arrow className="h-3 w-3" />
            {t.text}
          </Badge>
        )}
        <span className="truncate">{t ? trendLabel : sub}</span>
      </div>
      {spark && spark.length > 1 && <Sparkline data={spark} dataKey={sparkKey} color={color} height={36} className="mt-3" />}
    </div>
  )
}

export function Segmented<T extends string>({ options, value, onChange, size = 'md', label }: {
  options: readonly { id: T; label: ReactNode }[]
  value: T
  onChange: (v: T) => void
  size?: 'sm' | 'md'
  label: string
}) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex rounded-xl border border-nd-line bg-nd-fill p-0.5">
      {options.map((o) => (
        <button
          key={o.id}
          role="radio"
          aria-checked={value === o.id}
          onClick={() => onChange(o.id)}
          className={`rounded-[10px] font-medium transition-all ${size === 'sm' ? 'px-2 py-0.5 text-[12px]' : 'px-3 py-1 text-[12.5px]'} ${
            value === o.id ? 'bg-nd-card text-nd-fg shadow-nd' : 'text-nd-dim hover:text-nd-fg'
          }`}
        >
          {o.label}
        </button>
      ))}
    </div>
  )
}

export function Chip({ on, onClick, children }: { on: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <button
      onClick={onClick}
      aria-pressed={on}
      className={`rounded-full border px-3 py-1 text-[12.5px] font-medium transition-colors ${
        on ? 'border-nd-fg bg-nd-fg text-nd-bg' : 'border-nd-line bg-nd-card text-nd-muted hover:border-nd-line-strong hover:text-nd-fg'
      }`}
    >
      {children}
    </button>
  )
}

export function IconButton({ icon: I, label, onClick, active }: { icon: LucideIcon; label: string; onClick?: () => void; active?: boolean }) {
  return (
    <button
      onClick={onClick}
      aria-label={label}
      title={label}
      className={`grid h-8 w-8 place-items-center rounded-lg border transition-colors ${active ? 'border-nd-line-strong bg-nd-fill-2 text-nd-fg' : 'border-nd-line bg-nd-card text-nd-muted hover:text-nd-fg'}`}
    >
      <I className="h-4 w-4" />
    </button>
  )
}

export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`aa-skeleton rounded-lg ${className}`} />
}

export function Empty({ icon: I, title, hint, className = '' }: { icon: LucideIcon; title: string; hint?: ReactNode; className?: string }) {
  return (
    <div className={`flex flex-col items-center justify-center px-6 py-10 text-center ${className}`}>
      <span className="grid h-10 w-10 place-items-center rounded-xl bg-nd-fill text-nd-dim">
        <I className="h-5 w-5" />
      </span>
      <p className="mt-3 text-[13.5px] font-medium text-nd-fg-2">{title}</p>
      {hint && <p className="mt-1 max-w-sm text-[12.5px] leading-relaxed text-nd-dim">{hint}</p>}
    </div>
  )
}

// Page numbers to show: always first and last, the current page with one
// neighbour each side, and "…" for the gaps (1 … 4 5 6 … 12).
function pageList(page: number, pages: number): (number | '…')[] {
  const keep = new Set([1, pages, page - 1, page, page + 1].filter((n) => n >= 1 && n <= pages))
  const out: (number | '…')[] = []
  let prev = 0
  for (const n of [...keep].sort((a, b) => a - b)) {
    if (n - prev > 1) out.push('…')
    out.push(n)
    prev = n
  }
  return out
}

export function Pagination({ page, pageSize, total, onPage, noun = 'items' }: {
  page: number // 1-based
  pageSize: number
  total: number
  onPage: (p: number) => void
  noun?: string
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize))
  const from = total ? (page - 1) * pageSize + 1 : 0
  const to = Math.min(total, page * pageSize)
  const cell = 'inline-flex h-8 min-w-8 items-center justify-center rounded-lg px-2 text-[13px] font-medium transition-colors'
  return (
    <nav aria-label="Pagination" className="flex flex-wrap items-center justify-between gap-3 border-t border-nd-line px-5 py-3">
      <p className="text-[12.5px] text-nd-dim">
        Showing <span className="font-medium text-nd-fg-2">{from}–{to}</span> of <span className="font-medium text-nd-fg-2">{total}</span> {noun}
      </p>
      {pages > 1 && (
        <div className="flex items-center gap-1">
          <button onClick={() => onPage(page - 1)} disabled={page <= 1} className={`${cell} gap-1 text-nd-muted hover:bg-nd-fill hover:text-nd-fg disabled:pointer-events-none disabled:opacity-40`}>
            <ChevronLeft className="h-4 w-4" /> <span className="hidden sm:inline">Previous</span>
          </button>
          {pageList(page, pages).map((n, i) =>
            n === '…' ? (
              <span key={`gap${i}`} className="px-1 text-[13px] text-nd-faint">…</span>
            ) : (
              <button
                key={n}
                onClick={() => onPage(n)}
                aria-current={n === page ? 'page' : undefined}
                aria-label={`Page ${n}`}
                className={`${cell} ${n === page ? 'bg-nd-fg text-nd-bg shadow-nd' : 'text-nd-muted hover:bg-nd-fill hover:text-nd-fg'}`}
              >
                {n}
              </button>
            )
          )}
          <button onClick={() => onPage(page + 1)} disabled={page >= pages} className={`${cell} gap-1 text-nd-muted hover:bg-nd-fill hover:text-nd-fg disabled:pointer-events-none disabled:opacity-40`}>
            <span className="hidden sm:inline">Next</span> <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      )}
    </nav>
  )
}

export const btn = {
  primary: 'inline-flex items-center gap-1.5 rounded-lg bg-nd-fg px-3.5 py-2 text-[13px] font-medium text-nd-bg shadow-nd transition-opacity hover:opacity-90 disabled:opacity-40',
  ghost: 'inline-flex items-center gap-1.5 rounded-lg border border-nd-line bg-nd-card px-3 py-1.5 text-[13px] font-medium text-nd-fg-3 shadow-nd transition-colors hover:border-nd-line-strong hover:text-nd-fg disabled:opacity-40',
  input: 'rounded-lg border border-nd-line bg-nd-card px-3 py-2 text-[13px] text-nd-fg shadow-nd outline-none transition-colors placeholder:text-nd-faint focus:border-nd-line-strong focus:ring-4 focus:ring-nd-fill-2',
}
