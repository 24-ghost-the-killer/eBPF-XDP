'use client'
// Shared bits for the admin pages (Users and Groups): the permission catalog
// types, a plain-language summary of what a set of permissions allows, the
// Users/Groups tab bar, and small visual helpers.
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { Users, UsersRound, Check, X } from 'lucide-react'

export const ADMIN_PAGE = 'users'
export interface PageDef { id: string; label: string; hint?: string }
export interface ActionDef { id: string; page: string; label: string; hint: string; danger?: boolean }
export interface AreaDef { id: string; label: string; pages: string[] }
export interface PresetDef { id: string; label: string; hint: string; perms: string[] }
export interface Catalog { pages: PageDef[]; actions: ActionDef[]; areas: AreaDef[]; presets: PresetDef[]; adminPage: string }
export interface Group { name: string; perms: string[]; members?: string[]; requireMfa?: boolean }
export interface SafeUser { username: string; group: string; disabled: boolean; createdAt: number; lastLogin: number; mfa: boolean }

export async function readError(r: Response): Promise<string> {
  try { const j = await r.json(); return j?.error || `error ${r.status}` } catch { return `error ${r.status}` }
}

// Deterministic accent for a name (group chips, avatars) from the chart ramp.
const ACCENTS = ['var(--s1)', 'var(--s2)', 'var(--s3)', 'var(--s4)', 'var(--s5)']
export function accentFor(name: string): string {
  let h = 0
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0
  return ACCENTS[h % ACCENTS.length]
}
export function initials(name: string): string {
  const parts = name.replace(/[._-]+/g, ' ').trim().split(/\s+/)
  return ((parts[0]?.[0] || '') + (parts[1]?.[0] || '')).toUpperCase() || name.slice(0, 2).toUpperCase()
}

export function relTime(ts: number): string {
  if (!ts) return 'never'
  const d = Math.floor(Date.now() / 1000) - ts
  if (d < 60) return 'just now'
  if (d < 3600) return `${Math.floor(d / 60)} min ago`
  if (d < 86400) return `${Math.floor(d / 3600)} h ago`
  if (d < 86400 * 30) return `${Math.floor(d / 86400)} d ago`
  return new Date(ts * 1000).toLocaleDateString()
}

// Plain-language summary of a permission set, most important first.
export type Level = 'admin' | 'full' | 'edit' | 'view' | 'none'
export interface AccessSummary { level: Level; chips: { label: string; tone: 'brand' | 'warn' | 'neutral' | 'good' }[]; pages: number; actions: number }
export function summarize(perms: string[], cat: Catalog): AccessSummary {
  const set = new Set(perms)
  const pages = cat.pages.filter((p) => set.has(p.id)).length
  const actions = cat.actions.filter((a) => set.has(a.id)).length
  const chips: AccessSummary['chips'] = []
  if (set.has(cat.adminPage)) chips.push({ label: 'Admin', tone: 'brand' })
  if (set.has('protect')) {
    const pa = cat.actions.filter((a) => a.page === 'protect')
    const n = pa.filter((a) => set.has(a.id)).length
    chips.push(n === pa.length ? { label: 'Protection: full', tone: 'warn' } : n > 0 ? { label: `Protection: ${n}/${pa.length} actions`, tone: 'good' } : { label: 'Protection: view', tone: 'neutral' })
  }
  const monitor = cat.areas.find((a) => a.id === 'monitor')?.pages ?? []
  const m = monitor.filter((p) => set.has(p)).length
  if (m) chips.push({ label: m === monitor.length ? 'All dashboards' : `${m} dashboard${m === 1 ? '' : 's'}`, tone: 'neutral' })
  if (set.has('query')) chips.push({ label: 'Query console', tone: 'neutral' })
  const level: Level = set.has(cat.adminPage) ? 'admin' : actions === cat.actions.length && actions > 0 ? 'full' : actions > 0 ? 'edit' : pages > 0 ? 'view' : 'none'
  if (!pages) chips.push({ label: 'No access', tone: 'warn' })
  return { level, chips, pages, actions }
}

const CHIP: Record<string, string> = {
  brand: 'bg-nd-brand-soft text-nd-brand ring-nd-brand/20',
  warn: 'bg-st-warn/10 text-st-warn-fg ring-st-warn/20',
  good: 'bg-st-good/10 text-st-good-fg ring-st-good/20',
  neutral: 'bg-nd-fill text-nd-fg-3 ring-nd-line',
}
export function AccessChips({ perms, cat, max = 4 }: { perms: string[]; cat: Catalog; max?: number }) {
  const { chips } = summarize(perms, cat)
  return (
    <span className="flex flex-wrap items-center gap-1">
      {chips.slice(0, max).map((c) => (
        <span key={c.label} className={`inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset ${CHIP[c.tone]}`}>{c.label}</span>
      ))}
    </span>
  )
}

export function Avatar({ name, color, size = 9, dim }: { name: string; color: string; size?: 7 | 8 | 9 | 10; dim?: boolean }) {
  const cls = { 7: 'h-7 w-7 text-[10.5px]', 8: 'h-8 w-8 text-[11px]', 9: 'h-9 w-9 text-[12px]', 10: 'h-10 w-10 text-[13px]' }[size]
  return (
    <span className={`grid shrink-0 place-items-center rounded-full font-semibold text-white ${cls} ${dim ? 'opacity-40 grayscale' : ''}`} style={{ background: color }}>
      {initials(name)}
    </span>
  )
}

// Users | Groups tab bar shared by both admin pages.
export function AccessTabs({ users, groups }: { users?: number; groups?: number }) {
  const path = usePathname()
  const tab = (href: string, label: string, Icon: typeof Users, n?: number) => {
    const on = path === href
    return (
      <Link href={href} aria-current={on ? 'page' : undefined}
        className={`inline-flex items-center gap-2 rounded-lg px-3.5 py-2 text-[13px] font-medium transition-colors ${on ? 'bg-nd-card text-nd-fg shadow-nd ring-1 ring-nd-line' : 'text-nd-dim hover:text-nd-fg'}`}>
        <Icon className={`h-4 w-4 ${on ? 'text-nd-brand' : ''}`} /> {label}
        {n !== undefined && <span className="rounded-full bg-nd-fill px-1.5 text-[11px] text-nd-dim">{n}</span>}
      </Link>
    )
  }
  return (
    <div className="inline-flex gap-1 rounded-xl border border-nd-line bg-nd-panel p-1">
      {tab('/analytics/users', 'Users', Users, users)}
      {tab('/analytics/groups', 'Groups & permissions', UsersRound, groups)}
    </div>
  )
}

export const btnPrimary = 'inline-flex items-center gap-1.5 rounded-lg bg-nd-brand px-3.5 py-2 text-[13px] font-semibold text-black shadow-nd transition-opacity hover:opacity-90 disabled:opacity-40'
export const btnGhost = 'inline-flex items-center gap-1.5 rounded-lg border border-nd-line bg-nd-card px-3 py-1.5 text-[13px] font-medium text-nd-fg-3 shadow-nd transition-colors hover:border-nd-line-strong hover:text-nd-fg disabled:opacity-40'
export const inputCls = 'rounded-lg border border-nd-line bg-nd-card px-3 py-2 text-[13px] text-nd-fg shadow-nd outline-none transition-colors placeholder:text-nd-faint focus:border-nd-brand'

// Read-only "what this group can do" list, grouped by area.
export function PermissionPreview({ perms, cat }: { perms: string[]; cat: Catalog }) {
  const set = new Set(perms)
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {cat.areas.map((area) => (
        <div key={area.id} className="rounded-xl border border-nd-line bg-nd-panel p-3">
          <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-nd-faint">{area.label}</div>
          <ul className="space-y-1">
            {area.pages.map((pid) => {
              const p = cat.pages.find((x) => x.id === pid)
              if (!p) return null
              const acts = cat.actions.filter((a) => a.page === pid)
              return (
                <li key={pid}>
                  <Line on={set.has(pid)} label={p.label} />
                  {acts.length > 0 && set.has(pid) && (
                    <ul className="ml-5 mt-0.5 space-y-0.5">
                      {acts.map((a) => <li key={a.id}><Line on={set.has(a.id)} label={a.label} small /></li>)}
                    </ul>
                  )}
                </li>
              )
            })}
          </ul>
        </div>
      ))}
    </div>
  )
}
function Line({ on, label, small }: { on: boolean; label: string; small?: boolean }) {
  return (
    <span className={`flex items-center gap-1.5 ${small ? 'text-[12px]' : 'text-[12.5px]'} ${on ? 'text-nd-fg-2' : 'text-nd-faint line-through decoration-nd-line'}`}>
      {on ? <Check className="h-3.5 w-3.5 text-st-good-fg" /> : <X className="h-3.5 w-3.5" />} {label}
    </span>
  )
}

