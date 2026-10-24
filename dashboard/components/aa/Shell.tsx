'use client'
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import {
  LayoutDashboard, LineChart, ShieldAlert, Fingerprint, TerminalSquare, Search, Moon, Sun, RefreshCw,
  CalendarRange, Shield, Lock, ChevronRight, Clock, Zap, BrainCircuit, LogOut, Users, UsersRound, type LucideIcon,
} from 'lucide-react'
import { PAGES } from '@/lib/authz'
import { CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList, CommandShortcut } from '@/components/ui/command'
import { instant, scalar } from '@/lib/prom'
import { usePoll } from '@/hooks/usePoll'
import { niceStep } from '@/lib/stats'
import { METRICS } from '@/lib/catalog'
import { Segmented, IconButton, btn } from './kit'

// Frame for the analytics site (/analytics/*): grouped sidebar, header with
// breadcrumbs, live state, a shared time range (presets or a custom window),
// refresh and theme, plus a ⌘K command palette. Pages read the window through
// useRange(); `key` changes whenever the window or a manual refresh does.

export const PRESETS = [
  { id: '15m', sec: 900, label: '15m' },
  { id: '1h', sec: 3600, label: '1h' },
  { id: '6h', sec: 21600, label: '6h' },
  { id: '24h', sec: 86400, label: '24h' },
  { id: '7d', sec: 604800, label: '7d' },
  { id: '15d', sec: 1296000, label: '15d' },
] as const
export type PresetId = (typeof PRESETS)[number]['id'] | 'custom'

export interface Window {
  start: number // unix seconds
  end: number
  span: number
  step: number
  rw: string // rate window for rate(): never shorter than the step
}

interface RangeCtx {
  preset: PresetId
  custom: { start: number; end: number }
  setPreset: (p: PresetId) => void
  setCustom: (start: number, end: number) => void
  resolve: () => Window
  key: string
  label: string
  refreshMs: number
  refresh: () => void
}
const Ctx = createContext<RangeCtx | null>(null)
export const useRange = () => {
  const c = useContext(Ctx)
  if (!c) throw new Error('useRange outside <Shell>')
  return c
}
const ThemeCtx = createContext<'light' | 'dark'>('light')
export const useAATheme = () => useContext(ThemeCtx)

function windowOf(start: number, end: number): Window {
  const span = Math.max(60, end - start)
  const step = niceStep(span)
  return { start, end, span, step, rw: `${Math.max(60, step)}s` }
}

interface NavItem { href: string; label: string; icon: LucideIcon; hint: string }
// page id (lib/authz PAGES) a nav href maps to, for permission gating. Groups is
// its own page but shares the `users` admin permission.
const PATH_PAGE: Record<string, string> = { ...Object.fromEntries(PAGES.map((p) => [p.path, p.id])), '/analytics/groups': 'users' }
const NAV: { group: string; items: NavItem[] }[] = [
  {
    group: 'Analyze',
    items: [
      { href: '/analytics', label: 'Overview', icon: LayoutDashboard, hint: 'Key numbers and automatic insights' },
      { href: '/analytics/explore', label: 'Explorer', icon: LineChart, hint: 'Any metric, any range, with statistics' },
      { href: '/analytics/attacks', label: 'Attacks', icon: ShieldAlert, hint: 'Every episode, with drill-down' },
      { href: '/analytics/ai', label: 'AI security', icon: BrainCircuit, hint: 'Risk engine, detectors and automated defenses' },
      { href: '/analytics/protect', label: 'Protection', icon: Lock, hint: 'Protected hosts and allowed services (default-deny)' },
      { href: '/analytics/ip', label: 'IP lookup', icon: Fingerprint, hint: 'Investigate one address' },
    ],
  },
  {
    group: 'Tools',
    items: [
      { href: '/analytics/query', label: 'Query console', icon: TerminalSquare, hint: 'Run raw PromQL' },
    ],
  },
  {
    group: 'Administration',
    items: [
      { href: '/analytics/users', label: 'Users', icon: Users, hint: 'Accounts and their group' },
      { href: '/analytics/groups', label: 'Groups', icon: UsersRound, hint: 'Groups and per-page permissions' },
    ],
  },
]
const ALL = NAV.flatMap((g) => g.items)
const IP_RE = /^[0-9a-fA-F:.]{3,45}$/

const toLocalInput = (sec: number) => {
  const d = new Date(sec * 1000)
  d.setMinutes(d.getMinutes() - d.getTimezoneOffset())
  return d.toISOString().slice(0, 16)
}
const fromLocalInput = (s: string) => Math.floor(new Date(s).getTime() / 1000)

function CustomRange({ onApply, onClose, initial }: { onApply: (s: number, e: number) => void; onClose: () => void; initial: { start: number; end: number } }) {
  const [draft, setDraft] = useState({ start: toLocalInput(initial.start), end: toLocalInput(initial.end) })
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const away = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) onClose() }
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('mousedown', away)
    document.addEventListener('keydown', esc)
    return () => { document.removeEventListener('mousedown', away); document.removeEventListener('keydown', esc) }
  }, [onClose])
  const now = Math.floor(Date.now() / 1000)
  const midnight = (() => { const d = new Date(); d.setHours(0, 0, 0, 0); return Math.floor(d.getTime() / 1000) })()
  const quick = [
    { label: 'Last 30 minutes', s: now - 1800, e: now },
    { label: 'Last 3 hours', s: now - 10800, e: now },
    { label: 'Today', s: midnight, e: now },
    { label: 'Yesterday', s: midnight - 86400, e: midnight },
    { label: 'Last 3 days', s: now - 259200, e: now },
  ]
  return (
    <div ref={ref} className="aa-in absolute right-0 top-[calc(100%+8px)] z-40 w-[340px] rounded-2xl border border-nd-line bg-nd-card p-4 shadow-nd-lg">
      <div className="text-[12px] font-medium uppercase tracking-[0.08em] text-nd-dim">Quick ranges</div>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {quick.map((q) => (
          <button key={q.label} onClick={() => onApply(q.s, q.e)} className="rounded-full border border-nd-line px-2.5 py-1 text-[12px] text-nd-fg-3 hover:border-nd-line-strong hover:text-nd-fg">
            {q.label}
          </button>
        ))}
      </div>
      <form
        className="mt-4 space-y-2.5"
        onSubmit={(e) => { e.preventDefault(); if (draft.start && draft.end) onApply(fromLocalInput(draft.start), fromLocalInput(draft.end)) }}
      >
        <label className="block text-[12px] text-nd-dim">
          From
          <input type="datetime-local" value={draft.start} onChange={(e) => setDraft({ ...draft, start: e.target.value })} className={`${btn.input} mt-1 w-full`} />
        </label>
        <label className="block text-[12px] text-nd-dim">
          To
          <input type="datetime-local" value={draft.end} onChange={(e) => setDraft({ ...draft, end: e.target.value })} className={`${btn.input} mt-1 w-full`} />
        </label>
        <div className="flex items-center justify-between pt-1">
          <span className="text-[11.5px] text-nd-faint">Up to 15 days back</span>
          <button type="submit" className={btn.primary}>Apply range</button>
        </div>
      </form>
    </div>
  )
}

export default function Shell({ children }: { children: ReactNode }) {
  const path = usePathname()
  const router = useRouter()
  const [preset, setPresetState] = useState<PresetId>('1h')
  const [custom, setCustomState] = useState(() => {
    const end = Math.floor(Date.now() / 1000)
    return { start: end - 3600, end }
  })
  const [theme, setTheme] = useState<'light' | 'dark'>('light')
  const [nonce, setNonce] = useState(0)
  const [spin, setSpin] = useState(false)
  const [showCustom, setShowCustom] = useState(false)
  const [cmdOpen, setCmdOpen] = useState(false)
  const [cmdText, setCmdText] = useState('')
  const [me, setMe] = useState<{ username?: string; group?: string; pages?: string[]; isAdmin?: boolean; authDisabled?: boolean } | null>(null)

  useEffect(() => {
    let alive = true
    fetch('/api/me')
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => { if (alive && d) setMe(d) })
      .catch(() => {})
    return () => { alive = false }
  }, [])

  useEffect(() => {
    try {
      const t = localStorage.getItem('aa.theme')
      if (t === 'light' || t === 'dark') setTheme(t)
      const p = localStorage.getItem('aa.preset')
      if (p && PRESETS.some((x) => x.id === p)) setPresetState(p as PresetId)
    } catch {}
    const onKey = (e: KeyboardEvent) => {
      if (e.key.toLowerCase() === 'k' && (e.metaKey || e.ctrlKey)) { e.preventDefault(); setCmdOpen((o) => !o) }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const setPreset = useCallback((p: PresetId) => {
    setPresetState(p)
    setShowCustom(false)
    if (p !== 'custom') try { localStorage.setItem('aa.preset', p) } catch {}
  }, [])
  const setCustom = useCallback((start: number, end: number) => {
    setCustomState({ start: Math.min(start, end), end: Math.max(start, end) })
    setPresetState('custom')
    setShowCustom(false)
  }, [])
  const refresh = useCallback(() => {
    setNonce((n) => n + 1)
    setSpin(true)
    setTimeout(() => setSpin(false), 700)
  }, [])
  const flipTheme = useCallback(() => {
    setTheme((t) => {
      const n = t === 'light' ? 'dark' : 'light'
      try { localStorage.setItem('aa.theme', n) } catch {}
      return n
    })
  }, [])

  const value = useMemo<RangeCtx>(() => {
    const p = PRESETS.find((x) => x.id === preset)
    const resolve = () => {
      if (p) {
        const end = Math.floor(Date.now() / 1000)
        return windowOf(end - p.sec, end)
      }
      return windowOf(custom.start, custom.end)
    }
    const fmt = (s: number) => new Date(s * 1000).toLocaleString([], { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })
    return {
      preset, custom, setPreset, setCustom, resolve, refresh,
      key: `${p ? preset : `${custom.start}-${custom.end}`}#${nonce}`,
      label: p ? `last ${preset}` : `${fmt(custom.start)} – ${fmt(custom.end)}`,
      refreshMs: !p ? 600_000 : p.sec <= 21600 ? 30_000 : p.sec <= 86400 ? 60_000 : 300_000,
    }
  }, [preset, custom, setPreset, setCustom, refresh, nonce])

  // agent heartbeat for the sidebar status card
  const hb = usePoll(async () => scalar(await instant('max(up{job="xdp-sentinel-agent"})'), 0)!, 30_000)
  const live = preset !== 'custom'

  // Nav filtered to the pages this user's group grants. While /api/me is still
  // loading (pages == null), show everything to avoid a flash of a shrinking
  // menu; auth-disabled servers report all pages, so nothing is hidden there.
  const pages = me?.pages ?? null
  const can = useCallback((href: string) => {
    const id = PATH_PAGE[href]
    return !id || pages == null || pages.includes(id)
  }, [pages])
  const nav = useMemo(() => NAV.map((g) => ({ ...g, items: g.items.filter((n) => can(n.href)) })).filter((g) => g.items.length), [can])
  const allNav = useMemo(() => nav.flatMap((g) => g.items), [nav])
  const page = ALL.find((n) => n.href === path) ?? ALL[0]
  const go = (href: string) => { setCmdOpen(false); setCmdText(''); router.push(href) }
  const ipCandidate = cmdText.trim()

  return (
    <ThemeCtx.Provider value={theme}>
      <Ctx.Provider value={value}>
        <div className={`nd-${theme} aa-root min-h-screen bg-nd-bg text-nd-fg-2 antialiased`}>
          {/* sidebar */}
          <aside className="fixed inset-y-0 left-0 z-30 hidden w-64 flex-col border-r border-nd-line bg-nd-panel lg:flex">
            <div className="flex items-center gap-3 px-5 pb-4 pt-5">
              <span className="grid h-9 w-9 place-items-center rounded-xl bg-gradient-to-br from-emerald-400 to-teal-600 text-white shadow-nd">
                <Shield className="h-[18px] w-[18px]" strokeWidth={2.2} />
              </span>
              <div className="leading-tight">
                <div className="text-[14.5px] font-semibold tracking-[-0.01em] text-nd-fg">xdp-sentinel</div>
                <div className="text-[11.5px] text-nd-dim">Analytics</div>
              </div>
            </div>
            <div className="px-3">
              <button onClick={() => setCmdOpen(true)} className="flex w-full items-center gap-2 rounded-lg border border-nd-line bg-nd-card px-3 py-2 text-[13px] text-nd-dim shadow-nd transition-colors hover:text-nd-fg">
                <Search className="h-4 w-4" />
                <span className="flex-1 text-left">Search or jump to…</span>
                <kbd className="rounded-md border border-nd-line bg-nd-fill px-1.5 py-0.5 text-[10.5px] font-medium">⌘K</kbd>
              </button>
            </div>
            <nav className="mt-5 flex-1 space-y-5 overflow-y-auto px-3">
              {nav.map((g) => (
                <div key={g.group}>
                  <div className="px-2 pb-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] text-nd-faint">{g.group}</div>
                  <ul className="space-y-0.5">
                    {g.items.map((n) => {
                      const on = n.href === path
                      return (
                        <li key={n.href}>
                          <Link
                            href={n.href}
                            aria-current={on ? 'page' : undefined}
                            className={`relative flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-[13.5px] transition-colors ${
                              on ? 'bg-nd-card font-medium text-nd-fg shadow-nd ring-1 ring-nd-line' : 'text-nd-muted hover:bg-nd-fill hover:text-nd-fg'
                            }`}
                          >
                            {on && <span className="absolute -left-3 top-1/2 h-5 w-1 -translate-y-1/2 rounded-r-full bg-nd-brand" />}
                            <n.icon className={`h-4 w-4 ${on ? 'text-nd-brand' : 'text-nd-dim'}`} />
                            {n.label}
                          </Link>
                        </li>
                      )
                    })}
                  </ul>
                </div>
              ))}
            </nav>
            <div className="m-3 rounded-xl border border-nd-line bg-nd-card p-3 shadow-nd">
              <div className="flex items-center gap-2 text-[12.5px] font-medium text-nd-fg-2">
                <span className="relative flex h-2 w-2">
                  {hb.data != null && hb.data >= 0.5 && <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-st-good opacity-60" />}
                  <span className={`relative inline-flex h-2 w-2 rounded-full ${hb.data == null ? 'bg-st-neutral' : hb.data >= 0.5 ? 'bg-st-good' : 'bg-st-crit'}`} />
                </span>
                {hb.data == null ? (hb.error ? 'Prometheus unreachable' : 'Connecting…') : hb.data >= 0.5 ? 'Sentinel agent online' : 'Sentinel agent down'}
              </div>
              <p className="mt-1 text-[11.5px] text-nd-dim">data via Prometheus</p>
            </div>
            {me && !me.authDisabled && me.username && (
              <div className="mx-3 mb-3 flex items-center justify-between gap-2 rounded-xl border border-nd-line bg-nd-card px-3 py-2 shadow-nd">
                <div className="min-w-0">
                  <div className="truncate text-[12.5px] font-medium text-nd-fg">{me.username}</div>
                  <div className="text-[11px] text-nd-dim">{me.group}</div>
                </div>
                <a
                  href="/api/logout"
                  title="Log out"
                  aria-label="Log out"
                  className="grid h-7 w-7 shrink-0 place-items-center rounded-lg border border-nd-line text-nd-muted transition-colors hover:text-nd-fg"
                >
                  <LogOut className="h-3.5 w-3.5" />
                </a>
              </div>
            )}
          </aside>

          <div className="lg:pl-64">
            {/* header */}
            <header className="sticky top-0 z-20 border-b border-nd-line bg-nd-bg/80 backdrop-blur-xl">
              <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 lg:px-8">
                <div className="min-w-0">
                  <div className="flex items-center gap-1 text-[12px] text-nd-dim">
                    <span>Analytics</span>
                    <ChevronRight className="h-3 w-3" />
                    <span className="text-nd-fg-3">{page.label}</span>
                  </div>
                  <h1 className="mt-0.5 text-[20px] font-semibold tracking-[-0.02em] text-nd-fg">{page.label}</h1>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`hidden items-center gap-1.5 rounded-full px-2.5 py-1 text-[12px] font-medium sm:inline-flex ${live ? 'bg-st-good/10 text-st-good-fg' : 'bg-nd-fill text-nd-muted'}`}>
                    {live ? <Zap className="h-3 w-3" /> : <Clock className="h-3 w-3" />}
                    {live ? 'Live' : value.label}
                  </span>
                  <Segmented
                    label="Time range"
                    value={preset === 'custom' ? ('' as PresetId) : preset}
                    onChange={(p) => setPreset(p)}
                    options={PRESETS.map((p) => ({ id: p.id as PresetId, label: p.label }))}
                  />
                  <div className="relative">
                    <IconButton icon={CalendarRange} label="Custom range" active={preset === 'custom' || showCustom} onClick={() => setShowCustom((s) => !s)} />
                    {showCustom && <CustomRange initial={value.resolve()} onApply={setCustom} onClose={() => setShowCustom(false)} />}
                  </div>
                  <button onClick={refresh} aria-label="Refresh" title="Refresh now" className="grid h-8 w-8 place-items-center rounded-lg border border-nd-line bg-nd-card text-nd-muted transition-colors hover:text-nd-fg">
                    <RefreshCw className={`h-4 w-4 ${spin ? 'animate-spin' : ''}`} />
                  </button>
                  <IconButton icon={theme === 'light' ? Moon : Sun} label={theme === 'light' ? 'Dark theme' : 'Light theme'} onClick={flipTheme} />
                </div>
              </div>
              <nav className="flex gap-1 overflow-x-auto px-3 pb-2 lg:hidden">
                {allNav.map((n) => (
                  <Link key={n.href} href={n.href} className={`whitespace-nowrap rounded-lg px-2.5 py-1 text-[12.5px] ${n.href === path ? 'bg-nd-card text-nd-fg shadow-nd' : 'text-nd-dim'}`}>
                    {n.label}
                  </Link>
                ))}
              </nav>
            </header>
            <main className="mx-auto max-w-[1480px] px-4 py-6 lg:px-8 lg:py-8">
              <p className="mb-6 text-[13.5px] text-nd-dim">{page.hint} · <span className="text-nd-muted">{value.label}</span></p>
              {children}
            </main>
          </div>

          {/* ⌘K palette (portalled, so it carries the theme class itself) */}
          <CommandDialog
            open={cmdOpen}
            onOpenChange={(o) => { setCmdOpen(o); if (!o) setCmdText('') }}
            title="Command palette"
            description="Jump to a page, metric or IP, or change the time range"
            className={`nd-${theme} aa-root max-w-xl border-nd-line bg-nd-card text-nd-fg shadow-nd-lg sm:max-w-xl [&_[cmdk-group-heading]]:text-nd-dim [&_[cmdk-item][data-selected=true]]:bg-nd-fill-2 [&_[cmdk-item][data-selected=true]]:text-nd-fg [&_[cmdk-item]]:text-nd-fg-3 [&_[cmdk-input]]:text-nd-fg [&_[cmdk-input]]:placeholder:text-nd-faint [&_[data-slot=command]]:bg-nd-card [&_[data-slot=command]]:text-nd-fg [&_[data-slot=command-input-wrapper]]:border-nd-line [&_[data-slot=command-input-wrapper]_svg]:text-nd-dim`}
            showCloseButton={false}
          >
            <CommandInput placeholder="Type a page, metric, range or IP address…" value={cmdText} onValueChange={setCmdText} />
            <CommandList className="max-h-[420px]">
              <CommandEmpty>No matches.</CommandEmpty>
              {IP_RE.test(ipCandidate) && /[.:]/.test(ipCandidate) && (
                <CommandGroup heading="Investigate">
                  <CommandItem value={`ip ${ipCandidate}`} onSelect={() => go(`/analytics/ip?ip=${encodeURIComponent(ipCandidate)}`)}>
                    <Fingerprint /> Look up {ipCandidate}
                  </CommandItem>
                </CommandGroup>
              )}
              <CommandGroup heading="Pages">
                {allNav.map((n) => (
                  <CommandItem key={n.href} value={`page ${n.label} ${n.hint}`} onSelect={() => go(n.href)}>
                    <n.icon /> {n.label}
                    <span className="ml-auto truncate text-[12px] text-nd-faint">{n.hint}</span>
                  </CommandItem>
                ))}
              </CommandGroup>
              <CommandGroup heading="Time range">
                {PRESETS.map((p) => (
                  <CommandItem key={p.id} value={`range last ${p.id}`} onSelect={() => { setPreset(p.id); setCmdOpen(false) }}>
                    <Clock /> Last {p.id}
                    {preset === p.id && <CommandShortcut>current</CommandShortcut>}
                  </CommandItem>
                ))}
              </CommandGroup>
              <CommandGroup heading="Explore a metric">
                {METRICS.map((m) => (
                  <CommandItem key={m.id} value={`metric ${m.label} ${m.group} ${m.help}`} onSelect={() => go(`/analytics/explore?metric=${m.id}`)}>
                    <LineChart /> {m.label}
                    <span className="ml-auto text-[12px] text-nd-faint">{m.group}</span>
                  </CommandItem>
                ))}
              </CommandGroup>
              <CommandGroup heading="Actions">
                <CommandItem value="action toggle theme dark light" onSelect={() => { flipTheme(); setCmdOpen(false) }}>
                  {theme === 'light' ? <Moon /> : <Sun />} Switch to {theme === 'light' ? 'dark' : 'light'} theme
                </CommandItem>
                <CommandItem value="action refresh reload data" onSelect={() => { refresh(); setCmdOpen(false) }}>
                  <RefreshCw /> Refresh all data
                </CommandItem>
              </CommandGroup>
            </CommandList>
          </CommandDialog>
        </div>
      </Ctx.Provider>
    </ThemeCtx.Provider>
  )
}
