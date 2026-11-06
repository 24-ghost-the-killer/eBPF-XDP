'use client'
import { useCallback, useEffect, useState } from 'react'
import { Lock, Plus, X, Users } from 'lucide-react'
import type { Report } from '@/lib/reports'
import type { Tone } from './kit'

// Shared pieces of the Protection section: plan/notes types, the allowed-services
// editor, and a hook that loads the plan + per-host notes. The overview page, the
// per-host page and the Shell's protection sidebar all read through useProtect(),
// and any of them can call notifyProtectChanged() after a save so the others
// refresh (e.g. a new nickname shows up in the sidebar immediately).

export type Proto = 'tcp' | 'udp' | 'icmp'
export interface Svc { proto: Proto; port: number }
export interface Host { iface: string; ip: string; services: Svc[] }
export interface LogEntry { id: string; ts: number; author: string; text: string }
export interface HostMeta { nickname: string; log: LogEntry[]; reports: Report[] }
export interface EditorRef { clientId: string; name: string }
export const emptyMeta = (): HostMeta => ({ nickname: '', log: [], reports: [] })
export const reportHref = (ip: string, id: string) => `/analytics/protect/${encodeURIComponent(ip)}/reports/${encodeURIComponent(id)}`
export const fmtWhen = (ts: number) => new Date(ts * 1000).toLocaleString([], { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })

// "<name> editing" badge for the other people who have a document open in an editor.
export function EditingBadge({ editors }: { editors: EditorRef[] }) {
  if (editors.length === 0) return null
  const names = [...new Set(editors.map((e) => e.name))]
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-st-warn/10 px-2 py-0.5 text-[11px] font-medium text-st-warn-fg ring-1 ring-inset ring-st-warn/20" title="editing right now">
      <Users className="h-3 w-3" /> {names.join(', ')}{names.length === 1 && editors.length > 1 ? ` (${editors.length} tabs)` : ''} editing
    </span>
  )
}

// Heartbeat "I'm editing this" while `active`; withdrawn when it stops.
export function useEditingPresence(active: boolean, ip: string, report?: string) {
  useEffect(() => {
    if (!active) return
    const ping = (on: boolean) =>
      fetch('/api/protect-meta/presence', { method: 'POST', keepalive: true, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ip, report, clientId: CLIENT_ID, editing: on }) }).catch(() => {})
    ping(true)
    const t = setInterval(() => ping(true), 10_000)
    const bye = () => { ping(false) }
    window.addEventListener('pagehide', bye)
    return () => { clearInterval(t); window.removeEventListener('pagehide', bye); ping(false) }
  }, [active, ip, report])
}
export const CONFLICT_START = '<<<<<<< your version'
export const CONFLICT_END = '>>>>>>> their version'
export interface LiveProt { ip: string; services: { proto: string; port: number }[] }
export interface LiveIface { iface: string; protected: LiveProt[] }
export interface LiveResp { interfaces: LiveIface[]; unavailable?: boolean }

export const PROTO_TONE: Record<string, string> = { tcp: 'var(--s1)', udp: 'var(--s4)', icmp: 'var(--s2)' }
export const svcKey = (s: { proto: string; port: number }) => `${s.proto}/${s.port}`
export const hostKey = (iface: string, ip: string) => `${iface}|${ip}`
export const fmtSvc = (s: { proto: string; port: number }) => `${s.proto}/${s.port === 0 ? '*' : s.port}`
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
export const validIp = (ip: string) => { const m = IPV4.exec(ip); return !!m && m.slice(1).every((o) => +o >= 0 && +o <= 255) }
export const hostHref = (ip: string) => `/analytics/protect/${encodeURIComponent(ip)}`

// Friendly names for common ports.
const WELL_KNOWN: Record<string, string> = {
  'tcp/22': 'SSH', 'tcp/80': 'HTTP', 'tcp/443': 'HTTPS', 'tcp/3000': 'Dashboard', 'tcp/8006': 'Proxmox',
  'tcp/3389': 'RDP', 'tcp/8080': 'HTTP-alt', 'tcp/5432': 'Postgres', 'tcp/6443': 'Kubernetes',
  'tcp/53': 'DNS', 'udp/53': 'DNS', 'udp/123': 'NTP', 'udp/51820': 'WireGuard', 'icmp/0': 'ping',
  'tcp/21114': 'RustDesk', 'tcp/21115': 'RustDesk', 'tcp/21116': 'RustDesk', 'udp/21116': 'RustDesk',
  'tcp/21117': 'RustDesk relay', 'tcp/21118': 'RustDesk web', 'tcp/21119': 'RustDesk web',
}
export const svcName = (s: { proto: string; port: number }) => WELL_KNOWN[svcKey(s)]

export function statusOf(applied: boolean, hasLive: boolean): { label: string; tone: Tone } {
  if (applied) return { label: 'live', tone: 'good' }
  if (hasLive) return { label: 'pending', tone: 'warn' }
  return { label: 'not applied', tone: 'neutral' }
}

// True when the dataplane holds exactly the plan's services for this host.
export function isApplied(h: Host, live?: Set<string>): boolean {
  return !!live && live.size === h.services.length && h.services.every((s) => live.has(svcKey(s)))
}

export async function fetchLive(): Promise<LiveResp> {
  const r = await fetch('/api/agent/api/services.json', { cache: 'no-store' })
  if (!r.ok) return { interfaces: [], unavailable: true }
  try { return await r.json() } catch { return { interfaces: [], unavailable: true } }
}

// Small inline note shown where a control is hidden for lack of a permission.
export function NeedsPerm({ label }: { label: string }) {
  return (
    <span className="inline-flex items-center gap-1 text-[11.5px] text-nd-faint" title={`Your group needs the “${label}” permission`}>
      <Lock className="h-3 w-3" /> view only
    </span>
  )
}

const EVT = 'xs:protect-changed'
export const notifyProtectChanged = () => window.dispatchEvent(new Event(EVT))

// One id per browser tab, so presence can tell two tabs of the same user apart.
// (crypto.randomUUID needs a secure context; the dashboard is often plain http.)
export const CLIENT_ID = typeof window === 'undefined' ? 'ssr' : `c${Math.random().toString(36).slice(2, 12)}${Date.now().toString(36)}`

// ---- live notes stream (one EventSource per tab, shared by all listeners) --
type LiveListener = (event: 'hello' | 'meta' | 'presence', data: any) => void
const liveListeners = new Set<LiveListener>()
let liveSource: EventSource | null = null
function openLive() {
  if (liveSource || typeof EventSource === 'undefined') return
  const es = new EventSource('/api/protect-meta/stream')
  for (const ev of ['hello', 'meta', 'presence'] as const) {
    es.addEventListener(ev, (m) => {
      let data: unknown = null
      try { data = JSON.parse((m as MessageEvent).data) } catch { return }
      for (const fn of liveListeners) fn(ev, data)
    })
  }
  // EventSource reconnects by itself; every reconnect re-sends 'hello', and
  // listeners reload on 'hello', so nothing missed while offline is lost.
  liveSource = es
}
export function subscribeLive(fn: LiveListener): () => void {
  liveListeners.add(fn)
  openLive()
  return () => {
    liveListeners.delete(fn)
    if (liveListeners.size === 0 && liveSource) { liveSource.close(); liveSource = null }
  }
}

export interface ProtectData {
  hosts: Host[]
  meta: Record<string, HostMeta>
  presence: Record<string, EditorRef[]>
  management: string[]
  lifeline: Svc[]
  ingress: string
  loaded: boolean
  forbidden: boolean
  reload: () => void
}

// Plan + notes, refreshed whenever any Protection view saves something.
export function useProtect(enabled = true): ProtectData {
  const [s, setS] = useState<Omit<ProtectData, 'reload' | 'presence'>>({ hosts: [], meta: {}, management: [], lifeline: [], ingress: 'vlan10', loaded: false, forbidden: false })
  const [presence, setPresence] = useState<Record<string, EditorRef[]>>({})
  const reload = useCallback(async () => {
    try {
      const [p, m] = await Promise.all([
        fetch('/api/protect-plan', { cache: 'no-store' }),
        fetch('/api/protect-meta', { cache: 'no-store' }),
      ])
      if (p.status === 403) { setS((x) => ({ ...x, loaded: true, forbidden: true })); return }
      const pd = p.ok ? await p.json() : null
      const md = m.ok ? await m.json() : null
      setS({
        hosts: (pd?.plan?.hosts || []).map((x: any) => ({ iface: x.iface, ip: x.ip, services: x.services || [] })),
        meta: md?.hosts || {},
        management: pd?.management || [],
        lifeline: pd?.lifeline || [],
        ingress: pd?.ingress || 'vlan10',
        loaded: true,
        forbidden: false,
      })
    } catch {
      setS((x) => ({ ...x, loaded: true }))
    }
  }, [])
  useEffect(() => {
    if (!enabled) return
    reload()
    window.addEventListener(EVT, reload)
    // Live: apply pushed note changes and editing presence as they happen.
    const off = subscribeLive((ev, data) => {
      if (ev === 'hello') { setPresence(data?.presence || {}); reload() }
      else if (ev === 'meta' && data?.ip) setS((x) => ({ ...x, meta: { ...x.meta, [data.ip]: data.meta } }))
      else if (ev === 'presence' && data?.ip) setPresence((p) => ({ ...p, [data.ip]: data.editors || [] }))
    })
    return () => { window.removeEventListener(EVT, reload); off() }
  }, [enabled, reload])
  return { ...s, presence, reload }
}

// Allowed-services editor: a table of rows (proto · port · name · status ·
// remove) with an add row at the bottom (segmented proto control + port).
export function ServiceEditor({ services, onAdd, onRemove, toneFor, lockedKey, readOnly }: {
  services: Svc[]
  onAdd: (s: Svc) => void
  onRemove: (key: string) => void
  toneFor?: (s: Svc) => 'good' | 'warn' | null
  lockedKey?: (key: string) => boolean
  readOnly?: boolean
}) {
  const [proto, setProto] = useState<Proto>('tcp')
  const [port, setPort] = useState('')
  function add() {
    const svc: Svc = { proto, port: proto === 'icmp' ? 0 : Number(port) }
    if (svc.proto !== 'icmp' && (!Number.isInteger(svc.port) || svc.port < 1 || svc.port > 65535)) return
    if (!services.some((e) => svcKey(e) === svcKey(svc))) onAdd(svc)
    setPort('')
  }

  return (
    <div className="overflow-hidden rounded-xl border border-nd-line">
      {services.length > 0 && (
        <div className="divide-y divide-nd-line">
          {services.map((s) => {
            const key = svcKey(s)
            const tone = toneFor?.(s) ?? null
            const locked = lockedKey?.(key) ?? false
            const name = svcName(s)
            return (
              <div key={key} className="flex items-center gap-3 px-3 py-2 text-[12.5px]">
                <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: PROTO_TONE[s.proto] ?? 'var(--s3)' }} />
                <span className="w-9 font-mono uppercase tracking-wide text-nd-dim">{s.proto}</span>
                <span className="w-12 font-mono font-semibold text-nd-fg">{s.port === 0 ? '*' : s.port}</span>
                <span className="flex-1 truncate text-nd-fg-3">{name ?? <span className="text-nd-faint">—</span>}</span>
                {tone && (
                  <span className={`inline-flex items-center gap-1 text-[11px] ${tone === 'good' ? 'text-st-good-fg' : 'text-st-warn-fg'}`} title={tone === 'good' ? 'live on the dataplane' : 'pending — not applied yet'}>
                    <span className={`h-1.5 w-1.5 rounded-full ${tone === 'good' ? 'bg-st-good' : 'bg-st-warn'}`} />
                    {tone === 'good' ? 'live' : 'pending'}
                  </span>
                )}
                {readOnly ? null : locked ? (
                  <Lock className="h-3.5 w-3.5 shrink-0 text-nd-faint" aria-label="lifeline — can’t be removed" />
                ) : (
                  <button onClick={() => onRemove(key)} title="Remove service" className="grid h-6 w-6 shrink-0 place-items-center rounded-md text-nd-faint transition-colors hover:bg-nd-fill hover:text-st-crit-fg"><X className="h-3.5 w-3.5" /></button>
                )}
              </div>
            )
          })}
        </div>
      )}

      {!readOnly && <div className={`flex items-center gap-2 bg-nd-panel px-3 py-2 ${services.length > 0 ? 'border-t border-nd-line' : ''}`}>
        <div className="inline-flex rounded-lg border border-nd-line bg-nd-card p-0.5">
          {(['tcp', 'udp', 'icmp'] as Proto[]).map((p) => (
            <button key={p} onClick={() => setProto(p)}
              className={`rounded-md px-2.5 py-1 text-[12px] font-medium uppercase tracking-wide transition-colors ${proto === p ? 'bg-nd-fill text-nd-fg' : 'text-nd-dim hover:text-nd-fg'}`}>{p}</button>
          ))}
        </div>
        {proto !== 'icmp' && (
          <input value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, ''))} onKeyDown={(e) => e.key === 'Enter' && add()} placeholder="port"
            className="w-24 rounded-lg border border-nd-line bg-nd-card px-2.5 py-1.5 text-[12.5px] text-nd-fg outline-none focus:border-nd-brand" />
        )}
        <button onClick={add} disabled={proto !== 'icmp' && !port}
          className="ml-auto inline-flex items-center gap-1 rounded-lg bg-nd-brand px-3 py-1.5 text-[12px] font-semibold text-black transition-opacity hover:opacity-90 disabled:opacity-40"><Plus className="h-3.5 w-3.5" /> allow</button>
      </div>}
      {readOnly && services.length === 0 && <p className="px-3 py-3 text-[12px] text-nd-faint">No allowed services.</p>}
    </div>
  )
}
