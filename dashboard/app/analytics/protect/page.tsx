'use client'
import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import Link from 'next/link'
import { instantAt, scalar } from '@/lib/prom'
import { usePoll } from '@/hooks/usePoll'
import { si } from '@/lib/format'
import { Stat } from '@/components/aa/kit'
import { useRange, useMe } from '@/components/aa/Shell'
import {
  type Proto, type Svc, type Host, type HostMeta, svcKey, hostKey, fmtSvc, validIp, hostHref, statusOf, isApplied,
  fetchLive, notifyProtectChanged, subscribeLive, ServiceEditor, NeedsPerm,
} from '@/components/aa/protect'
import {
  Lock, ShieldCheck, Ban, AlertTriangle, Server, Network, Info, Plus, X, Loader2, Check, ShieldOff,
  ChevronRight, Crosshair,
} from 'lucide-react'

// Protection — EDIT the service-allowlist (default-deny). Each protected host
// has its own page (/analytics/protect/<ip>) with notes, ports and statistics. You edit a desired-state "plan"; a root job on
// the box (xs-protect-apply) reconciles the eBPF maps with sentinelctl. Live
// state comes from the agent; a host shows "pending" until the dataplane matches
// the plan. Management IPs always keep a lifeline so the dashboard can't lock
// itself out. Denial counters are PER INTERFACE (the dataplane counts denials by
// interface, not by destination), so the drawer scopes them to the host's iface.

export default function Protection() {
  const rng = useRange()
  const canPlan = useMe().can('protect.plan')
  const live = usePoll(fetchLive, 10_000)
  const deny = usePoll(async () => {
    const w = rng.resolve()
    const [win, life] = await Promise.all([
      instantAt(`sum(increase(xs_service_packets_total{event="deny"}[${w.span}s]))`, w.end),
      instantAt('sum(increase(xs_service_packets_total{event="deny"}[1y]))', w.end),
    ])
    return { win: scalar(win, 0) ?? 0, life: scalar(life, 0) ?? 0 }
  }, 15_000, [rng.key])
  const [meta, setMeta] = useState<Record<string, HostMeta>>({})

  const [hosts, setHosts] = useState<Host[]>([])
  const [saved, setSaved] = useState<string>('[]') // JSON of last-saved hosts, for dirty check
  const [management, setManagement] = useState<string[]>([])
  const [lifeline, setLifeline] = useState<Svc[]>([])
  const [ingress, setIngress] = useState('vlan10')
  const [loaded, setLoaded] = useState(false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')
  // live index: "iface|ip" -> Set of "proto/port"
  const liveIndex = useMemo(() => {
    const m = new Map<string, Set<string>>()
    for (const i of live.data?.interfaces ?? []) for (const p of i.protected) m.set(hostKey(i.iface, p.ip), new Set(p.services.map(svcKey)))
    return m
  }, [live.data])

  // Nicknames for the host list.
  useEffect(() => {
    const load = () => fetch('/api/protect-meta', { cache: 'no-store' }).then((r) => (r.ok ? r.json() : null)).then((d) => d && setMeta(d.hosts || {})).catch(() => {})
    load()
    window.addEventListener('xs:protect-changed', load)
    // Live: nicknames edited by someone else appear without a refresh.
    const off = subscribeLive((ev, data) => {
      if (ev === 'meta' && data?.ip) setMeta((m) => ({ ...m, [data.ip]: data.meta }))
      else if (ev === 'hello') load()
    })
    return () => { window.removeEventListener('xs:protect-changed', load); off() }
  }, [])

  // Load the plan once; if empty, seed from whatever is live so editing starts from reality.
  useEffect(() => {
    let alive = true
    fetch('/api/protect-plan', { cache: 'no-store' })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (!alive || !d) return
        setManagement(d.management || [])
        setLifeline(d.lifeline || [])
        if (d.ingress) setIngress(d.ingress)
        let h: Host[] = (d.plan?.hosts || []).map((x: any) => ({ iface: x.iface, ip: x.ip, services: x.services || [] }))
        if (h.length === 0 && (live.data?.interfaces?.length ?? 0) > 0) {
          h = (live.data!.interfaces).flatMap((i) => i.protected.map((p) => ({ iface: i.iface, ip: p.ip, services: p.services.map((s) => ({ proto: s.proto as Proto, port: s.port })) })))
        }
        setHosts(h)
        setSaved(JSON.stringify(h))
        setLoaded(true)
      })
      .catch(() => setLoaded(true))
    return () => { alive = false }
    // seed only once, after first live sample is in
  }, [live.data]) // eslint-disable-line react-hooks/exhaustive-deps

  const dirty = useMemo(() => JSON.stringify(hosts) !== saved, [hosts, saved])

  const totals = useMemo(() => {
    const svcs = hosts.reduce((n, h) => n + h.services.length, 0)
    const blackholed = hosts.filter((h) => h.services.length === 0).length
    return { hosts: hosts.length, svcs, blackholed }
  }, [hosts])

  // live hosts NOT in the plan (managed by ufw-sync / CLI) — shown read-only.
  const elsewhere = useMemo(() => {
    const planKeys = new Set(hosts.map((h) => hostKey(h.iface, h.ip)))
    const out: { iface: string; ip: string; services: { proto: string; port: number }[] }[] = []
    for (const i of live.data?.interfaces ?? []) for (const p of i.protected) if (!planKeys.has(hostKey(i.iface, p.ip))) out.push({ iface: i.iface, ip: p.ip, services: p.services })
    return out
  }, [hosts, live.data])

  // Drops aimed at each protected host (victim map, sampled 1 in 16 drops).
  const ipList = hosts.map((h) => h.ip).filter(validIp)
  const ipRe = ipList.map((ip) => ip.replace(/\./g, '\\\\.')).join('|')
  const targeted = usePoll(async () => {
    if (!ipRe) return { total: 0, top: null as null | { ip: string; v: number } }
    const w = rng.resolve()
    const R = `${w.span}s`
    const sel = `xs_target_packets_total{dst=~"${ipRe}"}`
    const r = await instantAt(`clamp_min((sum by(dst)(${sel}) - sum by(dst)(${sel} offset ${R})) or sum by(dst)(${sel}), 0)`, w.end)
    const rows = r.map((x) => ({ ip: x.metric.dst, v: parseFloat(x.value[1]) * 16 })).sort((a, b) => b.v - a.v)
    return { total: rows.reduce((n, x) => n + x.v, 0), top: rows[0] && rows[0].v > 0 ? rows[0] : null }
  }, 30_000, [rng.key, ipRe])
  const nameOf = (ip: string) => meta[ip]?.nickname || ip

  async function save() {
    setBusy(true); setErr(''); setOk('')
    try {
      const r = await fetch('/api/protect-plan', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ hosts }) })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) { setErr(d?.error || `error ${r.status}`); setBusy(false); return }
      const h = (d.plan?.hosts || hosts) as Host[]
      setHosts(h); setSaved(JSON.stringify(h))
      notifyProtectChanged()
      setOk('Saved — the box is applying it; live state refreshes in a few seconds.')
    } catch { setErr('could not reach the server') }
    setBusy(false)
  }

  return (
    <div className="space-y-6">
      {live.data?.unavailable && (
        <div className="flex items-start gap-2 rounded-xl border border-st-warn/30 bg-st-warn/[0.06] px-4 py-3 text-[13px] text-st-warn-fg">
          <Info className="mt-0.5 h-4 w-4 shrink-0" /> The service-allowlist isn’t live yet (updated dataplane + agent not deployed). You can still edit the plan; it applies once the box is ready.
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Protected hosts" icon={ShieldCheck} value={totals.hosts} sub="in the plan" color="var(--s1)" />
        <Stat label="Allowed services" icon={Lock} value={totals.svcs} sub="{proto, port} entries" color="var(--s4)" />
        <Stat label="Denied (lifetime)" icon={Ban} loading={!deny.data} value={si(deny.data?.life)} sub={deny.data ? `${si(deny.data.win)} in this window` : undefined} color="var(--s2)" />
        <Stat label="Blackholed" icon={AlertTriangle} value={totals.blackholed} sub="protected, zero services" color={totals.blackholed > 0 ? 'var(--st-crit)' : 'var(--s3)'} />
      </div>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Attack drops at protected hosts" icon={Crosshair} loading={!targeted.data} value={si(targeted.data?.total)} sub="this window · estimated (sampled 1 in 16)" color="var(--s2)" />
        <Stat label="Most targeted" icon={Server} loading={!targeted.data} value={targeted.data?.top ? nameOf(targeted.data.top.ip) : '—'} sub={targeted.data?.top ? `${si(targeted.data.top.v)} drops · ${targeted.data.top.ip}` : 'no drops in this window'} color="var(--s1)" />
        <Stat label="Live on the dataplane" icon={ShieldCheck} loading={!live.data} value={`${hosts.filter((h) => isApplied(h, liveIndex.get(hostKey(h.iface, h.ip)))).length} / ${hosts.length}`} sub="hosts where plan = dataplane" color="var(--s3)" />
        <Stat label="Documented" icon={Info} value={`${hosts.filter((h) => meta[h.ip]?.nickname || meta[h.ip]?.reports?.length || meta[h.ip]?.log?.length).length} / ${hosts.length}`} sub="hosts with a nickname, report or log" color="var(--s4)" />
      </div>

      {totals.blackholed > 0 && (
        <div className="flex items-start gap-2 rounded-xl border border-st-crit/30 bg-st-crit/[0.06] px-4 py-3 text-[13px] text-st-crit-fg">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>A host with no services is fully blackholed — every packet to it is dropped. Add at least one service, or remove the host.</span>
        </div>
      )}

      <LockdownCard />

      {/* host list — click a host to open its slide-over */}
      <div className="overflow-hidden rounded-2xl border border-nd-line bg-nd-card shadow-nd">
        <div className="flex flex-wrap items-center gap-2 border-b border-nd-line bg-nd-panel px-5 py-3.5">
          <ShieldCheck className="h-4 w-4 text-nd-brand" />
          <span className="text-[13.5px] font-semibold text-nd-fg">Protected hosts</span>
          <span className="text-[12px] text-nd-dim">default-deny — open a host for its notes, ports &amp; statistics</span>
          <div className="ml-auto flex items-center gap-2">
            {dirty && <span className="text-[12px] text-st-warn-fg">unsaved</span>}
            {canPlan ? (
              <button onClick={save} disabled={busy || !dirty} className="inline-flex items-center gap-1.5 rounded-lg bg-nd-brand px-3.5 py-2 text-[13px] font-semibold text-black shadow-nd transition-opacity hover:opacity-90 disabled:opacity-40">
                {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />} Save &amp; apply
              </button>
            ) : <NeedsPerm label="Edit protected hosts & ports" />}
          </div>
        </div>

        <div className="divide-y divide-nd-line">
          {!loaded ? (
            <p className="px-5 py-8 text-center text-[13px] text-nd-dim">Loading…</p>
          ) : hosts.length === 0 ? (
            <p className="px-5 py-8 text-center text-[13px] text-nd-dim">No hosts in the plan. Add one below to put it in default-deny.</p>
          ) : (
            hosts.map((h, idx) => {
              const liveSvcs = liveIndex.get(hostKey(h.iface, h.ip))
              return (
                <HostRow key={`${h.iface}|${h.ip}|${idx}`} host={h} nickname={meta[h.ip]?.nickname} applied={isApplied(h, liveSvcs)} hasLive={!!liveSvcs} />
              )
            })
          )}
        </div>

        {canPlan && <AddHost management={management} lifeline={lifeline} ingress={ingress} existing={hosts} onAdd={(iface, ip, services) => setHosts((hs) => [...hs, { iface, ip, services }])} />}

        {(err || ok) && (
          <div className="border-t border-nd-line px-5 py-3">
            {err && <p className="flex items-center gap-1.5 text-[12.5px] text-st-crit-fg"><AlertTriangle className="h-3.5 w-3.5" /> {err}</p>}
            {ok && <p className="flex items-center gap-1.5 text-[12.5px] text-st-good-fg"><Check className="h-3.5 w-3.5" /> {ok}</p>}
          </div>
        )}
      </div>

      {elsewhere.length > 0 && (
        <div className="rounded-2xl border border-nd-line bg-nd-panel p-4">
          <div className="mb-2 flex items-center gap-2 text-[12.5px] font-medium text-nd-dim"><Network className="h-4 w-4" /> Also protected on the dataplane (managed outside the dashboard — e.g. ufw-sync)</div>
          <ul className="flex flex-wrap gap-2">
            {elsewhere.map((p) => (
              <li key={hostKey(p.iface, p.ip)} className="rounded-lg border border-nd-line bg-nd-card px-2.5 py-1.5 font-mono text-[12px] text-nd-fg-2">
                {p.ip} <span className="text-nd-faint">on {p.iface} · {p.services.length} svc</span>
              </li>
            ))}
          </ul>
          <p className="mt-2 text-[11.5px] text-nd-faint">These are left untouched by the plan. Add one here to take it over from the dashboard.</p>
        </div>
      )}

      <p className="flex items-center gap-2 px-1 text-[12px] text-nd-dim">
        <ShieldOff className="h-3.5 w-3.5" /> Management IPs ({management.join(', ') || '—'}) can be protected, but their lifeline ({lifeline.map(fmtSvc).join(', ') || '—'}) is always kept open so the dashboard can’t blackhole SSH or itself.
      </p>

    </div>
  )
}

function HostRow({ host, nickname, applied, hasLive }: {
  host: Host; nickname?: string; applied: boolean; hasLive: boolean
}) {
  const st = statusOf(applied, hasLive)
  const dotCls = st.tone === 'good' ? 'bg-st-good' : st.tone === 'warn' ? 'bg-st-warn' : 'bg-nd-faint'
  const txtCls = st.tone === 'good' ? 'text-st-good-fg' : st.tone === 'warn' ? 'text-st-warn-fg' : 'text-nd-dim'
  return (
    <Link href={hostHref(host.ip)} className="flex w-full items-center gap-3 px-5 py-3.5 text-left transition-colors hover:bg-nd-fill">
      <Server className="h-4 w-4 shrink-0 text-nd-dim" />
      {nickname ? (
        <span className="flex min-w-0 flex-col leading-tight">
          <span className="truncate text-[13.5px] font-semibold text-nd-fg">{nickname}</span>
          <span className="font-mono text-[11.5px] text-nd-dim">{host.ip}</span>
        </span>
      ) : (
        <span className="font-mono text-[13.5px] font-semibold text-nd-fg">{host.ip}</span>
      )}
      <span className="rounded-md border border-nd-line bg-nd-fill px-1.5 py-0.5 text-[11px] text-nd-dim">{host.iface}</span>
      {host.services.length === 0 ? (
        <span className="inline-flex items-center gap-1 rounded-full bg-st-crit/10 px-2 py-0.5 text-[11px] font-medium text-st-crit-fg ring-1 ring-inset ring-st-crit/20"><AlertTriangle className="h-3 w-3" /> blackholed</span>
      ) : (
        <span className="hidden flex-wrap items-center gap-1 sm:flex">
          {host.services.slice(0, 4).map((s) => (
            <span key={svcKey(s)} className="rounded border border-nd-line bg-nd-bg px-1.5 py-0.5 font-mono text-[11px] text-nd-fg-3">{fmtSvc(s)}</span>
          ))}
          {host.services.length > 4 && <span className="text-[11px] text-nd-faint">+{host.services.length - 4}</span>}
        </span>
      )}
      <span className={`ml-auto inline-flex items-center gap-1 text-[11.5px] ${txtCls}`}>
        <span className={`h-1.5 w-1.5 rounded-full ${dotCls}`} />{st.label}
      </span>
      <ChevronRight className="h-4 w-4 text-nd-faint" />
    </Link>
  )
}

// Lockdown kill-switch: block every connection on the ingress interface except
// the protected hosts. Always armed with an auto-revert timer (enforced on the
// box) so it can never strand a remote operator.
function LockdownCard() {
  const canLock = useMe().can('protect.lockdown')
  const [s, setS] = useState<{ enabled: boolean; expires_at: number; now: number; ifaces: string[]; maxMinutes: number } | null>(null)
  const [minutes, setMinutes] = useState('15')
  const [busy, setBusy] = useState(false)
  const [alertOpen, setAlertOpen] = useState(false)
  const [err, setErr] = useState('')

  const load = useCallback(async () => {
    try { const r = await fetch('/api/lockdown', { cache: 'no-store' }); if (r.ok) setS(await r.json()) } catch {}
  }, [])
  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t) }, [load])

  const active = !!s?.enabled && (!s.expires_at || s.now < s.expires_at)
  const remaining = active && s?.expires_at ? Math.max(0, s.expires_at - s.now) : 0
  const mmss = (n: number) => `${Math.floor(n / 60)}m ${String(n % 60).padStart(2, '0')}s`
  const ifaceList = (s?.ifaces ?? ['vlan10', 'vlan20']).join(', ')

  async function apply(enabled: boolean) {
    setBusy(true); setErr('')
    try {
      const r = await fetch('/api/lockdown', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ enabled, minutes: Number(minutes) || 15 }) })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) setErr(d?.error || `error ${r.status}`)
      else { setS((prev) => ({ ...(prev ?? { maxMinutes: 1440 }), ...d })); setAlertOpen(false) }
    } catch { setErr('could not reach the server') }
    setBusy(false)
  }

  return (
    <div className={`overflow-hidden rounded-2xl border shadow-nd ${active ? 'border-st-crit/40 bg-st-crit/[0.05]' : 'border-nd-line bg-nd-card'}`}>
      <div className="flex flex-wrap items-center gap-3 px-5 py-4">
        <span className={`grid h-9 w-9 place-items-center rounded-xl ${active ? 'bg-st-crit/15 text-st-crit-fg' : 'bg-nd-fill text-nd-dim'}`}><Lock className="h-4 w-4" /></span>
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-[14px] font-semibold text-nd-fg">
            Lockdown
            {active && <span className="inline-flex items-center gap-1 rounded-full bg-st-crit/15 px-2 py-0.5 text-[11px] font-medium text-st-crit-fg">ACTIVE</span>}
          </div>
          <p className="text-[12px] text-nd-dim">Block every connection to your internal network — across the XDP dataplane (<span className="font-mono">{ifaceList}</span>) <strong>and over Twingate</strong> — except the protected hosts. {active ? `Auto-reverts in ${mmss(remaining)}.` : 'Your Twingate tunnel stays up, so you keep access and can lift it anytime. Arms with an auto-revert timer.'}</p>
        </div>
        <div className="ml-auto flex items-center gap-2">
          {!canLock ? (
            <NeedsPerm label="Arm & lift lockdown" />
          ) : active ? (
            <button onClick={() => apply(false)} disabled={busy} className="inline-flex items-center gap-1.5 rounded-lg bg-st-crit px-3.5 py-2 text-[13px] font-semibold text-white transition-opacity hover:opacity-90 disabled:opacity-40">
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldOff className="h-4 w-4" />} Lift now
            </button>
          ) : (
            <button onClick={() => { setErr(''); setAlertOpen(true) }} className="inline-flex items-center gap-1.5 rounded-lg border border-st-crit/40 px-3.5 py-2 text-[13px] font-semibold text-st-crit-fg transition-colors hover:bg-st-crit/10"><Lock className="h-4 w-4" /> Arm lockdown</button>
          )}
        </div>
      </div>
      {err && !alertOpen && (
        <div className="border-t border-nd-line px-5 py-2.5">
          <p className="flex items-center gap-1.5 text-[12px] text-st-crit-fg"><AlertTriangle className="h-3.5 w-3.5" /> {err}</p>
        </div>
      )}

      {alertOpen && (
        <Modal title="Arm lockdown?" onClose={() => setAlertOpen(false)}>
          <div className="space-y-3 px-5 py-4">
            <div className="flex items-start gap-2 rounded-xl border border-st-crit/30 bg-st-crit/[0.06] px-4 py-3 text-[13px] text-st-crit-fg">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>This drops <strong>every</strong> connection to your internal network — across the XDP dataplane (<span className="font-mono">{ifaceList}</span>) <strong>and over Twingate</strong> — to any host that isn’t in the protection plan. Non-protected LAN hosts lose access to other internal hosts. Management IPs keep their lifeline.</span>
            </div>
            <div className="flex items-start gap-2 rounded-xl border border-nd-line bg-nd-fill px-4 py-3 text-[13px] text-nd-dim">
              <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-nd-brand" />
              <span>Your <strong>Twingate tunnel stays up.</strong> Lockdown only blocks traffic bound for the internal network, never the connector’s link to its relays — so you keep dashboard access and can hit “Lift now” anytime. The timer is a backstop.</span>
            </div>
            <label className="flex items-center gap-2 text-[13px] text-nd-dim">Auto-revert after
              <input autoFocus value={minutes} onChange={(e) => setMinutes(e.target.value.replace(/\D/g, ''))} className="w-20 rounded-lg border border-nd-line bg-nd-card px-2.5 py-1.5 text-center text-[13px] text-nd-fg outline-none focus:border-nd-brand" /> minutes
            </label>
            {err && <p className="flex items-center gap-1.5 text-[12.5px] text-st-crit-fg"><AlertTriangle className="h-3.5 w-3.5" /> {err}</p>}
          </div>
          <div className="flex items-center justify-end gap-2 border-t border-nd-line bg-nd-panel px-5 py-3.5">
            <button onClick={() => setAlertOpen(false)} className="inline-flex items-center gap-1.5 rounded-lg border border-nd-line bg-nd-card px-3 py-2 text-[13px] font-medium text-nd-fg-3 hover:border-nd-line-strong hover:text-nd-fg">Cancel</button>
            <button onClick={() => apply(true)} disabled={busy || !minutes} className="inline-flex items-center gap-1.5 rounded-lg bg-st-crit px-3.5 py-2 text-[13px] font-semibold text-white transition-opacity hover:opacity-90 disabled:opacity-40">{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Lock className="h-4 w-4" />} Arm lockdown</button>
          </div>
        </Modal>
      )}
    </div>
  )
}

function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  useEffect(() => {
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', esc)
    document.body.style.overflow = 'hidden'
    return () => { document.removeEventListener('keydown', esc); document.body.style.overflow = '' }
  }, [onClose])
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true">
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-md overflow-hidden rounded-2xl border border-nd-line bg-nd-card shadow-nd-lg">
        <div className="flex items-center justify-between border-b border-nd-line bg-nd-panel px-5 py-3.5">
          <span className="flex items-center gap-2 text-[14px] font-semibold text-nd-fg"><ShieldCheck className="h-4 w-4 text-nd-brand" /> {title}</span>
          <button onClick={onClose} aria-label="Close" className="grid h-7 w-7 place-items-center rounded-lg border border-nd-line text-nd-muted hover:text-nd-fg"><X className="h-4 w-4" /></button>
        </div>
        {children}
      </div>
    </div>
  )
}

function AddHost({ management, lifeline, ingress, existing, onAdd }: { management: string[]; lifeline: Svc[]; ingress: string; existing: Host[]; onAdd: (iface: string, ip: string, services: Svc[]) => void }) {
  const [open, setOpen] = useState(false)
  const [ip, setIp] = useState('')
  const [svcs, setSvcs] = useState<Svc[]>([])
  const [err, setErr] = useState('')
  const inputCls = 'rounded-lg border border-nd-line bg-nd-card px-3 py-2 text-[13px] text-nd-fg outline-none focus:border-nd-brand'

  function reset() { setIp(''); setSvcs([]); setErr('') }
  function close() { setOpen(false); reset() }

  const isMgmt = management.includes(ip)

  function submit() {
    setErr('')
    if (!validIp(ip)) { setErr('enter a valid IPv4 address'); return }
    if (existing.some((h) => h.iface === ingress && h.ip === ip)) { setErr('already in the plan'); return }
    // A management IP always keeps its lifeline open (SSH + dashboard).
    let services = svcs
    if (isMgmt) {
      services = [...svcs]
      for (const l of lifeline) if (!services.some((e) => svcKey(e) === svcKey(l))) services.push(l)
    }
    onAdd(ingress, ip, services)
    close()
  }

  return (
    <>
      <div className="border-t border-nd-line bg-nd-panel px-5 py-3.5">
        <button onClick={() => setOpen(true)} className="inline-flex items-center gap-1.5 rounded-lg bg-nd-brand px-3.5 py-2 text-[13px] font-semibold text-black shadow-nd transition-opacity hover:opacity-90">
          <Plus className="h-4 w-4" /> Protect a host
        </button>
      </div>

      {open && (
        <Modal title="Protect a host" onClose={close}>
          <div className="space-y-4 px-5 py-4">
            <label className="block text-[12px] text-nd-dim">Host IP
              <input autoFocus value={ip} onChange={(e) => setIp(e.target.value)} placeholder="e.g. 192.168.1.173" className={`${inputCls} mt-1 block w-full font-mono`} />
            </label>
            <p className="flex items-start gap-1.5 rounded-lg border border-nd-line bg-nd-panel px-3 py-2 text-[11.5px] text-nd-dim">
              <Network className="mt-0.5 h-3.5 w-3.5 shrink-0 text-nd-brand" />
              <span>Protected at ingress on <span className="font-mono text-nd-fg-2">{ingress}</span> — where inbound requests enter the bridge. This is the interface that enforces default-deny, regardless of which side the host sits on.</span>
            </p>

            <div>
              <div className="mb-2 text-[12px] text-nd-dim">Allowed services <span className="text-nd-faint">— everything else to this host is dropped</span></div>
              <ServiceEditor
                services={svcs}
                onAdd={(s) => setSvcs((cur) => (cur.some((e) => svcKey(e) === svcKey(s)) ? cur : [...cur, s]))}
                onRemove={(k) => setSvcs((cur) => cur.filter((e) => svcKey(e) !== k))}
              />
              {isMgmt ? (
                <p className="mt-1.5 flex items-start gap-1 text-[11.5px] text-st-warn-fg"><AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" /> {ip} is a management IP — its lifeline ({lifeline.map(fmtSvc).join(', ') || '—'}) is kept open automatically, so you can’t lose SSH or the dashboard.</p>
              ) : svcs.length === 0 ? (
                <p className="mt-1.5 flex items-center gap-1 text-[11.5px] text-st-warn-fg"><AlertTriangle className="h-3 w-3" /> No services yet — the host would be fully blackholed until you add one.</p>
              ) : null}
            </div>

            {err && <p className="flex items-center gap-1.5 text-[12.5px] text-st-crit-fg"><AlertTriangle className="h-3.5 w-3.5" /> {err}</p>}
          </div>

          <div className="flex items-center justify-end gap-2 border-t border-nd-line bg-nd-panel px-5 py-3.5">
            <button onClick={close} className="inline-flex items-center gap-1.5 rounded-lg border border-nd-line bg-nd-card px-3 py-2 text-[13px] font-medium text-nd-fg-3 hover:border-nd-line-strong hover:text-nd-fg">Cancel</button>
            <button onClick={submit} disabled={!ip} className="inline-flex items-center gap-1.5 rounded-lg bg-nd-brand px-3.5 py-2 text-[13px] font-semibold text-black shadow-nd transition-opacity hover:opacity-90 disabled:opacity-40"><ShieldCheck className="h-4 w-4" /> Protect host</button>
          </div>
        </Modal>
      )}
    </>
  )
}
