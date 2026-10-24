'use client'
import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { instantAt, scalar, rangeAbs, toSeries } from '@/lib/prom'
import { usePoll } from '@/hooks/usePoll'
import { si, pps } from '@/lib/format'
import { niceStep } from '@/lib/stats'
import { Stat, Panel, Badge, type Tone } from '@/components/aa/kit'
import { TimeChart } from '@/components/nd/charts'
import { SERIES } from '@/components/nd/ui'
import { useRange } from '@/components/aa/Shell'
import {
  Lock, ShieldCheck, Ban, AlertTriangle, Server, Network, Info, Plus, Trash2, X, Loader2, Check, ShieldOff,
  ChevronRight, Activity,
} from 'lucide-react'

// Protection — EDIT the service-allowlist (default-deny), and inspect each
// protected host in a slide-over. You edit a desired-state "plan"; a root job on
// the box (xs-protect-apply) reconciles the eBPF maps with sentinelctl. Live
// state comes from the agent; a host shows "pending" until the dataplane matches
// the plan. Management IPs always keep a lifeline so the dashboard can't lock
// itself out. Denial counters are PER INTERFACE (the dataplane counts denials by
// interface, not by destination), so the drawer scopes them to the host's iface.

type Proto = 'tcp' | 'udp' | 'icmp'
interface Svc { proto: Proto; port: number }
interface Host { iface: string; ip: string; services: Svc[] }
interface LiveProt { ip: string; services: { proto: string; port: number }[] }
interface LiveIface { iface: string; protected: LiveProt[] }
interface LiveResp { interfaces: LiveIface[]; unavailable?: boolean }

const PROTO_TONE: Record<string, string> = { tcp: 'var(--s1)', udp: 'var(--s4)', icmp: 'var(--s2)' }
const svcKey = (s: { proto: string; port: number }) => `${s.proto}/${s.port}`
const hostKey = (iface: string, ip: string) => `${iface}|${ip}`
const fmtSvc = (s: { proto: string; port: number }) => `${s.proto}/${s.port === 0 ? '*' : s.port}`
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
const validIp = (ip: string) => { const m = IPV4.exec(ip); return !!m && m.slice(1).every((o) => +o >= 0 && +o <= 255) }

// Friendly names for common ports, and one-click presets for the editor.
const WELL_KNOWN: Record<string, string> = {
  'tcp/22': 'SSH', 'tcp/80': 'HTTP', 'tcp/443': 'HTTPS', 'tcp/3000': 'Dashboard', 'tcp/8006': 'Proxmox',
  'tcp/3389': 'RDP', 'tcp/8080': 'HTTP-alt', 'tcp/5432': 'Postgres', 'tcp/6443': 'Kubernetes',
  'tcp/53': 'DNS', 'udp/53': 'DNS', 'udp/123': 'NTP', 'udp/51820': 'WireGuard', 'icmp/0': 'ping',
}
const svcName = (s: { proto: string; port: number }) => WELL_KNOWN[svcKey(s)]

function statusOf(applied: boolean, hasLive: boolean): { label: string; tone: Tone } {
  if (applied) return { label: 'live', tone: 'good' }
  if (hasLive) return { label: 'pending', tone: 'warn' }
  return { label: 'not applied', tone: 'neutral' }
}

async function fetchLive(): Promise<LiveResp> {
  const r = await fetch('/api/agent/api/services.json', { cache: 'no-store' })
  if (!r.ok) return { interfaces: [], unavailable: true }
  try { return await r.json() } catch { return { interfaces: [], unavailable: true } }
}

export default function Protection() {
  const rng = useRange()
  const live = usePoll(fetchLive, 10_000)
  const deny = usePoll(async () => {
    const w = rng.resolve()
    const [win, life] = await Promise.all([
      instantAt(`sum(increase(xs_service_packets_total{event="deny"}[${w.span}s]))`, w.end),
      instantAt('sum(increase(xs_service_packets_total{event="deny"}[1y]))', w.end),
    ])
    return { win: scalar(win, 0) ?? 0, life: scalar(life, 0) ?? 0 }
  }, 15_000, [rng.key])

  const [hosts, setHosts] = useState<Host[]>([])
  const [saved, setSaved] = useState<string>('[]') // JSON of last-saved hosts, for dirty check
  const [management, setManagement] = useState<string[]>([])
  const [lifeline, setLifeline] = useState<Svc[]>([])
  const [ingress, setIngress] = useState('vlan10')
  const [loaded, setLoaded] = useState(false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')
  const [open, setOpen] = useState<number | null>(null) // selected host index for the drawer

  // live index: "iface|ip" -> Set of "proto/port"
  const liveIndex = useMemo(() => {
    const m = new Map<string, Set<string>>()
    for (const i of live.data?.interfaces ?? []) for (const p of i.protected) m.set(hostKey(i.iface, p.ip), new Set(p.services.map(svcKey)))
    return m
  }, [live.data])

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

  const setHost = (idx: number, fn: (h: Host) => Host) => setHosts((hs) => hs.map((h, i) => (i === idx ? fn(h) : h)))
  const removeHost = (idx: number) => setHosts((hs) => hs.filter((_, i) => i !== idx))

  async function save() {
    setBusy(true); setErr(''); setOk('')
    try {
      const r = await fetch('/api/protect-plan', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ hosts }) })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) { setErr(d?.error || `error ${r.status}`); setBusy(false); return }
      const h = (d.plan?.hosts || hosts) as Host[]
      setHosts(h); setSaved(JSON.stringify(h))
      setOk('Saved — the box is applying it; live state refreshes in a few seconds.')
    } catch { setErr('could not reach the server') }
    setBusy(false)
  }

  const sel = open != null && open < hosts.length ? hosts[open] : null
  const selLive = sel ? liveIndex.get(hostKey(sel.iface, sel.ip)) : undefined
  const selApplied = !!sel && !!selLive && selLive.size === sel.services.length && sel.services.every((s) => selLive.has(svcKey(s)))

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
          <span className="text-[12px] text-nd-dim">default-deny — click a host for stats &amp; to edit its allowed services</span>
          <div className="ml-auto flex items-center gap-2">
            {dirty && <span className="text-[12px] text-st-warn-fg">unsaved</span>}
            <button onClick={save} disabled={busy || !dirty} className="inline-flex items-center gap-1.5 rounded-lg bg-nd-brand px-3.5 py-2 text-[13px] font-semibold text-black shadow-nd transition-opacity hover:opacity-90 disabled:opacity-40">
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />} Save &amp; apply
            </button>
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
              const applied = !!liveSvcs && liveSvcs.size === h.services.length && h.services.every((s) => liveSvcs.has(svcKey(s)))
              return (
                <HostRow key={`${h.iface}|${h.ip}|${idx}`} host={h} applied={applied} hasLive={!!liveSvcs} selected={open === idx} onOpen={() => setOpen(idx)} />
              )
            })
          )}
        </div>

        <AddHost management={management} lifeline={lifeline} ingress={ingress} existing={hosts} onAdd={(iface, ip, services) => setHosts((hs) => [...hs, { iface, ip, services }])} />

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

      {sel && (
        <HostDrawer
          host={sel}
          applied={selApplied}
          hasLive={!!selLive}
          liveSvcs={selLive}
          isMgmt={management.includes(sel.ip)}
          lifeline={lifeline}
          onClose={() => setOpen(null)}
          onAddSvc={(s) => setHost(open!, (x) => (x.services.some((e) => svcKey(e) === svcKey(s)) ? x : { ...x, services: [...x.services, s] }))}
          onRemoveSvc={(k) => setHost(open!, (x) => ({ ...x, services: x.services.filter((e) => svcKey(e) !== k) }))}
          onRemove={() => { removeHost(open!); setOpen(null) }}
        />
      )}
    </div>
  )
}

function HostRow({ host, applied, hasLive, selected, onOpen }: {
  host: Host; applied: boolean; hasLive: boolean; selected: boolean; onOpen: () => void
}) {
  const st = statusOf(applied, hasLive)
  const dotCls = st.tone === 'good' ? 'bg-st-good' : st.tone === 'warn' ? 'bg-st-warn' : 'bg-nd-faint'
  const txtCls = st.tone === 'good' ? 'text-st-good-fg' : st.tone === 'warn' ? 'text-st-warn-fg' : 'text-nd-dim'
  return (
    <button onClick={onOpen} className={`flex w-full items-center gap-3 px-5 py-3.5 text-left transition-colors hover:bg-nd-fill ${selected ? 'bg-nd-fill' : ''}`}>
      <Server className="h-4 w-4 shrink-0 text-nd-dim" />
      <span className="font-mono text-[13.5px] font-semibold text-nd-fg">{host.ip}</span>
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
    </button>
  )
}

function HostDrawer({ host, applied, hasLive, liveSvcs, isMgmt, lifeline, onClose, onAddSvc, onRemoveSvc, onRemove }: {
  host: Host; applied: boolean; hasLive: boolean; liveSvcs?: Set<string>; isMgmt: boolean; lifeline: Svc[]
  onClose: () => void; onAddSvc: (s: Svc) => void; onRemoveSvc: (key: string) => void; onRemove: () => void
}) {
  const rng = useRange()
  const iface = host.iface
  const [confirmDel, setConfirmDel] = useState(false)
  const st = statusOf(applied, hasLive)

  const stats = usePoll(async () => {
    const w = rng.resolve()
    const [win, life] = await Promise.all([
      instantAt(`sum(increase(xs_service_packets_total{iface="${iface}",event="deny"}[${w.span}s]))`, w.end),
      instantAt(`sum(increase(xs_service_packets_total{iface="${iface}",event="deny"}[1y]))`, w.end),
    ])
    return { win: scalar(win, 0) ?? 0, life: scalar(life, 0) ?? 0 }
  }, 15_000, [iface, rng.key])

  const chart = usePoll(async () => {
    const w = rng.resolve()
    const step = niceStep(w.span, 160)
    const rw = `${Math.max(60, step)}s`
    const [dn, vd] = await Promise.all([
      rangeAbs(`sum(rate(xs_service_packets_total{iface="${iface}",event="deny"}[${rw}]))`, w.end - w.span, w.end, step),
      rangeAbs(`sum by(verdict)(rate(xs_verdict_packets_total{iface="${iface}",verdict=~"pass|drop"}[${rw}]))`, w.end - w.span, w.end, step),
    ])
    return {
      deny: toSeries(dn, () => 'deny'),
      verdict: toSeries(vd, (m) => m.verdict ?? 'drop'),
      spanMs: w.span * 1000,
    }
  }, 30_000, [iface, rng.key])

  useEffect(() => {
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', esc)
    document.body.style.overflow = 'hidden'
    return () => { document.removeEventListener('keydown', esc); document.body.style.overflow = '' }
  }, [onClose])

  const spanMs = chart.data?.spanMs ?? 3_600_000

  return (
    <div className="fixed inset-0 z-50" role="dialog" aria-modal="true" aria-label={`Protected host ${host.ip}`}>
      <button aria-label="Close" onClick={onClose} className="absolute inset-0 bg-black/30 backdrop-blur-[2px]" />
      <div className="aa-in absolute inset-y-0 right-0 flex w-full max-w-[760px] flex-col border-l border-nd-line bg-nd-bg shadow-nd-lg">
        <header className="flex items-start justify-between gap-4 border-b border-nd-line bg-nd-card px-6 py-5">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone="brand" icon={Server}>{host.iface}</Badge>
              <Badge tone={st.tone}>{st.label}</Badge>
              {host.services.length === 0 && <Badge tone="bad" icon={AlertTriangle}>blackholed</Badge>}
              {isMgmt && <Badge tone="warn" icon={ShieldOff}>management</Badge>}
            </div>
            <h2 className="mt-2 font-mono text-[20px] font-semibold tracking-[-0.02em] text-nd-fg">{host.ip}</h2>
            <p className="mt-1 text-[13px] text-nd-dim">Default-deny on {host.iface} — only the services below reach this host; everything else is dropped.</p>
          </div>
          <button onClick={onClose} aria-label="Close" className="grid h-8 w-8 shrink-0 place-items-center rounded-lg text-nd-dim hover:bg-nd-fill hover:text-nd-fg"><X className="h-4 w-4" /></button>
        </header>

        <div className="flex-1 space-y-5 overflow-y-auto px-6 py-6">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Stat label="Allowed services" icon={Lock} value={host.services.length} sub="reach this host" color="var(--s4)" />
            <Stat label="Denied (window)" icon={Ban} loading={!stats.data} value={si(stats.data?.win)} sub={`drops on ${iface}`} color="var(--s2)" />
            <Stat label="Denied (lifetime)" icon={ShieldCheck} loading={!stats.data} value={si(stats.data?.life)} sub={`drops on ${iface}`} color="var(--s1)" />
            <Stat label="State" icon={Activity} value={st.label} sub={applied ? 'plan = dataplane' : hasLive ? 'applying…' : 'not yet applied'} color={st.tone === 'good' ? 'var(--s3)' : 'var(--st-warn)'} />
          </div>

          <div className="flex items-start gap-2 rounded-xl border border-nd-line bg-nd-panel px-4 py-2.5 text-[11.5px] text-nd-dim">
            <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <span>The dataplane counts service-allowlist denials <strong className="font-medium text-nd-fg-2">per interface</strong>, not per destination — these figures are all protected-host drops on <span className="font-mono">{iface}</span>. Traffic that enters via another interface is counted there.</span>
          </div>

          <Panel icon={Ban} title="Denied packets" sub={`Service-allowlist drops on ${iface}, per second`}>
            <TimeChart loading={!chart.data} data={chart.data?.deny ?? []} series={[{ key: 'deny', label: 'Denied', color: SERIES[1] }]} yfmt={pps} spanMs={spanMs} height={190} />
          </Panel>

          <Panel icon={ShieldCheck} title="Passed vs dropped" sub={`All verdicts on ${iface}, per second`}>
            <TimeChart loading={!chart.data} data={chart.data?.verdict ?? []} series={[{ key: 'pass', label: 'Passed', color: SERIES[2] }, { key: 'drop', label: 'Dropped', color: SERIES[1] }]} yfmt={pps} spanMs={spanMs} height={190} />
          </Panel>

          {/* editor */}
          <Panel
            icon={Lock}
            title="Allowed services"
            sub="everything else to this host is dropped"
            actions={
              confirmDel ? (
                <span className="inline-flex items-center gap-1.5">
                  <button onClick={onRemove} className="inline-flex items-center gap-1 rounded-lg bg-st-crit px-2.5 py-1.5 text-[12px] font-medium text-white hover:opacity-90">unprotect host</button>
                  <button onClick={() => setConfirmDel(false)} className="grid h-7 w-7 place-items-center rounded-lg border border-nd-line text-nd-muted hover:text-nd-fg"><X className="h-3.5 w-3.5" /></button>
                </span>
              ) : (
                <button onClick={() => setConfirmDel(true)} className="inline-flex items-center gap-1 rounded-lg border border-nd-line px-2.5 py-1.5 text-[12px] font-medium text-st-crit-fg hover:border-st-crit/40"><Trash2 className="h-3.5 w-3.5" /> Unprotect</button>
              )
            }
          >
            <ServiceEditor
              services={host.services}
              onAdd={onAddSvc}
              onRemove={onRemoveSvc}
              toneFor={(s) => (liveSvcs ? (liveSvcs.has(svcKey(s)) ? 'good' : 'warn') : null)}
              lockedKey={(k) => isMgmt && lifeline.some((l) => svcKey(l) === k)}
            />
            {host.services.length === 0 && <p className="mt-2 flex items-center gap-1 text-[11.5px] text-st-crit-fg"><AlertTriangle className="h-3 w-3" /> No services — this host is fully blackholed until you add one.</p>}
            {isMgmt && <p className="mt-2 flex items-start gap-1 text-[11.5px] text-st-warn-fg"><ShieldOff className="mt-0.5 h-3 w-3 shrink-0" /> Management IP — its lifeline ({lifeline.map(fmtSvc).join(', ') || '—'}) is kept open automatically and can’t be removed.</p>}
            <p className="mt-2 text-[11px] text-nd-faint">Changes here are staged — hit <strong className="font-medium">Save &amp; apply</strong> on the list to push them to the box.</p>
          </Panel>
        </div>
      </div>
    </div>
  )
}

// Shared allowed-services editor: a table of rows (proto · port · name · status
// · remove) with an add row at the bottom (segmented proto control + port).
// Used in the host drawer (with live/pending status) and the add-host modal.
function ServiceEditor({ services, onAdd, onRemove, toneFor, lockedKey }: {
  services: Svc[]
  onAdd: (s: Svc) => void
  onRemove: (key: string) => void
  toneFor?: (s: Svc) => 'good' | 'warn' | null
  lockedKey?: (key: string) => boolean
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
                {locked ? (
                  <Lock className="h-3.5 w-3.5 shrink-0 text-nd-faint" aria-label="lifeline — can’t be removed" />
                ) : (
                  <button onClick={() => onRemove(key)} title="Remove service" className="grid h-6 w-6 shrink-0 place-items-center rounded-md text-nd-faint transition-colors hover:bg-nd-fill hover:text-st-crit-fg"><X className="h-3.5 w-3.5" /></button>
                )}
              </div>
            )
          })}
        </div>
      )}

      <div className={`flex items-center gap-2 bg-nd-panel px-3 py-2 ${services.length > 0 ? 'border-t border-nd-line' : ''}`}>
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
      </div>
    </div>
  )
}

// Lockdown kill-switch: block every connection on the ingress interface except
// the protected hosts. Always armed with an auto-revert timer (enforced on the
// box) so it can never strand a remote operator.
function LockdownCard() {
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
          <p className="text-[12px] text-nd-dim">Block every connection across the XDP dataplane (<span className="font-mono">{ifaceList}</span>) <strong>and the Twingate tunnel</strong> except the protected hosts. {active ? `Auto-reverts in ${mmss(remaining)}.` : 'Severs remote (Twingate) access until the auto-revert timer expires — keep the timer short.'}</p>
        </div>
        <div className="ml-auto flex items-center gap-2">
          {active ? (
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
              <span>This drops <strong>every</strong> connection across the XDP dataplane (<span className="font-mono">{ifaceList}</span>) <strong>and the Twingate tunnel</strong> to any host that isn’t in the protection plan — WAN clients and LAN hosts alike, so non-protected LAN hosts lose internet. Management IPs keep their lifeline.</span>
            </div>
            <div className="flex items-start gap-2 rounded-xl border border-st-crit/40 bg-st-crit/[0.1] px-4 py-3 text-[13px] text-st-crit-fg">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <span><strong>You will lose your own remote access.</strong> The Twingate connector reaches its relays over the same path, so arming this cuts your tunnel — you will <strong>not</strong> be able to reach the dashboard or hit “Lift now”. Only the on-box timer below ends it, so set it short.</span>
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
