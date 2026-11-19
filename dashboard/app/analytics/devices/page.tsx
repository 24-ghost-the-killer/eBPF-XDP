'use client'
// Devices: everything the box can see on its bridge. Unknown and new devices
// stand out; you can name them, mark them known, or forget old ones. Devices
// that have been an attack source (e.g. a laptop port-scanning the box) say so.
import { useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import Link from 'next/link'
import {
  MonitorSmartphone, Wifi, HelpCircle, Sparkles, ShieldAlert, Pencil, Check, X, Trash2, Loader2, Search, BadgeCheck, AlertTriangle,
  Router, Network, Cctv, Printer, Smartphone, Laptop, Server, Tv, Cpu, Apple, Globe, Monitor, Radar, ExternalLink, type LucideIcon,
} from 'lucide-react'
import { usePoll } from '@/hooks/usePoll'
import { Panel, Stat, Badge, Empty, btn, type Tone } from '@/components/aa/kit'
import { useMe } from '@/components/aa/Shell'
import { LanGuard } from '@/components/devices/LanGuard'

interface Device {
  mac: string; vendor: string | null; name: string | null; note: string | null; known: boolean
  ips: string[]; port: string | null; firstSeen: number; lastSeen: number; online: boolean; reachable: boolean
  flags: string[]; attacks: { count: number; last: number } | null
  kind: string; label: string | null; os: string | null; webUrl: string | null; services: string[]; ports: number[]; hostname: string | null; checkedAt: number | null
  switchPort: number | null; vlans: string[]; sources: string[]
}
interface Scan { at: number | null; running: boolean; found: number; took: number; error?: string }
interface Addr { ip: string; first: number; last: number; from: string[]; attacks: number }
interface Resp {
  devices: Device[]; addresses?: Addr[]; scan?: Scan
  summary: { total: number; online: number; unknown: number; new24h: number; attackers: number; fromSwitch?: number; historySince?: number | null }
}

const KIND_ICON: [RegExp, LucideIcon][] = [
  [/router/i, Router], [/switch|access point/i, Network], [/camera/i, Cctv], [/printer/i, Printer], [/iphone|phone/i, Smartphone],
  [/apple/i, Apple], [/proxmox|server|linux/i, Server], [/tv|chromecast/i, Tv], [/raspberry/i, Cpu], [/windows|computer/i, Laptop],
  [/web page/i, Globe],
]
const kindIcon = (k: string) => KIND_ICON.find(([re]) => re.test(k))?.[1] ?? Monitor

const FLAG: Record<string, { label: string; tone: Tone; hint: string }> = {
  new: { label: 'New', tone: 'warn', hint: 'first seen in the last 24 hours' },
  attacker: { label: 'Attack', tone: 'bad', hint: 'its address was a source in recorded attacks' },
  'ip-conflict': { label: 'IP conflict', tone: 'bad', hint: 'another device answers for the same IP: a misconfiguration or ARP spoofing' },
  'multi-ip': { label: 'Several IPs', tone: 'neutral', hint: 'uses more than one IPv4 address right now' },
  'private-mac': { label: 'Private MAC', tone: 'neutral', hint: 'a randomised address (phones and laptops use these for privacy), so the maker is unknown' },
}
const SIDE: Record<string, string> = { vlan10: 'WAN side', vlan20: 'LAN side' }
const ago = (ms: number) => {
  const s = Math.max(0, (Date.now() - ms) / 1000)
  return s < 90 ? 'now' : s < 3600 ? `${Math.round(s / 60)} min ago` : s < 86400 * 2 ? `${Math.round(s / 3600)} h ago` : `${Math.round(s / 86400)} days ago`
}
const day = (ms: number) => new Date(ms).toLocaleDateString([], { day: 'numeric', month: 'short', year: 'numeric' })
type Filter = 'all' | 'unknown' | 'new' | 'attacker' | 'online' | 'gone'

export default function DevicesPage() {
  const { can } = useMe()
  const editable = can('devices.edit')
  const [rev, setRev] = useState(0)
  const [scanning, setScanning] = useState(false)
  const [scanErr, setScanErr] = useState('')
  const scanNow = async () => {
    setScanning(true); setScanErr('')
    try {
      const r = await fetch('/api/devices?action=scan', { method: 'POST' })
      const j = await r.json().catch(() => ({}))
      if (!r.ok || j.status !== 'success') throw new Error(j.error || 'scan failed')
      setRev((x) => x + 1)
    } catch (e) {
      setScanErr(e instanceof Error ? e.message : 'scan failed')
    }
    setScanning(false)
  }
  const q = usePoll(async () => {
    const r = await fetch('/api/devices', { cache: 'no-store' })
    const j = await r.json()
    if (j.status !== 'success') throw new Error(j.error === 'forbidden' ? 'You don’t have access to the device list.' : j.error || 'could not load devices')
    return j as Resp
  }, 30_000, [rev])
  const [filter, setFilter] = useState<Filter>('all')
  const [text, setText] = useState('')
  const d = q.data
  const rows = useMemo(() => {
    const t = text.trim().toLowerCase()
    return [...(d?.devices ?? [])].sort(byAddress).filter((x) =>
      (filter === 'all' || (filter === 'online' ? x.online : filter === 'gone' ? !x.online : filter === 'unknown' ? !x.known : x.flags.includes(filter))) &&
      (!t || [x.name, x.label, x.kind, x.os, x.hostname, x.vendor, x.mac, ...x.ips, x.note].some((v) => v?.toLowerCase().includes(t))))
  }, [d, filter, text])

  const patch = async (mac: string, body: Record<string, unknown>) => {
    const r = await fetch('/api/devices', { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ mac, ...body }) })
    const j = await r.json().catch(() => ({}))
    if (!r.ok || j.status !== 'success') throw new Error(j.error || 'could not save')
    setRev((x) => x + 1)
  }
  const forget = async (mac: string) => {
    await fetch(`/api/devices?mac=${encodeURIComponent(mac)}`, { method: 'DELETE' })
    setRev((x) => x + 1)
  }

  if (!d) return q.error ? <Empty icon={MonitorSmartphone} title="Couldn’t load the device list" hint={q.error} /> : <div className="aa-skeleton h-64 rounded-2xl" />
  const s = d.summary
  const fresh = d.devices.filter((x) => x.flags.includes('new'))

  return (
    <div className="space-y-6">
      <LanGuard onApproved={() => setRev((x) => x + 1)} />
      {fresh.length > 0 && (
        <div className="flex items-start gap-3 rounded-2xl border border-st-warn/30 bg-st-warn/[0.07] px-5 py-3.5">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-st-warn-fg" />
          <div className="text-[13px]">
            <span className="font-semibold text-nd-fg">{fresh.length} new device{fresh.length === 1 ? '' : 's'} in the last 24 hours</span>
            <span className="text-nd-fg-3"> · {fresh.slice(0, 4).map((x) => x.ips[0] ?? x.mac).join(', ')}{fresh.length > 4 ? '…' : ''}. If you don’t recognise {fresh.length === 1 ? 'it' : 'them'}, find out what {fresh.length === 1 ? 'it is' : 'they are'} before marking {fresh.length === 1 ? 'it' : 'them'} known.</span>
          </div>
        </div>
      )}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <Stat label="Devices" icon={MonitorSmartphone} value={s.total} sub={s.historySince ? `ever seen, since ${new Date(s.historySince).toLocaleDateString([], { day: 'numeric', month: 'short' })}` : 'ever seen'} />
        <Stat label="Online now" icon={Wifi} value={s.online} sub="in the box’s tables" />
        <Stat label="Unknown" icon={HelpCircle} value={s.unknown} sub="not marked known" />
        <Stat label="New (24 h)" icon={Sparkles} value={s.new24h} sub="first seen today" />
        <Stat label="Attack sources" icon={ShieldAlert} value={s.attackers} sub="seen in recorded attacks" />
      </div>

      <Panel icon={MonitorSmartphone} title="Devices on the network"
        sub={d.scan?.running || scanning ? 'Scanning the network…' : d.scan?.at ? `Last scan ${ago(d.scan.at)}: ${d.scan.found} device${d.scan.found === 1 ? '' : 's'} answered · the whole subnet is swept every 10 min` : 'The first network scan runs a few seconds after the dashboard starts'}
        bodyClass=""
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {editable && (
              <button type="button" onClick={scanNow} disabled={scanning || d.scan?.running} className={`${btn.ghost} py-1.5 text-[12.5px]`} title="Sweep the subnet and check every device’s services now (takes ~20 s)">
                {scanning || d.scan?.running ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Radar className="h-3.5 w-3.5" />} Scan now
              </button>
            )}
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-nd-faint" />
              <input value={text} onChange={(e) => setText(e.target.value)} placeholder="Name, IP, MAC, maker" aria-label="Search devices" className={`${btn.input} w-48 py-1.5 pl-8 text-[12.5px]`} />
            </div>
            <select value={filter} onChange={(e) => setFilter(e.target.value as Filter)} aria-label="Show" className={`${btn.input} py-1.5 text-[12.5px]`}>
              <option value="all">All devices</option>
              <option value="online">Online now</option>
              <option value="gone">Been here, gone now</option>
              <option value="unknown">Unknown</option>
              <option value="new">New (24 h)</option>
              <option value="attacker">Attack sources</option>
            </select>
          </div>
        }>
        {rows.length === 0 ? (
          <Empty icon={MonitorSmartphone} title="No devices match" hint="Clear the search or pick “All devices”." />
        ) : (
          <div className="overflow-x-auto">
            {/* fixed layout: columns never resize, every row is the same height, long
                content is cut with … (full text on hover) or opens in a pop-over */}
            <table className="w-full min-w-[940px] table-fixed text-left text-[13px]">
              <colgroup>
                <col />
                <col className="w-[190px]" />
                <col className="w-[236px]" />
                <col className="w-[96px]" />
                <col className="w-[196px]" />
                {editable && <col className="w-[112px]" />}
              </colgroup>
              <thead>
                <tr className="border-y border-nd-line bg-nd-fill text-[11px] uppercase tracking-[0.06em] text-nd-dim">
                  <th className="py-2 pl-5 pr-3 font-medium">Device</th>
                  <th className="px-3 py-2 font-medium">Address</th>
                  <th className="px-3 py-2 font-medium">Services</th>
                  <th className="px-3 py-2 font-medium">Seen</th>
                  <th className="px-3 py-2 font-medium">Flags</th>
                  {editable && <th className="px-3 py-2 pr-5 text-right font-medium"><span className="sr-only">Actions</span></th>}
                </tr>
              </thead>
              <tbody>
                {rows.map((x) => <DeviceRow key={x.mac} x={x} editable={editable} onPatch={patch} onForget={forget} />)}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      {scanErr && <p className="text-[12px] text-st-crit-fg">Scan failed: {scanErr}</p>}
      {(d.addresses?.length ?? 0) > 0 && <Addresses list={d.addresses!} />}
      <p className="text-[11.5px] text-nd-faint">
        How devices are found and named: every 10 minutes the box sweeps its subnet (each switched-on device must answer ARP), asks for names over mDNS, NetBIOS and UPnP,
        and once a day checks a few well-known ports, the SSH banner and the web page title. Devices that have been and gone come from the Zyxel switch’s address table
        and the per-address traffic counters, which Prometheus keeps for ~15 days; from then on this list keeps them for good. Makers from the IEEE OUI register. A device
        with a MAC but no IP has no address on this subnet (asleep, or a fixed address on another network), or only ever appeared in the switch’s table.
      </p>
    </div>
  )
}

// LAN addresses seen in traffic or attacks that no device record holds (e.g. a
// phone that had .110 last week and has gone since): shown so nothing is missed.
function Addresses({ list }: { list: Addr[] }) {
  const when = (ms: number) => new Date(ms).toLocaleString([], { day: 'numeric', month: 'numeric', hour: '2-digit', minute: '2-digit' })
  return (
    <Panel icon={Globe} title="Addresses with no device yet" bodyClass=""
      sub={`${list.length} LAN address${list.length === 1 ? '' : 'es'} that sent traffic (or attacked) but whose device the box never matched: usually a device that left before it was scanned`}>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[640px] table-fixed text-left text-[13px]">
          <colgroup><col className="w-[190px]" /><col className="w-[160px]" /><col className="w-[160px]" /><col /></colgroup>
          <thead>
            <tr className="border-y border-nd-line bg-nd-fill text-[11px] uppercase tracking-[0.06em] text-nd-dim">
              <th className="py-2 pl-5 pr-3 font-medium">IP address</th>
              <th className="px-3 py-2 font-medium">First seen</th>
              <th className="px-3 py-2 font-medium">Last seen</th>
              <th className="px-3 py-2 pr-5 font-medium">Seen in</th>
            </tr>
          </thead>
          <tbody>
            {list.map((a) => (
              <tr key={a.ip} className="h-11 border-b border-nd-line-soft last:border-0">
                <td className="pl-5 pr-3"><Link href={`/analytics/ip?ip=${encodeURIComponent(a.ip)}`} className="mono text-[12.5px] text-nd-fg-2 hover:text-nd-fg hover:underline">{a.ip}</Link></td>
                <td className="mono px-3 text-[12px] text-nd-fg-3">{when(a.first)}</td>
                <td className="mono px-3 text-[12px] text-nd-fg-3">{when(a.last)}</td>
                <td className="px-3 pr-5">
                  <div className="flex items-center gap-1 overflow-hidden whitespace-nowrap">
                    {a.from.includes('traffic') && <Badge>traffic</Badge>}
                    {a.from.includes('attack') && <Badge tone="bad">attack source{a.attacks ? ` ×${a.attacks}` : ''}</Badge>}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  )
}

// IPv4 address as a number; devices without one go last (then by MAC)
const ipNum = (x: Device) => {
  const ip = x.ips.find((i) => !i.includes(':'))
  return ip ? ip.split('.').reduce((n, o) => n * 256 + Number(o), 0) : Number.MAX_SAFE_INTEGER
}
const byAddress = (a: Device, b: Device) => ipNum(a) - ipNum(b) || a.mac.localeCompare(b.mac)

// what each checked port is, for the services pop-over
const PORT_INFO: Record<number, string> = {
  22: 'SSH remote login', 53: 'DNS name server', 80: 'Web page (HTTP)', 443: 'Web page (HTTPS)', 445: 'Windows file sharing (SMB)',
  554: 'Video stream (RTSP, cameras)', 631: 'Printing (IPP)', 3389: 'Windows Remote Desktop', 5000: 'UPnP / AirPlay', 7000: 'AirPlay',
  8006: 'Proxmox web interface', 8008: 'Chromecast', 8080: 'Web page (port 8080)', 8443: 'Web page (HTTPS, port 8443)', 9100: 'Raw printing (JetDirect)',
  62078: 'iPhone / iPad sync',
}

// One line of chips that shows exactly what fits at the current width and
// reports how many did not: the items wrap onto a hidden second line, which is
// measured (on mount and whenever the cell resizes) instead of guessed.
function FitRow({ items, more }: { items: { key: string; node: ReactNode }[]; more: (hidden: number) => ReactNode }) {
  const box = useRef<HTMLDivElement | null>(null)
  const [hidden, setHidden] = useState(0)
  useLayoutEffect(() => {
    const el = box.current
    if (!el) return
    const measure = () => {
      const kids = [...el.children] as HTMLElement[]
      const top = kids[0]?.offsetTop ?? 0
      setHidden(kids.filter((k) => k.offsetTop > top + 2).length)
    }
    measure()
    const ro = new ResizeObserver(measure)
    ro.observe(el)
    return () => ro.disconnect()
  }, [items.length, hidden])
  return (
    <div className="flex min-w-0 items-center gap-1">
      <div ref={box} className="flex h-[22px] min-w-0 flex-1 flex-wrap items-center gap-1 overflow-hidden">
        {items.map((it) => <span key={it.key} className="shrink-0">{it.node}</span>)}
      </div>
      {hidden > 0 && more(hidden)}
    </div>
  )
}

// A pop-over pinned to the viewport: opens over the table, so no row moves.
function Popover({ label, title, children }: { label: string; title: string; children: React.ReactNode }) {
  const [at, setAt] = useState<{ top: number; left: number } | null>(null)
  const ref = useRef<HTMLButtonElement | null>(null)
  const panel = useRef<HTMLDivElement | null>(null)
  // keep it fully on screen (measured after it renders)
  useLayoutEffect(() => {
    const el = panel.current
    if (!at || !el) return
    const r = el.getBoundingClientRect()
    const vw = document.documentElement.clientWidth
    const vh = document.documentElement.clientHeight
    const left = Math.max(8, Math.min(at.left, vw - r.width - 8))
    const top = r.bottom > vh - 8 ? Math.max(8, at.top - (r.bottom - vh) - 8) : at.top
    if (left !== at.left || top !== at.top) setAt({ left, top })
  }, [at])
  useEffect(() => {
    if (!at) return
    const close = (e: Event) => { if (e.type !== 'mousedown' || !(e.target as Element).closest?.('[data-popover]')) setAt(null) }
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') setAt(null) }
    document.addEventListener('mousedown', close)
    window.addEventListener('scroll', close, true)
    window.addEventListener('resize', close)
    document.addEventListener('keydown', esc)
    return () => { document.removeEventListener('mousedown', close); window.removeEventListener('scroll', close, true); window.removeEventListener('resize', close); document.removeEventListener('keydown', esc) }
  }, [at])
  const open = () => {
    const r = ref.current?.getBoundingClientRect()
    if (!r) return
    const W = 272
    setAt(at ? null : { top: Math.min(r.bottom + 6, window.innerHeight - 300), left: Math.max(8, Math.min(r.left, window.innerWidth - W - 8)) })
  }
  return (
    <>
      <button ref={ref} type="button" onClick={open} title={title} aria-expanded={!!at} data-popover
        className="shrink-0 rounded bg-nd-fill-2 px-1.5 py-0.5 text-[11px] font-medium text-nd-fg-2 hover:bg-nd-line">{label}</button>
      {at && (
        <div ref={panel} data-popover role="dialog" aria-label={title} style={{ top: at.top, left: at.left, width: 272 }}
          className="fixed z-40 max-h-[290px] overflow-y-auto rounded-xl border border-nd-line bg-nd-card p-3 text-[12.5px] shadow-nd-lg">
          {children}
        </div>
      )}
    </>
  )
}

function Services({ x }: { x: Device }) {
  if (!x.ports.length) {
    return <span className="text-[11.5px] text-nd-faint">{x.checkedAt ? 'none open' : x.ips.length ? 'not checked yet' : '—'}</span>
  }
  const list = (
    <>
      <div className="mb-2 text-[11px] font-medium uppercase tracking-[0.06em] text-nd-dim">{x.ports.length} open service{x.ports.length === 1 ? '' : 's'}</div>
      <ul className="space-y-1.5">
        {x.ports.map((port, k) => (
          <li key={port} className="flex items-baseline gap-2">
            <span className="w-16 shrink-0 font-medium text-nd-fg">{x.services[k]}</span>
            <span className="min-w-0 flex-1 text-nd-fg-3">{PORT_INFO[port] ?? 'service'}</span>
            <span className="mono shrink-0 text-[11px] text-nd-faint">{port}</span>
          </li>
        ))}
      </ul>
      {x.webUrl && (
        <a href={x.webUrl} target="_blank" rel="noopener noreferrer" className="mt-2.5 inline-flex items-center gap-1 text-nd-dim hover:text-nd-fg hover:underline">
          Open its web page <ExternalLink className="h-3 w-3" />
        </a>
      )}
    </>
  )
  return (
    <div className="flex min-w-0 items-center gap-1">
      {x.webUrl ? (
        <a href={x.webUrl} target="_blank" rel="noopener noreferrer" title={`Open its web page (${x.webUrl})`} aria-label="Open its web page"
          className="grid h-5 w-5 shrink-0 place-items-center rounded text-nd-dim hover:bg-nd-fill hover:text-nd-fg"><ExternalLink className="h-3.5 w-3.5" /></a>
      ) : <span className="w-5 shrink-0" />}
      <div className="min-w-0 flex-1">
        <FitRow
          items={x.services.map((sv, k) => ({ key: `${x.ports[k]}`, node: <span title={PORT_INFO[x.ports[k]] ?? sv} className="block rounded bg-nd-fill px-1.5 py-0.5 text-[11px] text-nd-fg-3">{sv}</span> }))}
          more={(n) => <Popover label={`+${n}`} title={`All ${x.ports.length} open services`}>{list}</Popover>}
        />
      </div>
    </div>
  )
}

function Flags({ x }: { x: Device }) {
  const all: { key: string; label: string; tone: Tone; hint: string }[] = x.flags.filter((f) => FLAG[f]).map((f) => ({
    key: f, tone: FLAG[f].tone,
    label: `${FLAG[f].label}${f === 'attacker' && x.attacks ? ` ×${x.attacks.count}` : ''}`,
    hint: f === 'attacker' && x.attacks ? `${FLAG[f].hint}: ${x.attacks.count} attack${x.attacks.count === 1 ? '' : 's'}, latest ${day(x.attacks.last)}` : FLAG[f].hint,
  }))
  if (!x.known && !x.flags.includes('new')) all.push({ key: 'unknown', label: 'Unknown', tone: 'warn', hint: 'not marked known yet' })
  if (!all.length) return <span className="text-[11.5px] text-nd-faint">—</span>
  return (
    <FitRow
      items={all.map((f) => ({ key: f.key, node: <span title={f.hint}><Badge tone={f.tone}>{f.label}</Badge></span> }))}
      more={(n) => {
        const rest = all.slice(all.length - n)
        return <span title={rest.map((f) => `${f.label}: ${f.hint}`).join('\n')} className="shrink-0 rounded bg-nd-fill px-1.5 py-0.5 text-[11px] text-nd-dim">+{n}</span>
      }}
    />
  )
}

function DeviceRow({ x, editable, onPatch, onForget }: { x: Device; editable: boolean; onPatch: (mac: string, b: Record<string, unknown>) => Promise<void>; onForget: (mac: string) => Promise<void> }) {
  const [edit, setEdit] = useState(false)
  const [name, setName] = useState(x.name ?? '')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [confirm, setConfirm] = useState(false)
  const act = async (fn: () => Promise<void>) => {
    setBusy(true); setErr('')
    try { await fn(); setEdit(false); setConfirm(false) } catch (e) { setErr(e instanceof Error ? e.message : 'could not save') }
    setBusy(false)
  }
  const iconBtn = 'grid h-7 w-7 shrink-0 place-items-center rounded-md text-nd-dim transition-colors hover:bg-nd-fill hover:text-nd-fg disabled:opacity-40'
  const Kind = kindIcon(x.kind)
  // what it is · OS · maker · its own name, skipping repeats and whatever the title already says
  const head = x.name ?? x.label ?? x.kind
  const sub = [x.name || x.label ? x.kind : null, x.os, x.vendor ?? (x.flags.includes('private-mac') ? 'private MAC (maker hidden)' : null), x.hostname && x.hostname !== head ? x.hostname : null, x.note]
    .filter((v, i, a): v is string => !!v && v !== head && a.indexOf(v) === i).join(' · ') || (x.known ? '' : 'not named yet')
  const ip4 = x.ips.filter((i) => !i.includes(':'))
  const cell = 'h-16 px-3 align-middle'
  return (
    <tr className={`border-b border-nd-line-soft last:border-0 ${!x.known ? 'bg-st-warn/[0.03]' : ''}`}>
      <td className={`${cell} pl-5`}>
        <div className="flex min-w-0 items-center gap-2.5">
          <span className="relative grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-nd-fill text-nd-muted" title={x.kind}>
            <Kind className="h-4 w-4" />
            <span className={`absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full ring-2 ring-nd-card ${x.online ? (x.reachable ? 'bg-st-good' : 'bg-st-good/60') : 'bg-nd-faint'}`}
              title={x.online ? 'online' : 'not seen now'} />
          </span>
          <div className="min-w-0 flex-1">
            {edit ? (
              <form className="flex h-6 items-center gap-1" onSubmit={(e) => { e.preventDefault(); act(() => onPatch(x.mac, { name, known: true })) }}>
                <input autoFocus value={name} onChange={(e) => setName(e.target.value)} maxLength={60} placeholder="e.g. Lucas’ laptop"
                  className={`${btn.input} h-6 min-w-0 flex-1 py-0 text-[12.5px]`} />
                <button type="submit" className={`${iconBtn} h-6 w-6`} disabled={busy} aria-label="Save name">{busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}</button>
                <button type="button" className={`${iconBtn} h-6 w-6`} onClick={() => { setEdit(false); setName(x.name ?? '') }} aria-label="Cancel"><X className="h-3.5 w-3.5" /></button>
              </form>
            ) : (
              <div className="flex h-6 min-w-0 items-center gap-1.5">
                <span className={`truncate font-medium ${x.name || x.label ? 'text-nd-fg' : 'text-nd-fg-3'}`} title={head}>{head}</span>
                {x.known && <BadgeCheck className="h-3.5 w-3.5 shrink-0 text-st-good-fg" aria-label="known" />}
              </div>
            )}
            <div className={`truncate text-[11.5px] ${err ? 'text-st-crit-fg' : 'text-nd-faint'}`} title={err || sub}>{err || sub}</div>
          </div>
        </div>
      </td>
      <td className={cell}>
        {ip4.length || x.ips.length ? (
          <div className="flex min-w-0 items-center gap-1">
            <Link href={`/analytics/ip?ip=${encodeURIComponent(ip4[0] ?? x.ips[0])}`} className="mono truncate text-[12.5px] text-nd-fg-2 hover:text-nd-fg hover:underline">{ip4[0] ?? x.ips[0]}</Link>
            {x.ips.length > 1 && <span title={x.ips.join('\n')} className="shrink-0 rounded bg-nd-fill px-1 text-[10.5px] text-nd-dim">+{x.ips.length - 1}</span>}
          </div>
        ) : (
          <div className="truncate text-[12px] text-nd-faint"
            title={x.online ? 'It never answered on this subnet: asleep, or a fixed address on another network' : 'Only the switch’s address table saw it (that table has MACs, not IPs); it left before the box looked it up'}>
            {x.online ? 'no address here' : 'no IP recorded'}
          </div>
        )}
        <div className="mono truncate text-[11px] text-nd-faint" title={`MAC ${x.mac}${x.port ? ` · ${SIDE[x.port] ?? x.port}` : ''}`}>
          {x.mac}{x.port ? ` · ${x.port === 'vlan10' ? 'WAN' : x.port === 'vlan20' ? 'LAN' : x.port}` : ''}{x.switchPort ? ` · switch port ${x.switchPort}` : ''}
        </div>
      </td>
      <td className={cell}><Services x={x} /></td>
      <td className={`${cell} whitespace-nowrap text-[12px]`} title={`first seen ${day(x.firstSeen)}${x.online ? '' : ` · last seen ${new Date(x.lastSeen).toLocaleString()}`}`}>
        <div className="truncate text-nd-fg-3">{x.online ? 'now' : ago(x.lastSeen)}</div>
        <div className="truncate text-[11px] text-nd-faint">since {new Date(x.firstSeen).toLocaleDateString([], { day: 'numeric', month: 'numeric' })}</div>
      </td>
      <td className={cell}><Flags x={x} /></td>
      {editable && (
        <td className={`${cell} pr-5`}>
          <div className="flex items-center justify-end gap-0.5">
            {confirm ? (
              <>
                <span className="mr-0.5 text-[11.5px] text-nd-dim">Forget?</span>
                <button type="button" className={iconBtn} onClick={() => act(() => onForget(x.mac))} aria-label="Yes, forget it" title="Yes, forget it"><Check className="h-3.5 w-3.5" /></button>
                <button type="button" className={iconBtn} onClick={() => setConfirm(false)} aria-label="Keep it" title="Keep it"><X className="h-3.5 w-3.5" /></button>
              </>
            ) : (
              <>
                <button type="button" className={iconBtn} onClick={() => setEdit(true)} title="Name it" aria-label="Name it"><Pencil className="h-3.5 w-3.5" /></button>
                <button type="button" className={`${iconBtn} ${x.known ? 'text-st-good-fg' : ''}`} disabled={busy} onClick={() => act(() => onPatch(x.mac, { known: !x.known }))}
                  title={x.known ? 'Known — click to mark unknown' : 'Mark known'} aria-label={x.known ? 'Mark unknown' : 'Mark known'} aria-pressed={x.known}>
                  {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <BadgeCheck className="h-3.5 w-3.5" />}
                </button>
                <button type="button" className={`${iconBtn} ${x.online ? 'invisible' : ''}`} onClick={() => setConfirm(true)} title="Forget this device" aria-label="Forget this device" disabled={x.online}>
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </>
            )}
          </div>
        </td>
      )}
    </tr>
  )
}
