'use client'
// Honeypot: unused LAN addresses the firewall pretends to own. Nothing
// legitimate knows them, so any device that talks to one is scanning the
// network or infected. Each address can also block a device that probes it.
import { useEffect, useState } from 'react'
import { Bug, Plus, Trash2, Loader2, ShieldAlert, ShieldOff, Radar, AlertTriangle, Info, RotateCcw, Save, KeyRound, Terminal } from 'lucide-react'
import { usePoll } from '@/hooks/usePoll'
import { si } from '@/lib/format'
import { Panel, Badge, Empty, btn } from '@/components/aa/kit'
import { useMe } from '@/components/aa/Shell'

interface Wanted { ip: string; block: boolean; interactive?: boolean; note?: string; addedBy?: string; addedAt?: number }
interface Attempt { at: number; service: 'ssh' | 'telnet' | 'web'; src: string; decoy: string; username?: string; password?: string | null; client?: string; agent?: string; path?: string; note?: string; device: string | null }
interface LiveAddr { ip: string; mac: string; block: boolean; conflict_at: number | null }
interface Source {
  ip: string; mac: string; first_at: number | null; last_at: number | null; packets: number; arps: number
  last_dst: string; last_dport: number; last_proto: number; blocked: boolean; device: string | null
}
interface Data {
  wanted: { addresses: Wanted[]; updatedAt?: number; updatedBy?: string }
  live: { active: number; interfaces: string[]; addresses: LiveAddr[]; sources: Source[] } | null
  agentReachable: boolean; lan: { net: string; self: string; gateway: string | null } | null
  suggestions: string[]; max: number
  attempts: Attempt[]; passwordsShown: boolean
}

const PROTO: Record<number, string> = { 1: 'ping', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6' }
const PORT: Record<number, string> = { 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 135: 'RPC', 139: 'NetBIOS', 443: 'HTTPS', 445: 'SMB', 3389: 'RDP', 5900: 'VNC', 8006: 'Proxmox', 8080: 'HTTP', 8443: 'HTTPS' }
const ago = (s: number | null) => {
  if (!s) return '—'
  const d = Math.max(0, Date.now() / 1000 - s)
  return d < 60 ? `${Math.round(d)} s ago` : d < 3600 ? `${Math.round(d / 60)} min ago` : d < 86400 ? `${Math.round(d / 3600)} h ago` : new Date(s * 1000).toLocaleDateString([], { day: 'numeric', month: 'short' })
}
const what = (s: Source) => {
  if (!s.packets) return 'asked where it is (ARP) — looked, did not knock yet'
  const p = PROTO[s.last_proto] ?? `protocol ${s.last_proto}`
  if (!s.last_dport) return `${p} to ${s.last_dst}`
  return `${p} port ${s.last_dport}${PORT[s.last_dport] ? ` (${PORT[s.last_dport]})` : ''} on ${s.last_dst}`
}

export default function HoneypotPage() {
  const { can } = useMe()
  const q = usePoll(async () => {
    const r = await fetch('/api/honeypot', { cache: 'no-store' })
    const j = await r.json()
    if (j.status !== 'success') throw new Error(j.error || 'honeypot unavailable')
    return j as Data
  }, 5000)
  const d = q.data
  const [list, setList] = useState<Wanted[] | null>(null)
  const [add, setAdd] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [saved, setSaved] = useState(false)
  useEffect(() => { if (d && list === null) setList(d.wanted.addresses) }, [d, list])

  if (!d || !list) return q.error ? <Empty icon={Bug} title="The honeypot is unavailable" hint={q.error} /> : <div className="aa-skeleton h-64 rounded-2xl" />
  const edit = can('honeypot.edit')
  const dirty = JSON.stringify(list.map((a) => [a.ip, a.block, !!a.interactive])) !== JSON.stringify(d.wanted.addresses.map((a) => [a.ip, a.block, !!a.interactive]))
  const liveBy = new Map((d.live?.addresses ?? []).map((a) => [a.ip, a]))
  const sources = d.live?.sources ?? []
  const probing = sources.filter((s) => s.packets > 0)

  const save = async () => {
    setBusy(true); setErr(''); setSaved(false)
    try {
      const r = await fetch('/api/honeypot', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ addresses: list }) })
      const j = await r.json()
      if (j.status !== 'success') throw new Error(j.error || 'could not save')
      setList(j.wanted.addresses); setSaved(true)
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'could not save')
    }
    setBusy(false)
  }
  const reset = async (ip: string) => {
    setErr('')
    const r = await fetch('/api/honeypot', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ reset: ip }) })
    const j = await r.json().catch(() => ({}))
    if (j.status !== 'success') setErr(j.error || 'could not re-arm')
  }
  const addIp = (ip: string) => {
    const v = ip.trim()
    if (!v || list.some((a) => a.ip === v)) return
    setList([...list, { ip: v, block: true }]); setAdd(''); setSaved(false)
  }

  return (
    <div className="space-y-6">
      <section className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <Big label="Decoy addresses" value={String(d.live?.active ?? 0)} sub={d.agentReachable ? `armed on ${(d.live?.interfaces ?? []).join(', ') || '—'}` : 'agent not reachable'} />
        <Big label="Devices that looked" value={String(sources.length)} sub="asked for a decoy or knocked on it" tone={sources.length ? 'warn' : undefined} />
        <Big label="Devices that knocked" value={String(probing.length)} sub={`${probing.filter((s) => s.blocked).length} blocked from the LAN`} tone={probing.length ? 'bad' : undefined} />
      </section>

      <Panel icon={Radar} title="Who touched a decoy" sub="Nothing legitimate knows these addresses: a device here is scanning the network or infected. Newest first." bodyClass="">
        {sources.length === 0 ? (
          <p className="px-5 pb-5 text-[13px] text-nd-faint">{d.live?.active ? 'Nobody yet. Try it: scan your network (e.g. nmap -sn ' + (d.lan?.net ?? '192.168.1.0/24') + ') and the scanner appears here within seconds.' : 'Add a decoy address below to start.'}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] text-left text-[13px]">
              <thead className="text-[11px] uppercase tracking-[0.06em] text-nd-dim">
                <tr className="border-b border-nd-line">{['Device', 'What it did', 'Packets', 'First', 'Last', ''].map((h) => <th key={h} className="px-5 py-2 font-medium">{h}</th>)}</tr>
              </thead>
              <tbody className="divide-y divide-nd-line-soft">
                {sources.map((s) => (
                  <tr key={s.ip}>
                    <td className="px-5 py-2.5">
                      <a href={`/analytics/ip?ip=${encodeURIComponent(s.ip)}`} className="font-mono text-[12.5px] font-medium text-nd-fg hover:underline">{s.ip}</a>
                      <div className="text-[11.5px] text-nd-faint">{s.device ?? 'unnamed device'} · {s.mac}</div>
                    </td>
                    <td className="px-5 py-2.5 text-nd-fg-3">{what(s)}</td>
                    <td className="px-5 py-2.5 tabular-nums text-nd-fg-3">{si(s.packets)}{s.arps ? <span className="block text-[11px] text-nd-faint">{s.arps} ARP</span> : null}</td>
                    <td className="px-5 py-2.5 text-nd-dim">{ago(s.first_at)}</td>
                    <td className="px-5 py-2.5 text-nd-dim">{ago(s.last_at)}</td>
                    <td className="px-5 py-2.5">{s.blocked ? <Badge tone="bad" icon={ShieldAlert}>blocked from LAN</Badge> : s.packets ? <Badge tone="warn">recorded</Badge> : <Badge>looked</Badge>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Attempts list={d.attempts} shown={d.passwordsShown} anyInteractive={list.some((a) => a.interactive)} />

      <Panel icon={Bug} title="Decoy addresses" sub={d.lan ? `Free addresses in ${d.lan.net}. The firewall answers for them, records who knocks, and drops everything sent to them.` : 'Free LAN addresses the firewall answers for'}
        actions={edit && dirty ? <button type="button" onClick={save} disabled={busy} className={btn.primary}>{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />} Save & arm</button> : saved ? <span className="text-[12px] text-st-good-fg">Saved: armed within a few seconds</span> : null}>
        {list.length === 0 && <p className="mb-3 text-[13px] text-nd-faint">No decoys yet.</p>}
        <ul className="divide-y divide-nd-line-soft">
          {list.map((a) => {
            const l = liveBy.get(a.ip)
            return (
              <li key={a.ip} className="flex flex-wrap items-center gap-3 py-2.5">
                <span className="w-32 font-mono text-[13px] font-medium text-nd-fg">{a.ip}</span>
                {l?.conflict_at ? <Badge tone="warn" icon={AlertTriangle}>stood down: a real device used it</Badge>
                  : l ? <Badge tone="good">armed</Badge> : <Badge>{dirty ? 'not saved' : 'arming…'}</Badge>}
                <label className="ml-auto flex items-center gap-1.5 text-[12.5px] text-nd-fg-3" title="The box takes the address and shows fake SSH, telnet and web logins on it: every username and password tried is recorded">
                  <input type="checkbox" checked={!!a.interactive} disabled={!edit} onChange={(e) => { setList(list.map((x) => (x.ip === a.ip ? { ...x, interactive: e.target.checked } : x))); setSaved(false) }} className="accent-current" />
                  <KeyRound className="h-3.5 w-3.5" /> Fake login
                </label>
                <label className="flex items-center gap-1.5 text-[12.5px] text-nd-fg-3">
                  <input type="checkbox" checked={a.block} disabled={!edit} onChange={(e) => { setList(list.map((x) => (x.ip === a.ip ? { ...x, block: e.target.checked } : x))); setSaved(false) }} className="accent-current" />
                  {a.block ? <ShieldAlert className="h-3.5 w-3.5" /> : <ShieldOff className="h-3.5 w-3.5" />} Block devices that knock
                </label>
                {edit && l?.conflict_at && <button type="button" onClick={() => reset(a.ip)} className={`${btn.ghost} py-1 text-[12px]`}><RotateCcw className="h-3.5 w-3.5" /> Re-arm</button>}
                {edit && <button type="button" onClick={() => { setList(list.filter((x) => x.ip !== a.ip)); setSaved(false) }} className={`${btn.ghost} py-1 text-[12px]`} aria-label={`Remove ${a.ip}`}><Trash2 className="h-3.5 w-3.5" /></button>}
              </li>
            )
          })}
        </ul>
        {edit && list.length < d.max && (
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <input value={add} onChange={(e) => setAdd(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && addIp(add)} placeholder="e.g. 192.168.1.240" className={`${btn.input} w-44 py-1.5 font-mono`} />
            <button type="button" onClick={() => addIp(add)} className={btn.ghost}><Plus className="h-4 w-4" /> Add</button>
            {d.suggestions.length > 0 && <span className="text-[12px] text-nd-faint">Free:</span>}
            {d.suggestions.filter((s) => !list.some((a) => a.ip === s)).map((s) => (
              <button key={s} type="button" onClick={() => addIp(s)} className="rounded-md border border-nd-line px-2 py-0.5 font-mono text-[12px] text-nd-fg-3 hover:border-nd-line-strong hover:text-nd-fg">{s}</button>
            ))}
          </div>
        )}
        {err && <p className="mt-2 text-[12px] text-st-crit-fg">{err}</p>}
        <div className="mt-4 space-y-1.5 text-[11.5px] leading-relaxed text-nd-faint">
          <p className="flex gap-1.5"><Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />Pick addresses outside the router’s DHCP range. If a real device ever gets one, the firewall notices and stops answering for it at once, so nothing breaks.</p>
          <p className="flex gap-1.5"><Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />“Fake login”: the box takes the address itself and shows a fake SSH, telnet and web login there. Nobody can get in: every username and password tried is recorded below. The box’s real services never show through a decoy.</p>
          <p className="flex gap-1.5"><Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />“Block” cuts a device that knocks (TCP/UDP) off from the rest of the LAN for 10 minutes. It can still reach the internet and this box. A ping alone never blocks.</p>
          {!d.agentReachable && <p className="flex gap-1.5 text-st-warn-fg"><AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />The firewall agent is not answering, so live data is missing.</p>}
        </div>
      </Panel>
    </div>
  )
}

const SVC: Record<string, string> = { ssh: 'SSH', telnet: 'Telnet', web: 'Web' }
function Attempts({ list, shown, anyInteractive }: { list: Attempt[]; shown: boolean; anyInteractive: boolean }) {
  const tries = list.filter((a) => a.username != null)
  const top = (k: 'username' | 'password') => {
    const m = new Map<string, number>()
    for (const a of tries) { const v = a[k]; if (v) m.set(v, (m.get(v) ?? 0) + 1) }
    return [...m.entries()].sort((x, y) => y[1] - x[1]).slice(0, 6)
  }
  if (!anyInteractive && list.length === 0) return null
  return (
    <Panel icon={KeyRound} title="Logins tried on the fake logins" sub={`Every username and password an intruder typed into a decoy’s fake SSH, telnet or web login${shown ? '' : ' (passwords hidden: your group may not see them)'}`} bodyClass="">
      {list.length === 0 ? (
        <p className="px-5 pb-5 text-[13px] text-nd-faint">None yet. Try it from another device: <code className="rounded bg-nd-fill px-1">ssh admin@&lt;decoy&gt;</code> or open the decoy in a browser.</p>
      ) : (
        <>
          {tries.length > 0 && (
            <div className="grid grid-cols-1 gap-4 px-5 pb-4 sm:grid-cols-2">
              {(['username', 'password'] as const).map((k) => (
                <div key={k}>
                  <div className="mb-1.5 text-[11px] font-medium uppercase tracking-[0.06em] text-nd-dim">Most tried {k}s</div>
                  <div className="flex flex-wrap gap-1.5">
                    {top(k).map(([v, n]) => <span key={v} className="rounded-md bg-nd-fill px-2 py-0.5 font-mono text-[12px] text-nd-fg-3">{v} <span className="text-nd-faint">×{n}</span></span>)}
                  </div>
                </div>
              ))}
            </div>
          )}
          <div className="max-h-[360px] overflow-auto">
            <table className="w-full min-w-[720px] text-left text-[12.5px]">
              <thead className="sticky top-0 bg-nd-card text-[11px] uppercase tracking-[0.06em] text-nd-dim">
                <tr className="border-b border-nd-line">{['When', 'From', 'Login', 'Username', 'Password', 'Client'].map((h) => <th key={h} className="px-5 py-2 font-medium">{h}</th>)}</tr>
              </thead>
              <tbody className="divide-y divide-nd-line-soft">
                {list.slice(0, 100).map((a, i) => (
                  <tr key={i}>
                    <td className="px-5 py-1.5 text-nd-dim">{ago(a.at)}</td>
                    <td className="px-5 py-1.5"><span className="font-mono text-nd-fg">{a.src}</span>{a.device && <span className="ml-1 text-nd-faint">{a.device}</span>}</td>
                    <td className="px-5 py-1.5"><span className="inline-flex items-center gap-1 text-nd-fg-3"><Terminal className="h-3 w-3" />{SVC[a.service] ?? a.service} on {a.decoy}</span></td>
                    <td className="px-5 py-1.5 font-mono text-nd-fg">{a.username ?? <span className="text-nd-faint">{a.path ? `GET ${a.path}` : a.note ?? 'connected'}</span>}</td>
                    <td className="px-5 py-1.5 font-mono text-nd-fg-3">{a.password ?? '—'}</td>
                    <td className="max-w-[220px] truncate px-5 py-1.5 text-nd-faint" title={a.client ?? a.agent}>{a.client ?? a.agent ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </Panel>
  )
}

function Big({ label, value, sub, tone }: { label: string; value: string; sub: string; tone?: 'warn' | 'bad' }) {
  const ink = tone === 'bad' ? 'text-st-crit-fg' : tone === 'warn' ? 'text-st-warn-fg' : 'text-nd-fg'
  return (
    <div className="rounded-2xl border border-nd-line bg-nd-card px-5 py-4 shadow-nd">
      <div className="text-[11px] font-medium uppercase tracking-[0.06em] text-nd-dim">{label}</div>
      <div className={`mt-1 text-[28px] font-semibold tabular-nums ${ink}`}>{value}</div>
      <div className="text-[12px] text-nd-faint">{sub}</div>
    </div>
  )
}
