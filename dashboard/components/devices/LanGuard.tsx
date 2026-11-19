'use client'
// LAN guard panel (top of the Devices page): the ARP-spoofing alarm and
// new-device approval. Approving = marking the device known (devices.edit);
// the mode (off / watch / enforce) needs devices.guard.
import { useState } from 'react'
import { ShieldAlert, ShieldCheck, UserCheck, Eye, Lock, Power, AlertTriangle, Loader2, Info } from 'lucide-react'
import { usePoll } from '@/hooks/usePoll'
import { si } from '@/lib/format'
import { Panel, Badge, btn } from '@/components/aa/kit'
import { useMe } from '@/components/aa/Shell'

type Mode = 'off' | 'watch' | 'enforce'
interface Pending { mac: string; ip: string | null; name: string | null; firstSeen: number | null; lastSeen: number | null; packets: number; dropped: number }
interface Spoof { ip: string; mac: string; first_at: number | null; last_at: number | null; frames: number; dropped: number; claimedBy: string | null; realOwner: string | null; realName: string | null; protectedAddr: boolean }
interface Data {
  settings: { nac: Mode; arpGuard: boolean; since: number }
  agentReachable: boolean; liveMode: string | null; approved: number; bindings: number
  pending: Pending[]; spoofing: Spoof[]
}

const ago = (ms: number | null) => {
  if (!ms) return '—'
  const d = Math.max(0, Date.now() - ms) / 1000
  return d < 60 ? 'just now' : d < 3600 ? `${Math.round(d / 60)} min ago` : d < 86400 ? `${Math.round(d / 3600)} h ago` : new Date(ms).toLocaleDateString([], { day: 'numeric', month: 'short' })
}
const MODES: { id: Mode; label: string; icon: typeof Eye; hint: string }[] = [
  { id: 'off', label: 'Off', icon: Power, hint: 'new devices are not tracked' },
  { id: 'watch', label: 'Watch', icon: Eye, hint: 'new devices are flagged, nothing is blocked' },
  { id: 'enforce', label: 'Enforce', icon: Lock, hint: 'new devices can only get an address and reach this box until you approve them' },
]

export function LanGuard({ onApproved }: { onApproved: () => void }) {
  const { can } = useMe()
  const [rev, setRev] = useState(0)
  const q = usePoll(async () => {
    const r = await fetch('/api/languard', { cache: 'no-store' })
    const j = await r.json()
    if (j.status !== 'success') throw new Error(j.error || 'LAN guard unavailable')
    return j as Data
  }, 10_000, [rev])
  const [busy, setBusy] = useState('')
  const [err, setErr] = useState('')
  const d = q.data
  if (!d) return null

  const setMode = async (body: Partial<{ nac: Mode; arpGuard: boolean }>) => {
    if (body.nac === 'enforce' && !window.confirm(`Enforce: ${d.pending.length} unapproved device(s) lose access to everything except getting an address and this box, until you approve them. Continue?`)) return
    setBusy('mode'); setErr('')
    const r = await fetch('/api/languard', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
    const j = await r.json().catch(() => ({}))
    if (j.status !== 'success') setErr(j.error || 'could not save')
    setBusy(''); setRev((x) => x + 1)
  }
  const approve = async (mac: string) => {
    setBusy(mac); setErr('')
    const r = await fetch('/api/devices', { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ mac, known: true }) })
    const j = await r.json().catch(() => ({}))
    if (j.status !== 'success') setErr(j.error || 'could not approve')
    setBusy(''); setRev((x) => x + 1); onApproved()
  }

  const mode = d.settings.nac
  const recentSpoof = d.spoofing.filter((s) => s.last_at && Date.now() / 1000 - s.last_at < 7 * 86400)
  const guardTone = recentSpoof.length ? 'border-st-crit/40' : ''

  return (
    <Panel icon={recentSpoof.length ? ShieldAlert : ShieldCheck} className={guardTone}
      title={<span className="flex items-center gap-2">LAN guard {recentSpoof.length ? <Badge tone="bad">spoofing seen</Badge> : <Badge tone="good">no spoofing</Badge>}</span>}
      sub={`ARP-spoofing alarm (${d.bindings} address${d.bindings === 1 ? '' : 'es'} guarded) and new-device approval · ${d.approved} device${d.approved === 1 ? '' : 's'} approved`}
      actions={
        <div className="inline-flex rounded-lg border border-nd-line p-0.5" role="group" aria-label="New devices">
          {MODES.map((m) => {
            const I = m.icon
            return (
              <button key={m.id} type="button" title={m.hint} disabled={!can('devices.guard') || busy === 'mode'} onClick={() => mode !== m.id && setMode({ nac: m.id })}
                className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[12.5px] font-medium disabled:cursor-not-allowed ${mode === m.id ? (m.id === 'enforce' ? 'bg-st-crit/15 text-st-crit-fg' : 'bg-nd-fill-2 text-nd-fg') : 'text-nd-dim hover:text-nd-fg'}`}>
                <I className="h-3.5 w-3.5" /> {m.label}
              </button>
            )
          })}
        </div>
      }>
      {err && <p className="mb-3 text-[12.5px] text-st-crit-fg">{err}</p>}

      {recentSpoof.length > 0 && (
        <div className="mb-4 space-y-2">
          {recentSpoof.map((s) => (
            <div key={`${s.ip}-${s.mac}`} className="flex items-start gap-3 rounded-xl border border-st-crit/30 bg-st-crit/[0.07] px-4 py-3">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-st-crit-fg" />
              <div className="min-w-0 text-[13px]">
                <div className="font-semibold text-nd-fg">
                  {s.claimedBy ?? s.mac} pretended to be {s.realName ?? s.ip} ({s.ip})
                </div>
                <div className="text-nd-fg-3">
                  {s.frames} fake ARP message{s.frames === 1 ? '' : 's'}, last {ago(s.last_at ? s.last_at * 1000 : null)}.{' '}
                  {s.dropped > 0 ? <>All {s.dropped} were dropped: {s.protectedAddr ? 'nobody may ever claim this address' : 'blocked'}.</> : <>Not blocked (this address is watched only). If {s.mac} is not a device you know, unplug it.</>}
                  {' '}This is how a man-in-the-middle attack starts: the device tries to make others send it their traffic.
                </div>
                <div className="mt-0.5 font-mono text-[11.5px] text-nd-faint">real owner {s.realOwner ?? 'unknown'} · impostor {s.mac}</div>
              </div>
            </div>
          ))}
        </div>
      )}

      {mode === 'off' ? (
        <p className="text-[13px] text-nd-faint">New-device approval is off. Switch to Watch to have new devices flagged here.</p>
      ) : d.pending.length === 0 ? (
        <p className="flex items-center gap-2 text-[13px] text-nd-fg-3"><UserCheck className="h-4 w-4 text-st-good-fg" /> Every device on the network is approved.</p>
      ) : (
        <>
          <div className="mb-2 text-[12px] font-medium uppercase tracking-[0.06em] text-nd-dim">Waiting for approval · {d.pending.length}</div>
          <ul className="divide-y divide-nd-line-soft">
            {d.pending.slice(0, 12).map((p) => (
              <li key={p.mac} className="flex flex-wrap items-center gap-3 py-2">
                <span className="w-32 font-mono text-[12.5px] text-nd-fg">{p.ip ?? '—'}</span>
                <span className="min-w-0 flex-1 text-[12.5px] text-nd-fg-3">{p.name ?? 'unnamed device'} <span className="font-mono text-[11.5px] text-nd-faint">{p.mac}</span></span>
                <span className="text-[12px] text-nd-faint">first seen {ago(p.firstSeen)}</span>
                {p.dropped > 0 && <Badge tone="bad">{si(p.dropped)} packets held back</Badge>}
                {can('devices.edit') && (
                  <button type="button" onClick={() => approve(p.mac)} disabled={busy === p.mac} className={`${btn.ghost} py-1 text-[12px]`}>
                    {busy === p.mac ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <UserCheck className="h-3.5 w-3.5" />} Approve
                  </button>
                )}
              </li>
            ))}
          </ul>
          {d.pending.length > 12 && <p className="mt-1 text-[12px] text-nd-faint">…and {d.pending.length - 12} more: filter the list below on “unknown”.</p>}
        </>
      )}
      <p className="mt-3 flex gap-1.5 text-[11.5px] leading-relaxed text-nd-faint">
        <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        {mode === 'enforce'
          ? 'Enforce: traffic from unapproved devices that passes through the firewall is dropped (they can still get an address and reach this box). Devices on the same switch can still talk to each other directly: the firewall only sees traffic that crosses it.'
          : 'Watch: new devices are listed here; nothing is blocked. Approving one marks it known. Switch to Enforce to hold back unapproved devices.'}
        {!d.agentReachable && ' · The firewall agent is not answering, so live data is missing.'}
      </p>
    </Panel>
  )
}
