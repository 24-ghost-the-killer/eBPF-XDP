'use client'
// Attacker profiles: who attacks you, from the permanent attack archive.
// Per network (ASN), country and address: how many attacks they took part in,
// first and last seen, what kind, and a 30-day activity strip. Repeat
// offenders are flagged. Click one for its full profile.
import { useMemo, useState } from 'react'
import { Crosshair, Repeat, Globe2, Network, MapPin, X, ArrowRight } from 'lucide-react'
import { usePoll } from '@/hooks/usePoll'
import { si, pretty } from '@/lib/format'
import { flagOf } from '@/lib/country-centroids'
import type { Episode } from '@/lib/attacks'
import { Panel, Badge, Empty, Segmented } from '@/components/aa/kit'

type By = 'network' | 'country' | 'address'
interface Profile {
  key: string; label: string; sub: string; cc?: string
  attacks: Map<number, Episode>; packets: number; first: number; last: number
  ips: Map<string, number>; types: Map<string, number>; days: Set<string>; countries: Set<string>
}
const day = (ms: number) => new Date(ms).toISOString().slice(0, 10)
const when = (ms: number) => new Date(ms).toLocaleDateString([], { day: 'numeric', month: 'short', year: '2-digit' })

// a flood with hundreds of different senders almost always has forged (random)
// source addresses: those say nothing about who really attacked
const SPOOFED = 300
function build(attacks: Episode[], by: By, spoofed: boolean): Profile[] {
  const m = new Map<string, Profile>()
  for (const a of attacks) {
    if (a.mark || (!spoofed && (a.uniqueSources ?? 0) >= SPOOFED)) continue
    for (const x of a.attackers ?? []) {
      if (x.scope === 'lan' && by !== 'address') continue // LAN sources only make sense per address
      const key = by === 'network' ? (x.asn ? `AS${x.asn}` : x.org ?? '') : by === 'country' ? x.cc ?? '' : x.ip
      if (!key) continue
      const label = by === 'network' ? x.org ?? `AS${x.asn}` : by === 'country' ? x.country ?? x.cc ?? key : x.ip
      const sub = by === 'network' ? (x.asn ? `AS${x.asn}` : 'no AS number') : by === 'country' ? '' : [x.org, x.country].filter(Boolean).join(' · ') || x.scope || ''
      const p = m.get(key) ?? { key, label, sub, cc: x.cc, attacks: new Map(), packets: 0, first: a.start, last: a.end, ips: new Map(), types: new Map(), days: new Set(), countries: new Set() }
      p.attacks.set(a.id, a)
      p.packets += x.packets || 0
      p.first = Math.min(p.first, a.start)
      p.last = Math.max(p.last, a.end)
      p.ips.set(x.ip, (p.ips.get(x.ip) ?? 0) + (x.packets || 0))
      if (x.cc) p.countries.add(x.cc)
      p.days.add(day(a.start))
      m.set(key, p)
    }
  }
  for (const p of m.values()) {
    for (const a of p.attacks.values()) for (const v of a.vectors.length ? a.vectors : ['unknown']) p.types.set(v, (p.types.get(v) ?? 0) + 1)
  }
  return [...m.values()].sort((x, y) => y.attacks.size - x.attacks.size || y.packets - x.packets)
}

export default function AttackersPage() {
  const q = usePoll(async () => {
    const r = await fetch('/api/attacks', { cache: 'no-store' })
    const j = await r.json()
    if (j.status !== 'success') throw new Error(j.error || 'could not load attacks')
    return j.attacks as Episode[]
  }, 120_000)
  const [by, setBy] = useState<By>('network')
  const [sel, setSel] = useState<string | null>(null)
  const [spoofed, setSpoofed] = useState(false)
  const list = useMemo(() => build(q.data ?? [], by, spoofed), [q.data, by, spoofed])
  if (!q.data) return q.error ? <Empty icon={Crosshair} title="Couldn’t load the attack history" hint={q.error} /> : <div className="aa-skeleton h-64 rounded-2xl" />
  const repeat = list.filter((p) => p.attacks.size >= 3 || p.days.size >= 3)
  const cur = list.find((p) => p.key === sel) ?? null
  const real = q.data.filter((a) => !a.mark)
  const forged = real.filter((a) => (a.uniqueSources ?? 0) >= SPOOFED).length

  return (
    <div className="space-y-6">
      <section className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Big label="Attacks analysed" value={String(real.length)} sub={forged ? `${forged} with forged senders ${spoofed ? 'included' : 'left out'}` : undefined} />
        <Big label={by === 'network' ? 'Networks' : by === 'country' ? 'Countries' : 'Addresses'} value={String(list.length)} />
        <Big label="Repeat offenders" value={String(repeat.length)} sub="3+ attacks or 3+ different days" tone={repeat.length ? 'bad' : undefined} />
        <Big label="Worst" value={list[0]?.label ?? '—'} sub={list[0] ? `${list[0].attacks.size} attacks` : ''} small />
      </section>

      <div className={`grid grid-cols-1 gap-6 ${cur ? 'xl:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]' : ''}`}>
        <Panel icon={Crosshair} title="Who attacks you" sub={<span>From every analysed attack (top 25 sources each); false alarms left out. <label className="ml-1 inline-flex cursor-pointer items-center gap-1"><input type="checkbox" checked={spoofed} onChange={(e) => setSpoofed(e.target.checked)} className="accent-current" /> include floods with forged senders ({SPOOFED}+ different addresses)</label></span>}
          actions={<Segmented<By> label="Group by" value={by} onChange={(v) => { setBy(v); setSel(null) }} options={[{ id: 'network', label: 'Networks' }, { id: 'country', label: 'Countries' }, { id: 'address', label: 'Addresses' }]} size="sm" />}
          bodyClass="">
          <div className="max-h-[640px] overflow-auto">
            <table className="w-full min-w-[640px] text-left text-[13px]">
              <thead className="sticky top-0 bg-nd-card text-[11px] uppercase tracking-[0.06em] text-nd-dim">
                <tr className="border-b border-nd-line">{['', 'Attacks', 'Last 30 days', 'Seen', 'Kind'].map((h) => <th key={h} className="px-4 py-2 font-medium">{h}</th>)}</tr>
              </thead>
              <tbody className="divide-y divide-nd-line-soft">
                {list.slice(0, 200).map((p) => (
                  <tr key={p.key} onClick={() => setSel(p.key === sel ? null : p.key)} className={`cursor-pointer ${p.key === sel ? 'bg-nd-fill' : 'hover:bg-nd-fill/60'}`}>
                    <td className="px-4 py-2">
                      <div className="flex items-center gap-2 font-medium text-nd-fg">
                        {p.cc && by !== 'address' && <span>{flagOf(p.cc)}</span>}
                        <span className={by === 'address' ? 'font-mono text-[12.5px]' : 'truncate'}>{p.label}</span>
                        {(p.attacks.size >= 3 || p.days.size >= 3) && <Badge tone="bad" icon={Repeat}>repeat</Badge>}
                      </div>
                      {p.sub && <div className="truncate text-[11.5px] text-nd-faint">{p.sub}</div>}
                    </td>
                    <td className="px-4 py-2 font-semibold tabular-nums text-nd-fg">{p.attacks.size}</td>
                    <td className="px-4 py-2"><Strip days={p.days} /></td>
                    <td className="px-4 py-2 text-[12px] text-nd-dim">{when(p.first)}{p.last - p.first > 86400e3 ? ` → ${when(p.last)}` : ''}</td>
                    <td className="max-w-[200px] truncate px-4 py-2 text-[12px] text-nd-fg-3">{[...p.types.entries()].sort((a, b) => b[1] - a[1]).slice(0, 2).map(([t]) => pretty(t)).join(', ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>

        {cur && <ProfileCard p={cur} by={by} onClose={() => setSel(null)} />}
      </div>
    </div>
  )
}

function ProfileCard({ p, by, onClose }: { p: Profile; by: By; onClose: () => void }) {
  const attacks = [...p.attacks.values()].sort((a, b) => b.start - a.start)
  const ips = [...p.ips.entries()].sort((a, b) => b[1] - a[1])
  const I = by === 'network' ? Network : by === 'country' ? Globe2 : MapPin
  return (
    <Panel icon={I} title={<span className="flex items-center gap-2">{p.cc && by !== 'address' && flagOf(p.cc)} {p.label}</span>} sub={p.sub || undefined}
      actions={<button type="button" onClick={onClose} className="rounded-md p-1 text-nd-dim hover:bg-nd-fill hover:text-nd-fg" aria-label="Close"><X className="h-4 w-4" /></button>}>
      <div className="grid grid-cols-3 gap-3">
        <Mini label="Attacks" value={String(p.attacks.size)} />
        <Mini label="Different days" value={String(p.days.size)} />
        <Mini label="Packets dropped" value={si(p.packets)} />
      </div>
      <p className="mt-3 text-[13px] text-nd-fg-3">
        First seen <b className="text-nd-fg">{when(p.first)}</b>, last <b className="text-nd-fg">{when(p.last)}</b>.{' '}
        {p.attacks.size >= 3 || p.days.size >= 3 ? 'A repeat offender: it keeps coming back.' : p.attacks.size === 1 ? 'Seen in one attack only.' : 'Seen more than once.'}
        {by !== 'address' && ` ${ips.length} address${ips.length === 1 ? '' : 'es'} used.`}
      </p>
      <div className="mt-3"><div className="mb-1 text-[11px] font-medium uppercase tracking-[0.06em] text-nd-dim">Last 30 days</div><Strip days={p.days} big /></div>
      <div className="mt-4 flex flex-wrap gap-1.5">
        {[...p.types.entries()].sort((a, b) => b[1] - a[1]).map(([t, n]) => <Badge key={t}>{pretty(t)} ×{n}</Badge>)}
      </div>
      {by !== 'address' && (
        <div className="mt-4">
          <div className="mb-1 text-[11px] font-medium uppercase tracking-[0.06em] text-nd-dim">Busiest addresses</div>
          <ul className="space-y-0.5 text-[12.5px]">
            {ips.slice(0, 8).map(([ip, n]) => (
              <li key={ip} className="flex justify-between gap-3"><a href={`/analytics/ip?ip=${encodeURIComponent(ip)}`} className="font-mono text-nd-fg hover:underline">{ip}</a><span className="tabular-nums text-nd-faint">{si(n)} packets</span></li>
            ))}
          </ul>
        </div>
      )}
      <div className="mt-4">
        <div className="mb-1 text-[11px] font-medium uppercase tracking-[0.06em] text-nd-dim">Its attacks</div>
        <ul className="max-h-[260px] space-y-0.5 overflow-auto text-[12.5px]">
          {attacks.map((a) => (
            <li key={a.id}>
              <a href={`/analytics/attacks?attack=${a.id}`} className="flex items-center justify-between gap-3 rounded-md px-1.5 py-1 hover:bg-nd-fill">
                <span className="text-nd-fg">{new Date(a.start).toLocaleString([], { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })}</span>
                <span className="min-w-0 flex-1 truncate text-nd-fg-3">{(a.vectors.length ? a.vectors : ['attack']).map(pretty).join(', ')}</span>
                <span className="tabular-nums text-nd-faint">{Math.round(a.dropShare * 100)}% blocked</span>
                <ArrowRight className="h-3.5 w-3.5 text-nd-faint" />
              </a>
            </li>
          ))}
        </ul>
      </div>
    </Panel>
  )
}

// 30 small squares, one per day, lit when the attacker was active that day
function Strip({ days, big }: { days: Set<string>; big?: boolean }) {
  const cells = Array.from({ length: 30 }, (_, i) => day(Date.now() - (29 - i) * 86400e3))
  return (
    <div className="flex gap-[2px]" aria-label={`active on ${cells.filter((c) => days.has(c)).length} of the last 30 days`}>
      {cells.map((c) => <span key={c} title={c} className={`${big ? 'h-5 flex-1' : 'h-3 w-1.5'} rounded-[2px] ${days.has(c) ? 'bg-st-crit' : 'bg-nd-fill-2'}`} />)}
    </div>
  )
}

function Big({ label, value, sub, tone, small }: { label: string; value: string; sub?: string; tone?: 'bad'; small?: boolean }) {
  return (
    <div className="rounded-2xl border border-nd-line bg-nd-card px-5 py-4 shadow-nd">
      <div className="text-[11px] font-medium uppercase tracking-[0.06em] text-nd-dim">{label}</div>
      <div className={`mt-1 truncate font-semibold tabular-nums ${small ? 'text-[18px]' : 'text-[26px]'} ${tone === 'bad' ? 'text-st-crit-fg' : 'text-nd-fg'}`}>{value}</div>
      {sub && <div className="truncate text-[12px] text-nd-faint">{sub}</div>}
    </div>
  )
}

function Mini({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-nd-line bg-nd-panel px-3 py-2">
      <div className="text-[10.5px] font-medium uppercase tracking-[0.06em] text-nd-dim">{label}</div>
      <div className="text-[18px] font-semibold tabular-nums text-nd-fg">{value}</div>
    </div>
  )
}
