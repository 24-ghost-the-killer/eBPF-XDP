'use client'
import { Suspense, useEffect, useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { instantAt, rangeAbs, toSeries, scalar, type InstantResult } from '@/lib/prom'
import { usePoll } from '@/hooks/usePoll'
import { fetchAttacks, vectorsOf } from '@/lib/attacks'
import { bps, pps, duration, si, pretty } from '@/lib/format'
import { SERIES } from '@/components/nd/ui'
import { Panel, Stat, Badge, Empty, btn, type Tone } from '@/components/aa/kit'
import { Fingerprint, Search, Upload, Download, Ban, Crosshair, ShieldAlert, Users, Target, Send, ChevronRight, Activity } from 'lucide-react'
import { TimeChart } from '@/components/nd/charts'
import { useRange } from '@/components/aa/Shell'

// IP lookup: everything the appliance knows about one address over the shared
// window — bytes it sent/received (talker tap), packets dropped with it as the
// attack source or as the victim, and the episodes it appeared in.

// Only IP characters reach PromQL, so the label matcher can't be broken out of.
const IP_RE = /^[0-9a-fA-F:.]{2,45}$/
// Counter delta over the window that keeps series born inside it.
const delta = (sel: string, R: string) => `clamp_min((sum(${sel}) - sum(${sel} offset ${R})) or sum(${sel}), 0)`

function Picker({ onPick }: { onPick: (ip: string) => void }) {
  const rng = useRange()
  const top = usePoll(async () => {
    const w = rng.resolve()
    const R = `${w.span}s`
    const tops = (m: string, l: string) =>
      instantAt(`topk(6, clamp_min((sum by(${l})(${m}) - sum by(${l})(${m} offset ${R})) or sum by(${l})(${m}), 0) > 0)`, w.end)
    const [att, vic, tx] = await Promise.all([
      tops('xs_attacker_packets_total', 'src'),
      tops('xs_target_packets_total', 'dst'),
      instantAt(`topk(6, sum by(ip)(increase(xs_talker_tx_bytes_total[${R}])) > 0)`, w.end),
    ])
    const rows = (r: InstantResult[], k: string) => r.map((s) => ({ ip: s.metric[k], v: parseFloat(s.value[1]) })).sort((a, b) => b.v - a.v)
    return { att: rows(att, 'src'), vic: rows(vic, 'dst'), tx: rows(tx, 'ip') }
  }, rng.refreshMs, [rng.key])
  const List = ({ title, icon, rows, fmt }: { title: string; icon: typeof Users; rows: { ip: string; v: number }[]; fmt: (n: number) => string }) => (
    <Panel icon={icon} title={title} sub={rng.label} bodyClass="px-3 pb-3">
      {!top.data ? (
        <div className="space-y-1.5 px-2">{[0, 1, 2, 3].map((i) => <div key={i} className="aa-skeleton h-8 rounded-lg" />)}</div>
      ) : rows.length ? (
        <ul className="space-y-0.5">
          {rows.map((r, i) => (
            <li key={r.ip}>
              <button onClick={() => onPick(r.ip)} className="group flex w-full items-center gap-3 rounded-lg px-2 py-2 text-left text-[13px] transition-colors hover:bg-nd-fill">
                <span className="w-4 text-right text-[11.5px] text-nd-faint">{i + 1}</span>
                <span className="mono flex-1 truncate text-nd-fg-2">{r.ip}</span>
                <span className="mono text-[12px] text-nd-dim">{fmt(r.v)}</span>
                <ChevronRight className="h-3.5 w-3.5 text-nd-faint opacity-0 transition-opacity group-hover:opacity-100" />
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <Empty icon={icon} title="None in this window" className="py-6" />
      )}
    </Panel>
  )
  return (
    <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
      <List title="Top attack sources" icon={ShieldAlert} rows={top.data?.att ?? []} fmt={(n) => `${si(n)} pkts`} />
      <List title="Most targeted hosts" icon={Target} rows={top.data?.vic ?? []} fmt={(n) => `${si(n)} pkts`} />
      <List title="Top senders" icon={Send} rows={top.data?.tx ?? []} fmt={(n) => si(n, 'B')} />
    </div>
  )
}

function Report({ ip }: { ip: string }) {
  const rng = useRange()
  const hist = usePoll(fetchAttacks, 120_000)
  const q = usePoll(async () => {
    const w = rng.resolve()
    const R = `${w.span}s`
    const [tx, rx, att, vic, txT, rxT, attT, vicT, scope] = await Promise.all([
      rangeAbs(`sum(rate(xs_talker_tx_bytes_total{ip="${ip}"}[${w.rw}]))*8`, w.start, w.end, w.step),
      rangeAbs(`sum(rate(xs_talker_rx_bytes_total{ip="${ip}"}[${w.rw}]))*8`, w.start, w.end, w.step),
      rangeAbs(`sum(rate(xs_attacker_packets_total{src="${ip}"}[${w.rw}]))`, w.start, w.end, w.step),
      rangeAbs(`sum(rate(xs_target_packets_total{dst="${ip}"}[${w.rw}]))`, w.start, w.end, w.step),
      instantAt(`sum(increase(xs_talker_tx_bytes_total{ip="${ip}"}[${R}]))`, w.end),
      instantAt(`sum(increase(xs_talker_rx_bytes_total{ip="${ip}"}[${R}]))`, w.end),
      instantAt(delta(`xs_attacker_packets_total{src="${ip}"}`, R), w.end),
      instantAt(delta(`xs_target_packets_total{dst="${ip}"}`, R), w.end),
      instantAt(`max by(scope)(xs_talker_tx_bytes_total{ip="${ip}"} or xs_talker_rx_bytes_total{ip="${ip}"})`, w.end),
    ])
    return {
      bw: toSeries([...tx.map((s) => ({ metric: { k: 'sent' }, values: s.values })), ...rx.map((s) => ({ metric: { k: 'received' }, values: s.values }))], (m) => m.k),
      drops: toSeries([...att.map((s) => ({ metric: { k: 'as_source' }, values: s.values })), ...vic.map((s) => ({ metric: { k: 'as_target' }, values: s.values }))], (m) => m.k),
      txT: scalar(txT, 0)!, rxT: scalar(rxT, 0)!, attT: scalar(attT, 0)!, vicT: scalar(vicT, 0)!,
      scope: scope[0]?.metric.scope ?? null,
      span: w.span,
    }
  }, rng.refreshMs, [ip, rng.key])
  const d = q.data
  const episodes = (hist.data?.attacks ?? []).filter((a) => a.attackers.some((x) => x.ip === ip) || a.victims.some((x) => x.ip === ip))
  const role: Tone | null = !d ? null : d.attT > 0 ? 'bad' : d.vicT > 0 ? 'warn' : d.txT + d.rxT > 0 ? 'good' : 'neutral'
  const roleLabel = !d ? '' : d.attT > 0 ? 'Attack source' : d.vicT > 0 ? 'Attack target' : d.txT + d.rxT > 0 ? 'Normal talker' : 'No activity seen'
  const spanMs = (d?.span ?? 3600) * 1000

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <span className="grid h-11 w-11 place-items-center rounded-xl bg-nd-fill text-nd-muted"><Fingerprint className="h-5 w-5" /></span>
        <div>
          <h2 className="mono text-[22px] font-semibold tracking-[-0.01em] text-nd-fg">{ip}</h2>
          <div className="mt-1 flex flex-wrap gap-1.5">
            {role ? <Badge tone={role}>{roleLabel}</Badge> : <div className="aa-skeleton h-5 w-24 rounded-full" />}
            {d?.scope && <Badge>{d.scope}</Badge>}
            {episodes.length > 0 && <Badge tone="warn">{episodes.length} episode{episodes.length === 1 ? '' : 's'}</Badge>}
          </div>
        </div>
      </div>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Sent" icon={Upload} loading={!d} value={si(d?.txT, 'B')} sub={d ? `avg ${bps((d.txT * 8) / d.span)}` : undefined} />
        <Stat label="Received" icon={Download} loading={!d} value={si(d?.rxT, 'B')} sub={d ? `avg ${bps((d.rxT * 8) / d.span)}` : undefined} />
        <Stat label="Dropped as source" icon={Ban} loading={!d} value={si(d?.attT)} sub="packets from this IP" />
        <Stat label="Dropped as target" icon={Crosshair} loading={!d} value={si(d?.vicT)} sub="attack packets aimed at it" />
      </div>
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <Panel icon={Activity} title="Bandwidth" sub="Talker tap · bits per second">
          <TimeChart loading={!d} data={d?.bw ?? []} series={[{ key: 'sent', label: 'Sent', color: SERIES[0] }, { key: 'received', label: 'Received', color: SERIES[2] }]} yfmt={bps} spanMs={spanMs} height={220} />
        </Panel>
        <Panel icon={Ban} title="Dropped attack packets" sub="Per second">
          <TimeChart loading={!d} data={d?.drops ?? []} series={[{ key: 'as_source', label: 'As source', color: SERIES[1] }, { key: 'as_target', label: 'As target', color: SERIES[4] }]} yfmt={pps} spanMs={spanMs} height={220} />
        </Panel>
      </div>
      <Panel icon={ShieldAlert} title="Attack episodes involving this IP" sub="Last 15 days">
        {!hist.data ? (
          <div className="aa-skeleton h-10 rounded-lg" />
        ) : episodes.length ? (
          <ul className="divide-y divide-nd-line-soft text-[13px]">
            {episodes.map((a) => (
              <li key={a.id} className="flex flex-wrap items-center justify-between gap-2 py-2.5">
                <span className="flex flex-wrap items-center gap-2">
                  <Badge tone={a.attackers.some((x) => x.ip === ip) ? 'bad' : 'warn'}>{a.attackers.some((x) => x.ip === ip) ? 'source' : 'target'}</Badge>
                  <span className="font-medium text-nd-fg-2">{vectorsOf(a).map(pretty).slice(0, 3).join(', ')}</span>
                </span>
                <span className="mono text-[12px] text-nd-dim">
                  {new Date(a.start).toLocaleString([], { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })} · {duration(a.durationSec)} · {bps(a.peakBps)}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-[13px] text-nd-dim">Not part of any recorded episode.</p>
        )}
      </Panel>
    </div>
  )
}

function IpInner() {
  const sp = useSearchParams()
  const router = useRouter()
  const [ip, setIp] = useState<string | null>(null)
  const [draft, setDraft] = useState('')
  useEffect(() => {
    const q = sp.get('ip')
    if (q && IP_RE.test(q)) { setIp(q); setDraft(q) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  const pick = (v: string) => {
    if (!IP_RE.test(v)) return
    setIp(v)
    setDraft(v)
    router.replace(`/analytics/ip?ip=${encodeURIComponent(v)}`, { scroll: false })
  }
  const bad = draft.length > 0 && !IP_RE.test(draft.trim())
  return (
    <div className="space-y-6">
      <form onSubmit={(e) => { e.preventDefault(); pick(draft.trim()) }} className="rounded-2xl border border-nd-line bg-nd-card p-4 shadow-nd">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative min-w-[260px] flex-1">
            <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-nd-faint" />
            <input
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder="Search an IPv4 or IPv6 address, e.g. 192.168.1.173"
              aria-label="IP address"
              aria-invalid={bad}
              className={`${btn.input} mono w-full py-2.5 pl-10 text-[14px] ${bad ? 'border-st-crit' : ''}`}
            />
          </div>
          <button type="submit" disabled={bad || !draft} className={`${btn.primary} py-2.5`}>Investigate</button>
        </div>
        {bad && <p className="mt-2 text-[12px] text-st-crit-fg">Only digits, a–f, “.” and “:” are allowed.</p>}
      </form>
      {ip ? <Report ip={ip} /> : <Empty icon={Fingerprint} title="Investigate an address" hint="Search above, or pick one of the busiest addresses below, to see its traffic, drops and attack history." />}
      <Picker onPick={pick} />
    </div>
  )
}

export default function IpPage() {
  return (
    <Suspense fallback={<div className="aa-skeleton h-[120px] rounded-2xl" />}>
      <IpInner />
    </Suspense>
  )
}
