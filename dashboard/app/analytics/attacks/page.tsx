'use client'
import { useEffect, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import {
  ShieldAlert, Timer, Maximize2, Ban, ShieldCheck, Search, X, LineChart as LineIcon, Network, Crosshair, Gauge, Users, ArrowRight, Activity,
} from 'lucide-react'
import { rangeAbs, toSeries } from '@/lib/prom'
import { usePoll } from '@/hooks/usePoll'
import { fetchAttacks, vectorsOf, type Episode } from '@/lib/attacks'
import { pps, bps, duration, si, pretty } from '@/lib/format'
import { niceStep, quantile } from '@/lib/stats'
import { SERIES, BarList } from '@/components/nd/ui'
import { TimeChart } from '@/components/nd/charts'
import { Panel, Stat, Badge, Empty, Pagination, btn, type Tone } from '@/components/aa/kit'
import { useRange } from '@/components/aa/Shell'

// Attacks: every detected episode in Prometheus' 15-day history — filterable,
// sortable, and opened in a slide-over that re-queries the episode's own
// window (padded either side) for bandwidth, verdicts and risk.

type SortKey = 'start' | 'durationSec' | 'peakBps' | 'peakPps' | 'droppedPackets' | 'dropShare'
const COLS: { key: SortKey; label: string; right?: boolean }[] = [
  { key: 'start', label: 'Started' },
  { key: 'durationSec', label: 'Duration', right: true },
  { key: 'peakBps', label: 'Peak bandwidth', right: true },
  { key: 'peakPps', label: 'Peak rate', right: true },
  { key: 'droppedPackets', label: 'Dropped', right: true },
  { key: 'dropShare', label: 'Blocked', right: true },
]
const when = (ms: number) => new Date(ms).toLocaleString([], { weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })
const PAGE_SIZE = 10
const blockedTone = (x: number): Tone => (x >= 0.9 ? 'good' : x >= 0.5 ? 'warn' : 'bad')

function Drawer({ a, onClose, onExplore }: { a: Episode; onClose: () => void; onExplore: () => void }) {
  const pad = Math.max(120, Math.round(a.durationSec * 0.5))
  const start = Math.floor(a.start / 1000) - pad
  const end = Math.ceil(a.end / 1000) + pad
  const step = niceStep(end - start, 200)
  const rw = `${Math.max(60, step)}s`
  const q = usePoll(async () => {
    const [bw, verdict, rl, risk, l4, tcp] = await Promise.all([
      rangeAbs(`sum by(iface)(rate(xs_rx_bytes_total[${rw}]))*8`, start, end, step),
      rangeAbs(`sum by(verdict)(rate(xs_verdict_packets_total{verdict=~"pass|drop"}[${rw}]))`, start, end, step),
      rangeAbs(`sum(rate(xs_policy_event_packets_total{event="rate_limited"}[${rw}]))`, start, end, step),
      rangeAbs('max(xs_risk)', start, end, step),
      rangeAbs(`sum by(proto)(rate(xs_l4_packets_total[${rw}]))`, start, end, step),
      rangeAbs(`sum by(class)(rate(xs_tcp_flags_packets_total[${rw}]))`, start, end, step),
    ])
    return {
      bw: toSeries(bw, (m) => m.iface ?? 'all'), bwKeys: bw.map((s) => s.metric.iface ?? 'all'),
      pk: toSeries([...verdict.map((s) => ({ metric: { k: s.metric.verdict }, values: s.values })), ...rl.map((s) => ({ metric: { k: 'rate_limited' }, values: s.values }))], (m) => m.k),
      risk: toSeries(risk, () => 'risk'),
      proto: toSeries(l4, (m) => m.proto ?? 'other'), protoKeys: l4.map((s) => s.metric.proto ?? 'other'),
      tcp: toSeries(tcp, (m) => m.class ?? 'other'), tcpKeys: tcp.map((s) => s.metric.class ?? 'other'),
    }
  }, 600_000, [a.id, a.start])
  const spanMs = (end - start) * 1000
  useEffect(() => {
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', esc)
    return () => document.removeEventListener('keydown', esc)
  }, [onClose])

  return (
    <div className="fixed inset-0 z-50" role="dialog" aria-modal="true" aria-label={`Attack episode ${a.id}`}>
      <button aria-label="Close" onClick={onClose} className="absolute inset-0 bg-black/30 backdrop-blur-[2px]" />
      <div className="aa-in absolute inset-y-0 right-0 flex w-full max-w-[900px] flex-col border-l border-nd-line bg-nd-bg shadow-nd-lg">
        <header className="flex items-start justify-between gap-4 border-b border-nd-line bg-nd-card px-6 py-5">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone="bad" icon={ShieldAlert}>Episode #{a.id}</Badge>
              <Badge tone={blockedTone(a.dropShare)}>{(a.dropShare * 100).toFixed(0)}% blocked</Badge>
            </div>
            <h2 className="mt-2 text-[20px] font-semibold tracking-[-0.02em] text-nd-fg">{vectorsOf(a).map(pretty).slice(0, 3).join(', ')}</h2>
            <p className="mt-1 text-[13px] text-nd-dim">{when(a.start)} · lasted {duration(a.durationSec)}{a.target ? ` · hit ${a.target.label}` : ''}</p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <button onClick={onExplore} className={btn.ghost}>Open in Explorer <ArrowRight className="h-3.5 w-3.5" /></button>
            <button onClick={onClose} aria-label="Close" className="grid h-8 w-8 place-items-center rounded-lg text-nd-dim hover:bg-nd-fill hover:text-nd-fg"><X className="h-4 w-4" /></button>
          </div>
        </header>
        <div className="flex-1 space-y-5 overflow-y-auto px-6 py-6">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Stat label="Peak bandwidth" icon={Maximize2} value={bps(a.peakBps)} sub={`${si(a.totalBytes, 'B')} total`} />
            <Stat label="Traffic" icon={Activity} value={si(a.totalPackets)} sub={`${pps(a.peakPps)} peak`} />
            <Stat label="Dropped" icon={Ban} value={si(a.droppedPackets)} sub={`${(a.dropShare * 100).toFixed(1)}% of the flood`} />
            <Stat label="Peak risk" icon={Gauge} value={`L${a.peakRiskLevel}`} sub={`threat state ${a.peakThreatState}`} />
          </div>
          <Panel icon={Network} title="Bandwidth by interface" sub="Episode window ± padding">
            <TimeChart kind="area" stacked loading={!q.data} data={q.data?.bw ?? []} series={(q.data?.bwKeys ?? []).map((k, i) => ({ key: k, label: k, color: SERIES[i % SERIES.length] }))} yfmt={bps} spanMs={spanMs} height={200} />
          </Panel>
          <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
            <Panel icon={Network} title="Protocols sent" sub="Transport protocol, packets per second">
              <TimeChart kind="area" stacked loading={!q.data} data={q.data?.proto ?? []} series={(q.data?.protoKeys ?? []).map((k, i) => ({ key: k, label: pretty(k), color: SERIES[i % SERIES.length] }))} yfmt={pps} spanMs={spanMs} height={190} />
            </Panel>
            <Panel icon={Activity} title="TCP flag types" sub="SYN · ACK · RST · FIN · SYN-ACK, packets per second">
              <TimeChart kind="area" stacked loading={!q.data} data={q.data?.tcp ?? []} series={(q.data?.tcpKeys ?? []).map((k, i) => ({ key: k, label: pretty(k), color: SERIES[i % SERIES.length] }))} yfmt={pps} spanMs={spanMs} height={190} />
            </Panel>
          </div>
          <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
            <Panel icon={ShieldCheck} title="Passed · dropped · rate-limited" sub="Packets per second">
              <TimeChart loading={!q.data} data={q.data?.pk ?? []} series={[{ key: 'pass', label: 'Passed', color: SERIES[2] }, { key: 'drop', label: 'Dropped', color: SERIES[1] }, { key: 'rate_limited', label: 'Rate-limited', color: SERIES[4] }]} yfmt={pps} spanMs={spanMs} height={190} />
            </Panel>
            <Panel icon={Gauge} title="Risk score" sub="Fused risk, 0–1">
              <TimeChart loading={!q.data} data={q.data?.risk ?? []} series={[{ key: 'risk', label: 'Risk', color: SERIES[1] }]} yfmt={(n) => n.toFixed(2)} spanMs={spanMs} height={190} />
            </Panel>
          </div>
          <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
            <Panel icon={Users} title="Attack sources" sub={a.uniqueSources ? `${si(a.uniqueSources)} distinct${a.uniqueSources > 1000 ? ' — likely spoofed' : ''}` : 'Not attributed'}>
              <BarList rows={a.attackers.slice(0, 8).map((x) => ({ label: x.ip, sub: x.scope, v: x.packets }))} fmt={(n) => si(n)} mono color={SERIES[1]} empty="No per-source attribution — on-box or injected traffic bypasses the talker tap." />
            </Panel>
            <Panel icon={Crosshair} title="Targets" sub={a.classifier ? `Classifier: ${pretty(a.classifier.label)} (${Math.round(a.classifier.conf * 100)}%)` : 'Victim hosts'}>
              <BarList rows={a.victims.slice(0, 8).map((v) => ({ label: v.ip, v: v.packets }))} fmt={(n) => si(n)} mono color={SERIES[4]} empty="No victim hosts recorded." />
            </Panel>
          </div>
        </div>
      </div>
    </div>
  )
}

export default function AttacksPage() {
  const rng = useRange()
  const router = useRouter()
  const hist = usePoll(fetchAttacks, 60_000)
  const [vector, setVector] = useState('all')
  const [inWindow, setInWindow] = useState(false)
  const [ipq, setIpq] = useState('')
  const [sort, setSort] = useState<{ key: SortKey; desc: boolean }>({ key: 'start', desc: true })
  const [open, setOpen] = useState<number | null>(null)
  const [page, setPage] = useState(1)

  const all = hist.data?.attacks ?? []
  const vectors = useMemo(() => Array.from(new Set(all.flatMap(vectorsOf))).sort(), [all])
  const rows = useMemo(() => {
    const w = rng.resolve()
    const q = ipq.trim()
    return all
      .filter((a) => vector === 'all' || vectorsOf(a).includes(vector))
      .filter((a) => !inWindow || (a.end / 1000 >= w.start && a.start / 1000 <= w.end))
      .filter((a) => !q || a.attackers.some((x) => x.ip.includes(q)) || a.victims.some((x) => x.ip.includes(q)))
      .sort((x, y) => (sort.desc ? y[sort.key] - x[sort.key] : x[sort.key] - y[sort.key]))
    // rng.key keeps the window filter in step with the range picker
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [all, vector, inWindow, ipq, sort, rng.key])
  const sel = all.find((a) => a.id === open) ?? null
  // 10 episodes per page; a new filter, sort or window starts again at page 1
  useEffect(() => { setPage(1) }, [vector, inWindow, ipq, sort, rng.key])
  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE))
  const cur = Math.min(page, pages)
  const pageRows = rows.slice((cur - 1) * PAGE_SIZE, cur * PAGE_SIZE)
  const goPage = (p: number) => {
    setPage(Math.max(1, Math.min(pages, p)))
    document.getElementById('episodes')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }
  const durs = rows.map((a) => a.durationSec).sort((a, b) => a - b)
  const loading = !hist.data

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <Stat label="Episodes" icon={ShieldAlert} loading={loading} value={rows.length} sub={`of ${all.length} in ${hist.data?.days ?? 15} days`} />
        <Stat label="Time under attack" icon={Timer} loading={loading} value={duration(rows.reduce((s, a) => s + a.durationSec, 0))} sub={durs.length ? `median ${duration(quantile(durs, 0.5))} each` : 'no episodes'} />
        <Stat label="Largest" icon={Maximize2} loading={loading} value={bps(Math.max(0, ...rows.map((a) => a.peakBps)))} sub={`${pps(Math.max(0, ...rows.map((a) => a.peakPps)))} peak`} />
        <Stat label="Packets dropped" icon={Ban} loading={loading} value={si(rows.reduce((s, a) => s + a.droppedPackets, 0))} sub="across shown episodes" />
        <Stat
          label="Avg blocked"
          icon={ShieldCheck}
          loading={loading}
          value={rows.length ? `${((rows.reduce((s, a) => s + a.dropShare, 0) / rows.length) * 100).toFixed(1)}%` : '—'}
          sub="mean share of each flood dropped"
        />
      </div>

      <div id="episodes" className="scroll-mt-28" />
      <Panel
        icon={ShieldAlert}
        title="Episodes"
        sub={hist.data?.incomplete ? `${hist.data.incomplete} episode${hist.data.incomplete === 1 ? '' : 's'} couldn't be rebuilt this round and will be retried shortly` : 'Select a row for the full breakdown · click a column to sort'}
        bodyClass=""
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-nd-faint" />
              <input value={ipq} onChange={(e) => setIpq(e.target.value)} placeholder="Filter by IP" aria-label="Filter by IP" className={`${btn.input} mono w-40 py-1.5 pl-8 text-[12.5px]`} />
            </div>
            <select value={vector} onChange={(e) => setVector(e.target.value)} aria-label="Vector" className={`${btn.input} py-1.5 text-[12.5px]`}>
              <option value="all">All vectors</option>
              {vectors.map((v) => <option key={v} value={v}>{pretty(v)}</option>)}
            </select>
            <label className="flex cursor-pointer items-center gap-2 text-[12.5px] text-nd-fg-3">
              <button role="switch" aria-checked={inWindow} onClick={() => setInWindow((x) => !x)} className={`relative h-5 w-9 rounded-full transition-colors ${inWindow ? 'bg-nd-fg' : 'bg-nd-fill-2'}`}>
                <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-nd-card shadow-nd transition-all ${inWindow ? 'left-[18px]' : 'left-0.5'}`} />
              </button>
              Only {rng.label}
            </label>
          </div>
        }
      >
        {hist.error && !hist.data ? (
          <Empty icon={ShieldAlert} title="Attack history unavailable" hint={`${hist.error}. The history is rebuilt from 15 days of Prometheus data and can time out while the appliance is busy.`} />
        ) : loading ? (
          <div className="space-y-2 px-5 pb-3">{[0, 1, 2, 3].map((i) => <div key={i} className="aa-skeleton h-10 rounded-lg" />)}<p className="pt-1 text-center text-[12px] text-nd-faint">Reconstructing 15 days of history — the first load after a restart can take ~25 s.</p></div>
        ) : rows.length === 0 ? (
          <Empty icon={ShieldCheck} title={all.length ? 'No episodes match these filters' : 'No attacks recorded'} hint={all.length ? 'Clear the filters to see all episodes.' : 'Nothing triggered the detector in the last 15 days.'} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px] text-left text-[13px]">
              <thead>
                <tr className="border-y border-nd-line bg-nd-fill text-[11px] uppercase tracking-[0.06em] text-nd-dim">
                  {COLS.map((c) => (
                    <th key={c.key} className={`px-4 py-2 font-medium first:pl-5 ${c.right ? 'text-right' : ''}`}>
                      <button onClick={() => setSort((s) => ({ key: c.key, desc: s.key === c.key ? !s.desc : true }))} className={`inline-flex items-center gap-1 hover:text-nd-fg ${sort.key === c.key ? 'text-nd-fg' : ''}`}>
                        {c.label}{sort.key === c.key ? (sort.desc ? ' ↓' : ' ↑') : ''}
                      </button>
                    </th>
                  ))}
                  <th className="px-4 py-2 font-medium">Vectors</th>
                </tr>
              </thead>
              <tbody>
                {pageRows.map((a) => (
                  <tr key={a.id} onClick={() => setOpen(a.id)} className="group cursor-pointer border-b border-nd-line-soft transition-colors last:border-0 hover:bg-nd-fill">
                    <td className="py-3 pl-5 pr-4">
                      <div className="font-medium text-nd-fg">{when(a.start)}</div>
                      <div className="text-[11.5px] text-nd-dim">{a.target?.label ?? 'target unknown'}</div>
                    </td>
                    <td className="mono px-4 py-3 text-right text-nd-fg-3">{duration(a.durationSec)}</td>
                    <td className="mono px-4 py-3 text-right font-medium text-nd-fg">{bps(a.peakBps)}</td>
                    <td className="mono px-4 py-3 text-right text-nd-fg-3">{pps(a.peakPps)}</td>
                    <td className="mono px-4 py-3 text-right text-nd-fg-3">{si(a.droppedPackets)}</td>
                    <td className="px-4 py-3 text-right"><Badge tone={blockedTone(a.dropShare)}>{(a.dropShare * 100).toFixed(0)}%</Badge></td>
                    <td className="px-4 py-3">
                      <div className="flex max-w-[300px] flex-wrap gap-1">
                        {vectorsOf(a).slice(0, 3).map((v) => <Badge key={v}>{pretty(v)}</Badge>)}
                        {vectorsOf(a).length > 3 && <Badge>+{vectorsOf(a).length - 3}</Badge>}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pagination page={cur} pageSize={PAGE_SIZE} total={rows.length} onPage={goPage} noun="episodes" />
          </div>
        )}
      </Panel>

      {sel && (
        <Drawer
          a={sel}
          onClose={() => setOpen(null)}
          onExplore={() => {
            const pad = Math.max(120, Math.round(sel.durationSec * 0.5))
            rng.setCustom(Math.floor(sel.start / 1000) - pad, Math.ceil(sel.end / 1000) + pad)
            router.push('/analytics/explore?metric=ingress_bps&by=iface')
          }}
        />
      )}
    </div>
  )
}
