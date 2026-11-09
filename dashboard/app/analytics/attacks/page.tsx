'use client'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import {
  ShieldAlert, Timer, Maximize2, Ban, ShieldCheck, Search, X, LineChart as LineIcon, Network, Crosshair, Gauge, Users, ArrowRight, Activity,
  ChevronLeft, ChevronRight, Loader2, Archive, List, Info,
} from 'lucide-react'
import Link from 'next/link'
import { rangeAbs, toSeries } from '@/lib/prom'
import { usePoll } from '@/hooks/usePoll'
import { fetchAttackPage, fetchAttack, fetchParties, attackHref, vectorsOf, type Episode, type AttackPage, type Party, type Parties } from '@/lib/attacks'
import { pps, bps, duration, si, pretty } from '@/lib/format'
import { niceStep } from '@/lib/stats'
import { SERIES, BarList } from '@/components/nd/ui'
import { TimeChart } from '@/components/nd/charts'
import { Panel, Stat, Badge, Empty, btn, type Tone } from '@/components/aa/kit'
import { CsvButton } from '@/components/aa/export'
import { downloadCsv } from '@/lib/csv'
import { useRange } from '@/components/aa/Shell'

// Attacks: every attack the appliance has recorded — Prometheus' retention plus
// the permanent archive — paged (20, then 10 per page), filterable and sortable
// on the server, and opened in a slide-over that re-queries the episode's own
// window for charts (while Prometheus still holds it).

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
const blockedTone = (x: number): Tone => (x >= 0.9 ? 'good' : x >= 0.5 ? 'warn' : 'bad')

// Every source / target of one attack, searchable, with CSV export. Opened from
// the attack's slide-over; the list there only shows the top 8.
type Side = 'sources' | 'targets'
function PartiesDialog({ a, side: initial, onClose }: { a: Episode; side: Side; onClose: () => void }) {
  const [side, setSide] = useState<Side>(initial)
  const [data, setData] = useState<Parties | null>(null)
  const [err, setErr] = useState('')
  const [q, setQ] = useState('')
  const [shown, setShown] = useState(200)
  useEffect(() => {
    fetchParties(a.id).then(setData).catch((e) => setErr(e instanceof Error ? e.message : 'failed'))
  }, [a.id])
  // Esc closes this dialog only, not the attack behind it.
  useEffect(() => {
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') { e.stopPropagation(); onClose() } }
    document.addEventListener('keydown', esc, true)
    return () => document.removeEventListener('keydown', esc, true)
  }, [onClose])
  useEffect(() => setShown(200), [side, q])

  const all: Party[] = data ? (side === 'sources' ? data.attackers : data.victims) : []
  const total = all.reduce((n, p) => n + p.packets, 0)
  const rows = q.trim() ? all.filter((p) => p.ip.includes(q.trim())) : all
  const dropped = a.droppedPackets
  const traced = dropped > 0 ? Math.min(1, total / dropped) : 0
  const isSrc = side === 'sources'
  const exportCsv = () => downloadCsv(`attack-${a.id}-${side}`, rows, [
    { key: 'ip', label: isSrc ? 'source IP' : 'target IP' },
    ...(isSrc ? [{ key: 'scope', label: 'scope' } as const] : []),
    { key: 'packets', label: 'dropped packets' },
    { key: 'share', label: 'share of traced %', get: (p: Party) => (total ? (p.packets / total) * 100 : 0).toFixed(2) },
    { key: 'bytes', label: 'dropped bytes' },
    { key: 'pps', label: 'avg packets/s', get: (p: Party) => p.pps ?? Math.round(p.packets / Math.max(1, a.durationSec)) },
  ], `${rows.length} attack ${side} of the ${new Date(a.start).toISOString()} attack`, `attack:${a.id}`)

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-label={`All ${side} of this attack`}>
      <button aria-label="Close" onClick={onClose} className="absolute inset-0 bg-black/40 backdrop-blur-[2px]" />
      <div className="aa-in relative flex h-[min(86vh,780px)] w-full max-w-[860px] flex-col overflow-hidden rounded-2xl border border-nd-line bg-nd-bg shadow-nd-lg">
        <header className="flex items-start justify-between gap-4 border-b border-nd-line bg-nd-card px-5 py-4">
          <div className="min-w-0">
            <h3 className="text-[16px] font-semibold tracking-[-0.01em] text-nd-fg">Sources and targets</h3>
            <p className="mt-0.5 text-[12.5px] text-nd-dim">{vectorsOf(a).map(pretty).slice(0, 3).join(', ')} · {when(a.start)} · {duration(a.durationSec)}</p>
          </div>
          <button onClick={onClose} aria-label="Close" className="grid h-8 w-8 shrink-0 place-items-center rounded-lg text-nd-dim hover:bg-nd-fill hover:text-nd-fg"><X className="h-4 w-4" /></button>
        </header>
        <div className="flex flex-wrap items-center gap-2 border-b border-nd-line px-5 py-3">
          <div className="inline-flex rounded-lg border border-nd-line bg-nd-fill p-0.5 text-[12.5px]" role="tablist">
            {(['sources', 'targets'] as Side[]).map((t) => (
              <button key={t} role="tab" aria-selected={side === t} onClick={() => setSide(t)}
                className={`rounded-md px-3 py-1 font-medium transition-colors ${side === t ? 'bg-nd-card text-nd-fg shadow-nd' : 'text-nd-dim hover:text-nd-fg'}`}>
                {t === 'sources' ? 'Attack sources' : 'Targets'}{data ? ` (${(t === 'sources' ? data.attackers : data.victims).length})` : ''}
              </button>
            ))}
          </div>
          <div className="relative ml-auto">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-nd-faint" />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Find an IP" aria-label="Find an IP" className={`${btn.input} mono w-44 py-1.5 pl-8 text-[12.5px]`} />
          </div>
          <CsvButton disabled={!rows.length} onClick={exportCsv} title={`Every ${isSrc ? 'source' : 'target'} shown, as CSV`} />
        </div>
        {data && (
          <div className="space-y-1 border-b border-nd-line bg-nd-panel px-5 py-2.5 text-[12px] text-nd-dim">
            <p>
              <span className="font-medium text-nd-fg-3">{si(total)}</span> of {si(dropped)} dropped packets traced to {isSrc ? 'a source' : 'a target'} address ({(traced * 100).toFixed(0)}%)
              {traced < 0.95 && dropped > 0 && ' — the rest was IPv6 or non-IP traffic, which is not traced per address.'}
            </p>
            {data.sample > 1 && <p className="flex items-start gap-1.5"><Info className="mt-[1px] h-3.5 w-3.5 shrink-0" />Per-address counts are estimates: the dataplane records 1 in {data.sample} dropped packets per address (to stay fast under a flood) and they are scaled back up.</p>}
            {!data.complete && <p className="flex items-start gap-1.5"><Archive className="mt-[1px] h-3.5 w-3.5 shrink-0" />This attack is older than Prometheus keeps, so only the top {all.length} kept in the archive are listed.</p>}
          </div>
        )}
        <div className="min-h-0 flex-1 overflow-y-auto">
          {err ? (
            <Empty icon={ShieldAlert} title="Couldn’t load the list" hint={err} />
          ) : !data ? (
            <div className="space-y-2 p-5">{Array.from({ length: 8 }).map((_, i) => <div key={i} className="aa-skeleton h-8 rounded-lg" />)}</div>
          ) : rows.length === 0 ? (
            <Empty icon={isSrc ? Users : Crosshair} title={q ? 'No address matches' : `No ${side} recorded`} hint={q ? 'Try part of an address.' : 'Nothing was traced to an address for this attack.'} />
          ) : (
            <table className="w-full text-left text-[12.5px]">
              <thead className="sticky top-0 bg-nd-fill">
                <tr className="text-[11px] uppercase tracking-[0.06em] text-nd-dim">
                  <th className="w-10 py-2 pl-5 pr-2 font-medium">#</th>
                  <th className="px-3 py-2 font-medium">{isSrc ? 'Source' : 'Target'}</th>
                  {isSrc && <th className="px-3 py-2 font-medium">Scope</th>}
                  <th className="px-3 py-2 text-right font-medium">Dropped packets</th>
                  <th className="px-3 py-2 font-medium">Share</th>
                  <th className="px-3 py-2 text-right font-medium">Data</th>
                  <th className="py-2 pl-3 pr-5 text-right font-medium">Avg rate</th>
                </tr>
              </thead>
              <tbody>
                {rows.slice(0, shown).map((p) => {
                  const share = total ? p.packets / total : 0
                  return (
                    <tr key={p.ip} className="border-b border-nd-line-soft last:border-0 hover:bg-nd-fill">
                      <td className="py-2 pl-5 pr-2 text-nd-faint">{all.indexOf(p) + 1}</td>
                      <td className="mono px-3 py-2"><Link href={`/analytics/ip?ip=${encodeURIComponent(p.ip)}`} className="text-nd-fg hover:underline" title="Look up this IP">{p.ip}</Link></td>
                      {isSrc && <td className="px-3 py-2"><Badge tone={p.scope === 'lan' ? 'warn' : 'neutral'}>{p.scope || '—'}</Badge></td>}
                      <td className="mono px-3 py-2 text-right text-nd-fg">{p.packets.toLocaleString()}</td>
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-2">
                          <div className="h-1.5 w-20 overflow-hidden rounded-full bg-nd-fill-2"><div className="h-full rounded-full" style={{ width: `${Math.max(1, share * 100)}%`, background: isSrc ? SERIES[1] : SERIES[4] }} /></div>
                          <span className="mono w-12 text-nd-dim">{(share * 100).toFixed(share < 0.01 ? 2 : 1)}%</span>
                        </div>
                      </td>
                      <td className="mono px-3 py-2 text-right text-nd-fg-3">{si(p.bytes, 'B')}</td>
                      <td className="mono py-2 pl-3 pr-5 text-right text-nd-fg-3">{pps(p.pps ?? p.packets / Math.max(1, a.durationSec))}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
          {data && rows.length > shown && (
            <div className="flex justify-center p-4">
              <button onClick={() => setShown((n) => n + 200)} className={btn.ghost}>Show {Math.min(200, rows.length - shown)} more of {rows.length - shown}</button>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function Drawer({ a, retentionDays, onClose, onExplore }: { a: Episode; retentionDays: number; onClose: () => void; onExplore: () => void }) {
  const [all, setAll] = useState<Side | null>(null)
  const archivedOnly = Date.now() - a.end > retentionDays * 86_400_000
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
  const viewAll = (side: Side, n: number) => (
    <button onClick={() => setAll(side)} className={`${btn.ghost} py-1 text-[12px]`} title={`Every ${side === 'sources' ? 'source' : 'target'} of this attack`}>
      <List className="h-3.5 w-3.5" /> View all{n ? ` ${si(n)}` : ''}
    </button>
  )

  return (
    <div className="fixed inset-0 z-50" role="dialog" aria-modal="true" aria-label={`Attack episode ${a.id}`}>
      <button aria-label="Close" onClick={onClose} className="absolute inset-0 bg-black/30 backdrop-blur-[2px]" />
      <div className="aa-in absolute inset-y-0 right-0 flex w-full max-w-[900px] flex-col border-l border-nd-line bg-nd-bg shadow-nd-lg">
        <header className="flex items-start justify-between gap-4 border-b border-nd-line bg-nd-card px-6 py-5">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone="bad" icon={ShieldAlert}>Attack {new Date(a.start).toLocaleDateString([], { day: 'numeric', month: 'short', year: 'numeric' })}</Badge>
              {archivedOnly && <Badge icon={Archive}>archived</Badge>}
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
          {archivedOnly && (
            <div className="flex items-start gap-2 rounded-xl border border-nd-line bg-nd-panel px-4 py-3 text-[12.5px] text-nd-dim">
              <Archive className="mt-0.5 h-4 w-4 shrink-0" />
              <span>This attack is older than Prometheus keeps raw data ({retentionDays} days), so the second-by-second charts below are empty. The numbers, sources and targets come from the permanent attack archive.</span>
            </div>
          )}
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
          {(a.v ?? 2) < 3 && (
            <div className="flex items-start gap-2 rounded-xl border border-nd-line bg-nd-panel px-4 py-3 text-[12.5px] text-nd-dim">
              <Info className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{archivedOnly ? 'The source and target counts for this attack were saved by an older version that undercounted them, and Prometheus no longer has the data to redo them. Treat them as a lower bound.' : 'The source and target counts are being recalculated with the corrected method — reopen this attack in a minute.'}</span>
            </div>
          )}
          <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
            <Panel icon={Users} title="Attack sources" actions={viewAll('sources', a.uniqueSources)}
              sub={a.uniqueSources ? `${si(a.uniqueSources)} distinct${a.uniqueSources > 1000 ? ' — likely spoofed' : ''}${a.sample && a.sample > 1 ? ' · estimated' : ''}` : 'Not attributed'}>
              <BarList rows={a.attackers.slice(0, 8).map((x) => ({ label: x.ip, sub: x.scope, v: x.packets }))} fmt={(n) => si(n)} mono color={SERIES[1]} empty="No per-source attribution — on-box or injected traffic bypasses the talker tap." />
            </Panel>
            <Panel icon={Crosshair} title="Targets" actions={viewAll('targets', a.uniqueTargets ?? a.victims.length)}
              sub={`${a.uniqueTargets ?? a.victims.length} host${(a.uniqueTargets ?? a.victims.length) === 1 ? '' : 's'} hit${a.sample && a.sample > 1 ? ' · estimated' : ''}`}>
              <BarList rows={a.victims.slice(0, 8).map((v) => ({ label: v.ip, v: v.packets }))} fmt={(n) => si(n)} mono color={SERIES[4]} empty="No victim hosts recorded." />
            </Panel>
          </div>
        </div>
      </div>
      {all && <PartiesDialog a={a} side={all} onClose={() => setAll(null)} />}
    </div>
  )
}

// 10 attacks per page, always one page ahead: the first load fetches 20 (pages 1
// and 2), and landing on a page quietly fetches the one after it, so "Next" is
// instant. Fetched attacks are kept, so going back is instant too. (The server
// analyses an attack the first time it is fetched.)
const PAGE = 10
const pageCount = (total: number) => Math.max(1, Math.ceil(total / PAGE))
type Row = Episode & { partial?: boolean }

export default function AttacksPage() {
  const rng = useRange()
  const router = useRouter()
  const [vector, setVector] = useState('all')
  const [inWindow, setInWindow] = useState(false)
  const [ipq, setIpq] = useState('')
  const [ipDeb, setIpDeb] = useState('')
  const [sort, setSort] = useState<{ key: SortKey; desc: boolean }>({ key: 'start', desc: true })
  const [open, setOpen] = useState<number | null>(null)
  const [page, setPage] = useState(1)
  const [items, setItems] = useState<Record<number, Row>>({}) // by position in the list
  const [meta, setMeta] = useState<AttackPage | null>(null) // total, summary, pending
  const [busy, setBusy] = useState(false)
  const inflight = useRef(new Set<number>())
  const gen = useRef(0) // bumps when the filters change; late answers for old filters are dropped
  const [err, setErr] = useState('')
  const [exporting, setExporting] = useState(false)
  // Opened from a link (?attack=<id>, e.g. a host's page): that attack may not
  // be on the page that is loaded, so it is fetched on its own.
  const [deep, setDeep] = useState<{ attack: Episode; retentionDays: number } | null>(null)
  const [deepState, setDeepState] = useState<{ id: number; error?: string } | null>(null)
  useEffect(() => {
    const id = Number(new URLSearchParams(window.location.search).get('attack'))
    if (!id) return
    setOpen(id)
    setDeepState({ id })
    fetchAttack(id)
      .then((d) => { setDeep(d); setDeepState(null) })
      .catch((e) => setDeepState({ id, error: e instanceof Error ? e.message : 'could not load that attack' }))
  }, [])
  // Keep the address bar in step with the open attack, so it can be shared and
  // Back still returns to wherever the link came from.
  const openAttack = (id: number | null) => {
    setOpen(id)
    if (id === null) setDeepState(null)
    window.history.replaceState(window.history.state, '', id === null ? '/analytics/attacks' : attackHref(id))
  }

  useEffect(() => { const t = setTimeout(() => setIpDeb(ipq.trim()), 350); return () => clearTimeout(t) }, [ipq])

  // Everything that changes WHICH attacks are listed; a change starts over at page 1.
  const query = useMemo(() => {
    const w = rng.resolve()
    return {
      vector: vector === 'all' ? undefined : vector,
      ip: ipDeb || undefined,
      from: inWindow ? w.start : undefined,
      to: inWindow ? w.end : undefined,
      sort: sort.key,
      desc: sort.desc,
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vector, ipDeb, inWindow, sort, inWindow ? rng.key : ''])
  const qkey = JSON.stringify(query)
  useEffect(() => { gen.current++; inflight.current.clear(); setItems({}); setMeta(null); setPage(1) }, [qkey])

  // Fetch `limit` attacks starting at `offset`. `refresh` = the minute poll: if
  // the list changed (a new attack shifts every position), keep only this range.
  const fetchRange = useCallback(async (offset: number, limit: number, quiet: boolean, refresh = false) => {
    if (inflight.current.has(offset)) return
    inflight.current.add(offset)
    const g = gen.current
    if (!quiet) setBusy(true)
    try {
      const d = await fetchAttackPage({ ...query, offset, limit })
      if (g !== gen.current) return
      setItems((cur) => {
        const shifted = refresh && meta !== null && d.total !== meta.total
        const n: Record<number, Row> = shifted ? {} : { ...cur }
        d.attacks.forEach((a, i) => { n[offset + i] = a })
        return n
      })
      setMeta(d)
      setErr('')
    } catch (e) {
      if (g === gen.current) setErr(e instanceof Error ? e.message : 'attack history failed')
    } finally {
      inflight.current.delete(offset)
      if (!quiet && g === gen.current) setBusy(false)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qkey, meta?.total])

  const total = meta?.total ?? 0
  const nPages = pageCount(total)
  const hasPage = (p: number) => {
    if (!meta) return false
    const from = (p - 1) * PAGE, to = Math.min(p * PAGE, total)
    for (let i = from; i < to; i++) if (!items[i]) return false
    return true
  }
  // Current page missing -> fetch it plus the next one (20). Present -> make sure
  // the next page is already there (10, in the background).
  useEffect(() => {
    if (!hasPage(page)) fetchRange((page - 1) * PAGE, 2 * PAGE, false)
    else if (page < nPages && !hasPage(page + 1)) fetchRange(page * PAGE, PAGE, true)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, items, meta, fetchRange])
  useEffect(() => {
    const t = setInterval(() => fetchRange((page - 1) * PAGE, 2 * PAGE, true, true), 60_000)
    return () => clearInterval(t)
  }, [page, fetchRange])

  const any = meta
  const s = meta?.summary
  const rows: Row[] = []
  for (let i = (page - 1) * PAGE; i < Math.min(page * PAGE, total); i++) if (items[i]) rows.push(items[i])
  const cur = hasPage(page) ? meta : null
  const sel = rows.find((a) => a.id === open) ?? (deep && deep.attack.id === open ? deep.attack : null)
  const goPage = (p: number) => {
    setPage(Math.max(1, Math.min(nPages, p)))
    document.getElementById('episodes')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }
  const loading = !any

  // CSV: every ANALYSED attack matching the filters (all pages, not just this one).
  async function exportAll() {
    setExporting(true)
    try {
      const out: Episode[] = []
      for (let off = 0; ; off += 500) {
        const d = await fetchAttackPage({ ...query, offset: off, limit: 500, analysedOnly: true })
        out.push(...d.attacks)
        if (out.length >= d.total || !d.attacks.length) break
      }
      downloadCsv('ddos-attacks', out, [
        { key: 'start', label: 'start (UTC)', get: (a) => new Date(a.start).toISOString() },
        { key: 'end', label: 'end (UTC)', get: (a) => new Date(a.end).toISOString() },
        { key: 'durationSec', label: 'duration (s)' },
        { key: 'vectors', label: 'attack type', get: (a) => vectorsOf(a).join(' ') },
        { key: 'peakPps', label: 'peak packets/s', get: (a) => Math.round(a.peakPps) },
        { key: 'peakBps', label: 'peak bits/s', get: (a) => Math.round(a.peakBps) },
        { key: 'totalPackets', label: 'total packets' },
        { key: 'totalBytes', label: 'total bytes' },
        { key: 'droppedPackets', label: 'dropped packets' },
        { key: 'dropShare', label: 'blocked %', get: (a) => (a.dropShare * 100).toFixed(1) },
        { key: 'peakRiskLevel', label: 'peak risk level' },
        { key: 'uniqueSources', label: 'distinct sources' },
        { key: 'attackers', label: 'top sources', get: (a) => a.attackers.map((x) => x.ip).join(' ') },
        { key: 'victims', label: 'targets', get: (a) => a.victims.map((x) => x.ip).join(' ') },
        { key: 'target', label: 'interface', get: (a) => a.target?.iface ?? '' },
      ], `${out.length} DDoS attack episode${out.length === 1 ? '' : 's'}${query.vector ? ` (${query.vector})` : ''}${query.ip ? ` matching ${query.ip}` : ''}`, 'attacks')
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'export failed')
    }
    setExporting(false)
  }

  const firstShown = (page - 1) * PAGE + 1
  const lastShown = (page - 1) * PAGE + rows.length
  const filtered = !!(query.vector || query.ip || query.sort !== 'start')

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <Stat label="Attacks" icon={ShieldAlert} loading={loading} value={s?.count ?? 0}
          sub={s?.oldest ? `since ${new Date(s.oldest).toLocaleDateString([], { day: 'numeric', month: 'short', year: 'numeric' })}` : 'none recorded'} />
        <Stat label="Time under attack" icon={Timer} loading={loading} value={duration(s?.totalDurationSec ?? 0)} sub={s?.count ? `median ${duration(s.medianDurationSec)} each` : 'no episodes'} />
        <Stat label="Largest" icon={Maximize2} loading={loading} value={bps(s?.peakBps ?? 0)} sub={`${pps(s?.peakPps ?? 0)} peak`} />
        <Stat label="Packets dropped" icon={Ban} loading={loading} value={si(s?.droppedPackets ?? 0)} sub={s && s.analysed < s.count ? `across ${s.analysed} analysed so far` : 'across all attacks'} />
        <Stat label="Avg blocked" icon={ShieldCheck} loading={loading} value={s?.analysed ? `${(s.avgDropShare * 100).toFixed(1)}%` : '—'} sub="mean share of each flood dropped" />
      </div>

      <div id="episodes" className="scroll-mt-28" />
      <Panel
        icon={ShieldAlert}
        title="Attack history"
        sub={any ? `Every recorded attack, newest first · ${s!.archived} kept permanently in the archive${any.pending ? ` · ${any.pending} still being analysed in the background` : ''}` : 'Loading…'}
        bodyClass=""
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <CsvButton label={exporting ? 'Exporting…' : 'Export CSV'} disabled={exporting || !total} onClick={exportAll} title="Every analysed attack matching the filters — all pages" />
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-nd-faint" />
              <input value={ipq} onChange={(e) => setIpq(e.target.value)} placeholder="Filter by IP" aria-label="Filter by IP" className={`${btn.input} mono w-40 py-1.5 pl-8 text-[12.5px]`} />
            </div>
            <select value={vector} onChange={(e) => setVector(e.target.value)} aria-label="Attack type" className={`${btn.input} py-1.5 text-[12.5px]`}>
              <option value="all">All attack types</option>
              {(s?.vectors ?? []).map((v) => <option key={v} value={v}>{pretty(v)}</option>)}
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
        {filtered && any && any.pending > 0 && (
          <p className="mx-5 mb-3 rounded-lg bg-nd-fill px-3 py-2 text-[12px] text-nd-dim">
            Filters and sorting look at analysed attacks; {any.pending} older attack{any.pending === 1 ? ' is' : 's are'} still being analysed and will show up here within a few minutes.
          </p>
        )}
        {err && !cur ? (
          <Empty icon={ShieldAlert} title="Couldn’t load the attack history" hint={err} />
        ) : !cur ? (
          <div className="space-y-2 px-5 pb-5">{Array.from({ length: 6 }).map((_, i) => <div key={i} className="aa-skeleton h-11 rounded-lg" />)}</div>
        ) : rows.length === 0 ? (
          <Empty icon={ShieldCheck} title={total || filtered ? 'No attacks match these filters' : 'No attacks recorded'} hint={filtered ? 'Clear the filters to see every attack.' : 'Nothing has triggered the detector yet.'} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px] text-left text-[13px]">
              <thead>
                <tr className="border-y border-nd-line bg-nd-fill text-[11px] uppercase tracking-[0.06em] text-nd-dim">
                  {COLS.map((c) => (
                    <th key={c.key} className={`px-4 py-2 font-medium first:pl-5 ${c.right ? 'text-right' : ''}`}>
                      <button onClick={() => setSort((x) => ({ key: c.key, desc: x.key === c.key ? !x.desc : true }))} className={`inline-flex items-center gap-1 hover:text-nd-fg ${sort.key === c.key ? 'text-nd-fg' : ''}`}>
                        {c.label}{sort.key === c.key ? (sort.desc ? ' ↓' : ' ↑') : ''}
                      </button>
                    </th>
                  ))}
                  <th className="px-4 py-2 font-medium">Attack type</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((a) => (
                  <tr key={a.id} onClick={() => !a.partial && openAttack(a.id)} className={`group border-b border-nd-line-soft transition-colors last:border-0 ${a.partial ? '' : 'cursor-pointer hover:bg-nd-fill'}`}>
                    <td className="py-3 pl-5 pr-4">
                      <div className="font-medium text-nd-fg">{when(a.start)}</div>
                      <div className="text-[11.5px] text-nd-dim">{a.partial ? 'being analysed…' : a.target?.label ?? 'target unknown'}</div>
                    </td>
                    <td className="mono px-4 py-3 text-right text-nd-fg-3">{duration(a.durationSec)}</td>
                    <td className="mono px-4 py-3 text-right font-medium text-nd-fg">{a.partial ? '…' : bps(a.peakBps)}</td>
                    <td className="mono px-4 py-3 text-right text-nd-fg-3">{a.partial ? '…' : pps(a.peakPps)}</td>
                    <td className="mono px-4 py-3 text-right text-nd-fg-3">{a.partial ? '…' : si(a.droppedPackets)}</td>
                    <td className="px-4 py-3 text-right">{a.partial ? <Badge>…</Badge> : <Badge tone={blockedTone(a.dropShare)}>{(a.dropShare * 100).toFixed(0)}%</Badge>}</td>
                    <td className="px-4 py-3">
                      <div className="flex max-w-[300px] flex-wrap gap-1">
                        {a.partial ? <Badge>retrying</Badge> : vectorsOf(a).slice(0, 3).map((v) => <Badge key={v}>{pretty(v)}</Badge>)}
                        {!a.partial && vectorsOf(a).length > 3 && <Badge>+{vectorsOf(a).length - 3}</Badge>}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pager page={page} pages={nPages} first={firstShown} last={lastShown} total={total} busy={busy} onPage={goPage} />
          </div>
        )}
      </Panel>

      {sel && (
        <Drawer
          a={sel}
          retentionDays={cur?.retentionDays ?? deep?.retentionDays ?? 15}
          onClose={() => openAttack(null)}
          onExplore={() => {
            const pad = Math.max(120, Math.round(sel.durationSec * 0.5))
            rng.setCustom(Math.floor(sel.start / 1000) - pad, Math.ceil(sel.end / 1000) + pad)
            router.push('/analytics/explore?metric=ingress_bps&by=iface')
          }}
        />
      )}
      {!sel && deepState && deepState.id === open && (
        <div className="fixed inset-0 z-50" role="dialog" aria-modal="true" aria-label="Loading attack">
          <button aria-label="Close" onClick={() => openAttack(null)} className="absolute inset-0 bg-black/30 backdrop-blur-[2px]" />
          <div className="aa-in absolute inset-y-0 right-0 flex w-full max-w-[900px] flex-col items-center justify-center gap-3 border-l border-nd-line bg-nd-bg px-6 text-center shadow-nd-lg">
            {deepState.error ? (
              <>
                <ShieldAlert className="h-6 w-6 text-nd-dim" />
                <p className="text-[14px] font-medium text-nd-fg">Couldn’t open that attack</p>
                <p className="max-w-sm text-[12.5px] text-nd-dim">{deepState.error}</p>
                <button onClick={() => openAttack(null)} className={btn.ghost}>Show all attacks</button>
              </>
            ) : (
              <><Loader2 className="h-5 w-5 animate-spin text-nd-dim" /><p className="text-[13px] text-nd-dim">Loading attack…</p></>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// Pager for uneven pages (20 first, then 10): numbers, prev/next, and the range shown.
function Pager({ page, pages, first, last, total, busy, onPage }: { page: number; pages: number; first: number; last: number; total: number; busy: boolean; onPage: (p: number) => void }) {
  const nums = Array.from(new Set([1, 2, page - 1, page, page + 1, pages - 1, pages].filter((p) => p >= 1 && p <= pages))).sort((a, b) => a - b)
  const btnCls = 'grid h-8 min-w-8 place-items-center rounded-lg border px-2 text-[12.5px] transition-colors disabled:opacity-40'
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-t border-nd-line px-5 py-3">
      <span className="text-[12.5px] text-nd-dim">
        Showing <b className="text-nd-fg-2">{first}–{last}</b> of <b className="text-nd-fg-2">{total}</b> attacks{busy && <Loader2 className="ml-2 inline h-3.5 w-3.5 animate-spin" />}
      </span>
      <div className="flex items-center gap-1">
        <button onClick={() => onPage(page - 1)} disabled={page <= 1} className={`${btnCls} border-nd-line bg-nd-card text-nd-fg-3 hover:text-nd-fg`} aria-label="Previous page"><ChevronLeft className="h-4 w-4" /></button>
        {nums.map((p, i) => (
          <span key={p} className="flex items-center gap-1">
            {i > 0 && p - nums[i - 1] > 1 && <span className="px-1 text-nd-faint">…</span>}
            <button onClick={() => onPage(p)} aria-current={p === page ? 'page' : undefined}
              className={`${btnCls} ${p === page ? 'border-nd-fg bg-nd-fg text-nd-bg' : 'border-nd-line bg-nd-card text-nd-fg-3 hover:text-nd-fg'}`}>{p}</button>
          </span>
        ))}
        <button onClick={() => onPage(page + 1)} disabled={page >= pages} className={`${btnCls} border-nd-line bg-nd-card text-nd-fg-3 hover:text-nd-fg`} aria-label="Next page">
          {page < pages ? <span className="flex items-center gap-1 px-1">Next 10 <ChevronRight className="h-4 w-4" /></span> : <ChevronRight className="h-4 w-4" />}
        </button>
      </div>
    </div>
  )
}
