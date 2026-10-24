'use client'
import { useMemo } from 'react'
import Link from 'next/link'
import { instantAt, rangeAbs, scalar, toSeries, type RangeResult } from '@/lib/prom'
import { usePoll } from '@/hooks/usePoll'
import { fetchAttacks, vectorsOf } from '@/lib/attacks'
import { bps, pps, duration, si, pretty } from '@/lib/format'
import { quantile } from '@/lib/stats'
import { SERIES, type Status } from '@/components/nd/ui'
import { Panel, Stat, Badge, Empty, trend, type Tone } from '@/components/aa/kit'
import { Inbox, HardDrive, Ban, Percent, Gauge, HeartPulse, Sparkles, AlertTriangle, ShieldAlert, Info, CheckCircle2, ArrowRight, Clock, Activity, type LucideIcon } from 'lucide-react'
import { TimeChart } from '@/components/nd/charts'
import { useRange } from '@/components/aa/Shell'

// Overview: the window's key numbers plus automatically generated insights —
// floods (and whether the detector flagged them), traffic peaks, a dominant
// attack source, handshake imbalance, kernel drops and agent downtime. Each
// insight links to the page that lets you dig into it.

interface Insight { sev: Status; title: string; detail: string; at?: number; href?: string; cta?: string }
const SEV_LABEL: Record<Status, string> = { crit: 'Critical', serious: 'High', warn: 'Warning', good: 'OK', neutral: 'Info' }
const SEV_RANK: Record<Status, number> = { crit: 0, serious: 1, warn: 2, neutral: 3, good: 4 }
const vals = (r: RangeResult[]) => (r[0]?.values ?? []).map(([t, v]) => [t, parseFloat(v)] as [number, number])
const hhmm = (sec: number) => new Date(sec * 1000).toLocaleString([], { weekday: 'short', hour: '2-digit', minute: '2-digit' })

export default function Overview() {
  const rng = useRange()
  const hist = usePoll(fetchAttacks, 120_000)
  const q = usePoll(async () => {
    const w = rng.resolve()
    const R = `${w.span}s`
    const inc = (m: string, off = false) => instantAt(`sum(increase(${m}[${R}]${off ? ` offset ${R}` : ''}))`, w.end)
    const wd = (m: string, l: string) => `(sum by(${l})(${m}) - sum by(${l})(${m} offset ${R})) or sum by(${l})(${m})`
    const [rxP, rxB, dropP, rlP, syn, synack, avail, nic, rxPp, dropPp, topSrc, allSrc, ing, rx, drop, det, lvl] = await Promise.all([
      inc('xs_rx_packets_total'),
      inc('xs_rx_bytes_total'),
      inc('xs_verdict_packets_total{verdict="drop"}'),
      inc('xs_policy_event_packets_total{event="rate_limited"}'),
      inc('xs_tcp_flags_packets_total{class="syn"}'),
      inc('xs_tcp_flags_packets_total{class="synack"}'),
      instantAt(`avg_over_time(up{job="xdp-sentinel-agent"}[${R}])`, w.end),
      inc('node_network_receive_drop_total{device="enp1s0"}'),
      inc('xs_rx_packets_total', true),
      inc('xs_verdict_packets_total{verdict="drop"}', true),
      instantAt(`topk(1, clamp_min(${wd('xs_attacker_packets_total', 'src')}, 0))`, w.end),
      instantAt(`sum(clamp_min(${wd('xs_attacker_packets_total', 'src')}, 0))`, w.end),
      rangeAbs(`sum(rate(xs_rx_bytes_total[${w.rw}]))*8`, w.start, w.end, w.step),
      rangeAbs(`sum(rate(xs_rx_packets_total[${w.rw}]))`, w.start, w.end, w.step),
      rangeAbs(`sum(rate(xs_verdict_packets_total{verdict="drop"}[${w.rw}]))`, w.start, w.end, w.step),
      rangeAbs(`max(max_over_time(xs_detection_active[${w.rw}]))`, w.start, w.end, w.step),
      rangeAbs(`max(max_over_time(xs_risk_level[${w.rw}]))`, w.start, w.end, w.step),
    ])
    return {
      w,
      rxP: scalar(rxP, 0)!, rxB: scalar(rxB, 0)!, dropP: scalar(dropP, 0)!, rlP: scalar(rlP, 0)!,
      syn: scalar(syn, 0)!, synack: scalar(synack, 0)!, avail: scalar(avail), nic: scalar(nic, 0)!,
      rxPp: scalar(rxPp, 0)!, dropPp: scalar(dropPp, 0)!,
      top: topSrc[0] ? { ip: topSrc[0].metric.src, v: parseFloat(topSrc[0].value[1]) } : null,
      allSrc: scalar(allSrc, 0)!,
      ing: vals(ing), rx: vals(rx), drop: vals(drop), det: vals(det), lvl: vals(lvl),
      chart: { ing: toSeries(ing, () => 'ingress'), drop: toSeries(drop, () => 'dropped') },
    }
  }, rng.refreshMs, [rng.key])

  const d = q.data
  const rangeQ = rng.preset !== 'custom' ? `&range=${rng.preset}` : ''

  const insights = useMemo<Insight[]>(() => {
    if (!d) return []
    const out: Insight[] = []
    const step = d.w.step
    const rxMed = quantile(d.rx.map(([, v]) => v).filter(Number.isFinite).sort((a, b) => a - b), 0.5) || 0
    const detAt = new Map(d.det.map(([t, v]) => [t, v]))
    const lvlAt = new Map(d.lvl.map(([t, v]) => [t, v]))
    const ingAt = new Map(d.ing.map(([t, v]) => [t, v]))

    // floods: contiguous runs where drops tower over normal traffic
    const thr = Math.max(500, rxMed * 10)
    const segs: { s: number; e: number; peak: number; total: number; det: boolean; lvl: number; ing: number }[] = []
    for (const [t, v] of d.drop) {
      if (!(v > thr)) continue
      const last = segs.at(-1)
      if (last && t - last.e <= step * 2) {
        last.e = t; last.peak = Math.max(last.peak, v); last.total += v * step
      } else segs.push({ s: t, e: t, peak: v, total: v * step, det: false, lvl: 0, ing: 0 })
    }
    for (const g of segs) {
      for (let t = g.s; t <= g.e; t += step) {
        if ((detAt.get(t) ?? 0) > 0) g.det = true
        g.lvl = Math.max(g.lvl, lvlAt.get(t) ?? 0)
        g.ing = Math.max(g.ing, ingAt.get(t) ?? 0)
      }
    }
    for (const g of [...segs].sort((a, b) => b.total - a.total).slice(0, 3)) {
      const len = Math.max(step, g.e - g.s + step)
      out.push({
        sev: g.det ? 'warn' : 'crit',
        title: g.det ? `Flood detected and dropped at ${hhmm(g.s)}` : `Flood at ${hhmm(g.s)} was dropped but never flagged as an attack`,
        detail: `${duration(len)} long, peaking at ${pps(g.peak)} dropped (${bps(g.ing)} ingress), about ${si(g.total)} packets in total. Risk level reached ${Math.round(g.lvl)}.${g.det ? '' : ' The rule-based detector stayed inactive, so it is missing from the attack history — worth checking its thresholds.'}`,
        at: g.s,
        href: `/analytics/explore?metric=drop_pps${rangeQ}`,
        cta: 'See drops in Explorer',
      })
    }

    // dominant source
    if (d.top && d.allSrc > 0 && d.top.v / d.allSrc >= 0.5 && d.top.v > 1000) {
      out.push({
        sev: 'warn',
        title: `One source sent ${((d.top.v / d.allSrc) * 100).toFixed(0)}% of the dropped attack packets`,
        detail: `${d.top.ip} accounts for ${si(d.top.v)} of ${si(d.allSrc)} dropped attack packets in this window — a targeted rather than spoofed attack.`,
        href: `/analytics/ip?ip=${encodeURIComponent(d.top.ip)}`,
        cta: 'Investigate this IP',
      })
    }

    // handshake imbalance
    if (d.synack > 0 && d.syn / d.synack > 3 && d.syn > 10_000) {
      out.push({
        sev: 'warn',
        title: `${(d.syn / d.synack).toFixed(1)} SYNs for every SYN-ACK`,
        detail: `${si(d.syn)} SYN vs ${si(d.synack)} SYN-ACK — many handshakes were never answered, the signature of a SYN flood or a scan.`,
        href: `/analytics/explore?metric=tcp_flags_pps&by=class${rangeQ}`,
        cta: 'See TCP flags',
      })
    }

    // kernel drops
    if (d.nic > 0) {
      out.push({
        sev: 'crit',
        title: `${si(d.nic)} frames lost in the kernel before XDP`,
        detail: 'The network card dropped frames the filter never saw — a sign the box was overloaded.',
        href: `/analytics/explore?metric=nic_drops${rangeQ}`,
        cta: 'See NIC drops',
      })
    }

    // agent downtime
    if (d.avail != null && d.avail < 0.999) {
      out.push({
        sev: d.avail < 0.95 ? 'crit' : 'warn',
        title: `Agent available ${(d.avail * 100).toFixed(2)}% of the time`,
        detail: `About ${duration((1 - d.avail) * d.w.span)} without metrics from the sentinel agent in this window.`,
      })
    }

    // traffic peak
    const peak = d.ing.reduce((m, p) => (p[1] > m[1] ? p : m), [0, -1] as [number, number])
    const ingMed = quantile(d.ing.map(([, v]) => v).filter(Number.isFinite).sort((a, b) => a - b), 0.5) || 0
    if (peak[1] > 0) {
      out.push({
        sev: 'neutral',
        title: `Traffic peaked at ${bps(peak[1])} on ${hhmm(peak[0])}`,
        detail: ingMed > 0 ? `${(peak[1] / ingMed).toFixed(peak[1] / ingMed >= 10 ? 0 : 1)}× the typical ${bps(ingMed)} for this window.` : 'Traffic was otherwise near zero.',
        href: `/analytics/explore?metric=ingress_bps&by=iface${rangeQ}`,
        cta: 'See bandwidth',
      })
    }

    // recorded episodes
    const eps = (hist.data?.attacks ?? []).filter((a) => a.end / 1000 >= d.w.start && a.start / 1000 <= d.w.end)
    if (eps.length) {
      out.push({
        sev: 'warn',
        title: `${eps.length} recorded attack episode${eps.length === 1 ? '' : 's'} in this window`,
        detail: eps.slice(0, 3).map((a) => `${vectorsOf(a).map(pretty).slice(0, 2).join(', ')} (${duration(a.durationSec)}, ${bps(a.peakBps)})`).join(' · '),
        href: '/analytics/attacks',
        cta: 'Open attacks',
      })
    }

    if (!out.some((i) => i.sev === 'crit' || i.sev === 'warn')) {
      out.unshift({ sev: 'good', title: 'Nothing unusual in this window', detail: 'No floods, no dominant source, no kernel drops and the agent was up throughout.' })
    }
    return out.sort((a, b) => SEV_RANK[a.sev] - SEV_RANK[b.sev])
  }, [d, hist.data, rangeQ])

  const ratio = d && d.rxP > 0 ? d.dropP / d.rxP : null
  const ratioPrev = d && d.rxPp > 0 ? d.dropPp / d.rxPp : null
  const prevLabel = rng.preset !== 'custom' ? `vs prev ${rng.preset}` : 'vs previous window'
  const spark = (v: [number, number][]) => v.map(([t, x]) => ({ t: t * 1000, v: Number.isFinite(x) ? x : 0 }))
  const SEV: Record<Status, { icon: LucideIcon; tone: Tone; stripe: string; label: string }> = {
    crit: { icon: AlertTriangle, tone: 'bad', stripe: 'bg-st-crit', label: 'Critical' },
    serious: { icon: AlertTriangle, tone: 'bad', stripe: 'bg-st-serious', label: 'High' },
    warn: { icon: ShieldAlert, tone: 'warn', stripe: 'bg-st-warn', label: 'Warning' },
    neutral: { icon: Info, tone: 'neutral', stripe: 'bg-st-neutral', label: 'Info' },
    good: { icon: CheckCircle2, tone: 'good', stripe: 'bg-st-good', label: 'All clear' },
  }
  const counts = insights.reduce((m, i) => ({ ...m, [i.sev]: (m[i.sev] ?? 0) + 1 }), {} as Partial<Record<Status, number>>)

  return (
    <div className="space-y-6">
      {q.error && !d && (
        <div className="flex items-center gap-2 rounded-xl border border-st-crit/30 bg-st-crit/[0.06] px-4 py-3 text-[13px] text-st-crit-fg">
          <AlertTriangle className="h-4 w-4" /> Can&apos;t load data: {q.error}
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
        <Stat label="Packets received" icon={Inbox} loading={!d} value={si(d?.rxP)} trend={trend(d?.rxP, d?.rxPp)} trendLabel={prevLabel} spark={d ? spark(d.rx) : undefined} color="var(--s4)" />
        <Stat label="Data received" icon={HardDrive} loading={!d} value={si(d?.rxB, 'B')} sub={d ? `avg ${bps((d.rxB * 8) / d.w.span)}` : undefined} spark={d ? spark(d.ing) : undefined} color="var(--s1)" />
        <Stat label="Packets dropped" icon={Ban} loading={!d} value={si(d?.dropP)} trend={trend(d?.dropP, d?.dropPp, true)} trendLabel={prevLabel} spark={d ? spark(d.drop) : undefined} color="var(--s2)" />
        <Stat label="Drop ratio" icon={Percent} loading={!d} value={ratio != null ? `${(ratio * 100).toFixed(2)}%` : '—'} trend={trend(ratio, ratioPrev, true)} trendLabel={prevLabel} />
        <Stat label="Rate-limited" icon={Gauge} loading={!d} value={si(d?.rlP)} sub="packets capped per source" />
        <Stat
          label="Agent availability"
          icon={HeartPulse}
          loading={!d}
          value={d?.avail != null ? `${(d.avail * 100).toFixed(2)}%` : '—'}
          sub={d?.avail != null ? (d.avail >= 0.999 ? 'no downtime' : `${duration((1 - d.avail) * d.w.span)} down`) : undefined}
        />
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-5">
        <Panel
          className="xl:col-span-3"
          icon={Sparkles}
          title="Insights"
          sub="Generated automatically from this window"
          actions={
            d && (
              <div className="flex gap-1.5">
                {counts.crit ? <Badge tone="bad">{counts.crit} critical</Badge> : null}
                {counts.warn ? <Badge tone="warn">{counts.warn} warning{counts.warn > 1 ? 's' : ''}</Badge> : null}
              </div>
            )
          }
        >
          {!d ? (
            <div className="space-y-3">{[0, 1, 2].map((i) => <div key={i} className="aa-skeleton h-[92px] rounded-xl" />)}</div>
          ) : insights.length === 0 ? (
            <Empty icon={CheckCircle2} title="Nothing to report" />
          ) : (
            <ul className="space-y-3">
              {insights.map((i, n) => {
                const S = SEV[i.sev]
                return (
                  <li key={n} className="aa-in relative overflow-hidden rounded-xl border border-nd-line bg-nd-card pl-5 pr-4 py-3.5 transition-shadow hover:shadow-nd" style={{ animationDelay: `${n * 40}ms` }}>
                    <span className={`absolute inset-y-0 left-0 w-1 ${S.stripe}`} />
                    <div className="flex items-start gap-3">
                      <S.icon className={`mt-0.5 h-4 w-4 shrink-0 ${i.sev === 'crit' || i.sev === 'serious' ? 'text-st-crit-fg' : i.sev === 'warn' ? 'text-st-warn-fg' : i.sev === 'good' ? 'text-st-good-fg' : 'text-nd-dim'}`} />
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <h3 className="text-[14px] font-semibold leading-snug tracking-[-0.01em] text-nd-fg">{i.title}</h3>
                        </div>
                        <p className="mt-1 text-[13px] leading-relaxed text-nd-muted">{i.detail}</p>
                        <div className="mt-2.5 flex flex-wrap items-center gap-2">
                          <Badge tone={S.tone}>{S.label}</Badge>
                          {i.at && <Badge icon={Clock}>{hhmm(i.at)}</Badge>}
                          {i.href && (
                            <Link href={i.href} className="ml-auto inline-flex items-center gap-1 text-[12.5px] font-medium text-nd-fg-2 hover:text-nd-fg">
                              {i.cta ?? 'Explore'} <ArrowRight className="h-3.5 w-3.5" />
                            </Link>
                          )}
                        </div>
                      </div>
                    </div>
                  </li>
                )
              })}
            </ul>
          )}
        </Panel>
        <div className="space-y-6 xl:col-span-2">
          <Panel icon={Activity} title="Ingress" sub="Bits per second" actions={<Link href={`/analytics/explore?metric=ingress_bps&by=iface${rangeQ}`} className="text-[12px] font-medium text-nd-dim hover:text-nd-fg">Explore</Link>}>
            <TimeChart kind="area" loading={!d} data={d?.chart.ing ?? []} series={[{ key: 'ingress', label: 'Ingress', color: SERIES[0] }]} yfmt={bps} spanMs={(d?.w.span ?? 3600) * 1000} height={180} />
          </Panel>
          <Panel icon={Ban} title="Dropped" sub="Packets per second" actions={<Link href={`/analytics/explore?metric=drop_pps${rangeQ}`} className="text-[12px] font-medium text-nd-dim hover:text-nd-fg">Explore</Link>}>
            <TimeChart loading={!d} data={d?.chart.drop ?? []} series={[{ key: 'dropped', label: 'Dropped', color: SERIES[1] }]} yfmt={pps} spanMs={(d?.w.span ?? 3600) * 1000} height={180} />
          </Panel>
        </div>
      </div>
    </div>
  )
}
