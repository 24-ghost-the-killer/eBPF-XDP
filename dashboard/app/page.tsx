'use client'
import { useEffect, useState } from 'react'
import { instant, range, scalar, toSeries, talkers, type Metric, type RangeResult, type InstantResult } from '@/lib/prom'
import { usePoll } from '@/hooks/usePoll'
import { useEventLog } from '@/hooks/useEventLog'
import { useAlerts } from '@/hooks/useAlerts'
import { pps, bps, duration } from '@/lib/format'
import LineCard from '@/components/LineCard'
import TopTalkers from '@/components/TopTalkers'
import RatesTable, { type RateRow } from '@/components/RatesTable'
import Breakdown, { type BreakdownRow } from '@/components/Breakdown'
import LogConsole from '@/components/LogConsole'
import CommandHeader from '@/components/wall/CommandHeader'
import Ticker from '@/components/wall/Ticker'
import Radar from '@/components/noc/Radar'
import Gauge from '@/components/noc/Gauge'
import MetricTile from '@/components/noc/MetricTile'
import RiskEngine, { type RiskData } from '@/components/wall/RiskEngine'
import Defenses, { type DefenseData } from '@/components/wall/Defenses'
import ClassProbs from '@/components/wall/ClassProbs'
import Attacks from '@/components/wall/Attacks'
import CommandMenu, { type WallSection } from '@/components/app/CommandMenu'
import Icon, { type IconName } from '@/components/app/icons'

const tag = (rs: RangeResult[], f: (m: Metric) => string): RangeResult[] =>
  rs.map((s) => ({ metric: { k: f(s.metric) }, values: s.values }))
const byIface = (r: InstantResult[]) =>
  Object.fromEntries(r.map((s) => [s.metric.iface ?? '_', parseFloat(s.value[1])]))

type TabId = 'overview' | 'traffic' | 'security' | 'attacks' | 'system' | 'telemetry'
const TABS: { id: TabId; label: string; icon: IconName; hint: string }[] = [
  { id: 'overview', label: 'Overview', icon: 'grid', hint: 'posture · load · vitals' },
  { id: 'traffic', label: 'Traffic', icon: 'activity', hint: 'charts · network · talkers' },
  { id: 'security', label: 'Security · AI', icon: 'shield', hint: 'risk engine · defenses' },
  { id: 'attacks', label: 'Attacks', icon: 'pulse', hint: 'DDoS attack history' },
  { id: 'system', label: 'System', icon: 'cpu', hint: 'capacity · ML · health' },
  { id: 'telemetry', label: 'Telemetry', icon: 'terminal', hint: 'full event log' },
]
const PALETTE: WallSection[] = TABS.map((t) => ({ id: t.id, label: t.label, group: 'Views', hint: t.hint, icon: t.icon }))

// titled panel header
function Panel({ title, right, children }: { title: string; right?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section>
      <div className="mb-2.5 flex items-center justify-between">
        <span className="eyebrow">{title}</span>
        {right}
      </div>
      {children}
    </section>
  )
}

export default function Page() {
  const log = useEventLog(3000)
  const [cmdOpen, setCmdOpen] = useState(false)
  const [tab, setTab] = useState<TabId>('overview')
  const [now, setNow] = useState<Date | null>(null)
  useEffect(() => {
    setNow(new Date())
    const id = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(id)
  }, [])

  const status = usePoll(async () => {
    const [up, posture, drop, pass, rl, cap, sw, ingress, syn, conn, anom] = await Promise.all([
      instant('up{job="xdp-sentinel-agent"}'),
      instant('count(ALERTS{alertstate="firing",severity=~"warning|critical"}) or vector(0)'),
      instant('sum(rate(xs_verdict_packets_total{verdict="drop"}[1m]))'),
      instant('sum(rate(xs_verdict_packets_total{verdict="pass"}[1m]))'),
      instant('sum(rate(xs_policy_event_packets_total{event="rate_limited"}[1m]))'),
      instant('xs_capacity_max_block_bps'),
      instant('up{job="switch"}'),
      instant('sum(rate(xs_rx_bytes_total[1m]))*8'),
      instant('sum(rate(xs_tcp_flags_packets_total{class="syn"}[1m]))'),
      instant('sum(rate(xs_conntrack_packets_total[1m]))'),
      instant('sum(rate(xs_anomaly_packets_total[1m]))'),
    ])
    return {
      up: scalar(up, 0)!, posture: scalar(posture, 0)!, drop: scalar(drop, 0)!,
      pass: scalar(pass, 0)!, rl: scalar(rl, 0)!, cap: scalar(cap), sw: scalar(sw, 0)!,
      ingress: scalar(ingress, 0)!, syn: scalar(syn, 0)!, conn: scalar(conn, 0)!, anom: scalar(anom, 0)!,
    }
  }, 5000)

  const spark = usePoll(async () => {
    const [ing, drp] = await Promise.all([
      range('sum(rate(xs_rx_bytes_total[1m]))*8', 30, 60),
      range('sum(rate(xs_verdict_packets_total{verdict="drop"}[1m]))', 30, 60),
    ])
    return { bps: toSeries(ing, () => 'bps'), drop: toSeries(drp, () => 'drop') }
  }, 15000)

  const charts = usePoll(async () => {
    const [rx, dr, flags] = await Promise.all([
      range('sum by(iface)(rate(xs_rx_packets_total[1m]))', 60, 30),
      range('sum by(iface)(rate(xs_verdict_packets_total{verdict="drop"}[1m]))', 60, 30),
      range('sum by(class)(rate(xs_tcp_flags_packets_total[1m]))', 60, 30),
    ])
    return {
      txData: toSeries([...tag(rx, (m) => `rx ${m.iface}`), ...tag(dr, (m) => `drop ${m.iface}`)], (m) => m.k),
      txKeys: [...rx.map((s) => `rx ${s.metric.iface}`), ...dr.map((s) => `drop ${s.metric.iface}`)],
      flagData: toSeries(flags, (m) => m.class),
      flagKeys: flags.map((s) => s.metric.class),
    }
  }, 10000)

  const net = usePoll(async () => {
    const [l3, l4, vlan] = await Promise.all([
      instant('sum by(proto)(rate(xs_l3_packets_total[1m]))'),
      instant('sum by(proto)(rate(xs_l4_packets_total[1m]))'),
      instant('sum by(tags)(rate(xs_vlan_packets_total[1m]))'),
    ])
    const L3: Record<string, string> = { ipv4: 'bg-sky-500', ipv6: 'bg-indigo-500', arp: 'bg-amber-500', other: 'bg-zinc-500' }
    const L4: Record<string, string> = { tcp: 'bg-emerald-500', udp: 'bg-violet-500', icmp: 'bg-amber-500', icmpv6: 'bg-orange-500', other: 'bg-zinc-500' }
    const rows = (r: InstantResult[], colors: Record<string, string>): BreakdownRow[] =>
      r.map((s) => ({ label: s.metric.proto, v: parseFloat(s.value[1]), color: colors[s.metric.proto] ?? 'bg-zinc-500' }))
        .sort((a, b) => b.v - a.v)
    const l2: BreakdownRow[] = vlan.map((s) => ({ label: `${s.metric.tags} vlan tag(s)`, v: parseFloat(s.value[1]), color: 'bg-cyan-500' }))
    return { l3: rows(l3, L3), l4: rows(l4, L4), l2 }
  }, 5000)

  const counters = usePoll(async () => {
    const specs: Array<[string, string, boolean]> = [
      ['received', 'xs_rx_packets_total', false],
      ['passed', 'xs_verdict_packets_total{verdict="pass"}', false],
      ['dropped', 'xs_verdict_packets_total{verdict="drop"}', true],
      ['rate-limited', 'xs_policy_event_packets_total{event="rate_limited"}', true],
      ['tcp syn', 'xs_tcp_flags_packets_total{class="syn"}', false],
      ['tcp syn-ack', 'xs_tcp_flags_packets_total{class="synack"}', false],
      ['tcp ack', 'xs_tcp_flags_packets_total{class="ack"}', false],
      ['tcp rst', 'xs_tcp_flags_packets_total{class="rst"}', true],
      ['udp', 'xs_l4_packets_total{proto="udp"}', false],
      ['icmp', 'xs_l4_packets_total{proto="icmp"}', false],
      ['bad flags/anom', 'xs_anomaly_packets_total', true],
      ['conntrack miss', 'xs_conntrack_packets_total', true],
      ['malformed', 'xs_parse_outcome_packets_total{class="malformed"}', true],
    ]
    const res = await Promise.all(specs.map(([, m]) => instant(`sum by(iface)(rate(${m}[1m]))`)))
    return specs.map(([label, , warn], i): RateRow => {
      const m = byIface(res[i])
      return { label, v10: m['vlan10'] || 0, v20: m['vlan20'] || 0, warn }
    })
  }, 5000)

  const top = usePoll(async () => {
    const [tx, rx] = await Promise.all([
      instant('topk(8, rate(xs_talker_tx_bytes_total[5m])*8)'),
      instant('topk(8, rate(xs_talker_rx_bytes_total[5m])*8)'),
    ])
    return { tx: talkers(tx), rx: talkers(rx) }
  }, 10000)

  // AI risk engine + active-defense state.
  const risk = usePoll(async () => {
    const [
      threat, rsk, level, az, ddos, iforest, det, mit, mitRate, acts, apps, classesR, flagsR, layersR,
    ] = await Promise.all([
      instant('max(xs_threat_state)'),
      instant('max(xs_risk)'),
      instant('max(xs_risk_level)'),
      instant('max(xs_anomaly_score01)'),
      instant('max(xs_ddos_score)'),
      instant('max(xs_anomaly_iforest)'),
      instant('max(xs_detection_active)'),
      instant('max(xs_mitigation_active)'),
      instant('max(xs_mitigation_rate_pps)'),
      instant('sum(xs_auto_actions_total)'),
      instant('sum(xs_analysis_pps)'),
      instant('max by(class)(xs_ddos_class_probability)'),
      instant('xs_config_flag'),
      instant('max by(layer)(xs_layer_state)'),
    ])
    const flags: DefenseData['flags'] = {}
    for (const s of flagsR) {
      const ifc = s.metric.iface ?? '_'
      ;(flags[ifc] ??= {})[s.metric.flag] = parseFloat(s.value[1])
    }
    const riskData: RiskData = {
      threat: Math.round(scalar(threat, 0)!),
      risk: scalar(rsk, 0)!,
      level: Math.round(scalar(level, 0)!),
      anomalyZ: scalar(az, 0)!,
      ddos: scalar(ddos, 0)!,
      iforest: scalar(iforest),
      detection: scalar(det, 0)! > 0,
      mitigation: scalar(mit, 0)! > 0,
      mitRate: scalar(mitRate, 0)!,
      autoActions: Math.round(scalar(acts, 0)!),
      analysisPps: scalar(apps, 0)!,
      classes: classesR.map((s) => ({ label: s.metric.class, v: parseFloat(s.value[1]) })),
    }
    const defense: DefenseData = {
      flags,
      layers: layersR.map((s) => ({ layer: s.metric.layer, v: parseFloat(s.value[1]) })).sort((a, b) => a.layer.localeCompare(b.layer)),
    }
    return { riskData, defense }
  }, 5000)

  // Security KPI rates.
  const sec = usePoll(async () => {
    const q = (e: string) => instant(`sum(rate(${e}[1m]))`)
    const [synack, ack, rst, fin, dropped, malformed, connmiss, frag, ext, rtrack] = await Promise.all([
      q('xs_tcp_flags_packets_total{class="synack"}'),
      q('xs_tcp_flags_packets_total{class="ack"}'),
      q('xs_tcp_flags_packets_total{class="rst"}'),
      q('xs_tcp_flags_packets_total{class="fin"}'),
      q('xs_verdict_packets_total{verdict="drop"}'),
      q('xs_parse_outcome_packets_total{class="malformed"}'),
      q('xs_conntrack_packets_total'),
      q('xs_fragment_packets_total'),
      q('xs_ipv6_ext_packets_total'),
      q('xs_rate_tracked_packets_total'),
    ])
    return {
      synack: scalar(synack, 0)!, ack: scalar(ack, 0)!, rst: scalar(rst, 0)!, fin: scalar(fin, 0)!,
      dropped: scalar(dropped, 0)!, malformed: scalar(malformed, 0)!, connmiss: scalar(connmiss, 0)!,
      frag: scalar(frag, 0)!, ext: scalar(ext, 0)!, rtrack: scalar(rtrack, 0)!,
    }
  }, 5000)

  // Detector score trend (last hour).
  const secTrend = usePoll(async () => {
    const [z, ddos, rsk] = await Promise.all([
      range('max(xs_anomaly_score01)', 60, 30),
      range('max(xs_ddos_score)', 60, 30),
      range('max(xs_risk)', 60, 30),
    ])
    const data = toSeries(
      [
        ...tag(z, () => 'z-score'),
        ...tag(ddos, () => 'ddos'),
        ...tag(rsk, () => 'risk'),
      ],
      (m) => m.k
    )
    return { data, keys: ['z-score', 'ddos', 'risk'] }
  }, 15000)

  // Bench + host/health extras.
  const health = usePoll(async () => {
    const [mpps, nspp, cores, nicbps, tracked, dpAttached, collUp, talkUp, agentUp] = await Promise.all([
      instant('xs_bench_mpps_per_core'), instant('xs_bench_ns_per_packet'),
      instant('xs_capacity_cores_logical'), instant('xs_capacity_nic_link_bps'),
      instant('xs_talker_tracked_ips'), instant('max(xs_dataplane_attached)'),
      instant('max(xs_collector_up)'), instant('max(xs_talker_up)'), instant('max(xs_agent_up)'),
    ])
    return {
      mpps: scalar(mpps), nspp: scalar(nspp), cores: scalar(cores), nicbps: scalar(nicbps),
      tracked: scalar(tracked, 0)!, dpAttached: scalar(dpAttached, 0)! > 0,
      collUp: scalar(collUp, 0)! > 0, talkUp: scalar(talkUp, 0)! > 0, agentUp: scalar(agentUp, 0)! > 0,
    }
  }, 15000)

  const info = usePoll(async () => {
    const [capBps, cap64, head, prog, benign, suspect, uptime, swcpu, nicdrop] = await Promise.all([
      instant('xs_capacity_max_block_bps'), instant('xs_capacity_max_block_pps_64b'),
      instant('xs_capacity_headroom_ratio'), instant('xs_capacity_program_pps_total'),
      instant('xs_collector_windows_total'), instant('xs_collector_suspect_windows_total'),
      instant('sysUpTime{job="switch"}/100'), instant('gs1900_cpu_utilization_percent{job="switch-web"}'),
      instant('rate(node_network_receive_drop_total{device="enp1s0"}[5m])'),
    ])
    return {
      capBps: scalar(capBps), cap64: scalar(cap64), head: scalar(head), prog: scalar(prog),
      benign: scalar(benign, 0)!, suspect: scalar(suspect, 0)!, uptime: scalar(uptime),
      swcpu: scalar(swcpu), nicdrop: scalar(nicdrop, 0)!,
    }
  }, 30000)

  const s = status.data
  const attack = (s?.posture ?? 0) > 0
  const d = info.data
  const h = health.data
  const sc = sec.data
  const connected = !status.error

  // Load gauge — LOG-scaled pipe utilization. On a 1GbE link normal traffic is a
  // tiny fraction of capacity, so a linear ingress÷capacity reads 0% forever. A
  // log scale spreads the realistic range (kbps→Gbps) across the dial and never
  // false-alarms: ~50% at 100kbps, ~90% near 100Mbps.
  const cap = s?.cap ?? null
  const load =
    s?.ingress != null && cap && cap > 1
      ? Math.min(1, Math.max(0, Math.log10(Math.max(s.ingress, 1)) / Math.log10(cap)))
      : 0

  // Threat toasts on state transitions.
  useAlerts({
    attack,
    dropping: (s?.drop ?? 0) > 1,
    ratelimiting: (s?.rl ?? 0) > 1,
    ready: !!s,
  })

  // ---- views (each tab is a focused, lighter screen) ----
  const overview = (
    <div className="space-y-4">
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="panel panel-ticks flex flex-col items-center p-4 xl:col-span-3">
          <div className="eyebrow mb-3 self-start">Defense core</div>
          <Gauge value={load} center={`${Math.round(load * 100)}%`} sub="pipe utilization" size={168} />
          <div className="mt-4 grid w-full grid-cols-3 gap-2 text-center">
            <Mini label="drop" value={pps(s?.drop ?? 0)} tone={(s?.drop ?? 0) > 0 ? 'text-rose-400' : 'text-zinc-300'} />
            <Mini label="pass" value={pps(s?.pass ?? 0)} tone="text-emerald-400" />
            <Mini label="rl" value={pps(s?.rl ?? 0)} tone={(s?.rl ?? 0) > 0 ? 'text-amber-400' : 'text-zinc-300'} />
          </div>
          <div className="mt-3 w-full border-t border-white/[0.06] pt-3 text-center">
            <div className="text-[10px] uppercase tracking-[0.16em] text-zinc-500">max block capacity</div>
            <div className="mono mt-1 text-[22px] font-semibold text-sky-400">{bps(s?.cap ?? 0)}</div>
          </div>
        </div>
        <div className="xl:col-span-6">
          <LineCard title="Live traffic vs drops (pps) — all interfaces" data={charts.data?.txData ?? []} keys={charts.data?.txKeys ?? []} yfmt={pps} />
        </div>
        <div className="panel panel-ticks p-4 xl:col-span-3">
          <div className="eyebrow mb-2">Threat radar</div>
          <Radar talkers={top.data?.tx ?? []} attack={attack} />
          <div className="mt-1 flex items-center justify-center gap-4 text-[10px] text-zinc-500">
            <span className="flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />lan</span>
            <span className="flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-sky-400" />wan</span>
            <span className="flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-rose-400" />hostile</span>
          </div>
        </div>
      </section>
      <section className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
        <MetricTile label="Ingress" num={s?.ingress ?? null} fmt={bps} status="info" spark={spark.data?.bps} sparkKey="bps" tip="Live ingress bandwidth across all interfaces (last-minute rate)." />
        <MetricTile label="SYN rate" num={s?.syn ?? null} fmt={pps} status={(s?.syn ?? 0) > 150 ? 'warn' : 'neutral'} sub="tcp handshake/s" tip="New TCP handshakes per second; a sustained spike far above SYN-ACK is a SYN-flood signature." />
        <MetricTile label="Untracked TCP" num={s?.conn ?? null} fmt={pps} status={(s?.conn ?? 0) > 5 ? 'warn' : 'neutral'} sub="ACK/RST gauge" tip="TCP packets with no matching conntrack entry — the gauge for ACK/RST floods." />
        <MetricTile label="Anomalies" num={s?.anom ?? null} fmt={pps} status={(s?.anom ?? 0) > 0.5 ? 'warn' : 'neutral'} sub="bad flags / LAND" tip="Packets flagged malformed: illegal flag combos, LAND attacks, bad lengths." />
        <MetricTile label="Rate-limited" num={s?.rl ?? null} fmt={pps} status={(s?.rl ?? 0) > 0 ? 'warn' : 'neutral'} spark={spark.data?.drop} sparkKey="drop" tip="Packets capped by the per-source GCRA rate limiter." />
        <MetricTile label="NIC RX drops" num={d?.nicdrop ?? null} fmt={pps} status={(d?.nicdrop ?? 0) > 0 ? 'crit' : 'neutral'} sub={d?.swcpu != null ? `switch cpu ${d.swcpu.toFixed(0)}%` : 'kernel-level loss'} tip="Frames dropped by the kernel before XDP can see them — a true overload signal." />
      </section>
    </div>
  )

  const traffic = (
    <div className="space-y-4">
      <Panel title="Per-interface traffic">
        <LineCard title="Live traffic vs drops (pps) — all interfaces" data={charts.data?.txData ?? []} keys={charts.data?.txKeys ?? []} yfmt={pps} />
      </Panel>
      <Panel title="Network breakdown (L2 / L3 / L4)">
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <Breakdown title="L2 — VLAN tags" rows={net.data?.l2 ?? []} />
          <Breakdown title="L3 — network layer" rows={net.data?.l3 ?? []} />
          <Breakdown title="L4 — transport" rows={net.data?.l4 ?? []} />
        </div>
      </Panel>
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="Dataplane counters"><RatesTable title="per-interface counter rates" rows={counters.data ?? []} /></Panel>
        <Panel title="Top talkers">
          <div className="space-y-4">
            <TopTalkers title="Top senders" rows={top.data?.tx ?? []} />
            <TopTalkers title="Top receivers" rows={top.data?.rx ?? []} />
          </div>
        </Panel>
      </div>
    </div>
  )

  const security = (
    <div className="space-y-4">
      <Panel title="AI risk engine & active defenses">
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <RiskEngine d={risk.data?.riskData ?? null} />
          <Defenses d={risk.data?.defense ?? null} />
        </div>
      </Panel>

      <Panel title="Threat indicators (per-second rates)">
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-8">
          <MetricTile label="SYN-ACK" num={sc?.synack ?? null} fmt={pps} status="neutral" tip="SYN-ACK replies — far below SYN during a SYN-flood (half-open connections)." />
          <MetricTile label="ACK" num={sc?.ack ?? null} fmt={pps} status="neutral" tip="Bare ACK packets. A spike without a handshake is an ACK-flood." />
          <MetricTile label="RST" num={sc?.rst ?? null} fmt={pps} status={(sc?.rst ?? 0) > 50 ? 'warn' : 'neutral'} tip="TCP resets. Elevated RST can indicate RST-floods or scanning." />
          <MetricTile label="FIN" num={sc?.fin ?? null} fmt={pps} status="neutral" tip="TCP FIN packets — connection teardown." />
          <MetricTile label="Dropped" num={sc?.dropped ?? null} fmt={pps} status={(sc?.dropped ?? 0) > 0 ? 'crit' : 'good'} tip="Packets dropped by the XDP dataplane." />
          <MetricTile label="Malformed" num={sc?.malformed ?? null} fmt={pps} status={(sc?.malformed ?? 0) > 0.5 ? 'warn' : 'neutral'} tip="Frames rejected by the parser (truncated / illegal headers)." />
          <MetricTile label="Conntrack miss" num={sc?.connmiss ?? null} fmt={pps} status={(sc?.connmiss ?? 0) > 5 ? 'warn' : 'neutral'} tip="Packets with no conntrack entry — out-of-state / spoofed." />
          <MetricTile label="Fragments" num={sc?.frag ?? null} fmt={pps} status={(sc?.frag ?? 0) > 1 ? 'warn' : 'neutral'} tip="IP fragments. Non-first fragment floods are an evasion technique." />
          <MetricTile label="IPv6 ext-hdr" num={sc?.ext ?? null} fmt={pps} status={(sc?.ext ?? 0) > 0.5 ? 'warn' : 'neutral'} tip="IPv6 extension-header packets — watched for ext-chain evasion." />
          <MetricTile label="Rate-tracked" num={sc?.rtrack ?? null} fmt={pps} status="info" tip="Packets from sources currently under per-source rate tracking." />
          <MetricTile label="Untracked TCP" num={s?.conn ?? null} fmt={pps} status={(s?.conn ?? 0) > 5 ? 'warn' : 'neutral'} tip="TCP with no matching conntrack entry — ACK/RST-flood gauge." />
          <MetricTile label="Anomalies" num={s?.anom ?? null} fmt={pps} status={(s?.anom ?? 0) > 0.5 ? 'warn' : 'neutral'} tip="Bad-flags / LAND / bad-length packets flagged by the dataplane." />
        </div>
      </Panel>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="xl:col-span-2 space-y-4">
          <Panel title="Detector scores (last hour)">
            <LineCard title="Statistical z-score · DDoS classifier · fused risk (0–1)" data={secTrend.data?.data ?? []} keys={secTrend.data?.keys ?? []} yfmt={(n) => n.toFixed(2)} />
          </Panel>
          <Panel title="SYN-flood signature">
            <LineCard title="TCP flag mix (pps)" data={charts.data?.flagData ?? []} keys={charts.data?.flagKeys ?? []} yfmt={pps} />
          </Panel>
        </div>
        <div className="xl:col-span-1">
          <Panel title="Classifier confidence">
            <ClassProbs classes={risk.data?.riskData?.classes ?? []} />
          </Panel>
        </div>
      </div>
    </div>
  )

  const system = (
    <div className="space-y-4">
      <Panel title="Blocking capacity">
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <MetricTile label="Max throughput" num={d?.capBps ?? null} fmt={bps} status="good" sub="measured ceiling" />
          <MetricTile label="Max rate 64B" num={d?.cap64 ?? null} fmt={pps} status="good" sub="smallest frames" />
          <MetricTile label="Headroom" num={d?.head ?? null} fmt={(n) => `${Math.round(n)}×`} status="info" sub="vs live load" />
          <MetricTile label="Program cap" num={d?.prog ?? null} fmt={pps} status="info" sub="all 4 cores" />
        </div>
      </Panel>
      <Panel title="Performance & health">
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <MetricTile label="Throughput/core" num={h?.mpps ?? null} fmt={(n) => `${n.toFixed(1)} Mpps`} status="good" sub="benchmarked" />
          <MetricTile label="Latency/pkt" num={h?.nspp ?? null} fmt={(n) => `${Math.round(n)} ns`} status="good" sub="per-packet cost" />
          <MetricTile label="Tracked IPs" num={h?.tracked ?? null} fmt={(n) => Math.round(n).toLocaleString('en-US')} status="info" sub="per-source state" />
          <MetricTile label="Dataplane" value={h ? (h.dpAttached ? 'ATTACHED' : 'DOWN') : '…'} status={h?.dpAttached ? 'good' : 'crit'} sub="xdp program" />
        </div>
      </Panel>
      <Panel title="ML training & infrastructure">
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <MetricTile label="ML benign" num={d?.benign ?? null} fmt={(n) => Math.round(n).toLocaleString('en-US')} status="good" sub="clean windows" />
          <MetricTile label="ML suspect" num={d?.suspect ?? null} fmt={(n) => Math.round(n).toLocaleString('en-US')} status="warn" sub="quarantined" />
          <MetricTile label="Collector" value={h ? (h.collUp ? 'UP' : 'DOWN') : '…'} status={h?.collUp ? 'good' : 'warn'} sub="ML feature tap" />
          <MetricTile label="Switch" value={s ? (s.sw ? 'UP' : 'DOWN') : '…'} status={s?.sw ? 'good' : 'crit'} sub={d?.uptime != null ? `up ${duration(d.uptime)}` : undefined} />
        </div>
      </Panel>
    </div>
  )

  const attacks = (
    <Panel title="DDoS attack history (last 15 days)">
      <Attacks />
    </Panel>
  )

  const telemetry = (
    <div className="h-[calc(100vh-11rem)]">
      <LogConsole events={log} />
    </div>
  )

  const body =
    tab === 'overview' ? overview
    : tab === 'traffic' ? traffic
    : tab === 'security' ? security
    : tab === 'attacks' ? attacks
    : tab === 'system' ? system
    : telemetry

  return (
    <div className="flex min-h-screen flex-col">
      <CommandMenu open={cmdOpen} setOpen={setCmdOpen} sections={PALETTE} onGo={(id) => setTab(id as TabId)} />
      <CommandHeader
        attack={attack}
        up={!!s?.up}
        connected={connected}
        now={now}
        ingress={s?.ingress ?? null}
        drop={s?.drop ?? null}
        pass={s?.pass ?? null}
        rl={s?.rl ?? null}
        load={load}
        onCommand={() => setCmdOpen(true)}
      />

      {/* tab bar */}
      <nav className="sticky top-[47px] z-20 flex gap-1 overflow-x-auto border-b border-white/[0.06] bg-[#07070a]/85 px-3 py-1.5 backdrop-blur-xl lg:px-6">
        {TABS.map((t) => {
          const active = tab === t.id
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-2 whitespace-nowrap rounded-lg px-3 py-1.5 text-[12.5px] font-medium transition-colors ${
                active
                  ? 'bg-emerald-500/[0.1] text-zinc-50 ring-1 ring-inset ring-emerald-500/25'
                  : 'text-zinc-500 hover:bg-white/[0.03] hover:text-zinc-200'
              }`}
            >
              <Icon name={t.icon} className={`h-[15px] w-[15px] ${active ? 'text-emerald-400' : ''}`} />
              {t.label}
              {t.id === 'security' && attack && <span className="h-1.5 w-1.5 rounded-full bg-rose-400 animate-pulse" />}
            </button>
          )
        })}
      </nav>

      <main className="flex-1 px-4 py-4 lg:px-6">
        {status.error && (
          <div className="mb-4 rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-2.5 text-sm text-amber-300">
            Can&apos;t reach Prometheus ({status.error}). The dashboard proxies{' '}
            <code className="text-amber-200">/api/prom → localhost:9091</code> on the server.
          </div>
        )}
        {body}
        <footer className="mt-5 pb-2 text-center font-mono text-[10px] text-zinc-600">
          xdp-sentinel console · data via /api/prom → Prometheus · L2–L4 dataplane (no L7)
        </footer>
      </main>

      <Ticker events={log} />
    </div>
  )
}

function Mini({ label, value, tone }: { label: string; value: string; tone: string }) {
  return (
    <div className="rounded-md border border-white/[0.06] bg-white/[0.015] py-1.5">
      <div className="text-[8.5px] uppercase tracking-[0.14em] text-zinc-600">{label}</div>
      <div className={`mono mt-0.5 text-[12px] font-semibold tabular-nums ${tone}`}>{value}</div>
    </div>
  )
}
