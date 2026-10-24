// Metric catalogue for the analytics Explorer: every series the appliance
// exports, how to query it as a time series, which labels it can be split by,
// and its unit (which picks the formatter and whether a window total makes
// sense). `rw` is the rate window; `by` a label to split on, or null.

import { si, pps, bps } from '@/lib/format'

export type Unit = 'bps' | 'pps' | 'bytes' | 'ratio' | 'score' | 'level'
export interface MetricDef {
  id: string
  label: string
  group: 'Traffic' | 'Defense' | 'Protocols' | 'Detection' | 'Host'
  unit: Unit
  help: string
  dims: string[]
  build: (rw: string, by: string | null) => string
}

const agg = (by: string | null, fn = 'sum') => (by ? `${fn} by(${by})` : fn)
const rate = (sel: string) => (rw: string, by: string | null) => `${agg(by)}(rate(${sel}[${rw}]))`
const gauge = (sel: string) => (_rw: string, by: string | null) => `${agg(by, 'max')}(${sel})`

export const METRICS: MetricDef[] = [
  // traffic
  { id: 'ingress_bps', label: 'Ingress bandwidth', group: 'Traffic', unit: 'bps', dims: ['iface'],
    help: 'Bits per second seen by the XDP program.', build: (rw, by) => `${rate('xs_rx_bytes_total')(rw, by)}*8` },
  { id: 'rx_pps', label: 'Packets received', group: 'Traffic', unit: 'pps', dims: ['iface'],
    help: 'Frames per second seen by the XDP program.', build: rate('xs_rx_packets_total') },
  { id: 'frame_size', label: 'Average frame size', group: 'Traffic', unit: 'bytes', dims: ['iface'],
    help: 'Bytes per received frame. Small-packet floods pull it down.',
    build: (rw, by) => `${rate('xs_rx_bytes_total')(rw, by)} / ${rate('xs_rx_packets_total')(rw, by)}` },
  { id: 'vlan_pps', label: 'Frames by VLAN tag count', group: 'Traffic', unit: 'pps', dims: ['tags', 'iface'],
    help: 'Frames per second by number of VLAN tags.', build: rate('xs_vlan_packets_total') },
  // defense
  { id: 'verdict_pps', label: 'Verdicts', group: 'Defense', unit: 'pps', dims: ['verdict', 'iface'],
    help: 'Frames per second by final XDP action (pass, drop, …).', build: rate('xs_verdict_packets_total') },
  { id: 'drop_pps', label: 'Dropped', group: 'Defense', unit: 'pps', dims: ['iface'],
    help: 'Frames per second dropped by the dataplane.', build: rate('xs_verdict_packets_total{verdict="drop"}') },
  { id: 'drop_ratio', label: 'Drop ratio', group: 'Defense', unit: 'ratio', dims: ['iface'],
    help: 'Dropped ÷ received frames.',
    build: (rw, by) => `${rate('xs_verdict_packets_total{verdict="drop"}')(rw, by)} / ${rate('xs_rx_packets_total')(rw, by)}` },
  { id: 'ratelimited_pps', label: 'Rate-limited', group: 'Defense', unit: 'pps', dims: ['iface'],
    help: 'Frames per second capped by the per-source rate limiter.', build: rate('xs_policy_event_packets_total{event="rate_limited"}') },
  { id: 'policy_pps', label: 'Policy events', group: 'Defense', unit: 'pps', dims: ['event', 'iface'],
    help: 'Allow/deny list and rate-limiter actions per second.', build: rate('xs_policy_event_packets_total') },
  { id: 'mitigation_pps', label: 'Mitigation rate limit', group: 'Defense', unit: 'pps', dims: [],
    help: 'Rate the active mitigation limits traffic to.', build: gauge('xs_mitigation_rate_pps') },
  // protocols
  { id: 'l3_pps', label: 'L3 protocols', group: 'Protocols', unit: 'pps', dims: ['proto', 'iface'],
    help: 'Frames per second by network-layer protocol.', build: rate('xs_l3_packets_total') },
  { id: 'l4_pps', label: 'L4 protocols', group: 'Protocols', unit: 'pps', dims: ['proto', 'iface'],
    help: 'Packets per second by transport protocol.', build: rate('xs_l4_packets_total') },
  { id: 'tcp_flags_pps', label: 'TCP flags', group: 'Protocols', unit: 'pps', dims: ['class', 'iface'],
    help: 'TCP segments per second by flag class.', build: rate('xs_tcp_flags_packets_total') },
  { id: 'untracked_pps', label: 'Untracked TCP', group: 'Protocols', unit: 'pps', dims: ['iface'],
    help: 'TCP packets with no conntrack entry (ACK/RST flood gauge).', build: rate('xs_conntrack_packets_total') },
  { id: 'fragment_pps', label: 'Fragments', group: 'Protocols', unit: 'pps', dims: ['kind', 'iface'],
    help: 'IP fragments per second by kind.', build: rate('xs_fragment_packets_total') },
  { id: 'anomaly_pps', label: 'Header anomalies', group: 'Protocols', unit: 'pps', dims: ['kind', 'iface'],
    help: 'Bad flags, LAND, length mismatches… per second.', build: rate('xs_anomaly_packets_total') },
  { id: 'parse_reject_pps', label: 'Parser rejects', group: 'Protocols', unit: 'pps', dims: ['outcome', 'class'],
    help: 'Frames per second the parser marked malformed or unsupported.', build: rate('xs_parse_outcome_packets_total{class!="ok"}') },
  // detection
  { id: 'risk', label: 'Fused risk', group: 'Detection', unit: 'score', dims: [],
    help: 'Risk engine output, 0–1.', build: gauge('xs_risk') },
  { id: 'risk_level', label: 'Risk level', group: 'Detection', unit: 'level', dims: [],
    help: 'Discrete risk level 0 (calm) – 5 (critical).', build: gauge('xs_risk_level') },
  { id: 'anomaly_score', label: 'Statistical anomaly score', group: 'Detection', unit: 'score', dims: [],
    help: 'Z-score detector, scaled 0–1.', build: gauge('xs_anomaly_score01') },
  { id: 'ddos_score', label: 'DDoS score', group: 'Detection', unit: 'score', dims: [],
    help: 'DDoS detector score, 0–1.', build: gauge('xs_ddos_score') },
  { id: 'iforest', label: 'Isolation-forest score', group: 'Detection', unit: 'score', dims: [],
    help: 'ML isolation-forest anomaly score.', build: gauge('xs_anomaly_iforest') },
  { id: 'detection_active', label: 'Detection active', group: 'Detection', unit: 'level', dims: [],
    help: '1 while the rule-based detector reports an attack.', build: gauge('xs_detection_active') },
  // host
  { id: 'nic_drops', label: 'NIC receive drops', group: 'Host', unit: 'pps', dims: [],
    help: 'Frames the kernel dropped before XDP could see them.',
    build: (rw) => `sum(rate(node_network_receive_drop_total{device="enp1s0"}[${rw}]))` },
]
export const metricById = (id: string) => METRICS.find((m) => m.id === id) ?? METRICS[0]

export function fmtUnit(unit: Unit, n: number | null | undefined): string {
  if (n == null || !Number.isFinite(n)) return '—'
  switch (unit) {
    case 'bps': return bps(n)
    case 'pps': return pps(n)
    case 'bytes': return `${n >= 1000 ? si(n, 'B') : `${Math.round(n)} B`}`
    case 'ratio': return `${(n * 100).toFixed(n > 0 && n < 0.01 ? 3 : 1)}%`
    case 'score': return n.toFixed(3)
    case 'level': return n.toFixed(1)
  }
}

// Window total for rate units: packets for pps, bytes for bps.
export function fmtTotal(unit: Unit, integral: number): string | null {
  if (unit === 'pps') return `${si(integral)} packets`
  if (unit === 'bps') return si(integral / 8, 'B')
  return null
}
