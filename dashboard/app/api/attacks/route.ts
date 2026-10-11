import { NextResponse } from 'next/server'

// Reconstructs a DDoS attack history from Prometheus (15d retention). An attack
// is a contiguous period where the risk engine had detection_active > 0. For
// each episode we derive duration, peak/total traffic, drops, the dominant
// vectors, the classifier's verdict, and attacker IPs (when the per-source tap
// captured them — injected/on-box floods bypass it, so that list can be empty).
export const dynamic = 'force-dynamic'
export const maxDuration = 60

const PROM = process.env.PROM_URL || 'http://localhost:9091'

async function instant(expr: string, time?: number) {
  const u = new URL(`${PROM}/api/v1/query`)
  u.searchParams.set('query', expr)
  if (time) u.searchParams.set('time', String(time))
  const r = await fetch(u.toString(), { cache: 'no-store' })
  const j = await r.json()
  if (j.status !== 'success') throw new Error(j.error || 'query failed')
  return j.data.result as { metric: Record<string, string>; value: [number, string] }[]
}
async function range(expr: string, start: number, end: number, step: number) {
  const u = new URL(`${PROM}/api/v1/query_range`)
  u.searchParams.set('query', expr)
  u.searchParams.set('start', String(start))
  u.searchParams.set('end', String(end))
  u.searchParams.set('step', String(step))
  const r = await fetch(u.toString(), { cache: 'no-store' })
  const j = await r.json()
  if (j.status !== 'success') throw new Error(j.error || 'range failed')
  return j.data.result as { metric: Record<string, string>; values: [number, string][] }[]
}
const num = (r: { value: [number, string] }[]) => (r[0] ? parseFloat(r[0].value[1]) : 0)
const vlanName = (ifc: string) => (ifc === 'vlan10' ? 'VLAN10 · wan' : ifc === 'vlan20' ? 'VLAN20 · lan' : ifc)

const VECTORS: [string, string][] = [
  ['SYN flood', 'xs_tcp_flags_packets_total{class="syn"}'],
  ['ACK flood', 'xs_tcp_flags_packets_total{class="ack"}'],
  ['RST flood', 'xs_tcp_flags_packets_total{class="rst"}'],
  ['UDP flood', 'xs_l4_packets_total{proto="udp"}'],
  ['ICMP flood', 'xs_l4_packets_total{proto="icmp"}'],
  ['Fragment flood', 'xs_fragment_packets_total'],
  ['Anomalous/bad-flags', 'xs_anomaly_packets_total'],
  ['Malformed', 'xs_parse_outcome_packets_total{class="malformed"}'],
]

export async function GET() {
  try {
    // 300s step keeps us well under Prometheus's 11k-point range limit over 15d.
    const STEP = 300
    // Align the window to STEP boundaries so bucket edges are stable across
    // refreshes (otherwise a moving `now` makes the result flicker).
    const end = Math.floor(Date.now() / 1000 / STEP) * STEP
    const start = end - 15 * 86400
    // Bucket with max_over_time so a short attack *anywhere* inside a 300s bucket
    // is always seen — sampling the instantaneous gauge misses spikes between
    // sample instants, which is why the count varied (6 vs 3) between loads.
    const series = await range(`max_over_time((max(xs_detection_active))[${STEP}s:15s])`, start, end, STEP)
    const vals = series[0]?.values ?? []

    // group contiguous active samples into episodes (merge gaps <= 2 steps)
    type Ep = { start: number; end: number }
    const eps: Ep[] = []
    for (const [t, v] of vals) {
      if (parseFloat(v) > 0) {
        const ts = +t
        const last = eps[eps.length - 1]
        if (last && ts - last.end <= STEP * 2) last.end = ts
        else eps.push({ start: ts, end: ts })
      }
    }
    // newest first, cap to 50
    eps.reverse()
    const picked = eps.slice(0, 50)

    const attacks = await Promise.all(
      picked.map(async (ep, i) => {
        // pad the window by one step on each side so the counters fully cover the spike
        const dur = ep.end - ep.start + 2 * STEP
        const at = ep.end + STEP
        const sub = `[${dur}s:30s]`
        const win = `[${dur}s]`

        const [
          peakPps, peakBps, totPkts, totBytes, dropped, peakRisk, peakThreat, uniq, cls, txB, txP,
          detIface, rxIface,
          ...vecRes
        ] = await Promise.all([
          instant(`max_over_time((sum(rate(xs_rx_packets_total[30s])))${sub})`, at),
          instant(`max_over_time((sum(rate(xs_rx_bytes_total[30s]))*8)${sub})`, at),
          instant(`sum(increase(xs_rx_packets_total${win}))`, at),
          instant(`sum(increase(xs_rx_bytes_total${win}))`, at),
          instant(`sum(increase(xs_verdict_packets_total{verdict="drop"}${win}))`, at),
          instant(`max_over_time((max(xs_risk_level))${sub})`, at),
          instant(`max_over_time((max(xs_threat_state))${sub})`, at),
          instant(`count(sum by(ip)(increase(xs_talker_tx_bytes_total${win})) > 0) or vector(0)`, at),
          instant(`topk(1, max_over_time((max by(class)(xs_ddos_class_probability{class!="benign"}))${sub}))`, at),
          instant(`topk(15, sum by(ip,scope)(increase(xs_talker_tx_bytes_total${win})))`, at),
          instant(`topk(15, sum by(ip,scope)(increase(xs_talker_tx_packets_total${win})))`, at),
          // target: which interface(s) were under attack + which absorbed the ingress
          instant(`max_over_time((xs_detection_active)${sub})`, at),
          instant(`sum by(iface)(increase(xs_rx_packets_total${win}))`, at),
          ...VECTORS.map(([, m]) => instant(`sum(increase(${m}${win}))`, at)),
        ])

        // vectors above 5% of the strongest signal
        const vecVals = vecRes.map((r, k) => ({ name: VECTORS[k][0], v: num(r) }))
        const vmax = Math.max(1, ...vecVals.map((x) => x.v))
        const vectors = vecVals.filter((x) => x.v > vmax * 0.05 && x.v > 100).sort((a, b) => b.v - a.v).map((x) => x.name)

        // attacker IPs (merge bytes + packets by ip)
        const pktByIp = new Map<string, number>()
        for (const s of txP) pktByIp.set(s.metric.ip, parseFloat(s.value[1]))
        const attackers = txB
          .map((s) => {
            const bytes = parseFloat(s.value[1])
            const pkts = pktByIp.get(s.metric.ip) ?? 0
            return {
              ip: s.metric.ip,
              scope: s.metric.scope || '',
              bytes,
              packets: Math.round(pkts),
              pps: Math.round(pkts / dur),
              bps: (bytes * 8) / dur,
            }
          })
          .filter((a) => a.bytes > 0)
          .sort((a, b) => b.bytes - a.bytes)

        // ---- target: where the attack was aimed ----
        const rxByIface = new Map<string, number>()
        for (const s of rxIface) rxByIface.set(s.metric.iface, parseFloat(s.value[1]))
        const detectedIfaces = new Set(detIface.filter((s) => parseFloat(s.value[1]) > 0).map((s) => s.metric.iface))
        const ifacesRanked = [...rxByIface.entries()].sort((a, b) => b[1] - a[1])
        const primaryIface = ifacesRanked.find(([i]) => detectedIfaces.has(i))?.[0] ?? ifacesRanked[0]?.[0] ?? null
        const totRxIface = [...rxByIface.values()].reduce((s, v) => s + v, 0) || 1
        const target = primaryIface
          ? {
              iface: primaryIface,
              label: vlanName(primaryIface),
              rxPackets: Math.round(rxByIface.get(primaryIface) ?? 0),
              rxShare: (rxByIface.get(primaryIface) ?? 0) / totRxIface,
            }
          : null

        const classRow = cls[0]
        const dropPkts = num(dropped)
        const totP = num(totPkts)

        return {
          id: i + 1,
          start: ep.start * 1000,
          end: ep.end * 1000,
          durationSec: ep.end - ep.start + STEP,
          peakPps: num(peakPps),
          peakBps: num(peakBps),
          totalPackets: Math.round(totP),
          totalBytes: num(totBytes),
          droppedPackets: Math.round(dropPkts),
          dropShare: totP > 0 ? Math.min(1, dropPkts / totP) : 0,
          peakRiskLevel: Math.round(num(peakRisk)),
          peakThreatState: Math.round(num(peakThreat)),
          classifier: classRow ? { label: classRow.metric.class, conf: parseFloat(classRow.value[1]) } : null,
          vectors,
          uniqueSources: Math.round(num(uniq)),
          attackers,
          target,
        }
      })
    )

    return NextResponse.json({ status: 'success', retentionDays: 15, attacks })
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    return NextResponse.json({ status: 'error', error: msg }, { status: 502 })
  }
}
