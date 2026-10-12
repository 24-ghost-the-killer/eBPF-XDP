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

// RFC1918 → lan, else wan (best-effort from the address alone).
function scopeOf(ip: string): string {
  const o = ip.split('.').map(Number)
  if (o.length !== 4 || o.some((n) => Number.isNaN(n))) return ''
  if (o[0] === 10) return 'lan'
  if (o[0] === 192 && o[1] === 168) return 'lan'
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return 'lan'
  return 'wan'
}

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
    type Ep = { start: number; end: number }

    // --- Pass 1 (coarse): find attack REGIONS over 15d. 300s step + max_over_time
    // keeps us under Prometheus's 11k-point limit and catches short spikes. This
    // only bounds *where* to look; it over-merges, which pass 2 fixes. ---
    const STEP = 300
    const end = Math.floor(Date.now() / 1000 / STEP) * STEP // bucket-aligned = stable across refreshes
    const start = end - 15 * 86400
    const coarse = await range(`max_over_time((max(xs_detection_active))[${STEP}s:15s])`, start, end, STEP)
    const cvals = coarse[0]?.values ?? []
    const regions: Ep[] = []
    for (const [t, v] of cvals) {
      if (parseFloat(v) > 0) {
        const ts = +t
        const last = regions[regions.length - 1]
        if (last && ts - last.end <= STEP) last.end = ts // only join consecutive buckets
        else regions.push({ start: ts - STEP, end: ts })
      }
    }

    // --- Pass 2 (fine): within each region, scan at 30s and split into distinct
    // episodes wherever there's >= GAP_SPLIT of calm. This separates attacks that
    // fell in adjacent 5-min buckets but are really two different attacks. ---
    const FINE = 30
    const GAP_SPLIT = 150 // >= 2.5 min of calm between detections = separate attack
    const eps: Ep[] = []
    for (const r of regions) {
      const fine = await range('max(xs_detection_active)', r.start - STEP, r.end + STEP, FINE)
      const fv = fine[0]?.values ?? []
      let cur: Ep | null = null
      for (const [t, v] of fv) {
        if (parseFloat(v) > 0) {
          const ts = +t
          if (cur && ts - cur.end <= GAP_SPLIT) cur.end = ts
          else {
            cur = { start: ts, end: ts }
            eps.push(cur)
          }
        }
      }
    }
    // newest first, cap to 50
    eps.reverse()
    const picked = eps.slice(0, 50)

    const attacks = await Promise.all(
      picked.map(async (ep, i) => {
        // pad the window by one step on each side so the counters fully cover the spike
        // stats window: the detection span padded ±PAD so increase()/max_over_time
        // capture the flood's counter rise without pulling in a neighbouring attack.
        const PAD = 90
        const dur = ep.end - ep.start + 2 * PAD
        const at = ep.end + PAD
        const sub = `[${dur}s:30s]`
        const win = `[${dur}s]`

        const [
          peakPps, peakBps, totPkts, totBytes, dropped, peakRisk, peakThreat, uniq, cls, atkPkts, atkBytes,
          detIface, rxIface, vicP, vicB,
          ...vecRes
        ] = await Promise.all([
          instant(`max_over_time((sum(rate(xs_rx_packets_total[30s])))${sub})`, at),
          instant(`max_over_time((sum(rate(xs_rx_bytes_total[30s]))*8)${sub})`, at),
          instant(`sum(increase(xs_rx_packets_total${win}))`, at),
          instant(`sum(increase(xs_rx_bytes_total${win}))`, at),
          instant(`sum(increase(xs_verdict_packets_total{verdict="drop"}${win}))`, at),
          instant(`max_over_time((max(xs_risk_level))${sub})`, at),
          instant(`max_over_time((max(xs_threat_state))${sub})`, at),
          // attacker sources = sources of DROPPED packets (tracked in XDP), not the talker tap.
          // uniqueSources = peak distinct sources in the attacker map (thousands = spoofed).
          instant(`max_over_time((max(xs_attacker_sources))${sub}) or vector(0)`, at),
          instant(`topk(1, max_over_time((max by(class)(xs_ddos_class_probability{class!="benign"}))${sub}))`, at),
          instant(`topk(15, sum by(src)(increase(xs_attacker_packets_total${win})))`, at),
          instant(`topk(15, sum by(src)(increase(xs_attacker_bytes_total${win})))`, at),
          // target: which interface(s) were under attack + which absorbed the ingress
          instant(`max_over_time((xs_detection_active)${sub})`, at),
          instant(`sum by(iface)(increase(xs_rx_packets_total${win}))`, at),
          // victim: exact destination IP(s) the dropped attack packets were aimed at
          instant(`topk(5, sum by(dst)(increase(xs_target_packets_total${win})))`, at),
          instant(`topk(5, sum by(dst)(increase(xs_target_bytes_total${win})))`, at),
          ...VECTORS.map(([, m]) => instant(`sum(increase(${m}${win}))`, at)),
        ])

        // victim destination hosts (exact IPs the flood was aimed at)
        const vicBytesByDst = new Map<string, number>()
        for (const s of vicB) vicBytesByDst.set(s.metric.dst, parseFloat(s.value[1]))
        const victims = vicP
          .map((s) => ({
            ip: s.metric.dst,
            packets: Math.round(parseFloat(s.value[1])),
            bytes: Math.round(vicBytesByDst.get(s.metric.dst) ?? 0),
          }))
          .filter((v) => v.packets > 0)
          .sort((a, b) => b.packets - a.packets)

        // vectors above 5% of the strongest signal
        const vecVals = vecRes.map((r, k) => ({ name: VECTORS[k][0], v: num(r) }))
        const vmax = Math.max(1, ...vecVals.map((x) => x.v))
        const vectors = vecVals.filter((x) => x.v > vmax * 0.05 && x.v > 100).sort((a, b) => b.v - a.v).map((x) => x.name)

        // attacker sources: IPs whose packets XDP dropped during the episode
        // (tracked inside the dataplane), merged bytes + packets by src.
        const atkBytesBySrc = new Map<string, number>()
        for (const s of atkBytes) atkBytesBySrc.set(s.metric.src, parseFloat(s.value[1]))
        const attackers = atkPkts
          .map((s) => {
            const ip = s.metric.src
            const pkts = parseFloat(s.value[1])
            const bytes = atkBytesBySrc.get(ip) ?? 0
            return {
              ip,
              scope: scopeOf(ip),
              bytes,
              packets: Math.round(pkts),
              pps: Math.round(pkts / dur),
              bps: (bytes * 8) / dur,
            }
          })
          .filter((a) => a.packets > 0)
          .sort((a, b) => b.packets - a.packets)

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
          durationSec: ep.end - ep.start + FINE,
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
          victims,
        }
      })
    )

    return NextResponse.json({ status: 'success', retentionDays: 15, attacks })
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    return NextResponse.json({ status: 'error', error: msg }, { status: 502 })
  }
}
