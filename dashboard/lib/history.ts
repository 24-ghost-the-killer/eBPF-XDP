// Devices from the past: every MAC the Zyxel switch has had in its address
// table and every LAN address the talker tap has counted traffic for, as far
// back as Prometheus keeps them (~15 days), folded into the device registry
// so they are kept for good from then on. Re-run every 10 minutes (only the
// new part of the window), so devices that came and went between the box's
// own looks are caught too.
//
//   switch:  dot1qTpFdbPort{mac, vlan} = bridge port (SNMP exporter, job "switch")
//   talkers: xs_talker_{tx,rx}_packets_total{ip}    (job "talkers")
//   attacks: attacker addresses in the permanent attack archive (from 23 Oct)
const PROM = process.env.PROM_URL || 'http://localhost:9091'
const DAY = 86_400

export interface Seen { first: number; last: number } // ms
export interface HistMac extends Seen { vlans: string[]; port?: number }
export interface HistIp extends Seen { from: ('traffic' | 'attack')[] }

async function rangeQuery(expr: string, start: number, end: number, step: number) {
  const u = new URL(`${PROM}/api/v1/query_range`)
  u.searchParams.set('query', expr)
  u.searchParams.set('start', String(start))
  u.searchParams.set('end', String(end))
  u.searchParams.set('step', String(step))
  const r = await fetch(u.toString(), { cache: 'no-store', signal: AbortSignal.timeout(30_000) })
  const j = await r.json()
  if (j.status !== 'success') throw new Error(j.error || 'query failed')
  return j.data.result as { metric: Record<string, string>; values: [number, string][] }[]
}
// Prometheus keeps ~15 days; asking for more just returns nothing extra.
const retentionStart = (now: number) => now - 15 * DAY

// Presence windows from a range query: first and last sample time per key.
function spans(res: { metric: Record<string, string>; values: [number, string][] }[], key: (m: Record<string, string>) => string | null) {
  const out = new Map<string, Seen & { metric: Record<string, string>; lastVal: number }>()
  for (const s of res) {
    const k = key(s.metric)
    if (!k || !s.values.length) continue
    const first = s.values[0][0] * 1000
    const last = s.values[s.values.length - 1][0] * 1000
    const lastVal = parseFloat(s.values[s.values.length - 1][1])
    const e = out.get(k)
    if (!e) out.set(k, { first, last, metric: s.metric, lastVal })
    else {
      e.first = Math.min(e.first, first)
      if (last >= e.last) { e.last = last; e.metric = s.metric; e.lastVal = lastVal }
    }
  }
  return out
}

/** Read the switch's and the talker tap's history between `since` (s) and now. */
export async function readHistory(since?: number): Promise<{ macs: Map<string, HistMac>; ips: Map<string, HistIp> }> {
  const now = Math.floor(Date.now() / 1000)
  const start = Math.max(since ?? 0, retentionStart(now))
  // 5-minute steps keep 15 days under Prometheus's 11k points per series
  const step = 300
  const [fdb, talk] = await Promise.all([
    rangeQuery('max by(mac, vlan)(dot1qTpFdbPort)', start, now, step).catch(() => []),
    rangeQuery('sum by(ip)(xs_talker_tx_packets_total) or sum by(ip)(xs_talker_rx_packets_total)', start, now, step).catch(() => []),
  ])
  const macs = new Map<string, HistMac>()
  for (const s of fdb) {
    const mac = s.metric.mac?.toLowerCase()
    if (!mac || !/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(mac) || parseInt(mac.slice(0, 2), 16) & 1 || !s.values.length) continue
    const first = s.values[0][0] * 1000
    const last = s.values[s.values.length - 1][0] * 1000
    const e = macs.get(mac) ?? { first, last, vlans: [] as string[] }
    e.first = Math.min(e.first, first)
    if (last >= e.last) { e.last = last; const p = Number(s.values[s.values.length - 1][1]); if (p > 0) e.port = p }
    if (s.metric.vlan && !e.vlans.includes(s.metric.vlan)) e.vlans.push(s.metric.vlan)
    macs.set(mac, e)
  }
  const ips = new Map<string, HistIp>()
  for (const [ip, e] of spans(talk, (m) => m.ip ?? null)) ips.set(ip, { first: e.first, last: e.last, from: ['traffic'] })
  return { macs, ips }
}
