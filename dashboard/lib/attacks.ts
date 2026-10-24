// Attack episodes as reconstructed server-side by /api/attacks (15-day
// Prometheus retention; the route caches per 5-minute bucket).

export interface Attacker { ip: string; scope: string; bytes: number; packets: number; pps: number; bps: number }
export interface Episode {
  id: number
  start: number // ms
  end: number // ms
  durationSec: number
  peakPps: number
  peakBps: number
  totalPackets: number
  totalBytes: number
  droppedPackets: number
  dropShare: number
  peakRiskLevel: number
  peakThreatState: number
  classifier: { label: string; conf: number } | null
  vectors: string[]
  uniqueSources: number
  attackers: Attacker[]
  target: { iface: string; label: string; rxPackets: number; rxShare: number } | null
  victims: { ip: string; packets: number; bytes: number }[]
}

// `incomplete` = episodes whose breakdown failed this round (retried on the next refresh).
export async function fetchAttacks(): Promise<{ attacks: Episode[]; days: number; incomplete: number }> {
  const ctrl = new AbortController()
  // the first reconstruction after a cold start takes ~25 s; later calls are cached
  const timer = setTimeout(() => ctrl.abort(), 90000)
  try {
    const r = await fetch('/api/attacks', { cache: 'no-store', signal: ctrl.signal })
    const j = await r.json()
    if (j.status !== 'success') throw new Error(j.error || 'attack history failed')
    return { attacks: j.attacks as Episode[], days: (j.retentionDays as number) ?? 15, incomplete: (j.incomplete as number) ?? 0 }
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw new Error('attack history timed out')
    throw e
  } finally {
    clearTimeout(timer)
  }
}

export const vectorsOf = (a: Episode) => (a.vectors.length ? a.vectors : [a.classifier?.label ?? 'unknown'])
