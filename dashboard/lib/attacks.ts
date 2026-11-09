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
// One page of the full attack history (server-side paging, filters and sort).
export interface AttackSummary {
  count: number; totalDurationSec: number; analysed: number; peakBps: number; peakPps: number
  droppedPackets: number; avgDropShare: number; medianDurationSec: number; vectors: string[]
  oldest: number | null; newest: number | null; archived: number
}
export interface AttackPage {
  attacks: (Episode & { partial?: boolean })[]; total: number; offset: number; limit: number
  pending: number; summary: AttackSummary; retentionDays: number
}
export interface AttackQuery { offset: number; limit: number; vector?: string; ip?: string; from?: number; to?: number; sort?: string; desc?: boolean; analysedOnly?: boolean }
export async function fetchAttackPage(q: AttackQuery): Promise<AttackPage> {
  const p = new URLSearchParams({ offset: String(q.offset), limit: String(q.limit) })
  if (q.vector) p.set('vector', q.vector)
  if (q.ip) p.set('ip', q.ip)
  if (q.from) p.set('from', String(Math.floor(q.from)))
  if (q.to) p.set('to', String(Math.ceil(q.to)))
  if (q.sort) p.set('sort', q.sort)
  if (q.desc === false) p.set('desc', '0')
  if (q.analysedOnly) p.set('analysedOnly', '1')
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), 90000) // a page of never-analysed attacks takes a few seconds
  try {
    const r = await fetch(`/api/attacks?${p}`, { cache: 'no-store', signal: ctrl.signal })
    const j = await r.json()
    if (j.status !== 'success') throw new Error(j.error || 'attack history failed')
    return j as AttackPage
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw new Error('attack history timed out')
    throw e
  } finally {
    clearTimeout(timer)
  }
}

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
