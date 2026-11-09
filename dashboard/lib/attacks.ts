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
  uniqueTargets?: number
  // 16 = per-address counts are scaled up from the dataplane's 1-in-16 sample
  sample?: number
  // breakdown version; < 3 = an older, less accurate source/target calculation
  v?: number
}

// One source or target of an attack, with its share of the dropped traffic.
export interface Party { ip: string; scope?: string; packets: number; bytes: number; pps?: number; bps?: number }
export interface Parties { attackers: Party[]; victims: Party[]; sample: number; complete: boolean }
// Every source and target of one attack (the list only carries the top 25).
export async function fetchParties(id: number): Promise<Parties> {
  const r = await fetch(`/api/attacks?id=${encodeURIComponent(String(id))}&parties=1`, { cache: 'no-store' })
  const j = await r.json().catch(() => ({}))
  if (j.status !== 'success') throw new Error(j.error || 'could not load the sources and targets')
  return j.parties as Parties
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

// One attack by id (= its start time in seconds), for links into the Attacks page.
export async function fetchAttack(id: number): Promise<{ attack: Episode; retentionDays: number }> {
  const r = await fetch(`/api/attacks?id=${encodeURIComponent(String(id))}`, { cache: 'no-store' })
  const j = await r.json().catch(() => ({}))
  if (j.status !== 'success') throw new Error(j.error || 'could not load that attack')
  return { attack: j.attack as Episode, retentionDays: (j.retentionDays as number) ?? 15 }
}

export const attackHref = (id: number) => `/analytics/attacks?attack=${id}`

export async function fetchAttacks():Promise<{ attacks: Episode[]; days: number; incomplete: number }> {
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
