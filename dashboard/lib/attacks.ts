// Attack episodes as reconstructed server-side by /api/attacks (15-day
// Prometheus retention; the route caches per 5-minute bucket).

// Geo/ASN enrichment (present only when the offline DB-IP databases are installed).
export interface Geo { cc?: string; country?: string; asn?: number; org?: string }
// Top source countries / networks of an attack, weighted by dropped packets.
// `bytes` = dropped bytes (absent on attacks analysed before it was recorded).
// In the all-attacks summary: `attacks` = how many attacks the country took
// part in, `last` = end of the latest one (ms), `bytesPartial` = some of those
// attacks have no byte count at all, so `bytes` is a lower bound.
export interface GeoCount {
  key: string; label: string; packets: number; sources: number; cc?: string; asn?: number
  bytes?: number; attacks?: number; last?: number; bytesPartial?: boolean
  // some of `bytes` is estimated (older attacks: packets × that attack's bytes per packet)
  bytesEstimated?: boolean
}
export interface SourceGeo { countries: GeoCount[]; asns: GeoCount[]; located: number; unlocated: number }

// What the defences did (analysed from 14 Nov 2026 on; absent on older attacks).
export interface Mitigation {
  active: boolean // auto-mitigation applied at some point
  disarmed: boolean // auto-mitigation was switched off (detect-only)
  rateCap: number // strongest per-source cap armed, pps (0 = none)
  rateLimited: number // packets the rate limiter dropped
  autoLockdown: boolean
  armed: string[] // defences switched on for this attack
  baseline: string[] // defences already on before it
  ladder: [number, number][] // [seconds from start, ladder level] at each change
  limitAfterSec: number | null // when rate limiting (level 3+) began
  targetPeakPps: number // peak packet rate on the attacked interface
  untracked?: number // TCP packets that matched no tracked connection
}
export const MARK_REASONS: { id: string; label: string; hint: string }[] = [
  { id: 'download', label: 'Download / big transfer', hint: 'a large download’s acknowledgements read as an ACK flood' },
  { id: 'arp_storm', label: 'ARP / broadcast storm', hint: 'non-IP traffic, usually a switch loop' },
  { id: 'loop', label: 'Network loop', hint: 'the same traffic circling the LAN' },
  { id: 'own_test', label: 'My own test', hint: 'a stress test or pentest I ran' },
  { id: 'scan', label: 'Harmless scan', hint: 'a known device scanning the network' },
  { id: 'backup', label: 'Backup / sync job', hint: 'scheduled bulk traffic' },
  { id: 'other', label: 'Something else', hint: 'explain in the note' },
]
export interface AttackMark { reason: string; note?: string; by: string; at: number }
export const markLabel = (r: string) => MARK_REASONS.find((m) => m.id === r)?.label ?? r

export interface Attacker extends Geo { ip: string; scope: string; bytes: number; packets: number; pps: number; bps: number }
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
  // top source countries / networks (only when the geo DB is installed)
  sourceGeo?: SourceGeo
  // breakdown version; < 3 = an older, less accurate source/target calculation
  v?: number
  mitigation?: Mitigation
  // marked as not an attack (left out of the totals)
  mark?: AttackMark
}

// One source or target of an attack, with its share of the dropped traffic.
export interface Party extends Geo { ip: string; scope?: string; packets: number; bytes: number; pps?: number; bps?: number }
export interface Parties { attackers: Party[]; victims: Party[]; sample: number; sourceGeo?: SourceGeo; complete: boolean }
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
  // attacks in the window marked as false alarms (not in the numbers above)
  falseAlarms?: number
  // source countries summed over the analysed attacks (geo DB installed only)
  countries?: GeoCount[]
}
export interface AttackPage {
  attacks: (Episode & { partial?: boolean })[]; total: number; offset: number; limit: number
  pending: number; summary: AttackSummary; retentionDays: number
}
export interface AttackQuery { offset: number; limit: number; vector?: string; ip?: string; country?: string; marked?: 'hide' | 'only'; from?: number; to?: number; sort?: string; desc?: boolean; analysedOnly?: boolean }
export async function fetchAttackPage(q: AttackQuery): Promise<AttackPage> {
  const p = new URLSearchParams({ offset: String(q.offset), limit: String(q.limit) })
  if (q.vector) p.set('vector', q.vector)
  if (q.ip) p.set('ip', q.ip)
  if (q.country) p.set('country', q.country)
  if (q.marked) p.set('marked', q.marked)
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
    // false alarms are not attacks: leave them out of every total built from this list
    return { attacks: (j.attacks as Episode[]).filter((a) => !a.mark), days: (j.retentionDays as number) ?? 15, incomplete: (j.incomplete as number) ?? 0 }
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw new Error('attack history timed out')
    throw e
  } finally {
    clearTimeout(timer)
  }
}

// Mark / unmark an attack as a false alarm (needs the attacks.mark permission).
export async function setAttackMark(id: number, mark: { reason: string; note?: string } | null): Promise<AttackMark | null> {
  const r = await fetch(`/api/attacks/mark${mark ? '' : `?id=${id}`}`, {
    method: mark ? 'POST' : 'DELETE',
    headers: { 'content-type': 'application/json' },
    ...(mark ? { body: JSON.stringify({ id, ...mark }) } : {}),
  })
  const j = await r.json().catch(() => ({}))
  if (!r.ok || j.status !== 'success') throw new Error(j.error === 'forbidden' ? 'You don’t have permission to mark false alarms.' : j.error || 'could not save')
  return (j.mark as AttackMark) ?? null
}

export const vectorsOf = (a: Episode) => (a.vectors.length ? a.vectors : [a.classifier?.label ?? 'unknown'])
