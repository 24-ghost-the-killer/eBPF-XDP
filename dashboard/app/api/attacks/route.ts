import { NextResponse } from 'next/server'
import { readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// Reconstructs a DDoS attack history from Prometheus (15d retention). An attack
// is a contiguous period where the risk engine had detection_active > 0. For
// each episode we derive duration, peak/total traffic, drops, the dominant
// vectors, the classifier's verdict, and attacker IPs (when the per-source tap
// captured them — injected/on-box floods bypass it, so that list can be empty).
export const dynamic = 'force-dynamic'
export const maxDuration = 60

const PROM = process.env.PROM_URL || 'http://localhost:9091'
const STEP = 300 // coarse scan step; also the cache-key bucket size

type Payload = { status: string; retentionDays: number; attacks: unknown[]; incomplete?: number }

// Reconstructing 15 days of history runs hundreds of Prometheus queries (~5-7s).
// The result only changes when a new 300s bucket starts, and the client re-polls
// every 30s, so we cache it per bucket and serve the last-good result instantly
// while refreshing in the background (stale-while-revalidate). Module state is
// shared across requests in the same server process.
let CACHE: { key: number; data: Payload; builtAt: number } | null = null
let INFLIGHT: Promise<Payload> | null = null
const FRESH_MS = 60_000 // after this age, refresh in the background on next hit

// Prometheus evaluates ~20 queries at a time. Firing every episode's ~30
// queries at once (60 regions ≈ 1,500 requests) left most of them queued past
// their timeout, and one timeout failed the whole history. Cap what we keep in
// flight so each query is answered promptly.
const MAX_INFLIGHT = 8
let inflight = 0
const waiters: (() => void)[] = []
async function limited<T>(fn: () => Promise<T>): Promise<T> {
  if (inflight >= MAX_INFLIGHT) await new Promise<void>((r) => waiters.push(r))
  inflight++
  try {
    return await fn()
  } finally {
    inflight--
    waiters.shift()?.()
  }
}

// A finished episode never changes, so its (expensive) breakdown is computed
// once and reused; only new or still-running episodes are queried again. The
// cache is mirrored to disk so a dashboard restart doesn't start cold.
type Ep = { start: number; end: number }
type Built = Record<string, unknown> & { start: number; end: number }
const SETTLED_S = 600 // an episode that ended this long ago is final
// Bump whenever the per-episode breakdown logic changes, so a cache written by
// an older build is discarded instead of served with stale/wrong numbers.
// v2: per-source/victim counts read as peak-over-window (flush-safe) not instant.
const CACHE_SCHEMA = 2
const EPISODES = new Map<string, Built>()
const epKey = (ep: Ep) => `${ep.start}-${ep.end}`
const DISK = join(tmpdir(), 'xs-attacks-cache.json')
let loaded = false
async function loadDisk() {
  if (loaded) return
  loaded = true
  try {
    const j = JSON.parse(await readFile(DISK, 'utf8')) as { schema?: number; cache: typeof CACHE; episodes: [string, Built][] }
    // A cache from an older breakdown-logic version is discarded, not trusted.
    if (j.schema === CACHE_SCHEMA) {
      if (j.cache) CACHE = j.cache
      for (const [k, v] of j.episodes ?? []) EPISODES.set(k, v)
    }
  } catch {
    // no cache yet, or unreadable: rebuild from Prometheus
  }
}
async function saveDisk() {
  try {
    await writeFile(DISK, JSON.stringify({ schema: CACHE_SCHEMA, cache: CACHE, episodes: [...EPISODES.entries()] }))
  } catch {
    // best effort: the in-memory cache still works
  }
}

async function instant(expr: string, time?: number) {
  const u = new URL(`${PROM}/api/v1/query`)
  u.searchParams.set('query', expr)
  if (time) u.searchParams.set('time', String(time))
  const j = await limited(async () => (await fetch(u.toString(), { cache: 'no-store', signal: AbortSignal.timeout(20000) })).json())
  if (j.status !== 'success') throw new Error(j.error || 'query failed')
  return j.data.result as { metric: Record<string, string>; value: [number, string] }[]
}
async function range(expr: string, start: number, end: number, step: number) {
  const u = new URL(`${PROM}/api/v1/query_range`)
  u.searchParams.set('query', expr)
  u.searchParams.set('start', String(start))
  u.searchParams.set('end', String(end))
  u.searchParams.set('step', String(step))
  const j = await limited(async () => (await fetch(u.toString(), { cache: 'no-store', signal: AbortSignal.timeout(20000) })).json())
  if (j.status !== 'success') throw new Error(j.error || 'range failed')
  return j.data.result as { metric: Record<string, string>; values: [number, string][] }[]
}
const num = (r: { value: [number, string] }[]) => (r[0] ? parseFloat(r[0].value[1]) : 0)

// Per-key episode delta, correct whether or not the counter was reset. For each
// key we have its value at the end of the attack, its value just before the
// attack, and how many resets happened in the window:
//   * absent-before  -> the series was born in-window: use the full end value
//     (captures the first scrape's packets that increase() drops);
//   * reset in-window -> the map was flushed / agent restarted: the end value is
//     entirely this episode's (everything since the reset);
//   * otherwise       -> a monotonic counter with prior history: subtract the
//     pre-attack value to isolate this episode.
// This keeps Σ(per-source) == Σ(per-victim) == episode drops in every case,
// including back-to-back flushed test runs that reuse the same source IPs.
type Vec = { metric: Record<string, string>; value: [number, string] }[]
function toMap(v: Vec, key: string): Map<string, number> {
  const m = new Map<string, number>()
  for (const r of v) if (r.metric[key] !== undefined) m.set(r.metric[key], parseFloat(r.value[1]))
  return m
}
function deltaByKey(end: Vec, start: Vec, resets: Vec, key: string): Map<string, number> {
  const s = toMap(start, key)
  const rs = toMap(resets, key)
  const out = new Map<string, number>()
  for (const r of end) {
    const k = r.metric[key]
    if (k === undefined) continue
    const endV = parseFloat(r.value[1])
    const startV = s.get(k)
    let d: number
    if (startV === undefined) d = endV // born in-window
    else if ((rs.get(k) ?? 0) > 0) d = endV // counter reset in-window (flush/restart)
    else d = endV - startV // monotonic: isolate this episode
    if (d > 0) out.set(k, d)
  }
  return out
}
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

async function build(): Promise<Payload> {

    // --- Pass 1 (coarse): find attack REGIONS over 15d. 300s step + max_over_time
    // keeps us under Prometheus's 11k-point limit and catches short spikes. This
    // only bounds *where* to look; it over-merges, which pass 2 fixes. ---
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
    // Scan every region in parallel (they're independent), then flatten in
    // chronological order so the newest-first reverse below still holds.
    const perRegion = await Promise.all(
      regions.map(async (r) => {
        const fine = await range('max(xs_detection_active)', r.start - STEP, r.end + STEP, FINE)
        const fv = fine[0]?.values ?? []
        const local: Ep[] = []
        let cur: Ep | null = null
        for (const [t, v] of fv) {
          if (parseFloat(v) > 0) {
            const ts = +t
            if (cur && ts - cur.end <= GAP_SPLIT) cur.end = ts
            else {
              cur = { start: ts, end: ts }
              local.push(cur)
            }
          }
        }
        return local
      })
    )
    const eps: Ep[] = perRegion.flat()
    // newest first, cap to 50
    eps.reverse()
    const picked = eps.slice(0, 50)

    const now = Math.floor(Date.now() / 1000)
    const settled = await Promise.allSettled(
      picked.map(async (ep): Promise<Built> => {
        const cached = EPISODES.get(epKey(ep))
        if (cached) return cached
        // pad the window by one step on each side so the counters fully cover the spike
        // stats window: the detection span padded ±PAD so increase()/max_over_time
        // capture the flood's counter rise without pulling in a neighbouring attack.
        const PAD = 90
        const dur = ep.end - ep.start + 2 * PAD
        const at = ep.end + PAD
        const atStart = ep.start - PAD // evaluation instant just before the attack
        const sub = `[${dur}s:30s]`
        const win = `[${dur}s]`

        const [
          peakPps, peakBps, totPkts, totBytes, dropped, peakRisk, peakThreat, uniq, cls,
          atkPEnd, atkPStart, atkBEnd, atkBStart, atkResets, durActive,
          detIface, rxIface, vicPEnd, vicPStart, vicBEnd, vicBStart, vicResets,
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
          // Attack type from the deterministic rule (xs_detection_info), NOT the
          // CART classifier (xs_ddos_class_probability): the CART model is trained
          // on synthetic data and mislabels real floods (e.g. a SYN flood as
          // "connection_flood", an ACK/ICMP/UDP flood as "benign"), whereas the
          // rule-based detection is what actually drives mitigation and is correct.
          // count_over_time gives how many windows each type was active -> dominant.
          instant(`sum by(type)(count_over_time(xs_detection_info${win}))`, at),
          // Per-source attacker drops. The "end" value is the per-source counter's
          // PEAK over the episode window (max_over_time), NOT its value at `at`:
          // the attacker map is flushed to 0 within ~seconds of the attack ending,
          // and `at` = ep.end + PAD lands AFTER that flush, so an instant read there
          // returns 0 for every flood source and the whole attack vanishes from the
          // breakdown (only leftover local traffic survives). The peak is the value
          // the counter reached just before the flush = this source's episode total.
          // deltaByKey then isolates the episode: subtract the pre-attack value for a
          // monotonic series, or take the full peak for one born in-window / reset.
          // (increase() is still WRONG here -- it drops the first scrape's packets for
          // every young series, which every freshly-seen attacker IP is.)
          instant(`sum by(src)(max_over_time(xs_attacker_packets_total${win}))`, at),
          instant(`sum by(src)(xs_attacker_packets_total)`, atStart),
          instant(`sum by(src)(max_over_time(xs_attacker_bytes_total${win}))`, at),
          instant(`sum by(src)(xs_attacker_bytes_total)`, atStart),
          instant(`sum by(src)(resets(xs_attacker_packets_total${win}))`, at),
          // True attack length in seconds (count of 1s windows detection was active),
          // used as the denominator for average rates. The episode's coarse 30s-step
          // span over/under-estimates; this is accurate to the second.
          instant(`sum_over_time((max(xs_detection_active) or vector(0))[${dur}s:1s])`, at),
          // target: which interface(s) were under attack + which absorbed the ingress
          instant(`max_over_time((xs_detection_active)${sub})`, at),
          instant(`sum by(iface)(increase(xs_rx_packets_total${win}))`, at),
          // victim destinations: same flush-safe peak-over-window as attackers.
          instant(`sum by(dst)(max_over_time(xs_target_packets_total${win}))`, at),
          instant(`sum by(dst)(xs_target_packets_total)`, atStart),
          instant(`sum by(dst)(max_over_time(xs_target_bytes_total${win}))`, at),
          instant(`sum by(dst)(xs_target_bytes_total)`, atStart),
          instant(`sum by(dst)(resets(xs_target_packets_total${win}))`, at),
          ...VECTORS.map(([, m]) => instant(`sum(increase(${m}${win}))`, at)),
        ])

        // True attack duration in seconds (count of active 1s windows), the
        // denominator for all average rates, with a sane fallback.
        const durSec = Math.max(1, Math.round(num(durActive)) || ep.end - ep.start + FINE)

        // victim destination hosts (exact IPs the flood was aimed at), top 5
        const vicPkt = deltaByKey(vicPEnd, vicPStart, vicResets, 'dst')
        const vicByte = deltaByKey(vicBEnd, vicBStart, vicResets, 'dst')
        const victims = [...vicPkt.entries()]
          .map(([ip, packets]) => ({ ip, packets: Math.round(packets), bytes: Math.round(vicByte.get(ip) ?? 0) }))
          .filter((v) => v.packets > 0)
          .sort((a, b) => b.packets - a.packets)
          .slice(0, 5)

        // vectors above 5% of the strongest signal
        const vecVals = vecRes.map((r, k) => ({ name: VECTORS[k][0], v: num(r) }))
        const vmax = Math.max(1, ...vecVals.map((x) => x.v))
        const vectors = vecVals.filter((x) => x.v > vmax * 0.05 && x.v > 100).sort((a, b) => b.v - a.v).map((x) => x.name)

        // attacker sources: per-source dropped packets/bytes (accurate end-start
        // delta), averaged over the true attack duration. Summed over all sources
        // these now equal the episode's total drops.
        const atkPkt = deltaByKey(atkPEnd, atkPStart, atkResets, 'src')
        const atkByte = deltaByKey(atkBEnd, atkBStart, atkResets, 'src')
        const attackers = [...atkPkt.entries()]
          .map(([ip, pkts]) => {
            const bytes = atkByte.get(ip) ?? 0
            return {
              ip,
              scope: scopeOf(ip),
              bytes,
              packets: Math.round(pkts),
              pps: Math.round(pkts / durSec),
              bps: (bytes * 8) / durSec,
            }
          })
          .filter((a) => a.packets > 0)
          .sort((a, b) => b.packets - a.packets)
          // keep the payload small: a spoofed flood has thousands of sources, the
          // UI shows the top few, and uniqueSources still carries the full count
          .slice(0, 25)

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

        // Dominant accurate attack type over the episode, with how much of the
        // detected time it was the active type as a confidence.
        const detCounts = cls
          .map((s) => ({ type: s.metric.type, n: parseFloat(s.value[1]) }))
          .filter((x) => x.type && x.n > 0)
          .sort((a, b) => b.n - a.n)
        const detTotal = detCounts.reduce((a, b) => a + b.n, 0)
        const classifier = detCounts[0]
          ? { label: detCounts[0].type, conf: detTotal > 0 ? detCounts[0].n / detTotal : 1 }
          : null

        const dropPkts = num(dropped)
        const totP = num(totPkts)

        const built: Built = {
          start: ep.start * 1000,
          end: ep.end * 1000,
          durationSec: durSec,
          peakPps: num(peakPps),
          peakBps: num(peakBps),
          totalPackets: Math.round(totP),
          totalBytes: num(totBytes),
          droppedPackets: Math.round(dropPkts),
          dropShare: totP > 0 ? Math.min(1, dropPkts / totP) : 0,
          peakRiskLevel: Math.round(num(peakRisk)),
          peakThreatState: Math.round(num(peakThreat)),
          classifier,
          vectors,
          uniqueSources: Math.round(num(uniq)),
          attackers,
          target,
          victims,
        }
        if (now - ep.end >= SETTLED_S) EPISODES.set(epKey(ep), built)
        return built
      })
    )

    // An episode whose queries failed is left out this round (and retried on
    // the next refresh) instead of failing the whole history.
    const attacks = settled
      .map((r) => (r.status === 'fulfilled' ? r.value : null))
      .filter((a): a is Built => a !== null)
      .map((a, i) => ({ ...a, id: i + 1 }))
    const incomplete = settled.length - attacks.length
    if (incomplete === settled.length && settled.length > 0) {
      throw (settled[0] as PromiseRejectedResult).reason
    }
    // forget episodes that have aged out of the retention window
    const live = new Set(picked.map(epKey))
    for (const k of EPISODES.keys()) if (!live.has(k)) EPISODES.delete(k)

    return { status: 'success', retentionDays: 15, attacks, ...(incomplete ? { incomplete } : {}) }
}

// Build once per bucket, deduped across concurrent callers.
function rebuild(key: number): Promise<Payload> {
  if (!INFLIGHT) {
    INFLIGHT = build()
      .then((data) => {
        CACHE = { key, data, builtAt: Date.now() }
        void saveDisk()
        return data
      })
      .finally(() => {
        INFLIGHT = null
      })
  }
  return INFLIGHT
}

export async function GET() {
  const key = Math.floor(Date.now() / 1000 / STEP) * STEP
  try {
    await loadDisk()
    // Warm cache: serve it instantly. If it's for an old bucket or getting old,
    // kick off a background refresh so the NEXT poll gets fresh data — the user
    // never waits on the 5-7s reconstruction.
    if (CACHE) {
      const stale = CACHE.key !== key || Date.now() - CACHE.builtAt > FRESH_MS
      if (stale) void rebuild(key).catch(() => {})
      return NextResponse.json(CACHE.data)
    }
    // Cold start (no cache yet): build synchronously this once.
    const data = await rebuild(key)
    return NextResponse.json(data)
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    return NextResponse.json({ status: 'error', error: msg }, { status: 502 })
  }
}
