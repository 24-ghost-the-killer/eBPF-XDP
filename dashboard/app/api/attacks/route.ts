import { NextRequest, NextResponse } from 'next/server'
import { requirePerm } from '@/lib/api-auth'
import { readFile, writeFile, rename, mkdir } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'

// Every DDoS attack the appliance has ever seen, paged.
//
// * The LIST of attacks (start/end of each episode) is rebuilt from Prometheus
//   over its whole retention: cheap, two passes over xs_detection_active.
// * The BREAKDOWN of an attack (traffic, drops, vectors, sources, targets) costs
//   ~30 queries, so it is computed only for the page being viewed, plus a few
//   per minute in the background (oldest first, so nothing ages out of
//   Prometheus unanalysed).
// * Every finished breakdown goes into a PERMANENT archive next to the users
//   file. Prometheus forgets after its retention (15 d); the archive never does,
//   so attacks older than the retention stay listed with all their numbers.
//
// GET /api/attacks?offset=0&limit=20[&vector=x][&ip=y][&from=s&to=s][&sort=k&desc=1][&analysedOnly=1]
//   -> { status, total, offset, limit, attacks, pending, summary, retentionDays }
// GET /api/attacks?id=<start seconds> -> { status, attack, retentionDays }
// GET /api/attacks?id=<start seconds>&parties=1 -> every source and target of
//   that attack (not just the top few kept in the list), { status, parties }
// GET /api/attacks          (no offset) -> every analysed attack, newest first
//   (the shape older callers — overview, IP lookup, host pages — expect).
export const dynamic = 'force-dynamic'
export const maxDuration = 60

const PROM = process.env.PROM_URL || 'http://localhost:9091'
const STEP = 300 // coarse scan step
const SETTLED_S = 600 // an episode that ended this long ago is final
// Bump whenever the per-episode breakdown logic changes, so archived results
// from an older build are recomputed (while Prometheus still has the data).
// v2: per-source/victim counts read as peak-over-window (flush-safe) not instant.
// v3: per-source/victim counts summed over every burst of the episode (the map is
//     flushed between bursts, v2 kept only the biggest one) and scaled by the
//     dataplane's 1-in-16 attribution sampling.
// The version is kept PER archived attack: an older entry is recomputed while
// Prometheus still has its data, and kept as it is (marked) once it does not.
const CACHE_SCHEMA = 3

// Since the 27 Oct 2026 dataplane (xdp_main.c, "Sample the per-IP attribution
// maps"), victims/attackers are credited on 1 drop in 16 to keep a spoofed
// flood's LRU churn off the fast path. Counts from then on are scaled back up.
// Measured on the box: drops / attributed was ~1.0-1.3 up to 17:31 that day
// and ~16 from 17:52 on (no drops in between).
const ATTRIB_SAMPLE = 16
const ATTRIB_SAMPLED_SINCE = Number(process.env.DASH_ATTRIB_SAMPLED_SINCE) || 1793118700
const sampleOf = (ep: Ep) => (ep.start >= ATTRIB_SAMPLED_SINCE ? ATTRIB_SAMPLE : 1)

// Prometheus evaluates ~20 queries at a time; keep a bounded number in flight.
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

type Ep = { start: number; end: number } // seconds
type Built = Record<string, unknown> & { start: number; end: number; durationSec: number; vectors: string[]; attackers: { ip: string }[]; victims: { ip: string }[]; v?: number }
const epKey = (ep: Ep) => `${ep.start}-${ep.end}`

// ---- permanent archive ------------------------------------------------------
function archivePath(): string {
  if (process.env.DASH_ATTACKS_ARCHIVE) return process.env.DASH_ATTACKS_ARCHIVE
  const users = process.env.DASH_USERS_FILE || '/home/test_server/xdp-sentinel-data/dash-users.json'
  return join(dirname(users), 'attacks-archive.json')
}
const ARCHIVE = new Map<string, Built>() // settled episodes, forever
const LIVE = new Map<string, { b: Built; at: number }>() // still-running episodes, short-lived
let loaded: Promise<void> | null = null
function loadArchive(): Promise<void> {
  if (!loaded) {
    loaded = (async () => {
      try {
        const j = JSON.parse(await readFile(archivePath(), 'utf8'))
        // v2 files are kept (their entries carry no `v` = version 2) and upgraded entry by entry
        if (j.schema >= 2 && j.schema <= CACHE_SCHEMA) for (const [k, v] of Object.entries(j.episodes ?? {})) ARCHIVE.set(k, v as Built)
      } catch {}
      // One-time import of the old per-process cache (same breakdown schema).
      try {
        const old = JSON.parse(await readFile(join(tmpdir(), 'xs-attacks-cache.json'), 'utf8'))
        if (old.schema === 2) for (const [k, v] of old.episodes ?? []) if (!ARCHIVE.has(k)) ARCHIVE.set(k, v)
      } catch {}
    })()
  }
  return loaded
}
let saving: Promise<void> | null = null
let dirty = false
function saveArchive() {
  dirty = true
  if (saving) return
  saving = (async () => {
    while (dirty) {
      dirty = false
      const file = archivePath()
      try {
        await mkdir(dirname(file), { recursive: true })
        await writeFile(`${file}.tmp`, JSON.stringify({ schema: CACHE_SCHEMA, episodes: Object.fromEntries(ARCHIVE) }), { mode: 0o640 })
        await rename(`${file}.tmp`, file)
      } catch (e) {
        console.error('[attacks] could not write archive', e)
      }
    }
  })().finally(() => { saving = null })
}

async function instant(expr: string, time?: number, timeoutMs = 20000) {
  const u = new URL(`${PROM}/api/v1/query`)
  u.searchParams.set('query', expr)
  if (time) u.searchParams.set('time', String(time))
  const j = await limited(async () => (await fetch(u.toString(), { cache: 'no-store', signal: AbortSignal.timeout(timeoutMs) })).json())
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

// ---- sources and targets of one attack ---------------------------------------
// The dataplane credits each dropped packet's source and destination in two LRU
// maps; the agent exports them as counters per src / dst. Those counters are
// NOT monotonic over an attack: the maps are flushed between test bursts (and
// LRU churn can evict an entry), so one episode is often several 0 -> N runs.
// The episode total per address is therefore the SUM of every increase,
// counting a drop or a re-appearance (after a flush) as a fresh start:
//   per step:  x - x[step ago]   if that is >= 0
//              x                 otherwise (reset, or the series is new/back)
// summed over the padded window (`x * 1` drops the metric name so both branches
// share one label set). Steps telescope, so a plain monotonic counter
// still gives end - start, and nothing from before the attack leaks in.
// (v1 used increase(), which drops each new series' first scrape; v2 took the
// peak over the window, which keeps only the biggest burst.)
const PAD = 90 // seconds of padding around the detected span
function windowOf(ep: Ep) {
  const dur = ep.end - ep.start + 2 * PAD
  return { dur, at: ep.end + PAD, step: dur > 3 * 3600 ? 15 : 5 } // 5 s = the agent's scrape interval
}
const episodeSum = (metric: string, by: string, w: { dur: number; step: number }) =>
  `sum by(${by})(sum_over_time((((${metric} - ${metric} offset ${w.step}s) >= 0) or (${metric} * 1))[${w.dur}s:${w.step}s]))`

type Vec = { metric: Record<string, string>; value: [number, string] }[]
function toMap(v: Vec, key: string): Map<string, number> {
  const m = new Map<string, number>()
  for (const r of v) if (r.metric[key] !== undefined) m.set(r.metric[key], parseFloat(r.value[1]))
  return m
}
interface Party { ip: string; scope?: string; packets: number; bytes: number; pps: number; bps: number }
async function parties(ep: Ep, durSec: number): Promise<{ attackers: Party[]; victims: Party[]; sample: number }> {
  const w = windowOf(ep)
  const k = sampleOf(ep)
  const [ap, ab, vp, vb] = await Promise.all([
    instant(episodeSum('xs_attacker_packets_total', 'src', w), w.at, 60000),
    instant(episodeSum('xs_attacker_bytes_total', 'src', w), w.at, 60000),
    instant(episodeSum('xs_target_packets_total', 'dst', w), w.at, 60000),
    instant(episodeSum('xs_target_bytes_total', 'dst', w), w.at, 60000),
  ])
  const list = (pk: Vec, by: Vec, key: string, withScope: boolean): Party[] => {
    const bytes = toMap(by, key)
    return [...toMap(pk, key).entries()]
      .filter(([, n]) => n > 0)
      .map(([ip, n]) => {
        const packets = Math.round(n * k)
        const b = Math.round((bytes.get(ip) ?? 0) * k)
        return { ip, ...(withScope ? { scope: scopeOf(ip) } : {}), packets, bytes: b, pps: Math.round(packets / durSec), bps: (b * 8) / durSec }
      })
      .sort((x, y) => y.packets - x.packets)
  }
  return { attackers: list(ap, ab, 'src', true), victims: list(vp, vb, 'dst', false), sample: k }
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


// ---- the list of episodes (cheap, whole retention) -----------------------
let retentionDays = 15
async function readRetention() {
  try {
    const j = await (await fetch(`${PROM}/api/v1/status/flags`, { cache: 'no-store', signal: AbortSignal.timeout(5000) })).json()
    const m = /^(\d+)([dhwy])$/.exec(j?.data?.['storage.tsdb.retention.time'] ?? '')
    if (m) retentionDays = Math.max(1, Math.round(Number(m[1]) * ({ h: 1 / 24, d: 1, w: 7, y: 365 } as Record<string, number>)[m[2]]))
  } catch {}
}

async function scanEpisodes(): Promise<Ep[]> {
  await readRetention()
  // Pass 1 (coarse): attack REGIONS. 300 s steps + max_over_time catch short
  // spikes; chunked by 30 days to stay under Prometheus's 11k-point limit.
  const end = Math.floor(Date.now() / 1000 / STEP) * STEP
  const start = end - retentionDays * 86400
  const regions: Ep[] = []
  for (let a = start; a < end; a += 30 * 86400) {
    const b = Math.min(end, a + 30 * 86400)
    const coarse = await range(`max_over_time((max(xs_detection_active))[${STEP}s:15s])`, a, b, STEP)
    for (const [t, v] of coarse[0]?.values ?? []) {
      if (parseFloat(v) > 0) {
        const ts = +t
        const last = regions[regions.length - 1]
        if (last && ts - last.end <= STEP) last.end = ts
        else regions.push({ start: ts - STEP, end: ts })
      }
    }
  }
  // Pass 2 (fine): split each region at >= 2.5 min of calm into separate attacks.
  const FINE = 30
  const GAP_SPLIT = 150
  const perRegion = await Promise.all(regions.map(async (r) => {
    const fine = await range('max(xs_detection_active)', r.start - STEP, r.end + STEP, FINE)
    const local: Ep[] = []
    let cur: Ep | null = null
    for (const [t, v] of fine[0]?.values ?? []) {
      if (parseFloat(v) > 0) {
        const ts = +t
        if (cur && ts - cur.end <= GAP_SPLIT) cur.end = ts
        else { cur = { start: ts, end: ts }; local.push(cur) }
      }
    }
    return local
  }))
  return perRegion.flat()
}

// The full list = what Prometheus still has + archived attacks older than that.
// Cached for a minute, refreshed in the background (stale-while-revalidate).
let INDEX: { eps: Ep[]; at: number } | null = null
let INDEXING: Promise<Ep[]> | null = null
const INDEX_FRESH_MS = 60_000
async function refreshIndex(): Promise<Ep[]> {
  if (!INDEXING) {
    INDEXING = (async () => {
      const prom = await scanEpisodes()
      const overlaps = (x: Ep) => prom.some((p) => p.start <= x.end && x.start <= p.end)
      const old: Ep[] = []
      for (const k of ARCHIVE.keys()) {
        const [s0, e0] = k.split('-').map(Number)
        const ep = { start: s0, end: e0 }
        if (!overlaps(ep)) old.push(ep)
      }
      const eps = [...prom, ...old].sort((x, y) => y.start - x.start) // newest first
      INDEX = { eps, at: Date.now() }
      void backfill(eps)
      return eps
    })().finally(() => { INDEXING = null })
  }
  return INDEXING
}
async function index(): Promise<Ep[]> {
  if (INDEX) {
    if (Date.now() - INDEX.at > INDEX_FRESH_MS) void refreshIndex().catch(() => {})
    return INDEX.eps
  }
  return refreshIndex()
}

// ---- the breakdown of one episode (expensive, cached forever once settled) --
async function analyse(ep: Ep): Promise<Built> {
  // pad the window by one step on each side so the counters fully cover the spike
  // stats window: the detection span padded ±PAD so increase()/max_over_time
  // capture the flood's counter rise without pulling in a neighbouring attack.
  const { dur, at } = windowOf(ep)
  const sub = `[${dur}s:30s]`
  const win = `[${dur}s]`

  const [
    peakPps, peakBps, totPkts, totBytes, dropped, peakRisk, peakThreat, uniq, cls,
    durActive, detIface, rxIface,
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
    // True attack length in seconds (count of 1s windows detection was active),
    // used as the denominator for average rates. The episode's coarse 30s-step
    // span over/under-estimates; this is accurate to the second.
    instant(`sum_over_time((max(xs_detection_active) or vector(0))[${dur}s:1s])`, at),
    // target: which interface(s) were under attack + which absorbed the ingress
    instant(`max_over_time((xs_detection_active)${sub})`, at),
    instant(`sum by(iface)(increase(xs_rx_packets_total${win}))`, at),
    ...VECTORS.map(([, m]) => instant(`sum(increase(${m}${win}))`, at)),
  ])

  // True attack duration in seconds (count of active 1s windows), the
  // denominator for all average rates, with a sane fallback.
  const durSec = Math.max(1, Math.round(num(durActive)) || ep.end - ep.start + 30) // +30: one fine-scan step

  // Sources and targets, summed over every burst (see parties()). The list keeps
  // the top 25 of each; ?parties=1 serves the full lists on demand.
  const who = await parties(ep, durSec)
  const victims = who.victims.slice(0, 25).map(({ ip, packets, bytes }) => ({ ip, packets, bytes }))

  // vectors above 5% of the strongest signal
  const vecVals = vecRes.map((r, k) => ({ name: VECTORS[k][0], v: num(r) }))
  const vmax = Math.max(1, ...vecVals.map((x) => x.v))
  const vectors = vecVals.filter((x) => x.v > vmax * 0.05 && x.v > 100).sort((a, b) => b.v - a.v).map((x) => x.name)

  const attackers = who.attackers.slice(0, 25)

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
    // the map's peak size per burst, or every source seen over all bursts
    uniqueSources: Math.max(Math.round(num(uniq)), who.attackers.length),
    uniqueTargets: who.victims.length,
    attackers,
    target,
    victims,
    sample: who.sample,
    v: CACHE_SCHEMA,
  }
  return built
}

// An archived breakdown from an older build is recomputed while Prometheus still
// holds the attack (an hour's margin before it ages out); after that it is kept.
const inRetention = (ep: Ep) => ep.start > Date.now() / 1000 - retentionDays * 86400 + 3600
const outdated = (ep: Ep, b: Built) => (b.v ?? 2) < CACHE_SCHEMA && inRetention(ep)

async function getBuilt(ep: Ep): Promise<Built> {
  const k = epKey(ep)
  const a = ARCHIVE.get(k)
  if (a && !outdated(ep, a)) return a
  const l = LIVE.get(k)
  if (l && Date.now() - l.at < 60_000) return l.b
  let b: Built
  try {
    b = await analyse(ep)
  } catch (e) {
    if (a) return a // keep showing the older numbers rather than nothing
    throw e
  }
  if (Date.now() / 1000 - ep.end >= SETTLED_S) {
    ARCHIVE.set(k, b)
    saveArchive()
  } else {
    LIVE.set(k, { b, at: Date.now() })
    if (LIVE.size > 50) for (const key of [...LIVE.keys()].slice(0, LIVE.size - 50)) LIVE.delete(key)
  }
  return b
}
const known = (ep: Ep): Built | null => ARCHIVE.get(epKey(ep)) ?? LIVE.get(epKey(ep))?.b ?? null

// Background catch-up: analyse a few unanalysed settled episodes per refresh,
// OLDEST first, so every attack is archived before Prometheus forgets it.
let backfilling = false
async function backfill(eps: Ep[]) {
  if (backfilling) return
  backfilling = true
  try {
    const now = Date.now() / 1000
    const todo = eps.filter((e) => {
      if (now - e.end < SETTLED_S) return false
      const a = ARCHIVE.get(epKey(e))
      return !a || outdated(e, a)
    }).reverse().slice(0, 6)
    for (const e of todo) { try { await getBuilt(e) } catch {} }
  } finally {
    backfilling = false
  }
}

// Every source and target of one attack, for the "view all" list. Computed
// from Prometheus while it has the attack (cached once settled); after that,
// what the archive kept (the top 25 of each).
const PARTIES = new Map<string, { at: number; p: unknown }>()
async function allParties(ep: Ep) {
  const k = epKey(ep)
  const hit = PARTIES.get(k)
  const settled = Date.now() / 1000 - ep.end >= SETTLED_S
  if (hit && (settled || Date.now() - hit.at < 30_000)) return hit.p
  const b = await getBuilt(ep)
  let p: unknown
  if (inRetention(ep)) {
    const who = await parties(ep, Math.max(1, Number(b.durationSec) || 1))
    p = { ...who, complete: true }
  } else {
    p = { attackers: b.attackers, victims: b.victims, sample: (b.sample as number) ?? 1, complete: false }
  }
  PARTIES.set(k, { at: Date.now(), p })
  if (PARTIES.size > 20) PARTIES.delete(PARTIES.keys().next().value as string)
  return p
}

const withId = (b: Built) => ({ ...b, id: Math.floor(b.start / 1000) }) // stable: start time in seconds
const vectorsOf = (b: Built) => (b.vectors.length ? b.vectors : [((b.classifier as { label?: string } | null)?.label) ?? 'unknown'])
const SORTS = new Set(['start', 'durationSec', 'peakBps', 'peakPps', 'droppedPackets', 'dropShare'])

export async function GET(req: NextRequest) {
  const auth = await requirePerm(req, null) // live: disabled accounts lose access at once
  if (auth.error) return auth.error
  try {
    await loadArchive()
    const all = await index()
    const sp = req.nextUrl.searchParams

    // One attack by id (its start time in seconds) — deep links from host pages.
    if (sp.has('id')) {
      const id = Number(sp.get('id'))
      const ep = Number.isFinite(id) ? all.find((e) => Math.floor(e.start) === id) : undefined
      if (!ep) return NextResponse.json({ status: 'error', error: 'That attack is no longer in the history.' }, { status: 404 })
      if (sp.get('parties') === '1') return NextResponse.json({ status: 'success', parties: await allParties(ep) })
      return NextResponse.json({ status: 'success', retentionDays, attack: withId(await getBuilt(ep)) })
    }

    // Legacy shape: every analysed attack (overview, IP lookup, host pages).
    if (!sp.has('offset')) {
      const attacks = all.map(known).filter((b): b is Built => !!b).map(withId)
      return NextResponse.json({ status: 'success', retentionDays, attacks, total: all.length, pending: all.length - attacks.length })
    }

    const offset = Math.max(0, Number(sp.get('offset')) || 0)
    const limit = Math.min(500, Math.max(1, Number(sp.get('limit')) || 20))
    const from = Number(sp.get('from')) || 0
    const to = Number(sp.get('to')) || Infinity
    const vector = sp.get('vector') || ''
    const ip = (sp.get('ip') || '').trim()
    const sort = SORTS.has(sp.get('sort') || '') ? (sp.get('sort') as string) : 'start'
    const desc = sp.get('desc') !== '0'
    const analysedOnly = sp.get('analysedOnly') === '1'

    const inWindow = all.filter((e) => e.end >= from && e.start <= to)
    // Summary over everything in the window: counts/time from the list,
    // traffic numbers from the attacks analysed so far.
    const builtAll = inWindow.map(known).filter((b): b is Built => !!b)
    const num = (b: Built, k: string) => Number(b[k]) || 0
    const summary = {
      count: inWindow.length,
      totalDurationSec: inWindow.reduce((n, e) => n + Math.max(30, e.end - e.start), 0),
      analysed: builtAll.length,
      peakBps: Math.max(0, ...builtAll.map((b) => num(b, 'peakBps'))),
      peakPps: Math.max(0, ...builtAll.map((b) => num(b, 'peakPps'))),
      droppedPackets: builtAll.reduce((n, b) => n + num(b, 'droppedPackets'), 0),
      avgDropShare: builtAll.length ? builtAll.reduce((n, b) => n + num(b, 'dropShare'), 0) / builtAll.length : 0,
      medianDurationSec: (() => { const d = inWindow.map((e) => Math.max(30, e.end - e.start)).sort((x, y) => x - y); return d.length ? d[Math.floor(d.length / 2)] : 0 })(),
      vectors: [...new Set(builtAll.flatMap(vectorsOf))].sort(),
      oldest: inWindow.length ? inWindow[inWindow.length - 1].start * 1000 : null,
      newest: inWindow.length ? inWindow[0].end * 1000 : null,
      archived: ARCHIVE.size,
    }

    // Filters / sorts that need the breakdown run over analysed attacks; the
    // rest are counted as `pending` (the background catch-up fills them in).
    const needsBreakdown = !!vector || !!ip || sort !== 'start' || analysedOnly
    if (needsBreakdown) {
      let rows = builtAll
      if (vector) rows = rows.filter((b) => vectorsOf(b).includes(vector))
      if (ip) rows = rows.filter((b) => b.attackers.some((x) => x.ip.includes(ip)) || b.victims.some((x) => x.ip.includes(ip)))
      rows = [...rows].sort((x, y) => (desc ? num(y, sort) - num(x, sort) : num(x, sort) - num(y, sort)))
      void backfill(all)
      return NextResponse.json({
        status: 'success', retentionDays, total: rows.length, offset, limit,
        attacks: rows.slice(offset, offset + limit).map(withId), pending: inWindow.length - builtAll.length, summary,
      })
    }

    // Default: newest first; analyse exactly the requested page if needed.
    const ordered = desc ? inWindow : [...inWindow].reverse()
    const page = ordered.slice(offset, offset + limit)
    const settled = await Promise.allSettled(page.map(getBuilt))
    const attacks = settled.map((r, i) => (r.status === 'fulfilled'
      ? withId(r.value)
      : { ...withId({ start: page[i].start * 1000, end: page[i].end * 1000, durationSec: page[i].end - page[i].start, vectors: [], attackers: [], victims: [] } as Built), partial: true }))
    return NextResponse.json({
      status: 'success', retentionDays, total: ordered.length, offset, limit, attacks,
      pending: inWindow.length - inWindow.filter((e) => known(e)).length, summary,
    })
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    return NextResponse.json({ status: 'error', error: msg }, { status: 502 })
  }
}
