import { NextRequest, NextResponse } from 'next/server'
import { requirePerm } from '@/lib/api-auth'
import { readFile, writeFile, rename, mkdir } from 'node:fs/promises'
import { geoInit, geoReady, withGeo, summariseSources, type SourceGeo } from '@/lib/geo'
import { readMarks } from '@/lib/marks'
import { simulationAt } from '@/lib/sim'
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
// 4: + 'ARP storm' vector (in-retention episodes are re-analysed once)
// 5: + `mitigation` (what the defences did, for "why wasn't this blocked?") and
//    dropped bytes per source country
const CACHE_SCHEMA = 5

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
interface Party { ip: string; scope?: string; packets: number; bytes: number; pps: number; bps: number; cc?: string; country?: string; asn?: number; org?: string }
async function parties(ep: Ep, durSec: number): Promise<{ attackers: Party[]; victims: Party[]; sample: number; sourceGeo?: SourceGeo }> {
  const w = windowOf(ep)
  const k = sampleOf(ep)
  const [ap, ab, vp, vb] = await Promise.all([
    instant(episodeSum('xs_attacker_packets_total', 'src', w), w.at, 60000),
    instant(episodeSum('xs_attacker_bytes_total', 'src', w), w.at, 60000),
    instant(episodeSum('xs_target_packets_total', 'dst', w), w.at, 60000),
    instant(episodeSum('xs_target_bytes_total', 'dst', w), w.at, 60000),
  ])
  await geoInit() // warm the geo readers (no-op/false if the DBs aren't installed)
  const list = (pk: Vec, by: Vec, key: string, withScope: boolean): Party[] => {
    const bytes = toMap(by, key)
    return [...toMap(pk, key).entries()]
      .filter(([, n]) => n > 0)
      .map(([ip, n]) => {
        const packets = Math.round(n * k)
        const b = Math.round((bytes.get(ip) ?? 0) * k)
        const base: Party = { ip, ...(withScope ? { scope: scopeOf(ip) } : {}), packets, bytes: b, pps: Math.round(packets / durSec), bps: (b * 8) / durSec }
        return withScope ? withGeo(base) : base // enrich attacker sources; the few victims are our own hosts
      })
      .sort((x, y) => y.packets - x.packets)
  }
  const attackers = list(ap, ab, 'src', true)
  return { attackers, victims: list(vp, vb, 'dst', false), sample: k, sourceGeo: geoReady() ? summariseSources(attackers) : undefined }
}
const vlanName = (ifc: string) => (ifc === 'vlan10' ? 'VLAN10 · wan' : ifc === 'vlan20' ? 'VLAN20 · lan' : ifc)

// RFC1918 (v4) / ULA + link-local (v6) → lan, else wan (from the address alone).
function scopeOf(ip: string): string {
  if (ip.includes(':')) {
    const h = ip.toLowerCase()
    if (h.startsWith('fe8') || h.startsWith('fe9') || h.startsWith('fea') || h.startsWith('feb')) return 'lan' // fe80::/10 link-local
    if (/^f[cd]/.test(h)) return 'lan' // fc00::/7 unique local
    if (h === '::1') return 'lan'
    return 'wan'
  }
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
  // non-IP: an L2 loop / broadcast storm (the 10 Nov episode read as 'UDP reflection')
  ['ARP storm', 'xs_l3_packets_total{proto="arp"}'],
  // scan detection (15 Nov): packets dropped from sources caught scanning
  ['Port scan', 'xs_scan_packets_total{event="drop"}'],
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
  // Top source countries / networks, rolled up over EVERY attacker (not just the
  // 25 listed), so a spoofed flood's geography still reads right.
  const sourceGeo = who.sourceGeo

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
  const mitigation = await mitigationOf(ep, sub, win, at, primaryIface)

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
    ...(sourceGeo ? { sourceGeo } : {}),
    ...(mitigation ? { mitigation } : {}),
    v: CACHE_SCHEMA,
  }
  return built
}

// What the defences did during an attack: whether auto-mitigation was armed or
// switched off, the strongest per-source cap, packets the rate limiter dropped,
// defences switched on for the attack (vs already on before it), the mitigation
// ladder over time, and the target interface's peak rate (to compare with the
// cap). Best effort: an attack is still listed if this fails.
const FLAG_ORDER = ['drop_syn', 'drop_ack', 'drop_udp', 'drop_udp_strict', 'drop_udp_dns', 'drop_icmp', 'drop_fragments', 'drop_untracked',
  'drop_ipv6_ext', 'ratelimit', 'global_rl', 'lockdown', 'auto_lockdown', 'drop_spoofed', 'drop_malformed', 'drop_bad_tcp_flags', 'conntrack', 'check_allow', 'service_allow']
async function mitigationOf(ep: Ep, sub: string, win: string, at: number, iface: string | null) {
  try {
    const before = ep.start - PAD - 30
    const span = ep.end - ep.start + 90
    const step = Math.max(5, Math.ceil(span / 1500))
    const [on, off, cap, rl, autoLock, during, prior, ladder, peak, untracked] = await Promise.all([
      instant(`max_over_time((max(xs_mitigation_active))${sub}) or vector(0)`, at),
      instant(`max_over_time((max(xs_mitigation_disarmed))${sub}) or vector(0)`, at),
      instant(`min_over_time((min(xs_mitigation_rate_pps > 0))${sub})`, at),
      instant(`sum(increase(xs_policy_event_packets_total{event="rate_limited"}${win})) or vector(0)`, at),
      instant(`max_over_time((max(xs_auto_lockdown_active))${sub}) or vector(0)`, at),
      instant(`max by(flag)(max_over_time(xs_config_flag${win}))`, at),
      instant(`max by(flag)(xs_config_flag)`, before),
      range(`max(xs_risk_level)`, ep.start - 30, ep.end + 60, step),
      instant(`max_over_time((sum by(iface)(rate(xs_rx_packets_total[30s])))${sub})`, at),
      // TCP packets matching no tracked connection (what "drop untracked" can drop)
      instant(`sum(increase(xs_conntrack_packets_total{event="untracked"}${win})) or vector(0)`, at),
    ])
    const flagsOn = (v: Vec) => new Set(v.filter((r) => parseFloat(r.value[1]) > 0).map((r) => r.metric.flag))
    const was = flagsOn(prior)
    const now = flagsOn(during)
    const order = (xs: string[]) => xs.sort((a, b) => (FLAG_ORDER.indexOf(a) + 99) % 99 - (FLAG_ORDER.indexOf(b) + 99) % 99)
    // ladder: only the points where the level changes, as [seconds from start, level]
    const steps: [number, number][] = []
    for (const [t, v] of ladder[0]?.values ?? []) {
      const lv = Math.round(parseFloat(v))
      if (!steps.length || steps[steps.length - 1][1] !== lv) steps.push([Math.round(+t - ep.start), lv])
    }
    const firstLimit = steps.find(([, lv]) => lv >= 3)
    const peakBy = new Map(peak.map((r) => [r.metric.iface, parseFloat(r.value[1])]))
    return {
      active: num(on) > 0,
      disarmed: num(off) > 0,
      rateCap: cap[0] ? Math.round(parseFloat(cap[0].value[1])) : 0,
      rateLimited: Math.round(num(rl)),
      autoLockdown: num(autoLock) > 0,
      armed: order([...now].filter((f) => !was.has(f))),
      baseline: order([...was]),
      ladder: steps.slice(0, 200),
      limitAfterSec: firstLimit ? Math.max(0, firstLimit[0]) : null,
      targetPeakPps: iface ? Math.round(peakBy.get(iface) ?? 0) : 0,
      untracked: Math.round(num(untracked)),
    }
  } catch {
    return null
  }
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
    p = { attackers: b.attackers, victims: b.victims, sample: (b.sample as number) ?? 1, sourceGeo: b.sourceGeo, complete: false }
  }
  PARTIES.set(k, { at: Date.now(), p })
  if (PARTIES.size > 20) PARTIES.delete(PARTIES.keys().next().value as string)
  return p
}

// Dropped bytes per source country. Attacks analysed before that was recorded
// only have packets per country: estimate bytes from the attack's own bytes per
// packet over its recorded sources, and flag the figure as an estimate.
type GeoC = { key: string; label: string; cc?: string; packets: number; sources: number; bytes?: number; bytesEstimated?: boolean }
function geoWithBytes(b: Built): GeoC[] {
  const sg = b.sourceGeo as { countries?: GeoC[] } | undefined
  const cs = sg?.countries ?? []
  if (cs.every((c) => typeof c.bytes === 'number')) return cs
  let pk = 0, by = 0
  for (const a of b.attackers as { packets?: number; bytes?: number }[]) {
    if ((a.bytes ?? 0) > 0 && (a.packets ?? 0) > 0) { pk += a.packets!; by += a.bytes! }
  }
  const per = pk ? by / pk : 0
  return cs.map((c) => (typeof c.bytes === 'number' || !per ? c : { ...c, bytes: Math.round(c.packets * per), bytesEstimated: true }))
}
const withGeoBytes = (b: Built): Built => (b.sourceGeo ? { ...b, sourceGeo: { ...(b.sourceGeo as object), countries: geoWithBytes(b) } } : b)
// stable id = start time in seconds; `mark` = a false-alarm mark, if any
// An attack a dashboard simulation caused carries a "simulation" mark (not
// stored: worked out from the simulation history), so it leaves the totals.
const simMark = (startSec: number, endSec: number) => {
  const r = simulationAt(startSec, endSec)
  return r ? { reason: 'simulation', note: r.label, by: r.by, at: Math.round(r.started_at * 1000) } : null
}
const withId = (b: Built) => {
  const id = Math.floor(b.start / 1000)
  const mark = readMarks()[String(id)] ?? simMark(b.start / 1000, (Number(b.end) || b.start) / 1000)
  return { ...withGeoBytes(b), id, ...(mark ? { mark } : {}) }
}
const isMarked = (e: { start: number; end: number }, marks: Record<string, unknown>) =>
  !!marks[String(Math.floor(e.start))] || !!simulationAt(e.start, e.end)
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
    const country = (sp.get('country') || '').trim().toUpperCase().slice(0, 2)
    const sort = SORTS.has(sp.get('sort') || '') ? (sp.get('sort') as string) : 'start'
    const desc = sp.get('desc') !== '0'
    const analysedOnly = sp.get('analysedOnly') === '1'
    // false alarms: 'hide' = real attacks only, 'only' = just the marked ones
    const markedFilter = sp.get('marked') || ''
    const marks = readMarks()

    const timeWindow = all.filter((e) => e.end >= from && e.start <= to)
    // Summary over the REAL attacks in the window (marked false alarms are left
    // out): counts/time from the list, traffic numbers from the analysed ones.
    const real = timeWindow.filter((e) => !isMarked(e, marks))
    const builtAll = real.map(known).filter((b): b is Built => !!b)
    const inWindow = markedFilter === 'hide' ? real : markedFilter === 'only' ? timeWindow.filter((e) => isMarked(e, marks)) : timeWindow
    const builtList = inWindow.map(known).filter((b): b is Built => !!b)
    const num = (b: Built, k: string) => Number(b[k]) || 0
    const summary = {
      count: real.length,
      falseAlarms: timeWindow.length - real.length,
      totalDurationSec: real.reduce((n, e) => n + Math.max(30, e.end - e.start), 0),
      analysed: builtAll.length,
      peakBps: Math.max(0, ...builtAll.map((b) => num(b, 'peakBps'))),
      peakPps: Math.max(0, ...builtAll.map((b) => num(b, 'peakPps'))),
      droppedPackets: builtAll.reduce((n, b) => n + num(b, 'droppedPackets'), 0),
      avgDropShare: builtAll.length ? builtAll.reduce((n, b) => n + num(b, 'dropShare'), 0) / builtAll.length : 0,
      medianDurationSec: (() => { const d = real.map((e) => Math.max(30, e.end - e.start)).sort((x, y) => x - y); return d.length ? d[Math.floor(d.length / 2)] : 0 })(),
      vectors: [...new Set(builtList.flatMap(vectorsOf))].sort(),
      oldest: timeWindow.length ? timeWindow[timeWindow.length - 1].start * 1000 : null,
      newest: timeWindow.length ? timeWindow[0].end * 1000 : null,
      archived: ARCHIVE.size,
      // Source countries over every analysed attack in the window (for the
      // origins globe): each attack's top countries, summed by country code.
      countries: (() => {
        type C = { key: string; label: string; cc?: string; packets: number; sources: number; bytes: number; bytesPartial: boolean; bytesEstimated: boolean; attacks: number; last: number }
        const by = new Map<string, C>()
        for (const b of builtAll) {
          for (const c of geoWithBytes(b)) {
            const e = by.get(c.key) ?? { key: c.key, label: c.label, cc: c.cc, packets: 0, sources: 0, bytes: 0, bytesPartial: false, bytesEstimated: false, attacks: 0, last: 0 }
            e.packets += Number(c.packets) || 0
            e.sources += Number(c.sources) || 0
            if (typeof c.bytes === 'number') e.bytes += c.bytes
            else e.bytesPartial = true // no byte count at all for that attack
            if (c.bytesEstimated) e.bytesEstimated = true
            e.attacks += 1
            e.last = Math.max(e.last, Number(b.end) || 0)
            by.set(c.key, e)
          }
        }
        return [...by.values()].sort((x, y) => y.packets - x.packets).slice(0, 40)
      })(),
    }

    // Filters / sorts that need the breakdown run over analysed attacks; the
    // rest are counted as `pending` (the background catch-up fills them in).
    const needsBreakdown = !!vector || !!ip || !!country || sort !== 'start' || analysedOnly
    if (needsBreakdown) {
      let rows = builtList
      if (vector) rows = rows.filter((b) => vectorsOf(b).includes(vector))
      if (ip) rows = rows.filter((b) => b.attackers.some((x) => x.ip.includes(ip)) || b.victims.some((x) => x.ip.includes(ip)))
      // attacks with at least one source in that country (the globe's "show these attacks")
      if (country) rows = rows.filter((b) => ((b.sourceGeo as { countries?: { cc?: string }[] } | undefined)?.countries ?? []).some((c) => c.cc === country)
        || (b.attackers as { cc?: string }[]).some((x) => x.cc === country))
      rows = [...rows].sort((x, y) => (desc ? num(y, sort) - num(x, sort) : num(x, sort) - num(y, sort)))
      void backfill(all)
      return NextResponse.json({
        status: 'success', retentionDays, total: rows.length, offset, limit,
        attacks: rows.slice(offset, offset + limit).map(withId), pending: inWindow.length - builtList.length, summary,
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
