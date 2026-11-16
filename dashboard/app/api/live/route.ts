import { NextRequest, NextResponse } from 'next/server'
import { requirePerm } from '@/lib/api-auth'
import { geoInit, geoReady, withGeo, summariseSources, type GeoCount } from '@/lib/geo'

// Is an attack happening RIGHT NOW? Polled by the alert banner on every page
// (every few seconds) and by the live globe.
//   GET /api/live           -> { status, active: false } when calm (one query)
//   GET /api/live           -> { status, active: true, since, ifaces, types, pps,
//                                bps, dropPps, dropShare, level, cap, sources?, countries? }
//   GET /api/live?sources=1 -> also the live sources (top 60 by rate) and their
//                              countries, for the live globe
//   GET /api/live?at=<unix s> -> the same, as it was at that moment (testing the
//                              banner and globe against a past attack)
// Answers are cached for 3 s so many open tabs cost Prometheus one query set.
export const dynamic = 'force-dynamic'

const PROM = process.env.PROM_URL || 'http://localhost:9091'
const SAMPLE = 16 // the dataplane credits 1 dropped packet in 16 to its source (see /api/attacks)

async function qAt(expr: string, time?: number) {
  const u = new URL(`${PROM}/api/v1/query`)
  u.searchParams.set('query', expr)
  if (time) u.searchParams.set('time', String(time))
  const j = await (await fetch(u.toString(), { cache: 'no-store', signal: AbortSignal.timeout(6000) })).json()
  if (j.status !== 'success') throw new Error(j.error || 'query failed')
  return j.data.result as { metric: Record<string, string>; value: [number, string] }[]
}
async function qr(expr: string, start: number, end: number, step: number) {
  const u = new URL(`${PROM}/api/v1/query_range`)
  u.searchParams.set('query', expr)
  u.searchParams.set('start', String(start))
  u.searchParams.set('end', String(end))
  u.searchParams.set('step', String(step))
  const j = await (await fetch(u.toString(), { cache: 'no-store', signal: AbortSignal.timeout(6000) })).json()
  if (j.status !== 'success') throw new Error(j.error || 'query failed')
  return j.data.result as { metric: Record<string, string>; values: [number, string][] }[]
}
const val = (r: { value: [number, string] }[]) => (r[0] ? parseFloat(r[0].value[1]) || 0 : 0)
const by = (r: { metric: Record<string, string>; value: [number, string] }[], k: string) => new Map(r.map((x) => [x.metric[k], parseFloat(x.value[1]) || 0]))
const vlanName = (i: string) => (i === 'vlan10' ? 'VLAN10 · wan' : i === 'vlan20' ? 'VLAN20 · lan' : i)
function scopeOf(ip: string) {
  if (ip.includes(':')) return /^(fe[89ab]|f[cd])/i.test(ip) ? 'lan' : 'wan'
  const o = ip.split('.').map(Number)
  return o[0] === 10 || (o[0] === 192 && o[1] === 168) || (o[0] === 172 && o[1] >= 16 && o[1] <= 31) ? 'lan' : 'wan'
}

const cache = new Map<string, { at: number; body: unknown }>()

async function build(withSources: boolean, at?: number) {
  const q = (expr: string) => qAt(expr, at)
  const det = await q('max by(iface)(xs_detection_active)')
  const ifaces = det.filter((r) => parseFloat(r.value[1]) > 0).map((r) => r.metric.iface)
  if (!ifaces.length) return { status: 'success', active: false, at: Date.now() }

  const now = at ?? Math.floor(Date.now() / 1000)
  const [types, rx, rxb, drop, level, cap, run] = await Promise.all([
    q('max by(type)(xs_detection_info)'),
    q('sum by(iface)(rate(xs_rx_packets_total[15s]))'),
    q('sum(rate(xs_rx_bytes_total[15s]))*8'),
    q('sum(rate(xs_verdict_packets_total{verdict="drop"}[15s]))'),
    q('max(xs_risk_level)'),
    q('max(xs_mitigation_rate_pps)'),
    // when this attack began: walk back over the last hour to the start of the
    // current run of detection (gaps under 2.5 min belong to the same attack)
    qr('max(xs_detection_active)', now - 3600, now, 5),
  ])
  let since = now
  const pts = run[0]?.values ?? []
  for (let k = pts.length - 1, gap = 0; k >= 0; k--) {
    if (parseFloat(pts[k][1]) > 0) { since = +pts[k][0]; gap = 0 } else if ((gap += 5) > 150) break
  }
  const pps = [...by(rx, 'iface').values()].reduce((a, b) => a + b, 0)
  const dropPps = val(drop)
  const body: Record<string, unknown> = {
    status: 'success', active: true, at: Date.now(), since: since * 1000,
    ifaces: ifaces.map((i) => ({ iface: i, label: vlanName(i), pps: by(rx, 'iface').get(i) ?? 0 })),
    types: types.filter((r) => parseFloat(r.value[1]) > 0).map((r) => r.metric.type).filter(Boolean),
    pps, bps: val(rxb), dropPps, dropShare: pps > 0 ? Math.min(1, dropPps / pps) : 0,
    level: Math.round(val(level)), cap: Math.round(val(cap)),
  }
  if (withSources) {
    await geoInit()
    const [sp, sb] = await Promise.all([
      q(`topk(60, sum by(src)(rate(xs_attacker_packets_total[30s]))) > 0`),
      q(`sum by(src)(rate(xs_attacker_bytes_total[30s]))`),
    ])
    const bytes = by(sb, 'src')
    const sources = sp.map((r) => {
      const ip = r.metric.src
      const base = { ip, scope: scopeOf(ip), pps: Math.round(parseFloat(r.value[1]) * SAMPLE), bps: Math.round((bytes.get(ip) ?? 0) * SAMPLE * 8) }
      return geoReady() ? withGeo(base) : base
    }).sort((a, b) => b.pps - a.pps)
    // countries weighted by the live rate: packets = packets/s, bytes = bytes/s
    const countries: GeoCount[] = geoReady()
      ? summariseSources(sources.map((s) => ({ ip: s.ip, packets: s.pps, bytes: s.bps / 8 })), 23).countries
      : []
    body.sources = sources
    body.countries = countries
  }
  return body
}

export async function GET(req: NextRequest) {
  const auth = await requirePerm(req, null)
  if (auth.error) return auth.error
  const withSources = req.nextUrl.searchParams.get('sources') === '1'
  const atRaw = Number(req.nextUrl.searchParams.get('at'))
  const at = Number.isFinite(atRaw) && atRaw > 1e9 && atRaw < Date.now() / 1000 ? Math.floor(atRaw) : undefined
  const key = `${withSources ? 's' : 'b'}${at ?? ''}`
  const hit = cache.get(key)
  if (hit && Date.now() - hit.at < 3000) return NextResponse.json(hit.body)
  try {
    const body = await build(withSources, at)
    if (cache.size > 20) cache.clear()
    cache.set(key, { at: Date.now(), body })
    return NextResponse.json(body)
  } catch (e) {
    return NextResponse.json({ status: 'error', error: e instanceof Error ? e.message : String(e) }, { status: 502 })
  }
}
