// Offline IP -> country + ASN enrichment, Node-only. Reads the DB-IP Lite
// databases (MaxMind .mmdb format) from $DASH_GEOIP_DIR (default
// /usr/share/GeoIP); no per-lookup network calls. If the files are absent the
// module is simply inert (geoReady() === false) and every lookup returns null,
// so the dashboard works with or without the databases installed.
//
// The databases are CC BY 4.0 — the UI shows the attribution geoAttribution().
import maxmind, { type Reader, type Response, type CountryResponse, type AsnResponse } from 'maxmind'
import { statSync } from 'node:fs'
import { join } from 'node:path'

export interface GeoInfo { cc?: string; country?: string; asn?: number; org?: string }
export const geoAttribution = 'IP geolocation by DB-IP (CC BY 4.0)'

const dir = () => process.env.DASH_GEOIP_DIR || '/usr/share/GeoIP'
const COUNTRY_FILE = 'dbip-country-lite.mmdb'
const ASN_FILE = 'dbip-asn-lite.mmdb'

interface Loaded<T extends Response> { reader: Reader<T>; mtimeMs: number; path: string }
const readers: { country?: Loaded<CountryResponse>; asn?: Loaded<AsnResponse> } = {}
let lastCheck = 0
const CHECK_EVERY = 5 * 60_000 // re-stat at most every 5 min (picks up the monthly refresh)

function mtimeOf(path: string): number | null {
  try { return statSync(path).mtimeMs } catch { return null }
}

// Open (or re-open after a refresh) a database; returns null if the file is gone.
async function ensure<T extends Response>(slot: 'country' | 'asn', file: string): Promise<Reader<T> | null> {
  const path = join(dir(), file)
  const cur = readers[slot] as Loaded<T> | undefined
  const now = Date.now()
  const stale = !cur || cur.path !== path || now - lastCheck > CHECK_EVERY
  if (cur && !stale) return cur.reader
  lastCheck = now
  const mtime = mtimeOf(path)
  if (mtime === null) { delete readers[slot]; return null }
  if (cur && cur.path === path && cur.mtimeMs === mtime) return cur.reader // unchanged on disk
  try {
    const reader = await maxmind.open<T>(path)
    readers[slot] = { reader, mtimeMs: mtime, path } as never
    return reader
  } catch {
    return cur?.reader ?? null // keep the old reader if a reload failed mid-write
  }
}

// Warm both readers once; returns whether at least the country DB is present.
export async function geoInit(): Promise<boolean> {
  const [c] = await Promise.all([
    ensure<CountryResponse>('country', COUNTRY_FILE),
    ensure<AsnResponse>('asn', ASN_FILE),
  ])
  return !!c
}

export function geoReady(): boolean {
  return !!readers.country || mtimeOf(join(dir(), COUNTRY_FILE)) !== null
}

// Look up one IP (v4 or v6). Readers must be warmed with geoInit() first; this
// is synchronous so it can enrich long lists without a promise per address.
export function geoLookup(ip: string): GeoInfo | null {
  if (!maxmind.validate(ip)) return null
  const out: GeoInfo = {}
  try {
    const c = readers.country?.reader.get(ip)
    if (c?.country) { out.cc = c.country.iso_code; out.country = c.country.names?.en }
  } catch {}
  try {
    const a = readers.asn?.reader.get(ip)
    if (a) { out.asn = a.autonomous_system_number; out.org = a.autonomous_system_organization }
  } catch {}
  return out.cc || out.asn ? out : null
}

// Attach geo to one party-like object (returns a new object).
export function withGeo<T extends { ip: string }>(p: T): T & GeoInfo {
  const g = geoLookup(p.ip)
  return g ? { ...p, ...g } : p
}

// ---- aggregates for an attack: top source countries / networks --------------
export interface GeoCount { key: string; label: string; packets: number; sources: number; cc?: string; asn?: number; bytes?: number }
export interface SourceGeo { countries: GeoCount[]; asns: GeoCount[]; located: number; unlocated: number }

// Roll a full attacker list up into the top countries and top ASNs, weighted by
// dropped packets, with how many distinct sources each represents.
export function summariseSources(attackers: { ip: string; packets: number; bytes?: number }[], top = 8): SourceGeo {
  const byCc = new Map<string, GeoCount>()
  const byAsn = new Map<string, GeoCount>()
  let located = 0, unlocated = 0
  for (const a of attackers) {
    const g = geoLookup(a.ip)
    if (g?.cc) {
      const e = byCc.get(g.cc) ?? { key: g.cc, label: g.country || g.cc, cc: g.cc, packets: 0, sources: 0, bytes: 0 }
      e.packets += a.packets; e.sources += 1; e.bytes! += a.bytes ?? 0; byCc.set(g.cc, e)
    }
    if (g?.asn) {
      const k = String(g.asn)
      const e = byAsn.get(k) ?? { key: k, label: g.org || `AS${g.asn}`, asn: g.asn, packets: 0, sources: 0, bytes: 0 }
      e.packets += a.packets; e.sources += 1; e.bytes! += a.bytes ?? 0; byAsn.set(k, e)
    }
    if (g?.cc || g?.asn) located += 1; else unlocated += 1
  }
  const sort = (m: Map<string, GeoCount>) => [...m.values()].sort((x, y) => y.packets - x.packets).slice(0, top)
  return { countries: sort(byCc), asns: sort(byAsn), located, unlocated }
}
