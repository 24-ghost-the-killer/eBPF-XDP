// The address a request came from, and whether that is really the user or a
// Twingate connector relaying them.
//
// Remote users reach the dashboard through Twingate. A connector opens its own
// TCP connection to the dashboard for each user, so the dashboard only ever sees
// the CONNECTOR's address (192.168.1.51, or the Docker connector on the box at
// 172.17.0.x) — never the user's own. Such entries are labelled "via Twingate"
// instead of passing the connector off as the user's address, and the shared
// address is not used for per-address login lockouts (one person's typos would
// lock out everyone behind that connector).
//
// Override the list with DASH_TWINGATE_CONNECTORS="ip,ip,cidr,…".
import type { NextRequest } from 'next/server'

const DEFAULT_CONNECTORS = '192.168.1.51,172.17.0.0/16'

// "::ffff:192.168.1.51" (an IPv4 client on a dual-stack socket) -> "192.168.1.51"
export const normIp = (ip: string | null | undefined): string | null => (ip ? ip.trim().replace(/^::ffff:/i, '') || null : null)

const v4 = (ip: string): number | null => {
  const p = ip.split('.')
  if (p.length !== 4) return null
  let n = 0
  for (const s of p) {
    const o = Number(s)
    if (!/^\d{1,3}$/.test(s) || o > 255) return null
    n = n * 256 + o
  }
  return n
}

// A syntactically valid IPv4 or IPv6 literal (what a reverse proxy would set).
// Anything else — a hostname, an injected string, an "ip, ip" chain that slipped
// through, empty — is not an address and must not be stored or keyed on.
const V6 = /^(([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,7}:|([0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}|([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}|([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}|([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:((:[0-9a-f]{1,4}){1,6})|:((:[0-9a-f]{1,4}){1,7}|:))$/i
export function isValidIp(ip: string | null | undefined): boolean {
  const s = normIp(ip)
  if (!s) return false
  return v4(s) !== null || V6.test(s)
}

// The address the request came from: the first X-Forwarded-For hop (our nginx
// overwrites this header with the real peer, so it is a single trusted value),
// else X-Real-IP. Only a well-formed IP is returned — a forged or garbage value
// from a client that reached the app without going through the proxy becomes
// null (unknown) rather than being trusted as an address.
export function clientAddr(req: NextRequest): string | null {
  const raw = normIp(req.headers.get('x-forwarded-for')?.split(',')[0] || req.headers.get('x-real-ip'))
  return isValidIp(raw) ? raw : null
}

let cached: { raw: string; rules: { base: number; mask: number }[] } | null = null
function rules() {
  const raw = process.env.DASH_TWINGATE_CONNECTORS ?? DEFAULT_CONNECTORS
  if (cached?.raw === raw) return cached.rules
  const out: { base: number; mask: number }[] = []
  for (const item of raw.split(',').map((s) => s.trim()).filter(Boolean)) {
    const [ip, len] = item.split('/')
    const n = v4(ip)
    const bits = len === undefined ? 32 : Number(len)
    if (n === null || !Number.isInteger(bits) || bits < 0 || bits > 32) continue
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0
    out.push({ base: (n & mask) >>> 0, mask })
  }
  cached = { raw, rules: out }
  return out
}

// True when the address belongs to a Twingate connector (not the end user).
export function isTwingateConnector(ip: string | null | undefined): boolean {
  const n = v4(normIp(ip) ?? '')
  if (n === null) return false
  return rules().some((r) => ((n & r.mask) >>> 0) === r.base)
}
