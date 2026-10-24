// Shared, Edge-safe authorization core: the page catalog (the unit of
// permission), the route -> page map, and signed-session-token sign/verify
// (Web Crypto HMAC, so the same code runs in Edge middleware and Node routes).
//
// Permissions are per PAGE. A group grants a set of page ids; a user belongs to
// a group. At login the user's group is resolved to its page list and baked into
// the signed token, so middleware (which cannot read the groups file on the Edge
// runtime) only has to check the token. Group/password changes take effect at
// the user's next login.
//
// No Node-only APIs here (no node:crypto, no fs). Password hashing and the
// user/group store live in lib/users.ts (Node-only).

export interface PageDef { id: string; label: string; path: string }

// The pages a group can be granted. `users` is the admin surface (managing users
// and groups); granting it is what makes a group an "admin" group.
export const PAGES: PageDef[] = [
  { id: 'overview', label: 'Overview', path: '/analytics' },
  { id: 'explore', label: 'Explorer', path: '/analytics/explore' },
  { id: 'attacks', label: 'Attacks', path: '/analytics/attacks' },
  { id: 'ai', label: 'AI security', path: '/analytics/ai' },
  { id: 'protect', label: 'Protection', path: '/analytics/protect' },
  { id: 'ip', label: 'IP lookup', path: '/analytics/ip' },
  { id: 'query', label: 'Query console', path: '/analytics/query' },
  { id: 'users', label: 'Users & groups', path: '/analytics/users' },
]
export const PAGE_IDS = PAGES.map((p) => p.id)
export const ADMIN_PAGE = 'users' // granting this page = admin (manage users/groups)

export function isPageId(x: unknown): x is string {
  return typeof x === 'string' && PAGE_IDS.includes(x)
}

// Page-specific API prefixes beyond the page paths themselves.
const EXTRA_ROUTES: Array<[string, string]> = [
  ['/api/agent', 'protect'], // protection data proxy
  ['/api/protect-plan', 'protect'], // read/write the protection plan
  ['/api/lockdown', 'protect'], // read/write the lockdown kill-switch
  ['/analytics/groups', 'users'], // groups is its own page, still an admin surface
  ['/api/users', 'users'],
  ['/api/groups', 'users'],
]
// Longest prefix wins, so /analytics/explore beats /analytics (overview).
const ROUTE_PAGE: Array<[string, string]> = [
  ...PAGES.map((p) => [p.path, p.id] as [string, string]),
  ...EXTRA_ROUTES,
].sort((a, b) => b[0].length - a[0].length)

// The page id a path requires, or null when it only requires being signed in
// (shared data APIs like /api/prom, /api/attacks, /api/me).
export function routePageId(pathname: string): string | null {
  for (const [prefix, id] of ROUTE_PAGE) {
    if (pathname === prefix) return id
    // '/analytics' is the Overview page itself; it must not swallow unknown
    // subpaths like /analytics/no-access (those need only login).
    if (prefix !== '/analytics' && pathname.startsWith(prefix + '/')) return id
  }
  return null
}

// ---- signed session token -------------------------------------------------
// token = base64url(payloadJSON) + "." + base64url(HMAC-SHA256(payload, key))
// payload = { u: username, g: group, p: allowed page ids, exp: epoch-seconds }

export interface Session {
  u: string
  g: string
  p: string[]
  exp: number
}

export function sessionCan(s: Session, pageId: string | null): boolean {
  if (!pageId) return true // only needs to be signed in
  return s.p.includes(pageId)
}
export function sessionIsAdmin(s: Session): boolean {
  return s.p.includes(ADMIN_PAGE)
}
// First page this session may open, for a loop-free redirect out of a forbidden
// page. null when the group grants nothing.
export function firstAllowedPath(s: Session): string | null {
  for (const p of PAGES) if (s.p.includes(p.id)) return p.path
  return null
}

const enc = new TextEncoder()

function b64urlFromBytes(bytes: Uint8Array): string {
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i])
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function b64urlFromString(s: string): string {
  return b64urlFromBytes(enc.encode(s))
}
function stringFromB64url(b64: string): string {
  const s = b64.replace(/-/g, '+').replace(/_/g, '/')
  const pad = s.length % 4 ? '='.repeat(4 - (s.length % 4)) : ''
  const bin = atob(s + pad)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return new TextDecoder().decode(bytes)
}

async function hmac(secret: string, data: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data))
  return b64urlFromBytes(new Uint8Array(sig))
}

function timingSafeEqual(a: string, b: string): boolean {
  let r = a.length ^ b.length
  const n = Math.max(a.length, b.length)
  for (let i = 0; i < n; i++) r |= a.charCodeAt(i % a.length || 0) ^ b.charCodeAt(i % b.length || 0)
  return r === 0
}

const YEAR_SECONDS = 60 * 60 * 24 * 365

export async function signSession(
  secret: string,
  username: string,
  group: string,
  pages: string[],
  ttlSeconds: number = YEAR_SECONDS,
): Promise<string> {
  const payload: Session = { u: username, g: group, p: pages.filter(isPageId), exp: Math.floor(Date.now() / 1000) + ttlSeconds }
  const p = b64urlFromString(JSON.stringify(payload))
  const sig = await hmac(secret, p)
  return `${p}.${sig}`
}

export async function verifySession(secret: string, token: string | undefined): Promise<Session | null> {
  if (!secret || !token) return null
  const dot = token.indexOf('.')
  if (dot <= 0) return null
  const p = token.slice(0, dot)
  const sig = token.slice(dot + 1)
  let expect: string
  try {
    expect = await hmac(secret, p)
  } catch {
    return null
  }
  if (!timingSafeEqual(sig, expect)) return null
  let payload: Session
  try {
    payload = JSON.parse(stringFromB64url(p))
  } catch {
    return null
  }
  if (!payload || typeof payload.u !== 'string' || typeof payload.exp !== 'number' || !Array.isArray(payload.p)) return null
  if (payload.exp < Math.floor(Date.now() / 1000)) return null
  payload.p = payload.p.filter(isPageId)
  return payload
}
