// Shared, Edge-safe authorization core: the page catalog (the unit of
// permission), the route -> page map, and signed-session-token sign/verify
// (Web Crypto HMAC, so the same code runs in Edge middleware and Node routes).
//
// Permissions are PAGES (may open the page) plus ACTIONS inside a page (may
// change something there, e.g. edit the protection plan). A group grants a set
// of permission ids; a user belongs to a group. At login the group's permissions
// are baked into the signed token so Edge middleware can gate pages without
// reading the groups file. Node API routes re-check the user's CURRENT group on
// every request (lib/access.ts), and /api/me re-signs the cookie when it drifts,
// so permission changes and disabled accounts take effect immediately.
//
// No Node-only APIs here (no node:crypto, no fs). Password hashing and the
// user/group store live in lib/users.ts (Node-only).

// ---- auth mode -------------------------------------------------------------
// Fail CLOSED. Login is required unless explicitly turned off for a lab with
// DASH_AUTH_DISABLED=1. If DASH_SESSION (the cookie signing key) is missing the
// dashboard refuses to serve rather than silently running wide open (the old
// fail-open default exposed the protection plan, lockdown and user admin to
// anyone on the network whenever the env file was missing).
export type AuthMode = 'on' | 'off' | 'misconfigured'
export function authMode(): AuthMode {
  if (process.env.DASH_AUTH_DISABLED === '1') return 'off'
  return process.env.DASH_SESSION ? 'on' : 'misconfigured'
}

// Sessions are short and sliding: valid for SESSION_TTL, re-signed by /api/me
// once less than SESSION_REFRESH remains, so an active user stays signed in and
// an abandoned cookie dies on its own.
export const SESSION_TTL = 14 * 24 * 3600
export const SESSION_REFRESH = 7 * 24 * 3600

export interface PageDef { id: string; label: string; path: string; hint: string }

// The pages a group can be granted. `users` is the admin surface (managing users
// and groups); granting it is what makes a group an "admin" group.
export const PAGES: PageDef[] = [
  { id: 'overview', label: 'Overview', path: '/analytics', hint: 'key numbers and automatic insights' },
  { id: 'explore', label: 'Explorer', path: '/analytics/explore', hint: 'any metric over any time range' },
  { id: 'attacks', label: 'Attacks', path: '/analytics/attacks', hint: 'attack episodes with drill-down' },
  { id: 'ai', label: 'AI security', path: '/analytics/ai', hint: 'risk engine and automated defenses' },
  { id: 'protect', label: 'Protection', path: '/analytics/protect', hint: 'view protected hosts, reports and logs' },
  { id: 'ip', label: 'IP lookup', path: '/analytics/ip', hint: 'investigate one address' },
  { id: 'query', label: 'Query console', path: '/analytics/query', hint: 'run raw PromQL against Prometheus' },
  { id: 'users', label: 'Users & groups', path: '/analytics/users', hint: 'manage accounts and permissions (admin)' },
  { id: 'audit', label: 'Audit log', path: '/analytics/audit', hint: 'every action taken on the dashboard — who, what, when' },
]
export const PAGE_IDS = PAGES.map((p) => p.id)
export const ADMIN_PAGE = 'users' // granting this page = admin (manage users/groups)

export function isPageId(x: unknown): x is string {
  return typeof x === 'string' && PAGE_IDS.includes(x)
}

// Actions inside a page. An action only takes effect together with its page.
export interface ActionDef { id: string; page: string; label: string; hint: string; danger?: boolean }
export const ACTIONS: ActionDef[] = [
  { id: 'protect.plan', page: 'protect', label: 'Edit protected hosts & ports', hint: 'add or remove hosts and allowed services, then Save & apply to the firewall', danger: true },
  { id: 'protect.lockdown', page: 'protect', label: 'Arm & lift lockdown', hint: 'the kill-switch that blocks the internal network', danger: true },
  { id: 'protect.notes', page: 'protect', label: 'Edit nicknames & log', hint: 'rename hosts and add dated log entries' },
  { id: 'protect.reports', page: 'protect', label: 'Write reports', hint: 'create and edit setup, incident, maintenance and audit reports' },
  { id: 'protect.delete', page: 'protect', label: 'Delete reports & log entries', hint: 'permanently remove reports and log entries', danger: true },
]
export const ACTION_IDS = ACTIONS.map((a) => a.id)
export const PERM_IDS = [...PAGE_IDS, ...ACTION_IDS]
export function isPermId(x: unknown): x is string {
  return typeof x === 'string' && PERM_IDS.includes(x)
}
export const actionsOf = (page: string) => ACTIONS.filter((a) => a.page === page)

// Pages grouped for the permission editor.
export const AREAS: { id: string; label: string; pages: string[] }[] = [
  { id: 'monitor', label: 'Monitoring', pages: ['overview', 'explore', 'attacks', 'ai', 'ip'] },
  { id: 'protect', label: 'Protection', pages: ['protect'] },
  { id: 'tools', label: 'Tools', pages: ['query'] },
  { id: 'admin', label: 'Administration', pages: ['users', 'audit'] },
]

// Valid, de-duplicated permissions; drops actions whose page isn't granted.
export function effectivePerms(perms: unknown): string[] {
  if (!Array.isArray(perms)) return []
  const set = new Set(perms.filter(isPermId))
  return PERM_IDS.filter((id) => set.has(id) && (isPageId(id) || set.has(ACTIONS.find((a) => a.id === id)!.page)))
}

// One-click starting points in the group editor.
const MONITOR = ['overview', 'explore', 'attacks', 'ai', 'ip']
export const PRESETS: { id: string; label: string; hint: string; perms: string[] }[] = [
  { id: 'viewer', label: 'Viewer', hint: 'all dashboards and Protection, read-only', perms: [...MONITOR, 'protect'] },
  { id: 'operator', label: 'Operator', hint: 'viewer + manage protection, notes and reports', perms: [...MONITOR, 'protect', 'query', ...ACTION_IDS] },
  { id: 'admin', label: 'Admin', hint: 'everything, including users & groups', perms: [...PERM_IDS] },
]

// Page-specific API prefixes beyond the page paths themselves.
// (Pages only — actions are enforced inside the Node routes.)
const EXTRA_ROUTES: Array<[string, string]> = [
  ['/api/agent', 'protect'], // protection data proxy
  ['/api/protect-plan', 'protect'], // read/write the protection plan
  ['/api/protect-meta', 'protect'], // per-host nickname / reports / log
  ['/api/lockdown', 'protect'], // read/write the lockdown kill-switch
  ['/analytics/groups', 'users'], // groups is its own page, still an admin surface
  ['/api/users', 'users'],
  ['/api/groups', 'users'],
  // /api/audit is NOT mapped: any signed-in user may POST their own client
  // events (exports, page views); reading the log is checked in the route.
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
// payload = { u: username, g: group, p: permission ids, exp: epoch-seconds, k: kind }

// How the session was obtained: a stored user, the kiosk link, the DASH_PASSWORD
// break-glass, or the built-in default admin (only while no admin user exists).
export type SessionKind = 'user' | 'kiosk' | 'breakglass' | 'default'
export interface Session {
  u: string
  g: string
  p: string[]
  exp: number
  k?: SessionKind
  e?: number // user's session epoch at signing; bumping it revokes older cookies
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

// HMAC for server-internal messages (middleware -> /api/audit). Edge-safe.
export async function signInternal(secret: string, data: string): Promise<string> {
  return hmac(`audit:${secret}`, data)
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

export async function signSession(
  secret: string,
  username: string,
  group: string,
  perms: string[],
  ttlSeconds: number = SESSION_TTL,
  kind: SessionKind = 'user',
  epoch = 0,
): Promise<string> {
  const payload: Session = { u: username, g: group, p: effectivePerms(perms), exp: Math.floor(Date.now() / 1000) + ttlSeconds, k: kind, e: epoch }
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
  payload.p = effectivePerms(payload.p)
  return payload
}
