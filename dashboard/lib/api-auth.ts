// Node-only permission checks for API routes. Middleware (Edge) gates pages from
// the signed cookie; these helpers re-check against the CURRENT user store
// (lib/users liveAccess), so a changed group, removed permission, disabled or
// deleted account is enforced on the next request — not at cookie expiry.
// Only when auth is explicitly disabled (DASH_AUTH_DISABLED=1) does every caller
// get every permission; a missing DASH_SESSION denies everything (fail closed).
import { NextRequest, NextResponse } from 'next/server'
import { verifySession, PERM_IDS, ADMIN_PAGE, authMode } from './authz'
import { liveAccess, type Access } from './users'
import { audit } from './audit'

export function authEnabled(): boolean {
  return authMode() !== 'off'
}

// Cookie options: Secure whenever the dashboard is reached over HTTPS (directly
// or via a TLS proxy that sets X-Forwarded-Proto).
export function cookieOpts(req: NextRequest, maxAge: number) {
  const proto = req.headers.get('x-forwarded-proto') || req.nextUrl.protocol.replace(':', '')
  return { httpOnly: true, sameSite: 'lax' as const, path: '/', maxAge, secure: proto === 'https' }
}

// The caller's live access, or null when not signed in / no longer allowed.
export async function currentAccess(req: NextRequest): Promise<(Access & { authDisabled?: boolean }) | null> {
  const mode = authMode()
  if (mode === 'off') return { username: '', group: '', perms: [...PERM_IDS], kind: 'user', epoch: 0, authDisabled: true }
  if (mode === 'misconfigured') return null
  const s = await verifySession(process.env.DASH_SESSION!, req.cookies.get('dash_auth')?.value)
  return s ? liveAccess(s) : null
}

// Require a permission (null = just signed in and still active).
export async function requirePerm(
  req: NextRequest,
  perm: string | null,
): Promise<{ access: Access & { authDisabled?: boolean }; error?: undefined } | { access?: undefined; error: NextResponse }> {
  const access = await currentAccess(req)
  const path = req.nextUrl.pathname
  if (!access) {
    // Anonymous/revoked attempts to CHANGE something are always recorded.
    if (req.method !== 'GET') audit(req, { user: '', category: 'access', action: 'access.unauthorized', target: path, summary: `Not signed in: ${req.method} ${path}`, result: 'denied' })
    return { error: NextResponse.json({ error: 'unauthorized' }, { status: 401 }) }
  }
  if (access.mfaSetupRequired) {
    // The group requires two-factor and this user hasn't set it up: nothing but
    // their own profile (which doesn't go through here) works until they do.
    return { error: NextResponse.json({ error: 'mfa_setup_required', hint: 'set up two-factor on your profile page' }, { status: 403 }) }
  }
  if (perm && !access.perms.includes(perm)) {
    audit(req, { user: access.username, kind: access.kind, category: 'access', action: 'access.denied', target: path, summary: `Lacks “${perm}”: ${req.method} ${path}`, detail: { need: perm, method: req.method }, result: 'denied' })
    return { error: NextResponse.json({ error: 'forbidden', need: perm }, { status: 403 }) }
  }
  return { access }
}

export interface Caller {
  username: string | null
  authDisabled: boolean
}

// Admin = holds the Users & groups permission.
export async function requireAdmin(
  req: NextRequest,
): Promise<{ caller: Caller; error?: undefined } | { caller?: undefined; error: NextResponse }> {
  const r = await requirePerm(req, ADMIN_PAGE)
  if (r.error) return { error: r.error }
  return { caller: { username: r.access.authDisabled ? null : r.access.username, authDisabled: !!r.access.authDisabled } }
}

// The caller's username if they hold `perm` ('' when auth is disabled), or null.
export async function protectActor(req: NextRequest, perm = 'protect'): Promise<string | null> {
  const r = await requirePerm(req, perm)
  if (r.error) return null
  return r.access.authDisabled ? '' : r.access.username
}
