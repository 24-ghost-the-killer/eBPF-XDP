import { NextRequest, NextResponse } from 'next/server'
import { verifySession, signSession, ADMIN_PAGE, PERM_IDS, SESSION_TTL, SESSION_REFRESH } from '@/lib/authz'
import { liveAccess } from '@/lib/users'
import { authEnabled, cookieOpts } from '@/lib/api-auth'
import { audit } from '@/lib/audit'

// Who am I, right now? Identity, group and LIVE permissions (from the current
// user store, not the cookie), so the UI shows exactly what the user may do.
// If the cookie's permissions have drifted from the live ones (an admin changed
// the group), the cookie is re-signed here, so page access in the Edge
// middleware follows within one poll. A disabled or deleted account gets 401
// and its cookie cleared. Sessions also slide: once less than SESSION_REFRESH is
// left, the cookie is re-issued for another SESSION_TTL. When auth is explicitly
// disabled, everything is allowed.
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

const same = (a: string[], b: string[]) => a.length === b.length && a.every((x) => b.includes(x))

export async function GET(req: NextRequest) {
  if (!authEnabled()) {
    return NextResponse.json({ authDisabled: true, perms: PERM_IDS, pages: PERM_IDS, isAdmin: true })
  }
  const secret = process.env.DASH_SESSION!
  const s = await verifySession(secret, req.cookies.get('dash_auth')?.value)
  const live = s ? liveAccess(s) : null
  if (!s || !live) {
    const res = NextResponse.json({ error: 'unauthorized' }, { status: 401 })
    if (s) {
      res.cookies.set('dash_auth', '', { path: '/', maxAge: 0 }) // account disabled, removed or revoked
      audit(req, { user: s.u, kind: s.k, category: 'auth', action: 'auth.session_ended', target: `user:${s.u}`, summary: `${s.u}'s session was ended (account disabled, deleted or signed out everywhere)`, result: 'denied' })
    }
    return res
  }
  const body = {
    username: live.username, group: live.group, kind: live.kind,
    perms: live.perms, pages: live.perms, // `pages` kept for older clients
    isAdmin: live.perms.includes(ADMIN_PAGE),
  }
  const res = NextResponse.json(body)
  const expiringSoon = s.exp - Math.floor(Date.now() / 1000) < SESSION_REFRESH
  if (!same(s.p, live.perms) || s.g !== live.group || expiringSoon) {
    const token = await signSession(secret, live.username, live.group, live.perms, SESSION_TTL, live.kind, live.epoch)
    res.cookies.set('dash_auth', token, cookieOpts(req, SESSION_TTL))
  }
  return res
}
