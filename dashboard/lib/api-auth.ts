// Node-only helper for API routes that need an admin caller. Middleware already
// gates /api/users and /api/groups to the `users` page, but routes re-check
// (defense in depth). When auth is disabled on the server (fail-open), the
// caller is treated as a bootstrap admin so the first accounts can be created.
import { NextRequest, NextResponse } from 'next/server'
import { verifySession, sessionIsAdmin } from './authz'

export interface Caller {
  username: string | null
  authDisabled: boolean
}

export async function requireAdmin(
  req: NextRequest,
): Promise<{ caller: Caller; error?: undefined } | { caller?: undefined; error: NextResponse }> {
  const secret = process.env.DASH_SESSION
  const authOn = !!secret && (!!process.env.DASH_PASSWORD || !!process.env.DASH_USERS || !!process.env.DASH_USERS_FILE)
  if (!authOn) return { caller: { username: null, authDisabled: true } }
  const s = await verifySession(secret!, req.cookies.get('dash_auth')?.value)
  if (!s) return { error: NextResponse.json({ error: 'unauthorized' }, { status: 401 }) }
  if (!sessionIsAdmin(s)) return { error: NextResponse.json({ error: 'forbidden' }, { status: 403 }) }
  return { caller: { username: s.u, authDisabled: false } }
}
