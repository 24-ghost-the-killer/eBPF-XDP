import { NextRequest, NextResponse } from 'next/server'
import { timingSafeEqual } from 'node:crypto'
import { signSession, PAGE_IDS, SESSION_TTL } from '@/lib/authz'
import { permsForGroup } from '@/lib/users'
import { cookieOpts } from '@/lib/api-auth'
import { audit } from '@/lib/audit'

// Password-free sign-in for the local kiosk display. Its browser opens, once:
//   http://192.168.1.193:3000/api/kiosk?k=<DASH_KIOSK_KEY>
// and is signed in as the built-in `kiosk` user with the permissions of the
// group named by DASH_KIOSK_GROUP (default "viewers"); if that group is absent it
// falls back to the read-only dashboards (no Protection, no admin).
//
// DASH_KIOSK_KEY is a dedicated secret that can ONLY mint this kiosk session.
// (It used to be DASH_SESSION -- the cookie signing key -- in the URL, which
// leaked through browser history and the process list and let anyone forge an
// admin session.) No DASH_KIOSK_KEY = kiosk sign-in disabled.
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

const KIOSK_FALLBACK = ['overview', 'explore', 'attacks', 'ai', 'ip', 'query'].filter((p) => PAGE_IDS.includes(p))

function keyMatches(given: string | null): boolean {
  const want = process.env.DASH_KIOSK_KEY || ''
  if (!want || !given || want.length < 24 || want === process.env.DASH_SESSION) return false
  const a = Buffer.from(given), b = Buffer.from(want)
  return a.length === b.length && timingSafeEqual(a, b)
}

export async function GET(req: NextRequest) {
  const secret = process.env.DASH_SESSION
  if (!secret || !keyMatches(req.nextUrl.searchParams.get('k'))) {
    audit(req, { user: 'kiosk', kind: 'kiosk', category: 'auth', action: 'auth.kiosk', summary: 'Kiosk sign-in refused (missing or wrong kiosk key)', result: 'denied' })
    return NextResponse.json({ status: 'error', error: 'unauthorized' }, { status: 401 })
  }
  const groupName = process.env.DASH_KIOSK_GROUP || 'viewers'
  const perms = permsForGroup(groupName)
  const next = req.nextUrl.searchParams.get('next')
  const url = req.nextUrl.clone()
  const host = req.headers.get('host')
  if (host) url.host = host // stay on the host the client used, not localhost
  url.pathname = next && next.startsWith('/') && !next.startsWith('//') ? next : '/analytics'
  url.search = '' // drop the key from the address bar right away
  const token = await signSession(secret, 'kiosk', groupName, perms.length ? perms : KIOSK_FALLBACK, SESSION_TTL, 'kiosk')
  audit(req, { user: 'kiosk', kind: 'kiosk', category: 'auth', action: 'auth.kiosk', summary: `Kiosk display signed in (group ${groupName})` })
  const res = NextResponse.redirect(url)
  res.headers.set('referrer-policy', 'no-referrer')
  res.headers.set('cache-control', 'no-store')
  res.cookies.set('dash_auth', token, cookieOpts(req, SESSION_TTL))
  return res
}
