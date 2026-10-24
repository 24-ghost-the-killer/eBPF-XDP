import { NextRequest, NextResponse } from 'next/server'
import { signSession, PAGE_IDS } from '@/lib/authz'
import { pagesForGroup } from '@/lib/users'

// Password-free sign-in for the local kiosk display at 192.168.1.193. Its
// browser opens, once: http://192.168.1.193:3000/api/kiosk?k=<DASH_SESSION>
// It is signed in as the built-in `kiosk` user, with the pages of the group
// named by DASH_KIOSK_GROUP (default "viewers"); if that group is absent, it
// falls back to the read-only dashboards (no Protection, no admin).
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

const YEAR = 60 * 60 * 24 * 365
const KIOSK_FALLBACK = ['overview', 'explore', 'attacks', 'ai', 'ip', 'query'].filter((p) => PAGE_IDS.includes(p))

export async function GET(req: NextRequest) {
  const secret = process.env.DASH_SESSION
  const k = req.nextUrl.searchParams.get('k')
  if (!secret || k !== secret) {
    return NextResponse.json({ status: 'error', error: 'unauthorized' }, { status: 401 })
  }
  const groupName = process.env.DASH_KIOSK_GROUP || 'viewers'
  const pages = pagesForGroup(groupName)
  const next = req.nextUrl.searchParams.get('next')
  const url = req.nextUrl.clone()
  const host = req.headers.get('host')
  if (host) url.host = host // stay on the host the client used, not localhost
  url.pathname = next && next.startsWith('/') ? next : '/analytics'
  url.search = ''
  const token = await signSession(secret, 'kiosk', groupName, pages.length ? pages : KIOSK_FALLBACK, YEAR)
  const res = NextResponse.redirect(url)
  res.cookies.set('dash_auth', token, { httpOnly: true, sameSite: 'lax', path: '/', maxAge: YEAR })
  return res
}
