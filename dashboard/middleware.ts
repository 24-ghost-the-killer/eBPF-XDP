import { NextRequest, NextResponse } from 'next/server'
import { verifySession, routePageId, sessionCan, firstAllowedPath } from '@/lib/authz'

// Gate the dashboard behind per-user login with group-based, per-page
// permissions. Auth is OFF until DASH_SESSION is set together with a user source
// (DASH_USERS/DASH_USERS_FILE) or the legacy DASH_PASSWORD, so deploying this
// changes nothing until configured (no surprise lockout).
//
// The cookie is a signed token carrying {username, group, allowed page ids}. We
// verify the signature here (Web Crypto, Edge-safe) and allow the route only if
// the token grants the page that path requires (lib/authz: routePageId).
//
// Plain HTTP on the LAN: this is LAN-grade access control, not TLS. Keep ufw
// :3000 restricted to trusted hosts.
const COOKIE = 'dash_auth'
const PUBLIC = ['/login', '/api/login', '/api/kiosk', '/api/logout']

export async function middleware(req: NextRequest) {
  const secret = process.env.DASH_SESSION
  const authOn = !!secret && (!!process.env.DASH_PASSWORD || !!process.env.DASH_USERS || !!process.env.DASH_USERS_FILE)
  if (!authOn) return NextResponse.next()

  const { pathname, search } = req.nextUrl
  if (PUBLIC.some((p) => pathname === p || pathname.startsWith(p + '/'))) return NextResponse.next()

  const session = await verifySession(secret!, req.cookies.get(COOKIE)?.value)
  const isApi = pathname.startsWith('/api/')

  const host = req.headers.get('host') // pin redirects to the host the client used

  if (!session) {
    if (isApi) return NextResponse.json({ status: 'error', error: 'unauthorized' }, { status: 401 })
    const url = req.nextUrl.clone()
    if (host) url.host = host
    url.pathname = '/login'
    url.search = ''
    url.searchParams.set('next', pathname + search)
    return NextResponse.redirect(url)
  }

  const need = routePageId(pathname)
  if (!sessionCan(session, need)) {
    if (isApi) return NextResponse.json({ status: 'error', error: 'forbidden', need }, { status: 403 })
    const dest = firstAllowedPath(session)
    const url = req.nextUrl.clone()
    if (host) url.host = host
    url.search = ''
    if (dest && dest !== pathname) {
      url.pathname = dest
      url.searchParams.set('denied', need || '')
    } else {
      url.pathname = '/analytics/no-access'
    }
    return NextResponse.redirect(url)
  }

  return NextResponse.next()
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico|robots.txt).*)'],
}
