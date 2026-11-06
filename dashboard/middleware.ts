import { NextRequest, NextResponse, type NextFetchEvent } from 'next/server'
import { verifySession, routePageId, sessionCan, firstAllowedPath, authMode, signInternal } from '@/lib/authz'

// The Edge runtime can't write the audit file, so refusals decided HERE are sent
// to /api/audit as an HMAC-signed internal event (fire-and-forget, never delays
// the response). Only the server holds the key, so browsers can't forge these.
function auditFromEdge(req: NextRequest, ev: NextFetchEvent, secret: string, e: { user: string; action: string; summary: string; target: string }) {
  // Next.js prefetches sidebar links in the background (RSC fetches carrying a
  // next-url header / _rsc param; it strips its prefetch markers before
  // middleware). Those aren't something the user did, so for PAGES only a real
  // document visit is logged. API calls are never prefetched and always logged.
  const isPage = !req.nextUrl.pathname.startsWith('/api/')
  if (isPage && (req.headers.get('sec-fetch-dest') !== 'document' || req.headers.get('next-url') || req.nextUrl.searchParams.has('_rsc'))) return
  const body = JSON.stringify({ ...e, category: 'access', result: 'denied', ip: req.headers.get('x-forwarded-for')?.split(',')[0].trim() || req.headers.get('x-real-ip') || null, ua: req.headers.get('user-agent')?.slice(0, 160) || null })
  ev.waitUntil(
    signInternal(secret, body)
      .then((sig) => fetch(new URL('/api/audit', req.nextUrl.origin), { method: 'POST', headers: { 'content-type': 'application/json', 'x-xs-audit-sig': sig }, body }))
      .catch(() => {}),
  )
}

// Gate the dashboard behind per-user login with group-based permissions.
// Fails CLOSED: without DASH_SESSION nothing is served (503) unless auth was
// explicitly disabled for a lab with DASH_AUTH_DISABLED=1.
//
// The cookie is a signed token carrying {username, group, allowed page ids}. We
// verify the signature here (Web Crypto, Edge-safe) and allow the route only if
// the token grants the page that path requires (lib/authz: routePageId).
//
// Plain HTTP on the LAN: this is LAN-grade access control, not TLS. Keep ufw
// :3000 restricted to trusted hosts.
const COOKIE = 'dash_auth'
// /api/audit enforces its own access (reading needs "Audit log"; writing needs a
// session or the server-signed internal header) and must stay reachable for the
// internal refusal events sent from this middleware.
const PUBLIC = ['/login', '/api/login', '/api/kiosk', '/api/logout', '/api/audit']

export async function middleware(req: NextRequest, ev: NextFetchEvent) {
  const mode = authMode()
  if (mode === 'off') return NextResponse.next()
  const { pathname, search } = req.nextUrl
  if (mode === 'misconfigured') {
    const msg = 'Dashboard login is not configured: set DASH_SESSION in /etc/xdp-sentinel/dashboard.env (or DASH_AUTH_DISABLED=1 for a lab).'
    return pathname.startsWith('/api/')
      ? NextResponse.json({ status: 'error', error: msg }, { status: 503 })
      : new NextResponse(msg, { status: 503, headers: { 'content-type': 'text/plain; charset=utf-8' } })
  }
  const secret = process.env.DASH_SESSION!
  if (PUBLIC.some((p) => pathname === p || pathname.startsWith(p + '/'))) return NextResponse.next()

  const session = await verifySession(secret!, req.cookies.get(COOKIE)?.value)
  const isApi = pathname.startsWith('/api/')

  const host = req.headers.get('host') // pin redirects to the host the client used

  if (!session) {
    if (isApi && req.method !== 'GET') auditFromEdge(req, ev, secret, { user: '', action: 'access.unauthorized', target: pathname, summary: `Not signed in: ${req.method} ${pathname}` })
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
    auditFromEdge(req, ev, secret, { user: session.u, action: 'access.denied', target: pathname, summary: `${session.u} was refused ${isApi ? `${req.method} ${pathname}` : `the page ${pathname}`} (needs “${need}”)` })
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
