import { NextRequest, NextResponse } from 'next/server'
import { verifySession } from '@/lib/authz'
import { audit } from '@/lib/audit'

// Clear the auth cookie and return to the login page on the SAME host the
// browser used (192.168.1.193, 10.55.12.193, …) — not whatever host req.nextUrl
// reports, which `next start` can give as localhost.
export const dynamic = 'force-dynamic'

async function clear(req: NextRequest) {
  const s = process.env.DASH_SESSION ? await verifySession(process.env.DASH_SESSION, req.cookies.get('dash_auth')?.value) : null
  if (s) audit(req, { user: s.u, kind: s.k, category: 'auth', action: 'auth.logout', target: `user:${s.u}`, summary: `${s.u} signed out` })
  const url = req.nextUrl.clone()
  const host = req.headers.get('host')
  if (host) url.host = host // pin to the host the client actually requested
  url.pathname = '/login'
  url.search = ''
  const res = NextResponse.redirect(url, 303)
  res.cookies.set('dash_auth', '', { httpOnly: true, path: '/', maxAge: 0 })
  return res
}

export async function POST(req: NextRequest) {
  return clear(req)
}
export async function GET(req: NextRequest) {
  return clear(req)
}
