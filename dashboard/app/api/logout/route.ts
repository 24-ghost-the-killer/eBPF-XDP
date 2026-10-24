import { NextRequest, NextResponse } from 'next/server'

// Clear the auth cookie and return to the login page on the SAME host the
// browser used (192.168.1.193, 10.55.12.193, …) — not whatever host req.nextUrl
// reports, which `next start` can give as localhost.
export const dynamic = 'force-dynamic'

function clear(req: NextRequest) {
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
