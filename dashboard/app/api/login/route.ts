import { NextRequest, NextResponse } from 'next/server'
import { authenticate } from '@/lib/users'
import { signSession } from '@/lib/authz'

// Verify username + password and, on success, set a signed session cookie that
// carries the user's identity, group and the group's allowed pages. Middleware
// verifies the signature and checks the requested page against those pages.
// Node runtime: hashing + reading the store are Node-only; DASH_SESSION is the
// HMAC key.
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

const YEAR = 60 * 60 * 24 * 365

export async function POST(req: NextRequest) {
  const secret = process.env.DASH_SESSION
  if (!secret) return NextResponse.json({ error: 'auth is not configured on the server' }, { status: 500 })
  let body: { username?: string; password?: string } = {}
  try { body = await req.json() } catch {}
  const username = (body.username || '').trim()
  const password = body.password || ''
  if (!password) return NextResponse.json({ error: 'missing credentials' }, { status: 401 })
  const result = authenticate(username, password)
  if (!result) return NextResponse.json({ error: 'wrong username or password' }, { status: 401 })
  const token = await signSession(secret, result.username, result.group, result.pages, YEAR)
  const res = NextResponse.json({ ok: true, username: result.username, group: result.group })
  res.cookies.set('dash_auth', token, { httpOnly: true, sameSite: 'lax', path: '/', maxAge: YEAR })
  return res
}
