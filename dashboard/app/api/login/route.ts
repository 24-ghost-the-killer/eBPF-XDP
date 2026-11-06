import { NextRequest, NextResponse } from 'next/server'
import { authenticate } from '@/lib/users'
import { signSession, SESSION_TTL } from '@/lib/authz'
import { cookieOpts } from '@/lib/api-auth'
import { loginBlocked, loginFailed, loginSucceeded, FAIL_DELAY_MS } from '@/lib/login-guard'
import { audit } from '@/lib/audit'

// Verify username + password and, on success, set a signed session cookie that
// carries the user's identity, group, permissions and session epoch. Sessions
// last SESSION_TTL and slide while in use (/api/me re-signs them). Repeated
// failures are rate-limited per username, per forwarded client address and
// globally (lib/login-guard). Node runtime: scrypt + the user store are Node-only.
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

const clientAddr = (req: NextRequest) =>
  req.headers.get('x-forwarded-for')?.split(',')[0].trim() || req.headers.get('x-real-ip') || null

export async function POST(req: NextRequest) {
  const secret = process.env.DASH_SESSION
  if (!secret) return NextResponse.json({ error: 'auth is not configured on the server' }, { status: 503 })
  let body: { username?: string; password?: string } = {}
  try { body = await req.json() } catch {}
  const username = String(body.username || '').trim().slice(0, 64)
  const password = String(body.password || '').slice(0, 256)
  const addr = clientAddr(req)

  const wait = loginBlocked(username, addr)
  if (wait > 0) {
    audit(req, { user: username, category: 'auth', action: 'auth.login', target: `user:${username}`, summary: `Sign-in refused for “${username}”: locked after repeated failures (${wait}s left)`, detail: { reason: 'locked', retryAfter: wait }, result: 'denied' })
    return NextResponse.json({ error: `too many failed attempts — try again in ${wait >= 60 ? `${Math.ceil(wait / 60)} min` : `${wait} s`}` },
      { status: 429, headers: { 'retry-after': String(wait) } })
  }
  if (!password) return NextResponse.json({ error: 'missing credentials' }, { status: 401 })

  const result = authenticate(username, password)
  if (!result) {
    audit(req, { user: username, category: 'auth', action: 'auth.login', target: `user:${username}`, summary: `Failed sign-in for “${username}” (wrong username or password, or account disabled)`, detail: { reason: 'bad_credentials' }, result: 'denied' })
    loginFailed(username, addr)
    await new Promise((r) => setTimeout(r, FAIL_DELAY_MS))
    return NextResponse.json({ error: 'wrong username or password' }, { status: 401 })
  }
  loginSucceeded(username)
  audit(req, { user: result.username, kind: result.kind, category: 'auth', action: 'auth.login', target: `user:${result.username}`, summary: `${result.username} signed in (group ${result.group}${result.kind !== 'user' ? `, ${result.kind}` : ''})` })
  loginSucceeded(result.username) // also clear the canonical name's record (case-insensitive sign-in)
  const token = await signSession(secret, result.username, result.group, result.perms, SESSION_TTL, result.kind, result.epoch)
  const res = NextResponse.json({ ok: true, username: result.username, group: result.group })
  res.cookies.set('dash_auth', token, cookieOpts(req, SESSION_TTL))
  return res
}
