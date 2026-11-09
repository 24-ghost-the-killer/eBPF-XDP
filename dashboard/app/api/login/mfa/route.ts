import { NextRequest, NextResponse } from 'next/server'
import { verifyChallenge, signSession, SESSION_TTL } from '@/lib/authz'
import { verifySecondFactor, userEpoch } from '@/lib/users'
import { cookieOpts } from '@/lib/api-auth'
import { loginBlocked, loginFailed, loginSucceeded, FAIL_DELAY_MS } from '@/lib/login-guard'
import { audit } from '@/lib/audit'

// Second step of sign-in for users with two-factor on: { challenge, code } where
// the challenge came from /api/login after a correct password, and code is the
// 6-digit authenticator code or a one-time recovery code. Wrong codes count
// toward the same per-username lock as wrong passwords.
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

const clientAddr = (req: NextRequest) =>
  req.headers.get('x-forwarded-for')?.split(',')[0].trim() || req.headers.get('x-real-ip') || null

export async function POST(req: NextRequest) {
  const secret = process.env.DASH_SESSION
  if (!secret) return NextResponse.json({ error: 'auth is not configured on the server' }, { status: 503 })
  const body = await req.json().catch(() => ({}))
  const ch = await verifyChallenge(secret, typeof body?.challenge === 'string' ? body.challenge : undefined)
  if (!ch) return NextResponse.json({ error: 'the sign-in took too long — enter your password again', restart: true }, { status: 401 })
  if (ch.e < userEpoch(ch.u)) return NextResponse.json({ error: 'please sign in again', restart: true }, { status: 401 })
  const addr = clientAddr(req)
  const wait = loginBlocked(ch.u, addr)
  if (wait > 0) {
    audit(req, { user: ch.u, category: 'auth', action: 'auth.mfa', target: `user:${ch.u}`, summary: `Two-factor code refused for ${ch.u}: locked after repeated failures`, result: 'denied' })
    return NextResponse.json({ error: `too many failed attempts — try again in ${wait >= 60 ? `${Math.ceil(wait / 60)} min` : `${wait} s`}` }, { status: 429, headers: { 'retry-after': String(wait) } })
  }
  const code = String(body?.code || '').slice(0, 40)
  const r = verifySecondFactor(ch.u, code)
  if (!r) {
    loginFailed(ch.u, addr)
    audit(req, { user: ch.u, category: 'auth', action: 'auth.mfa', target: `user:${ch.u}`, summary: `Wrong two-factor code for ${ch.u}`, result: 'denied' })
    await new Promise((res) => setTimeout(res, FAIL_DELAY_MS))
    return NextResponse.json({ error: 'that code is not right' }, { status: 401 })
  }
  loginSucceeded(ch.u)
  audit(req, { user: r.username, kind: 'user', category: 'auth', action: 'auth.login', target: `user:${r.username}`,
    summary: r.usedRecovery ? `${r.username} signed in with a RECOVERY code (${r.recoveryLeft} left)` : `${r.username} signed in with two-factor (group ${r.group})`,
    detail: r.usedRecovery ? { recoveryLeft: r.recoveryLeft } : undefined })
  const token = await signSession(secret, r.username, r.group, r.perms, SESSION_TTL, 'user', r.epoch)
  const res = NextResponse.json({ ok: true, username: r.username, usedRecovery: !!r.usedRecovery, recoveryLeft: r.recoveryLeft })
  res.cookies.set('dash_auth', token, cookieOpts(req, SESSION_TTL))
  return res
}
