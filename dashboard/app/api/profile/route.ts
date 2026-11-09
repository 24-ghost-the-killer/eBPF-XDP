import { NextRequest, NextResponse } from 'next/server'
import QRCode from 'qrcode'
import { currentAccess, cookieOpts } from '@/lib/api-auth'
import {
  listUsers, mfaStatus, beginMfaSetup, confirmMfaSetup, checkTotp, regenerateRecovery, disableMfa, checkPassword,
  updateUser, permsForGroup, userEpoch, UserError,
} from '@/lib/users'
import { signSession, SESSION_TTL } from '@/lib/authz'
import { otpauthUri } from '@/lib/totp'
import { audit, readAll } from '@/lib/audit'
import { loginBlocked, loginFailed, loginSucceeded } from '@/lib/login-guard'
import { permissionCatalog } from '@/lib/catalog-api'

// Your own account. Any signed-in (stored) user — no page permission needed, and
// it stays usable while a group requires two-factor that isn't set up yet.
//   GET  -> profile, two-factor status, your recent activity
//   POST { action, ... }:
//     password        { current, next }          change your password
//     mfa_setup                                   new authenticator key + QR (pending)
//     mfa_enable      { code }                    confirm -> recovery codes (shown once)
//     mfa_recovery    { code }                    new recovery codes (needs a current code)
//     mfa_disable     { password, code }          turn two-factor off
//     signout_others                              end every other session
// Every change is in the audit log. Wrong passwords/codes count toward the
// sign-in lock, so this can't be used to guess either.
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

async function me(req: NextRequest) {
  const a = await currentAccess(req)
  if (!a || a.authDisabled) return null
  if (a.kind !== 'user') return { error: NextResponse.json({ error: 'this sign-in has no personal profile (kiosk / break-glass / default admin)' }, { status: 409 }) }
  return { a }
}

export async function GET(req: NextRequest) {
  const m = await me(req)
  if (!m) return NextResponse.json({ error: 'unauthorized' }, { status: 401 })
  if (m.error) return m.error
  const u = listUsers().find((x) => x.username === m.a.username)
  const activity = readAll().filter((e) => e.user === m.a.username && e.category !== 'view').slice(-25).reverse()
    .map(({ ts, action, summary, result, ip, target }) => ({ ts, action, summary, result, ip, target }))
  return NextResponse.json({
    username: m.a.username, group: m.a.group, perms: m.a.perms,
    createdAt: u?.createdAt ?? 0, lastLogin: u?.lastLogin ?? 0,
    mfa: mfaStatus(m.a.username), activity, catalog: permissionCatalog(),
  })
}

export async function POST(req: NextRequest) {
  const m = await me(req)
  if (!m) return NextResponse.json({ error: 'unauthorized' }, { status: 401 })
  if (m.error) return m.error
  const user = m.a.username
  const body = await req.json().catch(() => ({}))
  const action = String(body?.action || '')
  const t = `user:${user}`
  const log = (act: string, summary: string, result: 'ok' | 'denied' | 'error' = 'ok') =>
    audit(req, { user, kind: 'user', category: 'users', action: act, target: t, summary, result })
  const lockWait = () => loginBlocked(user, null)
  const reauthFail = (what: string) => { loginFailed(user, null); log(`profile.${action}`, `${what} while trying to ${action.replace('_', ' ')}`, 'denied') }
  const err = (msg: string, status = 400) => NextResponse.json({ error: msg }, { status })

  if (['password', 'mfa_recovery', 'mfa_disable'].includes(action) && lockWait() > 0) {
    return err('too many wrong passwords or codes — wait a few minutes', 429)
  }
  try {
    switch (action) {
      case 'password': {
        if (!checkPassword(user, String(body?.current || ''))) { reauthFail('Wrong current password'); return err('your current password is not right', 403) }
        const next = String(body?.next || '')
        updateUser(user, { password: next })
        loginSucceeded(user)
        log('profile.password', `${user} changed their password (other sessions signed out)`)
        const res = NextResponse.json({ ok: true })
        res.cookies.set('dash_auth', await signSession(process.env.DASH_SESSION!, user, m.a.group, permsForGroup(m.a.group), SESSION_TTL, 'user', userEpoch(user)), cookieOpts(req, SESSION_TTL))
        return res
      }
      case 'mfa_setup': {
        const secret = beginMfaSetup(user)
        const uri = otpauthUri(secret, user)
        const qr = await QRCode.toString(uri, { type: 'svg', errorCorrectionLevel: 'M', margin: 1 })
        log('profile.mfa_setup', `${user} started setting up two-factor`)
        return NextResponse.json({ secret, uri, qr })
      }
      case 'mfa_enable': {
        const codes = confirmMfaSetup(user, String(body?.code || ''))
        log('profile.mfa_enable', `${user} turned ON two-factor authentication`)
        return NextResponse.json({ ok: true, recoveryCodes: codes })
      }
      case 'mfa_recovery': {
        if (!checkTotp(user, String(body?.code || ''))) { reauthFail('Wrong two-factor code'); return err('that code is not right', 403) }
        const codes = regenerateRecovery(user)
        log('profile.mfa_recovery', `${user} generated new recovery codes (old ones no longer work)`)
        return NextResponse.json({ ok: true, recoveryCodes: codes })
      }
      case 'mfa_disable': {
        if (mfaStatus(user).required) return err('your group requires two-factor — it can’t be turned off', 409)
        if (!checkPassword(user, String(body?.password || ''))) { reauthFail('Wrong password'); return err('your password is not right', 403) }
        if (!checkTotp(user, String(body?.code || ''))) { reauthFail('Wrong two-factor code'); return err('that code is not right', 403) }
        disableMfa(user)
        log('profile.mfa_disable', `${user} turned OFF two-factor authentication`)
        return NextResponse.json({ ok: true })
      }
      case 'signout_others': {
        updateUser(user, { revoke: true })
        log('profile.signout_others', `${user} signed out all their other sessions`)
        const res = NextResponse.json({ ok: true })
        res.cookies.set('dash_auth', await signSession(process.env.DASH_SESSION!, user, m.a.group, permsForGroup(m.a.group), SESSION_TTL, 'user', userEpoch(user)), cookieOpts(req, SESSION_TTL))
        return res
      }
      default:
        return err('unknown action')
    }
  } catch (e) {
    if (e instanceof UserError) return err(e.message, e.status)
    log(`profile.${action}`, `Profile action ${action} failed`, 'error')
    return err('something went wrong', 500)
  }
}
