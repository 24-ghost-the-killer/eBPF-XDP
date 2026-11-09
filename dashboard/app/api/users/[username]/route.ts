import { NextRequest, NextResponse } from 'next/server'
import { requireAdmin, cookieOpts } from '@/lib/api-auth'
import { updateUser, removeUser, permsForGroup, userEpoch, UserError } from '@/lib/users'
import { signSession, SESSION_TTL } from '@/lib/authz'
import { clearLoginLock } from '@/lib/login-guard'
import { audit } from '@/lib/audit'
import { listUsers, disableMfa } from '@/lib/users'

// PATCH { group?, password?, disabled?, signOut? } / DELETE one user (requires
// Users & groups). Changes take effect on the user's next request. A new password
// or signOut:true revokes every existing session of that user.
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

const fail = (e: unknown, what: string) =>
  e instanceof UserError
    ? NextResponse.json({ error: e.message }, { status: e.status })
    : NextResponse.json({ error: `failed to ${what}` }, { status: 500 })

export async function PATCH(req: NextRequest, { params }: { params: { username: string } }) {
  const a = await requireAdmin(req)
  if (a.error) return a.error
  const username = decodeURIComponent(params.username)
  let body: { group?: unknown; password?: unknown; disabled?: unknown; signOut?: unknown; resetMfa?: unknown } = {}
  try { body = await req.json() } catch {}
  if (body.resetMfa === true) {
    // Lost phone: turn the user's two-factor off so they can set it up again.
    try {
      disableMfa(username)
      audit(req, { user: a.caller.username ?? '', category: 'users', action: 'users.mfa_reset', target: `user:${username}`, summary: `Reset ${username}'s two-factor (they must set it up again)` })
      return NextResponse.json({ ok: true })
    } catch (e) {
      return fail(e, 'reset two-factor')
    }
  }
  const changes: { group?: string; password?: string; disabled?: boolean; revoke?: boolean } = {}
  if (typeof body.group === 'string') changes.group = body.group
  if (typeof body.password === 'string') changes.password = body.password
  if (typeof body.disabled === 'boolean') changes.disabled = body.disabled
  if (body.signOut === true) changes.revoke = true
  if (!Object.keys(changes).length) return NextResponse.json({ error: 'nothing to change' }, { status: 400 })
  if (changes.disabled && a.caller.username === username) {
    return NextResponse.json({ error: 'you can’t disable your own account' }, { status: 409 })
  }
  try {
    const before = listUsers().find((u) => u.username === username)
    const user = updateUser(username, changes)
    const by = a.caller.username ?? ''
    const t = `user:${username}`
    if (changes.group !== undefined && before?.group !== user.group) audit(req, { user: by, category: 'users', action: 'users.group', target: t, summary: `Moved ${username} from group ${before?.group} to ${user.group}`, detail: { from: before?.group, to: user.group } })
    if (changes.password) audit(req, { user: by, category: 'users', action: 'users.password', target: t, summary: by === username ? `${username} changed their own password (other sessions signed out)` : `Reset ${username}'s password (their sessions signed out)` })
    if (changes.disabled !== undefined && !!before?.disabled !== changes.disabled) audit(req, { user: by, category: 'users', action: changes.disabled ? 'users.disable' : 'users.enable', target: t, summary: `${changes.disabled ? 'Disabled' : 'Enabled'} ${username}` })
    if (changes.revoke) audit(req, { user: by, category: 'users', action: 'users.sign_out', target: t, summary: `Signed ${username} out everywhere` })
    if (changes.password || changes.disabled === false) clearLoginLock(username) // let them in right away
    const res = NextResponse.json({ ok: true, user })
    // Changing your OWN password revokes your old cookies too; re-issue the
    // current browser's session so you aren't thrown out mid-task.
    if (changes.password && a.caller.username === username && process.env.DASH_SESSION) {
      const token = await signSession(process.env.DASH_SESSION, username, user.group, permsForGroup(user.group), SESSION_TTL, 'user', userEpoch(username))
      res.cookies.set('dash_auth', token, cookieOpts(req, SESSION_TTL))
    }
    return res
  } catch (e) {
    audit(req, { user: a.caller.username ?? '', category: 'users', action: 'users.update', target: `user:${username}`, summary: `Could not update ${username}: ${e instanceof Error ? e.message : 'error'}`, detail: { attempted: Object.keys(changes) }, result: 'error' })
    return fail(e, 'update user')
  }
}

export async function DELETE(req: NextRequest, { params }: { params: { username: string } }) {
  const a = await requireAdmin(req)
  if (a.error) return a.error
  const username = decodeURIComponent(params.username)
  if (a.caller.username === username) return NextResponse.json({ error: 'you can’t delete your own account' }, { status: 409 })
  try {
    const before = listUsers().find((u) => u.username === username)
    removeUser(username)
    audit(req, { user: a.caller.username ?? '', category: 'users', action: 'users.delete', target: `user:${username}`, summary: `Deleted user ${username} (was in ${before?.group ?? '?'})` })
    return NextResponse.json({ ok: true })
  } catch (e) {
    audit(req, { user: a.caller.username ?? '', category: 'users', action: 'users.delete', target: `user:${username}`, summary: `Could not delete ${username}: ${e instanceof Error ? e.message : 'error'}`, result: 'error' })
    return fail(e, 'remove user')
  }
}
