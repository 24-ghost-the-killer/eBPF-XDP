import { NextRequest, NextResponse } from 'next/server'
import { requireAdmin } from '@/lib/api-auth'
import { listUsers, listGroups, addUser, usingDefaultAdmin, noAdminUsers, UserError } from '@/lib/users'
import { permissionCatalog } from '@/lib/catalog-api'
import { audit } from '@/lib/audit'

// Users admin API (requires Users & groups).
//   GET  -> { users, groups, catalog, usingDefaultAdmin, me }
//   POST { username, group, password } -> create
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  const a = await requireAdmin(req)
  if (a.error) return a.error
  return NextResponse.json({
    users: listUsers(), groups: listGroups(), catalog: permissionCatalog(),
    usingDefaultAdmin: usingDefaultAdmin(), noAdmin: noAdminUsers(), me: a.caller.username,
  })
}

export async function POST(req: NextRequest) {
  const a = await requireAdmin(req)
  if (a.error) return a.error
  let body: { username?: string; group?: string; password?: string } = {}
  try { body = await req.json() } catch {}
  try {
    const user = addUser((body.username || '').trim(), (body.group || '').trim(), body.password || '')
    audit(req, { user: a.caller.username ?? '', category: 'users', action: 'users.create', target: `user:${user.username}`, summary: `Created user ${user.username} in group ${user.group}` })
    return NextResponse.json({ ok: true, user })
  } catch (e) {
    audit(req, { user: a.caller.username ?? '', category: 'users', action: 'users.create', target: `user:${(body.username || '').trim()}`, summary: `Could not create user “${(body.username || '').trim()}”: ${e instanceof Error ? e.message : 'error'}`, result: 'error' })
    if (e instanceof UserError) return NextResponse.json({ error: e.message }, { status: e.status })
    return NextResponse.json({ error: 'failed to create user' }, { status: 500 })
  }
}
