import { NextRequest, NextResponse } from 'next/server'
import { requireAdmin } from '@/lib/api-auth'
import { listGroups, listUsers, addGroup, permsForGroup, UserError } from '@/lib/users'
import { permissionCatalog } from '@/lib/catalog-api'
import { audit } from '@/lib/audit'

// Groups admin API (requires Users & groups).
//   GET  -> { groups: [{ name, perms, members: [username] }], catalog }
//   POST { name, perms?, copyFrom? } -> create (copyFrom duplicates a group's permissions)
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  const a = await requireAdmin(req)
  if (a.error) return a.error
  const users = listUsers()
  const groups = listGroups().map((g) => ({ ...g, members: users.filter((u) => u.group === g.name).map((u) => u.username) }))
  return NextResponse.json({ groups, catalog: permissionCatalog() })
}

export async function POST(req: NextRequest) {
  const a = await requireAdmin(req)
  if (a.error) return a.error
  let body: { name?: string; perms?: string[]; copyFrom?: string; requireMfa?: boolean } = {}
  try { body = await req.json() } catch {}
  try {
    const perms = typeof body.copyFrom === 'string' ? permsForGroup(body.copyFrom) : Array.isArray(body.perms) ? body.perms : []
    const group = addGroup((body.name || '').trim(), perms, body.requireMfa === true)
    audit(req, { user: a.caller.username ?? '', category: 'groups', action: 'groups.create', target: `group:${group.name}`,
      summary: `Created group ${group.name}${body.copyFrom ? ` (copied from ${body.copyFrom})` : ''} with ${group.perms.length} permissions`, detail: { perms: group.perms } })
    return NextResponse.json({ ok: true, group })
  } catch (e) {
    audit(req, { user: a.caller.username ?? '', category: 'groups', action: 'groups.create', target: `group:${(body.name || '').trim()}`, summary: `Could not create group “${(body.name || '').trim()}”: ${e instanceof Error ? e.message : 'error'}`, result: 'error' })
    if (e instanceof UserError) return NextResponse.json({ error: e.message }, { status: e.status })
    return NextResponse.json({ error: 'failed to create group' }, { status: 500 })
  }
}
