import { NextRequest, NextResponse } from 'next/server'
import { requireAdmin } from '@/lib/api-auth'
import { updateGroup, removeGroup, listGroups, UserError } from '@/lib/users'
import { audit } from '@/lib/audit'

// PATCH { perms?, name? } (name = rename; members follow) / DELETE (empty groups only).
// Requires Users & groups. Members get the new permissions on their next request.
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

const fail = (e: unknown, what: string) =>
  e instanceof UserError
    ? NextResponse.json({ error: e.message }, { status: e.status })
    : NextResponse.json({ error: `failed to ${what}` }, { status: 500 })

export async function PATCH(req: NextRequest, { params }: { params: { name: string } }) {
  const a = await requireAdmin(req)
  if (a.error) return a.error
  const name = decodeURIComponent(params.name)
  let body: { perms?: unknown; pages?: unknown; name?: unknown; requireMfa?: unknown } = {}
  try { body = await req.json() } catch {}
  const perms = Array.isArray(body.perms) ? body.perms : Array.isArray(body.pages) ? body.pages : undefined
  const newName = typeof body.name === 'string' ? body.name.trim() : undefined
  const requireMfa = typeof body.requireMfa === 'boolean' ? body.requireMfa : undefined
  if (perms === undefined && newName === undefined && requireMfa === undefined) return NextResponse.json({ error: 'nothing to change' }, { status: 400 })
  try {
    const before = listGroups().find((g) => g.name === name)
    const group = updateGroup(name, { perms: perms as string[] | undefined, newName, requireMfa })
    if (before && requireMfa !== undefined && !!before.requireMfa !== requireMfa) audit(req, { user: a.caller.username ?? '', category: 'groups', action: 'groups.require_mfa', target: `group:${group.name}`,
      summary: requireMfa ? `Group ${group.name} now REQUIRES two-factor for its members` : `Group ${group.name} no longer requires two-factor` })
    const by = a.caller.username ?? ''
    if (newName && newName !== name) audit(req, { user: by, category: 'groups', action: 'groups.rename', target: `group:${group.name}`, summary: `Renamed group ${name} to ${group.name}`, detail: { from: name, to: group.name } })
    if (before && perms) {
      const added = group.perms.filter((p) => !before.perms.includes(p)), removed = before.perms.filter((p) => !group.perms.includes(p))
      if (added.length || removed.length) audit(req, { user: by, category: 'groups', action: 'groups.permissions', target: `group:${group.name}`,
        summary: `Changed permissions of ${group.name}: ${[added.length ? `granted ${added.join(', ')}` : '', removed.length ? `removed ${removed.join(', ')}` : ''].filter(Boolean).join('; ')}`,
        detail: { granted: added, removed } })
    }
    return NextResponse.json({ ok: true, group })
  } catch (e) {
    audit(req, { user: a.caller.username ?? '', category: 'groups', action: 'groups.update', target: `group:${name}`, summary: `Could not update group ${name}: ${e instanceof Error ? e.message : 'error'}`, result: 'error' })
    return fail(e, 'update group')
  }
}

export async function DELETE(req: NextRequest, { params }: { params: { name: string } }) {
  const a = await requireAdmin(req)
  if (a.error) return a.error
  try {
    removeGroup(decodeURIComponent(params.name))
    audit(req, { user: a.caller.username ?? '', category: 'groups', action: 'groups.delete', target: `group:${decodeURIComponent(params.name)}`, summary: `Deleted group ${decodeURIComponent(params.name)}` })
    return NextResponse.json({ ok: true })
  } catch (e) {
    return fail(e, 'remove group')
  }
}
