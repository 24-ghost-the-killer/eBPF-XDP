import { NextRequest, NextResponse } from 'next/server'
import { requireAdmin } from '@/lib/api-auth'
import { listGroups, listUsers, addGroup, UserError } from '@/lib/users'
import { PAGES } from '@/lib/authz'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  const a = await requireAdmin(req)
  if (a.error) return a.error
  const users = listUsers()
  const groups = listGroups().map((g) => ({ ...g, members: users.filter((u) => u.group === g.name).length }))
  return NextResponse.json({ groups, pages: PAGES })
}

export async function POST(req: NextRequest) {
  const a = await requireAdmin(req)
  if (a.error) return a.error
  let body: { name?: string; pages?: string[] } = {}
  try { body = await req.json() } catch {}
  try {
    const group = addGroup((body.name || '').trim(), Array.isArray(body.pages) ? body.pages : [])
    return NextResponse.json({ ok: true, group })
  } catch (e) {
    if (e instanceof UserError) return NextResponse.json({ error: e.message }, { status: e.status })
    return NextResponse.json({ error: 'failed to create group' }, { status: 500 })
  }
}
