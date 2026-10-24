import { NextRequest, NextResponse } from 'next/server'
import { requireAdmin } from '@/lib/api-auth'
import { listUsers, listGroups, addUser, usingDefaultAdmin, UserError } from '@/lib/users'
import { PAGES } from '@/lib/authz'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  const a = await requireAdmin(req)
  if (a.error) return a.error
  return NextResponse.json({ users: listUsers(), groups: listGroups(), pages: PAGES, usingDefaultAdmin: usingDefaultAdmin() })
}

export async function POST(req: NextRequest) {
  const a = await requireAdmin(req)
  if (a.error) return a.error
  let body: { username?: string; group?: string; password?: string } = {}
  try { body = await req.json() } catch {}
  try {
    const user = addUser((body.username || '').trim(), (body.group || '').trim(), body.password || '')
    return NextResponse.json({ ok: true, user })
  } catch (e) {
    if (e instanceof UserError) return NextResponse.json({ error: e.message }, { status: e.status })
    return NextResponse.json({ error: 'failed to create user' }, { status: 500 })
  }
}
