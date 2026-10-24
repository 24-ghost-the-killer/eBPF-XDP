import { NextRequest, NextResponse } from 'next/server'
import { requireAdmin } from '@/lib/api-auth'
import { updateUser, removeUser, UserError } from '@/lib/users'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export async function PATCH(req: NextRequest, { params }: { params: { username: string } }) {
  const a = await requireAdmin(req)
  if (a.error) return a.error
  const username = decodeURIComponent(params.username)
  let body: { group?: string; password?: string } = {}
  try { body = await req.json() } catch {}
  const changes: { group?: string; password?: string } = {}
  if (typeof body.group === 'string') changes.group = body.group
  if (typeof body.password === 'string') changes.password = body.password
  if (changes.group === undefined && changes.password === undefined) {
    return NextResponse.json({ error: 'nothing to change' }, { status: 400 })
  }
  try {
    const user = updateUser(username, changes)
    return NextResponse.json({ ok: true, user })
  } catch (e) {
    if (e instanceof UserError) return NextResponse.json({ error: e.message }, { status: e.status })
    return NextResponse.json({ error: 'failed to update user' }, { status: 500 })
  }
}

export async function DELETE(req: NextRequest, { params }: { params: { username: string } }) {
  const a = await requireAdmin(req)
  if (a.error) return a.error
  const username = decodeURIComponent(params.username)
  try {
    removeUser(username)
    return NextResponse.json({ ok: true })
  } catch (e) {
    if (e instanceof UserError) return NextResponse.json({ error: e.message }, { status: e.status })
    return NextResponse.json({ error: 'failed to remove user' }, { status: 500 })
  }
}
