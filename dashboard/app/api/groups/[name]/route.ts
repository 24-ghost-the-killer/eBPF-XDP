import { NextRequest, NextResponse } from 'next/server'
import { requireAdmin } from '@/lib/api-auth'
import { updateGroup, removeGroup, UserError } from '@/lib/users'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export async function PATCH(req: NextRequest, { params }: { params: { name: string } }) {
  const a = await requireAdmin(req)
  if (a.error) return a.error
  const name = decodeURIComponent(params.name)
  let body: { pages?: string[] } = {}
  try { body = await req.json() } catch {}
  if (!Array.isArray(body.pages)) return NextResponse.json({ error: 'pages must be an array' }, { status: 400 })
  try {
    const group = updateGroup(name, body.pages)
    return NextResponse.json({ ok: true, group })
  } catch (e) {
    if (e instanceof UserError) return NextResponse.json({ error: e.message }, { status: e.status })
    return NextResponse.json({ error: 'failed to update group' }, { status: 500 })
  }
}

export async function DELETE(req: NextRequest, { params }: { params: { name: string } }) {
  const a = await requireAdmin(req)
  if (a.error) return a.error
  const name = decodeURIComponent(params.name)
  try {
    removeGroup(name)
    return NextResponse.json({ ok: true })
  } catch (e) {
    if (e instanceof UserError) return NextResponse.json({ error: e.message }, { status: e.status })
    return NextResponse.json({ error: 'failed to remove group' }, { status: 500 })
  }
}
