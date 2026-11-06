import { NextRequest, NextResponse } from 'next/server'
import { protectActor } from '@/lib/api-auth'
import { setEditing, assertIp, PlanError } from '@/lib/protect'

// Editing presence: a page editing a host's documentation heartbeats
// { ip, report?, clientId, editing: true } every few seconds and sends editing: false when
// it stops. Entries expire on their own if the heartbeats stop (tab closed).
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  const who = await protectActor(req, 'protect.reports')
  if (who === null) return NextResponse.json({ error: 'forbidden' }, { status: 403 })
  const body = await req.json().catch(() => ({}))
  try {
    const ip = String(body?.ip || '').trim()
    assertIp(ip)
    const clientId = String(body?.clientId || '').slice(0, 64)
    if (!/^[A-Za-z0-9_-]{6,64}$/.test(clientId)) throw new PlanError('invalid clientId')
    // Presence is per document: the host itself, or one of its reports ("ip#reportId").
    const report = body?.report ? String(body.report) : ''
    if (report && !/^[A-Za-z0-9_-]{1,64}$/.test(report)) throw new PlanError('invalid report id')
    setEditing(report ? `${ip}#${report}` : ip, clientId, who || 'admin', !!body?.editing)
    return NextResponse.json({ ok: true })
  } catch (e) {
    if (e instanceof PlanError) return NextResponse.json({ error: e.message }, { status: e.status })
    return NextResponse.json({ error: 'failed' }, { status: 500 })
  }
}
