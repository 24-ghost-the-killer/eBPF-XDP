import { NextRequest, NextResponse } from 'next/server'
import { requirePerm } from '@/lib/api-auth'
import { audit } from '@/lib/audit'
import { loadLockdown, saveLockdown, lockdownIfaces, LOCKDOWN_MAX_MINUTES, PlanError } from '@/lib/protect'

// Read / write the lockdown kill-switch. Requires the `protect` permission. A
// root job on the box applies it and enforces the auto-revert timer; the
// dashboard only ever writes a desired state that carries an expiry.
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  const a = await requirePerm(req, 'protect')
  if (a.error) return a.error
  return NextResponse.json({ ...loadLockdown(), now: Math.floor(Date.now() / 1000), maxMinutes: LOCKDOWN_MAX_MINUTES })
}

export async function PUT(req: NextRequest) {
  const a = await requirePerm(req, 'protect.lockdown') // viewing needs 'protect'; changing the lockdown kill-switch needs 'protect.lockdown'
  if (a.error) return a.error
  let body: any = {}
  try { body = await req.json() } catch {}
  const now = Math.floor(Date.now() / 1000)
  const enabled = !!body?.enabled
  let minutes = Number(body?.minutes)
  if (!Number.isFinite(minutes)) minutes = 0
  minutes = Math.max(1, Math.min(LOCKDOWN_MAX_MINUTES, Math.round(minutes)))
  try {
    const l = { enabled, ifaces: lockdownIfaces(), expires_at: enabled ? now + minutes * 60 : 0 }
    saveLockdown(l)
    audit(req, { user: a.access.username, kind: a.access.kind, category: 'lockdown', action: enabled ? 'lockdown.arm' : 'lockdown.lift', target: 'lockdown',
      summary: enabled ? `Armed lockdown on ${l.ifaces.join(', ')} for ${minutes} min` : 'Lifted lockdown', detail: { ifaces: l.ifaces, minutes: enabled ? minutes : 0 } })
    return NextResponse.json({ ...l, now, maxMinutes: LOCKDOWN_MAX_MINUTES })
  } catch (e) {
    if (e instanceof PlanError) return NextResponse.json({ error: e.message }, { status: e.status })
    return NextResponse.json({ error: 'failed to save lockdown' }, { status: 500 })
  }
}
