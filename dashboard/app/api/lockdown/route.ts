import { NextRequest, NextResponse } from 'next/server'
import { verifySession, sessionCan } from '@/lib/authz'
import { loadLockdown, saveLockdown, lockdownIfaces, LOCKDOWN_MAX_MINUTES, PlanError } from '@/lib/protect'

// Read / write the lockdown kill-switch. Requires the `protect` permission. A
// root job on the box applies it and enforces the auto-revert timer; the
// dashboard only ever writes a desired state that carries an expiry.
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

async function canProtect(req: NextRequest): Promise<boolean> {
  const secret = process.env.DASH_SESSION
  const authOn = !!secret && (!!process.env.DASH_PASSWORD || !!process.env.DASH_USERS || !!process.env.DASH_USERS_FILE)
  if (!authOn) return true // fail-open matches middleware
  const s = await verifySession(secret!, req.cookies.get('dash_auth')?.value)
  return !!s && sessionCan(s, 'protect')
}

export async function GET(req: NextRequest) {
  if (!(await canProtect(req))) return NextResponse.json({ error: 'forbidden' }, { status: 403 })
  return NextResponse.json({ ...loadLockdown(), now: Math.floor(Date.now() / 1000), maxMinutes: LOCKDOWN_MAX_MINUTES })
}

export async function PUT(req: NextRequest) {
  if (!(await canProtect(req))) return NextResponse.json({ error: 'forbidden' }, { status: 403 })
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
    return NextResponse.json({ ...l, now, maxMinutes: LOCKDOWN_MAX_MINUTES })
  } catch (e) {
    if (e instanceof PlanError) return NextResponse.json({ error: e.message }, { status: e.status })
    return NextResponse.json({ error: 'failed to save lockdown' }, { status: 500 })
  }
}
