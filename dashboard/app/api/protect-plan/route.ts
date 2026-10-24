import { NextRequest, NextResponse } from 'next/server'
import { verifySession, sessionCan } from '@/lib/authz'
import { loadPlan, normalizePlan, savePlan, managementIps, lifelineServices, ingressIface, PlanError } from '@/lib/protect'

// Read / write the protection plan (desired default-deny state). Requires the
// `protect` permission. A root job applies the saved plan to the dataplane.
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
  return NextResponse.json({ plan: loadPlan(), management: managementIps(), lifeline: lifelineServices(), ingress: ingressIface() })
}

export async function PUT(req: NextRequest) {
  if (!(await canProtect(req))) return NextResponse.json({ error: 'forbidden' }, { status: 403 })
  let body: unknown = {}
  try { body = await req.json() } catch {}
  try {
    const plan = normalizePlan(body)
    savePlan(plan)
    return NextResponse.json({ ok: true, plan })
  } catch (e) {
    if (e instanceof PlanError) return NextResponse.json({ error: e.message }, { status: e.status })
    return NextResponse.json({ error: 'failed to save plan' }, { status: 500 })
  }
}
