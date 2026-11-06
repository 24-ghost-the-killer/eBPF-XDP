import { NextRequest, NextResponse } from 'next/server'
import { requirePerm } from '@/lib/api-auth'
import { audit } from '@/lib/audit'
import { loadPlan, normalizePlan, savePlan, managementIps, lifelineServices, ingressIface, PlanError } from '@/lib/protect'

// Read / write the protection plan (desired default-deny state). Requires the
// `protect` permission. A root job applies the saved plan to the dataplane.
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

type H = { iface: string; ip: string; services: { proto: string; port: number }[] }
const svc = (s: { proto: string; port: number }) => `${s.proto}/${s.port}`
// Human-readable diff of the plan, for the audit log.
function planDiff(a: H[], b: H[]) {
  const key = (h: H) => `${h.iface}|${h.ip}`
  const A = new Map(a.map((h) => [key(h), h])), B = new Map(b.map((h) => [key(h), h]))
  const lines: string[] = []
  const detail: Record<string, unknown> = { added: [] as string[], removed: [] as string[], changed: {} as Record<string, unknown> }
  for (const [k, h] of B) if (!A.has(k)) { lines.push(`protected ${h.ip} (${h.services.map(svc).join(', ') || 'no services'})`); (detail.added as string[]).push(h.ip) }
  for (const [k, h] of A) if (!B.has(k)) { lines.push(`unprotected ${h.ip}`); (detail.removed as string[]).push(h.ip) }
  for (const [k, h] of B) {
    const o = A.get(k)
    if (!o) continue
    const os = new Set(o.services.map(svc)), ns = new Set(h.services.map(svc))
    const add = [...ns].filter((x) => !os.has(x)), rem = [...os].filter((x) => !ns.has(x))
    if (add.length || rem.length) {
      lines.push(`${h.ip}: ${[add.length ? `allowed ${add.join(', ')}` : '', rem.length ? `removed ${rem.join(', ')}` : ''].filter(Boolean).join(', ')}`)
      ;(detail.changed as Record<string, unknown>)[h.ip] = { allowed: add, removed: rem }
    }
  }
  return { lines, detail }
}

export async function GET(req: NextRequest) {
  const a = await requirePerm(req, 'protect')
  if (a.error) return a.error
  return NextResponse.json({ plan: loadPlan(), management: managementIps(), lifeline: lifelineServices(), ingress: ingressIface() })
}

export async function PUT(req: NextRequest) {
  const a = await requirePerm(req, 'protect.plan') // viewing needs 'protect'; changing the protection plan needs 'protect.plan'
  if (a.error) return a.error
  let body: unknown = {}
  try { body = await req.json() } catch {}
  try {
    const before = loadPlan()
    const plan = normalizePlan(body)
    savePlan(plan)
    const d = planDiff(before.hosts, plan.hosts)
    audit(req, { user: a.access.username, kind: a.access.kind, category: 'protect', action: 'protect.plan_save', target: 'protection-plan',
      summary: d.lines.length ? `Saved protection plan: ${d.lines.join('; ')}` : 'Saved protection plan (no changes)', detail: d.detail })
    return NextResponse.json({ ok: true, plan })
  } catch (e) {
    if (e instanceof PlanError) return NextResponse.json({ error: e.message }, { status: e.status })
    return NextResponse.json({ error: 'failed to save plan' }, { status: 500 })
  }
}
