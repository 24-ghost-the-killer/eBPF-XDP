import { NextRequest, NextResponse } from 'next/server'
import { createHmac, timingSafeEqual } from 'node:crypto'
import { requirePerm, currentAccess } from '@/lib/api-auth'
import { audit, readAll, verifyChain, type AuditCategory, type AuditEntry } from '@/lib/audit'

// Audit log API.
//   GET  (needs "Audit log")  ?limit&before&q&user&category=a,b&result&views=1&verify=1
//        -> newest-first entries + summary counts (+ chain status with verify=1)
//   POST (any signed-in user) { category: export|view|query, action, target?, summary, detail? }
//        -> the browser records actions only it can see (CSV exports, page views,
//           queries run). Everything else is logged server-side by the route that
//           performs it, so clients can't write auth/admin/protection events.
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

const CLIENT_CATEGORIES: AuditCategory[] = ['export', 'view', 'query']

export async function GET(req: NextRequest) {
  const a = await requirePerm(req, 'audit')
  if (a.error) return a.error
  const sp = req.nextUrl.searchParams
  const limit = Math.min(2000, Math.max(1, Number(sp.get('limit')) || 200))
  const before = Number(sp.get('before')) || Infinity
  const q = (sp.get('q') || '').toLowerCase().trim()
  const user = sp.get('user') || ''
  const cats = (sp.get('category') || '').split(',').filter(Boolean)
  const result = sp.get('result') || ''
  const views = sp.get('views') === '1'

  const all = readAll()
  const now = Date.now()
  const day = now - 86_400_000
  const recent = all.filter((e) => e.ts >= day)
  const summary = {
    total: all.length,
    last24h: recent.filter((e) => e.category !== 'view').length,
    failedLogins24h: recent.filter((e) => e.action === 'auth.login' && e.result !== 'ok').length,
    denied24h: recent.filter((e) => e.result === 'denied').length,
    changes24h: recent.filter((e) => ['users', 'groups', 'protect', 'lockdown', 'notes', 'reports'].includes(e.category) && e.result === 'ok').length,
    users: [...new Set(all.map((e) => e.user).filter(Boolean))].sort(),
  }
  const match = (e: AuditEntry) =>
    e.ts < before &&
    (views || e.category !== 'view' || cats.includes('view')) &&
    (!user || e.user === user) &&
    (!cats.length || cats.includes(e.category)) &&
    (!result || e.result === result) &&
    (!q || `${e.user} ${e.action} ${e.target ?? ''} ${e.summary} ${e.ip ?? ''} ${JSON.stringify(e.detail ?? {})}`.toLowerCase().includes(q))
  const out: AuditEntry[] = []
  for (let i = all.length - 1; i >= 0 && out.length < limit; i--) if (match(all[i])) out.push(all[i])
  const body: Record<string, unknown> = { entries: out, summary, more: out.length === limit }
  if (sp.get('verify') === '1') body.chain = verifyChain()
  return NextResponse.json(body)
}

// An event the Edge middleware signed (refusals it decided before any route ran).
function internalEvent(raw: string, sig: string | null): Record<string, any> | null {
  const secret = process.env.DASH_SESSION
  if (!secret || !sig) return null
  const want = createHmac('sha256', `audit:${secret}`).update(raw).digest('base64url')
  const a = Buffer.from(sig), b = Buffer.from(want)
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null
  try { return JSON.parse(raw) } catch { return null }
}

export async function POST(req: NextRequest) {
  const raw = await req.text()
  const internal = internalEvent(raw, req.headers.get('x-xs-audit-sig'))
  if (internal) {
    const action = internal.action === 'access.unauthorized' ? 'access.unauthorized' : 'access.denied'
    audit(null, { user: String(internal.user || ''), category: 'access', action, target: String(internal.target || '').slice(0, 200), summary: String(internal.summary || action).slice(0, 300), result: 'denied',
      ip: internal.ip ?? null, ua: internal.ua ?? null, detail: { via: 'middleware' } })
    return NextResponse.json({ ok: true })
  }
  const access = await currentAccess(req)
  if (!access) return NextResponse.json({ error: 'unauthorized' }, { status: 401 })
  let b: any = {}
  try { b = JSON.parse(raw) } catch {}
  const category = String(b?.category || '') as AuditCategory
  const action = String(b?.action || '').slice(0, 64)
  if (!CLIENT_CATEGORIES.includes(category) || !/^[a-z]+\.[a-z_.]+$/.test(action) || !action.startsWith(`${category}.`)) {
    return NextResponse.json({ error: 'invalid audit event' }, { status: 400 })
  }
  let detail: Record<string, unknown> | undefined
  if (b?.detail && typeof b.detail === 'object') {
    const s = JSON.stringify(b.detail)
    detail = s.length <= 2000 ? b.detail : { truncated: s.slice(0, 2000) }
  }
  audit(req, {
    user: access.authDisabled ? '(auth disabled)' : access.username, kind: access.kind,
    category, action,
    target: typeof b?.target === 'string' ? b.target.slice(0, 200) : undefined,
    summary: String(b?.summary || action).slice(0, 300),
    detail,
  })
  return NextResponse.json({ ok: true })
}
