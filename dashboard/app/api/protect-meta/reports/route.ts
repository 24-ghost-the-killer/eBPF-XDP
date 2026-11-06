import { randomUUID } from 'node:crypto'
import { NextRequest, NextResponse } from 'next/server'
import { protectActor } from '@/lib/api-auth'
import { audit } from '@/lib/audit'
import { loadMeta, saveMeta, emptyMeta, assertIp, publishMeta, PlanError } from '@/lib/protect'
import { newReport, validateEdit, mergeReport, editOf, kindOf, ReportError, REPORT_LIMITS, type ReportKind } from '@/lib/reports'

// Structured per-host reports. Create/edit need `protect.reports`; delete needs `protect.delete`.
//   POST   { ip, kind, title? }                 -> create a report from the kind's template
//   PUT    { ip, id, report, base, baseRev }    -> save an edit. `base`/`baseRev` are the
//          report as the editor loaded it. If someone saved in between, the edits are
//          three-way merged (fields + per-section text). Overlapping edits return 409
//          with the merged report (conflict markers / field choices) — never overwritten.
//   DELETE ?ip=..&id=..                         -> delete a report
// Every change is pushed live via /api/protect-meta/stream.
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

const forbidden = () => NextResponse.json({ error: 'forbidden' }, { status: 403 })
function fail(e: unknown) {
  if (e instanceof PlanError || e instanceof ReportError) return NextResponse.json({ error: e.message }, { status: e.status })
  return NextResponse.json({ error: 'failed to save the report' }, { status: 500 })
}
const cid = (v: unknown) => (typeof v === 'string' ? v.slice(0, 64) : undefined)
const shortId = () => randomUUID().replace(/-/g, '').slice(0, 12)

export async function POST(req: NextRequest) {
  const who = await protectActor(req, 'protect.reports')
  if (who === null) return forbidden()
  const body = await req.json().catch(() => ({}))
  try {
    const ip = String(body?.ip || '').trim()
    assertIp(ip)
    const kind = kindOf(String(body?.kind || 'note')).id as ReportKind
    const title = String(body?.title || '').slice(0, REPORT_LIMITS.title)
    const store = loadMeta()
    const m = store[ip] ?? emptyMeta()
    if (m.reports.length >= REPORT_LIMITS.perHost) throw new ReportError(`at most ${REPORT_LIMITS.perHost} reports per host`)
    const r = newReport(kind, title, who || 'admin', shortId)
    m.reports = [r, ...m.reports]
    store[ip] = m
    saveMeta(store)
    publishMeta(ip, m, who || 'admin', cid(body?.clientId))
    audit(req, { user: who || 'admin', category: 'reports', action: 'reports.create', target: `report:${ip}/${r.id}`, summary: `Created ${r.kind} report “${r.title}” for ${ip}`, detail: { ip, id: r.id, kind: r.kind } })
    return NextResponse.json({ ok: true, ip, report: r })
  } catch (e) {
    return fail(e)
  }
}

export async function PUT(req: NextRequest) {
  const who = await protectActor(req, 'protect.reports')
  if (who === null) return forbidden()
  const by = who || 'admin'
  const body = await req.json().catch(() => ({}))
  try {
    const ip = String(body?.ip || '').trim()
    assertIp(ip)
    const id = String(body?.id || '')
    const mine = validateEdit(body?.report)
    const baseRev = Number(body?.baseRev)
    if (!Number.isInteger(baseRev) || !body?.base) throw new ReportError('missing base/baseRev — reload the page and try again')
    // Load -> merge -> save is synchronous: concurrent requests can't interleave.
    const store = loadMeta()
    const m = store[ip] ?? emptyMeta()
    const idx = m.reports.findIndex((r) => r.id === id)
    if (idx < 0) throw new ReportError('this report was deleted', 404)
    const cur = m.reports[idx]
    let next = mine
    let merged = false
    if (baseRev !== cur.rev) {
      const base = validateEdit(body.base)
      const r = mergeReport(base, mine, editOf(cur))
      if (r.fieldConflicts.length || r.textConflicts) {
        audit(req, { user: by, category: 'reports', action: 'reports.conflict', target: `report:${ip}/${id}`,
          summary: `Save of report “${cur.title}” on ${ip} returned to the editor: overlaps with ${cur.updatedBy}'s newer version`, result: 'conflict' })
        return NextResponse.json({
          error: 'conflict', merged: r.merged, fieldConflicts: r.fieldConflicts, textConflicts: r.textConflicts,
          current: cur,
        }, { status: 409 })
      }
      next = validateEdit(r.merged) // re-check limits on the merged result
      merged = true
    }
    const changed = JSON.stringify(next) !== JSON.stringify(editOf(cur))
    const saved = changed
      ? { ...cur, ...next, rev: cur.rev + 1, updatedBy: by, updatedAt: Math.floor(Date.now() / 1000) }
      : cur
    m.reports[idx] = saved
    if (changed) {
      const before = editOf(cur)
      const what: string[] = []
      if (before.title !== next.title) what.push(`title “${before.title}” → “${next.title}”`)
      if (before.status !== next.status) what.push(`status ${before.status} → ${next.status}`)
      if (before.kind !== next.kind) what.push(`type ${before.kind} → ${next.kind}`)
      const bs = new Map(before.sections.map((s) => [s.id, s]))
      const ns = new Map(next.sections.map((s) => [s.id, s]))
      const edited = next.sections.filter((s) => bs.has(s.id) && (bs.get(s.id)!.body !== s.body || bs.get(s.id)!.heading !== s.heading)).map((s) => s.heading || 'untitled')
      const added = next.sections.filter((s) => !bs.has(s.id)).map((s) => s.heading || 'untitled')
      const removed = before.sections.filter((s) => !ns.has(s.id)).map((s) => s.heading || 'untitled')
      if (edited.length) what.push(`edited ${edited.join(', ')}`)
      if (added.length) what.push(`added section ${added.join(', ')}`)
      if (removed.length) what.push(`removed section ${removed.join(', ')}`)
      audit(req, { user: by, category: 'reports', action: 'reports.update', target: `report:${ip}/${id}`,
        summary: `Edited report “${saved.title}” on ${ip}${merged ? ' (merged with a concurrent edit)' : ''}: ${what.join('; ') || 'reordered sections'}`,
        detail: { ip, id, rev: saved.rev, merged, before, after: next } })
    }
    store[ip] = m
    saveMeta(store)
    if (changed) publishMeta(ip, m, by, cid(body?.clientId))
    return NextResponse.json({ ok: true, ip, report: saved, merged })
  } catch (e) {
    return fail(e)
  }
}

export async function DELETE(req: NextRequest) {
  const who = await protectActor(req, 'protect.delete')
  if (who === null) return forbidden()
  try {
    const ip = (req.nextUrl.searchParams.get('ip') || '').trim()
    assertIp(ip)
    const id = req.nextUrl.searchParams.get('id') || ''
    const store = loadMeta()
    const m = store[ip] ?? emptyMeta()
    const gone = m.reports.find((r) => r.id === id)
    m.reports = m.reports.filter((r) => r.id !== id)
    if (gone) audit(req, { user: who || 'admin', category: 'reports', action: 'reports.delete', target: `report:${ip}/${id}`,
      summary: `Deleted ${gone.kind} report “${gone.title}” from ${ip}`, detail: { ip, report: gone } })
    store[ip] = m
    saveMeta(store)
    publishMeta(ip, m, who || 'admin', cid(req.nextUrl.searchParams.get('clientId')))
    return NextResponse.json({ ok: true })
  } catch (e) {
    return fail(e)
  }
}
