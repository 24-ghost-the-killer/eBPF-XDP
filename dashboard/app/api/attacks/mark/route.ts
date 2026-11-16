import { NextRequest, NextResponse } from 'next/server'
import { requirePerm } from '@/lib/api-auth'
import { audit } from '@/lib/audit'
import { MARK_REASONS, readMarks, setMark, clearMark, type MarkReason } from '@/lib/marks'

// Mark an attack as a false alarm ("not an attack") or remove the mark.
//   POST   /api/attacks/mark  { id, reason, note? }  -> { status, mark }
//   DELETE /api/attacks/mark?id=<start seconds>      -> { status }
// Needs the attacks.mark permission; every change goes to the audit log.
export const dynamic = 'force-dynamic'

const when = (id: number) => new Date(id * 1000).toISOString().replace('T', ' ').slice(0, 16) + ' UTC'

export async function POST(req: NextRequest) {
  const auth = await requirePerm(req, 'attacks.mark')
  if (auth.error) return auth.error
  const body = await req.json().catch(() => null)
  const id = Number(body?.id)
  const reason = String(body?.reason ?? '') as MarkReason
  const note = typeof body?.note === 'string' ? body.note.trim().slice(0, 300) : ''
  if (!Number.isInteger(id) || id <= 0) return NextResponse.json({ status: 'error', error: 'bad attack id' }, { status: 400 })
  if (!MARK_REASONS.includes(reason)) return NextResponse.json({ status: 'error', error: 'pick a reason' }, { status: 400 })
  const by = auth.access.authDisabled ? '' : auth.access.username
  const mark = { reason, ...(note ? { note } : {}), by, at: Date.now() }
  try {
    const had = !!readMarks()[String(id)]
    setMark(id, mark)
    audit(req, {
      user: by, kind: auth.access.kind, category: 'attacks', action: had ? 'attacks.remark' : 'attacks.mark', target: String(id),
      summary: `Marked the attack of ${when(id)} as a false alarm (${reason})${note ? `: ${note}` : ''}`, detail: { reason, note },
    })
    return NextResponse.json({ status: 'success', mark })
  } catch (e) {
    return NextResponse.json({ status: 'error', error: e instanceof Error ? e.message : 'could not save' }, { status: 500 })
  }
}

export async function DELETE(req: NextRequest) {
  const auth = await requirePerm(req, 'attacks.mark')
  if (auth.error) return auth.error
  const id = Number(req.nextUrl.searchParams.get('id'))
  if (!Number.isInteger(id) || id <= 0) return NextResponse.json({ status: 'error', error: 'bad attack id' }, { status: 400 })
  try {
    const by = auth.access.authDisabled ? '' : auth.access.username
    if (clearMark(id)) {
      audit(req, { user: by, kind: auth.access.kind, category: 'attacks', action: 'attacks.unmark', target: String(id), summary: `Unmarked the attack of ${when(id)}: counts as an attack again` })
    }
    return NextResponse.json({ status: 'success' })
  } catch (e) {
    return NextResponse.json({ status: 'error', error: e instanceof Error ? e.message : 'could not save' }, { status: 500 })
  }
}
