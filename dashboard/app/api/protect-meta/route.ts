import { randomUUID } from 'node:crypto'
import { NextRequest, NextResponse } from 'next/server'
import { protectActor } from '@/lib/api-auth'
import { audit } from '@/lib/audit'
import { loadMeta, saveMeta, emptyMeta, assertIp, publishMeta, META_LIMITS, PlanError } from '@/lib/protect'

// Per-host notes for the Protection pages: nickname, reports and
// a timestamped log. Reading needs `protect`; nickname/log edits `protect.notes`;
// deleting a log entry `protect.delete`.
//   GET                          -> { hosts: { [ip]: { nickname, log[], reports[] } } }
//   PUT    { ip, nickname }        -> set the nickname
//   POST   { ip, text }            -> append a log entry (author = signed-in user)
//   DELETE ?ip=..&id=..            -> remove one log entry
// Reports have their own route (/api/protect-meta/reports). Every successful
// change is pushed to open pages via /api/protect-meta/stream.
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

const actor = protectActor
const forbidden = () => NextResponse.json({ error: 'forbidden' }, { status: 403 })
function fail(e: unknown) {
  if (e instanceof PlanError) return NextResponse.json({ error: e.message }, { status: e.status })
  return NextResponse.json({ error: 'failed to save notes' }, { status: 500 })
}

export async function GET(req: NextRequest) {
  if ((await actor(req)) === null) return forbidden()
  return NextResponse.json({ hosts: loadMeta(), limits: META_LIMITS })
}

export async function PUT(req: NextRequest) {
  const who = await actor(req, 'protect.notes')
  if (who === null) return forbidden()
  const body = await req.json().catch(() => ({}))
  const by = who || 'admin'
  const clientId = typeof body?.clientId === 'string' ? body.clientId.slice(0, 64) : undefined
  try {
    const ip = String(body?.ip || '').trim()
    assertIp(ip)
    // Load -> modify -> save runs synchronously (no await in between), so two
    // requests can never interleave inside this block.
    const store = loadMeta()
    const m = store[ip] ?? emptyMeta()
    const oldNick = m.nickname
    if (body?.nickname !== undefined) {
      const n = String(body.nickname).trim()
      if (n.length > META_LIMITS.nickname) throw new PlanError(`nickname is longer than ${META_LIMITS.nickname} characters`)
      if (n !== oldNick) audit(req, { user: by, category: 'notes', action: 'notes.nickname', target: `host:${ip}`,
        summary: n ? `Renamed ${ip} ${oldNick ? `from “${oldNick}” ` : ''}to “${n}”` : `Removed the nickname “${oldNick}” from ${ip}`, detail: { from: oldNick, to: n } })
      m.nickname = n
    }
    store[ip] = m
    saveMeta(store)
    publishMeta(ip, m, by, clientId)
    return NextResponse.json({ ok: true, ip, meta: m })
  } catch (e) {
    return fail(e)
  }
}

export async function POST(req: NextRequest) {
  const who = await actor(req, 'protect.notes')
  if (who === null) return forbidden()
  const body = await req.json().catch(() => ({}))
  try {
    const ip = String(body?.ip || '').trim()
    assertIp(ip)
    const text = String(body?.text || '').trim()
    if (!text) throw new PlanError('log entry is empty')
    if (text.length > META_LIMITS.logText) throw new PlanError(`log entry is longer than ${META_LIMITS.logText} characters`)
    const store = loadMeta()
    const m = store[ip] ?? emptyMeta()
    const entryId = randomUUID()
    m.log = [{ id: entryId, ts: Math.floor(Date.now() / 1000), author: who || 'admin', text }, ...m.log].slice(0, META_LIMITS.logEntries)
    audit(req, { user: who || 'admin', category: 'notes', action: 'notes.log_add', target: `host:${ip}`, summary: `Log entry on ${ip}: “${text.slice(0, 120)}${text.length > 120 ? '…' : ''}”`, detail: { entryId, text } })
    store[ip] = m
    saveMeta(store)
    publishMeta(ip, m, who || 'admin', typeof body?.clientId === 'string' ? body.clientId.slice(0, 64) : undefined)
    return NextResponse.json({ ok: true, ip, meta: m })
  } catch (e) {
    return fail(e)
  }
}

export async function DELETE(req: NextRequest) {
  const who = await actor(req, 'protect.delete')
  if (who === null) return forbidden()
  try {
    const ip = (req.nextUrl.searchParams.get('ip') || '').trim()
    const id = req.nextUrl.searchParams.get('id') || ''
    assertIp(ip)
    const store = loadMeta()
    const m = store[ip] ?? emptyMeta()
    const gone = m.log.find((e) => e.id === id)
    m.log = m.log.filter((e) => e.id !== id)
    if (gone) audit(req, { user: who || 'admin', category: 'notes', action: 'notes.log_delete', target: `host:${ip}`,
      summary: `Deleted ${gone.author}'s log entry on ${ip}: “${gone.text.slice(0, 120)}${gone.text.length > 120 ? '…' : ''}”`, detail: { entryId: id, author: gone.author, text: gone.text, ts: gone.ts } })
    store[ip] = m
    saveMeta(store)
    publishMeta(ip, m, who || 'admin', req.nextUrl.searchParams.get('clientId')?.slice(0, 64))
    return NextResponse.json({ ok: true, ip, meta: m })
  } catch (e) {
    return fail(e)
  }
}
