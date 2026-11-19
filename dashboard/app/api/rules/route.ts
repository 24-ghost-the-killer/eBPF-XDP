import { NextRequest, NextResponse } from 'next/server'
import { readFileSync, writeFileSync, renameSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { randomUUID } from 'node:crypto'
import { requirePerm } from '@/lib/api-auth'
import { audit } from '@/lib/audit'
import { describeRule, type Rule, type Field } from '@/lib/sigrules'

// Attack-signature rules.
//   GET  /api/rules?from=<unix>&to=<unix> -> rules (+ hits), and the packet shapes dropped in that window
//   POST /api/rules { rule }               -> add one (needs rules.edit)
//   PATCH /api/rules { id, on?, expires_at? } -> switch on/off, change expiry
//   DELETE /api/rules?id=…                 -> remove
// rules.json is loaded into the dataplane by xs-rules-apply (path unit).
export const dynamic = 'force-dynamic'

const AGENT = process.env.AGENT_URL || 'http://localhost:9464'
const MAX = 16
const FIELDS: Field[] = ['proto', 'dport', 'sport', 'flags', 'len', 'ttl']

function file() {
  const users = process.env.DASH_USERS_FILE || '/home/test_server/xdp-sentinel-data/dash-users.json'
  return join(dirname(users), 'rules.json')
}
function read(): Rule[] {
  try { const j = JSON.parse(readFileSync(file(), 'utf8')); return Array.isArray(j.rules) ? j.rules : [] } catch { return [] }
}
function write(rules: Rule[]) {
  mkdirSync(dirname(file()), { recursive: true })
  writeFileSync(`${file()}.tmp`, JSON.stringify({ rules, updatedAt: Date.now() }, null, 1), { mode: 0o644 })
  renameSync(`${file()}.tmp`, file())
}
const int = (v: unknown, lo: number, hi: number, d: number) => { const n = Math.round(Number(v)); return Number.isFinite(n) ? Math.max(lo, Math.min(hi, n)) : d }

export async function GET(req: NextRequest) {
  const auth = await requirePerm(req, 'rules')
  if (auth.error) return auth.error
  const sp = req.nextUrl.searchParams
  const q = sp.has('from') ? `?from=${int(sp.get('from'), 0, 4e9, 0)}&to=${int(sp.get('to'), 0, 4e9, 0)}` : ''
  let live: { shapes?: unknown[]; rules?: { slot: number; hits: number }[]; history_since?: number; sample?: number; sampled_total?: number } | null = null
  try {
    const r = await fetch(`${AGENT}/api/signatures.json${q}`, { cache: 'no-store', signal: AbortSignal.timeout(5000) })
    if (r.ok) live = await r.json()
  } catch {}
  const rules = read()
  // slot = the rule's position in rules.json (xs-rules-apply loads rule i into slot i)
  const now = Date.now() / 1000
  const hits = new Map((live?.rules ?? []).map((x) => [x.slot, x.hits]))
  return NextResponse.json({
    status: 'success', agentReachable: !!live,
    rules: rules.map((r, i) => ({ ...r, active: r.on && !(r.expires_at && r.expires_at < now), hits: hits.get(i) ?? 0, text: describeRule(r) })),
    shapes: live?.shapes ?? [], sampledTotal: live?.sampled_total ?? 0, sample: live?.sample ?? 16, historySince: live?.history_since ?? 0, max: MAX,
  })
}

export async function POST(req: NextRequest) {
  const auth = await requirePerm(req, 'rules.edit')
  if (auth.error) return auth.error
  const b = (await req.json().catch(() => null))?.rule
  if (!b) return NextResponse.json({ status: 'error', error: 'rule missing' }, { status: 400 })
  const rules = read()
  if (rules.length >= MAX) return NextResponse.json({ status: 'error', error: `At most ${MAX} rules: remove one first.` }, { status: 409 })
  const match = (Array.isArray(b.match) ? b.match : []).filter((f: string): f is Field => FIELDS.includes(f as Field))
  // a rule must pin more than the protocol, or it would drop a whole protocol
  if (match.filter((f: Field) => f !== 'proto').length < 1) return NextResponse.json({ status: 'error', error: 'A rule needs at least a port, size, flag or TTL condition.' }, { status: 400 })
  const by = auth.access.authDisabled ? '' : auth.access.username
  const hours = Number(b.hours)
  const rule: Rule = {
    id: randomUUID(), on: true, note: typeof b.note === 'string' ? b.note.slice(0, 120) : undefined,
    proto: int(b.proto, 0, 255, 0), dport: int(b.dport, 0, 65535, 0), sport: int(b.sport, 0, 65535, 0),
    tcp_flags: int(b.tcp_flags, 0, 255, 0), flags_mask: int(b.flags_mask, 0, 255, 0),
    len_lo: int(b.len_lo, 0, 65535, 0), len_hi: int(b.len_hi, 0, 65535, 65535), ttl_lo: int(b.ttl_lo, 0, 255, 0), ttl_hi: int(b.ttl_hi, 0, 255, 255),
    match, expires_at: hours > 0 ? Math.round(Date.now() / 1000 + hours * 3600) : null,
    createdAt: Date.now(), createdBy: by, fromAttack: Number(b.fromAttack) || undefined,
  }
  write([...rules, rule])
  audit(req, { user: by, kind: auth.access.kind, category: 'rules', action: 'rules.add', target: rule.id, summary: `Added signature rule: drop ${describeRule(rule)}${rule.expires_at ? ` for ${hours} h` : ''}`, detail: { ...rule } })
  return NextResponse.json({ status: 'success', rule })
}

export async function PATCH(req: NextRequest) {
  const auth = await requirePerm(req, 'rules.edit')
  if (auth.error) return auth.error
  const b = await req.json().catch(() => null)
  const rules = read()
  const i = rules.findIndex((r) => r.id === b?.id)
  if (i < 0) return NextResponse.json({ status: 'error', error: 'no such rule' }, { status: 404 })
  const r = { ...rules[i] }
  if (typeof b.on === 'boolean') r.on = b.on
  if (b.hours !== undefined) r.expires_at = Number(b.hours) > 0 ? Math.round(Date.now() / 1000 + Number(b.hours) * 3600) : null
  rules[i] = r
  write(rules)
  const by = auth.access.authDisabled ? '' : auth.access.username
  audit(req, { user: by, kind: auth.access.kind, category: 'rules', action: 'rules.update', target: r.id, summary: `Signature rule (${describeRule(r)}): ${r.on ? 'on' : 'off'}${r.expires_at ? `, until ${new Date(r.expires_at * 1000).toISOString().slice(0, 16)} UTC` : ', no expiry'}` })
  return NextResponse.json({ status: 'success' })
}

export async function DELETE(req: NextRequest) {
  const auth = await requirePerm(req, 'rules.edit')
  if (auth.error) return auth.error
  const id = req.nextUrl.searchParams.get('id')
  const rules = read()
  const r = rules.find((x) => x.id === id)
  if (!r) return NextResponse.json({ status: 'error', error: 'no such rule' }, { status: 404 })
  write(rules.filter((x) => x.id !== id))
  const by = auth.access.authDisabled ? '' : auth.access.username
  audit(req, { user: by, kind: auth.access.kind, category: 'rules', action: 'rules.remove', target: r.id, summary: `Removed signature rule: ${describeRule(r)}` })
  return NextResponse.json({ status: 'success' })
}
