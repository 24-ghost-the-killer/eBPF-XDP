import { NextRequest, NextResponse } from 'next/server'
import { randomUUID } from 'node:crypto'
import { requirePerm } from '@/lib/api-auth'
import { audit } from '@/lib/audit'
import { readStore } from '@/lib/devices'
import { startUptime, statuses, readChecks, writeChecks, checkNow, type Kind, type Check } from '@/lib/uptime'

// Service uptime board.
//   GET    /api/uptime                       -> every check with status, uptime and a 24 h strip; suggestions
//   POST   /api/uptime { name, host, kind, port?, path? }  -> add (needs uptime.edit)
//   DELETE /api/uptime?id=…                  -> remove
export const dynamic = 'force-dynamic'

const KINDS: Kind[] = ['ping', 'tcp', 'http', 'https']
const HOST = /^[a-zA-Z0-9.-]{1,253}$/

// services the device scan found that are worth watching
function suggestions(existing: Check[]) {
  const have = new Set(existing.map((c) => `${c.host}:${c.kind}:${c.port ?? ''}`))
  const out: Omit<Check, 'id' | 'createdAt'>[] = []
  const add = (s: Omit<Check, 'id' | 'createdAt'>) => { if (!have.has(`${s.host}:${s.kind}:${s.port ?? ''}`)) out.push(s) }
  for (const [, d] of Object.entries(readStore().devices)) {
    const ip = d.ips?.[0]
    const ports = d.probe?.ports ?? []
    if (!ip || !d.known && !d.name) continue
    const name = d.name ?? d.names?.mdns ?? ip
    if (ports.includes(8006)) add({ name: `${name} (Proxmox)`, host: ip, kind: 'https', port: 8006 })
    else if (ports.includes(554)) add({ name: `${name} (camera)`, host: ip, kind: 'tcp', port: 554 })
    else if (ports.includes(9100) || ports.includes(631)) add({ name: `${name} (printer)`, host: ip, kind: 'tcp', port: ports.includes(9100) ? 9100 : 631 })
    else if (ports.includes(443)) add({ name, host: ip, kind: 'https', port: 443 })
    else if (ports.includes(80)) add({ name, host: ip, kind: 'http', port: 80 })
    else if (ports.includes(22)) add({ name, host: ip, kind: 'tcp', port: 22 })
  }
  return out.slice(0, 12)
}

export async function GET(req: NextRequest) {
  const auth = await requirePerm(req, null)
  if (auth.error) return auth.error
  startUptime()
  const all = statuses()
  return NextResponse.json({ status: 'success', checks: all, suggestions: auth.access.perms.includes('uptime') ? suggestions(all) : [] })
}

export async function POST(req: NextRequest) {
  const auth = await requirePerm(req, 'uptime.edit')
  if (auth.error) return auth.error
  const b = await req.json().catch(() => null)
  const kind = KINDS.includes(b?.kind) ? (b.kind as Kind) : null
  const host = String(b?.host ?? '').trim()
  const name = String(b?.name ?? '').trim().slice(0, 60) || host
  const port = b?.port ? Math.round(Number(b.port)) : undefined
  if (!kind || !HOST.test(host)) return NextResponse.json({ status: 'error', error: 'Give a host (IP or name) and a check type.' }, { status: 400 })
  if (kind !== 'ping' && port !== undefined && !(port > 0 && port < 65536)) return NextResponse.json({ status: 'error', error: 'bad port' }, { status: 400 })
  if (kind === 'tcp' && !port) return NextResponse.json({ status: 'error', error: 'A TCP check needs a port.' }, { status: 400 })
  const checks = readChecks()
  if (checks.length >= 50) return NextResponse.json({ status: 'error', error: 'At most 50 checks.' }, { status: 409 })
  const c: Check = { id: randomUUID(), name, host, kind, ...(kind !== 'ping' && port ? { port } : {}), ...(kind.startsWith('http') && typeof b?.path === 'string' && b.path.startsWith('/') ? { path: b.path.slice(0, 200) } : {}), createdAt: Date.now() }
  writeChecks([...checks, c])
  void checkNow()
  const by = auth.access.authDisabled ? '' : auth.access.username
  audit(req, { user: by, kind: auth.access.kind, category: 'uptime', action: 'uptime.add', target: c.id, summary: `Added uptime check “${name}” (${kind} ${host}${c.port ? `:${c.port}` : ''})` })
  return NextResponse.json({ status: 'success', check: c })
}

export async function DELETE(req: NextRequest) {
  const auth = await requirePerm(req, 'uptime.edit')
  if (auth.error) return auth.error
  const id = req.nextUrl.searchParams.get('id')
  const checks = readChecks()
  const c = checks.find((x) => x.id === id)
  if (!c) return NextResponse.json({ status: 'error', error: 'no such check' }, { status: 404 })
  writeChecks(checks.filter((x) => x.id !== id))
  const by = auth.access.authDisabled ? '' : auth.access.username
  audit(req, { user: by, kind: auth.access.kind, category: 'uptime', action: 'uptime.remove', target: c.id, summary: `Removed uptime check “${c.name}”` })
  return NextResponse.json({ status: 'success' })
}
