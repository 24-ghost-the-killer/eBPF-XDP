import { NextRequest, NextResponse } from 'next/server'
import { requirePerm } from '@/lib/api-auth'
import { audit } from '@/lib/audit'
import { readStore } from '@/lib/devices'
import { MAX_ADDRESSES, readWanted, writeWanted, readLive, readAttempts, lanInfo, inSubnet, isIPv4, suggest, type Wanted } from '@/lib/honeypot'

// Honeypot addresses.
//   GET /api/honeypot                          -> wanted + live state, hits with device names, free-address suggestions
//   PUT /api/honeypot { addresses: [{ip, block, note?}] }  -> replace the list (needs honeypot.edit)
//   POST /api/honeypot { reset: "<ip>" }        -> clear a conflict so the honeypot answers again (needs honeypot.edit)
export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  const auth = await requirePerm(req, 'honeypot')
  if (auth.error) return auth.error
  const [live, info] = await Promise.all([readLive(), lanInfo()])
  const wanted = readWanted()
  const devices = readStore().devices
  const byIp = new Map<string, { mac: string; name?: string }>()
  for (const [mac, d] of Object.entries(devices)) for (const ip of d.ips ?? []) if (!byIp.has(ip)) byIp.set(ip, { mac, name: d.name })
  const byMac = new Map(Object.entries(devices).map(([mac, d]) => [mac.toLowerCase(), d.name]))
  const sources = (live?.sources ?? []).map((s) => ({ ...s, device: byMac.get(s.mac.toLowerCase()) ?? byIp.get(s.ip)?.name ?? null }))
  const taken = new Set(wanted.addresses.map((a) => a.ip))
  // passwords tried on the fake logins: shown only to those who may change the honeypot
  const reveal = auth.access.perms.includes('honeypot.edit')
  const attempts = readAttempts().map((x) => ({
    ...x, device: byIp.get(x.src)?.name ?? null,
    password: x.password == null ? null : reveal ? x.password : '•'.repeat(Math.min(12, x.password.length)),
  }))
  return NextResponse.json({
    attempts, passwordsShown: reveal,
    status: 'success', wanted, live: live ? { ...live, sources } : null,
    agentReachable: !!live, lan: info ? { net: `${info.net}/${info.prefix}`, self: info.self, gateway: info.gateway } : null,
    suggestions: info ? suggest(info, taken) : [], max: MAX_ADDRESSES,
  })
}

export async function PUT(req: NextRequest) {
  const auth = await requirePerm(req, 'honeypot.edit')
  if (auth.error) return auth.error
  const body = await req.json().catch(() => null)
  const list = Array.isArray(body?.addresses) ? body.addresses : null
  if (!list) return NextResponse.json({ status: 'error', error: 'addresses missing' }, { status: 400 })
  if (list.length > MAX_ADDRESSES) return NextResponse.json({ status: 'error', error: `at most ${MAX_ADDRESSES} addresses` }, { status: 400 })
  const info = await lanInfo()
  if (!info) return NextResponse.json({ status: 'error', error: 'could not read the box’s LAN address' }, { status: 500 })
  const by = auth.access.authDisabled ? '' : auth.access.username
  const before = readWanted()
  const old = new Map(before.addresses.map((a) => [a.ip, a]))
  const out: Wanted[] = []
  for (const a of list) {
    const ip = String(a?.ip ?? '').trim()
    if (!isIPv4(ip)) return NextResponse.json({ status: 'error', error: `${ip || '(empty)'} is not an IPv4 address` }, { status: 400 })
    if (!inSubnet(ip, info.net, info.prefix)) return NextResponse.json({ status: 'error', error: `${ip} is not in the LAN (${info.net}/${info.prefix})` }, { status: 400 })
    if (ip === info.self || ip === info.gateway) return NextResponse.json({ status: 'error', error: `${ip} is the box or the router` }, { status: 400 })
    if (!old.has(ip) && info.used.has(ip)) return NextResponse.json({ status: 'error', error: `${ip} is in use by a device: pick a free address` }, { status: 400 })
    if (out.some((x) => x.ip === ip)) continue
    const note = typeof a?.note === 'string' ? a.note.trim().slice(0, 80) : ''
    out.push({ ip, block: a?.block !== false, interactive: a?.interactive === true, ...(note ? { note } : {}), addedBy: old.get(ip)?.addedBy ?? by, addedAt: old.get(ip)?.addedAt ?? Date.now() })
  }
  writeWanted({ addresses: out, updatedAt: Date.now(), updatedBy: by })
  const added = out.filter((a) => !old.has(a.ip)).map((a) => a.ip)
  const removed = before.addresses.filter((a) => !out.some((x) => x.ip === a.ip)).map((a) => a.ip)
  const changed = [
    ...out.filter((a) => old.has(a.ip) && old.get(a.ip)!.block !== a.block).map((a) => `${a.ip} block ${a.block ? 'on' : 'off'}`),
    ...out.filter((a) => old.has(a.ip) && !!old.get(a.ip)!.interactive !== !!a.interactive).map((a) => `${a.ip} fake login ${a.interactive ? 'on' : 'off'}`),
  ]
  const parts = [added.length && `added ${added.join(', ')}`, removed.length && `removed ${removed.join(', ')}`, changed.length && changed.join(', ')].filter(Boolean)
  audit(req, {
    user: by, kind: auth.access.kind, category: 'honeypot', action: 'honeypot.update',
    summary: `Honeypot addresses: ${parts.join('; ') || 'saved, no change'}`, detail: { addresses: out.map((a) => ({ ip: a.ip, block: a.block, interactive: !!a.interactive })) },
  })
  return NextResponse.json({ status: 'success', wanted: readWanted() })
}

export async function POST(req: NextRequest) {
  const auth = await requirePerm(req, 'honeypot.edit')
  if (auth.error) return auth.error
  const body = await req.json().catch(() => null)
  const ip = String(body?.reset ?? '')
  const doc = readWanted()
  if (!isIPv4(ip) || !doc.addresses.some((a) => a.ip === ip)) return NextResponse.json({ status: 'error', error: 'not a honeypot address' }, { status: 400 })
  const info = await lanInfo()
  if (info?.used.has(ip)) return NextResponse.json({ status: 'error', error: `A device still uses ${ip}. Remove the honeypot or pick another address.` }, { status: 409 })
  const by = auth.access.authDisabled ? '' : auth.access.username
  writeWanted({ ...doc, reset: [ip], updatedAt: Date.now(), updatedBy: by })
  audit(req, { user: by, kind: auth.access.kind, category: 'honeypot', action: 'honeypot.reset', target: ip, summary: `Re-armed honeypot ${ip} after a conflict` })
  return NextResponse.json({ status: 'success' })
}
