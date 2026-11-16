import { NextRequest, NextResponse } from 'next/server'
import { requirePerm } from '@/lib/api-auth'
import { audit } from '@/lib/audit'
import { observe, startWatching, readStore, writeStore, vendorOf, randomised, attacksBySource, discover, scanStatus } from '@/lib/devices'
import { identify } from '@/lib/discover'
import { networkInterfaces } from 'node:os'
import { makerOf } from '@/lib/maker'

// Devices seen on the network (see lib/devices.ts).
//   GET    /api/devices                         -> { status, devices, summary }
//   PATCH  /api/devices { mac, name?, known?, note? }   (devices.edit)
//   DELETE /api/devices?mac=..                  forget a device (devices.edit)
//   POST   /api/devices?action=scan             sweep the subnet + check every device now (devices.edit)
export const dynamic = 'force-dynamic'

const DAY = 86_400_000
const MAC_RE = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/

export async function GET(req: NextRequest) {
  const auth = await requirePerm(req, 'devices')
  if (auth.error) return auth.error
  startWatching()
  const snap = await observe()
  const store = readStore()
  const attacks = attacksBySource()
  const now = Date.now()
  const devices = Object.entries(store.devices).map(([mac, d]) => {
    const o = snap.online.get(mac)
    // the switch had it in its address table at the last history import
    const onSwitch = !!d.switchAt && now - d.switchAt < 15 * 60_000
    const ips = d.ips ?? []
    const hits = ips.map((ip) => attacks.get(ip)).filter(Boolean) as { count: number; last: number }[]
    const attackCount = hits.reduce((n, h) => n + h.count, 0)
    // another MAC answering for the same IP right now = possible ARP spoofing
    const conflict = (o?.ips ?? []).some((ip) => (snap.ipOwners.get(ip) ?? []).length > 1)
    // new = appeared in the last day AND after watching began (not part of the first look)
    const isNew = now - d.firstSeen < DAY && d.firstSeen > snap.createdAt + 5 * 60_000
    const flags = [
      ...(!d.known ? ['unknown'] : []),
      ...(isNew && !d.known ? ['new'] : []),
      ...(attackCount ? ['attacker'] : []),
      ...(conflict ? ['ip-conflict'] : []),
      ...((o?.ips ?? []).filter((ip) => !ip.includes(':')).length > 1 ? ['multi-ip'] : []),
      ...(randomised(mac) ? ['private-mac'] : []),
    ]
    const vendor = vendorOf(mac)
    const id = identify({ vendor, randomised: randomised(mac), ip: ips.find((x) => !x.includes(':')), probe: d.probe, names: d.names })
    return {
      mac, vendor, name: d.name ?? null, note: d.note ?? null, known: !!d.known,
      kind: id.kind, label: id.label, labelFrom: id.labelFrom, os: id.os, webUrl: id.webUrl, services: id.services, ports: id.ports,
      maker: makerOf(vendor, randomised(mac)),
      hostname: d.names?.mdns ?? d.names?.netbios ?? d.names?.llmnr ?? d.names?.upnp?.name ?? null, checkedAt: d.probe?.at ?? null,
      ips, port: d.port ?? null, firstSeen: d.firstSeen, lastSeen: o?.seen || onSwitch ? now : d.lastSeen,
      online: !!o?.seen || onSwitch, reachable: !!o?.reachable, flags,
      switchPort: d.switchPort ?? null, vlans: d.vlans ?? [], sources: d.sources ?? [],
      attacks: attackCount ? { count: attackCount, last: Math.max(...hits.map((h) => h.last)) } : null,
    }
  }).sort((a, b) => Number(b.online) - Number(a.online) || Number(a.known) - Number(b.known) || b.lastSeen - a.lastSeen)
  // LAN addresses seen in traffic or attacks that no device record holds
  const held = new Set(devices.flatMap((x) => x.ips))
  // the box's own addresses, and its internal container networks (docker0, br-…),
  // aren't devices on the LAN
  const ifs = networkInterfaces()
  const selfIps = new Set(Object.values(ifs).flat().map((n) => n?.address).filter(Boolean) as string[])
  const num = (ip: string) => ip.split('.').reduce((n, o) => n * 256 + +o, 0) >>> 0
  const internal = Object.entries(ifs).filter(([name]) => /^(docker|br-|veth|lo)/.test(name))
    .flatMap(([, list]) => (list ?? []).filter((n) => n.family === 'IPv4' && n.cidr).map((n) => {
      const bits = Number(n.cidr!.split('/')[1]); const mask = bits ? (~0 << (32 - bits)) >>> 0 : 0
      return { net: (num(n.address) & mask) >>> 0, mask }
    }))
  const isInternal = (ip: string) => /^\d+\.\d+\.\d+\.\d+$/.test(ip) && internal.some((r) => ((num(ip) & r.mask) >>> 0) === r.net)
  const addresses = Object.entries(store.addresses ?? {})
    .filter(([ip]) => !held.has(ip) && !selfIps.has(ip) && !isInternal(ip) && !/\.(0|255)$/.test(ip))
    .map(([ip, a]) => ({ ip, first: a.first, last: a.last, from: a.from, attacks: attacks.get(ip)?.count ?? 0 }))
    .sort((a, b) => a.ip.split('.').reduce((n, o) => n * 256 + +o, 0) - b.ip.split('.').reduce((n, o) => n * 256 + +o, 0))
  const summary = {
    total: devices.length,
    fromSwitch: devices.filter((x) => x.sources.includes('switch')).length,
    historySince: store.historyAt ? Math.min(...devices.map((x) => x.firstSeen)) : null,
    online: devices.filter((d) => d.online).length,
    unknown: devices.filter((d) => !d.known).length,
    new24h: devices.filter((d) => d.flags.includes('new')).length,
    attackers: devices.filter((d) => d.attacks).length,
  }
  return NextResponse.json({ status: 'success', at: now, devices, addresses, summary, scan: scanStatus() })
}

export async function POST(req: NextRequest) {
  const auth = await requirePerm(req, 'devices.edit')
  if (auth.error) return auth.error
  if (req.nextUrl.searchParams.get('action') !== 'scan') return NextResponse.json({ status: 'error', error: 'unknown action' }, { status: 400 })
  startWatching()
  const r = await discover(true)
  const by = auth.access.authDisabled ? '' : auth.access.username
  audit(req, { user: by, kind: auth.access.kind, category: 'devices', action: 'devices.scan', summary: `Scanned the network: ${r.found} device${r.found === 1 ? '' : 's'} answered (${(r.took / 1000).toFixed(0)} s)` })
  return NextResponse.json({ status: 'success', scan: r })
}

export async function PATCH(req: NextRequest) {
  const auth = await requirePerm(req, 'devices.edit')
  if (auth.error) return auth.error
  const b = await req.json().catch(() => null)
  const mac = String(b?.mac ?? '').toLowerCase()
  if (!MAC_RE.test(mac)) return NextResponse.json({ status: 'error', error: 'bad MAC address' }, { status: 400 })
  const store = readStore()
  const d = store.devices[mac]
  if (!d) return NextResponse.json({ status: 'error', error: 'no such device' }, { status: 404 })
  const next = { ...d }
  const changes: string[] = []
  if (typeof b.name === 'string') {
    const name = b.name.trim().slice(0, 60)
    if (name) next.name = name; else delete next.name
    changes.push(name ? `named it “${name}”` : 'removed its name')
  }
  if (typeof b.note === 'string') {
    const note = b.note.trim().slice(0, 300)
    if (note) next.note = note; else delete next.note
    changes.push('edited its note')
  }
  if (typeof b.known === 'boolean') {
    next.known = b.known
    changes.push(b.known ? 'marked it known' : 'marked it unknown')
  }
  if (!changes.length) return NextResponse.json({ status: 'error', error: 'nothing to change' }, { status: 400 })
  writeStore({ ...store, devices: { ...store.devices, [mac]: next } })
  const by = auth.access.authDisabled ? '' : auth.access.username
  audit(req, { user: by, kind: auth.access.kind, category: 'devices', action: 'devices.edit', target: mac, summary: `Device ${mac}${d.ips[0] ? ` (${d.ips[0]})` : ''}: ${changes.join(', ')}`, detail: { name: next.name, known: next.known } })
  return NextResponse.json({ status: 'success' })
}

export async function DELETE(req: NextRequest) {
  const auth = await requirePerm(req, 'devices.edit')
  if (auth.error) return auth.error
  const mac = String(req.nextUrl.searchParams.get('mac') ?? '').toLowerCase()
  if (!MAC_RE.test(mac)) return NextResponse.json({ status: 'error', error: 'bad MAC address' }, { status: 400 })
  const store = readStore()
  const d = store.devices[mac]
  if (!d) return NextResponse.json({ status: 'success' })
  const devices = { ...store.devices }
  delete devices[mac]
  writeStore({ ...store, devices })
  const by = auth.access.authDisabled ? '' : auth.access.username
  audit(req, { user: by, kind: auth.access.kind, category: 'devices', action: 'devices.forget', target: mac, summary: `Forgot device ${d.name ? `“${d.name}” ` : ''}${mac} (it comes back as new if it is seen again)` })
  return NextResponse.json({ status: 'success' })
}
