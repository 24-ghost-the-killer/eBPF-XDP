import { NextRequest, NextResponse } from 'next/server'
import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { requirePerm } from '@/lib/api-auth'
import { audit } from '@/lib/audit'
import { readStore, writeStore } from '@/lib/devices'

// LAN guard: ARP-spoofing alarm and new-device approval.
//   GET /api/languard -> settings, what the dataplane saw (agent), unapproved devices
//   PUT /api/languard { nac: 'off'|'watch'|'enforce', arpGuard: boolean }  (needs devices.guard)
// Approving a device = marking it known on the Devices page (devices.edit).
// The root helper xs-languard-apply loads it all into the XDP maps.
//
// The first time this runs, every device already in the registry is approved
// and the mode starts at "watch": new devices are flagged, nothing is cut off.
export const dynamic = 'force-dynamic'

const AGENT = process.env.AGENT_URL || 'http://localhost:9464'
type Mode = 'off' | 'watch' | 'enforce'
interface Settings { nac: Mode; arpGuard: boolean; since: number; updatedAt?: number; updatedBy?: string }

function file() {
  const users = process.env.DASH_USERS_FILE || '/home/test_server/xdp-sentinel-data/dash-users.json'
  return join(dirname(users), 'languard.json')
}
function write(s: Settings) {
  mkdirSync(dirname(file()), { recursive: true })
  writeFileSync(`${file()}.tmp`, JSON.stringify(s, null, 1), { mode: 0o644 })
  renameSync(`${file()}.tmp`, file())
}
function settings(): Settings {
  if (!existsSync(file())) {
    // first run: approve everything that is already here, then watch
    const store = readStore()
    const devices = Object.fromEntries(Object.entries(store.devices).map(([m, d]) => [m, d.known === undefined ? { ...d, known: true } : d]))
    writeStore({ ...store, devices })
    const s: Settings = { nac: 'watch', arpGuard: true, since: Date.now() }
    write(s)
    audit(null, { user: 'system', kind: 'user', category: 'languard', action: 'languard.init', summary: `LAN guard started: ${Object.keys(devices).length} devices already on the network approved, new devices are watched` })
    return s
  }
  try {
    const j = JSON.parse(readFileSync(file(), 'utf8'))
    return { nac: ['off', 'watch', 'enforce'].includes(j.nac) ? j.nac : 'watch', arpGuard: j.arpGuard !== false, since: Number(j.since) || Date.now(), updatedAt: j.updatedAt, updatedBy: j.updatedBy }
  } catch {
    return { nac: 'watch', arpGuard: true, since: Date.now() }
  }
}

interface AgentGuard {
  nac: string; approved: number; bindings: number
  binds: { ip: string; mac: string; drop: boolean }[]
  spoofing: { ip: string; mac: string; first_at: number | null; last_at: number | null; frames: number; dropped: number }[]
  unapproved: { mac: string; ip: string; first_at: number | null; last_at: number | null; packets: number; dropped: number }[]
}

export async function GET(req: NextRequest) {
  const auth = await requirePerm(req, 'devices')
  if (auth.error) return auth.error
  const s = settings()
  let live: AgentGuard | null = null
  try {
    const r = await fetch(`${AGENT}/api/languard.json`, { cache: 'no-store', signal: AbortSignal.timeout(5000) })
    if (r.ok) live = await r.json()
  } catch {}
  const devices = readStore().devices
  const nameOf = (mac: string) => devices[mac]?.name ?? null
  // devices waiting for approval: registry entries not known, plus MACs the dataplane saw that the registry lacks
  const pending = new Map<string, { mac: string; ip: string | null; name: string | null; firstSeen: number | null; lastSeen: number | null; packets: number; dropped: number }>()
  for (const [mac, d] of Object.entries(devices)) {
    if (d.known) continue
    pending.set(mac, { mac, ip: d.ips?.[0] ?? null, name: d.name ?? null, firstSeen: d.firstSeen ?? null, lastSeen: d.lastSeen ?? null, packets: 0, dropped: 0 })
  }
  for (const u of live?.unapproved ?? []) {
    if (devices[u.mac]?.known) continue // approved since: the helper just hasn't run yet
    const p = pending.get(u.mac) ?? { mac: u.mac, ip: u.ip || null, name: nameOf(u.mac), firstSeen: u.first_at ? u.first_at * 1000 : null, lastSeen: null, packets: 0, dropped: 0 }
    p.packets = u.packets; p.dropped = u.dropped
    p.lastSeen = Math.max(p.lastSeen ?? 0, (u.last_at ?? 0) * 1000) || null
    if (!p.ip && u.ip) p.ip = u.ip
    pending.set(u.mac, p)
  }
  const bound = new Map((live?.binds ?? []).map((b) => [b.ip, b]))
  const spoofing = (live?.spoofing ?? []).map((x) => ({
    ...x, claimedBy: nameOf(x.mac), realOwner: bound.get(x.ip)?.mac ?? null, realName: nameOf(bound.get(x.ip)?.mac ?? ''), protectedAddr: !!bound.get(x.ip)?.drop,
  })).sort((a, b) => (b.last_at ?? 0) - (a.last_at ?? 0))
  return NextResponse.json({
    status: 'success', settings: s, agentReachable: !!live, liveMode: live?.nac ?? null,
    approved: Object.values(devices).filter((d) => d.known).length, bindings: live?.bindings ?? 0,
    pending: [...pending.values()].sort((a, b) => (b.lastSeen ?? 0) - (a.lastSeen ?? 0)), spoofing,
  })
}

export async function PUT(req: NextRequest) {
  const auth = await requirePerm(req, 'devices.guard')
  if (auth.error) return auth.error
  const b = await req.json().catch(() => null)
  const cur = settings()
  const nac: Mode = ['off', 'watch', 'enforce'].includes(b?.nac) ? b.nac : cur.nac
  const arpGuard = typeof b?.arpGuard === 'boolean' ? b.arpGuard : cur.arpGuard
  const approved = Object.values(readStore().devices).filter((d) => d.known).length
  if (nac === 'enforce' && approved < 2) {
    return NextResponse.json({ status: 'error', error: 'Approve your own devices first: enforcing now would cut off almost everything.' }, { status: 409 })
  }
  const by = auth.access.authDisabled ? '' : auth.access.username
  write({ ...cur, nac, arpGuard, updatedAt: Date.now(), updatedBy: by })
  const parts = [nac !== cur.nac && `new devices: ${nac}`, arpGuard !== cur.arpGuard && `ARP-spoofing guard ${arpGuard ? 'on' : 'off'}`].filter(Boolean)
  audit(req, { user: by, kind: auth.access.kind, category: 'languard', action: 'languard.update', summary: `LAN guard: ${parts.join(', ') || 'saved, no change'}`, detail: { nac, arpGuard } })
  return NextResponse.json({ status: 'success' })
}
