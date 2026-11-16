// Devices on the network: every MAC the box can see on its bridge, with the IPs
// it has used, the maker (IEEE OUI list), when it was first and last seen, a
// name and "known" flag you set, and whether it has ever been an attack source.
//
// Seen = in the box's neighbour table (`ip neigh`: hosts it exchanged IP with)
// or in the bridge's learned addresses (`bridge fdb`: every MAC that sent a
// frame through br0, even ones that never talked to the box). Read-only
// commands, no root needed. Observed every minute in the background and on
// every page load; the registry lives in devices.json next to the users file.
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { readFileSync, writeFileSync, renameSync, mkdirSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { subnets, sweep, names as lookupNames, fingerprint, type Probe, type Names } from './discover'
import { readHistory } from './history'

const run = promisify(execFile)
const PATH = '/usr/sbin:/usr/bin:/sbin:/bin'
const BRIDGES = (process.env.DASH_DEVICE_BRIDGES || 'br0').split(',').map((s) => s.trim()).filter(Boolean)
const OUI_FILE = process.env.DASH_OUI_FILE || '/usr/share/ieee-data/oui.csv'

export interface DeviceRec {
  name?: string; note?: string; known?: boolean
  firstSeen: number; lastSeen: number
  ips: string[] // most recent first, up to 6
  port?: string // bridge port it was learned on (vlan10 = WAN side, vlan20 = LAN side)
  probe?: Probe // open services, SSH banner, web title (see lib/discover.ts)
  names?: Names // names the device gives itself (mDNS, NetBIOS, UPnP)
  // from the Zyxel switch's address table (lib/history.ts)
  switchPort?: number
  vlans?: string[]
  switchAt?: number // last time the switch had it
  sources?: string[] // how it was seen: bridge, scan, switch
}
// A LAN address seen in traffic or attacks that no device record holds (yet).
export interface AddrRec { first: number; last: number; from: string[] }
// createdAt: when watching began; devices already there then are not "new"
interface Store { version: 1; createdAt?: number; historyAt?: number; devices: Record<string, DeviceRec>; addresses?: Record<string, AddrRec> }

function dataDir() {
  const users = process.env.DASH_USERS_FILE || '/home/test_server/xdp-sentinel-data/dash-users.json'
  return dirname(users)
}
export const devicesPath = () => process.env.DASH_DEVICES_FILE || join(dataDir(), 'devices.json')
function archivePath() {
  return process.env.DASH_ATTACKS_ARCHIVE || join(dataDir(), 'attacks-archive.json')
}

// ---- registry file (mtime-checked, so every route module sees the same) ----
let cache: { mtime: number; store: Store } | null = null
export function readStore(): Store {
  const file = devicesPath()
  let mtime = 0
  try { mtime = statSync(file).mtimeMs } catch {
    if (!cache || cache.mtime !== 0) cache = { mtime: 0, store: { version: 1, devices: {} } }
    return cache.store
  }
  if (cache && cache.mtime === mtime) return cache.store
  try {
    const j = JSON.parse(readFileSync(file, 'utf8'))
    cache = { mtime, store: {
      version: 1, createdAt: Number(j?.createdAt) || undefined, historyAt: Number(j?.historyAt) || undefined,
      devices: j && typeof j.devices === 'object' ? j.devices : {}, addresses: j && typeof j.addresses === 'object' ? j.addresses : {},
    } }
  } catch {
    cache = { mtime, store: { version: 1, devices: {} } }
  }
  return cache.store
}
export function writeStore(store: Store) {
  const file = devicesPath()
  mkdirSync(dirname(file), { recursive: true })
  writeFileSync(`${file}.tmp`, JSON.stringify(store, null, 1), { mode: 0o640 })
  renameSync(`${file}.tmp`, file)
  cache = null
}

// ---- maker lookup -----------------------------------------------------------
let oui: Map<string, string> | null = null
function vendorMap(): Map<string, string> {
  if (oui) return oui
  oui = new Map()
  try {
    for (const line of readFileSync(OUI_FILE, 'utf8').split('\n')) {
      // MA-L,F8C650,"Some Company, Inc.",Address…
      const m = /^MA-L,([0-9A-F]{6}),("([^"]*)"|[^,]*)/.exec(line)
      if (m) oui.set(m[1], (m[3] ?? m[2]).trim())
    }
  } catch {}
  return oui
}
// The second-lowest bit of the first byte set = a locally administered
// (randomised / "private") address: phones and laptops use these for privacy.
export const randomised = (mac: string) => (parseInt(mac.slice(0, 2), 16) & 2) === 2
export function vendorOf(mac: string): string | null {
  if (randomised(mac)) return null
  return vendorMap().get(mac.replace(/:/g, '').slice(0, 6).toUpperCase()) ?? null
}

// ---- observation -----------------------------------------------------------
interface Neigh { dst: string; dev: string; lladdr?: string; state?: string[] }
interface Fdb { mac: string; ifname?: string; master?: string; state?: string; flags?: string[] }
interface Link { ifname: string; address?: string }
async function jsonOf<T>(cmd: string, args: string[]): Promise<T[]> {
  try {
    const { stdout } = await run(cmd, args, { timeout: 5000, env: { ...process.env, PATH }, maxBuffer: 4 << 20, encoding: 'utf8' })
    const j = JSON.parse(stdout || '[]')
    return Array.isArray(j) ? j : []
  } catch {
    return []
  }
}
// seen = in the bridge's learned table (ages out after ~5 min) or actively
// talking to the box; a STALE neighbour entry alone only tells us its IP.
export interface Obs { ips: string[]; port?: string; reachable: boolean; seen: boolean }
export interface Snapshot { at: number; online: Map<string, Obs>; ipOwners: Map<string, string[]>; createdAt: number }

let last: Snapshot | null = null
let observing: Promise<Snapshot> | null = null
export function observe(fresh = false): Promise<Snapshot> {
  if (!fresh && last && Date.now() - last.at < 10_000) return Promise.resolve(last)
  if (observing) return observing
  observing = (async () => {
    const [neigh, fdb, links] = await Promise.all([
      jsonOf<Neigh>('ip', ['-j', 'neigh', 'show']),
      jsonOf<Fdb>('bridge', ['-j', 'fdb', 'show']),
      jsonOf<Link>('ip', ['-j', 'link', 'show']),
    ])
    const own = new Set(links.map((l) => (l.address ?? '').toLowerCase()))
    const online = new Map<string, Obs>()
    const ipOwners = new Map<string, string[]>()
    const valid = (mac?: string) => !!mac && /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(mac) && mac !== '00:00:00:00:00:00' && !own.has(mac) && !(parseInt(mac.slice(0, 2), 16) & 1)
    for (const f of fdb) {
      const mac = f.mac?.toLowerCase()
      if (!valid(mac) || f.state === 'permanent' || f.flags?.includes('self') || !f.master || !BRIDGES.includes(f.master)) continue
      const e = online.get(mac!) ?? { ips: [], reachable: false, seen: false }
      e.port = f.ifname
      e.seen = true
      online.set(mac!, e)
    }
    for (const n of neigh) {
      const mac = n.lladdr?.toLowerCase()
      if (!valid(mac) || !BRIDGES.includes(n.dev) || n.state?.includes('FAILED') || n.state?.includes('INCOMPLETE')) continue
      const e = online.get(mac!) ?? { ips: [], reachable: false, seen: false }
      if (!e.ips.includes(n.dst)) e.ips.push(n.dst)
      if (n.state?.some((s) => s === 'REACHABLE' || s === 'DELAY' || s === 'PROBE')) e.reachable = e.seen = true
      online.set(mac!, e)
      if (!n.dst.startsWith('fe80')) ipOwners.set(n.dst, [...new Set([...(ipOwners.get(n.dst) ?? []), mac!])])
    }
    // fold into the registry
    const now = Date.now()
    const store = readStore()
    const devices = { ...store.devices }
    const createdAt = store.createdAt ?? now
    let changed = !store.createdAt, added = false
    for (const [mac, o] of online) {
      const d = devices[mac]
      if (!d) {
        devices[mac] = { firstSeen: now, lastSeen: now, ips: o.ips.filter((ip) => !ip.startsWith('fe80')).slice(0, 6), ...(o.port ? { port: o.port } : {}) }
        changed = added = true
        continue
      }
      const ips = [...o.ips.filter((ip) => !ip.startsWith('fe80')), ...d.ips.filter((ip) => !o.ips.includes(ip))].slice(0, 6)
      const next = { ...d, lastSeen: o.seen ? now : d.lastSeen, ips, ...(o.port ? { port: o.port } : {}) }
      if (JSON.stringify(next.ips) !== JSON.stringify(d.ips) || next.port !== d.port) changed = true
      if (o.seen && now - d.lastSeen > 60_000) changed = true // keep lastSeen fresh to the minute
      devices[mac] = next
    }
    // write when something new appeared, and otherwise at most once a minute
    if (added || (changed && (!lastWrite || now - lastWrite > 60_000))) {
      // merge only what was observed into the newest file, so a name saved meanwhile survives
      const fresh = { ...readStore().devices }
      for (const [mac, d] of Object.entries(devices)) {
        const f = fresh[mac]
        fresh[mac] = f ? { ...f, firstSeen: Math.min(f.firstSeen, d.firstSeen), lastSeen: d.lastSeen, ips: d.ips, ...(d.port ? { port: d.port } : {}) } : d // f keeps name/probe/names
      }
      try { writeStore({ ...readStore(), createdAt: readStore().createdAt ?? createdAt, devices: fresh }); lastWrite = now } catch (e) { console.error('[devices] could not save', e) }
    } else {
      cache = cache ? { ...cache, store: { ...cache.store, createdAt, devices } } : cache
    }
    last = { at: now, online, ipOwners, createdAt }
    return last
  })().finally(() => { observing = null })
  return observing
}
let lastWrite = 0

// ---- active discovery (lib/discover.ts) ----------------------------------------
// Every 10 minutes: sweep the subnet so every switched-on device answers, ask
// for names, and check the services of devices not checked in the last day.
const SCAN_EVERY = 10 * 60_000
const PROBE_EVERY = 24 * 3600_000
export interface ScanStatus { at: number | null; running: boolean; found: number; took: number; error?: string }
let scan: ScanStatus = { at: null, running: false, found: 0, took: 0 }
let scanning: Promise<ScanStatus> | null = null
export const scanStatus = () => scan

export function discover(force = false): Promise<ScanStatus> {
  if (scanning) return scanning
  scanning = (async () => {
    const t0 = Date.now()
    scan = { ...scan, running: true }
    try {
      const nets = await subnets(BRIDGES)
      for (const n of nets) await sweep(n.hosts)
      const snap = await observe(true)
      // the IPv4 addresses that answered, and whose they are
      const owner = new Map<string, string>()
      for (const [mac, o] of snap.online) if (o.seen) for (const ip of o.ips) if (!ip.includes(':')) owner.set(ip, mac)
      const self = nets[0]?.self
      const named = self && owner.size ? await lookupNames(self, [...owner.keys()]) : new Map<string, Names>()
      // services: new devices, changed addresses, or a day since the last check
      const store = readStore()
      const due = [...owner].filter(([ip, mac]) => {
        const pr = store.devices[mac]?.probe
        return force || !pr || pr.ip !== ip || Date.now() - pr.at > PROBE_EVERY
      })
      const probes = new Map<string, Probe>()
      for (let i = 0; i < due.length; i += 4) {
        const batch = due.slice(i, i + 4)
        const res = await Promise.all(batch.map(([ip]) => fingerprint(ip).catch(() => null)))
        res.forEach((r, k) => { if (r) probes.set(batch[k][1], r) })
      }
      // save into the newest registry
      const fresh = { ...readStore().devices }
      for (const [ip, mac] of owner) {
        const d = fresh[mac]
        if (!d) continue
        const nm = named.get(ip)
        fresh[mac] = { ...d, ...(probes.get(mac) ? { probe: probes.get(mac) } : {}), ...(nm ? { names: { ...d.names, ...nm } } : {}) }
      }
      writeStore({ ...readStore(), createdAt: readStore().createdAt ?? snap.createdAt, devices: fresh })
      scan = { at: Date.now(), running: false, found: owner.size, took: Date.now() - t0 }
    } catch (e) {
      scan = { ...scan, at: Date.now(), running: false, error: e instanceof Error ? e.message : String(e) }
    }
    return scan
  })().finally(() => { scanning = null })
  return scanning
}

// ---- history: the switch's and the talker tap's memory (lib/history.ts) ------------
let importing: Promise<number> | null = null
const LAN = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/
export function importHistory(): Promise<number> {
  if (importing) return importing
  importing = (async () => {
    const before = readStore()
    // the first run reads the whole retention; later runs the last hour onwards
    const since = before.historyAt ? Math.floor(before.historyAt / 1000) - 3600 : undefined
    const [{ macs, ips }, links] = await Promise.all([readHistory(since), jsonOf<Link>('ip', ['-j', 'link', 'show'])])
    const own = new Set(links.map((l) => (l.address ?? '').toLowerCase()))
    const store = readStore()
    const devices = { ...store.devices }
    let added = 0
    for (const [mac, h] of macs) {
      if (own.has(mac)) continue // the box itself
      const d = devices[mac]
      const vlans = [...new Set([...(d?.vlans ?? []), ...h.vlans])].sort()
      const sources = [...new Set([...(d?.sources ?? []), 'switch'])]
      if (!d) added += 1
      devices[mac] = {
        ...(d ?? { ips: [] }),
        firstSeen: Math.min(d?.firstSeen ?? h.first, h.first),
        lastSeen: Math.max(d?.lastSeen ?? h.last, h.last),
        switchAt: Math.max(d?.switchAt ?? 0, h.last),
        vlans, sources,
        ...(h.port ? { switchPort: h.port } : {}),
      }
    }
    // addresses: traffic history plus LAN attack sources from the archive
    const addresses = { ...(store.addresses ?? {}) }
    const addAddr = (ip: string, first: number, last: number, from: string) => {
      if (!LAN.test(ip)) return
      const a = addresses[ip]
      addresses[ip] = a
        ? { first: Math.min(a.first, first), last: Math.max(a.last, last), from: [...new Set([...a.from, from])] }
        : { first, last, from: [from] }
    }
    for (const [ip, h] of ips) addAddr(ip, h.first, h.last, 'traffic')
    for (const [ip, h] of attacksBySource()) addAddr(ip, h.last, h.last, 'attack')
    writeStore({ ...store, createdAt: store.createdAt ?? Date.now(), historyAt: Date.now(), devices, addresses })
    return added
  })().finally(() => { importing = null })
  return importing
}

// keep watching in the background while the dashboard runs
let timer: ReturnType<typeof setInterval> | null = null
export function startWatching() {
  if (timer) return
  timer = setInterval(() => { void observe().catch(() => {}) }, 60_000)
  timer.unref?.()
  const scanTimer = setInterval(() => { void discover().catch(() => {}) }, SCAN_EVERY)
  scanTimer.unref?.()
  setTimeout(() => { void discover().catch(() => {}) }, 5_000).unref?.()
  // the switch's memory: first the whole retention, then every 10 minutes
  setTimeout(() => { void importHistory().catch((e) => console.error('[devices] history import failed', e)) }, 2_000).unref?.()
  const histTimer = setInterval(() => { void importHistory().catch(() => {}) }, SCAN_EVERY)
  histTimer.unref?.()
}

// ---- attacks each address took part in (from the permanent archive) ---------
let attackCache: { mtime: number; by: Map<string, { count: number; last: number }> } | null = null
export function attacksBySource(): Map<string, { count: number; last: number }> {
  const file = archivePath()
  let mtime = 0
  try { mtime = statSync(file).mtimeMs } catch { return new Map() }
  if (attackCache?.mtime === mtime) return attackCache.by
  const by = new Map<string, { count: number; last: number }>()
  try {
    const j = JSON.parse(readFileSync(file, 'utf8'))
    for (const ep of Object.values(j.episodes ?? {}) as { end?: number; attackers?: { ip: string }[] }[]) {
      for (const ip of new Set((ep.attackers ?? []).map((a) => a.ip))) {
        const e = by.get(ip) ?? { count: 0, last: 0 }
        e.count += 1
        e.last = Math.max(e.last, Number(ep.end) || 0)
        by.set(ip, e)
      }
    }
  } catch {}
  attackCache = { mtime, by }
  return by
}
