// Honeypot addresses: unused LAN addresses the firewall pretends to own. Any
// device that talks to one is scanning the network or infected (nothing
// legitimate knows the address).
//
// The page writes the wanted addresses to honeypot.json; the root helper
// xs-honeypot-apply (run by xdp-sentinel-honeypot.path) loads them into the XDP
// maps. What the dataplane recorded comes from the agent's /api/honeypot.json.
import { readFileSync, writeFileSync, renameSync, mkdirSync, statSync, openSync, readSync, closeSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { readStore } from './devices'

const run = promisify(execFile)
const PATH = '/usr/sbin:/usr/bin:/sbin:/bin'
const AGENT = process.env.AGENT_URL || 'http://localhost:9464'
export const MAX_ADDRESSES = 16

export interface Wanted { ip: string; block: boolean; interactive?: boolean; note?: string; addedBy?: string; addedAt?: number }
export interface WantedDoc { addresses: Wanted[]; reset?: string[]; updatedAt?: number; updatedBy?: string }
export interface LiveAddr { ip: string; mac: string; block: boolean; conflict_at: number | null }
export interface LiveSource {
  ip: string; mac: string; first_at: number | null; last_at: number | null; packets: number; arps: number
  last_dst: string; last_dport: number; last_proto: number; blocked: boolean
}
export interface LiveDoc { now: number; active: number; interfaces: string[]; addresses: LiveAddr[]; sources: LiveSource[] }

function dataDir() {
  const users = process.env.DASH_USERS_FILE || '/home/test_server/xdp-sentinel-data/dash-users.json'
  return dirname(users)
}
const wantedPath = () => join(dataDir(), 'honeypot.json')

export function readWanted(): WantedDoc {
  try {
    const j = JSON.parse(readFileSync(wantedPath(), 'utf8'))
    return { addresses: Array.isArray(j?.addresses) ? j.addresses : [], updatedAt: j?.updatedAt, updatedBy: j?.updatedBy }
  } catch {
    return { addresses: [] }
  }
}

export function writeWanted(doc: WantedDoc) {
  const file = wantedPath()
  mkdirSync(dirname(file), { recursive: true })
  writeFileSync(`${file}.tmp`, JSON.stringify(doc, null, 1), { mode: 0o644 })
  renameSync(`${file}.tmp`, file)
}

// Logins tried on the interactive decoys (xs-fakelogin), newest first.
export interface Attempt { at: number; service: 'ssh' | 'telnet' | 'web'; src: string; src_port: number; decoy: string; username?: string; password?: string | null; client?: string; agent?: string; path?: string; key?: string; note?: string }
const ATTEMPTS = process.env.DASH_FAKELOGIN_LOG || '/var/lib/xs-fakelogin/attempts.jsonl'
export function readAttempts(max = 300): Attempt[] {
  try {
    const st = statSync(ATTEMPTS)
    const len = Math.min(st.size, 512 * 1024)
    const fd = openSync(ATTEMPTS, 'r')
    const buf = Buffer.alloc(len)
    readSync(fd, buf, 0, len, st.size - len)
    closeSync(fd)
    const lines = buf.toString('utf8').split('\n').filter(Boolean)
    if (st.size > len) lines.shift() // first line may be cut
    const out: Attempt[] = []
    for (const l of lines.reverse()) {
      try { out.push(JSON.parse(l)) } catch {}
      if (out.length >= max) break
    }
    return out
  } catch {
    return []
  }
}

export async function readLive(): Promise<LiveDoc | null> {
  try {
    const r = await fetch(`${AGENT}/api/honeypot.json`, { cache: 'no-store', signal: AbortSignal.timeout(5000) })
    if (!r.ok) return null
    return (await r.json()) as LiveDoc
  } catch {
    return null
  }
}

const ipNum = (ip: string) => ip.split('.').reduce((n, x) => n * 256 + Number(x), 0)
const ipStr = (n: number) => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.')
export const isIPv4 = (s: string) => /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(s)

// The box's LAN subnet (from br0) and every address known to be in use there.
export async function lanInfo(): Promise<{ net: string; prefix: number; self: string; gateway: string | null; used: Set<string> } | null> {
  const env = { ...process.env, PATH }
  try {
    const { stdout } = await run('ip', ['-j', '-4', 'addr', 'show', 'dev', process.env.DASH_DEVICE_BRIDGES?.split(',')[0] || 'br0'], { env, timeout: 4000 })
    const a = JSON.parse(stdout)[0]?.addr_info?.find((x: { family: string }) => x.family === 'inet')
    if (!a) return null
    const prefix = Number(a.prefixlen)
    const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0
    const net = ipStr((ipNum(a.local) & mask) >>> 0)
    const used = new Set<string>([a.local])
    let gateway: string | null = null
    try {
      const r = JSON.parse((await run('ip', ['-j', '-4', 'route', 'show', 'default'], { env, timeout: 4000 })).stdout)
      for (const x of r) if (x.gateway) { used.add(x.gateway); gateway ??= x.gateway }
    } catch {}
    try {
      const n = JSON.parse((await run('ip', ['-j', 'neigh', 'show'], { env, timeout: 4000 })).stdout)
      for (const x of n) if (x.lladdr && !String(x.lladdr).startsWith('02:58:53:48:50:') && !(x.state ?? []).includes('FAILED')) used.add(x.dst)
    } catch {}
    for (const d of Object.values(readStore().devices)) for (const ip of d.ips ?? []) used.add(ip)
    return { net, prefix, self: a.local, gateway, used }
  } catch {
    return null
  }
}

export function inSubnet(ip: string, net: string, prefix: number) {
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0
  return ((ipNum(ip) & mask) >>> 0) === ipNum(net)
}

// A few free addresses near the top of the range (DHCP pools usually sit lower).
export function suggest(info: { net: string; prefix: number; used: Set<string> }, taken: Set<string>, n = 6): string[] {
  const base = ipNum(info.net)
  const size = 2 ** (32 - info.prefix)
  const out: string[] = []
  for (let k = size - 6; k > 1 && out.length < n; k -= 7) {
    const ip = ipStr(base + k)
    if (!info.used.has(ip) && !taken.has(ip)) out.push(ip)
  }
  return out
}
