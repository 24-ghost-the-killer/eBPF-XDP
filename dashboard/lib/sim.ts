// Attack simulator: the page writes a request file, xdp-sentinel-simulate.path
// runs /usr/local/bin/xs-simulate as root, which injects synthetic attack
// packets into the live XDP program (BPF_PROG_RUN, nothing on the wire) and
// writes its progress to simulate.status.json. Finished runs go to
// simulate.history.json, which the attack list uses to label the attacks a
// simulation caused (they then stay out of the totals, like false alarms).
import { readFileSync, statSync, writeFileSync, renameSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { randomUUID } from 'node:crypto'

// Must match SCENARIOS in scripts/xs-simulate (the script refuses anything else).
export const SCENARIOS: { id: string; label: string; what: string; group: string }[] = [
  { id: 'tcp-syn', label: 'SYN flood', group: 'TCP', what: 'Millions of connection requests that are never completed, to fill up a server’s connection table.' },
  { id: 'tcp-ack', label: 'ACK flood', group: 'TCP', what: 'Packets that pretend to belong to connections that do not exist.' },
  { id: 'tcp-xmas', label: 'XMAS flood', group: 'TCP', what: 'TCP packets with impossible flag combinations (every flag “lit up”).' },
  { id: 'udp-std', label: 'UDP flood', group: 'UDP', what: 'A torrent of UDP packets to random ports.' },
  { id: 'udp-large', label: 'UDP flood, large packets', group: 'UDP', what: 'Big UDP packets that try to fill the line rather than the CPU.' },
  { id: 'evasion-spoofed-udp', label: 'Spoofed-source UDP flood', group: 'UDP', what: 'Every packet claims a different random sender, so blocking one address does nothing.' },
  { id: 'icmp-echo', label: 'Ping flood', group: 'Other', what: 'Endless ICMP echo requests (pings).' },
  { id: 'ip-frag', label: 'Fragment flood', group: 'Other', what: 'Broken-up IP packets that are expensive to put back together.' },
  { id: 'ip-malformed', label: 'Malformed packets', group: 'Other', what: 'Packets with headers that break the rules.' },
  { id: 'ipv6-icmpv6', label: 'ICMPv6 flood', group: 'Other', what: 'A ping-style flood over IPv6.' },
  { id: 'refl-dns', label: 'DNS amplification', group: 'Amplification', what: 'Huge DNS answers to questions the victim never asked: open resolvers are tricked into flooding it.' },
  { id: 'refl-ntp', label: 'NTP amplification', group: 'Amplification', what: 'Time servers tricked into sending big “monlist” replies to the victim.' },
  { id: 'refl-memcached', label: 'Memcached amplification', group: 'Amplification', what: 'The biggest amplifier known: a tiny request, a reply up to 50,000× larger.' },
  { id: 'multi-carpet', label: 'Carpet bombing', group: 'Combined', what: 'Several attack types at once, spread over many targets.' },
]
export const SCENARIO_IDS = SCENARIOS.map((s) => s.id)
export const MIN_S = 5
export const MAX_S = 60

export interface SimPoint { t: number; pps: number; threat: number; risk: number; dropped: number }
export interface SimStatus {
  state: 'running' | 'done' | 'stopped' | 'error'
  id: string; scenario: string; label: string; by: string; iface: string; duration: number
  player?: string | null; game?: boolean
  started_at: number; attack_ends_at: number; ended_at: number | null
  phase: 'attack' | 'recovery' | 'finished'
  sent: number; target_pps: number | null; sources: string; victim: string
  live: { threat?: number; risk?: number; pps?: number; types?: string[]; flags?: string[] }
  timeline: SimPoint[]
  detected_at: number | null; classified_at: number | null; mitigated_at: number | null; recovered_at: number | null
  types: string[]; flags: string[]; peak_threat: number; peak_pps: number; dropped: number; passed: number
  error: string | null
}
export type SimRun = Pick<SimStatus, 'id' | 'scenario' | 'label' | 'by' | 'player' | 'game' | 'duration' | 'started_at' | 'attack_ends_at' | 'ended_at' | 'state' | 'sent' | 'detected_at' | 'classified_at' | 'mitigated_at' | 'recovered_at' | 'types' | 'flags' | 'peak_threat' | 'peak_pps' | 'dropped'>

function dataDir() {
  const users = process.env.DASH_USERS_FILE || '/home/test_server/xdp-sentinel-data/dash-users.json'
  return dirname(users)
}
const reqPath = () => join(dataDir(), 'simulate.json')
const statusPath = () => join(dataDir(), 'simulate.status.json')
const historyPath = () => join(dataDir(), 'simulate.history.json')

function readJson<T>(file: string): T | null {
  try { return JSON.parse(readFileSync(file, 'utf8')) as T } catch { return null }
}

export function readStatus(): SimStatus | null {
  return readJson<SimStatus>(statusPath())
}
export function readRequest(): { id?: string; action?: string; at?: number } | null {
  return readJson(reqPath())
}

let hist: { mtime: number; runs: SimRun[] } | null = null
export function readHistory(): SimRun[] {
  let mtime = 0
  try { mtime = statSync(historyPath()).mtimeMs } catch { return [] }
  if (hist && hist.mtime === mtime) return hist.runs
  const j = readJson<SimRun[]>(historyPath())
  hist = { mtime, runs: Array.isArray(j) ? j : [] }
  return hist.runs
}

export function writeRequest(r: { action: 'start'; scenario: string; duration: number; by: string; player?: string; game?: boolean } | { action: 'stop'; id: string; by: string }): string {
  const id = r.action === 'start' ? randomUUID() : r.id
  const file = reqPath()
  mkdirSync(dirname(file), { recursive: true })
  writeFileSync(`${file}.tmp`, JSON.stringify({ ...r, id, at: Date.now() / 1000 }), { mode: 0o644 })
  renameSync(`${file}.tmp`, file)
  return id
}

// The simulation (if any) that explains an attack between start and end
// (seconds): it ran then, so the "attack" was this simulation.
export function simulationAt(startSec: number, endSec: number): SimRun | null {
  for (const r of readHistory()) {
    const s = Number(r.started_at) || 0
    const e = (Number(r.attack_ends_at) || Number(r.ended_at) || s) + 30
    if (startSec <= e && endSec >= s - 5) return r
  }
  const st = readStatus()
  if (st && st.state === 'running' && startSec >= st.started_at - 5) return st
  return null
}
