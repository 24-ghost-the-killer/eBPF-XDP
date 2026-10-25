// Protection plan: the desired default-deny state the dashboard edits. A root
// systemd job (scripts/xs-protect-apply) watches the plan file and reconciles
// the eBPF maps with sentinelctl. Node-only (reads/writes a file).
//
// The plan is NOT the live state — live comes from the agent's /api/services.json.
// Source file: $DASH_PROTECT_PLAN (default /home/test_server/xdp-sentinel-data/protect-plan.json).
import { readFileSync, writeFileSync, mkdirSync, chmodSync } from 'node:fs'
import { dirname } from 'node:path'

export type Proto = 'tcp' | 'udp' | 'icmp'
export interface Svc { proto: Proto; port: number }
export interface PlanHost { iface: string; ip: string; services: Svc[] }
export interface Plan { version: number; hosts: PlanHost[] }

const DEFAULT_FILE = '/home/test_server/xdp-sentinel-data/protect-plan.json'
const IFACE_RE = /^[a-z0-9._-]{1,15}$/i
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

// The appliance's own management addresses. These MAY be protected from the
// dashboard, but a "lifeline" of services (SSH + the dashboard) is always forced
// onto them so default-deny can never blackhole your SSH or the dashboard itself.
// Extend the set with DASH_PROTECT_MANAGEMENT (comma-separated). The box-side
// reconcile job additionally detects the live sshd port(s) as a backstop.
const BUILTIN_MGMT = ['192.168.1.193', '10.55.12.193']
export function managementIps(): string[] {
  const extra = (process.env.DASH_PROTECT_MANAGEMENT || '').split(',').map((s) => s.trim()).filter(Boolean)
  return [...new Set([...BUILTIN_MGMT, ...extra])]
}

// Services always kept open on a protected management IP. Override with
// DASH_PROTECT_LIFELINE="tcp/22,tcp/3000".
export function lifelineServices(): Svc[] {
  const raw = process.env.DASH_PROTECT_LIFELINE || 'tcp/22,tcp/3000'
  const out: Svc[] = []
  for (const tok of raw.split(',').map((s) => s.trim()).filter(Boolean)) {
    const [p, portStr] = tok.split('/')
    const proto = (p || '').toLowerCase()
    if (proto !== 'tcp' && proto !== 'udp' && proto !== 'icmp') continue
    const port = proto === 'icmp' ? 0 : Number(portStr)
    if (!Number.isInteger(port) || port < 0 || port > 65535) continue
    out.push({ proto: proto as Proto, port })
  }
  return out
}

// The single interface new hosts are protected on. XDP enforces default-deny at
// INGRESS, so a host must be protected on the interface its inbound requests
// arrive on — on this inline bridge that is the WAN/router side (vlan10), even
// for a host that physically sits on the LAN side (vlan20). The dashboard no
// longer asks; override with DASH_PROTECT_IFACE if the topology changes.
export function ingressIface(): string {
  const v = (process.env.DASH_PROTECT_IFACE || 'vlan10').trim()
  return IFACE_RE.test(v) ? v : 'vlan10'
}

function planPath(): string {
  return process.env.DASH_PROTECT_PLAN || DEFAULT_FILE
}

// ---- Lockdown kill-switch ------------------------------------------------
// A desired-state control file the dashboard writes; a root job on the box
// applies it to the dataplane (sentinelctl config --lockdown) and enforces the
// auto-revert timer. When on, every IPv4 packet on a locked interface bound for
// an INTERNAL (RFC1918) destination that is not a protected host is dropped;
// traffic to public destinations always passes, so the Twingate connector's link
// to its relays is never cut and arming can't strand the operator. Still always
// carries an expiry as a backstop (the box-side timer runs locally).
export interface Lockdown { enabled: boolean; ifaces: string[]; expires_at: number }
const LOCKDOWN_DEFAULT_FILE = '/home/test_server/xdp-sentinel-data/lockdown.json'
export const LOCKDOWN_MAX_MINUTES = 1440

function lockdownPath(): string {
  return process.env.DASH_LOCKDOWN_FILE || LOCKDOWN_DEFAULT_FILE
}

// Static interfaces lockdown applies to = the inline-bridge XDP dataplane. The
// Twingate connector veth is ALSO locked ("everything through XDP"), but its name
// is regenerated on every container restart, so the box job (xs-lockdown-apply)
// resolves and appends it at apply time rather than it being listed here. Lockdown
// only drops internal-bound traffic, so locking the veth enforces the plan on
// Twingate yet never cuts the connector's link to its public relays.
export function lockdownIfaces(): string[] {
  const raw = (process.env.DASH_LOCKDOWN_IFACES || 'vlan10,vlan20').split(/[,\s]+/).map((s) => s.trim())
  const out = raw.filter((s) => IFACE_RE.test(s))
  return out.length ? [...new Set(out)] : ['vlan10', 'vlan20']
}

export function loadLockdown(): Lockdown {
  try {
    const d = JSON.parse(readFileSync(lockdownPath(), 'utf8'))
    const ifaces = Array.isArray(d?.ifaces) ? d.ifaces.map(String).filter((s: string) => IFACE_RE.test(s)) : []
    return { enabled: !!d?.enabled, ifaces: ifaces.length ? ifaces : lockdownIfaces(), expires_at: Number(d?.expires_at) || 0 }
  } catch {
    return { enabled: false, ifaces: lockdownIfaces(), expires_at: 0 }
  }
}

export function saveLockdown(l: Lockdown): void {
  const file = lockdownPath()
  try {
    mkdirSync(dirname(file), { recursive: true })
    writeFileSync(file, JSON.stringify(l, null, 2) + '\n', { mode: 0o644 })
    try { chmodSync(file, 0o644) } catch {}
  } catch (e: any) {
    throw new PlanError(`could not write ${file}: ${e?.code || e?.message || 'error'} (must be writable by the dashboard user)`, 500)
  }
}

export class PlanError extends Error {
  status: number
  constructor(message: string, status = 400) { super(message); this.status = status }
}

function validIp(ip: string): boolean {
  const m = IPV4_RE.exec(ip)
  if (!m) return false
  return m.slice(1).every((o) => { const n = Number(o); return n >= 0 && n <= 255 })
}

export function loadPlan(): Plan {
  try {
    const d = JSON.parse(readFileSync(planPath(), 'utf8'))
    const hosts: PlanHost[] = Array.isArray(d?.hosts) ? d.hosts : []
    return { version: 1, hosts }
  } catch {
    return { version: 1, hosts: [] }
  }
}

// Validate + normalize an incoming plan, enforcing the management-IP block.
export function normalizePlan(input: unknown): Plan {
  const hostsIn = (input as any)?.hosts
  if (!Array.isArray(hostsIn)) throw new PlanError('plan must have a hosts array')
  const mgmt = new Set(managementIps())
  const lifeline = lifelineServices()
  const seen = new Set<string>()
  const hosts: PlanHost[] = []
  for (const h of hostsIn) {
    const iface = String(h?.iface || '').trim()
    const ip = String(h?.ip || '').trim()
    if (!IFACE_RE.test(iface)) throw new PlanError(`invalid interface "${iface}"`)
    if (!validIp(ip)) throw new PlanError(`invalid IPv4 address "${ip}"`)
    const key = `${iface}|${ip}`
    if (seen.has(key)) throw new PlanError(`duplicate host ${ip} on ${iface}`)
    seen.add(key)
    const svcSeen = new Set<string>()
    const services: Svc[] = []
    const addSvc = (proto: Proto, port: number) => {
      const sk = `${proto}/${port}`
      if (svcSeen.has(sk)) return
      svcSeen.add(sk)
      services.push({ proto, port })
    }
    for (const s of Array.isArray(h?.services) ? h.services : []) {
      const proto = String(s?.proto || '').toLowerCase()
      if (proto !== 'tcp' && proto !== 'udp' && proto !== 'icmp') throw new PlanError(`invalid protocol "${proto}" on ${ip}`)
      let port = Number(s?.port ?? 0)
      if (proto === 'icmp') port = 0
      if (!Number.isInteger(port) || port < 0 || port > 65535) throw new PlanError(`invalid port ${s?.port} on ${ip}`)
      addSvc(proto as Proto, port)
    }
    // A management IP always keeps its lifeline open, so default-deny can never
    // blackhole SSH or the dashboard.
    if (mgmt.has(ip)) for (const l of lifeline) addSvc(l.proto, l.port)
    hosts.push({ iface, ip, services })
  }
  return { version: 1, hosts }
}

export function savePlan(plan: Plan): void {
  const file = planPath()
  try {
    mkdirSync(dirname(file), { recursive: true })
    writeFileSync(file, JSON.stringify(plan, null, 2) + '\n', { mode: 0o644 })
    try { chmodSync(file, 0o644) } catch {}
  } catch (e: any) {
    throw new PlanError(`could not write ${file}: ${e?.code || e?.message || 'error'} (must be writable by the dashboard user)`, 500)
  }
}
