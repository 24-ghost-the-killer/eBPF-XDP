// Active discovery, so the Devices page lists EVERY device on the LAN — not
// only those that happened to talk to the box — and says what each one is.
//
//  1. Sweep: a 1-byte UDP packet to every address of the bridge's subnet
//     (port 9, "discard"). The kernel must ARP for each one first, so every
//     device that is switched on answers and lands in the neighbour table,
//     whether or not it accepts the packet itself. No root needed.
//  2. Names: mDNS reverse lookups (Apple, Linux/avahi, printers, Pis),
//     LLMNR reverse lookups and NetBIOS node status (Windows), and an
//     SSDP/UPnP search (TVs, routers, NAS: their description XML has a
//     friendly name and model). The service check below adds the host
//     names in each HTTPS certificate.
//  3. Services: a connect-only check of a few well-known ports, the SSH
//     banner (gives the OS) and the web page title / Server header. Once a
//     day per device (or when its address changes); never sends credentials.
//
// Multicast is pinned to the bridge address: the box's default route is the
// school WiFi, so unpinned queries would leave on the wrong interface.
import dgram from 'node:dgram'
import net from 'node:net'
import http from 'node:http'
import https from 'node:https'
import tls from 'node:tls'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const run = promisify(execFile)
const PATH = '/usr/sbin:/usr/bin:/sbin:/bin'
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

export const PROBE_PORTS = [22, 53, 80, 443, 445, 554, 631, 3389, 5000, 7000, 8006, 8008, 8080, 8443, 9100, 62078]
const WEB = new Set([80, 443, 8006, 8080, 8443])
const TLS = new Set([443, 8006, 8443])

export interface Probe {
  at: number
  ip: string
  ports: number[]
  ssh?: string
  web?: { port: number; tls: boolean; status?: number; title?: string; server?: string }[]
  certNames?: string[] // host names in the HTTPS certificate(s)
}
export interface Names { mdns?: string; netbios?: string; llmnr?: string; upnp?: { name?: string; model?: string; maker?: string } }

// ---- the bridge's IPv4 subnet(s) --------------------------------------------
export async function subnets(bridges: string[]): Promise<{ self: string; prefix: number; hosts: string[] }[]> {
  const out: { self: string; prefix: number; hosts: string[] }[] = []
  for (const dev of bridges) {
    try {
      const { stdout } = await run('ip', ['-j', '-4', 'addr', 'show', 'dev', dev], { timeout: 4000, env: { ...process.env, PATH }, encoding: 'utf8' })
      for (const l of JSON.parse(stdout || '[]')) {
        for (const a of l.addr_info ?? []) {
          const prefix = Number(a.prefixlen)
          if (a.family !== 'inet' || !(prefix >= 22 && prefix <= 30)) continue // at most 1022 hosts
          const ip = String(a.local).split('.').map(Number)
          const n = ((ip[0] << 24) | (ip[1] << 16) | (ip[2] << 8) | ip[3]) >>> 0
          const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0
          const netw = (n & mask) >>> 0
          const size = 2 ** (32 - prefix)
          const hosts: string[] = []
          for (let k = 1; k < size - 1; k++) {
            const h = (netw + k) >>> 0
            const s = `${h >>> 24}.${(h >>> 16) & 255}.${(h >>> 8) & 255}.${h & 255}`
            if (s !== a.local) hosts.push(s)
          }
          out.push({ self: a.local, prefix, hosts })
        }
      }
    } catch {}
  }
  return out
}

// ---- 1. sweep -----------------------------------------------------------------
export async function sweep(hosts: string[]): Promise<void> {
  const s = dgram.createSocket('udp4')
  s.on('error', () => {})
  await new Promise<void>((r) => s.bind(0, () => r()))
  const one = Buffer.alloc(1)
  for (let i = 0; i < hosts.length; i++) {
    s.send(one, 9, hosts[i], () => {})
    if (i % 25 === 24) await sleep(100) // ~250 addresses a second: gentle on every device
  }
  await sleep(2500) // ARP replies
  s.close()
}

// ---- 2. names -------------------------------------------------------------------
function encodeName(name: string) {
  const parts: Buffer[] = []
  for (const l of name.split('.')) parts.push(Buffer.from([l.length]), Buffer.from(l))
  parts.push(Buffer.from([0]))
  return Buffer.concat(parts)
}
const ptrQuery = (ip: string) => Buffer.concat([Buffer.from([0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]), encodeName(`${ip.split('.').reverse().join('.')}.in-addr.arpa`), Buffer.from([0, 12, 0, 1])])
function readName(buf: Buffer, off: number): [string, number] {
  const out: string[] = []
  let end = off, jumped = false
  for (let i = 0; i < 64 && off < buf.length; i++) {
    const len = buf[off]
    if (len === 0) { if (!jumped) end = off + 1; break }
    if ((len & 0xc0) === 0xc0) { if (!jumped) end = off + 2; off = ((len & 0x3f) << 8) | buf[off + 1]; jumped = true; continue }
    out.push(buf.subarray(off + 1, off + 1 + len).toString('utf8'))
    off += len + 1
  }
  return [out.join('.'), end]
}
function parsePtr(buf: Buffer): string | null {
  try {
    const qd = buf.readUInt16BE(4), an = buf.readUInt16BE(6)
    let off = 12
    for (let i = 0; i < qd; i++) off = readName(buf, off)[1] + 4
    for (let i = 0; i < an; i++) {
      off = readName(buf, off)[1]
      const type = buf.readUInt16BE(off), len = buf.readUInt16BE(off + 8)
      off += 10
      if (type === 12) return readName(buf, off)[0].replace(/\.local$/i, '') || null
      off += len
    }
  } catch {}
  return null
}
// NetBIOS node status for "*"
const NB_STATUS = Buffer.from('a2480000000100000000000020434b4141414141414141414141414141414141414141414141414141414141410000210001', 'hex')
function parseNb(buf: Buffer): string | null {
  try {
    let off = 56
    const n = buf[off++]
    for (let i = 0; i < n; i++, off += 18) {
      const suffix = buf[off + 15], group = buf.readUInt16BE(off + 16) & 0x8000
      if (suffix === 0 && !group) return buf.subarray(off, off + 15).toString('latin1').trim() || null
    }
  } catch {}
  return null
}
const xml = (s: string, tag: string) => (new RegExp(`<${tag}>([^<]{1,120})</${tag}>`, 'i').exec(s)?.[1] ?? '').trim() || undefined

export async function names(self: string, ips: string[]): Promise<Map<string, Names>> {
  const res = new Map<string, Names>()
  const put = (ip: string, n: Names) => res.set(ip, { ...res.get(ip), ...n })
  const mk = () => { const s = dgram.createSocket('udp4'); s.on('error', () => {}); return s }
  const mdns = mk(), nb = mk(), ssdp = mk(), llmnr = mk()
  const locations = new Map<string, string>()
  mdns.on('message', (m, r) => { const n = parsePtr(m); if (n) put(r.address, { mdns: n }) })
  nb.on('message', (m, r) => { const n = parseNb(m); if (n) put(r.address, { netbios: n }) })
  // LLMNR answers carry the queried address in the question, so match on that, not the sender
  llmnr.on('message', (m) => {
    try {
      const n = parsePtr(m)
      const q = readName(m, 12)[0].replace(/\.in-addr\.arpa$/i, '').split('.').reverse().join('.')
      if (n && wanted.has(q)) put(q, { llmnr: n })
    } catch {}
  })
  ssdp.on('message', (m, r) => { const loc = /^location:\s*(\S+)/im.exec(m.toString())?.[1]; if (loc && !locations.has(r.address)) locations.set(r.address, loc) })
  const wanted = new Set(ips)
  await Promise.all([mdns, nb, ssdp, llmnr].map((s) => new Promise<void>((r) => s.bind(0, () => r()))))
  for (const s of [mdns, ssdp, llmnr]) { try { s.setMulticastInterface(self); s.setMulticastTTL(1) } catch {} }
  for (const ip of ips) {
    mdns.send(ptrQuery(ip), 5353, '224.0.0.251', () => {}) // "legacy unicast" query: answered to our port
    nb.send(NB_STATUS, 137, ip, () => {})
    llmnr.send(ptrQuery(ip), 5355, ip, () => {}) // Windows answers LLMNR reverse lookups
    await sleep(15)
  }
  ssdp.send(Buffer.from('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: upnp:rootdevice\r\n\r\n'), 1900, '239.255.255.250', () => {})
  await sleep(3000)
  for (const s of [mdns, nb, ssdp, llmnr]) s.close()
  // UPnP description XML: friendly name, model, maker (only from devices on our LAN)
  await Promise.all([...locations].filter(([ip]) => wanted.has(ip)).map(async ([ip, loc]) => {
    try {
      const u = new URL(loc)
      if (u.hostname !== ip || !/^https?:$/.test(u.protocol)) return
      const body = await get(u.protocol === 'https:', ip, Number(u.port) || (u.protocol === 'https:' ? 443 : 80), u.pathname + u.search, 30000)
      if (body?.body) put(ip, { upnp: { name: xml(body.body, 'friendlyName'), model: xml(body.body, 'modelName'), maker: xml(body.body, 'manufacturer') } })
    } catch {}
  }))
  return res
}

// ---- 3. services ------------------------------------------------------------------
function connect(ip: string, port: number): Promise<{ port: number; banner?: string } | null> {
  return new Promise((resolve) => {
    const s = net.connect({ host: ip, port, timeout: 900 })
    let done = false
    const end = (v: { port: number; banner?: string } | null) => { if (!done) { done = true; s.destroy(); resolve(v) } }
    s.on('connect', () => { if (port !== 22) end({ port }); else setTimeout(() => end({ port }), 1200) })
    s.on('data', (d) => end({ port, banner: d.toString('latin1').split(/\r?\n/)[0].trim().slice(0, 100) }))
    s.on('timeout', () => end(null))
    s.on('error', () => end(null))
  })
}
function get(tls: boolean, ip: string, port: number, path = '/', cap = 20000): Promise<{ status?: number; server?: string; body: string } | null> {
  return new Promise((resolve) => {
    const req = (tls ? https : http).get({ host: ip, port, path, timeout: 2500, rejectUnauthorized: false, headers: { 'user-agent': 'xdp-sentinel device check' } }, (r) => {
      let body = ''
      r.setEncoding('utf8')
      r.on('data', (d: string) => { if (body.length < cap) body += d })
      r.on('end', () => resolve({ status: r.statusCode, server: typeof r.headers.server === 'string' ? r.headers.server.slice(0, 80) : undefined, body }))
      r.on('error', () => resolve(null))
    })
    req.on('timeout', () => { req.destroy(); resolve(null) })
    req.on('error', () => resolve(null))
  })
}
// Host names an HTTPS certificate is issued to (CN + DNS alt names), minus the
// generic ones (localhost, bare IPs, wildcards, vendor defaults).
function certNames(ip: string, port: number): Promise<string[]> {
  return new Promise((resolve) => {
    const sock = tls.connect({ host: ip, port, rejectUnauthorized: false, timeout: 2500 })
    const done = (v: string[]) => { sock.destroy(); resolve(v) }
    sock.on('secureConnect', () => {
      const c = sock.getPeerCertificate()
      const raw = [String(c?.subject?.CN ?? ''), ...String(c?.subjectaltname ?? '').split(',').map((x) => x.trim()).filter((x) => x.startsWith('DNS:')).map((x) => x.slice(4))]
      done([...new Set(raw.map((x) => x.trim()).filter((x) => x && !x.includes('*') && !/^\d+\.\d+\.\d+\.\d+$/.test(x) && !/^(localhost|localhost\.localdomain|router|default|www|example\.com)$/i.test(x)))].slice(0, 4))
    })
    sock.on('timeout', () => done([]))
    sock.on('error', () => done([]))
  })
}

const decode = (s: string) => s.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/\s+/g, ' ').trim()

export async function fingerprint(ip: string): Promise<Probe> {
  const open = (await Promise.all(PROBE_PORTS.map((p) => connect(ip, p)))).filter(Boolean) as { port: number; banner?: string }[]
  const web: NonNullable<Probe['web']> = []
  for (const o of open.filter((x) => WEB.has(x.port))) {
    const tls = TLS.has(o.port)
    const r = await get(tls, ip, o.port)
    const title = r?.body ? /<title[^>]*>([^<]{1,100})/i.exec(r.body)?.[1] : undefined
    web.push({ port: o.port, tls, status: r?.status, server: r?.server, title: title ? decode(title) : undefined })
  }
  const ssh = open.find((x) => x.port === 22)?.banner
  const certs = [...new Set((await Promise.all(open.filter((x) => TLS.has(x.port)).map((x) => certNames(ip, x.port)))).flat())]
  return {
    at: Date.now(), ip, ports: open.map((x) => x.port).sort((a, b) => a - b),
    ...(ssh?.startsWith('SSH-') ? { ssh } : {}), ...(web.length ? { web } : {}), ...(certs.length ? { certNames: certs } : {}),
  }
}

// ---- what is it? ---------------------------------------------------------------------
export interface Identity { kind: string; label: string | null; labelFrom: string | null; os: string | null; webUrl: string | null; services: string[]; ports: number[] }
// short chip labels (the page explains each port in its pop-over)
const SERVICE: Record<number, string> = { 22: 'SSH', 53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 445: 'SMB', 554: 'RTSP', 631: 'IPP', 3389: 'RDP', 5000: 'UPnP', 7000: 'AirPlay', 8006: 'Proxmox', 8008: 'Cast', 8080: 'HTTP-alt', 8443: 'HTTPS-alt', 9100: 'Print', 62078: 'iOS sync' }

function osOf(ssh?: string): string | null {
  if (!ssh) return null
  const v = /OpenSSH_([\d.]+p?\d*)\s*(\S+)?/.exec(ssh)
  if (v) {
    const d = (v[2] ?? '').toLowerCase()
    return d.includes('ubuntu') ? 'Ubuntu Linux' : d.includes('raspbian') ? 'Raspberry Pi OS' : d.includes('debian') ? 'Debian Linux' : d ? `Linux (${v[2]})` : 'Linux/Unix'
  }
  if (/dropbear/i.test(ssh)) return 'embedded Linux'
  if (/TPSSH|Cisco|Zyxel|ROSSSH|Comware/i.test(ssh)) return 'network device firmware'
  return null
}

export function identify(d: { vendor: string | null; randomised: boolean; ip?: string; probe?: Probe; names?: Names; gateway?: boolean }): Identity {
  const p = d.probe
  const ports = new Set(p?.ports ?? [])
  const titles = (p?.web ?? []).map((w) => `${w.title ?? ''} ${w.server ?? ''}`).join(' ')
  const v = (d.vendor ?? '').toLowerCase()
  const t = titles.toLowerCase()
  const up = d.names?.upnp
  const has = (...xs: number[]) => xs.some((x) => ports.has(x))
  let kind = 'Unknown device'
  if (ports.has(8006) || /proxmox/.test(t)) kind = 'Proxmox server'
  else if (d.gateway || (has(53) && /tp-?link|router|gateway|fritz|asus|netgear|ubiquiti|mikrotik/.test(`${v} ${t}`))) kind = 'Router'
  else if (/switch/.test(t) || /zyxel|netgear|cisco/.test(v) && has(80, 443) && !has(53)) kind = 'Network switch'
  else if (has(554) || /abus|hikvision|dahua|axis|reolink|amcrest|foscam|uniview/.test(v) || /camera|nvr|dvr/.test(t)) kind = 'Camera'
  else if (has(9100, 631) || /printer|hp inc|brother|epson|canon|kyocera|xerox/.test(`${v} ${t}`)) kind = 'Printer'
  else if (has(62078)) kind = 'iPhone / iPad'
  else if (has(8008)) kind = 'Chromecast / Google device'
  else if (has(7000) || /apple/.test(v)) kind = 'Apple device'
  else if (has(3389, 445) || d.names?.netbios) kind = 'Windows PC'
  else if (/raspberry/.test(v)) kind = 'Raspberry Pi'
  else if (/tv|bravia|roku|webos|tizen/i.test(`${up?.model ?? ''} ${up?.name ?? ''}`)) kind = 'TV / media player'
  else if (p?.ssh && /openssh/i.test(p.ssh)) kind = 'Linux computer / server'
  else if (/access point|wifi|wi-fi|mesh/.test(t)) kind = 'WiFi access point'
  else if (has(80, 443, 8080, 8443)) kind = 'Device with a web page'
  else if (d.randomised) kind = 'Phone, tablet or laptop'
  else if (p && !p.ports.length) kind = 'Computer or phone (no open services)'
  // best name a device gives itself
  const webTitle = (p?.web ?? []).map((w) => w.title).find((x) => x && !/^(loading|index|home|login|redirect|untitled)/i.test(x))
  // the device's own name, best source first, and where it came from
  // certificate names: only real host names (no spaces, no factory placeholders like "My Name" or "SMB")
  const GENERIC = /^(proxmox|pve|smb|nas|router|switch|gateway|ap|admin|device|camera|server|default|my-?name|tp-?link|zyxel|netgear|asus|synology|unifi|mikrotik|test)$/i
  const cert = p?.certNames
    ?.map((n) => n.replace(/\.(localdomain|local|lan|home|internal|home\.arpa)$/i, ''))
    .find((n) => /^[a-z0-9][a-z0-9-]{2,}(\.[a-z0-9-]+)*$/i.test(n) && !GENERIC.test(n))
  const named: [string | undefined | null, string][] = [
    [up?.name, 'UPnP'], [d.names?.mdns, 'mDNS'], [d.names?.netbios, 'NetBIOS'], [d.names?.llmnr, 'LLMNR'],
    [cert, 'its HTTPS certificate'], [webTitle ? webTitle.replace(/\s*[-|·]\s*Proxmox Virtual Environment$/i, '') : null, 'its web page title'],
  ]
  const hit = named.find(([n]) => !!n)
  const label = hit?.[0] ?? null
  const labelFrom = hit?.[1] ?? null
  const os = osOf(p?.ssh) ?? (up?.model ? [up.maker, up.model].filter(Boolean).join(' ') : null)
  const w = (p?.web ?? []).find((x) => x.status && x.status < 500) ?? p?.web?.[0]
  const webUrl = w && d.ip ? `${w.tls ? 'https' : 'http'}://${d.ip}${(w.tls && w.port === 443) || (!w.tls && w.port === 80) ? '' : `:${w.port}`}/` : null
  return { kind, label, labelFrom, os, webUrl, services: (p?.ports ?? []).map((x) => SERVICE[x] ?? `port ${x}`), ports: p?.ports ?? [] }
}
