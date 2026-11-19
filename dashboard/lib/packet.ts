// Packet explainer: decode raw packet bytes into header fields with a plain-
// language explanation each, and build example attack packets to look at.
// Pure functions, used in the browser (no Node APIs).

export interface Field { name: string; value: string; explain: string; off: number; len: number }
export interface Layer { name: string; summary: string; fields: Field[]; off: number; len: number }
export interface Decoded { layers: Layer[]; summary: string; verdict: string | null; length: number }
export interface Packet { ts: number; bytes: Uint8Array; origLen: number }

const hex = (b: Uint8Array, o: number, n: number) => Array.from(b.subarray(o, o + n), (x) => x.toString(16).padStart(2, '0')).join('')
const mac = (b: Uint8Array, o: number) => Array.from(b.subarray(o, o + 6), (x) => x.toString(16).padStart(2, '0')).join(':')
const ip4 = (b: Uint8Array, o: number) => `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`
const u16 = (b: Uint8Array, o: number) => (b[o] << 8) | b[o + 1]
const u32 = (b: Uint8Array, o: number) => ((b[o] << 24) >>> 0) + (b[o + 1] << 16) + (b[o + 2] << 8) + b[o + 3]
function ip6(b: Uint8Array, o: number) {
  const g = Array.from({ length: 8 }, (_, i) => u16(b, o + i * 2).toString(16))
  return g.join(':').replace(/(^|:)0(:0)+(:|$)/, '::').replace(/:{3,}/, '::')
}
const PORTS: Record<number, string> = {
  20: 'FTP data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 67: 'DHCP server', 68: 'DHCP client', 80: 'HTTP', 123: 'NTP',
  137: 'NetBIOS', 161: 'SNMP', 389: 'LDAP/CLDAP', 443: 'HTTPS', 445: 'SMB', 554: 'RTSP (cameras)', 1900: 'SSDP', 3389: 'RDP', 5353: 'mDNS',
  8006: 'Proxmox', 8080: 'HTTP alt', 11211: 'memcached', 19: 'chargen', 3702: 'WS-Discovery', 5683: 'CoAP', 9100: 'printer',
}
const portName = (p: number) => (PORTS[p] ? `${p} (${PORTS[p]})` : p >= 49152 ? `${p} (temporary port)` : String(p))
const ETHERTYPE: Record<number, string> = { 0x0800: 'IPv4', 0x86dd: 'IPv6', 0x0806: 'ARP', 0x8100: '802.1Q VLAN tag', 0x88a8: '802.1ad VLAN tag' }
const PROTO: Record<number, string> = { 1: 'ICMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6', 47: 'GRE', 2: 'IGMP' }
const ICMP4: Record<number, string> = { 0: 'echo reply (ping answer)', 3: 'destination unreachable', 5: 'redirect', 8: 'echo request (ping)', 11: 'time exceeded', 13: 'timestamp request' }
const ICMP6: Record<number, string> = { 128: 'echo request (ping)', 129: 'echo reply', 133: 'router solicitation', 134: 'router advertisement', 135: 'neighbour solicitation (IPv6 "ARP")', 136: 'neighbour advertisement' }
const TCPF: [number, string, string][] = [
  [0x02, 'SYN', 'asks to open a connection'], [0x10, 'ACK', 'acknowledges data'], [0x01, 'FIN', 'closes the connection politely'],
  [0x04, 'RST', 'aborts the connection'], [0x08, 'PSH', 'deliver the data now'], [0x20, 'URG', 'urgent data'],
]

export function decode(b: Uint8Array, origLen = b.length): Decoded {
  const layers: Layer[] = []
  let verdict: string | null = null
  const f = (name: string, value: string, explain: string, off: number, len: number): Field => ({ name, value, explain, off, len })
  if (b.length < 14) return { layers, summary: 'too short for Ethernet', verdict, length: origLen }

  // Ethernet
  let off = 14
  let type = u16(b, 12)
  const eth: Layer = { name: 'Ethernet', off: 0, len: 14, summary: `${mac(b, 6)} → ${mac(b, 0)}`, fields: [
    f('Destination MAC', mac(b, 0), b[0] === 0xff ? 'Broadcast: every device on the LAN receives it.' : b[0] & 1 ? 'Multicast: a group of devices receives it.' : 'The network card this frame is delivered to on the local network.', 0, 6),
    f('Source MAC', mac(b, 6), (b[6] & 2) ? 'The sender’s network card. This one is “locally administered” (random or virtual), e.g. a phone’s private Wi-Fi address or a VM.' : 'The sender’s network card. The first 3 bytes name the manufacturer.', 6, 6),
    f('EtherType', `0x${type.toString(16).padStart(4, '0')} (${ETHERTYPE[type] ?? 'other'})`, 'Says what is inside the frame.', 12, 2),
  ] }
  layers.push(eth)
  while ((type === 0x8100 || type === 0x88a8) && b.length >= off + 4) {
    const tci = u16(b, off)
    layers.push({ name: '802.1Q VLAN tag', off: off - 2, len: 4, summary: `VLAN ${tci & 0xfff}`, fields: [
      f('Priority', String(tci >> 13), 'Quality-of-service priority (0 = normal).', off, 1),
      f('VLAN ID', String(tci & 0xfff), 'Which virtual network the frame belongs to: one cable can carry many VLANs (this is how the firewall sits between the router on VLAN 10 and your LAN on VLAN 20).', off, 2),
      f('EtherType', `0x${u16(b, off + 2).toString(16)} (${ETHERTYPE[u16(b, off + 2)] ?? 'other'})`, 'What comes after the tag.', off + 2, 2),
    ] })
    type = u16(b, off + 2)
    off += 4
  }

  let l4 = -1, l4off = 0, src = '', dst = '', ttl = 0, ipLen = 0
  if (type === 0x0806 && b.length >= off + 28) {
    const op = u16(b, off + 6)
    const spa = ip4(b, off + 14), tpa = ip4(b, off + 24)
    layers.push({ name: 'ARP', off, len: 28, summary: op === 1 ? `Who has ${tpa}? Tell ${spa}` : `${spa} is at ${mac(b, off + 8)}`, fields: [
      f('Operation', op === 1 ? '1 (request)' : op === 2 ? '2 (reply)' : String(op), op === 1 ? 'A question to everyone: which MAC has this IP address?' : 'The answer: “that IP address is at my MAC”. Devices believe replies without checking, which is what ARP spoofing abuses.', off + 6, 2),
      f('Sender MAC', mac(b, off + 8), 'The MAC the sender says it has.', off + 8, 6),
      f('Sender IP', spa, spa === '0.0.0.0' ? 'A probe: a device checking that an address is free before taking it.' : 'The IP the sender claims as its own. If another device claims the router’s IP, it is trying to become a man in the middle.', off + 14, 4),
      f('Target MAC', mac(b, off + 18), op === 1 ? 'Unknown yet (zeros): that is what is being asked.' : 'Who the answer is for.', off + 18, 6),
      f('Target IP', tpa, 'The address being asked about.', off + 24, 4),
    ] })
    if (op === 2) verdict = 'An ARP reply. Normal when answering a question; if it claims the router’s or another device’s address from a different MAC, it is ARP spoofing (the LAN guard catches that).'
  } else if (type === 0x0800 && b.length >= off + 20) {
    const ihl = (b[off] & 0x0f) * 4
    ipLen = u16(b, off + 2)
    const fl = u16(b, off + 6)
    const mf = !!(fl & 0x2000), df = !!(fl & 0x4000), frag = (fl & 0x1fff) * 8
    l4 = b[off + 9]; ttl = b[off + 8]; src = ip4(b, off + 12); dst = ip4(b, off + 16)
    layers.push({ name: 'IPv4', off, len: ihl, summary: `${src} → ${dst} (${PROTO[l4] ?? l4})`, fields: [
      f('Version + header length', `4, ${ihl} bytes`, ihl > 20 ? 'Version 4. The header is longer than 20 bytes: it carries IP options, which are rare and often a sign of trickery.' : 'Version 4, standard 20-byte header.', off, 1),
      f('DSCP/ECN', `0x${b[off + 1].toString(16)}`, 'Traffic class / congestion bits (usually 0).', off + 1, 1),
      f('Total length', `${ipLen} bytes`, 'Size of the IP packet (header + data).', off + 2, 2),
      f('Identification', String(u16(b, off + 4)), 'Numbers the packet so its fragments can be put back together.', off + 4, 2),
      f('Flags + fragment offset', `${df ? 'DF ' : ''}${mf ? 'MF ' : ''}offset ${frag}`, mf || frag ? 'This is a FRAGMENT of a bigger packet. Floods of fragments are expensive to reassemble: a classic attack.' : df ? '“Don’t fragment”: normal for modern traffic.' : 'Not fragmented.', off + 6, 2),
      f('TTL', String(ttl), `Time to live: each router subtracts 1. Starts at 64 (Linux, macOS), 128 (Windows) or 255 (network gear), so ${ttl} suggests ${ttl > 128 ? 'a router or a crafted packet' : ttl > 64 ? 'Windows' : 'Linux/macOS/phone'} about ${ttl > 128 ? 255 - ttl : ttl > 64 ? 128 - ttl : 64 - ttl} hops away. In a spoofed flood every packet often has the same odd TTL.`, off + 8, 1),
      f('Protocol', `${l4} (${PROTO[l4] ?? 'other'})`, 'What the IP packet carries.', off + 9, 1),
      f('Header checksum', `0x${hex(b, off + 10, 2)}`, 'Detects damage to the header on the way.', off + 10, 2),
      f('Source IP', src, /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(src) ? 'A private address: a device inside a local network.' : 'A public internet address. In an attack it may be spoofed (forged): the sender can write anything here.', off + 12, 4),
      f('Destination IP', dst, 'Where the packet is going.', off + 16, 4),
    ] })
    if (mf || frag) verdict = 'An IP fragment. Normal traffic is rarely fragmented today; a flood of fragments is a fragment attack (the firewall can drop all fragments).'
    l4off = off + ihl
    if (frag) l4 = -1
  } else if (type === 0x86dd && b.length >= off + 40) {
    l4 = b[off + 6]; ttl = b[off + 7]; src = ip6(b, off + 8); dst = ip6(b, off + 24)
    layers.push({ name: 'IPv6', off, len: 40, summary: `${src} → ${dst} (${PROTO[l4] ?? l4})`, fields: [
      f('Version + traffic class + flow label', `6, 0x${hex(b, off, 4)}`, 'Version 6. The flow label lets routers keep one connection’s packets together.', off, 4),
      f('Payload length', `${u16(b, off + 4)} bytes`, 'Size of what follows the 40-byte header.', off + 4, 2),
      f('Next header', `${l4} (${PROTO[l4] ?? 'extension header or other'})`, 'What comes next. IPv6 can chain “extension headers”; long chains are used to sneak past firewalls.', off + 6, 1),
      f('Hop limit', String(ttl), 'Like IPv4’s TTL: decremented by each router.', off + 7, 1),
      f('Source', src, src.startsWith('fe80') ? 'Link-local: only valid on this LAN.' : 'The sender’s IPv6 address.', off + 8, 16),
      f('Destination', dst, dst.startsWith('ff') ? 'Multicast: a group of devices.' : 'Where it is going.', off + 24, 16),
    ] })
    l4off = off + 40
  }

  // transport
  if (l4 === 6 && b.length >= l4off + 20) {
    const sp = u16(b, l4off), dp = u16(b, l4off + 2), flags = b[l4off + 13], doff = (b[l4off + 12] >> 4) * 4
    const names = TCPF.filter(([bit]) => flags & bit)
    layers.push({ name: 'TCP', off: l4off, len: Math.min(doff, b.length - l4off), summary: `${sp} → ${dp} [${names.map((n) => n[1]).join(',') || 'no flags'}]`, fields: [
      f('Source port', portName(sp), sp >= 49152 ? 'A temporary port the client picked for this connection.' : 'The port the sender uses.', l4off, 2),
      f('Destination port', portName(dp), 'Which service on the receiver it wants.', l4off + 2, 2),
      f('Sequence number', String(u32(b, l4off + 4)), 'Numbers every byte sent, so the receiver can put them in order. A SYN’s number is random.', l4off + 4, 4),
      f('Acknowledgement', String(u32(b, l4off + 8)), flags & 0x10 ? 'The next byte the sender expects from the other side.' : 'Unused (no ACK flag).', l4off + 8, 4),
      f('Header length', `${doff} bytes`, doff > 20 ? 'Longer than 20: TCP options follow (window scaling, timestamps…).' : 'No options.', l4off + 12, 1),
      f('Flags', names.map((n) => n[1]).join(' + ') || 'none', names.length ? names.map((n) => `${n[1]} ${n[2]}`).join('; ') + '.' : 'No flags at all: a “NULL scan”, never used by real traffic.', l4off + 13, 1),
      f('Window', String(u16(b, l4off + 14)), 'How much data the sender can receive right now.', l4off + 14, 2),
      f('Checksum', `0x${hex(b, l4off + 16, 2)}`, 'Detects damage.', l4off + 16, 2),
    ] })
    const syn = flags & 0x02, ack = flags & 0x10
    if ((flags & 0x29) === 0x29) verdict = 'An XMAS packet (FIN+PSH+URG “lit up like a Christmas tree”). Real software never sends this: it is a scan or a flood meant to confuse firewalls.'
    else if (flags === 0) verdict = 'A NULL packet (no flags). Never sent by real software: a scan or an attack.'
    else if (syn && !ack) verdict = `A connection request (SYN). One is normal; millions from random addresses are a SYN flood that fills ${dst}’s connection table.`
    else if (ack && !syn && !(flags & 0x05) && ipLen > 0 && ipLen <= 60) verdict = 'A bare ACK. Normal inside a connection; floods of ACKs for connections that do not exist are an ACK flood (connection tracking catches them).'
    else if (syn && (flags & 0x01)) verdict = 'SYN and FIN together: impossible in real traffic, a scan or malformed-packet attack.'
  } else if (l4 === 17 && b.length >= l4off + 8) {
    const sp = u16(b, l4off), dp = u16(b, l4off + 2), len = u16(b, l4off + 4)
    layers.push({ name: 'UDP', off: l4off, len: 8, summary: `${sp} → ${dp}, ${len - 8} bytes of data`, fields: [
      f('Source port', portName(sp), 'The port the sender uses.', l4off, 2),
      f('Destination port', portName(dp), 'Which service it is for.', l4off + 2, 2),
      f('Length', `${len} bytes`, 'Header + data.', l4off + 4, 2),
      f('Checksum', `0x${hex(b, l4off + 6, 2)}`, 'Detects damage (0 = not used).', l4off + 6, 2),
    ] })
    const amp: Record<number, string> = { 53: 'DNS', 123: 'NTP', 11211: 'memcached', 1900: 'SSDP', 161: 'SNMP', 389: 'CLDAP', 19: 'chargen', 3702: 'WS-Discovery', 5683: 'CoAP' }
    if (amp[sp] && dp >= 1024 && origLen > 400) verdict = `A big ${amp[sp]} ANSWER to a port nobody asked from. This is amplification: an attacker sent tiny questions to ${amp[sp]} servers with ${dst} as the forged sender, and the much larger answers flood ${dst}.`
    else if (sp === 53 || dp === 53) verdict = 'DNS: looking up a name. Normal traffic.'
    if (sp === 53 || dp === 53) {
      const o = l4off + 8
      if (b.length >= o + 12) {
        const fl = u16(b, o + 2)
        const qd = u16(b, o + 4), an = u16(b, o + 6)
        const fields = [
          f('Transaction ID', `0x${hex(b, o, 2)}`, 'Matches an answer to its question.', o, 2),
          f('Flags', `${fl & 0x8000 ? 'answer' : 'question'}, opcode ${(fl >> 11) & 15}, rcode ${fl & 15}`, fl & 0x8000 ? 'This is a response.' : 'This is a query.', o + 2, 2),
          f('Questions', String(qd), 'How many names are asked about.', o + 4, 2),
          f('Answers', String(an), an > 10 ? 'Many answers: amplification attacks pick record types (ANY, TXT) with huge answers.' : 'Records in the answer.', o + 6, 2),
        ]
        let q = o + 12, name = ''
        while (q < b.length && b[q] && b[q] < 64 && name.length < 120) { name += (name ? '.' : '') + String.fromCharCode(...b.subarray(q + 1, Math.min(b.length, q + 1 + b[q]))); q += b[q] + 1 }
        if (name) fields.push(f('Name', name, 'The name being looked up.', o + 12, Math.min(q - o - 12 + 1, b.length - o - 12)))
        layers.push({ name: 'DNS', off: o, len: Math.min(b.length - o, 12 + (name ? q - o - 12 + 1 : 0)), summary: `${fl & 0x8000 ? 'answer' : 'query'}${name ? ` for ${name}` : ''}`, fields })
      }
    }
  } else if ((l4 === 1 || l4 === 58) && b.length >= l4off + 4) {
    const t = b[l4off], c = b[l4off + 1]
    const names = l4 === 1 ? ICMP4 : ICMP6
    layers.push({ name: l4 === 1 ? 'ICMP' : 'ICMPv6', off: l4off, len: Math.min(8, b.length - l4off), summary: `${names[t] ?? `type ${t}`}`, fields: [
      f('Type', `${t} (${names[t] ?? 'other'})`, l4 === 58 && t >= 133 && t <= 136 ? 'Neighbour discovery: IPv6 cannot work without it, so firewalls must let it through.' : 'What kind of control message this is.', l4off, 1),
      f('Code', String(c), 'More detail on the type.', l4off + 1, 1),
      f('Checksum', `0x${hex(b, l4off + 2, 2)}`, 'Detects damage.', l4off + 2, 2),
    ] })
    if ((l4 === 1 && t === 8) || (l4 === 58 && t === 128)) verdict = 'A ping. One is a harmless “are you there?”; thousands per second are a ping flood.'
  }

  const top = layers[layers.length - 1]
  const payload = top ? b.length - (top.off + top.len) : 0
  if (payload > 0 && top && top.name !== 'Ethernet') {
    layers.push({ name: 'Data', off: top.off + top.len, len: payload, summary: `${payload} bytes${origLen > b.length ? ` shown of ${origLen - top.off - top.len}` : ''}`, fields: [
      f('Payload', `${payload} bytes`, origLen > b.length ? 'The content. Only the start was recorded (headers are what the firewall looks at).' : 'The content carried by the packet.', top.off + top.len, payload),
    ] })
  }
  const summary = layers.filter((l) => l.name !== 'Data' && l.name !== 'Ethernet').map((l) => l.summary).join(' · ') || eth.summary
  return { layers, summary, verdict, length: origLen }
}

// ---- pcap ---------------------------------------------------------------------
export function parsePcap(buf: ArrayBuffer): Packet[] {
  const v = new DataView(buf)
  if (buf.byteLength < 24) throw new Error('not a pcap file')
  const magic = v.getUint32(0, false)
  let le: boolean, nano = false
  if (magic === 0xa1b2c3d4) le = false
  else if (magic === 0xd4c3b2a1) le = true
  else if (magic === 0xa1b23c4d) { le = false; nano = true }
  else if (magic === 0x4d3cb2a1) { le = true; nano = true }
  else if (magic === 0x0a0d0d0a) throw new Error('This is a pcapng file: save it as classic pcap (in Wireshark: File → Save As → “pcap”).')
  else throw new Error('not a pcap file')
  const link = v.getUint32(20, le)
  const out: Packet[] = []
  let o = 24
  while (o + 16 <= buf.byteLength && out.length < 2000) {
    const sec = v.getUint32(o, le), frac = v.getUint32(o + 4, le), incl = v.getUint32(o + 8, le), orig = v.getUint32(o + 12, le)
    o += 16
    if (o + incl > buf.byteLength) break
    let bytes = new Uint8Array(buf, o, incl)
    if (link === 113 && bytes.length >= 16) { // Linux cooked capture: rebuild an Ethernet header
      const e = new Uint8Array(bytes.length - 2); e.set(bytes.subarray(14, 16), 12); e.set(bytes.subarray(16), 14); bytes = e
    } else if (link === 276 && bytes.length >= 20) {
      const e = new Uint8Array(bytes.length - 6); e.set(bytes.subarray(0, 2), 12); e.set(bytes.subarray(20), 14); bytes = e
    } else if (link !== 1) throw new Error(`unsupported capture type (link type ${link})`)
    out.push({ ts: sec * 1000 + (nano ? frac / 1e6 : frac / 1e3), bytes: new Uint8Array(bytes), origLen: orig - (bytes.length < incl ? incl - bytes.length : 0) })
    o += incl
  }
  return out
}

// ---- example attack packets -------------------------------------------------
function csum(b: Uint8Array, o: number, n: number, init = 0) {
  let s = init
  for (let i = 0; i < n; i += 2) s += (b[o + i] << 8) | (i + 1 < n ? b[o + i + 1] : 0)
  while (s >> 16) s = (s & 0xffff) + (s >> 16)
  return ~s & 0xffff
}
const MAC_BOX = [0x06, 0xcb, 0xa9, 0xa2, 0xf3, 0x21], MAC_ROUTER = [0x5c, 0xa6, 0xe6, 0x3a, 0x1d, 0xc3]
const ipb = (s: string) => s.split('.').map(Number)
function build(opts: { proto: number; src: string; dst: string; ttl: number; l4: number[]; payload?: number; frag?: number; srcMac?: number[]; dstMac?: number[] }): Uint8Array {
  const pay = opts.payload ?? 0
  const total = 20 + opts.l4.length + pay
  const b = new Uint8Array(14 + total)
  b.set(opts.dstMac ?? MAC_BOX, 0); b.set(opts.srcMac ?? MAC_ROUTER, 6); b[12] = 0x08; b[13] = 0x00
  const o = 14
  b[o] = 0x45; b[o + 2] = total >> 8; b[o + 3] = total & 255; b[o + 4] = 0x1a; b[o + 5] = 0x2b
  b[o + 6] = (opts.frag ?? 0x4000) >> 8; b[o + 7] = (opts.frag ?? 0x4000) & 255; b[o + 8] = opts.ttl; b[o + 9] = opts.proto
  b.set(ipb(opts.src), o + 12); b.set(ipb(opts.dst), o + 16)
  const c = csum(b, o, 20); b[o + 10] = c >> 8; b[o + 11] = c & 255
  b.set(opts.l4, o + 20)
  for (let i = 0; i < pay; i++) b[o + 20 + opts.l4.length + i] = (i * 37 + 11) & 255
  return b
}
const tcp = (sp: number, dp: number, flags: number, seq = 0x5a17c0de) => [sp >> 8, sp & 255, dp >> 8, dp & 255, seq >>> 24, (seq >> 16) & 255, (seq >> 8) & 255, seq & 255, 0, 0, 0, 0, 0x50, flags, 0xfa, 0xf0, 0x3c, 0x1d, 0, 0]
const udp = (sp: number, dp: number, len: number) => [sp >> 8, sp & 255, dp >> 8, dp & 255, (len + 8) >> 8, (len + 8) & 255, 0, 0]

export const EXAMPLES: { id: string; title: string; note: string; bytes: () => Uint8Array; origLen?: number }[] = [
  { id: 'normal', title: 'Normal: opening a website', note: 'A laptop starts an HTTPS connection: SYN from a temporary port to port 443, TTL 64 (Linux/macOS). Compare the attacks with this.',
    bytes: () => build({ proto: 6, src: '192.168.1.103', dst: '142.250.74.110', ttl: 64, l4: tcp(52144, 443, 0x02), srcMac: [0x76, 0x5f, 0x8e, 0xb3, 0x26, 0x06], dstMac: MAC_ROUTER }) },
  { id: 'syn', title: 'SYN flood', note: 'Looks like a normal connection request, but the sender is forged and it never finishes the handshake. Millions per second fill the server’s table of half-open connections.',
    bytes: () => build({ proto: 6, src: '185.220.101.50', dst: '192.168.1.173', ttl: 241, l4: tcp(31337, 80, 0x02, 0x12345678) }) },
  { id: 'ack', title: 'ACK flood', note: 'An acknowledgement for a connection that never existed. The firewall’s connection tracking knows no handshake happened.',
    bytes: () => build({ proto: 6, src: '45.95.168.12', dst: '192.168.1.173', ttl: 238, l4: tcp(40112, 443, 0x10) }) },
  { id: 'xmas', title: 'XMAS packet', note: 'FIN, PSH and URG all set: an impossible combination used to probe and confuse firewalls.',
    bytes: () => build({ proto: 6, src: '203.0.113.66', dst: '192.168.1.173', ttl: 52, l4: tcp(53122, 22, 0x29) }) },
  { id: 'dns', title: 'DNS amplification', note: 'A big DNS answer the victim never asked for: the attacker asked thousands of open DNS servers with the victim’s address forged as sender. 60 bytes in, ~3,000 bytes out.',
    bytes: () => { const dns = [0x7a, 0x11, 0x81, 0x80, 0, 1, 0, 23, 0, 0, 0, 0, 3, 0x69, 0x73, 0x63, 3, 0x6f, 0x72, 0x67, 0, 0, 0xff, 0, 1]; const b = build({ proto: 17, src: '8.8.4.4', dst: '192.168.1.173', ttl: 57, l4: [...udp(53, 38245, dns.length + 1400), ...dns], payload: 90 }); b[16] = (20 + 8 + dns.length + 1400) >> 8; b[17] = (20 + 8 + dns.length + 1400) & 255; return b }, origLen: 14 + 20 + 8 + 25 + 1400 },
  { id: 'memcached', title: 'Memcached amplification', note: 'The biggest amplifier known: a 15-byte request to an open memcached server returns up to 750 KB. Note the source port 11211.',
    bytes: () => build({ proto: 17, src: '91.121.42.10', dst: '192.168.1.173', ttl: 49, l4: udp(11211, 61022, 1400), payload: 100 }), origLen: 1442 },
  { id: 'ping', title: 'Ping flood', note: 'An ordinary ping. Thousands per second from many senders are a ping flood.',
    bytes: () => build({ proto: 1, src: '198.51.100.23', dst: '192.168.1.173', ttl: 115, l4: [8, 0, 0xf7, 0xff, 0, 1, 0, 1], payload: 32 }) },
  { id: 'frag', title: 'Fragment flood', note: 'The first piece of a broken-up packet (MF = more fragments). The receiver must hold it and wait for the rest, which never comes.',
    bytes: () => build({ proto: 17, src: '192.0.2.200', dst: '192.168.1.173', ttl: 60, frag: 0x2000, l4: udp(4444, 5555, 1472), payload: 60 }) },
  { id: 'arpspoof', title: 'ARP spoofing', note: 'A device with an unknown MAC tells the LAN “192.168.1.1 (the router) is at my MAC”. Everyone who believes it sends their internet traffic through the attacker.',
    bytes: () => { const b = new Uint8Array(42); b.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0); b.set([0x02, 0xde, 0xad, 0xbe, 0xef, 0x01], 6); b[12] = 8; b[13] = 6; b.set([0, 1, 8, 0, 6, 4, 0, 2], 14); b.set([0x02, 0xde, 0xad, 0xbe, 0xef, 0x01], 22); b.set([192, 168, 1, 1], 28); b.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 32); b.set([192, 168, 1, 255], 38); return b } },
]

export function hexLines(b: Uint8Array): { off: number; bytes: number[] }[] {
  const out = []
  for (let o = 0; o < b.length; o += 16) out.push({ off: o, bytes: Array.from(b.subarray(o, o + 16)) })
  return out
}
