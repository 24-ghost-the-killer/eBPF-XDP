// Attack-signature rules, shared by the API and the pages. A "shape" is what
// the dataplane counts for every 16th dropped packet: protocol, ports, TCP
// flags, TTL and a 64-byte size bucket. A rule matches some of those fields and
// drops matching traffic from outside at once (scripts/xs-rules-apply loads them).

export type Field = 'proto' | 'dport' | 'sport' | 'flags' | 'len' | 'ttl'
export interface Rule {
  id: string; on: boolean; note?: string
  proto: number; dport: number; sport: number; tcp_flags: number; flags_mask: number
  len_lo: number; len_hi: number; ttl_lo: number; ttl_hi: number
  match: Field[]
  expires_at: number | null // unix seconds; null = until removed
  createdAt: number; createdBy: string; fromAttack?: number
}
export interface Shape {
  proto: number; tcp_flags: number; ttl: number; len_lo: number; len_hi: number; dport: number; sport: number
  icmp_type: number | null; icmp_code: number | null; sampled_packets: number; sampled_bytes: number; share: number
}

export const PROTO: Record<number, string> = { 1: 'ICMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6' }
const FLAG_BITS: [number, string][] = [[0x02, 'SYN'], [0x10, 'ACK'], [0x01, 'FIN'], [0x04, 'RST'], [0x08, 'PSH'], [0x20, 'URG']]
export const flagsText = (f: number) => FLAG_BITS.filter(([b]) => f & b).map(([, n]) => n).join('+') || 'none'
// UDP source ports that attackers bounce floods off (amplification / reflection)
export const REFLECTORS: Record<number, string> = {
  19: 'chargen', 53: 'DNS', 111: 'portmap', 123: 'NTP', 137: 'NetBIOS', 161: 'SNMP', 389: 'CLDAP', 520: 'RIP',
  1900: 'SSDP', 3702: 'WS-Discovery', 5353: 'mDNS', 5683: 'CoAP', 11211: 'memcached', 17: 'QOTD',
}

export function describeShape(s: Pick<Shape, 'proto' | 'tcp_flags' | 'ttl' | 'len_lo' | 'len_hi' | 'dport' | 'sport' | 'icmp_type'>): string {
  const p = PROTO[s.proto] ?? `protocol ${s.proto}`
  const size = `${s.len_lo}–${s.len_hi} bytes`
  if (s.proto === 6) return `TCP ${flagsText(s.tcp_flags)} to port ${s.dport}, ${size}, TTL ${s.ttl}`
  if (s.proto === 17) {
    const r = REFLECTORS[s.sport]
    return r ? `UDP from port ${s.sport} (${r} reflection) to port ${s.dport}, ${size}` : `UDP to port ${s.dport} (from ${s.sport}), ${size}, TTL ${s.ttl}`
  }
  if (s.proto === 1 || s.proto === 58) return `${p} type ${s.icmp_type ?? '?'}, ${size}, TTL ${s.ttl}`
  return `${p}, ${size}`
}

// The most precise rule for one shape that still catches all of it.
export function suggest(s: Shape): Omit<Rule, 'id' | 'on' | 'createdAt' | 'createdBy' | 'expires_at'> {
  const base = { proto: s.proto, dport: 0, sport: 0, tcp_flags: 0, flags_mask: 0, len_lo: s.len_lo, len_hi: s.len_hi, ttl_lo: 0, ttl_hi: 255 }
  const match: Field[] = ['proto', 'len']
  if (s.proto === 17) {
    if (REFLECTORS[s.sport]) { base.sport = s.sport; match.push('sport') } else { base.dport = s.dport; match.push('dport') }
  } else if (s.proto === 6) {
    base.dport = s.dport; base.tcp_flags = s.tcp_flags; base.flags_mask = 0x3f
    match.push('dport', 'flags')
  }
  // spoofed floods often leave every packet with the same TTL: pin it (±2)
  if (s.share >= 0.6) { base.ttl_lo = Math.max(0, s.ttl - 2); base.ttl_hi = Math.min(255, s.ttl + 2); match.push('ttl') }
  return { ...base, match }
}

export function describeRule(r: Pick<Rule, 'proto' | 'dport' | 'sport' | 'tcp_flags' | 'len_lo' | 'len_hi' | 'ttl_lo' | 'ttl_hi' | 'match'>): string {
  const m = new Set(r.match)
  const parts: string[] = [m.has('proto') ? (PROTO[r.proto] ?? `protocol ${r.proto}`) : 'any protocol']
  if (m.has('flags')) parts.push(flagsText(r.tcp_flags))
  if (m.has('sport')) parts.push(`from port ${r.sport}${REFLECTORS[r.sport] && r.proto === 17 ? ` (${REFLECTORS[r.sport]})` : ''}`)
  if (m.has('dport')) parts.push(`to port ${r.dport}`)
  if (m.has('len')) parts.push(`${r.len_lo}–${r.len_hi} bytes`)
  if (m.has('ttl')) parts.push(`TTL ${r.ttl_lo}–${r.ttl_hi}`)
  return parts.join(', ')
}
