// SI-scaled formatting (1000-based), matching Grafana's pps/bps/bytes units.
export function si(n: number | null | undefined, unit = ''): string {
  if (n == null || Number.isNaN(n)) return '—'
  const u = ['', 'k', 'M', 'G', 'T', 'P']
  let i = 0
  let v = n
  while (Math.abs(v) >= 1000 && i < u.length - 1) {
    v /= 1000
    i++
  }
  const dec = i === 0 || Math.abs(v) >= 100 ? 0 : 1
  return `${v.toFixed(dec)} ${u[i]}${unit}`.trim()
}

export const pps = (n: number | null | undefined) => si(n, 'p/s')
export const bps = (n: number | null | undefined) => si(n, 'bps')
export const bytes = (n: number | null | undefined) => si(n, 'B')

export function duration(sec: number | null | undefined): string {
  if (sec == null || Number.isNaN(sec)) return '—'
  if (sec < 60) return `${Math.max(0, Math.round(sec))}s`
  const d = Math.floor(sec / 86400)
  const h = Math.floor((sec % 86400) / 3600)
  const m = Math.floor((sec % 3600) / 60)
  if (d) return `${d}d ${h}h`
  if (h) return `${h}h ${m}m`
  return `${m}m`
}

// "syn_flood" → "SYN flood": metric label values as readable text.
const TOKENS = new Set(['syn', 'ack', 'rst', 'fin', 'udp', 'icmp', 'icmpv6', 'ipv4', 'ipv6', 'tcp', 'ext', 'ip', 'land'])
export const pretty = (s: string) =>
  s.split('_').map((w) => (TOKENS.has(w) ? w.toUpperCase() : w)).join(' ').replace(/^./, (c) => c.toUpperCase())
