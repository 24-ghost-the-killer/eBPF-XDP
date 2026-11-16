// "Why wasn't this blocked?" — a plain-language reading of one attack: how much
// of it was dropped, and the reasons, from what the defences recorded
// (Episode.mitigation, analysed from 14 Nov 2026 on) plus what every attack
// has (drop share, vectors, ladder peak, duration, sources).
import type { Episode } from './attacks'
import { markLabel } from './attacks'
import { si } from './format'

export type Tone = 'good' | 'warn' | 'bad' | 'neutral'
export interface Reason { tone: Tone; title: string; text: string }
export interface Explanation { tone: Tone; headline: string; reasons: Reason[] }

// The mitigation ladder (userspace/common/src/risk.rs + the agent's enforce()).
export const LADDER: { name: string; does: string }[] = [
  { name: 'Pass', does: 'no action' },
  { name: 'Monitor', does: 'watching only' },
  { name: 'Sample', does: 'sampling packets for analysis' },
  { name: 'Rate limit', does: 'each source capped at 5,000 packets/s' },
  { name: 'Aggressive rate limit', does: 'each source capped at 1,000 packets/s' },
  { name: 'Temporary block', does: 'each source capped at 500 packets/s plus attack-type drops' },
]
export const levelName = (lv: number) => LADDER[Math.max(0, Math.min(5, lv))]?.name ?? `level ${lv}`

const FLAG: Record<string, string> = {
  drop_syn: 'Drop SYN', drop_ack: 'Drop stray ACK', drop_udp: 'Drop UDP', drop_udp_strict: 'Drop all UDP', drop_udp_dns: 'Drop DNS replies',
  drop_icmp: 'Drop ICMP', drop_fragments: 'Drop fragments', drop_untracked: 'Drop untracked', drop_ipv6_ext: 'Drop IPv6 ext. headers',
  ratelimit: 'Per-source rate limit', global_rl: 'Global rate limit', lockdown: 'Lockdown', auto_lockdown: 'Auto-lockdown',
  drop_spoofed: 'Anti-spoofing', drop_malformed: 'Drop malformed', drop_bad_tcp_flags: 'Drop bad TCP flags', conntrack: 'Connection tracking',
  check_allow: 'Allowlist', service_allow: 'Service allowlist', hll: 'Distinct-source counter', sampling: 'Sampling', check_policy: 'Policy map', dport_hist: 'Port histogram',
  syn_auth: 'SYN authentication', scan_block: 'Scan block',
}
export const flagName = (f: string) => FLAG[f] ?? f.replace(/_/g, ' ')
const n = (x: number) => Math.round(x).toLocaleString('en')

export function explain(a: Episode): Explanation {
  const m = a.mitigation
  const share = a.dropShare
  const reasons: Reason[] = []
  const vec = new Set(a.vectors)
  const cls = a.classifier?.label ?? ''
  const peak = m?.targetPeakPps || a.peakPps

  if (a.mark) {
    reasons.push({ tone: 'neutral', title: 'Marked as a false alarm', text: `${markLabel(a.mark.reason)}${a.mark.note ? ` — ${a.mark.note}` : ''}${a.mark.by ? ` (by ${a.mark.by})` : ''}. It is left out of the totals.` })
  }
  if (m?.disarmed) {
    reasons.push({ tone: 'bad', title: 'Auto-mitigation was switched off', text: 'The box was in detect-only mode: it saw the attack but was not allowed to block it. Turn auto-mitigation back on under AI security.' })
  }
  const arp = vec.has('ARP storm') || cls === 'arp_storm'
  if (arp) {
    reasons.push({ tone: share < 0.5 ? 'warn' : 'neutral', title: 'Mostly ARP (not IP) traffic', text: 'ARP is not IP, so the per-source rules don’t apply. Since 14 Nov the firewall caps ARP at 2,000 packets/s. Storms like this usually mean a network loop: turn on Loop Guard / STP and storm control on the switch.' })
  }
  const ackOnly = vec.has('ACK flood') && a.vectors.length <= 2 && !arp
  if (ackOnly && share < 0.5) {
    reasons.push({ tone: 'neutral', title: 'Looks like a download, not a flood', text: 'Pure ACKs on tracked connections are what a big download sends back. Most of the “ACK floods” recorded here were downloads. Since 14 Nov the detector ignores ACKs that a matching download in the other direction explains.' })
  }

  if (m) {
    if (!m.disarmed && a.peakRiskLevel < 3) {
      reasons.push({ tone: share < 0.5 ? 'warn' : 'neutral', title: `Risk only reached level ${a.peakRiskLevel} (${levelName(a.peakRiskLevel)})`, text: `Blocking starts at level 3 (${LADDER[3].does}). The risk engine didn’t see enough evidence to go that far.` })
    }
    if (m.rateCap > 0) {
      const under = peak > 0 && peak < m.rateCap
      reasons.push({
        tone: (under || !m.rateLimited) && share < 0.5 ? 'warn' : 'neutral',
        title: `Rate limit armed at ${n(m.rateCap)} packets/s per source`,
        text: under
          ? `But the whole flood only peaked at ${si(peak)} packets/s, so no single source was over the cap and nothing was dropped by it.`
          : m.rateLimited > 0 ? `It dropped ${si(m.rateLimited)} packets from sources sending faster than that.`
          : `The flood peaked at ${si(peak)} packets/s, yet the limiter dropped nothing: the traffic was spread over sources that each stayed under the cap, or came from trusted (allowlisted) hosts, which skip it by design.`,
      })
    }
    if (m.armed.includes('drop_untracked') && (m.untracked ?? -1) === 0 && share < 0.5) {
      reasons.push({ tone: 'warn', title: 'Every packet belonged to an established connection', text: '“Drop untracked” only removes TCP packets that match no connection; here there were none. A real ACK flood is untracked; tracked ACKs are a live transfer (e.g. a download).' })
    }
    if (m.limitAfterSec != null && m.limitAfterSec > 10) {
      const late = m.limitAfterSec > a.durationSec * 0.5
      reasons.push({ tone: late && share < 0.5 ? 'warn' : 'neutral', title: `Blocking began after ${m.limitAfterSec} s`, text: late ? 'Most of the attack was already over by then: the ladder climbs one level every few seconds of sustained evidence.' : 'The ladder climbs one level every few seconds of sustained evidence, so the first seconds pass through.' })
    }
    if (m.armed.length) {
      reasons.push({ tone: 'good', title: 'Defences switched on for this attack', text: m.armed.map(flagName).join(', ') + (m.autoLockdown ? ', and auto-lockdown (default-deny) was armed' : '') + '.' })
    } else if (m.autoLockdown) {
      reasons.push({ tone: 'good', title: 'Auto-lockdown was armed', text: 'The attack leaked past the other defences, so the box switched to default-deny.' })
    }
  } else if (share < 0.5 && !a.mark) {
    reasons.push({ tone: 'neutral', title: 'No defence details for this attack', text: `It was analysed before the box recorded what its defences did (14 Nov 2026). The risk ladder peaked at level ${a.peakRiskLevel} (${levelName(a.peakRiskLevel)}): ${LADDER[Math.max(0, Math.min(5, a.peakRiskLevel))].does}.` })
  }

  if (a.durationSec < 15 && share < 0.5) {
    reasons.push({ tone: 'neutral', title: `Short burst (${a.durationSec} s)`, text: 'Over before the risk engine had the few seconds of evidence it needs to escalate.' })
  }
  if (a.attackers.length && a.attackers.every((x) => x.scope === 'lan')) {
    reasons.push({ tone: 'neutral', title: 'Every source was inside your network', text: 'Not an internet attack: think downloads, backups, scans or a loop on the LAN. Check the Devices page for who it was.' })
  }

  const tone: Tone = a.mark ? 'neutral' : share >= 0.9 ? 'good' : share >= 0.5 ? 'warn' : 'bad'
  const pct = `${(share * 100).toFixed(share < 0.1 && share > 0 ? 1 : 0)}%`
  const headline = a.mark
    ? 'Not an attack (marked as a false alarm)'
    : share >= 0.9 ? `Blocked: ${pct} of the flood was dropped`
    : share >= 0.5 ? `Mostly blocked: ${pct} dropped`
    : a.droppedPackets > 0 ? `Barely blocked: only ${share < 0.001 ? '<0.1%' : pct} dropped (${si(a.droppedPackets)} packets)`
    : 'Not blocked: nothing was dropped'
  if (!reasons.length) {
    reasons.push(share >= 0.9
      ? { tone: 'good', title: 'The standing defences handled it', text: 'Dropped by the rules that are always on (anti-spoofing, malformed and bad-flag drops, allowlists), without needing to escalate.' }
      : { tone: 'neutral', title: 'No single cause recorded', text: 'Check the replay below to see the traffic and the risk ladder second by second.' })
  }
  return { tone, headline, reasons }
}
