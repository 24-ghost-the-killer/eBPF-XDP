// Red vs blue scoring. The red team (a player) launches a simulated attack; the
// blue team is the firewall. Red scores up to 100 points per attack:
//   up to 40 for every second the firewall needed to notice (4 points/s),
//   up to 20 for the time between noticing and defending (2 points/s; 20 if it never defended),
//   up to 40 for the share of attack packets that got through,
//   100 straight away if the attack was never detected.
// Blue gets the rest (100 - red).
export interface GameRun {
  id: string; scenario: string; label: string; player?: string | null; game?: boolean; state: string
  started_at: number; sent: number; dropped: number; detected_at: number | null; mitigated_at: number | null; recovered_at: number | null
}
export interface Score { red: number; blue: number; detect: number; defend: number; through: number; throughShare: number; missed: boolean }

export function score(r: GameRun): Score | null {
  if (r.state === 'error' || !r.sent) return null
  const throughShare = Math.max(0, Math.min(1, 1 - (r.dropped || 0) / r.sent))
  if (r.detected_at == null) return { red: 100, blue: 0, detect: 40, defend: 20, through: 40, throughShare, missed: true }
  const detect = Math.min(40, Math.round(r.detected_at * 4))
  const defend = r.mitigated_at == null ? 20 : Math.min(20, Math.round(Math.max(0, r.mitigated_at - r.detected_at) * 2))
  const through = Math.round(throughShare * 40)
  const red = Math.min(100, detect + defend + through)
  return { red, blue: 100 - red, detect, defend, through, throughShare, missed: false }
}

export interface PlayerRow { player: string; runs: number; best: number; avg: number; bestWith: string; last: number }
export function leaderboard(runs: GameRun[]): PlayerRow[] {
  const m = new Map<string, PlayerRow & { sum: number }>()
  for (const r of runs) {
    if (!r.game || !r.player) continue
    const s = score(r)
    if (!s) continue
    const e = m.get(r.player) ?? { player: r.player, runs: 0, best: -1, avg: 0, bestWith: '', last: 0, sum: 0 }
    e.runs++; e.sum += s.red; e.last = Math.max(e.last, r.started_at)
    if (s.red > e.best) { e.best = s.red; e.bestWith = r.label }
    m.set(r.player, e)
  }
  return [...m.values()].map(({ sum, ...e }) => ({ ...e, avg: Math.round(sum / e.runs) })).sort((a, b) => b.best - a.best || b.avg - a.avg)
}
