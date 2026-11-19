'use client'
// Red vs blue: a player (red team) launches a simulated attack and the
// firewall (blue team) tries to stop it. Points for red when the firewall is
// slow to notice, slow to defend, or lets packets through. Leaderboard of the
// players, and how the firewall does overall. Shown on Show mode while a round runs.
import { useEffect, useMemo, useState } from 'react'
import { Swords, Trophy, Shield, Crosshair, Loader2, Play, Timer } from 'lucide-react'
import { usePoll } from '@/hooks/usePoll'
import { score, leaderboard, type GameRun } from '@/lib/game'
import { Panel, Empty, btn } from '@/components/aa/kit'
import { useMe } from '@/components/aa/Shell'

interface Scenario { id: string; label: string; group: string }
interface Cur extends GameRun { phase: string; duration: number; live: { threat?: number } }
interface Data { scenarios: Scenario[]; current: Cur | null; pending: { id: string } | null; history: GameRun[] }
const ROUND_S = 20

export default function GamePage() {
  const { can } = useMe()
  const [fast, setFast] = useState(false)
  const q = usePoll(async () => {
    const r = await fetch('/api/simulate?all=1', { cache: 'no-store' })
    const j = await r.json()
    if (j.status !== 'success') throw new Error(j.error || 'the game needs the attack simulator')
    return j as Data
  }, fast ? 1000 : 5000, [fast])
  const [player, setPlayer] = useState('')
  const [pick, setPick] = useState('tcp-syn')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => { try { setPlayer(localStorage.getItem('xs-game-player') ?? '') } catch {} }, [])
  const d = q.data
  const running = d?.current?.state === 'running' || !!d?.pending
  useEffect(() => setFast(running), [running])
  const games = useMemo(() => (d?.history ?? []).filter((r) => r.game && r.player), [d])
  const board = useMemo(() => leaderboard(games), [games])

  if (!d) return q.error ? <Empty icon={Swords} title="The game is unavailable" hint={q.error} /> : <div className="aa-skeleton h-64 rounded-2xl" />
  const cur = d.current && d.current.game ? d.current : null
  const last = cur && cur.state !== 'running' ? cur : null
  const lastScore = last ? score(last) : null
  const scored = games.map(score).filter((s): s is NonNullable<typeof s> => !!s)
  const blueAvg = scored.length ? Math.round(scored.reduce((a, s) => a + s.blue, 0) / scored.length) : null
  const detected = games.filter((r) => r.detected_at != null)
  const avgDetect = detected.length ? detected.reduce((a, r) => a + (r.detected_at ?? 0), 0) / detected.length : null

  const attack = async () => {
    const name = player.trim()
    if (!name) { setErr('Enter your name first.'); return }
    try { localStorage.setItem('xs-game-player', name) } catch {}
    setBusy(true); setErr('')
    const r = await fetch('/api/simulate', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ scenario: pick, duration: ROUND_S, player: name, game: true }) })
    const j = await r.json().catch(() => ({}))
    if (j.status !== 'success') setErr(j.error || 'could not start'); else setFast(true)
    setBusy(false)
  }

  return (
    <div className="space-y-6">
      <section className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)]">
        <Panel icon={Crosshair} title="Red team: your attack" sub={`Pick an attack and try to get past the firewall. Each round lasts ${ROUND_S} seconds.`}>
          <label className="block text-[12px] font-medium text-nd-dim" htmlFor="player">Your name</label>
          <input id="player" value={player} onChange={(e) => setPlayer(e.target.value.slice(0, 24))} placeholder="e.g. Lucas" className={`${btn.input} mt-1 w-56 py-1.5`} />
          <div className="mt-4 flex flex-wrap gap-2">
            {d.scenarios.map((s) => (
              <button key={s.id} type="button" onClick={() => setPick(s.id)} disabled={running}
                className={`rounded-lg border px-3 py-1.5 text-[12.5px] font-medium disabled:opacity-50 ${pick === s.id ? 'border-st-crit bg-st-crit text-white' : 'border-nd-line bg-nd-card text-nd-fg-3 hover:border-nd-line-strong hover:text-nd-fg'}`}>{s.label}</button>
            ))}
          </div>
          <div className="mt-4 flex items-center gap-3">
            <button type="button" onClick={attack} disabled={busy || running || !can('simulator.run')} className={`${btn.primary} !bg-st-crit !text-white`}>
              {busy || running ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />} {running ? 'Round in progress…' : 'Attack!'}
            </button>
            {!can('simulator.run') && <span className="text-[12px] text-nd-faint">Your group may watch, not play.</span>}
          </div>
          {err && <p className="mt-2 text-[12.5px] text-st-crit-fg">{err}</p>}
          <p className="mt-4 text-[11.5px] leading-relaxed text-nd-faint">
            Scoring: up to 40 points for every second before the firewall notices (4/s), up to 20 while it decides how to defend (2/s), up to 40 for the share of your packets that get through. Go undetected and you score 100. The packets are simulated inside the firewall: nothing leaves the box.
          </p>
        </Panel>

        <Panel icon={Shield} title="Blue team: the firewall" sub="How xdp-sentinel does against every player">
          <div className="grid grid-cols-3 gap-3">
            <Stat label="Rounds" value={String(games.length)} />
            <Stat label="Blue score" value={blueAvg == null ? '—' : `${blueAvg}`} sub="average / 100" />
            <Stat label="Notices in" value={avgDetect == null ? '—' : `${avgDetect.toFixed(1)} s`} sub="on average" />
          </div>
          {cur && cur.state === 'running' && (
            <div className="mt-4 rounded-xl border border-st-crit/30 bg-st-crit/[0.06] px-4 py-3 text-[13px]">
              <div className="flex items-center gap-2 font-semibold text-nd-fg"><Timer className="h-4 w-4 text-st-crit-fg" /> {cur.player} attacks with {cur.label}</div>
              <div className="mt-1 text-nd-fg-3">{cur.phase === 'attack' ? `Attacking… ${Math.min(cur.duration, Math.round(Date.now() / 1000 - cur.started_at))} / ${cur.duration} s` : 'Attack over, scoring…'}{cur.detected_at != null ? ` · firewall noticed after ${cur.detected_at.toFixed(1)} s` : ''}</div>
            </div>
          )}
          {last && lastScore && (
            <div className="mt-4 rounded-xl border border-nd-line bg-nd-panel px-4 py-3">
              <div className="text-[12px] text-nd-dim">Last round: {last.player} with {last.label}</div>
              <div className="mt-1 flex items-baseline gap-4">
                <span className="text-[28px] font-bold tabular-nums text-st-crit-fg">{lastScore.red}</span><span className="text-[12px] text-nd-faint">red</span>
                <span className="text-[28px] font-bold tabular-nums text-sky-500">{lastScore.blue}</span><span className="text-[12px] text-nd-faint">blue</span>
              </div>
              <div className="mt-1 text-[12px] text-nd-fg-3">
                {lastScore.missed ? 'The firewall never noticed: full points for red.' : `Noticed after ${last.detected_at?.toFixed(1)} s (+${lastScore.detect}), defended ${last.mitigated_at == null ? 'never' : `after ${last.mitigated_at.toFixed(1)} s`} (+${lastScore.defend}), ${Math.round(lastScore.throughShare * 100)}% got through (+${lastScore.through}).`}
              </div>
            </div>
          )}
        </Panel>
      </section>

      <Panel icon={Trophy} title="Leaderboard" sub="Best red score per player (higher = you beat the firewall more)" bodyClass="">
        {board.length === 0 ? <p className="px-5 pb-5 text-[13px] text-nd-faint">No rounds played yet.</p> : (
          <table className="w-full text-left text-[13px]">
            <thead className="text-[11px] uppercase tracking-[0.06em] text-nd-dim">
              <tr className="border-b border-nd-line">{['#', 'Player', 'Best', 'With', 'Average', 'Rounds'].map((h) => <th key={h} className="px-5 py-2 font-medium">{h}</th>)}</tr>
            </thead>
            <tbody className="divide-y divide-nd-line-soft">
              {board.map((p, i) => (
                <tr key={p.player}>
                  <td className="px-5 py-2 font-semibold text-nd-dim">{i === 0 ? '🥇' : i === 1 ? '🥈' : i === 2 ? '🥉' : i + 1}</td>
                  <td className="px-5 py-2 font-medium text-nd-fg">{p.player}</td>
                  <td className="px-5 py-2 text-[15px] font-bold tabular-nums text-st-crit-fg">{p.best}</td>
                  <td className="px-5 py-2 text-nd-fg-3">{p.bestWith}</td>
                  <td className="px-5 py-2 tabular-nums text-nd-fg-3">{p.avg}</td>
                  <td className="px-5 py-2 tabular-nums text-nd-fg-3">{p.runs}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  )
}

function Stat({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="rounded-xl border border-nd-line bg-nd-panel px-3 py-2">
      <div className="text-[10.5px] font-medium uppercase tracking-[0.06em] text-nd-dim">{label}</div>
      <div className="text-[20px] font-semibold tabular-nums text-nd-fg">{value}</div>
      {sub && <div className="text-[11px] text-nd-faint">{sub}</div>}
    </div>
  )
}
