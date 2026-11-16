'use client'
// Attack replay: step through one attack second by second. A slider (or Play)
// moves a cursor over the traffic; at the cursor you see the rate, how much was
// being dropped, the mitigation ladder level, the per-source cap and which
// defences were on, and a log of every change (detected, escalated, defence on…)
// that you can click to jump to. Needs Prometheus's raw data (kept ~15 days).
import { useEffect, useMemo, useRef, useState } from 'react'
import { Play, Pause, SkipBack, Clapperboard, Loader2 } from 'lucide-react'
import { rangeAbs, type RangeResult } from '@/lib/prom'
import { usePoll } from '@/hooks/usePoll'
import { si, pretty } from '@/lib/format'
import { LADDER, levelName, flagName } from '@/lib/explain'
import { Panel, Badge } from '@/components/aa/kit'
import type { Episode } from '@/lib/attacks'

interface Frame {
  t: number; rx: number; drop: number; rl: number; level: number; cap: number; det: number
  types: string[]; flags: string[]; lock: number; sources: number
}
interface Event { i: number; t: number; tone: 'bad' | 'warn' | 'good' | 'neutral'; text: string }

const WATCH = new Set(['drop_syn', 'drop_ack', 'drop_udp', 'drop_udp_strict', 'drop_udp_dns', 'drop_icmp', 'drop_fragments', 'drop_untracked', 'drop_ipv6_ext', 'global_rl', 'lockdown', 'auto_lockdown', 'syn_auth'])
const LEVEL_COLOR = ['var(--nd-fill-2)', 'var(--nd-fill-2)', 'var(--s1)', 'var(--st-warn)', '#f97316', 'var(--st-crit)']
const SPEEDS = [5, 20, 60]

function byTime(rs: RangeResult[]): Map<number, number> {
  const m = new Map<number, number>()
  for (const [t, v] of rs[0]?.values ?? []) m.set(Math.round(+t), parseFloat(v))
  return m
}
function labelsAt(rs: RangeResult[], label: string): Map<number, string[]> {
  const m = new Map<number, string[]>()
  for (const s of rs) {
    const name = s.metric[label]
    if (!name) continue
    for (const [t, v] of s.values) if (parseFloat(v) > 0) {
      const k = Math.round(+t)
      m.set(k, [...(m.get(k) ?? []), name])
    }
  }
  return m
}

function useReplay(a: Episode) {
  const s0 = Math.floor(a.start / 1000) - 30
  const e0 = Math.ceil(a.end / 1000) + 60
  const step = Math.max(5, Math.ceil((e0 - s0) / 600))
  return usePoll(async () => {
    const q = (e: string) => rangeAbs(e, s0, e0, step)
    const rw = `[${Math.max(15, step * 3)}s]`
    const [rx, drop, rl, level, cap, det, type, flags, lock, srcs] = await Promise.all([
      q(`sum(rate(xs_rx_packets_total${rw}))`),
      q(`sum(rate(xs_verdict_packets_total{verdict="drop"}${rw}))`),
      q(`sum(rate(xs_policy_event_packets_total{event="rate_limited"}${rw}))`),
      q('max(xs_risk_level)'),
      q('max(xs_mitigation_rate_pps)'),
      q('max(xs_detection_active)'),
      q('max by(type)(xs_detection_info)'),
      q('max by(flag)(xs_config_flag)'),
      q('max(xs_auto_lockdown_active)'),
      q('max(xs_attacker_sources)'),
    ])
    const M = { rx: byTime(rx), drop: byTime(drop), rl: byTime(rl), level: byTime(level), cap: byTime(cap), det: byTime(det), lock: byTime(lock), sources: byTime(srcs) }
    const types = labelsAt(type, 'type')
    const fl = labelsAt(flags, 'flag')
    const frames: Frame[] = []
    for (let t = s0; t <= e0; t += step) {
      const g = (m: Map<number, number>) => m.get(t) ?? 0
      frames.push({ t, rx: g(M.rx), drop: g(M.drop), rl: g(M.rl), level: Math.round(g(M.level)), cap: g(M.cap), det: g(M.det), types: types.get(t) ?? [], flags: fl.get(t) ?? [], lock: g(M.lock), sources: g(M.sources) })
    }
    return { frames, step, hasData: frames.some((f) => f.rx > 0) }
  }, 3_600_000, [a.id])
}

function eventsOf(frames: Frame[]): Event[] {
  const out: Event[] = []
  for (let i = 1; i < frames.length; i++) {
    const p = frames[i - 1], f = frames[i]
    const add = (tone: Event['tone'], text: string) => out.push({ i, t: f.t, tone, text })
    if (!p.det && f.det) add('bad', 'Attack detected')
    if (p.det && !f.det) add('good', 'Detection ended')
    const newTypes = f.types.filter((x) => !p.types.includes(x))
    if (newTypes.length) add('warn', `Classified as ${newTypes.map(pretty).join(', ')}`)
    if (f.level !== p.level) add(f.level > p.level ? 'warn' : 'neutral', `Ladder ${f.level > p.level ? 'up' : 'down'} to level ${f.level}: ${levelName(f.level)} (${LADDER[Math.max(0, Math.min(5, f.level))].does})`)
    if (Math.round(f.cap) !== Math.round(p.cap)) add(f.cap ? 'good' : 'neutral', f.cap ? `Per-source cap set to ${Math.round(f.cap).toLocaleString('en')} packets/s` : 'Per-source cap lifted')
    for (const x of f.flags) if (WATCH.has(x) && !p.flags.includes(x)) add('good', `Defence on: ${flagName(x)}`)
    for (const x of p.flags) if (WATCH.has(x) && !f.flags.includes(x)) add('neutral', `Defence off: ${flagName(x)}`)
    if (!p.lock && f.lock) add('bad', 'Auto-lockdown armed (default-deny)')
    if (p.lock && !f.lock) add('neutral', 'Auto-lockdown lifted')
  }
  return out
}

const clock = (t: number) => new Date(t * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
const rel = (s: number) => `${s < 0 ? '−' : '+'}${Math.floor(Math.abs(s) / 60)}:${String(Math.abs(s) % 60).padStart(2, '0')}`

export function Replay({ a, archived }: { a: Episode; archived: boolean }) {
  const q = useReplay(a)
  const frames = q.data?.frames ?? []
  const [i, setI] = useState(0)
  const [playing, setPlaying] = useState(false)
  const [speed, setSpeed] = useState(SPEEDS[1])
  const events = useMemo(() => eventsOf(frames), [frames])
  const logRef = useRef<HTMLOListElement | null>(null)

  // play: one frame every (step / speed) seconds of wall time
  useEffect(() => {
    if (!playing || !q.data) return
    const ms = Math.max(30, (q.data.step * 1000) / speed)
    const id = setInterval(() => setI((x) => {
      if (x >= frames.length - 1) { setPlaying(false); return x }
      return x + 1
    }), ms)
    return () => clearInterval(id)
  }, [playing, speed, q.data, frames.length])

  // keep the latest event in view in the log
  const lastEv = events.filter((e) => e.i <= i).length - 1
  useEffect(() => {
    const el = logRef.current?.children[Math.max(0, lastEv)] as HTMLElement | undefined
    el?.scrollIntoView({ block: 'nearest' })
  }, [lastEv])

  if (archived) {
    return (
      <Panel icon={Clapperboard} title="Replay" sub="Step through the attack second by second">
        <p className="text-[12.5px] text-nd-dim">Replay needs the raw second-by-second data, which Prometheus keeps for about 15 days. This attack is older, so only its saved totals are left.</p>
      </Panel>
    )
  }
  if (!q.data) {
    return (
      <Panel icon={Clapperboard} title="Replay" sub="Step through the attack second by second">
        <div className="flex items-center gap-2 text-[12.5px] text-nd-dim">{q.error ? `Couldn’t load the replay: ${q.error}` : <><Loader2 className="h-4 w-4 animate-spin" /> Loading…</>}</div>
      </Panel>
    )
  }
  if (!q.data.hasData) {
    return (
      <Panel icon={Clapperboard} title="Replay" sub="Step through the attack second by second">
        <p className="text-[12.5px] text-nd-dim">No traffic data was recorded for this window.</p>
      </Panel>
    )
  }

  const f = frames[Math.min(i, frames.length - 1)]
  const t0 = Math.floor(a.start / 1000)
  const max = Math.max(1, ...frames.map((x) => x.rx))
  const W = 1000, H = 120
  const x = (k: number) => (k / Math.max(1, frames.length - 1)) * W
  const y = (v: number) => H - (v / max) * (H - 6)
  const area = (key: 'rx' | 'drop') => `M0,${H} ${frames.map((fr, k) => `L${x(k).toFixed(1)},${y(fr[key]).toFixed(1)}`).join(' ')} L${W},${H} Z`
  const dropPct = f.rx > 0 ? Math.min(1, f.drop / f.rx) : 0
  const on = f.flags.filter((x) => WATCH.has(x))

  return (
    <Panel icon={Clapperboard} title="Replay" sub="Step through the attack second by second · click the chart or an event to jump">
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" onClick={() => { if (i >= frames.length - 1) setI(0); setPlaying((p) => !p) }}
          className="inline-flex h-8 w-8 items-center justify-center rounded-lg bg-nd-fg text-nd-bg" aria-label={playing ? 'Pause' : 'Play'}>
          {playing ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
        </button>
        <button type="button" onClick={() => { setI(0); setPlaying(false) }} className="inline-flex h-8 w-8 items-center justify-center rounded-lg border border-nd-line text-nd-fg-3 hover:text-nd-fg" aria-label="Back to the start">
          <SkipBack className="h-4 w-4" />
        </button>
        <div className="flex rounded-lg border border-nd-line p-0.5" role="group" aria-label="Speed">
          {SPEEDS.map((s) => (
            <button key={s} type="button" onClick={() => setSpeed(s)} className={`rounded-md px-2 py-0.5 text-[11.5px] font-medium ${speed === s ? 'bg-nd-fill-2 text-nd-fg' : 'text-nd-dim hover:text-nd-fg'}`}>{s}×</button>
          ))}
        </div>
        <div className="ml-auto text-right">
          <div className="mono text-[13px] font-semibold tabular-nums text-nd-fg">{clock(f.t)}</div>
          <div className="mono text-[11px] tabular-nums text-nd-dim">{rel(f.t - t0)} from the start</div>
        </div>
      </div>

      <div className="relative mt-3 select-none">
        <svg viewBox={`0 0 ${W} ${H + 14}`} preserveAspectRatio="none" className="h-[150px] w-full cursor-pointer"
          onClick={(e) => { const r = e.currentTarget.getBoundingClientRect(); setI(Math.round(((e.clientX - r.left) / r.width) * (frames.length - 1))) }}
          role="img" aria-label="Traffic (grey) and dropped traffic (red) over the attack">
          {frames.map((fr, k) => fr.det ? <rect key={k} x={x(k)} y={0} width={W / frames.length + 0.5} height={H} fill="var(--st-crit)" opacity={0.06} /> : null)}
          <path d={area('rx')} fill="var(--nd-dim)" opacity={0.25} />
          <path d={area('drop')} fill="var(--st-crit)" opacity={0.7} />
          {frames.map((fr, k) => <rect key={`l${k}`} x={x(k)} y={H + 4} width={W / frames.length + 0.5} height={10} fill={LEVEL_COLOR[Math.max(0, Math.min(5, fr.level))]} />)}
          <line x1={x(i)} x2={x(i)} y1={0} y2={H + 14} stroke="var(--nd-fg)" strokeWidth={2} vectorEffect="non-scaling-stroke" />
        </svg>
        <input type="range" min={0} max={frames.length - 1} value={i} onChange={(e) => { setI(+e.target.value); setPlaying(false) }}
          className="mt-1 w-full accent-current" aria-label="Replay position" />
        <div className="mt-0.5 flex justify-between text-[10.5px] text-nd-faint">
          <span>grey: all traffic · red: dropped · shaded: attack detected</span>
          <span>bar: mitigation ladder level</span>
        </div>
      </div>

      <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-5">
        <Cell label="Traffic" value={`${si(f.rx)} pps`} />
        <Cell label="Dropped" value={`${(dropPct * 100).toFixed(dropPct < 0.1 && dropPct > 0 ? 1 : 0)}%`} sub={`${si(f.drop)} pps`} />
        <Cell label="Ladder" value={`L${f.level}`} sub={levelName(f.level)} />
        <Cell label="Per-source cap" value={f.cap ? `${si(f.cap)} pps` : 'none'} />
        <Cell label="Attack sources" value={f.sources ? si(f.sources) : '—'} sub={f.types.length ? f.types.map(pretty).join(', ') : f.det ? 'detected' : 'not detected'} />
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-1.5">
        <span className="text-[11.5px] text-nd-dim">Defences on now:</span>
        {on.length ? on.map((x) => <Badge key={x} tone="good">{flagName(x)}</Badge>) : <span className="text-[11.5px] text-nd-faint">only the standing rules</span>}
        {f.lock > 0 && <Badge tone="bad">Auto-lockdown</Badge>}
      </div>

      <div className="mt-4">
        <div className="mb-1.5 text-[11px] font-medium uppercase tracking-[0.06em] text-nd-dim">What happened · {events.length} change{events.length === 1 ? '' : 's'}</div>
        {events.length === 0 ? (
          <p className="text-[12px] text-nd-faint">Nothing changed in the defences during this window.</p>
        ) : (
          <ol ref={logRef} className="max-h-[200px] space-y-0.5 overflow-y-auto pr-1">
            {events.map((ev, k) => (
              <li key={k}>
                <button type="button" onClick={() => { setI(ev.i); setPlaying(false) }}
                  className={`flex w-full items-baseline gap-3 rounded-md px-2 py-1 text-left text-[12.5px] transition-colors hover:bg-nd-fill ${ev.i <= i ? 'text-nd-fg-2' : 'text-nd-faint'} ${k === lastEv ? 'bg-nd-fill' : ''}`}>
                  <span className="mono w-12 shrink-0 tabular-nums text-nd-dim">{rel(ev.t - t0)}</span>
                  <span className={`h-1.5 w-1.5 shrink-0 translate-y-[-1px] rounded-full ${ev.tone === 'bad' ? 'bg-st-crit' : ev.tone === 'warn' ? 'bg-st-warn' : ev.tone === 'good' ? 'bg-st-good' : 'bg-nd-faint'}`} />
                  <span>{ev.text}</span>
                </button>
              </li>
            ))}
          </ol>
        )}
      </div>
    </Panel>
  )
}

function Cell({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="rounded-lg bg-nd-fill px-3 py-2">
      <div className="text-[10.5px] font-medium uppercase tracking-[0.06em] text-nd-dim">{label}</div>
      <div className="mono text-[15px] font-semibold tabular-nums text-nd-fg">{value}</div>
      {sub && <div className="truncate text-[11px] text-nd-faint">{sub}</div>}
    </div>
  )
}
