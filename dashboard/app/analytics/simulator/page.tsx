'use client'
// Attack simulator: pick an attack, press start, and watch the system find and
// stop it live. The packets are injected straight into the running XDP program
// (BPF_PROG_RUN) by the root helper xs-simulate -- nothing goes on the wire --
// so detection and mitigation react exactly as they would to the real thing.
import { useEffect, useMemo, useState } from 'react'
import { FlaskConical, Play, Square, Loader2, CheckCircle2, XCircle, Clock, ShieldCheck, Radar, Gauge, History, AlertTriangle } from 'lucide-react'
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'
import { usePoll } from '@/hooks/usePoll'
import { si, pretty } from '@/lib/format'
import { flagName, levelName } from '@/lib/explain'
import { Panel, Badge, Empty, btn } from '@/components/aa/kit'
import { useMe } from '@/components/aa/Shell'

interface Scenario { id: string; label: string; what: string; group: string }
interface Point { t: number; pps: number; threat: number; risk: number; dropped: number }
interface Status {
  state: 'running' | 'done' | 'stopped' | 'error'; id: string; scenario: string; label: string; by: string; iface: string; duration: number
  started_at: number; attack_ends_at: number; ended_at: number | null; phase: 'attack' | 'recovery' | 'finished'
  sent: number; victim: string; sources: string
  live: { threat?: number; risk?: number; pps?: number; types?: string[]; flags?: string[] }
  timeline: Point[]; detected_at: number | null; classified_at: number | null; mitigated_at: number | null; recovered_at: number | null
  types: string[]; flags: string[]; peak_threat: number; peak_pps: number; dropped: number; error: string | null
}
type Run = Pick<Status, 'id' | 'scenario' | 'label' | 'by' | 'started_at' | 'state' | 'sent' | 'detected_at' | 'mitigated_at' | 'recovered_at' | 'types' | 'flags' | 'peak_pps' | 'dropped'>
interface Data { scenarios: Scenario[]; limits: { min: number; max: number }; current: Status | null; pending: { id: string; waitedSec: number } | null; history: Run[] }

const THREAT = ['Normal', 'Suspicious', 'Under attack']
const secs = (n: number | null | undefined) => (n == null ? '—' : `${n < 10 ? n.toFixed(1) : Math.round(n)} s`)
const when = (s: number) => new Date(s * 1000).toLocaleString([], { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })

export default function SimulatorPage() {
  const { can } = useMe()
  const [fast, setFast] = useState(false)
  const q = usePoll(async () => {
    const r = await fetch('/api/simulate', { cache: 'no-store' })
    const j = await r.json()
    if (j.status !== 'success') throw new Error(j.error || 'simulator unavailable')
    return j as Data
  }, fast ? 1000 : 5000, [fast])
  const d = q.data
  const cur = d?.current ?? null
  const running = cur?.state === 'running' || !!d?.pending
  useEffect(() => setFast(running), [running])

  const [pick, setPick] = useState('tcp-syn')
  const [dur, setDur] = useState(20)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const send = async (body: object) => {
    setBusy(true); setErr('')
    try {
      const r = await fetch('/api/simulate', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
      const j = await r.json()
      if (j.status !== 'success') throw new Error(j.error || 'failed')
      setFast(true)
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'failed')
    }
    setBusy(false)
  }

  if (!d) return q.error ? <Empty icon={FlaskConical} title="The simulator is unavailable" hint={q.error} /> : <div className="aa-skeleton h-64 rounded-2xl" />
  const groups = [...new Set(d.scenarios.map((s) => s.group))]
  const chosen = d.scenarios.find((s) => s.id === pick)
  const mayRun = can('simulator.run')
  const stuck = d.pending && d.pending.waitedSec > 15

  return (
    <div className="space-y-6">
      <Panel icon={FlaskConical} title="Start a simulated attack"
        sub="Synthetic attack packets are fed straight into the live firewall program: nothing is sent on the network, but detection and the defences react exactly as to a real attack.">
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-5">
          <div className="lg:col-span-3 space-y-4">
            {groups.map((g) => (
              <div key={g}>
                <div className="mb-1.5 text-[11px] font-medium uppercase tracking-[0.06em] text-nd-dim">{g}</div>
                <div className="flex flex-wrap gap-2">
                  {d.scenarios.filter((s) => s.group === g).map((s) => (
                    <button key={s.id} type="button" onClick={() => setPick(s.id)} disabled={running}
                      className={`rounded-lg border px-3 py-1.5 text-[12.5px] font-medium transition-colors disabled:opacity-50 ${pick === s.id ? 'border-nd-fg bg-nd-fg text-nd-bg' : 'border-nd-line bg-nd-card text-nd-fg-3 hover:border-nd-line-strong hover:text-nd-fg'}`}>
                      {s.label}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
          <div className="lg:col-span-2 rounded-xl border border-nd-line bg-nd-panel p-4">
            <div className="text-[15px] font-semibold text-nd-fg">{chosen?.label}</div>
            <p className="mt-1 text-[12.5px] leading-relaxed text-nd-fg-3">{chosen?.what}</p>
            <label className="mt-4 block text-[12px] font-medium text-nd-dim" htmlFor="sim-dur">Length: {dur} seconds</label>
            <input id="sim-dur" type="range" min={d.limits.min} max={d.limits.max} step={5} value={dur} onChange={(e) => setDur(Number(e.target.value))} disabled={running} className="mt-1 w-full accent-current" />
            <div className="mt-4 flex flex-wrap items-center gap-2">
              {running ? (
                <button type="button" onClick={() => send({ stop: true })} disabled={busy || !mayRun || !!d.pending} className={btn.ghost}>
                  {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Square className="h-4 w-4" />} Stop
                </button>
              ) : (
                <button type="button" onClick={() => send({ scenario: pick, duration: dur })} disabled={busy || !mayRun} className={btn.primary}>
                  {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />} Start simulation
                </button>
              )}
              {!mayRun && <span className="text-[12px] text-nd-faint">Your group may watch but not start simulations.</span>}
            </div>
            {err && <p className="mt-2 text-[12px] text-st-crit-fg">{err}</p>}
            <p className="mt-3 flex gap-1.5 text-[11.5px] leading-relaxed text-nd-faint">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              For about a minute the real defences switch on, as in a real attack. Your own LAN devices stay exempt. The attack it causes is labelled “Simulation” and left out of the attack totals.
            </p>
          </div>
        </div>
      </Panel>

      {d.pending && (
        <section className={`flex items-center gap-3 rounded-2xl border px-5 py-4 ${stuck ? 'border-st-warn/30 bg-st-warn/[0.07]' : 'border-nd-line bg-nd-card'}`}>
          {stuck ? <AlertTriangle className="h-5 w-5 text-st-warn-fg" /> : <Loader2 className="h-5 w-5 animate-spin text-nd-dim" />}
          <div className="text-[13px]">
            {stuck ? (
              <><span className="font-medium text-nd-fg">The simulator service hasn’t picked up the request.</span> <span className="text-nd-dim">Is it installed? On the server: <code className="rounded bg-nd-fill px-1">systemctl status xdp-sentinel-simulate.path</code></span></>
            ) : <span className="text-nd-fg">Starting…</span>}
          </div>
        </section>
      )}

      {cur && <Current s={cur} />}

      <Panel icon={History} title="Earlier simulations" sub="How quickly each one was spotted and stopped" bodyClass="">
        {d.history.length === 0 ? <p className="px-5 pb-5 text-[13px] text-nd-faint">None yet.</p> : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] text-left text-[13px]">
              <thead className="text-[11px] uppercase tracking-[0.06em] text-nd-dim">
                <tr className="border-b border-nd-line">
                  {['When', 'Attack', 'Detected', 'Defence on', 'Back to normal', 'Recognised as', 'Packets'].map((h) => <th key={h} className="px-5 py-2 font-medium">{h}</th>)}
                </tr>
              </thead>
              <tbody className="divide-y divide-nd-line-soft">
                {d.history.map((r) => (
                  <tr key={r.id}>
                    <td className="px-5 py-2 text-nd-dim">{when(r.started_at)}{r.by ? <span className="block text-[11px] text-nd-faint">{r.by}</span> : null}</td>
                    <td className="px-5 py-2 font-medium text-nd-fg">{r.label}{r.state !== 'done' && <span className="ml-1.5 text-[11px] text-nd-faint">({r.state})</span>}</td>
                    <td className="px-5 py-2">{r.detected_at == null ? <span className="text-st-crit-fg">missed</span> : secs(r.detected_at)}</td>
                    <td className="px-5 py-2">{secs(r.mitigated_at)}</td>
                    <td className="px-5 py-2">{secs(r.recovered_at)}</td>
                    <td className="px-5 py-2 text-nd-fg-3">{r.types.map(pretty).join(', ') || '—'}</td>
                    <td className="px-5 py-2 tabular-nums text-nd-fg-3">{si(r.sent)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  )
}

function Current({ s }: { s: Status }) {
  const [now, setNow] = useState(Date.now() / 1000)
  useEffect(() => {
    if (s.state !== 'running') return
    const t = setInterval(() => setNow(Date.now() / 1000), 250)
    return () => clearInterval(t)
  }, [s.state])
  const elapsed = (s.state === 'running' ? now : s.ended_at ?? now) - s.started_at
  const attackLen = s.phase === 'attack' ? s.duration : s.attack_ends_at - s.started_at
  const threat = s.live.threat ?? 0
  const steps = [
    { icon: Play, label: 'Attack started', at: 0 as number | null, hint: `${s.sources === 'spoofed' ? 'random spoofed senders' : 'synthetic senders'} → ${s.victim}` },
    { icon: Radar, label: 'Detected', at: s.detected_at, hint: 'the risk engine raised the alarm' },
    { icon: Gauge, label: 'Recognised', at: s.classified_at, hint: s.types.map(pretty).join(', ') || 'attack type named' },
    { icon: ShieldCheck, label: 'Defence switched on', at: s.mitigated_at, hint: s.flags.map(flagName).join(', ') || 'mitigations armed' },
    { icon: CheckCircle2, label: 'Back to normal', at: s.recovered_at, hint: 'defences lifted again' },
  ]
  const data = useMemo(() => s.timeline.map((p) => ({ ...p })), [s.timeline])
  const head = s.state === 'running'
    ? s.phase === 'attack' ? `Attacking… ${Math.min(Math.round(elapsed), s.duration)} / ${s.duration} s` : 'Attack over, watching the system stand down…'
    : s.state === 'error' ? 'The simulation failed' : s.detected_at == null ? 'Finished: the attack was NOT detected' : 'Finished: detected and handled'
  return (
    <Panel icon={FlaskConical} title={<span className="flex items-center gap-2">{s.label} {s.state === 'running' ? <Badge tone="bad">live</Badge> : <Badge tone={s.state === 'error' || s.detected_at == null ? 'bad' : 'good'}>{s.state}</Badge>}</span>}
      sub={`${head} · on ${s.iface}${s.by ? ` · started by ${s.by}` : ''}`}>
      {s.error && <p className="mb-3 rounded-lg bg-st-crit/[0.08] px-3 py-2 text-[12.5px] text-st-crit-fg">{s.error}</p>}
      {s.state === 'running' && s.phase === 'attack' && (
        <div className="mb-4 h-1.5 overflow-hidden rounded-full bg-nd-fill">
          <div className="h-full rounded-full bg-st-crit transition-[width] duration-300" style={{ width: `${Math.min(100, (elapsed / attackLen) * 100)}%` }} />
        </div>
      )}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Cell label="Packets injected" value={si(s.sent)} />
        <Cell label="Peak rate seen" value={`${si(s.peak_pps)} pps`} />
        <Cell label="Threat now" value={THREAT[threat] ?? `level ${threat}`} tone={threat >= 2 ? 'bad' : threat === 1 ? 'warn' : 'good'} />
        <Cell label="Defence level" value={`L${s.live.risk ?? 0}`} sub={levelName(s.live.risk ?? 0)} />
      </div>
      <ol className="mt-5 grid grid-cols-1 gap-2 sm:grid-cols-5">
        {steps.map((st, i) => {
          const done = st.at != null
          const missed = !done && s.state !== 'running' && i < 4
          const I = done ? st.icon : missed ? XCircle : Clock
          return (
            <li key={st.label} className={`rounded-xl border px-3 py-2.5 ${done ? 'border-st-good/30 bg-st-good/[0.06]' : missed ? 'border-st-crit/25 bg-st-crit/[0.05]' : 'border-nd-line bg-nd-panel'}`}>
              <div className="flex items-center gap-1.5 text-[12.5px] font-medium text-nd-fg">
                <I className={`h-4 w-4 ${done ? 'text-st-good-fg' : missed ? 'text-st-crit-fg' : 'text-nd-faint'}`} /> {st.label}
              </div>
              <div className="mt-0.5 text-[18px] font-semibold tabular-nums text-nd-fg">{done ? (i === 0 ? '0 s' : `+${secs(st.at)}`) : missed ? 'no' : '…'}</div>
              <div className="truncate text-[11px] text-nd-faint" title={st.hint}>{st.hint}</div>
            </li>
          )
        })}
      </ol>
      <div className="mt-5 h-[220px]">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
            <CartesianGrid stroke="var(--nd-line-soft, rgba(127,127,127,.15))" vertical={false} />
            <XAxis dataKey="t" type="number" domain={[0, 'dataMax']} tickFormatter={(v) => `${Math.round(v)} s`} tick={{ fontSize: 11 }} stroke="currentColor" opacity={0.5} />
            <YAxis yAxisId="pps" tickFormatter={(v) => si(v)} tick={{ fontSize: 11 }} width={44} stroke="currentColor" opacity={0.5} />
            <YAxis yAxisId="lvl" orientation="right" domain={[0, 5]} hide />
            <Tooltip formatter={(v: number, n: string) => (n === 'Packets/s' ? `${si(v)} pps` : v)} labelFormatter={(v) => `${Number(v).toFixed(1)} s`} />
            <Area yAxisId="pps" type="monotone" dataKey="pps" name="Packets/s" stroke="var(--s1)" fill="var(--s1)" fillOpacity={0.15} isAnimationActive={false} />
            <Area yAxisId="lvl" type="stepAfter" dataKey="risk" name="Defence level" stroke="var(--st-crit)" fill="none" isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <p className="mt-2 text-[11.5px] text-nd-faint">Blue: packets per second the firewall saw. Red line: the defence level (0 = pass everything, 5 = block the attack’s traffic).</p>
    </Panel>
  )
}

function Cell({ label, value, sub, tone }: { label: string; value: string; sub?: string; tone?: 'good' | 'warn' | 'bad' }) {
  const ink = tone === 'bad' ? 'text-st-crit-fg' : tone === 'warn' ? 'text-st-warn-fg' : 'text-nd-fg'
  return (
    <div className="rounded-xl border border-nd-line bg-nd-panel px-4 py-3">
      <div className="text-[11px] font-medium uppercase tracking-[0.06em] text-nd-dim">{label}</div>
      <div className={`mt-0.5 text-[20px] font-semibold tabular-nums ${ink}`}>{value}</div>
      {sub && <div className="text-[11.5px] text-nd-faint">{sub}</div>}
    </div>
  )
}
