'use client'
import { useMemo, useState } from 'react'
import {
  BrainCircuit, Scale, Waypoints, Activity, ListChecks, FlaskConical, Layers, ShieldHalf, GraduationCap, Siren, Radar,
  CheckCircle2, AlertTriangle, Info,
} from 'lucide-react'
import { instantAt, rangeAbs, scalar, toSeries, type InstantResult, type RangeResult } from '@/lib/prom'
import { usePoll } from '@/hooks/usePoll'
import { pps, duration, si, pretty } from '@/lib/format'
import { SERIES, BarList } from '@/components/nd/ui'
import { TimeChart } from '@/components/nd/charts'
import { Panel, Stat, Badge, Empty, type Tone } from '@/components/aa/kit'
import { useRange } from '@/components/aa/Shell'

// AI security: what the risk engine and its detectors think, per interface,
// right now and across the selected window — the fused risk and mitigation
// ladder, which detectors fire and how often they agree with the rule engine
// (which decides the attack type), the experimental classifier, per-layer
// state, the defenses the engine armed, and the ML training pipeline.

const IFACE: Record<string, string> = { vlan10: 'VLAN10 · WAN', vlan20: 'VLAN20 · LAN' }
const ifaceName = (i: string) => IFACE[i] ?? i
const THREAT = ['Normal', 'Suspect', 'Under attack'] as const
const THREAT_TONE: Tone[] = ['good', 'warn', 'bad']
const LADDER = [
  { name: 'Pass', desc: 'Normal traffic, no action' },
  { name: 'Monitor', desc: 'Watching more closely' },
  { name: 'Sample', desc: 'Capturing packet samples' },
  { name: 'Rate-limit', desc: 'Per-source limit applied' },
  { name: 'Aggressive limit', desc: 'Tight per-source limit' },
  { name: 'Temporary block', desc: 'Offending traffic dropped' },
]
const LAYERS = ['l2', 'l3', 'l4', 'l7'] as const
const LAYER_NAME: Record<string, string> = { l2: 'L2 · link', l3: 'L3 · network', l4: 'L4 · transport', l7: 'L7 · application' }
const LAYER_STATE = ['Normal', 'Elevated', 'Attack'] as const
// Who controls each dataplane flag (from the agent's enforce() logic): the risk
// engine arms the "auto" ones under attack and lifts them afterwards; some
// operator baseline drops are also raised by the engine from ladder step 4;
// drop_syn/drop_ack are never automatic because they would kill live TCP.
const CONTROL: Record<string, { by: string; auto?: boolean; order: number }> = {
  ratelimit: { by: 'Risk engine', auto: true, order: 0 },
  global_rl: { by: 'Risk engine · step 4+', auto: true, order: 0 },
  drop_icmp: { by: 'Risk engine · step 4+', auto: true, order: 0 },
  drop_ipv6_ext: { by: 'Risk engine · step 4+', auto: true, order: 0 },
  drop_untracked: { by: 'Risk engine · step 4+', auto: true, order: 0 },
  drop_udp_strict: { by: 'Risk engine · step 5', auto: true, order: 0 },
  drop_malformed: { by: 'Operator · engine at step 4+', order: 1 },
  drop_bad_tcp_flags: { by: 'Operator · engine at step 4+', order: 1 },
  drop_fragments: { by: 'Operator · engine at step 4+', order: 1 },
  drop_udp: { by: 'Operator · engine at step 4+', order: 1 },
  drop_udp_dns: { by: 'Operator', order: 1 },
  conntrack: { by: 'Always on', order: 2 },
  check_allow: { by: 'Allow/deny lists', order: 3 },
  check_policy: { by: 'Allow/deny lists', order: 3 },
  drop_syn: { by: 'Manual only', order: 4 },
  drop_ack: { by: 'Manual only', order: 4 },
  sampling: { by: 'Telemetry', order: 5 },
  hll: { by: 'Telemetry', order: 5 },
  dport_hist: { by: 'Telemetry', order: 5 },
}
const control = (f: string) => CONTROL[f] ?? { by: 'Other', order: 6 }
const FLAG_DESC: Record<string, string> = {
  drop_malformed: 'Drop malformed frames', drop_bad_tcp_flags: 'Drop illegal TCP flag combos', drop_fragments: 'Drop IP fragments',
  drop_udp_dns: 'Drop UDP DNS responses', drop_udp: 'Drop UDP', check_allow: 'Allowlist (exempts the management network)',
  check_policy: 'Deny/allow policy lists', ratelimit: 'Per-source rate limiter', sampling: 'Packet sampling',
  hll: 'Distinct-source counting', dport_hist: 'Destination-port histogram', global_rl: 'Global rate limit',
  drop_icmp: 'Drop ICMP', drop_syn: 'Drop excess SYN', drop_ack: 'Drop bare ACK', drop_udp_strict: 'Strict UDP drop',
  conntrack: 'Connection tracking', drop_untracked: 'Drop untracked TCP', drop_ipv6_ext: 'Drop IPv6 extension headers',
}

// Detectors and the score at which each counts as "firing". The rule engine is
// the reference: it is deterministic and is what labels and mitigates attacks.
type SeriesKey = 'det' | 'risk' | 'zraw' | 'ddos' | 'iforest'
const DETECTORS: { key: SeriesKey; label: string; sub: string; thr: number; fmt: (v: number) => string }[] = [
  { key: 'det', label: 'Rule engine', sub: 'Traffic-shape rules · sets the attack type', thr: 0.5, fmt: (v) => (v > 0 ? 'attack' : 'clear') },
  { key: 'risk', label: 'Fused risk', sub: 'All detectors combined, 0–1', thr: 0.5, fmt: (v) => v.toFixed(2) },
  { key: 'zraw', label: 'Statistical z-score', sub: 'Deviation from the learned baseline', thr: 8, fmt: (v) => (v >= 1000 ? si(v) : v.toFixed(1)) },
  { key: 'ddos', label: 'DDoS model', sub: 'Classifier’s top attack probability', thr: 0.5, fmt: (v) => v.toFixed(2) },
  { key: 'iforest', label: 'Isolation forest', sub: 'Unsupervised outlier score', thr: 0.6, fmt: (v) => v.toFixed(2) },
]

interface IfState {
  risk: number; level: number; threat: number; z: number; z01: number; ddos: number; iforest: number | null
  det: boolean; mit: boolean; mitRate: number; pps: number; types: string[]
  layers: Record<string, number>; layerDets: { layer: string; type: string }[]
  classes: { c: string; p: number }[]; flags: Record<string, number>
}
const blank = (): IfState => ({
  risk: 0, level: 0, threat: 0, z: 0, z01: 0, ddos: 0, iforest: null, det: false, mit: false, mitRate: 0, pps: 0,
  types: [], layers: {}, layerDets: [], classes: [], flags: {},
})
function byIface(rows: InstantResult[]): Record<string, IfState> {
  const out: Record<string, IfState> = {}
  for (const r of rows) {
    const i = r.metric.iface ?? '_'
    const s = (out[i] ??= blank())
    const v = parseFloat(r.value[1])
    switch (r.metric.__name__) {
      case 'xs_risk': s.risk = v; break
      case 'xs_risk_level': s.level = Math.round(v); break
      case 'xs_threat_state': s.threat = Math.round(v); break
      case 'xs_anomaly_score': s.z = v; break
      case 'xs_anomaly_score01': s.z01 = v; break
      case 'xs_ddos_score': s.ddos = v; break
      case 'xs_anomaly_iforest': s.iforest = v; break
      case 'xs_detection_active': s.det = v > 0; break
      case 'xs_mitigation_active': s.mit = v > 0; break
      case 'xs_mitigation_rate_pps': s.mitRate = v; break
      case 'xs_analysis_pps': s.pps = v; break
      case 'xs_detection_info': if (r.metric.type) s.types.push(r.metric.type); break
      case 'xs_layer_state': s.layers[r.metric.layer] = Math.round(v); break
      case 'xs_layer_detection': s.layerDets.push({ layer: r.metric.layer, type: r.metric.type }); break
      case 'xs_ddos_class_probability': s.classes.push({ c: r.metric.class, p: v }); break
      case 'xs_config_flag': s.flags[r.metric.flag] = v; break
    }
  }
  return out
}

function Ring({ value, tone }: { value: number; tone: Tone }) {
  const r = 34, c = 2 * Math.PI * r
  const v = Math.max(0, Math.min(1, value))
  const stroke = { good: 'var(--st-good)', warn: 'var(--st-warn)', bad: 'var(--st-crit)', neutral: 'var(--st-neutral)', brand: 'var(--nd-brand)' }[tone]
  return (
    <div className="relative h-[88px] w-[88px] shrink-0">
      <svg viewBox="0 0 88 88" className="h-full w-full -rotate-90">
        <circle cx="44" cy="44" r={r} fill="none" stroke="var(--nd-track)" strokeWidth="7" />
        <circle cx="44" cy="44" r={r} fill="none" stroke={stroke} strokeWidth="7" strokeLinecap="round" strokeDasharray={`${c * v} ${c}`} className="transition-[stroke-dasharray] duration-700" />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="mono text-[19px] font-semibold leading-none text-nd-fg">{v.toFixed(2)}</span>
        <span className="mt-0.5 text-[9.5px] uppercase tracking-[0.12em] text-nd-dim">risk</span>
      </div>
    </div>
  )
}

// Event lanes: one row per signal across the window, coloured where active.
// Hovering reads out the time and every lane's value at that point.
function Lanes({ t, lanes }: {
  t: number[]
  lanes: { label: string; v: (number | null)[]; color: (v: number) => string | null; fmt: (v: number) => string }[]
}) {
  const [h, setH] = useState<number | null>(null)
  if (t.length < 2) return <div className="aa-skeleton h-[118px] rounded-xl" />
  const at = (i: number) => new Date(t[i] * 1000).toLocaleString([], { weekday: 'short', hour: '2-digit', minute: '2-digit' })
  return (
    <div>
      <div className="mb-2 flex h-5 items-center gap-3 text-[12px] text-nd-dim">
        {h != null ? (
          <>
            <span className="mono text-nd-fg-2">{at(h)}</span>
            {lanes.map((l) => (
              <span key={l.label}>{l.label}: <span className="text-nd-fg-2">{l.v[h] == null ? '—' : l.fmt(l.v[h] as number)}</span></span>
            ))}
          </>
        ) : (
          'Hover the lanes to read a moment'
        )}
      </div>
      <div className="space-y-1.5" onMouseLeave={() => setH(null)}>
        {lanes.map((l) => (
          <div key={l.label} className="flex items-center gap-3">
            <span className="w-24 shrink-0 text-right text-[12px] text-nd-muted">{l.label}</span>
            <div className="flex h-6 flex-1 overflow-hidden rounded-md bg-nd-track">
              {l.v.map((v, i) => (
                <div
                  key={i}
                  onMouseEnter={() => setH(i)}
                  className={`h-full flex-1 ${h === i ? 'opacity-70' : ''}`}
                  style={{ background: v == null ? 'transparent' : l.color(v) ?? 'transparent' }}
                />
              ))}
            </div>
          </div>
        ))}
      </div>
      <div className="mt-1.5 flex justify-between pl-[108px] text-[11px] text-nd-faint">
        <span>{at(0)}</span>
        <span>{at(Math.floor(t.length / 2))}</span>
        <span>now</span>
      </div>
    </div>
  )
}

export default function AISecurity() {
  const rng = useRange()

  const live = usePoll(async () => {
    const now = Math.floor(Date.now() / 1000)
    const [ai, coll, cumW, cumS] = await Promise.all([
      instantAt('{__name__=~"xs_(risk|risk_level|threat_state|anomaly_score|anomaly_score01|ddos_score|anomaly_iforest|detection_active|mitigation_active|mitigation_rate_pps|analysis_pps|layer_state|layer_detection|detection_info|ddos_class_probability|config_flag)"}', now),
      instantAt('{__name__=~"xs_collector_(up|windows_total|suspect_windows_total)"}', now),
      // xs_collector_*_total is an in-memory counter that resets to 0 each time
      // the collector restarts (e.g. on reboot). sum(increase(..)) is reset-aware,
      // so it reports every window collected across restarts — the real lifetime
      // total — bounded only by TSDB retention.
      instantAt('sum(increase(xs_collector_windows_total[1y]))', now),
      instantAt('sum(increase(xs_collector_suspect_windows_total[1y]))', now),
    ])
    const c = (n: string) => coll.filter((r) => r.metric.__name__ === n).reduce((a, r) => a + parseFloat(r.value[1]), 0)
    const sinceBoot = c('xs_collector_windows_total')
    const sinceBootSuspect = c('xs_collector_suspect_windows_total')
    // lifetime is never below the current run; guard against an empty range query.
    const windows = Math.max(Math.round(scalar(cumW, 0) ?? 0), sinceBoot)
    const suspect = Math.max(Math.round(scalar(cumS, 0) ?? 0), sinceBootSuspect)
    return {
      ifaces: byIface(ai),
      collector: { up: coll.some((r) => r.metric.__name__ === 'xs_collector_up' && parseFloat(r.value[1]) > 0), windows, suspect, sinceBoot, sinceBootSuspect, seen: coll.length > 0 },
    }
  }, 10_000)

  const hist = usePoll(async () => {
    const w = rng.resolve()
    const R = `${w.span}s`
    const mx = (m: string) => rangeAbs(`max(max_over_time(${m}[${w.rw}]))`, w.start, w.end, w.step)
    const [det, risk, zraw, z01, ddos, iforest, mit, lvl, acts, wins] = await Promise.all([
      mx('xs_detection_active'), mx('xs_risk'), mx('xs_anomaly_score'), mx('xs_anomaly_score01'), mx('xs_ddos_score'),
      mx('xs_anomaly_iforest'), mx('xs_mitigation_active'), mx('xs_risk_level'),
      instantAt(`sum(increase(xs_auto_actions_total[${R}]))`, w.end),
      instantAt(`sum(increase(xs_collector_windows_total[${R}]))`, w.end),
    ])
    // align every series on the same timestamps
    const t: number[] = []
    for (let x = w.start; x <= w.end; x += w.step) t.push(x)
    const align = (r: RangeResult[]) => {
      const m = new Map((r[0]?.values ?? []).map(([ts, v]) => [Math.round(ts), parseFloat(v)]))
      return t.map((x) => m.get(x) ?? null)
    }
    return {
      w, t,
      s: { det: align(det), risk: align(risk), zraw: align(zraw), z01: align(z01), ddos: align(ddos), iforest: align(iforest), mit: align(mit), lvl: align(lvl) },
      chart: toSeries([
        ...risk.map((s) => ({ metric: { k: 'risk' }, values: s.values })),
        ...z01.map((s) => ({ metric: { k: 'z01' }, values: s.values })),
        ...ddos.map((s) => ({ metric: { k: 'ddos' }, values: s.values })),
        ...iforest.map((s) => ({ metric: { k: 'iforest' }, values: s.values })),
      ], (m) => m.k),
      actions: scalar(acts, 0)!,
      windowsAdded: scalar(wins, 0)!,
    }
  }, rng.refreshMs, [rng.key])

  const L = live.data
  const H = hist.data
  const ifs = Object.entries(L?.ifaces ?? {}).filter(([k]) => k !== '_').sort(([a], [b]) => a.localeCompare(b))
  const all = ifs.map(([, s]) => s)
  const maxOf = (f: (s: IfState) => number) => (all.length ? Math.max(...all.map(f)) : 0)

  // current consensus across detectors (worst interface)
  const nowVals: Record<SeriesKey, number> = {
    det: all.some((s) => s.det) ? 1 : 0, risk: maxOf((s) => s.risk), zraw: maxOf((s) => s.z), ddos: maxOf((s) => s.ddos), iforest: maxOf((s) => s.iforest ?? 0),
  }
  const firingNow = DETECTORS.filter((d) => nowVals[d.key] >= d.thr)
  const ruleOn = nowVals.det > 0
  const verdict = !L
    ? null
    : ruleOn
      ? { tone: 'bad' as Tone, icon: Siren, text: `Confirmed attack: the rule engine detects ${all.flatMap((s) => s.types).map(pretty).join(', ') || 'an attack'}${firingNow.length > 1 ? `, backed by ${firingNow.length - 1} other detector${firingNow.length > 2 ? 's' : ''}` : ''}.` }
      : firingNow.length
        ? { tone: 'warn' as Tone, icon: AlertTriangle, text: `${firingNow.map((d) => d.label).join(' and ')} ${firingNow.length === 1 ? 'is' : 'are'} elevated, but the rule engine sees no attack — likely a traffic burst rather than a flood.` }
        : { tone: 'good' as Tone, icon: CheckCircle2, text: 'All detectors are quiet. Traffic matches the learned baseline.' }

  // detector performance over the window, against the rule engine as reference
  const perf = useMemo(() => {
    if (!H) return []
    const det = H.s.det.map((v) => (v ?? 0) > 0)
    const detSec = det.filter(Boolean).length * H.w.step
    let episodes = 0
    det.forEach((on, i) => { if (on && !det[i - 1]) episodes++ })
    return DETECTORS.map((d) => {
      const vals = H.s[d.key]
      const fire = vals.map((v) => v != null && v >= d.thr)
      const n = fire.filter(Boolean).length
      const both = fire.filter((f, i) => f && det[i]).length
      const peak = Math.max(0, ...vals.filter((v): v is number => v != null))
      return {
        ...d,
        firingSec: n * H.w.step,
        agree: n ? both / n : null, // share of firing time inside confirmed attacks
        recall: det.some(Boolean) ? both / det.filter(Boolean).length : null, // share of attack time it caught
        unconfirmedSec: (n - both) * H.w.step,
        peak: vals.some((v) => v != null) ? peak : null,
        episodes: d.key === 'det' ? episodes : undefined,
        detSec,
      }
    })
  }, [H])

  // classifier: worst interface per class
  const classes = useMemo(() => {
    const m = new Map<string, number>()
    for (const s of all) for (const { c, p } of s.classes) m.set(c, Math.max(m.get(c) ?? 0, p))
    return [...m.entries()].map(([c, p]) => ({ label: pretty(c), v: p })).sort((a, b) => b.v - a.v)
  }, [all])
  const ruleTypes = Array.from(new Set(all.flatMap((s) => s.types)))
  const flagNames = Array.from(new Set(all.flatMap((s) => Object.keys(s.flags)))).sort((a, b) => control(a).order - control(b).order || a.localeCompare(b))
  const autoOn = all.reduce((n, s) => n + Object.entries(s.flags).filter(([f, v]) => v > 0 && control(f).auto).length, 0)
  const loading = !L

  return (
    <div className="space-y-6">
      {live.error && !L && (
        <div className="flex items-center gap-2 rounded-xl border border-st-crit/30 bg-st-crit/[0.06] px-4 py-3 text-[13px] text-st-crit-fg">
          <AlertTriangle className="h-4 w-4" /> Can&apos;t load the risk engine: {live.error}
        </div>
      )}

      {/* verdict */}
      {verdict ? (
        <div className={`aa-in flex items-start gap-3 rounded-2xl border px-5 py-4 shadow-nd ${verdict.tone === 'bad' ? 'border-st-crit/30 bg-st-crit/[0.06]' : verdict.tone === 'warn' ? 'border-st-warn/30 bg-st-warn/[0.07]' : 'border-st-good/25 bg-st-good/[0.06]'}`}>
          <verdict.icon className={`mt-0.5 h-5 w-5 shrink-0 ${verdict.tone === 'bad' ? 'text-st-crit-fg' : verdict.tone === 'warn' ? 'text-st-warn-fg' : 'text-st-good-fg'}`} />
          <div>
            <p className="text-[14.5px] font-semibold text-nd-fg">{verdict.text}</p>
            <p className="mt-0.5 text-[12.5px] text-nd-dim">{firingNow.length} of {DETECTORS.length} detectors firing · updated every 10 s</p>
          </div>
        </div>
      ) : (
        <div className="aa-skeleton h-[72px] rounded-2xl" />
      )}

      {/* per-interface assessment + consensus */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        {(loading ? [['vlan10', blank()], ['vlan20', blank()]] as [string, IfState][] : ifs).map(([name, s]) => {
          const tone: Tone = s.risk >= 0.75 ? 'bad' : s.risk >= 0.4 ? 'warn' : 'good'
          return (
            <Panel key={name} icon={BrainCircuit} title={ifaceName(name)} sub="Risk engine assessment">
              {loading ? (
                <div className="aa-skeleton h-[150px] rounded-xl" />
              ) : (
                <div className="flex gap-4">
                  <Ring value={s.risk} tone={tone} />
                  <div className="min-w-0 flex-1 space-y-2 text-[13px]">
                    <div className="flex flex-wrap gap-1.5">
                      <Badge tone={THREAT_TONE[s.threat] ?? 'neutral'}>{THREAT[s.threat] ?? `state ${s.threat}`}</Badge>
                      <Badge tone={s.level >= 3 ? 'bad' : s.level >= 1 ? 'warn' : 'good'}>Step {s.level} · {LADDER[s.level]?.name ?? '?'}</Badge>
                    </div>
                    <p className="text-nd-muted">
                      {s.types.length ? <>Detected <span className="font-medium text-st-crit-fg">{s.types.map(pretty).join(', ')}</span></> : 'No attack detected'}
                    </p>
                    <p className="text-nd-muted">
                      Mitigation <span className="font-medium text-nd-fg-2">{s.mit ? `active · ${s.mitRate > 0 ? `limit ${pps(s.mitRate)}` : 'armed'}` : 'standby'}</span>
                    </p>
                    <p className="mono text-[12px] text-nd-dim">z {s.z >= 1000 ? si(s.z) : s.z.toFixed(1)} · ddos {s.ddos.toFixed(2)} · iforest {s.iforest == null ? '—' : s.iforest.toFixed(2)} · {pps(s.pps)}</p>
                  </div>
                </div>
              )}
            </Panel>
          )
        })}
        <Panel icon={Scale} title="Detector consensus" sub="Firing now, worst interface">
          <ul className="space-y-2">
            {DETECTORS.map((d) => {
              const v = nowVals[d.key]
              const on = !loading && v >= d.thr
              return (
                <li key={d.key} className="flex items-center justify-between gap-3 text-[13px]">
                  <span className="flex min-w-0 items-center gap-2">
                    <span className={`h-2 w-2 shrink-0 rounded-full ${loading ? 'bg-st-neutral' : on ? (d.key === 'det' ? 'bg-st-crit' : 'bg-st-warn') : 'bg-st-good'}`} />
                    <span className="truncate text-nd-fg-2">{d.label}</span>
                  </span>
                  <span className="mono shrink-0 text-[12px] text-nd-dim">
                    {loading ? '…' : d.fmt(v)} <span className="text-nd-faint">/ {d.key === 'det' ? 'rule' : d.thr}</span>
                  </span>
                </li>
              )
            })}
          </ul>
          <p className="mt-3 border-t border-nd-line-soft pt-3 text-[12px] leading-relaxed text-nd-dim">A detector fires when its score passes the threshold shown. The rule engine is the reference: it labels attacks and drives mitigation.</p>
        </Panel>
      </div>

      {/* mitigation ladder */}
      <Panel icon={Waypoints} title="Mitigation ladder" sub="How far each interface has escalated · the engine steps up under sustained risk and back down when it clears">
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
          {LADDER.map((step, n) => {
            const here = ifs.filter(([, s]) => s.level === n)
            return (
              <div key={step.name} className={`rounded-xl border p-3 transition-colors ${here.length ? 'border-nd-line-strong bg-nd-card shadow-nd' : 'border-nd-line bg-nd-fill'}`}>
                <div className="flex items-center gap-2">
                  <span className="grid h-6 w-6 place-items-center rounded-md text-[12px] font-semibold text-nd-fg" style={{ background: `var(--lv${n})` }}>{n}</span>
                  <span className="text-[13px] font-medium text-nd-fg-2">{step.name}</span>
                </div>
                <p className="mt-1.5 text-[11.5px] leading-snug text-nd-dim">{step.desc}</p>
                <div className="mt-2 flex min-h-[20px] flex-wrap gap-1">
                  {here.map(([i]) => <Badge key={i} tone={n >= 3 ? 'bad' : n >= 1 ? 'warn' : 'brand'}>{i === 'vlan10' ? 'WAN' : i === 'vlan20' ? 'LAN' : i}</Badge>)}
                </div>
              </div>
            )
          })}
        </div>
      </Panel>

      {/* timeline */}
      <div className="grid grid-cols-1 gap-6 2xl:grid-cols-2">
        <Panel icon={Activity} title="Event timeline" sub={`Detection, mitigation and ladder step · ${rng.label}`}>
          <Lanes
            t={H?.t ?? []}
            lanes={[
              { label: 'Detection', v: H?.s.det ?? [], color: (v) => (v > 0 ? 'var(--st-crit)' : null), fmt: (v) => (v > 0 ? 'attack' : 'clear') },
              { label: 'Mitigation', v: H?.s.mit ?? [], color: (v) => (v > 0 ? 'var(--st-warn)' : null), fmt: (v) => (v > 0 ? 'active' : 'off') },
              { label: 'Ladder step', v: H?.s.lvl ?? [], color: (v) => (v >= 0.5 ? `var(--lv${Math.min(5, Math.round(v))})` : null), fmt: (v) => `${Math.round(v)} · ${LADDER[Math.min(5, Math.round(v))]?.name}` },
            ]}
          />
          <div className="mt-4 grid grid-cols-3 gap-3 border-t border-nd-line-soft pt-4 text-[12.5px]">
            <div><div className="text-nd-dim">Attack time</div><div className="mono mt-0.5 text-[15px] font-semibold text-nd-fg">{H ? duration(perf[0]?.detSec ?? 0) : '—'}</div></div>
            <div><div className="text-nd-dim">Episodes</div><div className="mono mt-0.5 text-[15px] font-semibold text-nd-fg">{H ? perf[0]?.episodes ?? 0 : '—'}</div></div>
            <div><div className="text-nd-dim">Automatic actions</div><div className="mono mt-0.5 text-[15px] font-semibold text-nd-fg">{H ? Math.round(H.actions).toLocaleString('en-US') : '—'}</div></div>
          </div>
        </Panel>
        <Panel icon={Radar} title="Detector scores" sub="All on a 0–1 scale">
          <TimeChart
            loading={!H}
            data={H?.chart ?? []}
            series={[
              { key: 'risk', label: 'Fused risk', color: SERIES[1] },
              { key: 'z01', label: 'Z-score (0–1)', color: SERIES[0] },
              { key: 'ddos', label: 'DDoS model', color: SERIES[3] },
              { key: 'iforest', label: 'Isolation forest', color: SERIES[2] },
            ]}
            yfmt={(n) => n.toFixed(2)}
            yDomain={[0, 1]}
            spanMs={(H?.w.span ?? 3600) * 1000}
            height={230}
          />
        </Panel>
      </div>

      {/* detector performance */}
      <Panel icon={ListChecks} title="Detector performance" sub={`How each detector behaved over ${rng.label}, measured against the rule engine`} bodyClass="">
        {!H ? (
          <div className="space-y-2 px-5 pb-5">{[0, 1, 2, 3, 4].map((i) => <div key={i} className="aa-skeleton h-9 rounded-lg" />)}</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[820px] text-left text-[13px]">
              <thead>
                <tr className="border-y border-nd-line bg-nd-fill text-[11px] uppercase tracking-[0.06em] text-nd-dim">
                  <th className="py-2 pl-5 pr-3 font-medium">Detector</th>
                  <th className="px-3 py-2 text-right font-medium">Threshold</th>
                  <th className="px-3 py-2 text-right font-medium">Peak</th>
                  <th className="px-3 py-2 text-right font-medium">Time firing</th>
                  <th className="px-3 py-2 text-right font-medium" title="Share of its firing time that fell inside a confirmed attack">Agrees with rules</th>
                  <th className="px-3 py-2 text-right font-medium" title="Share of confirmed attack time during which it was also firing">Caught</th>
                  <th className="py-2 pl-3 pr-5 text-right font-medium" title="Firing while the rule engine saw no attack">Unconfirmed</th>
                </tr>
              </thead>
              <tbody>
                {perf.map((p) => (
                  <tr key={p.key} className="border-b border-nd-line-soft last:border-0">
                    <td className="py-3 pl-5 pr-3">
                      <div className="font-medium text-nd-fg">{p.label}{p.key === 'det' && <Badge tone="brand" className="ml-2">reference</Badge>}</div>
                      <div className="text-[12px] text-nd-dim">{p.sub}</div>
                    </td>
                    <td className="mono px-3 py-3 text-right text-nd-dim">{p.key === 'det' ? '—' : p.thr}</td>
                    <td className="mono px-3 py-3 text-right text-nd-fg-3">{p.peak == null ? 'no data' : p.fmt(p.peak)}</td>
                    <td className="mono px-3 py-3 text-right text-nd-fg-2">{duration(p.firingSec)}{p.key === 'det' && p.episodes ? <span className="text-nd-dim"> · {p.episodes} ep.</span> : null}</td>
                    <td className="px-3 py-3 text-right">
                      {p.key === 'det' ? <span className="text-nd-faint">—</span> : p.agree == null ? <span className="text-[12px] text-nd-faint">never fired</span> : <Badge tone={p.agree >= 0.8 ? 'good' : p.agree >= 0.4 ? 'warn' : 'bad'}>{(p.agree * 100).toFixed(0)}%</Badge>}
                    </td>
                    <td className="px-3 py-3 text-right">
                      {p.key === 'det' ? <span className="text-nd-faint">—</span> : p.recall == null ? <span className="text-[12px] text-nd-faint">no attacks</span> : <Badge tone={p.recall >= 0.8 ? 'good' : p.recall >= 0.4 ? 'warn' : 'bad'}>{(p.recall * 100).toFixed(0)}%</Badge>}
                    </td>
                    <td className="mono py-3 pl-3 pr-5 text-right text-nd-fg-3">{p.key === 'det' ? '—' : p.unconfirmedSec ? duration(p.unconfirmedSec) : '0s'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="flex items-start gap-2 border-t border-nd-line px-5 py-3 text-[12px] leading-relaxed text-nd-dim">
              <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              High “unconfirmed” time means a detector reacts to bursts the rules don’t treat as attacks — candidates for false positives. Low “caught” means it misses real floods.
            </p>
          </div>
        )}
      </Panel>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        {/* classifier */}
        <Panel icon={FlaskConical} title="DDoS classifier" sub="Per-class probability, worst interface" actions={<Badge tone="warn">Experimental</Badge>}>
          {loading ? (
            <div className="aa-skeleton h-[160px] rounded-xl" />
          ) : classes.length ? (
            <>
              <BarList rows={classes.slice(0, 7)} fmt={(n) => `${(n * 100).toFixed(0)}%`} color={SERIES[3]} />
              <p className="mt-4 rounded-lg bg-nd-fill px-3 py-2 text-[12px] leading-relaxed text-nd-dim">
                Trained on synthetic data, so it often mislabels real floods (e.g. a SYN flood as “connection flood”). Only its score feeds the fused risk; the attack type comes from the rule engine
                {ruleTypes.length ? <> — which currently says <span className="font-medium text-nd-fg-2">{ruleTypes.map(pretty).join(', ')}</span></> : ''}.
              </p>
            </>
          ) : (
            <Empty icon={FlaskConical} title="No classifier output" hint="The model only reports while the agent is analysing traffic." />
          )}
        </Panel>

        {/* layers */}
        <Panel icon={Layers} title="Layer analysis" sub="Per-layer detection state">
          {loading ? (
            <div className="aa-skeleton h-[160px] rounded-xl" />
          ) : (
            <>
              <table className="w-full text-[13px]">
                <thead className="text-[11px] uppercase tracking-[0.06em] text-nd-dim">
                  <tr><th className="pb-2 text-left font-medium">Layer</th>{ifs.map(([i]) => <th key={i} className="pb-2 text-right font-medium">{i === 'vlan10' ? 'WAN' : i === 'vlan20' ? 'LAN' : i}</th>)}</tr>
                </thead>
                <tbody>
                  {LAYERS.map((l) => (
                    <tr key={l} className="border-t border-nd-line-soft">
                      <td className="py-2 text-nd-fg-2">{LAYER_NAME[l]}</td>
                      {ifs.map(([i, s]) => {
                        const v = s.layers[l] ?? 0
                        return <td key={i} className="py-2 text-right"><Badge tone={v >= 2 ? 'bad' : v === 1 ? 'warn' : 'good'}>{LAYER_STATE[v] ?? v}</Badge></td>
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="mt-3 space-y-1">
                {all.flatMap((s) => s.layerDets).length ? (
                  ifs.flatMap(([i, s]) => s.layerDets.map((d) => (
                    <p key={`${i}${d.layer}${d.type}`} className="text-[12.5px] text-nd-muted"><span className="font-medium text-st-crit-fg">{pretty(d.type)}</span> on {LAYER_NAME[d.layer] ?? d.layer} · {ifaceName(i)}</p>
                  )))
                ) : (
                  <p className="text-[12.5px] text-nd-dim">No layer reports an active attack.</p>
                )}
              </div>
            </>
          )}
        </Panel>

        {/* learning pipeline */}
        <Panel icon={GraduationCap} title="Learning pipeline" sub="Feature windows collected for training (lifetime)">
          <div className="grid grid-cols-2 gap-3">
            <Stat label="Clean windows" value={si(L ? L.collector.windows : null)} loading={loading} sub={L ? `${si(L.collector.sinceBoot)} since restart` : undefined} />
            <Stat
              label="Suspect windows"
              value={si(L ? L.collector.suspect : null)}
              loading={loading}
              sub={L && L.collector.windows + L.collector.suspect > 0 ? `${((L.collector.suspect / (L.collector.windows + L.collector.suspect)) * 100).toFixed(2)}% quarantined` : undefined}
            />
          </div>
          <div className="mt-3 flex items-center justify-between rounded-lg bg-nd-fill px-3 py-2 text-[12.5px]">
            <span className="text-nd-muted">Feature collector</span>
            {loading ? <span className="text-nd-faint">…</span> : L!.collector.seen ? <Badge tone={L!.collector.up ? 'good' : 'bad'}>{L!.collector.up ? 'Running' : 'Down'}</Badge> : <Badge>Not reporting</Badge>}
          </div>
          <p className="mt-3 text-[12px] leading-relaxed text-nd-dim">Suspect windows are kept out of the training set so the baseline never learns an attack as “normal”.</p>
        </Panel>
      </div>

      {/* defenses */}
      <Panel
        icon={ShieldHalf}
        title="Defenses"
        sub="Dataplane protections per interface · what the risk engine arms under attack vs. operator and standing settings"
        actions={!loading && <Badge tone={autoOn ? 'warn' : 'good'}>{autoOn ? `${autoOn} armed by the risk engine` : 'Nothing armed by the risk engine'}</Badge>}
        bodyClass=""
      >
        {loading ? (
          <div className="px-5 pb-5"><div className="aa-skeleton h-[200px] rounded-xl" /></div>
        ) : flagNames.length === 0 ? (
          <Empty icon={ShieldHalf} title="No defense flags reported" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[620px] text-[13px]">
              <thead>
                <tr className="border-y border-nd-line bg-nd-fill text-[11px] uppercase tracking-[0.06em] text-nd-dim">
                  <th className="py-2 pl-5 pr-3 text-left font-medium">Protection</th>
                  <th className="px-3 py-2 text-left font-medium">Controlled by</th>
                  {ifs.map(([i]) => <th key={i} className="px-3 py-2 text-right font-medium last:pr-5">{ifaceName(i)}</th>)}
                </tr>
              </thead>
              <tbody>
                {flagNames.map((f) => (
                  <tr key={f} className="border-b border-nd-line-soft last:border-0">
                    <td className="py-2.5 pl-5 pr-3">
                      <div className="text-nd-fg-2">{FLAG_DESC[f] ?? pretty(f)}</div>
                      <div className="mono text-[11px] text-nd-faint">{f}</div>
                    </td>
                    <td className="px-3 py-2.5"><Badge tone={control(f).auto ? 'brand' : 'neutral'}>{control(f).by}</Badge></td>
                    {ifs.map(([i, s]) => (
                      <td key={i} className="px-3 py-2.5 text-right last:pr-5">
                        {(s.flags[f] ?? 0) > 0 ? <Badge tone={control(f).auto ? 'warn' : 'good'}>On</Badge> : <span className="text-[12px] text-nd-faint">off</span>}
                      </td>
                    ))}
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
