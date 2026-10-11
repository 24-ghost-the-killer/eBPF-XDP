'use client'
import { pps } from '@/lib/format'

export interface RiskData {
  threat: number // 0 normal / 1 suspect / 2 under_attack
  risk: number // 0..1 fused
  level: number // 0 pass .. 5 block
  anomalyZ: number // statistical z-score, normalised 0..1
  ddos: number // classifier top non-benign prob 0..1
  iforest: number | null // isolation-forest score 0..1
  detection: boolean
  mitigation: boolean
  mitRate: number // pps
  autoActions: number
  analysisPps: number
  classes: { label: string; v: number }[] // ddos class probabilities
}

const THREAT = ['NORMAL', 'SUSPECT', 'UNDER ATTACK']
const THREAT_TONE = ['text-emerald-400', 'text-amber-400', 'text-rose-400']
const LADDER = ['pass', 'watch', 'rl-soft', 'rl-hard', 'drop', 'block']

function Meter({ label, v, tone }: { label: string; v: number | null; tone: string }) {
  const pct = v == null ? 0 : Math.max(0, Math.min(1, v)) * 100
  return (
    <div>
      <div className="flex items-baseline justify-between">
        <span className="text-[10px] uppercase tracking-[0.12em] text-zinc-500">{label}</span>
        <span className={`mono text-[12px] font-semibold tabular-nums ${v == null ? 'text-zinc-600' : tone}`}>
          {v == null ? 'n/a' : v.toFixed(2)}
        </span>
      </div>
      <div className="mt-1 h-1.5 overflow-hidden rounded-sm bg-white/[0.06]">
        <div className={`h-1.5 rounded-sm transition-all duration-500 ${tone.replace('text-', 'bg-')}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

export default function RiskEngine({ d }: { d: RiskData | null }) {
  const threat = d?.threat ?? 0
  const level = d?.level ?? 0
  const topClass = (d?.classes ?? []).filter((c) => c.label !== 'benign').sort((a, b) => b.v - a.v)[0]

  return (
    <div className="panel panel-ticks p-4">
      <div className="mb-3 flex items-center justify-between">
        <span className="eyebrow">AI risk engine</span>
        <span className={`mono text-[11px] font-semibold ${THREAT_TONE[threat]}`}>
          ● {THREAT[threat] ?? '—'}
        </span>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* left: fused risk + ladder */}
        <div>
          <Meter label="fused risk" v={d?.risk ?? null} tone={threat >= 2 ? 'text-rose-400' : threat === 1 ? 'text-amber-400' : 'text-emerald-400'} />
          <div className="mt-3">
            <div className="mb-1 flex items-baseline justify-between">
              <span className="text-[10px] uppercase tracking-[0.12em] text-zinc-500">mitigation ladder</span>
              <span className="mono text-[11px] text-zinc-400">lvl {level} · {LADDER[level] ?? '—'}</span>
            </div>
            <div className="flex gap-1">
              {LADDER.map((_, i) => (
                <div
                  key={i}
                  className={`h-2 flex-1 rounded-sm transition-colors ${
                    i <= level && level > 0
                      ? level >= 4 ? 'bg-rose-500' : level >= 2 ? 'bg-amber-500' : 'bg-emerald-500'
                      : 'bg-white/[0.07]'
                  }`}
                />
              ))}
            </div>
          </div>
          <div className="mt-3 grid grid-cols-3 gap-2 text-center">
            <Mini label="auto-actions" value={String(d?.autoActions ?? 0)} tone="text-zinc-200" />
            <Mini label="mitig rate" value={pps(d?.mitRate ?? 0)} tone={(d?.mitRate ?? 0) > 0 ? 'text-amber-400' : 'text-zinc-400'} />
            <Mini label="analysis" value={pps(d?.analysisPps ?? 0)} tone="text-zinc-300" />
          </div>
        </div>

        {/* right: detector scores */}
        <div className="space-y-2.5">
          <Meter label="statistical (z-score)" v={d?.anomalyZ ?? null} tone="text-sky-400" />
          <Meter label="isolation forest" v={d?.iforest ?? null} tone="text-violet-400" />
          <Meter label="ddos classifier" v={d?.ddos ?? null} tone="text-fuchsia-400" />
          <div className="flex items-center justify-between pt-0.5 text-[11px]">
            <span className="text-zinc-500">top class</span>
            <span className="mono text-zinc-300">
              {topClass && topClass.v > 0.01 ? `${topClass.label} ${(topClass.v * 100).toFixed(0)}%` : 'benign'}
            </span>
          </div>
          <div className="flex items-center gap-3 pt-0.5 text-[10px]">
            <span className={`flex items-center gap-1.5 ${d?.detection ? 'text-rose-400' : 'text-zinc-600'}`}>
              <span className={`h-1.5 w-1.5 rounded-full ${d?.detection ? 'bg-rose-400 animate-pulse' : 'bg-zinc-700'}`} />detection
            </span>
            <span className={`flex items-center gap-1.5 ${d?.mitigation ? 'text-amber-400' : 'text-zinc-600'}`}>
              <span className={`h-1.5 w-1.5 rounded-full ${d?.mitigation ? 'bg-amber-400 animate-pulse' : 'bg-zinc-700'}`} />mitigation
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}

function Mini({ label, value, tone }: { label: string; value: string; tone: string }) {
  return (
    <div className="rounded-md border border-white/[0.06] bg-white/[0.015] py-1.5">
      <div className="text-[8px] uppercase tracking-[0.1em] text-zinc-600">{label}</div>
      <div className={`mono mt-0.5 text-[12px] font-semibold tabular-nums ${tone}`}>{value}</div>
    </div>
  )
}
