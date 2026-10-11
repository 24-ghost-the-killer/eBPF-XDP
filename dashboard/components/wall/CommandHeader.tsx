'use client'
import Icon from '@/components/app/icons'
import { bps, pps } from '@/lib/format'

function Vital({ label, value, tone = 'text-zinc-200' }: { label: string; value: string; tone?: string }) {
  return (
    <div className="flex items-baseline gap-1.5 whitespace-nowrap">
      <span className="text-[9px] font-medium uppercase tracking-[0.14em] text-zinc-600">{label}</span>
      <span className={`mono text-[12px] font-semibold tabular-nums ${tone}`}>{value}</span>
    </div>
  )
}

// Cockpit command strip — replaces the sidebar + topbar entirely.
export default function CommandHeader({
  attack,
  up,
  connected,
  now,
  ingress,
  drop,
  pass,
  rl,
  load,
  onCommand,
}: {
  attack: boolean
  up: boolean
  connected: boolean
  now: Date | null
  ingress: number | null
  drop: number | null
  pass: number | null
  rl: number | null
  load: number
  onCommand: () => void
}) {
  return (
    <header className="sticky top-0 z-30 border-b border-white/[0.07] bg-[#07070a]/85 backdrop-blur-xl">
      <div className="flex flex-wrap items-center gap-x-5 gap-y-2 px-4 py-2.5 lg:px-6">
        {/* brand */}
        <div className="flex items-center gap-2.5">
          <span className="glow-emerald relative flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500/10 ring-1 ring-emerald-500/30">
            <span className={`absolute inline-flex h-3 w-3 rounded-full ${connected ? 'bg-emerald-400/40 animate-ping' : ''}`} />
            <Icon name="bolt" className="relative h-4 w-4 text-emerald-400" />
          </span>
          <div className="leading-none">
            <div className="text-[13px] font-bold tracking-tight text-zinc-100">
              XDP<span className="text-emerald-400 text-glow">·</span>SENTINEL
            </div>
            <div className="mt-0.5 text-[8.5px] uppercase tracking-[0.22em] text-zinc-600">operations wall</div>
          </div>
        </div>

        {/* posture */}
        <div
          className={`flex items-center gap-2 rounded-md px-3 py-1.5 text-[12px] font-bold tracking-wide ring-1 ${
            attack
              ? 'bg-rose-500/10 text-rose-300 ring-rose-500/40 shadow-[0_0_22px_-6px_rgba(244,63,94,0.7)]'
              : 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/25'
          }`}
        >
          <span className={`h-2 w-2 rounded-full ${attack ? 'bg-rose-400 animate-pulse' : 'bg-emerald-400'}`} />
          {attack ? 'UNDER ATTACK' : 'OPERATIONAL'}
        </div>

        {/* live vitals readout */}
        <div className="hidden items-center gap-4 md:flex">
          <Vital label="load" value={`${Math.round(load * 100)}%`} tone={load >= 0.85 ? 'text-rose-400' : load >= 0.6 ? 'text-amber-400' : 'text-emerald-400'} />
          <span className="text-zinc-800">│</span>
          <Vital label="in" value={bps(ingress ?? 0)} tone="text-sky-400" />
          <Vital label="pass" value={pps(pass ?? 0)} tone="text-emerald-400" />
          <Vital label="drop" value={pps(drop ?? 0)} tone={(drop ?? 0) > 0 ? 'text-rose-400' : 'text-zinc-400'} />
          <Vital label="rl" value={pps(rl ?? 0)} tone={(rl ?? 0) > 0 ? 'text-amber-400' : 'text-zinc-400'} />
        </div>

        {/* right cluster */}
        <div className="ml-auto flex items-center gap-3 text-xs">
          <button
            onClick={onCommand}
            className="hidden items-center gap-2 rounded-md border border-white/[0.08] bg-white/[0.02] px-2.5 py-1.5 text-[11px] text-zinc-500 transition-colors hover:border-white/[0.15] hover:text-zinc-300 sm:flex"
          >
            <span>Go to…</span>
            <kbd className="mono rounded border border-white/[0.1] bg-white/[0.04] px-1.5 py-0.5 text-[10px] text-zinc-400">⌘K</kbd>
          </button>
          <span className={`flex items-center gap-1.5 ${connected ? 'text-emerald-400' : 'text-rose-400'}`}>
            <span className={`h-1.5 w-1.5 rounded-full ${connected ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'}`} />
            <span className="mono hidden sm:inline">{connected ? 'live' : 'offline'}</span>
          </span>
          <span className="mono text-zinc-500">{now ? now.toLocaleTimeString('en-GB') : '—'}</span>
          <span className={`flex items-center gap-1.5 text-[11px] ${up ? 'text-zinc-500' : 'text-rose-400'}`}>
            <span className={`h-1.5 w-1.5 rounded-full ${up ? 'bg-emerald-400' : 'bg-rose-500'}`} />
            <span className="mono hidden lg:inline">dataplane</span>
          </span>
        </div>
      </div>
    </header>
  )
}
