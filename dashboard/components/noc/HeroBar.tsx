'use client'
import type { Row } from '@/lib/prom'
import { bps, pps } from '@/lib/format'
import Gauge from './Gauge'
import Sparkline from './Sparkline'
import CountUp from '@/components/reactbits/CountUp'

// The command-center hero band: posture, throughput gauge (load vs ceiling),
// live ingress + sparkline, and the three defense figures.
export default function HeroBar({
  attack,
  up,
  ingress,
  capacity,
  drop,
  pass,
  rl,
  spark,
}: {
  attack: boolean
  up: boolean
  ingress: number | null
  capacity: number | null
  drop: number | null
  pass: number | null
  rl: number | null
  spark: Row[]
}) {
  const load = ingress != null && capacity ? ingress / capacity : 0

  return (
    <div
      className={`panel panel-ticks relative overflow-hidden ${attack ? 'glow-rose' : 'glow-emerald'}`}
    >
      <div className="scanlines pointer-events-none absolute inset-0 opacity-40" />
      {/* ambient status wash */}
      <div
        className="pointer-events-none absolute -right-20 -top-24 h-72 w-72 rounded-full blur-3xl"
        style={{ background: attack ? 'rgba(244,63,94,0.16)' : 'rgba(16,185,129,0.14)' }}
      />

      <div className="relative grid grid-cols-1 gap-6 p-5 lg:grid-cols-[1.1fr_auto_1.3fr] lg:items-center lg:gap-4">
        {/* posture */}
        <div>
          <div className="flex items-center gap-2 text-[10px] font-medium uppercase tracking-[0.22em] text-zinc-500">
            <span className={`h-1.5 w-1.5 rounded-full ${attack ? 'bg-rose-400' : 'bg-emerald-400'} animate-pulse`} />
            System posture
          </div>
          <div
            className={`mt-2 font-mono text-[34px] font-bold leading-none tracking-tight sm:text-[42px] ${
              attack ? 'text-rose-400 text-glow-rose animate-flicker' : 'text-emerald-400 text-glow'
            }`}
          >
            {attack ? 'UNDER ATTACK' : 'OPERATIONAL'}
          </div>
          <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px]">
            <span className="flex items-center gap-1.5 text-zinc-400">
              <span className={`h-1.5 w-1.5 rounded-full ${up ? 'bg-emerald-400' : 'bg-rose-500'}`} />
              dataplane {up ? 'engaged' : 'down'}
            </span>
            <span className="mono text-zinc-600">XDP · eBPF · L2–L4</span>
          </div>
        </div>

        {/* throughput gauge */}
        <div className="flex items-center justify-center">
          <Gauge
            value={load}
            center={`${Math.round(load * 100)}%`}
            sub="line load"
            size={150}
          />
        </div>

        {/* live figures */}
        <div className="grid grid-cols-2 gap-x-5 gap-y-4 sm:grid-cols-4 lg:grid-cols-2 xl:grid-cols-4">
          <HeroFig label="Ingress" value={<CountUp to={ingress ?? 0} format={bps} />} color="text-sky-400">
            <Sparkline data={spark} dataKey="bps" color="#38bdf8" height={26} />
          </HeroFig>
          <HeroFig label="Max block" value={<CountUp to={capacity ?? 0} format={bps} />} color="text-emerald-400" note="NIC ceiling" />
          <HeroFig label="Dropping" value={<CountUp to={drop ?? 0} format={pps} />} color="text-rose-400" note={`rate-limited ${pps(rl ?? 0)}`} />
          <HeroFig label="Passing" value={<CountUp to={pass ?? 0} format={pps} />} color="text-emerald-400" note="clean traffic" />
        </div>
      </div>
    </div>
  )
}

function HeroFig({
  label,
  value,
  color,
  note,
  children,
}: {
  label: string
  value: React.ReactNode
  color: string
  note?: string
  children?: React.ReactNode
}) {
  return (
    <div>
      <div className="text-[10px] font-medium uppercase tracking-[0.16em] text-zinc-500">{label}</div>
      <div className={`mt-1 font-mono text-[19px] font-semibold leading-none tabular-nums ${color}`}>{value}</div>
      {children ? <div className="mt-1.5">{children}</div> : note ? <div className="mt-1 truncate text-[10px] text-zinc-600">{note}</div> : null}
    </div>
  )
}
