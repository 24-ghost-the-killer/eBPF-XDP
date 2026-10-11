'use client'
import type { Row } from '@/lib/prom'
import CountUp from '@/components/reactbits/CountUp'
import Sparkline from './Sparkline'
import { Skeleton } from '@/components/ui/skeleton'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'

type Status = 'good' | 'warn' | 'crit' | 'info' | 'neutral'

const STATUS: Record<Status, { text: string; dot: string; spark: string; word: string }> = {
  good: { text: 'text-emerald-400', dot: 'bg-emerald-400', spark: '#34d399', word: 'nominal' },
  warn: { text: 'text-amber-400', dot: 'bg-amber-400', spark: '#fbbf24', word: 'elevated' },
  crit: { text: 'text-rose-400', dot: 'bg-rose-400', spark: '#f43f5e', word: 'critical' },
  info: { text: 'text-sky-400', dot: 'bg-sky-400', spark: '#38bdf8', word: 'live' },
  neutral: { text: 'text-zinc-100', dot: 'bg-zinc-500', spark: '#8b8b94', word: 'idle' },
}

export default function MetricTile({
  label,
  value,
  num,
  fmt,
  status = 'neutral',
  sub,
  spark,
  sparkKey,
  tip,
  loading,
}: {
  label: string
  value?: string
  num?: number | null
  fmt?: (n: number) => string
  status?: Status
  sub?: string
  spark?: Row[]
  sparkKey?: string
  tip?: string
  loading?: boolean
}) {
  const s = STATUS[status]
  const isLoading = loading ?? (num == null && value == null)

  const tile = (
    <div className="panel panel-ticks group relative overflow-hidden p-3.5">
      {/* top sweep shimmer on hover */}
      <div className="pointer-events-none absolute inset-x-0 top-0 h-px overflow-hidden opacity-0 transition-opacity group-hover:opacity-100">
        <div className="animate-sweep h-px w-1/4 bg-gradient-to-r from-transparent via-emerald-400/70 to-transparent" />
      </div>
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-medium uppercase tracking-[0.16em] text-zinc-500">{label}</span>
        <span className={`h-1.5 w-1.5 rounded-full ${s.dot} ${status !== 'neutral' ? 'shadow-[0_0_8px_currentColor]' : ''}`} />
      </div>
      {isLoading ? (
        <Skeleton className="mt-3 h-[25px] w-20 bg-white/[0.06]" />
      ) : (
        <div className={`mt-2 font-mono text-[25px] font-semibold leading-none tabular-nums ${s.text}`}>
          {num != null && fmt ? <CountUp to={num} format={fmt} /> : value}
        </div>
      )}
      {spark && sparkKey ? (
        <div className="mt-2.5 -mb-0.5">
          {isLoading ? <Skeleton className="h-[30px] w-full bg-white/[0.04]" /> : <Sparkline data={spark} dataKey={sparkKey} color={s.spark} height={30} />}
        </div>
      ) : (
        sub && <div className="mt-2 truncate text-[11px] text-zinc-500">{sub}</div>
      )}
    </div>
  )

  if (!tip) return tile
  return (
    <Tooltip>
      <TooltipTrigger asChild>{tile}</TooltipTrigger>
      <TooltipContent side="top" className="max-w-[240px]">
        <p className="font-medium">
          {label} · <span className="text-emerald-300">{s.word}</span>
        </p>
        <p className="mt-0.5 text-[11px] opacity-80">{tip}</p>
      </TooltipContent>
    </Tooltip>
  )
}
