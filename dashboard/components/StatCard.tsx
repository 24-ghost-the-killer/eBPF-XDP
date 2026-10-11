import type { ReactNode } from 'react'
import SpotlightCard from './reactbits/SpotlightCard'
import CountUp from './reactbits/CountUp'

export default function StatCard({
  label,
  value,
  num,
  fmt,
  unit,
  color = 'text-zinc-50',
  sub,
  accent,
}: {
  label: string
  value?: ReactNode
  num?: number | null // when provided (with fmt), animates with CountUp
  fmt?: (n: number) => string
  unit?: string
  color?: string
  sub?: string
  accent?: string // dot color, e.g. 'bg-rose-500'
}) {
  return (
    <SpotlightCard className="p-4">
      <div className="flex items-center justify-between">
        <div className="text-[10.5px] font-medium uppercase tracking-[0.14em] text-zinc-500">
          {label}
        </div>
        {accent && <span className={`h-1.5 w-1.5 rounded-full ${accent}`} />}
      </div>
      <div
        className={`mt-2.5 font-mono text-[26px] font-semibold leading-none tracking-tight tabular-nums ${color}`}
      >
        {num != null && fmt ? <CountUp to={num} format={fmt} /> : (value ?? '…')}
        {unit && <span className="ml-1 text-sm font-normal text-zinc-500">{unit}</span>}
      </div>
      {sub && <div className="mt-2 truncate text-[11px] text-zinc-500">{sub}</div>}
    </SpotlightCard>
  )
}
