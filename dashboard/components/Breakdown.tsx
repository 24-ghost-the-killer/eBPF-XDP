import { pps } from '@/lib/format'
import SpotlightCard from './reactbits/SpotlightCard'

export interface BreakdownRow {
  label: string
  v: number
  color: string // tailwind bg-* class, solid (no gradient)
}

export default function Breakdown({ title, rows }: { title: string; rows: BreakdownRow[] }) {
  const total = Math.max(1, rows.reduce((a, r) => a + r.v, 0))
  return (
    <SpotlightCard className="p-3">
      <div className="text-[11px] uppercase tracking-wider text-zinc-500 mb-2">{title}</div>
      <div className="space-y-1.5">
        {rows.map((r) => (
          <div key={r.label} className="font-mono text-[11px]">
            <div className="mb-0.5 flex justify-between">
              <span className="text-zinc-400">{r.label}</span>
              <span className="tabular-nums text-zinc-300">
                {pps(r.v)} · {((r.v / total) * 100).toFixed(0)}%
              </span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-sm bg-zinc-800">
              <div className={`h-1.5 ${r.color}`} style={{ width: `${(r.v / total) * 100}%` }} />
            </div>
          </div>
        ))}
      </div>
    </SpotlightCard>
  )
}
