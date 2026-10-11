'use client'
import SpotlightCard from '@/components/reactbits/SpotlightCard'

// DDoS classifier output: each attack class carries an independent probability
// (0..1), not a share — so bars are absolute, highest first.
const COLOR: Record<string, string> = {
  benign: 'bg-emerald-500',
  syn_flood: 'bg-orange-500',
  ack_flood: 'bg-amber-500',
  udp_flood: 'bg-violet-500',
  udp_reflection: 'bg-fuchsia-500',
  icmp_flood: 'bg-rose-500',
  frag_flood: 'bg-pink-500',
  malformed_flood: 'bg-red-500',
  dns_amplification: 'bg-sky-500',
  connection_flood: 'bg-yellow-500',
}

export default function ClassProbs({ classes }: { classes: { label: string; v: number }[] }) {
  const rows = [...classes].sort((a, b) => b.v - a.v)
  return (
    <SpotlightCard className="p-3">
      <div className="mb-2 text-[11px] uppercase tracking-wider text-zinc-500">DDoS classifier · class confidence</div>
      <div className="space-y-1.5">
        {rows.length === 0 && <div className="text-xs text-zinc-600">no data</div>}
        {rows.map((c) => {
          const pct = Math.max(0, Math.min(1, c.v)) * 100
          const hot = c.label !== 'benign' && c.v >= 0.5
          return (
            <div key={c.label} className="font-mono text-[11px]">
              <div className="mb-0.5 flex justify-between">
                <span className={hot ? 'text-rose-300' : 'text-zinc-400'}>{c.label}</span>
                <span className={`tabular-nums ${hot ? 'text-rose-300' : 'text-zinc-300'}`}>{pct.toFixed(0)}%</span>
              </div>
              <div className="h-1.5 overflow-hidden rounded-sm bg-zinc-800">
                <div className={`h-1.5 ${COLOR[c.label] ?? 'bg-zinc-500'}`} style={{ width: `${pct}%` }} />
              </div>
            </div>
          )
        })}
      </div>
    </SpotlightCard>
  )
}
