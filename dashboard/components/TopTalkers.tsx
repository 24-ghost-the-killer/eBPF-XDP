import { bps } from '@/lib/format'
import type { Talker } from '@/lib/prom'
import SpotlightCard from './reactbits/SpotlightCard'
import { HoverCard, HoverCardContent, HoverCardTrigger } from '@/components/ui/hover-card'

// Solid bars (no gradient), colored by scope. Each row has a hover-card detail.
export default function TopTalkers({ title, rows }: { title: string; rows: Talker[] }) {
  const max = Math.max(1, ...rows.map((r) => r.v))
  const total = rows.reduce((a, r) => a + r.v, 0) || 1
  return (
    <SpotlightCard className="p-3">
      <div className="text-[11px] uppercase tracking-wider text-zinc-500 mb-2">{title}</div>
      <div className="space-y-1.5">
        {rows.length === 0 && <div className="text-zinc-600 text-xs">no data</div>}
        {rows.map((r, i) => {
          const lan = r.scope === 'lan'
          return (
            <HoverCard key={r.ip} openDelay={120} closeDelay={60}>
              <HoverCardTrigger asChild>
                <div className="flex cursor-default items-center gap-2 rounded px-1 py-0.5 text-[11px] font-mono transition-colors hover:bg-white/[0.03]">
                  <span className="w-4 shrink-0 text-right text-zinc-600">{i + 1}</span>
                  <span className="w-32 shrink-0 truncate text-zinc-300">{r.ip}</span>
                  <span className={`w-8 shrink-0 ${lan ? 'text-emerald-500' : 'text-sky-500'}`}>{r.scope}</span>
                  <div className="flex-1 h-2 bg-zinc-800 rounded-sm overflow-hidden">
                    <div className={`h-2 ${lan ? 'bg-emerald-500' : 'bg-sky-500'}`} style={{ width: `${(r.v / max) * 100}%` }} />
                  </div>
                  <span className="w-16 shrink-0 text-right tabular-nums text-zinc-200">{bps(r.v)}</span>
                </div>
              </HoverCardTrigger>
              <HoverCardContent side="left" className="w-60">
                <div className="mono text-[13px] font-semibold text-zinc-100">{r.ip}</div>
                <div className="mt-2 space-y-1.5 text-[11px]">
                  <Line label="scope" value={lan ? 'LAN (VLAN20)' : 'WAN / external'} tone={lan ? 'text-emerald-400' : 'text-sky-400'} />
                  <Line label="rank" value={`#${i + 1} of ${rows.length}`} />
                  <Line label="rate" value={bps(r.v)} />
                  <Line label="share" value={`${((r.v / total) * 100).toFixed(1)}% of shown`} />
                </div>
                <div className="mt-2 h-1.5 overflow-hidden rounded-sm bg-zinc-800">
                  <div className={`h-1.5 ${lan ? 'bg-emerald-500' : 'bg-sky-500'}`} style={{ width: `${(r.v / max) * 100}%` }} />
                </div>
              </HoverCardContent>
            </HoverCard>
          )
        })}
      </div>
    </SpotlightCard>
  )
}

function Line({ label, value, tone = 'text-zinc-200' }: { label: string; value: string; tone?: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-zinc-500">{label}</span>
      <span className={`mono tabular-nums ${tone}`}>{value}</span>
    </div>
  )
}
