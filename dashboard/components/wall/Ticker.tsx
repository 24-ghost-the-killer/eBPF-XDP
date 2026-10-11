'use client'
import type { LogEvent } from '@/hooks/useEventLog'

const TAG_COLOR: Record<string, string> = {
  IN: 'text-sky-400', OUT: 'text-cyan-400', NIC: 'text-teal-400', BW: 'text-zinc-400',
  VLAN: 'text-indigo-400', L3: 'text-zinc-500', ICMP: 'text-amber-400', EXT: 'text-blue-400',
  FRAG: 'text-orange-400', NET: 'text-teal-300', SYN: 'text-orange-400', ACK: 'text-orange-300',
  CONN: 'text-yellow-400', DROP: 'text-rose-400', RATE: 'text-amber-400', ANOM: 'text-fuchsia-400',
  MALF: 'text-pink-400', AI: 'text-emerald-400', DETECT: 'text-orange-400', SYS: 'text-zinc-500',
  ERR: 'text-rose-400', RISK: 'text-emerald-300', SCORE: 'text-sky-300', ACTION: 'text-rose-300',
  FLAG: 'text-lime-400', LAYER: 'text-cyan-300', TRACK: 'text-teal-400',
}
const tagColor = (t: string) => TAG_COLOR[t] ?? 'text-zinc-400'

// Bottom crawl — a continuous ticker of the latest telemetry, duplicated for a
// seamless loop. Pauses on hover.
export default function Ticker({ events }: { events: LogEvent[] }) {
  const recent = events.slice(-30)
  const loop = [...recent, ...recent]
  return (
    <div className="sticky bottom-0 z-30 flex items-stretch border-t border-white/[0.07] bg-[#07070a]/90 backdrop-blur-xl">
      <div className="flex shrink-0 items-center gap-1.5 border-r border-white/[0.07] bg-emerald-500/[0.06] px-3">
        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
        <span className="mono text-[10px] uppercase tracking-[0.16em] text-emerald-400">live feed</span>
      </div>
      <div className="relative flex-1 overflow-hidden">
        {recent.length === 0 ? (
          <div className="mono px-3 py-2 text-[11px] text-zinc-600">waiting for telemetry…</div>
        ) : (
          <div className="animate-marquee flex w-max gap-7 py-2 pl-7">
            {loop.map((e, i) => (
              <span key={i} className="mono flex items-center gap-1.5 text-[11px] whitespace-nowrap">
                <span className="text-zinc-700">{e.ts.toLocaleTimeString('en-GB')}</span>
                <span className={`font-semibold ${tagColor(e.tag)}`}>{e.tag}</span>
                <span className="text-zinc-400">{e.msg}</span>
                <span className="text-zinc-800">•</span>
              </span>
            ))}
          </div>
        )}
        {/* edge fades */}
        <div className="pointer-events-none absolute inset-y-0 left-0 w-10 bg-gradient-to-r from-[#07070a] to-transparent" />
        <div className="pointer-events-none absolute inset-y-0 right-0 w-10 bg-gradient-to-l from-[#07070a] to-transparent" />
      </div>
    </div>
  )
}
