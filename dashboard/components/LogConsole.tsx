'use client'
import { useEffect, useMemo, useRef, useState } from 'react'
import type { LogEvent, Cat } from '@/hooks/useEventLog'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'

const TAG_COLOR: Record<string, string> = {
  IN: 'text-sky-400', OUT: 'text-cyan-400', NIC: 'text-teal-400', BW: 'text-zinc-400',
  VLAN: 'text-indigo-400', L3: 'text-zinc-500', ICMP: 'text-amber-400', EXT: 'text-blue-400',
  FRAG: 'text-orange-400', NET: 'text-teal-300',
  SYN: 'text-orange-400', ACK: 'text-orange-300', CONN: 'text-yellow-400',
  DROP: 'text-rose-400', RATE: 'text-amber-400', ANOM: 'text-fuchsia-400', MALF: 'text-pink-400',
  AI: 'text-emerald-400', DETECT: 'text-orange-400',
  SCAN: 'text-violet-400', ALERT: 'text-rose-400',
  RISK: 'text-emerald-300', SCORE: 'text-sky-300', ACTION: 'text-rose-300',
  FLAG: 'text-lime-400', LAYER: 'text-cyan-300', TRACK: 'text-teal-400',
  SYS: 'text-zinc-500', ERR: 'text-rose-400',
}
const tagColor = (t: string) => TAG_COLOR[t] ?? 'text-zinc-400'

type Filter = 'all' | 'traffic' | 'security' | 'ai'
const CATS: Record<Filter, Cat[] | null> = {
  all: null,
  traffic: ['traffic'],
  security: ['security'],
  ai: ['ai'],
}

export default function LogConsole({ events }: { events: LogEvent[] }) {
  const [filter, setFilter] = useState<Filter>('all')
  const [paused, setPaused] = useState(false)
  const listRef = useRef<HTMLDivElement>(null)

  const shown = useMemo(() => {
    const cats = CATS[filter]
    return cats ? events.filter((e) => cats.includes(e.cat)) : events
  }, [events, filter])

  // Keep the console pinned to the newest line by scrolling ITS OWN container —
  // never scrollIntoView (that would drag the whole page down on load).
  useEffect(() => {
    if (paused) return
    const el = listRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [shown.length, paused])

  return (
    <div className="flex h-full flex-col overflow-hidden rounded-xl border border-white/[0.07] bg-[#09090c] shadow-card">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-3 py-2.5">
        <div className="flex items-center gap-2 text-xs">
          <span className={`h-1.5 w-1.5 rounded-full ${paused ? 'bg-amber-400' : 'bg-emerald-400 animate-pulse'}`} />
          <span className="font-medium tracking-wide text-zinc-300">Telemetry</span>
          <Badge variant="secondary" className="mono h-4 px-1.5 text-[10px] tabular-nums">{shown.length}</Badge>
        </div>
        <div className="flex items-center gap-1.5">
          <Tabs value={filter} onValueChange={(v) => setFilter(v as Filter)}>
            <TabsList className="h-7 bg-white/[0.03] p-0.5">
              {(['all', 'traffic', 'security', 'ai'] as Filter[]).map((f) => (
                <TabsTrigger key={f} value={f} className="h-6 px-2 text-[10px] uppercase tracking-wide">
                  {f}
                </TabsTrigger>
              ))}
            </TabsList>
          </Tabs>
          <button
            onClick={() => setPaused((p) => !p)}
            className={`rounded-md px-2 py-1 text-[10px] uppercase tracking-wide transition-colors ${
              paused ? 'bg-amber-500/20 text-amber-300' : 'text-zinc-500 hover:text-zinc-300'
            }`}
          >
            {paused ? 'paused' : 'live'}
          </button>
        </div>
      </div>
      <div ref={listRef} className="scroll-thin mono flex-1 overflow-y-auto px-1 py-1.5 text-[11px] leading-[1.6]">
        {shown.map((e) => (
          <div
            key={e.id}
            className="flex gap-2 rounded px-2 py-px transition-colors hover:bg-white/[0.03]"
          >
            <span className="shrink-0 text-zinc-600">{e.ts.toLocaleTimeString('en-GB')}</span>
            <span className={`w-14 shrink-0 font-semibold ${tagColor(e.tag)}`}>{e.tag}</span>
            <span className="min-w-0 break-words text-zinc-400">{e.msg}</span>
          </div>
        ))}
        {shown.length === 0 && <div className="px-2 text-zinc-600">waiting for events…</div>}
      </div>
    </div>
  )
}
