'use client'
// The live view (anchor #live): while an attack is in progress, a globe of
// where it is coming from right now, the busiest sources and the live numbers,
// refreshed every 5 s. When all is calm: a one-line "no attack" with the alert
// switches, so notifications can be turned on before they are needed.
import { useState } from 'react'
import { Radio, ShieldCheck } from 'lucide-react'
import { useLive, since } from '@/lib/live'
import { si, bps, pretty } from '@/lib/format'
import { levelName } from '@/lib/explain'
import { flagOf } from '@/lib/country-centroids'
import { Panel, Badge } from '@/components/aa/kit'
import { AlertSettings } from '@/components/aa/LiveAlert'
import { AttackGlobe } from '@/components/globe/AttackGlobe'

export function LivePanel({ height = 420, hideWhenCalm = false }: { height?: number; hideWhenCalm?: boolean }) {
  const { live, error } = useLive(5000, true)
  const [sel, setSel] = useState<string | null>(null)

  if (!live?.active) {
    if (hideWhenCalm) return null
    return (
      <section id="live" className="scroll-mt-28 flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-nd-line bg-nd-card px-5 py-3 shadow-nd">
        <div className="flex items-center gap-2.5 text-[13px]">
          <ShieldCheck className="h-4 w-4 text-st-good-fg" />
          <span className="font-medium text-nd-fg">No attack right now</span>
          <span className="text-nd-dim">{error ? `· live state unavailable (${error})` : '· the live globe appears here the moment one starts'}</span>
        </div>
        <AlertSettings />
      </section>
    )
  }

  const share = live.dropShare ?? 0
  const sources = live.sources ?? []
  return (
    <div id="live" className="scroll-mt-28">
      <Panel icon={Radio} title={<span className="flex items-center gap-2">Live attack <Badge tone="bad">for {since(live.since)}</Badge></span>}
        sub={`${(live.types ?? []).map(pretty).join(', ') || 'Flood'} on ${(live.ifaces ?? []).map((i) => i.label).join(', ')} · updates every 5 s`}
        actions={<AlertSettings />} className="border-st-crit/40">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Cell label="Traffic" value={`${si(live.pps ?? 0)} pps`} sub={bps(live.bps ?? 0)} />
          <Cell label="Dropped" value={`${(share * 100).toFixed(share < 0.1 && share > 0 ? 1 : 0)}%`} sub={`${si(live.dropPps ?? 0)} pps`} />
          <Cell label="Ladder" value={`L${live.level ?? 0}`} sub={levelName(live.level ?? 0)} />
          <Cell label="Per-source cap" value={live.cap ? `${si(live.cap)} pps` : 'none'} sub={`${sources.length} source${sources.length === 1 ? '' : 's'} seen`} />
        </div>
        <div className="mt-4 grid grid-cols-1 gap-5 lg:grid-cols-5">
          <div className="lg:col-span-3">
            <AttackGlobe countries={live.countries ?? []} height={height} scope="live" selected={sel} onSelect={setSel} />
          </div>
          <div className="lg:col-span-2">
            <div className="mb-2 text-[11px] font-medium uppercase tracking-[0.06em] text-nd-dim">Busiest sources now</div>
            {sources.length === 0 ? (
              <p className="text-[12.5px] text-nd-faint">No source attribution yet: sources are credited as their packets are dropped.</p>
            ) : (
              <ul className="divide-y divide-nd-line-soft">
                {sources.slice(0, 12).map((s) => (
                  <li key={s.ip}>
                    <button type="button" onClick={() => s.cc && setSel((p) => (p === s.cc ? null : s.cc!))}
                      className={`flex w-full items-center gap-3 rounded-md px-1.5 py-1.5 text-left text-[12.5px] ${s.cc ? 'hover:bg-nd-fill' : 'cursor-default'} ${s.cc && s.cc === sel ? 'bg-nd-fill' : ''}`}>
                      <span className="w-5 shrink-0 text-center">{s.cc ? flagOf(s.cc) : s.scope === 'lan' ? '🏠' : '·'}</span>
                      <span className="min-w-0 flex-1">
                        <span className="mono block truncate text-nd-fg">{s.ip}</span>
                        <span className="block truncate text-[11px] text-nd-faint">{s.scope === 'lan' ? 'inside your network' : [s.country, s.org].filter(Boolean).join(' · ') || 'unknown location'}</span>
                      </span>
                      <span className="mono shrink-0 text-right tabular-nums text-nd-fg-2">{si(s.pps)} pps</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </Panel>
    </div>
  )
}

function Cell({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="rounded-lg bg-nd-fill px-3 py-2">
      <div className="text-[10.5px] font-medium uppercase tracking-[0.06em] text-nd-dim">{label}</div>
      <div className="mono text-[16px] font-semibold tabular-nums text-nd-fg">{value}</div>
      {sub && <div className="truncate text-[11px] text-nd-faint">{sub}</div>}
    </div>
  )
}
