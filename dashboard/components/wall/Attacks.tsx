'use client'
import { useEffect, useState } from 'react'
import { bps, pps, bytes } from '@/lib/format'
import SpotlightCard from '@/components/reactbits/SpotlightCard'
import { Badge } from '@/components/ui/badge'

interface Attacker { ip: string; scope: string; bytes: number; packets: number; pps: number; bps: number }
interface Attack {
  id: number
  start: number
  end: number
  durationSec: number
  peakPps: number
  peakBps: number
  totalPackets: number
  totalBytes: number
  droppedPackets: number
  dropShare: number
  peakRiskLevel: number
  peakThreatState: number
  classifier: { label: string; conf: number } | null
  vectors: string[]
  uniqueSources: number
  attackers: Attacker[]
  target: { iface: string; label: string; rxPackets: number; rxShare: number } | null
}

function dur(sec: number) {
  if (sec < 60) return `${sec}s`
  const m = Math.floor(sec / 60)
  const s = sec % 60
  if (m < 60) return s ? `${m}m ${s}s` : `${m}m`
  return `${Math.floor(m / 60)}h ${m % 60}m`
}
const when = (ms: number) =>
  new Date(ms).toLocaleString('en-GB', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' })
const compact = (n: number) => {
  if (n >= 1e9) return (n / 1e9).toFixed(1) + 'B'
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M'
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'k'
  return String(Math.round(n))
}

function Board({ label, value, sub, tone = 'text-zinc-50' }: { label: string; value: string; sub?: string; tone?: string }) {
  return (
    <div className="panel panel-ticks p-3.5">
      <div className="text-[10px] font-medium uppercase tracking-[0.16em] text-zinc-500">{label}</div>
      <div className={`mono mt-2 text-[22px] font-semibold leading-none tabular-nums ${tone}`}>{value}</div>
      {sub && <div className="mt-1.5 truncate text-[11px] text-zinc-500">{sub}</div>}
    </div>
  )
}

function Stat({ label, value, tone = 'text-zinc-100' }: { label: string; value: string; tone?: string }) {
  return (
    <div>
      <div className="text-[9.5px] uppercase tracking-[0.12em] text-zinc-600">{label}</div>
      <div className={`mono mt-0.5 text-[14px] font-semibold tabular-nums ${tone}`}>{value}</div>
    </div>
  )
}

export default function Attacks() {
  const [data, setData] = useState<Attack[] | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [open, setOpen] = useState<number | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let alive = true
    const load = async () => {
      try {
        const r = await fetch('/api/attacks', { cache: 'no-store' })
        const j = await r.json()
        if (!alive) return
        if (j.status !== 'success') throw new Error(j.error || 'failed')
        setData(j.attacks)
        setErr(null)
      } catch (e) {
        if (alive) setErr(e instanceof Error ? e.message : String(e))
      } finally {
        if (alive) setLoading(false)
      }
    }
    load()
    const id = setInterval(load, 30000)
    return () => {
      alive = false
      clearInterval(id)
    }
  }, [])

  if (loading) return <div className="panel p-6 text-center text-sm text-zinc-500">Reconstructing attack history from 15 days of telemetry…</div>
  if (err) return <div className="panel p-6 text-sm text-amber-300">Couldn&apos;t load attack history: {err}</div>
  if (!data || data.length === 0)
    return (
      <SpotlightCard className="p-8 text-center">
        <div className="text-2xl">🛡️</div>
        <div className="mt-2 text-sm font-medium text-emerald-300">No DDoS attacks on record</div>
        <div className="mt-1 text-xs text-zinc-500">No detection episodes in the last 15 days of telemetry.</div>
      </SpotlightCard>
    )

  const peakBpsAll = Math.max(...data.map((a) => a.peakBps))
  const peakPpsAll = Math.max(...data.map((a) => a.peakPps))
  const totalDropped = data.reduce((s, a) => s + a.droppedPackets, 0)
  const totalVol = data.reduce((s, a) => s + a.totalBytes, 0)

  return (
    <div className="space-y-4">
      {/* summary boards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Board label="Attacks blocked" value={String(data.length)} sub="last 15 days" tone="text-rose-300" />
        <Board label="Largest attack" value={bps(peakBpsAll)} sub={`peak ${pps(peakPpsAll)}`} tone="text-orange-300" />
        <Board label="Packets dropped" value={compact(totalDropped)} sub="across all attacks" tone="text-emerald-300" />
        <Board label="Malicious volume" value={bytes(totalVol)} sub="seen & mitigated" tone="text-sky-300" />
      </div>

      <div className="flex items-center justify-between px-0.5 text-[11px] text-zinc-500">
        <span>{data.length} attack{data.length === 1 ? '' : 's'} reconstructed from the last 15 days</span>
        <span className="mono">peak = highest 30s rate · totals = over the episode</span>
      </div>

      {data.map((a) => {
        const isOpen = open === a.id
        const crit = a.peakRiskLevel >= 4
        return (
          <SpotlightCard key={a.id} className="overflow-hidden">
            {/* summary row */}
            <button onClick={() => setOpen(isOpen ? null : a.id)} className="flex w-full flex-wrap items-center gap-x-5 gap-y-2 p-3.5 text-left">
              <span className="mono text-[11px] text-zinc-600">#{a.id}</span>
              <div className="min-w-[128px]">
                <div className="mono text-[12px] text-zinc-200">{when(a.start)}</div>
                <div className="text-[10px] text-zinc-500">lasted {dur(a.durationSec)}</div>
              </div>
              <Badge className={`${crit ? 'bg-rose-500/15 text-rose-300 ring-rose-500/30' : 'bg-amber-500/15 text-amber-300 ring-amber-500/30'} ring-1 ring-inset`}>
                {a.classifier && a.classifier.conf > 0.3 ? a.classifier.label : a.vectors[0] ?? 'detected'}
              </Badge>
              <div className="flex flex-wrap gap-1">
                {a.vectors.slice(0, 3).map((v) => (
                  <span key={v} className="mono rounded bg-white/[0.04] px-1.5 py-0.5 text-[9.5px] text-zinc-400 ring-1 ring-inset ring-white/[0.06]">{v}</span>
                ))}
              </div>
              {a.target && (
                <span className="mono text-[10px] text-zinc-500">
                  → aimed at <span className="text-cyan-400">{a.target.label}</span>
                </span>
              )}
              <div className="ml-auto flex items-center gap-5">
                <Stat label="peak pps" value={pps(a.peakPps)} tone="text-rose-300" />
                <Stat label="peak bps" value={bps(a.peakBps)} tone="text-orange-300" />
                <Stat label="dropped" value={`${(a.dropShare * 100).toFixed(0)}%`} tone="text-emerald-300" />
                <span className={`mono text-[10px] text-zinc-600 transition-transform ${isOpen ? 'rotate-90' : ''}`}>▶</span>
              </div>
            </button>

            {/* detail */}
            {isOpen && (
              <div className="border-t border-white/[0.06] p-4">
                <div className="grid grid-cols-2 gap-4 sm:grid-cols-4 lg:grid-cols-7">
                  <Stat label="started" value={when(a.start)} />
                  <Stat label="duration" value={dur(a.durationSec)} />
                  <Stat label="peak pps" value={pps(a.peakPps)} tone="text-rose-300" />
                  <Stat label="peak bandwidth" value={bps(a.peakBps)} tone="text-orange-300" />
                  <Stat label="total packets" value={pps(a.totalPackets).replace('p/s', '')} tone="text-zinc-200" />
                  <Stat label="total volume" value={bytes(a.totalBytes)} tone="text-zinc-200" />
                  <Stat label="packets dropped" value={`${pps(a.droppedPackets).replace('p/s', '')} (${(a.dropShare * 100).toFixed(0)}%)`} tone="text-emerald-300" />
                </div>
                <div className="mt-3 grid grid-cols-2 gap-4 sm:grid-cols-4 lg:grid-cols-7">
                  <Stat label="peak risk level" value={`${a.peakRiskLevel} / 5`} tone={crit ? 'text-rose-300' : 'text-amber-300'} />
                  <Stat label="threat state" value={['normal', 'suspect', 'under attack'][a.peakThreatState] ?? String(a.peakThreatState)} tone="text-rose-300" />
                  <Stat label="classifier" value={a.classifier ? `${a.classifier.label} ${(a.classifier.conf * 100).toFixed(0)}%` : 'n/a'} tone="text-fuchsia-300" />
                  <Stat label="unique sources" value={String(a.uniqueSources)} />
                  <div className="col-span-2 lg:col-span-3">
                    <div className="text-[9.5px] uppercase tracking-[0.12em] text-zinc-600">vectors</div>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {a.vectors.length ? a.vectors.map((v) => <span key={v} className="mono rounded bg-white/[0.04] px-1.5 py-0.5 text-[10px] text-zinc-300">{v}</span>) : <span className="text-[11px] text-zinc-500">—</span>}
                    </div>
                  </div>
                </div>

                {/* target — where it was aimed */}
                <div className="mt-4">
                  <div className="mb-2 text-[11px] uppercase tracking-wider text-zinc-500">Target</div>
                  <div className="rounded-md border border-cyan-500/20 bg-cyan-500/[0.04] px-3 py-2.5 text-[11px]">
                    {a.target ? (
                      <span className="text-zinc-400">
                        Hit the <span className="mono font-semibold text-cyan-300">{a.target.label}</span> ingress — this interface absorbed{' '}
                        <span className="mono text-zinc-200">{pps(a.target.rxPackets).replace('p/s', '')}</span> packets (
                        {(a.target.rxShare * 100).toFixed(0)}% of all traffic on the appliance during the attack).
                      </span>
                    ) : (
                      <span className="text-zinc-500">Target interface could not be determined for this episode.</span>
                    )}
                    <div className="mt-1.5 text-zinc-500">
                      The appliance protects a bridge segment, so the attack is attributed to the targeted <em>interface</em>.
                      A single destination host isn&apos;t exported by the dataplane metrics (only aggregate per-interface volume).
                    </div>
                  </div>
                </div>

                {/* attacker IPs */}
                <div className="mt-4">
                  <div className="mb-2 text-[11px] uppercase tracking-wider text-zinc-500">Attacker sources</div>
                  {a.attackers.length === 0 ? (
                    <div className="rounded-md border border-white/[0.06] bg-white/[0.015] px-3 py-2.5 text-[11px] text-zinc-500">
                      No per-source attribution captured for this episode — the flood was injected on-box / bypassed the per-source talker tap.
                      Real attacks traversing the WAN interface populate this list.
                    </div>
                  ) : (
                    <table className="w-full text-[11px] font-mono">
                      <thead>
                        <tr className="text-[10px] uppercase text-zinc-600">
                          <th className="pb-1 text-left font-normal">source ip</th>
                          <th className="pb-1 text-left font-normal">scope</th>
                          <th className="pb-1 text-right font-normal">sent</th>
                          <th className="pb-1 text-right font-normal">packets</th>
                          <th className="pb-1 text-right font-normal">avg pps</th>
                          <th className="pb-1 text-right font-normal">avg bps</th>
                        </tr>
                      </thead>
                      <tbody>
                        {a.attackers.map((at) => (
                          <tr key={at.ip} className="border-t border-white/[0.05]">
                            <td className="py-[3px] text-zinc-200">{at.ip}</td>
                            <td className={at.scope === 'lan' ? 'text-emerald-500' : 'text-sky-500'}>{at.scope}</td>
                            <td className="text-right tabular-nums text-zinc-300">{bytes(at.bytes)}</td>
                            <td className="text-right tabular-nums text-zinc-300">{Math.round(at.packets).toLocaleString('en-US')}</td>
                            <td className="text-right tabular-nums text-rose-300">{pps(at.pps)}</td>
                            <td className="text-right tabular-nums text-orange-300">{bps(at.bps)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              </div>
            )}
          </SpotlightCard>
        )
      })}
    </div>
  )
}
