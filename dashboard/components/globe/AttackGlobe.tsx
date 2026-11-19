'use client'
// Attack origins on the dotted globe: one pin per source country (placed at the
// country's centre, from the offline geo DB's country code), each joined by an
// arc to this appliance. Colours come from the dashboard's own tokens and
// follow the dark/light theme of the surrounding .nd-dark / .nd-light wrapper.
//
// Click / tap a country, its label or its link (or a row of a list that shares
// `selected`) to select it: the globe turns and zooms so that link fills the
// view and the card below says how much came from there.
import { useEffect, useMemo, useRef, useState } from 'react'
import { Minus, Plus, RotateCcw, X, ArrowRight } from 'lucide-react'
import DotGlobe, { type Pin, type DotGlobeApi } from '@/components/globe/DotGlobe'
import { countryCentroid, distanceKm, flagOf } from '@/lib/country-centroids'
import { si, bps, bytes as fmtBytes } from '@/lib/format'
import type { GeoCount } from '@/lib/attacks'

// Where the appliance sits (the hub every arc lands on). Denmark by default.
const HOME = { label: 'XDP Sentinel', lat: 56.0, lng: 10.0 }
// DotGlobe draws at most 24 arcs from the hub; keep the strongest 23 countries.
const MAX_COUNTRIES = 23

interface Look { dot: string; ocean: string; glow: string; attack: string; label: string }
const FALLBACK: Look = { dot: '#71717a', ocean: '#111218', glow: '#34d399', attack: '#f43f5e', label: '#e4e4e7' }

// WebGL needs concrete colours, not var(--x): read the live token values.
function readLook(el: Element): Look {
  const cs = getComputedStyle(el)
  const v = (name: string, fb: string) => cs.getPropertyValue(name).trim() || fb
  return {
    dot: v('--nd-dim', FALLBACK.dot),
    ocean: v('--nd-card', FALLBACK.ocean),
    glow: v('--nd-brand', FALLBACK.glow),
    attack: v('--st-crit', FALLBACK.attack),
    label: v('--nd-fg-2', FALLBACK.label),
  }
}

function useThemeLook(ref: React.RefObject<HTMLElement | null>): Look {
  const [look, setLook] = useState<Look>(FALLBACK)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const update = () => setLook(readLook(el))
    update()
    // re-read when the theme wrapper flips between .nd-dark and .nd-light
    const themed = el.closest('.nd-dark, .nd-light')
    if (!themed) return
    const mo = new MutationObserver(update)
    mo.observe(themed, { attributes: true, attributeFilter: ['class'] })
    return () => mo.disconnect()
  }, [ref])
  return look
}

const keyOf = (c: GeoCount) => (c.cc ?? c.key).toUpperCase()
const ago = (ms: number) => {
  const s = Math.max(0, (Date.now() - ms) / 1000)
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))} min ago`
  if (s < 86400 * 2) return `${Math.round(s / 3600)} h ago`
  return `${Math.round(s / 86400)} days ago`
}

function Stat({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="min-w-0">
      <div className="text-[10.5px] font-medium uppercase tracking-[0.06em] text-nd-dim">{label}</div>
      <div className="mono mt-0.5 truncate text-[17px] font-semibold tabular-nums text-nd-fg">{value}</div>
      {sub && <div className="truncate text-[11px] text-nd-faint">{sub}</div>}
    </div>
  )
}

export function AttackGlobe({ countries, className, height = 360, selected, onSelect, onShowAttacks, scope = 'all', bare = false }: {
  countries: GeoCount[]
  className?: string
  height?: number
  /** Selected country code (controlled); leave out to let the globe keep its own. */
  selected?: string | null
  onSelect?: (cc: string | null) => void
  /** Overview only: "show the attacks from this country" in the card. */
  onShowAttacks?: (c: GeoCount) => void
  /** Wording of the card: totals over every attack, one attack, or live rates (packets = packets/s, bytes = bytes/s). */
  scope?: 'all' | 'attack' | 'live'
  /** Just the globe: no hint line, zoom buttons or details card (Show mode). */
  bare?: boolean
}) {
  const ref = useRef<HTMLDivElement | null>(null)
  const api = useRef<DotGlobeApi | null>(null)
  const look = useThemeLook(ref)
  const [own, setOwn] = useState<string | null>(null)
  const sel = selected !== undefined ? selected : own
  const select = (cc: string | null) => {
    if (selected === undefined) setOwn(cc)
    onSelect?.(cc)
  }

  // pins[0] is the hub; pins[i] (i >= 1) is shown[i - 1]
  const { pins, shown, unplaced, total } = useMemo(() => {
    const pins: Pin[] = [HOME]
    const shown: (GeoCount & { at: { lat: number; lng: number } })[] = []
    let unplaced = 0
    const sorted = [...countries].sort((a, b) => b.packets - a.packets)
    const top = sorted[0]?.packets || 1
    for (const c of sorted) {
      const at = countryCentroid(c.cc ?? c.key)
      if (!at) { unplaced += 1; continue }
      if (shown.length >= MAX_COUNTRIES) continue
      // a source in the box's own country sits on the hub: marker only, no second label
      const onHub = Math.abs(at.lat - HOME.lat) < 1 && Math.abs(at.lng - HOME.lng) < 1
      // arc thickness follows the share of dropped packets (square root, so small ones stay visible)
      pins.push({ label: onHub ? '' : c.label, ...at, weight: Math.sqrt(c.packets / top) })
      shown.push({ ...c, at })
    }
    const total = sorted.reduce((n, c) => n + c.packets, 0)
    return { pins, shown, unplaced, total }
  }, [countries])

  const idx = sel ? shown.findIndex((c) => keyOf(c) === sel) : -1
  const cur = idx >= 0 ? shown[idx] : null
  // a selection that has dropped out of the data (new window, other attack) is cleared
  useEffect(() => {
    if (sel && idx < 0 && countries.length && selected === undefined) setOwn(null)
  }, [sel, idx, countries.length, selected])

  const names = shown.map((c) => c.label).join(', ')
  const pinsShown = shown.length
  const share = cur && total ? cur.packets / total : 0
  const km = cur ? Math.round(distanceKm(cur.at, HOME) / 10) * 10 : 0
  const iconBtn = 'inline-flex h-7 w-7 items-center justify-center rounded-md border border-nd-line bg-nd-card text-nd-fg-3 shadow-nd transition-colors hover:border-nd-line-strong hover:text-nd-fg disabled:opacity-40'

  return (
    <div ref={ref} className={className}>
      <div className="mx-auto" style={{ height, aspectRatio: '1 / 1', maxWidth: '100%' }}>
        <DotGlobe
          pins={pins}
          selected={idx >= 0 ? idx + 1 : -1}
          onSelect={(i) => select(i >= 1 && shown[i - 1] ? (keyOf(shown[i - 1]) === sel ? null : keyOf(shown[i - 1])) : null)}
          apiRef={api}
          arcs={{ mode: pinsShown > 0 ? 'hub' : 'off', color: look.attack, speed: 45 }}
          markers={{ color: look.attack, labelColor: look.label, size: 110, pulse: true, labels: true }}
          globe={{ dotColor: look.dot, oceanColor: look.ocean, oceanOpacity: 90, glowColor: look.glow, glow: 45, size: 82, density: 55, dotSize: 55 }}
          motion={{ autoRotate: true, speed: 6, drag: true, startLng: HOME.lng, tilt: 24 }}
          background={{ transparent: true }}
          label={pinsShown ? `Attack origins: ${names}` : 'No geolocated attack sources'}
          style={{ width: '100%', height: '100%' }}
        />
      </div>

      {bare ? null : pinsShown === 0 ? (
        <p className="mt-2 text-center text-[12px] text-nd-dim">No geolocated internet sources yet: attacks so far came from inside the network.</p>
      ) : (
        <>
          <div className="mt-3 flex items-center justify-between gap-3">
            <p className="min-w-0 text-[11.5px] text-nd-faint">
              Click a country or its link · drag to turn · pinch or <span className="whitespace-nowrap">Ctrl/⌘ + scroll</span> to zoom
            </p>
            <div className="flex shrink-0 items-center gap-1.5">
              <button type="button" className={iconBtn} onClick={() => api.current?.zoomBy(1 / 1.5)} aria-label="Zoom out" title="Zoom out"><Minus className="h-3.5 w-3.5" /></button>
              <button type="button" className={iconBtn} onClick={() => api.current?.zoomBy(1.5)} aria-label="Zoom in" title="Zoom in"><Plus className="h-3.5 w-3.5" /></button>
              <button type="button" className={iconBtn} onClick={() => { select(null); api.current?.reset() }} aria-label="Reset view" title="Reset view"><RotateCcw className="h-3.5 w-3.5" /></button>
            </div>
          </div>

          {/* fixed-height slot: picking a country never shifts the page */}
          <div className="mt-3 min-h-[132px] rounded-xl border border-nd-line bg-nd-fill p-4" aria-live="polite">
            {cur ? (
              <div>
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="truncate text-[15px] font-semibold text-nd-fg">
                      <span className="mr-2">{flagOf(cur.cc)}</span>{cur.label}
                    </div>
                    <div className="mt-0.5 flex items-center gap-1.5 text-[11.5px] text-nd-dim">
                      {cur.label} <ArrowRight className="h-3 w-3" /> {HOME.label}
                      {km > 50 && <span className="text-nd-faint">· {si(km)} km link</span>}
                    </div>
                  </div>
                  <button type="button" className={iconBtn} onClick={() => select(null)} aria-label="Clear selection" title="Clear (Esc)"><X className="h-3.5 w-3.5" /></button>
                </div>
                <div className="mt-3 grid grid-cols-2 gap-x-4 gap-y-3 sm:grid-cols-4">
                  {scope === 'live' ? (
                    <>
                      <Stat label="Dropping now" value={`${si(cur.packets)} pps`} sub={`${(share * 100).toFixed(share < 0.1 ? 1 : 0)}% of the located flood`} />
                      <Stat label="Bandwidth" value={cur.bytes ? bps(cur.bytes * 8) : '—'} sub="from this country" />
                    </>
                  ) : (
                    <>
                      <Stat label="Packets dropped" value={si(cur.packets)} sub={`${(share * 100).toFixed(share < 0.1 ? 1 : 0)}% of ${scope === 'all' ? 'all located' : 'this attack'}`} />
                      <Stat label="Data dropped" value={cur.bytes ? `${cur.bytesPartial ? '≥ ' : cur.bytesEstimated ? '≈ ' : ''}${fmtBytes(cur.bytes)}` : '—'}
                        sub={cur.bytes ? (cur.bytesPartial ? 'some attacks not counted' : cur.bytesEstimated ? 'partly estimated' : 'bytes, all sources') : 'not recorded'} />
                    </>
                  )}
                  <Stat label="Sources" value={si(cur.sources)} sub={cur.sources === 1 ? 'address' : 'addresses'} />
                  {scope === 'all'
                    ? <Stat label="Attacks" value={si(cur.attacks ?? 0)} sub={cur.last ? `latest ${ago(cur.last)}` : undefined} />
                    : <Stat label="Rank" value={`#${idx + 1}`} sub={`of ${shown.length} countr${shown.length === 1 ? 'y' : 'ies'}`} />}
                </div>
                <div className="mt-3 h-1.5 rounded-full bg-nd-track" title={`${(share * 100).toFixed(1)}% of the dropped packets`}>
                  <div className="h-full rounded-full" style={{ width: `${Math.max(1.5, share * 100)}%`, background: look.attack }} />
                </div>
                {onShowAttacks && (
                  <button type="button" onClick={() => onShowAttacks(cur)} className="mt-3 inline-flex items-center gap-1.5 text-[12.5px] font-medium text-nd-fg-3 transition-colors hover:text-nd-fg">
                    Show {cur.attacks === 1 ? 'the attack' : `the ${si(cur.attacks ?? 0)} attacks`} from {cur.label} <ArrowRight className="h-3.5 w-3.5" />
                  </button>
                )}
              </div>
            ) : (
              <div className="flex h-full min-h-[100px] flex-col items-center justify-center text-center">
                <div className="text-[13px] font-medium text-nd-fg-3">Pick a country to zoom in on its link</div>
                <div className="mt-1 text-[11.5px] text-nd-faint">
                  {pinsShown} countr{pinsShown === 1 ? 'y' : 'ies'} on the map · the thicker the link, the more it sent
                </div>
              </div>
            )}
          </div>
        </>
      )}
      {!bare && unplaced > 0 && (
        <p className="mt-2 text-center text-[11px] text-nd-faint">{unplaced} countr{unplaced === 1 ? 'y' : 'ies'} could not be placed on the map.</p>
      )}
    </div>
  )
}
