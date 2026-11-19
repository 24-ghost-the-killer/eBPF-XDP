'use client'
// Show mode: a full-screen "network operations centre" view for a big screen or
// the kiosk display. Status and the defence ladder on the left, the attack
// globe in the middle, a live feed of events on the right, and live traffic
// with the key numbers along the bottom. Turns red and pulses during an
// attack; optional sound when one starts and ends.
// On the kiosk: /api/kiosk?k=<key>&next=/analytics/show
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import Link from 'next/link'
import { ShieldCheck, ShieldAlert, Maximize, Minimize, Volume2, VolumeX, X, Bug, FlaskConical, Zap, Radio, Activity, Swords, ServerCrash, UserX } from 'lucide-react'
import { AreaChart, Area, ResponsiveContainer, YAxis } from 'recharts'
import { useLive } from '@/lib/live'
import { instant, rangeAbs, scalar } from '@/lib/prom'
import { usePoll } from '@/hooks/usePoll'
import { si, bps, pretty } from '@/lib/format'
import { flagOf } from '@/lib/country-centroids'
import { AttackGlobe } from '@/components/globe/AttackGlobe'
import type { Episode, GeoCount } from '@/lib/attacks'
import { score } from '@/lib/game'

interface Numbers { inPps: number; dropPps: number; blockedToday: number }
interface Recent { attacks: Episode[]; week: number; countries: GeoCount[] }
interface HoneyHit { ip: string; device: string | null; last_at: number | null; packets: number; last_dport: number; blocked: boolean }
interface Honey { active: number; sources: HoneyHit[] }
interface SimRun { id: string; scenario: string; state: string; label: string; started_at: number; detected_at: number | null; mitigated_at: number | null; recovered_at: number | null; player?: string | null; game?: boolean; sent: number; dropped: number }
interface UpCheck { id: string; name: string; up: boolean | null; since: number | null }
interface Spoof { ip: string; mac: string; last_at: number | null; claimedBy: string | null; realName: string | null; dropped: number }
interface Sims { current: SimRun | null; history: SimRun[] }
type Point = { t: number; in: number; drop: number }
type Tone = 'red' | 'amber' | 'green' | 'sky' | 'pink' | 'orange'

const LADDER = [
  { name: 'Pass', hint: 'normal traffic' },
  { name: 'Watch', hint: 'looking closer' },
  { name: 'Sample', hint: 'recording packets' },
  { name: 'Rate-limit', hint: 'per-source cap' },
  { name: 'Clamp', hint: 'tight cap + type drops' },
  { name: 'Block', hint: 'attack traffic dropped' },
]
const INK: Record<Tone, string> = { red: 'text-rose-300', amber: 'text-amber-300', green: 'text-emerald-300', sky: 'text-sky-300', pink: 'text-fuchsia-300', orange: 'text-orange-300' }
const DOT: Record<Tone, string> = { red: 'bg-rose-400', amber: 'bg-amber-300', green: 'bg-emerald-400', sky: 'bg-sky-400', pink: 'bg-fuchsia-400', orange: 'bg-orange-400' }

const startOfDay = () => { const d = new Date(); d.setHours(0, 0, 0, 0); return d.getTime() / 1000 }
const hm = (ms: number) => new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
const dayHm = (ms: number) => {
  const d = new Date(ms), today = new Date()
  return d.toDateString() === today.toDateString() ? hm(ms) : d.toLocaleDateString([], { weekday: 'short' }) + ' ' + hm(ms)
}
const span = (sec: number) => {
  sec = Math.max(0, Math.round(sec))
  if (sec < 60) return `${sec} s`
  if (sec < 3600) return `${Math.floor(sec / 60)} min ${sec % 60} s`
  if (sec < 86400) return `${Math.floor(sec / 3600)} h ${Math.floor((sec % 3600) / 60)} min`
  return `${Math.floor(sec / 86400)} d ${Math.floor((sec % 86400) / 3600)} h`
}

// Smoothly counts towards the target value.
function useTween(target: number, ms = 900) {
  const [v, setV] = useState(target)
  const from = useRef(target)
  useEffect(() => {
    const a = from.current, t0 = performance.now()
    let raf = 0
    const step = (t: number) => {
      const k = Math.min(1, (t - t0) / ms)
      const val = a + (target - a) * (1 - Math.pow(1 - k, 3))
      setV(val); from.current = val
      if (k < 1) raf = requestAnimationFrame(step)
    }
    raf = requestAnimationFrame(step)
    return () => cancelAnimationFrame(raf)
  }, [target, ms])
  return v
}

// Size of an element (the globe needs a pixel height).
function useBox<T extends HTMLElement>() {
  const ref = useRef<T | null>(null)
  const [box, setBox] = useState({ w: 0, h: 0 })
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const ro = new ResizeObserver(([e]) => setBox({ w: e.contentRect.width, h: e.contentRect.height }))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  return [ref, box] as const
}

function tone(ctx: AudioContext, freq: number, at: number, len: number, vol = 0.18) {
  const o = ctx.createOscillator(), g = ctx.createGain()
  o.type = 'sine'; o.frequency.value = freq
  g.gain.setValueAtTime(0, ctx.currentTime + at)
  g.gain.linearRampToValueAtTime(vol, ctx.currentTime + at + 0.02)
  g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + at + len)
  o.connect(g).connect(ctx.destination)
  o.start(ctx.currentTime + at); o.stop(ctx.currentTime + at + len + 0.05)
}

export default function ShowPage() {
  const { live } = useLive(2000, true)
  const [now, setNow] = useState(() => Date.now())
  const [full, setFull] = useState(false)
  const [sound, setSound] = useState(false)
  const audio = useRef<AudioContext | null>(null)
  const wasActive = useRef<boolean | null>(null)
  const [globeRef, globeBox] = useBox<HTMLDivElement>()

  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(t) }, [])
  useEffect(() => {
    const f = () => setFull(!!document.fullscreenElement)
    document.addEventListener('fullscreenchange', f)
    try { setSound(localStorage.getItem('xs-show-sound') === '1') } catch {}
    return () => document.removeEventListener('fullscreenchange', f)
  }, [])

  const nums = usePoll<Numbers>(async () => {
    const q = async (e: string) => scalar(await instant(e), 0) ?? 0
    const sod = Math.max(60, Math.round(Date.now() / 1000 - startOfDay()))
    const [inPps, dropPps, blockedToday] = await Promise.all([
      q('sum(rate(xs_rx_packets_total[30s]))'),
      q('sum(rate(xs_verdict_packets_total{verdict="drop"}[30s]))'),
      q(`sum(increase(xs_verdict_packets_total{verdict="drop"}[${sod}s]))`),
    ])
    return { inPps, dropPps, blockedToday }
  }, 3000)

  const series = usePoll<Point[]>(async () => {
    const end = Math.floor(Date.now() / 1000), start = end - 15 * 60
    const [a, b] = await Promise.all([
      rangeAbs('sum(rate(xs_rx_packets_total[30s]))', start, end, 10),
      rangeAbs('sum(rate(xs_verdict_packets_total{verdict="drop"}[30s]))', start, end, 10),
    ])
    const drop = new Map((b[0]?.values ?? []).map(([t, v]) => [t, Number(v)]))
    // log scale below: keep values >= 1 so quiet periods and floods both show
    return (a[0]?.values ?? []).map(([t, v]) => ({ t, in: Math.max(1, Number(v) || 0), drop: Math.max(1, drop.get(t) ?? 0) }))
  }, 10000)

  const recent = usePoll<Recent>(async () => {
    const r = await fetch(`/api/attacks?offset=0&limit=12&marked=hide&from=${Math.floor(Date.now() / 1000 - 7 * 86400)}`, { cache: 'no-store' })
    const j = await r.json()
    if (j.status !== 'success') throw new Error(j.error)
    return { attacks: j.attacks as Episode[], week: Number(j.summary?.count) || 0, countries: (j.summary?.countries ?? []) as GeoCount[] }
  }, 20000)

  const honey = usePoll<Honey | null>(async () => {
    const r = await fetch('/api/honeypot', { cache: 'no-store' })
    if (!r.ok) return null
    const j = await r.json()
    return { active: Number(j.live?.active) || 0, sources: (j.live?.sources ?? []) as HoneyHit[] }
  }, 10000)

  const sims = usePoll<Sims | null>(async () => {
    const r = await fetch('/api/simulate', { cache: 'no-store' })
    if (!r.ok) return null
    const j = await r.json()
    return { current: j.current ?? null, history: j.history ?? [] }
  }, 3000)

  const uptime = usePoll<UpCheck[] | null>(async () => {
    const r = await fetch('/api/uptime', { cache: 'no-store' })
    if (!r.ok) return null
    const j = await r.json()
    return (j.checks ?? []) as UpCheck[]
  }, 20000)

  const guard = usePoll<Spoof[] | null>(async () => {
    const r = await fetch('/api/languard', { cache: 'no-store' })
    if (!r.ok) return null
    const j = await r.json()
    return (j.spoofing ?? []) as Spoof[]
  }, 15000)

  const active = !!live?.active
  useEffect(() => {
    if (wasActive.current !== null && wasActive.current !== active && sound) {
      try {
        audio.current ??= new AudioContext()
        const c = audio.current
        if (active) { tone(c, 880, 0, 0.18); tone(c, 660, 0.22, 0.18); tone(c, 880, 0.44, 0.18); tone(c, 660, 0.66, 0.3) }
        else { tone(c, 523, 0, 0.25, 0.12); tone(c, 784, 0.2, 0.4, 0.12) }
      } catch {}
    }
    wasActive.current = active
  }, [active, sound])

  const toggleSound = () => {
    const v = !sound
    setSound(v)
    try { localStorage.setItem('xs-show-sound', v ? '1' : '0') } catch {}
    if (v) { try { audio.current ??= new AudioContext(); audio.current.resume(); tone(audio.current, 660, 0, 0.15, 0.1) } catch {} }
  }
  const toggleFull = () => (document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen()).catch(() => {})

  const n = nums.data
  const inPps = useTween(active ? live?.pps ?? n?.inPps ?? 0 : n?.inPps ?? 0)
  const dropPps = useTween(active ? live?.dropPps ?? n?.dropPps ?? 0 : n?.dropPps ?? 0)
  const blockedToday = useTween(n?.blockedToday ?? 0, 1500)
  const level = Math.max(0, Math.min(5, live?.level ?? 0))
  const sim = sims.data?.current?.state === 'running' ? sims.data.current : null
  const lastAttack = recent.data?.attacks[0]
  const quietFor = lastAttack ? (now - lastAttack.end) / 1000 : null
  const countries = active ? live?.countries ?? [] : recent.data?.countries ?? []
  const globeH = Math.max(240, Math.min(globeBox.h, globeBox.w) - 8)
  const dropShare = inPps > 0 ? Math.min(1, dropPps / inPps) : 0

  const feed = useMemo(() => {
    const ev: { at: number; tone: Tone; icon: typeof Zap; title: string; sub: string }[] = []
    for (const a of recent.data?.attacks ?? []) {
      const kind = (a.vectors.length ? a.vectors : ['Attack']).map(pretty).join(' + ')
      ev.push({ at: a.start, tone: a.dropShare >= 0.9 ? 'green' : a.dropShare >= 0.3 ? 'amber' : 'red', icon: Zap, title: kind,
        sub: `${si(a.peakPps)} pps peak · ${Math.round(a.dropShare * 100)}% blocked · ${span(a.durationSec)}` })
    }
    for (const h of honey.data?.sources ?? []) {
      if (!h.last_at) continue
      ev.push({ at: h.last_at * 1000, tone: 'pink', icon: Bug, title: `Honeypot: ${h.device ?? h.ip}`,
        sub: h.packets ? `knocked${h.last_dport ? ` on port ${h.last_dport}` : ''}${h.blocked ? ' · blocked from the LAN' : ''}` : 'looked for a decoy' })
    }
    for (const s of sims.data?.history ?? []) {
      const sc = s.game ? score(s) : null
      if (sc) {
        ev.push({ at: s.started_at * 1000, tone: 'sky', icon: Swords, title: `Red vs blue: ${s.player} · ${s.label}`, sub: `red ${sc.red} – blue ${sc.blue}${sc.missed ? ' · went undetected!' : ''}` })
        continue
      }
      ev.push({ at: s.started_at * 1000, tone: 'sky', icon: FlaskConical, title: `Simulation: ${s.label}`,
        sub: s.detected_at == null ? 'not detected' : `detected in ${s.detected_at.toFixed(1)} s${s.mitigated_at != null ? ` · defended in ${s.mitigated_at.toFixed(1)} s` : ''}` })
    }
    for (const c of uptime.data ?? []) {
      if (c.up === false && c.since) ev.push({ at: c.since, tone: 'orange', icon: ServerCrash, title: `${c.name} is down`, sub: 'service check failing' })
    }
    for (const sp of guard.data ?? []) {
      if (sp.last_at) ev.push({ at: sp.last_at * 1000, tone: 'red', icon: UserX, title: `ARP spoofing: ${sp.claimedBy ?? sp.mac}`, sub: `pretended to be ${sp.realName ?? sp.ip}${sp.dropped ? ' · dropped' : ''}` })
    }
    return ev.sort((x, y) => y.at - x.at).slice(0, 9)
  }, [recent.data, honey.data, sims.data, uptime.data, guard.data])

  const d = new Date(now)
  return (
    <div className={`xs-show fixed inset-0 z-[100] grid grid-rows-[auto_minmax(0,1fr)_auto] gap-4 overflow-hidden p-6 text-white ${active ? 'xs-alert' : ''}`}>
      <style>{`
        .xs-show { background:
          radial-gradient(ellipse 60% 55% at 50% 45%, ${active ? 'rgba(244,63,94,.16)' : 'rgba(16,185,129,.10)'}, transparent 70%),
          linear-gradient(rgba(255,255,255,.025) 1px, transparent 1px) 0 0 / 100% 48px,
          linear-gradient(90deg, rgba(255,255,255,.025) 1px, transparent 1px) 0 0 / 48px 100%,
          #04060b; }
        .xs-alert { box-shadow: inset 0 0 0 3px rgba(244,63,94,.9), inset 0 0 140px rgba(244,63,94,.28); animation: xs-pulse 1.6s ease-in-out infinite; }
        @keyframes xs-pulse { 50% { box-shadow: inset 0 0 0 3px rgba(244,63,94,.4), inset 0 0 60px rgba(244,63,94,.1); } }
        .xs-card { border: 1px solid rgba(255,255,255,.08); background: rgba(10,14,22,.72); backdrop-filter: blur(6px); border-radius: 18px; }
        .xs-cap { font-size: 11px; font-weight: 600; letter-spacing: .16em; text-transform: uppercase; color: rgba(255,255,255,.45); }
        .xs-feed-in { animation: xs-in .5s ease-out both; }
        @keyframes xs-in { from { opacity: 0; transform: translateY(-6px); } }
        @media (prefers-reduced-motion: reduce) { .xs-alert, .xs-feed-in { animation: none; } }
      `}</style>

      {/* header */}
      <header className="flex items-center gap-4">
        <div className="flex items-center gap-2.5">
          <span className="relative flex h-3 w-3">
            <span className={`absolute inline-flex h-full w-full animate-ping rounded-full opacity-60 ${active ? 'bg-rose-400' : 'bg-emerald-400'}`} />
            <span className={`relative inline-flex h-3 w-3 rounded-full ${active ? 'bg-rose-400' : 'bg-emerald-400'}`} />
          </span>
          <span className="text-[19px] font-semibold tracking-tight">xdp-sentinel</span>
          <span className="xs-cap ml-1 hidden sm:inline">Network defence · live</span>
        </div>
        {sim && (sim.game ? (
          <div className="flex items-center gap-2 rounded-full border border-rose-400/40 bg-rose-500/20 px-3.5 py-1 text-[13px] font-semibold text-rose-100">
            <Swords className="h-4 w-4" /> Red vs blue: {sim.player} attacks with {sim.label}
          </div>
        ) : (
          <div className="flex items-center gap-2 rounded-full border border-sky-400/30 bg-sky-500/15 px-3.5 py-1 text-[13px] font-medium text-sky-200">
            <FlaskConical className="h-4 w-4" /> Simulation running: {sim.label}
          </div>
        ))}
        <div className="ml-auto text-right leading-tight">
          <div className="font-mono text-[26px] font-medium tabular-nums">{d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</div>
          <div className="text-[12px] text-white/45">{d.toLocaleDateString([], { weekday: 'long', day: 'numeric', month: 'long' })}</div>
        </div>
        <div className="flex items-center gap-1">
          <IconBtn onClick={toggleSound} label={sound ? 'Sound off' : 'Sound on'}>{sound ? <Volume2 className="h-5 w-5" /> : <VolumeX className="h-5 w-5" />}</IconBtn>
          <IconBtn onClick={toggleFull} label="Full screen">{full ? <Minimize className="h-5 w-5" /> : <Maximize className="h-5 w-5" />}</IconBtn>
          <Link href="/analytics" className="rounded-lg p-2 text-white/50 transition-colors hover:bg-white/10 hover:text-white" aria-label="Leave show mode"><X className="h-5 w-5" /></Link>
        </div>
      </header>

      {/* middle: status | globe | feed */}
      <div className="grid min-h-0 grid-cols-[minmax(230px,1fr)_minmax(0,2.4fr)_minmax(260px,1.15fr)] gap-4">
        <aside className="flex min-h-0 flex-col gap-4">
          <div className={`xs-card px-5 py-5 ${active ? '!border-rose-400/40 !bg-rose-500/10' : ''}`}>
            <div className="xs-cap">Status</div>
            <div className={`mt-2 flex items-center gap-2.5 text-[28px] font-bold leading-none tracking-tight ${active ? 'text-rose-300' : 'text-emerald-300'}`}>
              {active ? <ShieldAlert className="h-8 w-8" /> : <ShieldCheck className="h-8 w-8" />}
              {active ? 'Under attack' : 'All clear'}
            </div>
            <div className="mt-2.5 text-[13.5px] text-white/60">
              {active
                ? <>{(live?.types ?? []).map(pretty).join(' + ') || 'Flood'} for <span className="font-semibold text-white">{span(live?.since ? (now - live.since) / 1000 : 0)}</span></>
                : quietFor != null ? <>No attack for <span className="font-semibold text-white">{span(quietFor)}</span></> : 'No attacks recorded this week'}
            </div>
            {(uptime.data?.length ?? 0) > 0 && (() => {
              const down = (uptime.data ?? []).filter((c) => c.up === false)
              return (
                <div className={`mt-2 text-[13px] ${down.length ? 'font-medium text-orange-300' : 'text-white/50'}`}>
                  {down.length ? `Down: ${down.map((c) => c.name).join(', ')}` : `All ${uptime.data!.length} services up`}
                </div>
              )
            })()}
          </div>

          <div className="xs-card flex min-h-0 flex-1 flex-col px-5 py-4">
            <div className="xs-cap">Defence ladder</div>
            <ol className="mt-3 flex min-h-0 flex-1 flex-col-reverse gap-1.5">
              {LADDER.map((s, i) => {
                const on = i <= level, here = i === level
                const color = i >= 4 ? 'bg-rose-400' : i >= 2 ? 'bg-amber-300' : 'bg-emerald-400'
                return (
                  <li key={s.name} className={`flex max-h-16 min-h-0 flex-1 items-center gap-3 rounded-xl px-3 transition-colors duration-500 ${here ? 'bg-white/[0.08] ring-1 ring-white/10' : ''}`}>
                    <span className={`w-6 font-mono text-[12px] ${here ? 'text-white' : 'text-white/35'}`}>L{i}</span>
                    <span className="min-w-0 flex-1">
                      <span className={`block truncate text-[14px] font-medium leading-tight ${here ? 'text-white' : on ? 'text-white/70' : 'text-white/35'}`}>{s.name}</span>
                      {here && <span className="block truncate text-[11.5px] text-white/50">{s.hint}</span>}
                    </span>
                    <span className={`h-2 w-10 shrink-0 rounded-full transition-all duration-500 ${on ? `${color} opacity-90` : 'bg-white/[0.07]'}`} style={here ? { boxShadow: '0 0 14px currentColor' } : undefined} />
                  </li>
                )
              })}
            </ol>
          </div>
        </aside>

        <section className="relative flex min-h-0 flex-col">
          <div className="flex items-baseline justify-between">
            <div className="xs-cap">{active ? 'Attack sources — right now' : 'Where attacks came from — last 7 days'}</div>
            <div className="text-[12px] text-white/40">{countries.length ? `${countries.length} countr${countries.length === 1 ? 'y' : 'ies'}` : ''}</div>
          </div>
          <div ref={globeRef} className="nd-dark pointer-events-none flex min-h-0 flex-1 items-center justify-center !bg-transparent">
            {globeBox.h > 0 && <AttackGlobe countries={countries} height={globeH} scope={active ? 'live' : 'attack'} bare />}
          </div>
          {active && (live?.sources ?? []).length > 0 && (
            <div className="absolute inset-x-6 bottom-2 flex flex-wrap justify-center gap-2">
              {(live?.sources ?? []).slice(0, 5).map((s) => (
                <span key={s.ip} className="rounded-full border border-rose-400/30 bg-rose-500/15 px-3 py-1 font-mono text-[12.5px] text-rose-100">
                  {s.cc ? `${flagOf(s.cc)} ` : ''}{s.ip} · {si(s.pps)} pps
                </span>
              ))}
            </div>
          )}
        </section>

        <aside className="xs-card flex min-h-0 flex-col px-5 py-4">
          <div className="flex items-center justify-between">
            <div className="xs-cap">Live feed</div>
            <Radio className={`h-4 w-4 ${active ? 'text-rose-300' : 'text-white/30'}`} />
          </div>
          {feed.length === 0 ? (
            <p className="mt-6 text-[13.5px] text-white/40">Quiet. Events appear here as they happen.</p>
          ) : (
            <ul className="mt-3 flex min-h-0 flex-1 flex-col gap-1 overflow-hidden">
              {feed.map((e, i) => {
                const I = e.icon
                return (
                  <li key={`${e.at}-${e.title}`} className="xs-feed-in flex gap-3 rounded-xl px-2 py-2" style={{ opacity: 1 - i * 0.07 }}>
                    <span className={`mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-white/[0.06] ${INK[e.tone]}`}><I className="h-4 w-4" /></span>
                    <span className="min-w-0 flex-1">
                      <span className="flex items-baseline justify-between gap-2">
                        <span className="truncate text-[14px] font-medium text-white/90">{e.title}</span>
                        <span className="shrink-0 font-mono text-[11.5px] text-white/40">{dayHm(e.at)}</span>
                      </span>
                      <span className="block truncate text-[12px] text-white/50">{e.sub}</span>
                    </span>
                  </li>
                )
              })}
            </ul>
          )}
          <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 border-t border-white/[0.06] pt-3 text-[11.5px] text-white/45">
            {(['red', 'amber', 'green'] as Tone[]).map((t, i) => <span key={t} className="flex items-center gap-1.5"><span className={`h-1.5 w-1.5 rounded-full ${DOT[t]}`} />{['under 30% blocked', 'partly blocked', '90%+ blocked'][i]}</span>)}
            <span className="flex items-center gap-1.5"><span className={`h-1.5 w-1.5 rounded-full ${DOT.pink}`} />honeypot</span>
            <span className="flex items-center gap-1.5"><span className={`h-1.5 w-1.5 rounded-full ${DOT.sky}`} />simulation / game</span>
            <span className="flex items-center gap-1.5"><span className={`h-1.5 w-1.5 rounded-full ${DOT.orange}`} />service down</span>
          </div>
        </aside>
      </div>

      {/* bottom: numbers + live traffic */}
      <footer className="xs-card grid grid-cols-[repeat(5,minmax(0,1fr))_minmax(0,2.2fr)] overflow-hidden">
        <Kpi label="Traffic in" value={si(inPps)} unit="pps" sub={active && live?.bps ? bps(live.bps) : 'all interfaces'} />
        <Kpi label="Blocked now" value={si(dropPps)} unit="pps" sub={inPps > 1 ? `${Math.round(dropShare * 100)}% of traffic` : '—'} tone={dropPps >= 1 ? (active ? 'red' : 'green') : undefined} />
        <Kpi label="Blocked today" value={si(blockedToday)} sub="packets" />
        <Kpi label="Attacks" value={recent.data ? String(recent.data.week) : '—'} sub="last 7 days" />
        <Kpi label="Decoys" value={honey.data ? String(honey.data.active) : '—'} sub={honey.data ? `${honey.data.sources.filter((s) => s.packets > 0).length} caught knocking` : 'honeypot'} tone={honey.data?.sources.some((s) => s.packets > 0) ? 'pink' : undefined} />
        <div className="border-l border-white/[0.06] px-5 py-3">
          <div className="flex items-center justify-between">
            <div className="xs-cap flex items-center gap-1.5"><Activity className="h-3.5 w-3.5" />Traffic · last 15 min <span className="normal-case tracking-normal text-white/30">(log scale)</span></div>
            <div className="flex gap-3 text-[11px] text-white/45">
              <span className="flex items-center gap-1.5"><span className="h-1.5 w-3 rounded-full bg-sky-400" />in</span>
              <span className="flex items-center gap-1.5"><span className="h-1.5 w-3 rounded-full bg-rose-400" />blocked</span>
            </div>
          </div>
          <div className="mt-1 h-[64px]">
            {(series.data?.length ?? 0) > 1 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={series.data ?? []} margin={{ top: 4, right: 0, bottom: 0, left: 0 }}>
                  <defs>
                    <linearGradient id="xs-in" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#38bdf8" stopOpacity={0.45} /><stop offset="100%" stopColor="#38bdf8" stopOpacity={0} /></linearGradient>
                    <linearGradient id="xs-drop" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#fb7185" stopOpacity={0.55} /><stop offset="100%" stopColor="#fb7185" stopOpacity={0} /></linearGradient>
                  </defs>
                  <YAxis hide scale="log" domain={[1, 'dataMax']} allowDataOverflow />
                  <Area type="monotone" dataKey="drop" stroke="#fb7185" strokeWidth={1.5} fill="url(#xs-drop)" baseValue={1} isAnimationActive={false} />
                  <Area type="monotone" dataKey="in" stroke="#38bdf8" strokeWidth={1.75} fill="url(#xs-in)" fillOpacity={0.5} baseValue={1} isAnimationActive={false} />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center text-[12.5px] text-white/35">No traffic data yet (is the agent running?)</div>
            )}
          </div>
        </div>
      </footer>
    </div>
  )
}

function Kpi({ label, value, unit, sub, tone }: { label: string; value: string; unit?: string; sub: string; tone?: Tone }) {
  return (
    <div className="border-l border-white/[0.06] px-5 py-3 first:border-l-0">
      <div className="xs-cap">{label}</div>
      <div className={`mt-1 flex items-baseline gap-1.5 ${tone ? INK[tone] : 'text-white'}`}>
        <span className="text-[34px] font-semibold leading-none tabular-nums">{value}</span>
        {unit && <span className="text-[13px] text-white/45">{unit}</span>}
      </div>
      <div className="mt-1.5 truncate text-[12px] text-white/45">{sub}</div>
    </div>
  )
}

function IconBtn({ onClick, label, children }: { onClick: () => void; label: string; children: ReactNode }) {
  return (
    <button type="button" onClick={onClick} aria-label={label} title={label}
      className="rounded-lg p-2 text-white/50 transition-colors hover:bg-white/10 hover:text-white">{children}</button>
  )
}
