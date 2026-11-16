'use client'
// Red banner on every page while an attack is in progress, with what it is, how
// big, how much is being dropped and a link to the live view. Optional browser
// notification and alarm sound when a NEW attack starts (per-browser settings).
import { useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { Bell, BellOff, Volume2, VolumeX, X, ArrowRight } from 'lucide-react'
import { useLive, since } from '@/lib/live'
import { si, bps, pretty } from '@/lib/format'
import { levelName } from '@/lib/explain'

interface Prefs { notify: boolean; sound: boolean }
const KEY = 'xs-alert-prefs'
function loadPrefs(kiosk: boolean): Prefs {
  try {
    const j = JSON.parse(localStorage.getItem(KEY) || 'null')
    if (j && typeof j === 'object') return { notify: !!j.notify, sound: !!j.sound }
  } catch {}
  return { notify: false, sound: kiosk } // the kiosk screen sounds the alarm by default
}
function savePrefs(p: Prefs) {
  try { localStorage.setItem(KEY, JSON.stringify(p)) } catch {}
  window.dispatchEvent(new Event(KEY)) // other controls on the page follow
}

// The per-browser alert settings, kept in step across every control on the page.
export function useAlertPrefs(kiosk = false): [Prefs, (p: Prefs) => void] {
  const [prefs, setPrefs] = useState<Prefs>({ notify: false, sound: false })
  useEffect(() => {
    const load = () => setPrefs(loadPrefs(kiosk))
    load()
    window.addEventListener(KEY, load)
    return () => window.removeEventListener(KEY, load)
  }, [kiosk])
  return [prefs, (p: Prefs) => { setPrefs(p); savePrefs(p) }]
}

async function toggleNotify(prefs: Prefs, update: (p: Prefs) => void) {
  if (prefs.notify) return update({ ...prefs, notify: false })
  if (typeof Notification === 'undefined') return
  const p = Notification.permission === 'default' ? await Notification.requestPermission() : Notification.permission
  update({ ...prefs, notify: p === 'granted' })
}

// Standalone switches (shown with the live view even when all is calm).
export function AlertSettings() {
  const [prefs, update] = useAlertPrefs()
  const blocked = typeof Notification !== 'undefined' && Notification.permission === 'denied'
  const pill = (on: boolean) => `inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-[12px] font-medium transition-colors ${on ? 'border-st-crit/30 bg-st-crit/10 text-st-crit-fg' : 'border-nd-line text-nd-dim hover:text-nd-fg'}`
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <span className="text-[11.5px] text-nd-dim">When an attack starts:</span>
      <button type="button" className={pill(prefs.notify)} onClick={() => toggleNotify(prefs, update)} aria-pressed={prefs.notify}
        title={blocked ? 'Notifications are blocked for this site in the browser settings' : 'A browser notification, even when this tab is in the background'}>
        {prefs.notify ? <Bell className="h-3.5 w-3.5" /> : <BellOff className="h-3.5 w-3.5" />} Notify me
      </button>
      <button type="button" className={pill(prefs.sound)} onClick={() => { const on = !prefs.sound; update({ ...prefs, sound: on }); if (on) alarm() }} aria-pressed={prefs.sound}
        title="Three short beeps (needs this tab open)">
        {prefs.sound ? <Volume2 className="h-3.5 w-3.5" /> : <VolumeX className="h-3.5 w-3.5" />} Sound
      </button>
    </div>
  )
}

// Three short falling beeps (Web Audio, nothing to download).
function alarm() {
  try {
    const Ctx = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext
    const ctx = new Ctx()
    ;[0, 0.28, 0.56].forEach((t, k) => {
      const o = ctx.createOscillator()
      const g = ctx.createGain()
      o.type = 'square'
      o.frequency.value = 880 - k * 160
      g.gain.setValueAtTime(0.0001, ctx.currentTime + t)
      g.gain.exponentialRampToValueAtTime(0.18, ctx.currentTime + t + 0.02)
      g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + t + 0.22)
      o.connect(g).connect(ctx.destination)
      o.start(ctx.currentTime + t)
      o.stop(ctx.currentTime + t + 0.24)
    })
    setTimeout(() => ctx.close(), 1200)
  } catch {}
}

export function LiveAlert({ kiosk = false }: { kiosk?: boolean }) {
  const { live } = useLive(5000)
  const [prefs, update] = useAlertPrefs(kiosk)
  const [dismissed, setDismissed] = useState<number | null>(null)
  const [, tick] = useState(0)
  const seen = useRef<number | null>(null)
  const first = useRef(true)


  // a new attack (new start time) rings once; the first answer after a page load doesn't
  useEffect(() => {
    if (!live) return
    const start = live.active ? live.since ?? live.at : null
    if (start && start !== seen.current && !first.current) {
      if (prefs.sound) alarm()
      if (prefs.notify && typeof Notification !== 'undefined' && Notification.permission === 'granted') {
        try {
          new Notification('Attack detected', {
            body: `${(live.types ?? []).map(pretty).join(', ') || 'Flood'} on ${(live.ifaces ?? []).map((i) => i.label).join(', ')} · ${si(live.pps ?? 0)} packets/s`,
            tag: 'xs-attack',
          })
        } catch {}
      }
    }
    seen.current = start
    first.current = false
  }, [live, prefs])

  // keep the elapsed time ticking
  useEffect(() => {
    if (!live?.active) return
    const id = setInterval(() => tick((x) => x + 1), 1000)
    return () => clearInterval(id)
  }, [live?.active])

  if (!live?.active || (dismissed !== null && dismissed === live.since)) return null
  const share = live.dropShare ?? 0
  const askNotify = () => toggleNotify(prefs, update)
  const iconBtn = 'grid h-7 w-7 place-items-center rounded-md text-white/80 transition-colors hover:bg-white/15 hover:text-white'

  return (
    <div role="alert" className="border-t border-st-crit/40 bg-st-crit text-white print:hidden">
      <div className="mx-auto flex max-w-[1480px] flex-wrap items-center gap-x-4 gap-y-1.5 px-4 py-2.5 lg:px-8">
        <span className="relative flex h-2.5 w-2.5 shrink-0">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-white opacity-75 motion-reduce:animate-none" />
          <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-white" />
        </span>
        <div className="min-w-0 text-[13px]">
          <span className="font-semibold">Attack in progress</span>
          <span className="text-white/85"> · {(live.types ?? []).map(pretty).join(', ') || 'flood'} on {(live.ifaces ?? []).map((i) => i.label).join(', ')} · for {since(live.since)}</span>
        </div>
        <div className="mono flex flex-wrap gap-x-4 text-[12.5px] tabular-nums text-white/90">
          <span>{si(live.pps ?? 0)} pps</span>
          <span>{bps(live.bps ?? 0)}</span>
          <span>{(share * 100).toFixed(share < 0.1 && share > 0 ? 1 : 0)}% dropped</span>
          <span>L{live.level ?? 0} {levelName(live.level ?? 0)}</span>
        </div>
        <div className="ml-auto flex items-center gap-1">
          <Link href="/analytics/attacks#live" className="mr-1 inline-flex items-center gap-1 rounded-md bg-white px-2.5 py-1 text-[12.5px] font-semibold text-st-crit hover:bg-white/90">
            View live <ArrowRight className="h-3.5 w-3.5" />
          </Link>
          <button type="button" className={iconBtn} onClick={askNotify} title={prefs.notify ? 'Browser notifications on' : 'Notify me in the browser when an attack starts'} aria-pressed={prefs.notify}>
            {prefs.notify ? <Bell className="h-4 w-4" /> : <BellOff className="h-4 w-4" />}
          </button>
          <button type="button" className={iconBtn} onClick={() => { const on = !prefs.sound; update({ ...prefs, sound: on }); if (on) alarm() }} title={prefs.sound ? 'Alarm sound on' : 'Play an alarm when an attack starts'} aria-pressed={prefs.sound}>
            {prefs.sound ? <Volume2 className="h-4 w-4" /> : <VolumeX className="h-4 w-4" />}
          </button>
          <button type="button" className={iconBtn} onClick={() => setDismissed(live.since ?? null)} title="Hide until the next attack" aria-label="Hide until the next attack">
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  )
}
