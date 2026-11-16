'use client'
// Live attack state from /api/live (see the route for the shape).
import { useEffect, useRef, useState } from 'react'
import type { GeoCount } from './attacks'

export interface LiveSource { ip: string; scope: string; pps: number; bps: number; cc?: string; country?: string; asn?: number; org?: string }
export interface Live {
  active: boolean; at: number; since?: number
  ifaces?: { iface: string; label: string; pps: number }[]
  types?: string[]; pps?: number; bps?: number; dropPps?: number; dropShare?: number; level?: number; cap?: number
  sources?: LiveSource[]; countries?: GeoCount[]
}

// Poll every `ms` (slower while the tab is hidden). `sources` also asks for the
// live sources and their countries (heavier: only the live globe needs it).
export function useLive(ms = 5000, sources = false): { live: Live | null; error: string } {
  const [live, setLive] = useState<Live | null>(null)
  const [error, setError] = useState('')
  const busy = useRef(false)
  useEffect(() => {
    let alive = true
    let timer: ReturnType<typeof setTimeout>
    const tick = async () => {
      if (!busy.current) {
        busy.current = true
        try {
          const r = await fetch(`/api/live${sources ? '?sources=1' : ''}`, { cache: 'no-store', signal: AbortSignal.timeout(10000) })
          const j = await r.json()
          if (alive) {
            if (j.status === 'success') { setLive(j as Live); setError('') } else setError(j.error || 'live state unavailable')
          }
        } catch (e) {
          if (alive) setError(e instanceof Error ? e.message : 'live state unavailable')
        } finally {
          busy.current = false
        }
      }
      if (alive) timer = setTimeout(tick, document.hidden ? Math.max(ms, 15000) : ms)
    }
    tick()
    return () => { alive = false; clearTimeout(timer) }
  }, [ms, sources])
  return { live, error }
}

export const since = (ms?: number) => {
  if (!ms) return ''
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000))
  return s < 60 ? `${s} s` : s < 3600 ? `${Math.floor(s / 60)} min ${s % 60} s` : `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min`
}
