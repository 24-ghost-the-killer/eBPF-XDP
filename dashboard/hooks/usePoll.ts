'use client'
import { useEffect, useRef, useState } from 'react'

// Poll an async function on an interval. Returns { data, error, loading }.
export function usePoll<T>(fn: () => Promise<T>, intervalMs = 5000) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const saved = useRef(fn)
  saved.current = fn
  const busy = useRef(false)

  useEffect(() => {
    let alive = true
    const tick = async () => {
      // Overlap guard: never start a new poll while the previous one is still
      // in flight. Otherwise, when the backend slows down, setInterval keeps
      // stacking fetches on top of stuck ones until the browser's connection
      // pool is exhausted and the page locks up. On error we keep the last-good
      // `data` so panels (incl. Active Defense) show stale values, not blanks.
      if (busy.current) return
      busy.current = true
      try {
        const d = await saved.current()
        if (alive) {
          setData(d)
          setError(null)
        }
      } catch (e) {
        if (alive) setError(e instanceof Error ? e.message : String(e))
      } finally {
        busy.current = false
        if (alive) setLoading(false)
      }
    }
    tick()
    const id = setInterval(tick, intervalMs)
    return () => {
      alive = false
      clearInterval(id)
    }
  }, [intervalMs])

  return { data, error, loading }
}
