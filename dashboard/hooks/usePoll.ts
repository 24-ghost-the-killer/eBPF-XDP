'use client'
import { useEffect, useRef, useState } from 'react'

// Poll an async function on an interval. Returns { data, error, loading }.
export function usePoll<T>(fn: () => Promise<T>, intervalMs = 5000) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const saved = useRef(fn)
  saved.current = fn

  useEffect(() => {
    let alive = true
    const tick = async () => {
      try {
        const d = await saved.current()
        if (alive) {
          setData(d)
          setError(null)
        }
      } catch (e) {
        if (alive) setError(e instanceof Error ? e.message : String(e))
      } finally {
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
