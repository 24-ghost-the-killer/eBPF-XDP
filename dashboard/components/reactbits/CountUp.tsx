'use client'
// Adapted from React Bits — "Count Up" (https://reactbits.dev).
// Animates the displayed number from its previous value to the new target.
import { useEffect, useRef } from 'react'
import { animate, useInView } from 'framer-motion'

export default function CountUp({
  to,
  from = 0,
  duration = 0.8,
  format = (n: number) => Math.round(n).toString(),
  className = '',
}: {
  to: number
  from?: number
  duration?: number
  format?: (n: number) => string
  className?: string
}) {
  const ref = useRef<HTMLSpanElement>(null)
  const prev = useRef(from)
  const fmt = useRef(format)
  fmt.current = format
  const inView = useInView(ref, { once: false })

  useEffect(() => {
    const node = ref.current
    if (!node || !inView) return
    const controls = animate(prev.current, to, {
      duration,
      ease: 'easeOut',
      onUpdate: (v) => {
        node.textContent = fmt.current(v)
      },
    })
    prev.current = to
    return () => controls.stop()
  }, [to, inView, duration])

  return (
    <span ref={ref} className={className}>
      {format(from)}
    </span>
  )
}
