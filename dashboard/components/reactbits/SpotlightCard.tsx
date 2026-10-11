'use client'
// Adapted from React Bits — "Spotlight Card" (https://reactbits.dev).
// A card that reveals a soft radial spotlight that follows the cursor on hover.
import { useRef, type MouseEvent, type ReactNode } from 'react'

export default function SpotlightCard({
  children,
  className = '',
  spotlightColor = 'rgba(52, 211, 153, 0.10)',
}: {
  children: ReactNode
  className?: string
  spotlightColor?: string
}) {
  const ref = useRef<HTMLDivElement>(null)

  const onMove = (e: MouseEvent<HTMLDivElement>) => {
    const el = ref.current
    if (!el) return
    const r = el.getBoundingClientRect()
    el.style.setProperty('--sx', `${e.clientX - r.left}px`)
    el.style.setProperty('--sy', `${e.clientY - r.top}px`)
  }

  return (
    <div
      ref={ref}
      onMouseMove={onMove}
      className={`panel group relative overflow-hidden ${className}`}
    >
      <div
        className="pointer-events-none absolute inset-0 opacity-0 transition-opacity duration-500 group-hover:opacity-100"
        style={{
          background: `radial-gradient(500px circle at var(--sx) var(--sy), ${spotlightColor}, transparent 55%)`,
        }}
      />
      <div className="relative h-full">{children}</div>
    </div>
  )
}
