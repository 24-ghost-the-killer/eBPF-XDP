'use client'
// Adapted from React Bits — "Particles" (https://reactbits.dev), lightweight
// canvas version (no WebGL dep): a slow drifting dot field behind the UI.
import { useEffect, useRef } from 'react'

export default function Particles({
  count = 70,
  color = '148,163,184',
}: {
  count?: number
  color?: string
}) {
  const ref = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = ref.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return
    const dpr = Math.min(window.devicePixelRatio || 1, 2)
    let w = 0
    let h = 0
    let raf = 0
    const dots = Array.from({ length: count }, () => ({
      x: Math.random(),
      y: Math.random(),
      vx: (Math.random() - 0.5) * 0.0005,
      vy: (Math.random() - 0.5) * 0.0005,
      r: Math.random() * 1.4 + 0.4,
    }))
    const resize = () => {
      w = canvas.width = canvas.offsetWidth * dpr
      h = canvas.height = canvas.offsetHeight * dpr
    }
    const draw = () => {
      ctx.clearRect(0, 0, w, h)
      for (const d of dots) {
        d.x += d.vx
        d.y += d.vy
        if (d.x < 0 || d.x > 1) d.vx *= -1
        if (d.y < 0 || d.y > 1) d.vy *= -1
        ctx.beginPath()
        ctx.arc(d.x * w, d.y * h, d.r * dpr, 0, Math.PI * 2)
        ctx.fillStyle = `rgba(${color},0.45)`
        ctx.fill()
      }
      raf = requestAnimationFrame(draw)
    }
    resize()
    window.addEventListener('resize', resize)
    draw()
    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('resize', resize)
    }
  }, [count, color])

  return <canvas ref={ref} className="pointer-events-none fixed inset-0 -z-10 h-full w-full" />
}
