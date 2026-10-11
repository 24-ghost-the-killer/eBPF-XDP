'use client'
import type { Talker } from '@/lib/prom'
import { bps } from '@/lib/format'

const hash = (s: string) => {
  let h = 0
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0
  return h
}

// Threat radar — plots top talkers as blips. Angle is stable per-IP (hashed),
// radius scales with traffic. scope colors: lan=emerald, wan=sky. Red under attack.
export default function Radar({
  talkers,
  attack,
  size = 230,
}: {
  talkers: Talker[]
  attack: boolean
  size?: number
}) {
  const c = size / 2
  const R = c - 12
  const rings = [0.33, 0.66, 1].map((f) => f * R)
  const max = Math.max(1, ...talkers.map((t) => t.v))
  const sweep = attack ? '#f43f5e' : '#34d399'

  const blips = talkers.slice(0, 8).map((t, i) => {
    const ang = (hash(t.ip) % 360) * (Math.PI / 180)
    const rad = 26 + (t.v / max) * (R - 34)
    const x = c + Math.cos(ang) * rad
    const y = c + Math.sin(ang) * rad
    const lan = t.scope === 'lan'
    const col = attack ? '#f43f5e' : lan ? '#34d399' : '#38bdf8'
    const big = i < 2
    return { ...t, x, y, col, big, key: t.ip + i }
  })

  return (
    <svg width="100%" viewBox={`0 0 ${size} ${size}`} className="block">
      <defs>
        <radialGradient id="radar-wedge" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor={sweep} stopOpacity="0.35" />
          <stop offset="100%" stopColor={sweep} stopOpacity="0" />
        </radialGradient>
      </defs>

      {/* rings */}
      {rings.map((r, i) => (
        <circle key={i} cx={c} cy={c} r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth={1} />
      ))}
      {/* crosshair */}
      <line x1={c} y1={c - R} x2={c} y2={c + R} stroke="rgba(255,255,255,0.06)" />
      <line x1={c - R} y1={c} x2={c + R} y2={c} stroke="rgba(255,255,255,0.06)" />

      {/* rotating sweep */}
      <g className="animate-radar">
        <path d={`M${c},${c} L${c + R},${c} A${R},${R} 0 0 1 ${c + R * Math.cos(-1)},${c + R * Math.sin(-1)} Z`} fill="url(#radar-wedge)" />
        <line x1={c} y1={c} x2={c + R} y2={c} stroke={sweep} strokeWidth={1.5} opacity={0.8} />
      </g>

      {/* blips */}
      {blips.map((b) => (
        <g key={b.key}>
          <circle cx={b.x} cy={b.y} r={b.big ? 4.5 : 3} fill={b.col} className="animate-blip" style={{ transformOrigin: `${b.x}px ${b.y}px` }} opacity={0.5} />
          <circle cx={b.x} cy={b.y} r={b.big ? 3 : 2.2} fill={b.col} />
          {b.big && (
            <text x={b.x + 7} y={b.y + 3} fontSize={8} className="mono" fill="rgba(228,228,231,0.75)">
              {b.ip} · {bps(b.v)}
            </text>
          )}
        </g>
      ))}

      {/* center */}
      <circle cx={c} cy={c} r={3} fill={sweep} />
      <circle cx={c} cy={c} r={7} fill="none" stroke={sweep} strokeWidth={1} opacity={0.5} />
    </svg>
  )
}
