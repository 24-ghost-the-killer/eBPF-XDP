'use client'
// 270° radial gauge. Single-hue magnitude (emerald), escalating to amber/rose
// as load approaches the ceiling. Status color is reserved and thresholded.
export default function Gauge({
  value, // 0..1 ratio of the arc to fill
  center, // big center label (already formatted)
  sub,
  size = 148,
}: {
  value: number | null
  center: string
  sub?: string
  size?: number
}) {
  const v = value == null ? 0 : Math.max(0, Math.min(1, value))
  const r = size / 2 - 14
  const c = size / 2
  const circ = 2 * Math.PI * r
  const arc = 0.75 // 270°
  const track = arc * circ
  const fill = v * arc * circ

  const color = v >= 0.85 ? '#f43f5e' : v >= 0.6 ? '#fbbf24' : '#34d399'
  const glow = v >= 0.85 ? 'rgba(244,63,94,0.55)' : v >= 0.6 ? 'rgba(251,191,36,0.5)' : 'rgba(52,211,153,0.55)'

  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="block">
        <g transform={`rotate(135 ${c} ${c})`}>
          {/* track */}
          <circle
            cx={c}
            cy={c}
            r={r}
            fill="none"
            stroke="rgba(255,255,255,0.08)"
            strokeWidth={9}
            strokeLinecap="round"
            strokeDasharray={`${track} ${circ}`}
          />
          {/* value */}
          <circle
            cx={c}
            cy={c}
            r={r}
            fill="none"
            stroke={color}
            strokeWidth={9}
            strokeLinecap="round"
            strokeDasharray={`${fill} ${circ}`}
            style={{
              transition: 'stroke-dasharray 0.9s cubic-bezier(0.22,1,0.36,1), stroke 0.4s',
              filter: `drop-shadow(0 0 6px ${glow})`,
            }}
          />
        </g>
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <div className="mono text-[22px] font-semibold tabular-nums text-zinc-50">{center}</div>
        {sub && (
          <div className="mt-0.5 text-[9.5px] font-medium uppercase tracking-[0.18em] text-zinc-500">
            {sub}
          </div>
        )}
      </div>
    </div>
  )
}
