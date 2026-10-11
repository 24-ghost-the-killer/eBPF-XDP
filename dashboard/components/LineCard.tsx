'use client'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
  CartesianGrid,
} from 'recharts'
import type { Row } from '@/lib/prom'
import SpotlightCard from './reactbits/SpotlightCard'

const COLORS = [
  '#38bdf8', '#f87171', '#34d399', '#fbbf24',
  '#a78bfa', '#f472b6', '#2dd4bf', '#fb923c',
]

export default function LineCard({
  title,
  data,
  keys,
  yfmt,
}: {
  title: string
  data: Row[]
  keys: string[]
  yfmt?: (n: number) => string
}) {
  return (
    <SpotlightCard className="p-4 h-72">
      <div className="text-sm text-zinc-300 mb-2">{title}</div>
      <ResponsiveContainer width="100%" height="88%">
        <LineChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: -6 }}>
          <CartesianGrid stroke="#1e293b" vertical={false} />
          <XAxis
            dataKey="t"
            tickFormatter={(t) =>
              new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
            }
            stroke="#64748b"
            fontSize={11}
            minTickGap={44}
          />
          <YAxis tickFormatter={yfmt} stroke="#64748b" fontSize={11} width={54} />
          <Tooltip
            contentStyle={{
              background: '#0f172a',
              border: '1px solid #1e293b',
              borderRadius: 8,
              fontSize: 12,
            }}
            labelFormatter={(t) => new Date(Number(t)).toLocaleTimeString()}
            formatter={(v: number) => (yfmt ? yfmt(v) : v)}
          />
          <Legend wrapperStyle={{ fontSize: 11 }} />
          {keys.map((k, i) => (
            <Line
              key={k}
              type="monotone"
              dataKey={k}
              stroke={COLORS[i % COLORS.length]}
              dot={false}
              strokeWidth={1.6}
              isAnimationActive={false}
            />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </SpotlightCard>
  )
}
