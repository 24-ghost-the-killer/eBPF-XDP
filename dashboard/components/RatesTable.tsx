import { pps } from '@/lib/format'
import SpotlightCard from './reactbits/SpotlightCard'

export interface RateRow {
  label: string
  v10: number
  v20: number
  warn?: boolean
}

// Dense per-interface counter table.
export default function RatesTable({ title, rows }: { title: string; rows: RateRow[] }) {
  return (
    <SpotlightCard className="p-3">
      <div className="text-[11px] uppercase tracking-wider text-zinc-500 mb-2">{title}</div>
      <table className="w-full text-[11px] font-mono">
        <thead>
          <tr className="text-[10px] uppercase text-zinc-600">
            <th className="text-left font-normal pb-1">counter</th>
            <th className="text-right font-normal pb-1">vlan10</th>
            <th className="text-right font-normal pb-1">vlan20</th>
            <th className="text-right font-normal pb-1">total</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const total = r.v10 + r.v20
            const hot = r.warn && total > 0.5
            return (
              <tr key={r.label} className="border-t border-zinc-800/60">
                <td className="py-[3px] text-zinc-400">{r.label}</td>
                <td className="text-right tabular-nums text-zinc-300">{pps(r.v10)}</td>
                <td className="text-right tabular-nums text-zinc-300">{pps(r.v20)}</td>
                <td
                  className={`text-right tabular-nums font-semibold ${
                    hot ? 'text-rose-400' : 'text-zinc-200'
                  }`}
                >
                  {pps(total)}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </SpotlightCard>
  )
}
