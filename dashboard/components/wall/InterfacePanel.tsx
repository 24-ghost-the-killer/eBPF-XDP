'use client'
import { pps } from '@/lib/format'
import type { RateRow } from '@/components/RatesTable'

function Mini({ label, value, tone = 'text-zinc-200' }: { label: string; value: string; tone?: string }) {
  return (
    <div className="rounded-md border border-white/[0.06] bg-white/[0.015] px-2 py-1.5">
      <div className="text-[9px] uppercase tracking-[0.12em] text-zinc-600">{label}</div>
      <div className={`mono mt-0.5 text-[12px] font-semibold tabular-nums ${tone}`}>{value}</div>
    </div>
  )
}

// One interface's live picture: received headline, pass/drop split, protocol mix.
export default function InterfacePanel({
  name,
  role,
  rows,
  vlan,
}: {
  name: string
  role: 'wan' | 'lan'
  rows: RateRow[]
  vlan: 'v10' | 'v20'
}) {
  const get = (label: string) => {
    const r = rows.find((x) => x.label === label)
    return r ? (vlan === 'v10' ? r.v10 : r.v20) : 0
  }
  const received = get('received')
  const passed = get('passed')
  const dropped = get('dropped')
  const rl = get('rate-limited')
  const syn = get('tcp syn')
  const synack = get('tcp syn-ack')
  const ack = get('tcp ack')
  const rst = get('tcp rst')
  const udp = get('udp')
  const icmp = get('icmp')
  const anom = get('bad flags/anom')

  const total = Math.max(0.0001, passed + dropped)
  const dropPct = (dropped / total) * 100
  const passPct = 100 - dropPct

  const wan = role === 'wan'
  const accent = wan ? 'text-sky-400' : 'text-emerald-400'
  const dotBg = wan ? 'bg-sky-400' : 'bg-emerald-400'
  const chip = wan ? 'bg-sky-500/10 text-sky-300 ring-sky-500/30' : 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/30'
  const underAttack = dropped > 1

  return (
    <div className={`panel panel-ticks p-4 ${underAttack ? 'glow-rose' : ''}`}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className={`h-2 w-2 rounded-full ${dotBg}`} />
          <span className="mono text-[13px] font-semibold text-zinc-100">{name}</span>
          <span className={`rounded px-1.5 py-0.5 text-[9px] uppercase tracking-wide ring-1 ring-inset ${chip}`}>{role}</span>
        </div>
        <span className="text-[10px] uppercase tracking-[0.14em] text-zinc-600">ingress</span>
      </div>

      <div className="mt-3 flex items-end justify-between">
        <div>
          <div className={`mono text-[30px] font-semibold leading-none tabular-nums ${accent}`}>{pps(received)}</div>
          <div className="mt-1 text-[10px] uppercase tracking-[0.14em] text-zinc-500">received</div>
        </div>
        <div className="text-right text-[11px]">
          <div className="mono text-emerald-400">{pps(passed)} <span className="text-zinc-600">pass</span></div>
          <div className={`mono ${dropped > 0 ? 'text-rose-400' : 'text-zinc-500'}`}>{pps(dropped)} <span className="text-zinc-600">drop</span></div>
        </div>
      </div>

      {/* pass/drop split bar */}
      <div className="mt-3 flex h-2 overflow-hidden rounded-full bg-white/[0.06]">
        <div className="h-2 bg-emerald-500" style={{ width: `${passPct}%` }} />
        <div className="h-2 bg-rose-500" style={{ width: `${dropPct}%` }} />
      </div>
      <div className="mt-1 flex justify-between text-[9.5px] text-zinc-600">
        <span>{passPct.toFixed(dropPct > 0 && dropPct < 10 ? 1 : 0)}% passed</span>
        <span className={dropped > 0 ? 'text-rose-400' : ''}>{dropPct.toFixed(dropPct > 0 && dropPct < 10 ? 1 : 0)}% dropped</span>
      </div>

      {/* protocol / flag mix */}
      <div className="mt-3 grid grid-cols-4 gap-1.5">
        <Mini label="syn" value={pps(syn)} tone={syn > 150 ? 'text-amber-400' : 'text-zinc-300'} />
        <Mini label="syn-ack" value={pps(synack)} />
        <Mini label="ack" value={pps(ack)} />
        <Mini label="rst" value={pps(rst)} tone={rst > 50 ? 'text-amber-400' : 'text-zinc-300'} />
        <Mini label="udp" value={pps(udp)} tone="text-violet-300" />
        <Mini label="icmp" value={pps(icmp)} />
        <Mini label="rate-lim" value={pps(rl)} tone={rl > 0 ? 'text-amber-400' : 'text-zinc-300'} />
        <Mini label="anom" value={pps(anom)} tone={anom > 0.5 ? 'text-fuchsia-400' : 'text-zinc-300'} />
      </div>
    </div>
  )
}
