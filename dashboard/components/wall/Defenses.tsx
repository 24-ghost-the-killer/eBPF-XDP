'use client'

export interface DefenseData {
  // per interface: flag name -> 0/1
  flags: Record<string, Record<string, number>>
  // layer -> state value (0 normal, >0 escalating)
  layers: { layer: string; v: number }[]
}

const vlanName = (ifc: string) => (ifc === 'vlan10' ? 'VLAN10 · wan' : ifc === 'vlan20' ? 'VLAN20 · lan' : ifc)

// Human order for flags (most security-relevant first).
const FLAG_ORDER = [
  'drop_malformed', 'drop_bad_tcp_flags', 'drop_fragments', 'drop_syn', 'drop_ack',
  'drop_icmp', 'drop_udp', 'drop_udp_dns', 'drop_udp_strict', 'drop_untracked',
  'conntrack', 'ratelimit', 'global_rl', 'check_allow', 'check_policy',
  'sampling', 'hll', 'dport_hist',
]

function Chip({ name, on }: { name: string; on: boolean }) {
  return (
    <span
      className={`mono rounded px-1.5 py-0.5 text-[9.5px] tracking-tight transition-colors ${
        on
          ? 'bg-emerald-500/15 text-emerald-300 ring-1 ring-inset ring-emerald-500/30'
          : 'bg-white/[0.02] text-zinc-600 ring-1 ring-inset ring-white/[0.05]'
      }`}
      title={on ? `${name}: ARMED` : `${name}: off`}
    >
      {name}
    </span>
  )
}

export default function Defenses({ d }: { d: DefenseData | null }) {
  const ifaces = Object.keys(d?.flags ?? {}).sort()
  const layerTone = (v: number) => (v >= 2 ? 'text-rose-400 bg-rose-500/15 ring-rose-500/30' : v >= 1 ? 'text-amber-400 bg-amber-500/15 ring-amber-500/30' : 'text-emerald-400 bg-emerald-500/10 ring-emerald-500/20')

  return (
    <div className="panel panel-ticks p-4">
      <div className="mb-3 flex items-center justify-between">
        <span className="eyebrow">Active defenses</span>
        <span className="mono text-[10px] text-zinc-600">XDP flags · per interface</span>
      </div>

      {ifaces.length === 0 && <div className="text-xs text-zinc-600">no data</div>}

      <div className="space-y-3">
        {ifaces.map((ifc) => {
          const fl = d!.flags[ifc]
          const armed = Object.values(fl).filter((v) => v > 0).length
          const ordered = FLAG_ORDER.filter((f) => f in fl).concat(Object.keys(fl).filter((f) => !FLAG_ORDER.includes(f)))
          return (
            <div key={ifc}>
              <div className="mb-1.5 flex items-center justify-between">
                <span className="text-[11px] font-medium text-zinc-300">{vlanName(ifc)}</span>
                <span className="mono text-[10px] text-zinc-500">{armed}/{ordered.length} armed</span>
              </div>
              <div className="flex flex-wrap gap-1">
                {ordered.map((f) => (
                  <Chip key={f} name={f} on={fl[f] > 0} />
                ))}
              </div>
            </div>
          )
        })}
      </div>

      {/* layer state */}
      <div className="mt-3 border-t border-white/[0.06] pt-3">
        <div className="mb-1.5 text-[10px] uppercase tracking-[0.14em] text-zinc-500">layer state</div>
        <div className="grid grid-cols-4 gap-2">
          {(d?.layers ?? [{ layer: 'l2', v: 0 }, { layer: 'l3', v: 0 }, { layer: 'l4', v: 0 }, { layer: 'l7', v: 0 }]).map((l) => (
            <div key={l.layer} className={`rounded-md py-1.5 text-center ring-1 ring-inset ${layerTone(l.v)}`}>
              <div className="mono text-[11px] font-semibold uppercase">{l.layer}</div>
              <div className="text-[9px] opacity-80">{l.v >= 2 ? 'attack' : l.v >= 1 ? 'suspect' : 'clear'}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
