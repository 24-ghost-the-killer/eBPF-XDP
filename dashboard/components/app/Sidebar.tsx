'use client'
import Icon from './icons'
import { NAV, type ViewId } from './nav'

interface Status {
  up: boolean
  sw: boolean
  connected: boolean
  attack: boolean
}

function StatusDot({ ok, label, value }: { ok: boolean; label: string; value: string }) {
  return (
    <div className="flex items-center justify-between py-1">
      <span className="flex items-center gap-2 text-[11px] text-zinc-500">
        <span className={`h-1.5 w-1.5 rounded-full ${ok ? 'bg-emerald-400' : 'bg-rose-500'}`} />
        {label}
      </span>
      <span className={`mono text-[11px] ${ok ? 'text-zinc-300' : 'text-rose-400'}`}>{value}</span>
    </div>
  )
}

export default function Sidebar({
  view,
  setView,
  status,
  open,
  onClose,
}: {
  view: ViewId
  setView: (v: ViewId) => void
  status: Status
  open: boolean
  onClose: () => void
}) {
  return (
    <>
      {/* mobile backdrop */}
      <div
        onClick={onClose}
        className={`fixed inset-0 z-30 bg-black/60 backdrop-blur-sm transition-opacity lg:hidden ${
          open ? 'opacity-100' : 'pointer-events-none opacity-0'
        }`}
      />
      <aside
        className={`fixed inset-y-0 left-0 z-40 flex w-[244px] flex-col border-r border-white/[0.06] bg-[#0a0a0e]/95 backdrop-blur-xl transition-transform duration-300 lg:translate-x-0 ${
          open ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* brand */}
        <div className="flex items-center gap-3 border-b border-white/[0.06] px-5 py-[18px]">
          <span className="glow-emerald relative flex h-9 w-9 items-center justify-center rounded-xl bg-emerald-500/10 ring-1 ring-emerald-500/30">
            <span className={`absolute inline-flex h-3.5 w-3.5 rounded-full ${status.connected ? 'bg-emerald-400/40 animate-ping' : ''}`} />
            <Icon name="bolt" className="relative h-[17px] w-[17px] text-emerald-400" />
          </span>
          <div className="leading-tight">
            <div className="text-[14px] font-semibold tracking-tight text-zinc-100">
              XDP<span className="text-emerald-400 text-glow">·</span>SENTINEL
            </div>
            <div className="text-[9.5px] uppercase tracking-[0.2em] text-zinc-600">DDoS Console</div>
          </div>
          <button onClick={onClose} className="ml-auto text-zinc-500 hover:text-zinc-200 lg:hidden">
            <Icon name="close" />
          </button>
        </div>

        {/* nav */}
        <nav className="scroll-thin flex-1 overflow-y-auto px-3 py-4">
          {NAV.map((grp) => (
            <div key={grp.group} className="mb-5">
              <div className="px-3 pb-2 text-[10px] font-medium uppercase tracking-[0.18em] text-zinc-600">
                {grp.group}
              </div>
              <div className="space-y-0.5">
                {grp.items.map((it) => {
                  const active = view === it.id
                  return (
                    <button
                      key={it.id}
                      onClick={() => {
                        setView(it.id)
                        onClose()
                      }}
                      className={`group relative flex w-full items-center gap-3 rounded-lg px-3 py-2 text-[13px] transition-all ${
                        active
                          ? 'bg-emerald-500/[0.08] text-zinc-50 ring-1 ring-inset ring-emerald-500/20'
                          : 'text-zinc-500 hover:bg-white/[0.03] hover:text-zinc-200'
                      }`}
                    >
                      <span
                        className={`absolute left-0 h-5 w-[2.5px] rounded-r-full bg-emerald-400 transition-opacity ${
                          active ? 'opacity-100' : 'opacity-0'
                        }`}
                      />
                      <Icon name={it.icon} className={`h-[18px] w-[18px] ${active ? 'text-emerald-400' : ''}`} />
                      <span className="font-medium">{it.label}</span>
                      {it.id === 'security' && status.attack && (
                        <span className="ml-auto h-1.5 w-1.5 rounded-full bg-rose-400 animate-pulse" />
                      )}
                    </button>
                  )
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* status footer */}
        <div className="border-t border-white/[0.06] px-5 py-4">
          <div className="mb-2 text-[10px] font-medium uppercase tracking-[0.18em] text-zinc-600">
            System
          </div>
          <StatusDot ok={status.connected} label="Prometheus" value={status.connected ? 'online' : 'offline'} />
          <StatusDot ok={status.up} label="Dataplane" value={status.up ? 'up' : 'down'} />
          <StatusDot ok={status.sw} label="Switch" value={status.sw ? 'up' : 'down'} />
        </div>
      </aside>
    </>
  )
}
