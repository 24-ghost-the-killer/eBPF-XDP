'use client'
import Icon from './icons'

export default function Topbar({
  title,
  subtitle,
  now,
  connected,
  attack,
  onMenu,
  onCommand,
}: {
  title: string
  subtitle: string
  now: Date | null
  connected: boolean
  attack: boolean
  onMenu: () => void
  onCommand: () => void
}) {
  return (
    <header className="sticky top-0 z-20 flex items-center gap-4 border-b border-white/[0.06] bg-[#07070a]/80 px-4 py-3 backdrop-blur-md lg:px-6">
      <button
        onClick={onMenu}
        className="text-zinc-400 hover:text-zinc-100 lg:hidden"
        aria-label="Open navigation"
      >
        <Icon name="menu" />
      </button>

      <div className="min-w-0 leading-tight">
        <h1 className="truncate text-[15px] font-semibold tracking-tight text-zinc-100">{title}</h1>
        <p className="hidden truncate text-[11px] text-zinc-500 sm:block">{subtitle}</p>
      </div>

      <div className="ml-auto flex items-center gap-3 text-xs">
        <button
          onClick={onCommand}
          className="hidden items-center gap-2 rounded-lg border border-white/[0.08] bg-white/[0.02] px-2.5 py-1.5 text-[11px] text-zinc-500 transition-colors hover:border-white/[0.15] hover:text-zinc-300 md:flex"
          aria-label="Open command palette"
        >
          <span>Jump to…</span>
          <kbd className="mono rounded border border-white/[0.1] bg-white/[0.04] px-1.5 py-0.5 text-[10px] text-zinc-400">
            ⌘K
          </kbd>
        </button>
        <span className="mono hidden text-zinc-500 sm:inline">
          {now ? now.toLocaleTimeString('en-GB') : '—'}
        </span>
        <span className="hidden text-zinc-700 sm:inline">·</span>
        <span className={`flex items-center gap-1.5 ${connected ? 'text-emerald-400' : 'text-rose-400'}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${connected ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'}`} />
          <span className="mono">{connected ? 'live' : 'offline'}</span>
        </span>
        <span
          className={`flex items-center gap-1.5 rounded-full px-3 py-1 text-[11px] font-semibold ring-1 ${
            attack
              ? 'bg-rose-500/10 text-rose-300 ring-rose-500/40 shadow-[0_0_24px_-6px_rgba(244,63,94,0.6)]'
              : 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/25'
          }`}
        >
          <span className={`h-1.5 w-1.5 rounded-full ${attack ? 'bg-rose-400 animate-pulse' : 'bg-emerald-400'}`} />
          {attack ? 'UNDER ATTACK' : 'OPERATIONAL'}
        </span>
      </div>
    </header>
  )
}
