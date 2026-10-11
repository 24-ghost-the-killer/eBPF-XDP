// Lightweight inline stroke icons (no dependency) for the app shell.
// Each is 20×20, inherits currentColor, 1.6 stroke.
export type IconName =
  | 'grid' | 'activity' | 'shield' | 'cpu' | 'terminal'
  | 'menu' | 'close' | 'bolt' | 'pulse'

const P = {
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.6,
  strokeLinecap: 'round' as const,
  strokeLinejoin: 'round' as const,
}

export default function Icon({ name, className = 'h-[18px] w-[18px]' }: { name: IconName; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} aria-hidden>
      {name === 'grid' && (
        <g {...P}><rect x="3" y="3" width="7" height="7" rx="1.5" /><rect x="14" y="3" width="7" height="7" rx="1.5" /><rect x="3" y="14" width="7" height="7" rx="1.5" /><rect x="14" y="14" width="7" height="7" rx="1.5" /></g>
      )}
      {name === 'activity' && (
        <polyline {...P} points="2 13 7 13 10 4 14 20 17 13 22 13" />
      )}
      {name === 'shield' && (
        <g {...P}><path d="M12 3l7 3v5c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9V6l7-3z" /><path d="M9 12l2 2 4-4" /></g>
      )}
      {name === 'cpu' && (
        <g {...P}><rect x="6" y="6" width="12" height="12" rx="2" /><rect x="9.5" y="9.5" width="5" height="5" rx="1" /><path d="M9 3v2M15 3v2M9 19v2M15 19v2M3 9h2M3 15h2M19 9h2M19 15h2" /></g>
      )}
      {name === 'terminal' && (
        <g {...P}><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M7 9l3 3-3 3M13 15h4" /></g>
      )}
      {name === 'menu' && <path {...P} d="M4 6h16M4 12h16M4 18h16" />}
      {name === 'close' && <path {...P} d="M6 6l12 12M18 6L6 18" />}
      {name === 'bolt' && <path {...P} d="M13 2L4 14h7l-1 8 9-12h-7l1-8z" />}
      {name === 'pulse' && (
        <path {...P} d="M3 12h4l2-6 4 12 2-6h6" />
      )}
    </svg>
  )
}
