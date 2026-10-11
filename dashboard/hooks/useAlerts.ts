'use client'
import { useEffect, useRef } from 'react'
import { toast } from 'sonner'

interface Signals {
  attack: boolean
  dropping: boolean
  ratelimiting: boolean
  ready: boolean // only fire once real data has arrived
}

// Fire Sonner toasts on rising/falling edges of the defense state — mirrors the
// transitions the telemetry engine already detects, so alerts surface even when
// the operator isn't watching the log.
export function useAlerts(sig: Signals) {
  const prev = useRef<Signals | null>(null)

  useEffect(() => {
    if (!sig.ready) return
    const p = prev.current
    if (p) {
      if (sig.attack && !p.attack)
        toast.error('⚠ Threat detected', { description: 'Attack signature matched — risk level raised.' })
      if (!sig.attack && p.attack)
        toast.success('Threat cleared', { description: 'Risk level back to normal.' })
      if (sig.dropping && !p.dropping)
        toast.warning('Mitigation engaged', { description: 'Drop flags active on the dataplane.' })
      if (!sig.dropping && p.dropping)
        toast.info('Mitigation lifted', { description: 'Observe-only baseline restored.' })
      if (sig.ratelimiting && !p.ratelimiting)
        toast.warning('Rate-limiter activated', { description: 'Capping abusive sources (GCRA).' })
    }
    prev.current = sig
  }, [sig.attack, sig.dropping, sig.ratelimiting, sig.ready])
}
