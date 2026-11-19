'use client'
// The verdict on one attack ("why wasn't this blocked?") and the control that
// marks it as a false alarm. Shown at the top of the attack drawer.
import { useState } from 'react'
import { CheckCircle2, AlertTriangle, XCircle, Info, Flag, Loader2, Undo2 } from 'lucide-react'
import { explain, flagName, type Tone } from '@/lib/explain'
import { MARK_REASONS, markLabel, setAttackMark, type Episode, type AttackMark } from '@/lib/attacks'
import { useMe } from '@/components/aa/Shell'
import { btn } from '@/components/aa/kit'

const ICON = { good: CheckCircle2, warn: AlertTriangle, bad: XCircle, neutral: Info }
const INK: Record<Tone, string> = { good: 'text-st-good-fg', warn: 'text-st-warn-fg', bad: 'text-st-crit-fg', neutral: 'text-nd-dim' }
const RING: Record<Tone, string> = {
  good: 'border-st-good/25 bg-st-good/[0.06]', warn: 'border-st-warn/30 bg-st-warn/[0.07]',
  bad: 'border-st-crit/25 bg-st-crit/[0.06]', neutral: 'border-nd-line bg-nd-panel',
}

export function WhyPanel({ a, onMarked }: { a: Episode; onMarked: (mark: AttackMark | null) => void }) {
  const ex = explain(a)
  const Head = ICON[ex.tone]
  return (
    <section className={`rounded-2xl border px-5 py-4 ${RING[ex.tone]}`} aria-label="Why it was or wasn't blocked">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex min-w-0 items-center gap-2.5">
          <Head className={`h-5 w-5 shrink-0 ${INK[ex.tone]}`} />
          <div className="min-w-0">
            <div className="text-[11px] font-medium uppercase tracking-[0.06em] text-nd-dim">Why {a.dropShare >= 0.9 ? 'it was' : 'it wasn’t'} blocked</div>
            <h3 className="text-[15px] font-semibold text-nd-fg">{ex.headline}</h3>
          </div>
        </div>
        <MarkControl a={a} onMarked={onMarked} />
      </div>
      <ul className="mt-3 space-y-2.5">
        {ex.reasons.map((r) => {
          const I = ICON[r.tone]
          return (
            <li key={r.title} className="flex gap-2.5">
              <I className={`mt-0.5 h-4 w-4 shrink-0 ${INK[r.tone]}`} />
              <div className="min-w-0 text-[13px] leading-relaxed">
                <span className="font-medium text-nd-fg">{r.title}.</span> <span className="text-nd-fg-3">{r.text}</span>
              </div>
            </li>
          )
        })}
      </ul>
      {a.mitigation && a.mitigation.baseline.length > 0 && (
        <p className="mt-3 text-[11.5px] text-nd-faint">Always on before it started: {a.mitigation.baseline.map(flagName).join(', ')}</p>
      )}
    </section>
  )
}

function MarkControl({ a, onMarked }: { a: Episode; onMarked: (mark: AttackMark | null) => void }) {
  const { can } = useMe()
  const [open, setOpen] = useState(false)
  const [reason, setReason] = useState(a.vectors.includes('ARP storm') ? 'arp_storm' : a.vectors.includes('ACK flood') ? 'download' : 'own_test')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  if (a.mark?.reason === 'simulation') {
    return <span className="rounded-full bg-nd-fill px-2.5 py-1 text-[11.5px] font-medium text-nd-fg-3">Simulation · {a.mark.note}{a.mark.by ? ` · started by ${a.mark.by}` : ''}</span>
  }
  if (!can('attacks.mark')) {
    return a.mark ? <span className="rounded-full bg-nd-fill px-2.5 py-1 text-[11.5px] font-medium text-nd-dim">False alarm · {markLabel(a.mark.reason)}</span> : null
  }
  const save = async (mark: { reason: string; note?: string } | null) => {
    setBusy(true); setErr('')
    try {
      const m = await setAttackMark(a.id, mark)
      onMarked(m)
      setOpen(false)
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'could not save')
    }
    setBusy(false)
  }
  if (a.mark) {
    return (
      <button type="button" onClick={() => save(null)} disabled={busy} className={`${btn.ghost} py-1 text-[12px]`} title="Count it as an attack again">
        {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Undo2 className="h-3.5 w-3.5" />} It was an attack
      </button>
    )
  }
  return (
    <div className="relative">
      <button type="button" onClick={() => setOpen((o) => !o)} className={`${btn.ghost} py-1 text-[12px]`} aria-expanded={open}>
        <Flag className="h-3.5 w-3.5" /> Not an attack…
      </button>
      {open && (
        <div className="absolute right-0 top-full z-20 mt-2 w-[300px] rounded-xl border border-nd-line bg-nd-card p-4 shadow-nd-lg">
          <div className="text-[13px] font-semibold text-nd-fg">Mark as a false alarm</div>
          <p className="mt-0.5 text-[11.5px] text-nd-dim">It stays in the list with a badge but leaves the totals and the globe. You can undo it.</p>
          <fieldset className="mt-3 space-y-1.5">
            <legend className="sr-only">Reason</legend>
            {MARK_REASONS.map((r) => (
              <label key={r.id} className={`flex cursor-pointer items-start gap-2 rounded-lg px-2 py-1.5 text-[12.5px] ${reason === r.id ? 'bg-nd-fill' : 'hover:bg-nd-fill'}`}>
                <input type="radio" name="mark-reason" value={r.id} checked={reason === r.id} onChange={() => setReason(r.id)} className="mt-0.5 accent-current" />
                <span><span className="font-medium text-nd-fg">{r.label}</span><span className="block text-[11px] text-nd-faint">{r.hint}</span></span>
              </label>
            ))}
          </fieldset>
          <input value={note} onChange={(e) => setNote(e.target.value)} maxLength={300} placeholder="Note (optional), e.g. Steam update on .194"
            className={`${btn.input} mt-2 w-full py-1.5 text-[12.5px]`} />
          {err && <p className="mt-2 text-[12px] text-st-crit-fg">{err}</p>}
          <div className="mt-3 flex justify-end gap-2">
            <button type="button" onClick={() => setOpen(false)} className={`${btn.ghost} py-1 text-[12px]`}>Cancel</button>
            <button type="button" onClick={() => save({ reason, note: note.trim() || undefined })} disabled={busy} className={`${btn.primary} py-1 text-[12px]`}>
              {busy && <Loader2 className="h-3.5 w-3.5 animate-spin" />} Mark false alarm
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
