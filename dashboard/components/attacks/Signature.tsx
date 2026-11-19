'use client'
// "Learned rule" in the attack drawer: the shapes of the packets the firewall
// dropped during this attack, and a ready-made rule for the dominant one that
// stops the same attack at once next time (before the risk ladder has to climb).
import { useEffect, useState } from 'react'
import { Wand2, Loader2, Check, Info } from 'lucide-react'
import type { Episode } from '@/lib/attacks'
import { describeShape, describeRule, suggest, type Shape } from '@/lib/sigrules'
import { useMe } from '@/components/aa/Shell'
import { btn } from '@/components/aa/kit'

interface Resp { shapes: Shape[]; sampledTotal: number; sample: number; historySince: number; rules: { fromAttack?: number; text: string; active: boolean }[] }

export function SignaturePanel({ a }: { a: Episode }) {
  const { can } = useMe()
  const [d, setD] = useState<Resp | null>(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [added, setAdded] = useState('')
  const [hours, setHours] = useState(24)

  useEffect(() => {
    let alive = true
    fetch(`/api/rules?from=${Math.floor(a.start / 1000) - 30}&to=${Math.ceil(a.end / 1000) + 30}`, { cache: 'no-store' })
      .then((r) => r.json())
      .then((j) => { if (alive) { if (j.status === 'success') setD(j); else setErr(j.error || 'unavailable') } })
      .catch(() => alive && setErr('unavailable'))
    return () => { alive = false }
  }, [a.start, a.end])

  if (!can('rules')) return null
  const top = d?.shapes[0]
  const rule = top ? suggest(top) : null
  const already = d?.rules.find((r) => r.fromAttack === a.id)

  const add = async () => {
    if (!rule) return
    setBusy(true); setErr('')
    const r = await fetch('/api/rules', { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ rule: { ...rule, hours, fromAttack: a.id, note: `learned from the attack of ${new Date(a.start).toLocaleString()}` } }) })
    const j = await r.json().catch(() => ({}))
    if (j.status === 'success') setAdded(describeRule(j.rule)); else setErr(j.error || 'could not add the rule')
    setBusy(false)
  }

  return (
    <section className="rounded-2xl border border-nd-line bg-nd-card px-5 py-4" aria-label="Learned rule">
      <div className="flex items-center gap-2.5">
        <Wand2 className="h-5 w-5 text-nd-fg-3" />
        <div>
          <div className="text-[11px] font-medium uppercase tracking-[0.06em] text-nd-dim">Learned rule</div>
          <h3 className="text-[15px] font-semibold text-nd-fg">What the attack’s packets looked like</h3>
        </div>
      </div>
      {!d && !err && <div className="mt-3 aa-skeleton h-10 rounded-lg" />}
      {err && <p className="mt-2 text-[12.5px] text-nd-faint">Packet shapes unavailable ({err}).</p>}
      {d && !top && (
        <p className="mt-2 text-[12.5px] text-nd-faint">
          No packet shapes recorded for this attack. The firewall records them for 24 hours{d.historySince ? `, since ${new Date(d.historySince * 1000).toLocaleString()}` : ''}, and only for traffic it dropped.
        </p>
      )}
      {d && top && rule && (
        <>
          <ul className="mt-3 space-y-1.5">
            {d.shapes.slice(0, 4).map((s, i) => (
              <li key={i} className="flex items-center gap-3 text-[12.5px]">
                <span className="w-12 shrink-0 text-right font-semibold tabular-nums text-nd-fg">{Math.round(s.share * 100)}%</span>
                <span className="h-1.5 w-24 shrink-0 overflow-hidden rounded-full bg-nd-fill"><span className="block h-full rounded-full bg-st-crit" style={{ width: `${Math.max(3, s.share * 100)}%` }} /></span>
                <span className={i === 0 ? 'text-nd-fg' : 'text-nd-fg-3'}>{describeShape(s)}</span>
              </li>
            ))}
          </ul>
          <div className="mt-4 rounded-xl border border-nd-line bg-nd-panel px-4 py-3">
            <div className="text-[12px] font-medium text-nd-dim">Suggested rule</div>
            <div className="mt-0.5 text-[13.5px] font-medium text-nd-fg">Drop {describeRule(rule)}</div>
            <p className="mt-1 text-[12px] text-nd-faint">Catches {Math.round(top.share * 100)}% of what was dropped in this attack. Only traffic from outside is affected: your own LAN devices never match a rule.</p>
            {already || added ? (
              <p className="mt-2 flex items-center gap-1.5 text-[12.5px] text-st-good-fg"><Check className="h-4 w-4" /> Rule {added ? 'added' : 'already exists'}: {added || already?.text}. See Signature rules.</p>
            ) : can('rules.edit') ? (
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <select value={hours} onChange={(e) => setHours(Number(e.target.value))} className={`${btn.input} py-1.5 text-[12.5px]`} aria-label="How long">
                  <option value={1}>for 1 hour</option><option value={24}>for 24 hours</option><option value={168}>for 7 days</option><option value={0}>until I remove it</option>
                </select>
                <button type="button" onClick={add} disabled={busy} className={`${btn.primary} py-1.5 text-[12.5px]`}>
                  {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Wand2 className="h-3.5 w-3.5" />} Add rule
                </button>
              </div>
            ) : <p className="mt-2 text-[12px] text-nd-faint">Your group may not add rules.</p>}
          </div>
          <p className="mt-2 flex gap-1.5 text-[11.5px] text-nd-faint"><Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />Measured on every {d.sample}th dropped packet ({d.sampledTotal.toLocaleString()} sampled in this window).</p>
        </>
      )}
    </section>
  )
}
