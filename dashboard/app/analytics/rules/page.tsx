'use client'
// Signature rules: precise drop rules learned from earlier attacks (from the
// attack drawer's "Learned rule"), or written by hand. Each drops matching
// traffic from outside at once, before the risk ladder has to climb.
import { useState } from 'react'
import { Wand2, Trash2, Power, Plus, Loader2, Info, Clock } from 'lucide-react'
import { usePoll } from '@/hooks/usePoll'
import { si } from '@/lib/format'
import { describeShape, describeRule, suggest, PROTO, type Field, type Shape } from '@/lib/sigrules'
import { Panel, Badge, Empty, btn } from '@/components/aa/kit'
import { useMe } from '@/components/aa/Shell'

interface RuleRow {
  id: string; on: boolean; active: boolean; hits: number; text: string; note?: string
  expires_at: number | null; createdAt: number; createdBy: string; fromAttack?: number
}
interface Data { rules: RuleRow[]; shapes: Shape[]; agentReachable: boolean; max: number; historySince: number }

const until = (s: number | null) => (s ? (s * 1000 < Date.now() ? 'expired' : `until ${new Date(s * 1000).toLocaleString([], { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })}`) : 'no expiry')

export default function RulesPage() {
  const { can } = useMe()
  const edit = can('rules.edit')
  const [rev, setRev] = useState(0)
  const q = usePoll(async () => {
    const now = Math.floor(Date.now() / 1000)
    const r = await fetch(`/api/rules?from=${now - 86400}&to=${now + 60}`, { cache: 'no-store' })
    const j = await r.json()
    if (j.status !== 'success') throw new Error(j.error || 'rules unavailable')
    return j as Data
  }, 15_000, [rev])
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState('')
  const call = async (method: string, url: string, body?: object) => {
    setErr('')
    const r = await fetch(url, { method, headers: { 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined })
    const j = await r.json().catch(() => ({}))
    if (j.status !== 'success') setErr(j.error || 'failed')
    setRev((x) => x + 1)
  }

  // hand-written rule
  const [form, setForm] = useState({ proto: 17, port: '', portKind: 'dport' as 'dport' | 'sport', lenLo: '', lenHi: '', hours: 24 })

  const d = q.data
  if (!d) return q.error ? <Empty icon={Wand2} title="Signature rules unavailable" hint={q.error} /> : <div className="aa-skeleton h-64 rounded-2xl" />

  const addShape = async (s: Shape) => {
    setBusy(JSON.stringify(s)); await call('POST', '/api/rules', { rule: { ...suggest(s), hours: 24, note: 'from the last 24 h of drops' } }); setBusy('')
  }
  const addManual = async () => {
    const match: Field[] = ['proto']
    const rule: Record<string, unknown> = { proto: form.proto, hours: form.hours, note: 'written by hand' }
    if (form.port) { rule[form.portKind] = Number(form.port); match.push(form.portKind) }
    if (form.lenLo || form.lenHi) { rule.len_lo = Number(form.lenLo || 0); rule.len_hi = Number(form.lenHi || 65535); match.push('len') }
    rule.match = match
    await call('POST', '/api/rules', { rule })
  }

  return (
    <div className="space-y-6">
      <Panel icon={Wand2} title="Active rules" sub={`Each one drops matching traffic from outside the LAN at once · ${d.rules.length} of ${d.max} slots used`} bodyClass="">
        {d.rules.length === 0 ? (
          <p className="px-5 pb-5 text-[13px] text-nd-faint">No rules yet. Open an attack and use “Learned rule”, or pick a shape below.</p>
        ) : (
          <ul className="divide-y divide-nd-line-soft">
            {d.rules.map((r) => (
              <li key={r.id} className="flex flex-wrap items-center gap-3 px-5 py-3">
                <Badge tone={r.active ? 'good' : 'neutral'}>{r.active ? 'active' : r.on ? 'expired' : 'off'}</Badge>
                <div className="min-w-0 flex-1">
                  <div className="text-[13.5px] font-medium text-nd-fg">Drop {r.text}</div>
                  <div className="text-[11.5px] text-nd-faint">
                    {r.note ?? ''}{r.createdBy ? ` · by ${r.createdBy}` : ''} · <Clock className="inline h-3 w-3" /> {until(r.expires_at)}
                    {r.fromAttack ? <> · <a className="underline hover:text-nd-fg" href={`/analytics/attacks?attack=${r.fromAttack}`}>the attack</a></> : null}
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-[15px] font-semibold tabular-nums text-nd-fg">{si(r.hits)}</div>
                  <div className="text-[11px] text-nd-faint">packets stopped</div>
                </div>
                {edit && (
                  <>
                    <button type="button" onClick={() => call('PATCH', '/api/rules', { id: r.id, on: !r.on })} className={`${btn.ghost} py-1 text-[12px]`}><Power className="h-3.5 w-3.5" /> {r.on ? 'Turn off' : 'Turn on'}</button>
                    <button type="button" onClick={() => call('DELETE', `/api/rules?id=${r.id}`)} className={`${btn.ghost} py-1 text-[12px]`} aria-label="Remove rule"><Trash2 className="h-3.5 w-3.5" /></button>
                  </>
                )}
              </li>
            ))}
          </ul>
        )}
        {err && <p className="px-5 pb-3 text-[12.5px] text-st-crit-fg">{err}</p>}
      </Panel>

      <Panel icon={Info} title="What was dropped in the last 24 hours" sub="The shapes of the packets the firewall threw away, biggest first. Each can become a rule." bodyClass="">
        {d.shapes.length === 0 ? (
          <p className="px-5 pb-5 text-[13px] text-nd-faint">Nothing dropped{d.historySince ? ` since ${new Date(d.historySince * 1000).toLocaleString()}` : ' yet'}{!d.agentReachable ? ' (the agent is not answering)' : ''}.</p>
        ) : (
          <ul className="divide-y divide-nd-line-soft">
            {d.shapes.slice(0, 12).map((s, i) => (
              <li key={i} className="flex flex-wrap items-center gap-3 px-5 py-2.5 text-[13px]">
                <span className="w-12 text-right font-semibold tabular-nums text-nd-fg">{Math.round(s.share * 100)}%</span>
                <span className="min-w-0 flex-1 text-nd-fg-3">{describeShape(s)}</span>
                {edit && (
                  <button type="button" onClick={() => addShape(s)} disabled={!!busy} className={`${btn.ghost} py-1 text-[12px]`} title={`Drop ${describeRule(suggest(s))} for 24 h`}>
                    {busy === JSON.stringify(s) ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />} Rule
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
      </Panel>

      {edit && (
        <Panel icon={Plus} title="Write a rule by hand" sub="At least a port or a size range: a rule may never drop a whole protocol">
          <div className="flex flex-wrap items-end gap-3 text-[12.5px]">
            <label className="flex flex-col gap-1 text-nd-dim">Protocol
              <select value={form.proto} onChange={(e) => setForm({ ...form, proto: Number(e.target.value) })} className={`${btn.input} py-1.5`}>
                {[17, 6, 1, 58].map((p) => <option key={p} value={p}>{PROTO[p]}</option>)}
              </select>
            </label>
            <label className="flex flex-col gap-1 text-nd-dim">Port
              <div className="flex gap-1">
                <select value={form.portKind} onChange={(e) => setForm({ ...form, portKind: e.target.value as 'dport' | 'sport' })} className={`${btn.input} py-1.5`}>
                  <option value="dport">to port</option><option value="sport">from port</option>
                </select>
                <input value={form.port} onChange={(e) => setForm({ ...form, port: e.target.value.replace(/\D/g, '').slice(0, 5) })} placeholder="e.g. 11211" className={`${btn.input} w-24 py-1.5`} />
              </div>
            </label>
            <label className="flex flex-col gap-1 text-nd-dim">Size (bytes)
              <div className="flex items-center gap-1">
                <input value={form.lenLo} onChange={(e) => setForm({ ...form, lenLo: e.target.value.replace(/\D/g, '').slice(0, 5) })} placeholder="from" className={`${btn.input} w-20 py-1.5`} />
                <span>–</span>
                <input value={form.lenHi} onChange={(e) => setForm({ ...form, lenHi: e.target.value.replace(/\D/g, '').slice(0, 5) })} placeholder="to" className={`${btn.input} w-20 py-1.5`} />
              </div>
            </label>
            <label className="flex flex-col gap-1 text-nd-dim">For
              <select value={form.hours} onChange={(e) => setForm({ ...form, hours: Number(e.target.value) })} className={`${btn.input} py-1.5`}>
                <option value={1}>1 hour</option><option value={24}>24 hours</option><option value={168}>7 days</option><option value={0}>until removed</option>
              </select>
            </label>
            <button type="button" onClick={addManual} disabled={!form.port && !form.lenLo && !form.lenHi} className={btn.primary}><Plus className="h-4 w-4" /> Add rule</button>
          </div>
        </Panel>
      )}
    </div>
  )
}
