'use client'
// Service uptime: is each of your services up right now, how fast does it
// answer, and how reliable has it been (24 h strip, 24 h and 30 day %).
import { useState } from 'react'
import { Activity, Plus, Trash2, CircleCheck, CircleX, CircleDashed, Sparkles } from 'lucide-react'
import { usePoll } from '@/hooks/usePoll'
import { Panel, Empty, btn } from '@/components/aa/kit'
import { useMe } from '@/components/aa/Shell'

type Kind = 'ping' | 'tcp' | 'http' | 'https'
interface Check {
  id: string; name: string; host: string; kind: Kind; port?: number; path?: string
  up: boolean | null; ms: number | null; lastAt: number | null; since: number | null; day: number | null; month: number | null; strip: (0 | 1 | null)[]
}
interface Suggestion { name: string; host: string; kind: Kind; port?: number }

const pct = (x: number | null) => (x == null ? '—' : x >= 0.9995 ? '100%' : `${(x * 100).toFixed(x >= 0.99 ? 2 : 1)}%`)
const dur = (ms: number | null) => {
  if (!ms) return ''
  const s = Math.max(0, (Date.now() - ms) / 1000)
  return s < 3600 ? `${Math.round(s / 60)} min` : s < 86400 ? `${Math.round(s / 3600)} h` : `${Math.round(s / 86400)} d`
}
const what = (c: Pick<Check, 'kind' | 'host' | 'port' | 'path'>) => c.kind === 'ping' ? `ping ${c.host}` : c.kind === 'tcp' ? `TCP ${c.host}:${c.port}` : `${c.kind}://${c.host}${c.port ? `:${c.port}` : ''}${c.path ?? '/'}`

export default function UptimePage() {
  const { can } = useMe()
  const edit = can('uptime.edit')
  const [rev, setRev] = useState(0)
  const q = usePoll(async () => {
    const r = await fetch('/api/uptime', { cache: 'no-store' })
    const j = await r.json()
    if (j.status !== 'success') throw new Error(j.error || 'uptime unavailable')
    return j as { checks: Check[]; suggestions: Suggestion[] }
  }, 30_000, [rev])
  const [form, setForm] = useState({ name: '', host: '', kind: 'tcp' as Kind, port: '' })
  const [err, setErr] = useState('')
  const add = async (c: { name: string; host: string; kind: Kind; port?: number | string }) => {
    setErr('')
    const r = await fetch('/api/uptime', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...c, port: c.port ? Number(c.port) : undefined }) })
    const j = await r.json().catch(() => ({}))
    if (j.status !== 'success') setErr(j.error || 'could not add'); else setForm({ name: '', host: '', kind: 'tcp', port: '' })
    setRev((x) => x + 1)
  }
  const remove = async (id: string) => { await fetch(`/api/uptime?id=${id}`, { method: 'DELETE' }); setRev((x) => x + 1) }

  const d = q.data
  if (!d) return q.error ? <Empty icon={Activity} title="Uptime unavailable" hint={q.error} /> : <div className="aa-skeleton h-64 rounded-2xl" />
  const down = d.checks.filter((c) => c.up === false)

  return (
    <div className="space-y-6">
      <section className={`flex items-center gap-3 rounded-2xl border px-5 py-4 ${down.length ? 'border-st-crit/30 bg-st-crit/[0.06]' : 'border-st-good/25 bg-st-good/[0.06]'}`}>
        {down.length ? <CircleX className="h-6 w-6 text-st-crit-fg" /> : <CircleCheck className="h-6 w-6 text-st-good-fg" />}
        <div>
          <h2 className="text-[16px] font-semibold text-nd-fg">{d.checks.length === 0 ? 'No services watched yet' : down.length ? `${down.length} service${down.length === 1 ? ' is' : 's are'} down: ${down.map((c) => c.name).join(', ')}` : `All ${d.checks.length} services are up`}</h2>
          <p className="text-[12.5px] text-nd-dim">Checked every minute by the dashboard</p>
        </div>
      </section>

      {d.checks.length > 0 && (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 2xl:grid-cols-3">
          {d.checks.map((c) => (
            <div key={c.id} className={`rounded-2xl border bg-nd-card px-5 py-4 shadow-nd ${c.up === false ? 'border-st-crit/40' : 'border-nd-line'}`}>
              <div className="flex items-start gap-3">
                {c.up == null ? <CircleDashed className="mt-0.5 h-5 w-5 text-nd-faint" /> : c.up ? <CircleCheck className="mt-0.5 h-5 w-5 text-st-good-fg" /> : <CircleX className="mt-0.5 h-5 w-5 text-st-crit-fg" />}
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[14.5px] font-semibold text-nd-fg">{c.name}</div>
                  <div className="truncate font-mono text-[11.5px] text-nd-faint">{what(c)}</div>
                </div>
                <div className="text-right">
                  <div className={`text-[13px] font-semibold ${c.up === false ? 'text-st-crit-fg' : c.up ? 'text-st-good-fg' : 'text-nd-faint'}`}>{c.up == null ? 'waiting' : c.up ? 'Up' : 'Down'}</div>
                  <div className="text-[11.5px] text-nd-faint">{c.up != null && c.since ? `for ${dur(c.since)}` : ''}{c.up && c.ms != null ? ` · ${c.ms} ms` : ''}</div>
                </div>
              </div>
              <div className="mt-3 flex gap-[2px]" aria-label="last 24 hours, 15 minutes per bar">
                {c.strip.map((x, i) => <span key={i} className={`h-6 flex-1 rounded-[2px] ${x == null ? 'bg-nd-fill-2' : x ? 'bg-st-good/70' : 'bg-st-crit'}`} />)}
              </div>
              <div className="mt-1 flex justify-between text-[10.5px] text-nd-faint"><span>24 h ago</span><span>now</span></div>
              <div className="mt-2 flex items-center gap-4 text-[12px] text-nd-fg-3">
                <span>24 h <b className="text-nd-fg">{pct(c.day)}</b></span>
                <span>30 days <b className="text-nd-fg">{pct(c.month)}</b></span>
                {edit && <button type="button" onClick={() => remove(c.id)} className="ml-auto rounded-md p-1 text-nd-faint hover:bg-nd-fill hover:text-nd-fg" aria-label={`Remove ${c.name}`}><Trash2 className="h-3.5 w-3.5" /></button>}
              </div>
            </div>
          ))}
        </div>
      )}

      {edit && (
        <Panel icon={Plus} title="Watch a service" sub="Ping a device, check that a port answers, or load a web page">
          {d.suggestions.length > 0 && (
            <div className="mb-4">
              <div className="mb-1.5 flex items-center gap-1.5 text-[12px] font-medium text-nd-dim"><Sparkles className="h-3.5 w-3.5" /> Found on your network</div>
              <div className="flex flex-wrap gap-2">
                {d.suggestions.map((s) => (
                  <button key={`${s.host}${s.port}`} type="button" onClick={() => add(s)} className="rounded-lg border border-nd-line px-2.5 py-1 text-[12.5px] text-nd-fg-3 hover:border-nd-line-strong hover:text-nd-fg">
                    <Plus className="mr-1 inline h-3 w-3" />{s.name} <span className="font-mono text-[11px] text-nd-faint">{what(s)}</span>
                  </button>
                ))}
              </div>
            </div>
          )}
          <div className="flex flex-wrap items-end gap-3 text-[12.5px]">
            <label className="flex flex-col gap-1 text-nd-dim">Name<input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Proxmox" className={`${btn.input} w-40 py-1.5`} /></label>
            <label className="flex flex-col gap-1 text-nd-dim">Host<input value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} placeholder="192.168.1.173" className={`${btn.input} w-40 py-1.5 font-mono`} /></label>
            <label className="flex flex-col gap-1 text-nd-dim">Check
              <select value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value as Kind })} className={`${btn.input} py-1.5`}>
                <option value="ping">Ping</option><option value="tcp">TCP port</option><option value="http">HTTP page</option><option value="https">HTTPS page</option>
              </select>
            </label>
            {form.kind !== 'ping' && <label className="flex flex-col gap-1 text-nd-dim">Port<input value={form.port} onChange={(e) => setForm({ ...form, port: e.target.value.replace(/\D/g, '').slice(0, 5) })} placeholder={form.kind === 'https' ? '443' : form.kind === 'http' ? '80' : '22'} className={`${btn.input} w-20 py-1.5`} /></label>}
            <button type="button" onClick={() => add(form)} disabled={!form.host} className={btn.primary}><Plus className="h-4 w-4" /> Add</button>
          </div>
          {err && <p className="mt-2 text-[12.5px] text-st-crit-fg">{err}</p>}
        </Panel>
      )}
    </div>
  )
}
