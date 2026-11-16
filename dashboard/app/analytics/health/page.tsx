'use client'
// Dataplane health: is the firewall program on every interface the current one,
// is the agent running the binary on disk, is Prometheus collecting? Each
// problem comes with the command that fixes it.
import { useState } from 'react'
import { HeartPulse, CheckCircle2, AlertTriangle, XCircle, Info, Copy, Check, Cpu, FileCode2, Network, RefreshCw } from 'lucide-react'
import { usePoll } from '@/hooks/usePoll'
import { Panel, Badge, Empty } from '@/components/aa/kit'

type Tone = 'good' | 'warn' | 'bad' | 'neutral'
interface Check { id: string; tone: Tone; title: string; text: string; fix?: string }
interface Iface { iface: string; role: string; master: string | null; up: boolean; progId: number; mode: string; configured: boolean; progName: string | null; tag: string | null; loadedAt: number | null; pinnedId: number | null }
interface Health {
  overall: Tone; at: number; checks: Check[]; interfaces: Iface[]
  object: { path: string; mtime: number | null; size: number | null; sha?: string }
  agent: { active: boolean; started: number | null; binary: { path: string; mtime: number | null }; version: string | null; pid: number | null; mode: string | null; flags: string[]; schema: string | null; restarts: number }
}

const ICON = { good: CheckCircle2, warn: AlertTriangle, bad: XCircle, neutral: Info }
const INK: Record<Tone, string> = { good: 'text-st-good-fg', warn: 'text-st-warn-fg', bad: 'text-st-crit-fg', neutral: 'text-nd-dim' }
const BOX: Record<Tone, string> = { good: 'border-st-good/25 bg-st-good/[0.06]', warn: 'border-st-warn/30 bg-st-warn/[0.07]', bad: 'border-st-crit/25 bg-st-crit/[0.06]', neutral: 'border-nd-line bg-nd-panel' }
const when = (ms: number | null) => (ms ? new Date(ms).toLocaleString([], { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—')

export default function HealthPage() {
  const q = usePoll(async () => {
    const r = await fetch('/api/health', { cache: 'no-store' })
    const j = await r.json()
    if (j.status !== 'success') throw new Error(j.error || 'health check failed')
    return j as Health
  }, 15_000)
  const h = q.data
  if (!h) return q.error ? <Empty icon={HeartPulse} title="Couldn’t run the health check" hint={q.error} /> : <div className="aa-skeleton h-64 rounded-2xl" />

  const problems = h.checks.filter((c) => c.tone === 'bad' || c.tone === 'warn')
  const Head = ICON[h.overall]
  const stale = new Set(h.checks.filter((c) => c.tone === 'bad' && c.id.startsWith('if-')).map((c) => c.id.slice(3)))
  return (
    <div className="space-y-6">
      <section className={`flex flex-wrap items-center justify-between gap-3 rounded-2xl border px-5 py-4 ${BOX[h.overall]}`}>
        <div className="flex items-center gap-3">
          <Head className={`h-6 w-6 ${INK[h.overall]}`} />
          <div>
            <h2 className="text-[16px] font-semibold text-nd-fg">
              {h.overall === 'good' ? 'Everything is running the current dataplane' : `${problems.length} thing${problems.length === 1 ? '' : 's'} need${problems.length === 1 ? 's' : ''} attention`}
            </h2>
            <p className="text-[12.5px] text-nd-dim">Checked {when(h.at)} · re-checks every 15 s</p>
          </div>
        </div>
        <span className="inline-flex items-center gap-1.5 text-[12px] text-nd-dim"><RefreshCw className="h-3.5 w-3.5" /> live</span>
      </section>

      <Panel icon={HeartPulse} title="Checks" sub="Problems first, each with the command that fixes it (run it on the server)">
        <ul className="space-y-2.5">
          {h.checks.map((c) => <CheckRow key={c.id} c={c} />)}
        </ul>
      </Panel>

      <Panel icon={Network} title="Interfaces with a firewall program" sub="From the kernel (ip link) plus the agent’s program load times" bodyClass="">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[760px] text-left text-[13px]">
            <thead>
              <tr className="border-y border-nd-line bg-nd-fill text-[11px] uppercase tracking-[0.06em] text-nd-dim">
                <th className="py-2 pl-5 pr-3 font-medium">Interface</th>
                <th className="px-3 py-2 font-medium">Role</th>
                <th className="px-3 py-2 text-right font-medium">Program</th>
                <th className="px-3 py-2 font-medium">Mode</th>
                <th className="px-3 py-2 font-medium">Loaded</th>
                <th className="px-3 py-2 pr-5 font-medium">State</th>
              </tr>
            </thead>
            <tbody>
              {h.interfaces.map((i) => (
                <tr key={i.iface} className="border-b border-nd-line-soft last:border-0">
                  <td className="py-2.5 pl-5 pr-3"><span className="mono font-medium text-nd-fg">{i.iface}</span>{i.master && <span className="ml-2 text-[11px] text-nd-faint">on {i.master}</span>}</td>
                  <td className="px-3 py-2.5 text-nd-fg-3">{i.role}</td>
                  <td className="mono px-3 py-2.5 text-right text-nd-fg-2">{i.progId ? `#${i.progId}` : '—'}</td>
                  <td className="px-3 py-2.5 text-nd-fg-3">{i.mode}</td>
                  <td className="mono px-3 py-2.5 text-[12px] text-nd-dim">{when(i.loadedAt)}</td>
                  <td className="px-3 py-2.5 pr-5">
                    {!i.progId ? <Badge tone="bad">not attached</Badge> : stale.has(i.iface) ? <Badge tone="bad">old program</Badge> : !i.up ? <Badge tone="warn">link down</Badge> : <Badge tone="good">current</Badge>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <Panel icon={FileCode2} title="Installed dataplane" sub="The object every attach loads">
          <Facts rows={[
            ['File', h.object.path],
            ['Installed', when(h.object.mtime)],
            ['Size', h.object.size ? `${(h.object.size / 1024).toFixed(1)} KiB` : '—'],
            ['SHA-256', h.object.sha ? `${h.object.sha}…` : '—'],
          ]} />
        </Panel>
        <Panel icon={Cpu} title="Agent" sub="sentinel-agent (detection, auto-mitigation, metrics)">
          <Facts rows={[
            ['Service', h.agent.active ? `running${h.agent.pid ? ` · pid ${h.agent.pid}` : ''}` : 'stopped'],
            ['Started', when(h.agent.started)],
            ['Binary installed', when(h.agent.binary.mtime)],
            ['Version', h.agent.version ?? 'older build (no version endpoint)'],
            ['Restarts', String(h.agent.restarts)],
            ['Standing defences', h.agent.flags.length ? h.agent.flags.join(', ') : '—'],
          ]} />
        </Panel>
      </div>
    </div>
  )
}

function CheckRow({ c }: { c: Check }) {
  const I = ICON[c.tone]
  const [copied, setCopied] = useState(false)
  return (
    <li className={`rounded-xl border px-4 py-3 ${BOX[c.tone]}`}>
      <div className="flex gap-2.5">
        <I className={`mt-0.5 h-4 w-4 shrink-0 ${INK[c.tone]}`} />
        <div className="min-w-0 flex-1">
          <div className="text-[13.5px] font-semibold text-nd-fg">{c.title}</div>
          <p className="mt-0.5 text-[12.5px] leading-relaxed text-nd-fg-3">{c.text}</p>
          {c.fix && (
            <div className="mt-2 flex items-center gap-2 rounded-lg border border-nd-line bg-nd-card px-3 py-1.5">
              <code className="mono min-w-0 flex-1 truncate text-[12px] text-nd-fg">{c.fix}</code>
              <button type="button" title="Copy the command" aria-label="Copy the command"
                onClick={() => { navigator.clipboard?.writeText(c.fix!.replace(/\s+#.*$/, '')).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500) }).catch(() => {}) }}
                className="grid h-6 w-6 shrink-0 place-items-center rounded-md text-nd-dim hover:bg-nd-fill hover:text-nd-fg">
                {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
              </button>
            </div>
          )}
        </div>
      </div>
    </li>
  )
}

function Facts({ rows }: { rows: [string, string][] }) {
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 text-[12.5px]">
      {rows.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-nd-dim">{k}</dt>
          <dd className="mono min-w-0 break-all text-nd-fg-2">{v}</dd>
        </div>
      ))}
    </dl>
  )
}

