'use client'
import { useEffect, useState } from 'react'
import { instantAt, rangeAbs, toSeries, type InstantResult, type RangeResult } from '@/lib/prom'
import { si } from '@/lib/format'
import { SERIES } from '@/components/nd/ui'
import { Panel, Segmented, Empty, Badge, btn } from '@/components/aa/kit'
import { Play, BookOpen, History, AlertTriangle, LineChart as LineIcon, Table2, TerminalSquare, Loader2 } from 'lucide-react'
import { TimeChart } from '@/components/nd/charts'
import { useRange } from '@/components/aa/Shell'

// Query console: raw PromQL against the appliance's Prometheus, read-only
// (the /api/prom proxy only forwards GETs). Instant results render as a
// table; range results as a chart (top 5 series) plus a table of series.
// Recent queries are kept in this browser only.

const EXAMPLES = [
  { label: 'Ingress by interface', q: 'sum by(iface)(rate(xs_rx_bytes_total[1m]))*8' },
  { label: 'Drop ratio', q: 'sum(rate(xs_verdict_packets_total{verdict="drop"}[1m])) / sum(rate(xs_rx_packets_total[1m]))' },
  { label: 'TCP flag mix', q: 'sum by(class)(rate(xs_tcp_flags_packets_total[1m]))' },
  { label: 'Top 10 attack sources (all time)', q: 'topk(10, sum by(src)(xs_attacker_packets_total))' },
  { label: 'Active detections', q: 'xs_detection_info' },
  { label: 'Scrape targets up', q: 'up' },
]
const labelsOf = (m: Record<string, string>) =>
  Object.entries(m).filter(([k]) => k !== '__name__').map(([k, v]) => `${k}="${v}"`).join(', ')
const nameOf = (m: Record<string, string>) => `${m.__name__ ?? ''}{${labelsOf(m)}}`

export default function QueryPage() {
  const rng = useRange()
  const [q, setQ] = useState(EXAMPLES[0].q)
  const [mode, setMode] = useState<'range' | 'instant'>('range')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [res, setRes] = useState<{ mode: 'range'; r: RangeResult[]; span: number } | { mode: 'instant'; r: InstantResult[] } | null>(null)
  const [recent, setRecent] = useState<string[]>([])
  const [took, setTook] = useState<number | null>(null)

  useEffect(() => {
    try { setRecent(JSON.parse(localStorage.getItem('aa.queries') ?? '[]')) } catch {}
  }, [])

  const run = async (text = q) => {
    const expr = text.trim()
    if (!expr) return
    setBusy(true)
    setErr(null)
    const t0 = performance.now()
    try {
      const w = rng.resolve()
      if (mode === 'range') setRes({ mode, r: await rangeAbs(expr, w.start, w.end, w.step), span: w.span })
      else setRes({ mode, r: await instantAt(expr, w.end) })
      setTook(Math.round(performance.now() - t0))
      const next = [expr, ...recent.filter((x) => x !== expr)].slice(0, 10)
      setRecent(next)
      try { localStorage.setItem('aa.queries', JSON.stringify(next)) } catch {}
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
      setRes(null)
    } finally {
      setBusy(false)
    }
  }

  const rows = res?.mode === 'range'
    ? [...res.r].sort((a, b) => parseFloat(b.values.at(-1)?.[1] ?? '0') - parseFloat(a.values.at(-1)?.[1] ?? '0'))
    : []
  const shown = rows.slice(0, 5)

  return (
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1fr)_300px]">
      <div className="min-w-0 space-y-6">
        <section className="aa-in overflow-hidden rounded-2xl border border-nd-line bg-nd-card shadow-nd">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-nd-line bg-nd-fill px-4 py-2.5">
            <div className="flex items-center gap-2 text-[12.5px] font-medium text-nd-fg-3">
              <TerminalSquare className="h-4 w-4 text-nd-dim" /> PromQL
            </div>
            <div className="flex items-center gap-2">
              <Segmented label="Query type" size="sm" value={mode} onChange={setMode} options={[{ id: 'range', label: 'Range' }, { id: 'instant', label: 'Instant' }] as const} />
              <button onClick={() => run()} disabled={busy} className={`${btn.primary} py-1.5`}>
                {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
                Run
              </button>
            </div>
          </div>
          <textarea
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) { e.preventDefault(); run() } }}
            spellCheck={false}
            rows={5}
            aria-label="PromQL query"
            className="mono block w-full resize-y bg-nd-card px-4 py-3.5 text-[13.5px] leading-relaxed text-nd-fg outline-none"
          />
          <div className="flex flex-wrap items-center gap-2 border-t border-nd-line-soft px-4 py-2 text-[12px] text-nd-dim">
            <kbd className="rounded-md border border-nd-line bg-nd-fill px-1.5 py-0.5 text-[10.5px]">⌘ ↵</kbd> to run
            <span>·</span>
            {mode === 'range' ? rng.label : `evaluated at the end of ${rng.label}`}
            {took != null && <Badge className="ml-auto">{took} ms</Badge>}
          </div>
        </section>

        {err && (
          <div className="flex items-start gap-2 rounded-xl border border-st-crit/30 bg-st-crit/[0.06] px-4 py-3 text-[13px] text-st-crit-fg">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" /> <span className="mono break-all">{err}</span>
          </div>
        )}

        {!res && !err && (
          <Panel><Empty icon={TerminalSquare} title="Run a query to see results" hint="Range queries draw a chart over the selected window; instant queries return the current value of each series." /></Panel>
        )}

        {res?.mode === 'range' && (
          <>
            <Panel icon={LineIcon} title="Chart" sub={rows.length > 5 ? `Top 5 of ${rows.length} series by latest value` : `${rows.length} series`}>
              {rows.length ? (
                <TimeChart
                  loading={false}
                  data={toSeries(shown, (m) => nameOf(m))}
                  series={shown.map((s, i) => ({ key: nameOf(s.metric), label: labelsOf(s.metric) || s.metric.__name__ || 'value', color: SERIES[i % SERIES.length] }))}
                  yfmt={(n) => si(n)}
                  spanMs={res.span * 1000}
                  height={300}
                />
              ) : (
                <Empty icon={LineIcon} title="Empty result" />
              )}
            </Panel>
            <Panel icon={Table2} title="Series" sub="Latest value in the window" bodyClass="pb-2">
              <SeriesTable items={rows.map((s) => ({ m: s.metric, v: s.values.at(-1)?.[1] }))} />
            </Panel>
          </>
        )}
        {res?.mode === 'instant' && (
          <Panel icon={Table2} title="Result" sub={`${res.r.length} series`} bodyClass="pb-2">
            <SeriesTable items={res.r.map((s) => ({ m: s.metric, v: s.value[1] }))} />
          </Panel>
        )}
      </div>

      <div className="space-y-6">
        <Panel icon={BookOpen} title="Examples" bodyClass="px-3 pb-3">
          <ul className="space-y-0.5">
            {EXAMPLES.map((e) => (
              <li key={e.label}>
                <button onClick={() => { setQ(e.q); run(e.q) }} className="group flex w-full items-center gap-2 rounded-lg px-2 py-2 text-left text-[13px] text-nd-fg-3 hover:bg-nd-fill hover:text-nd-fg">
                  <Play className="h-3 w-3 text-nd-faint group-hover:text-nd-fg" /> {e.label}
                </button>
              </li>
            ))}
          </ul>
        </Panel>
        <Panel icon={History} title="Recent" sub="Kept in this browser" bodyClass="px-3 pb-3">
          {recent.length ? (
            <ul className="space-y-0.5">
              {recent.map((r) => (
                <li key={r}>
                  <button onClick={() => setQ(r)} className="mono w-full truncate rounded-lg px-2 py-1.5 text-left text-[12px] text-nd-muted hover:bg-nd-fill hover:text-nd-fg" title={r}>{r}</button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="px-2 pb-1 text-[12.5px] text-nd-faint">Queries you run appear here.</p>
          )}
        </Panel>
      </div>
    </div>
  )
}

function SeriesTable({ items }: { items: { m: Record<string, string>; v?: string }[] }) {
  if (!items.length) return <Empty icon={Table2} title="Empty result" />
  return (
    <div className="max-h-[420px] overflow-auto">
      <table className="w-full text-[12.5px]">
        <thead className="sticky top-0 bg-nd-fill text-left text-[11px] uppercase tracking-[0.06em] text-nd-dim">
          <tr className="border-y border-nd-line"><th className="px-5 py-2 font-medium">Series</th><th className="px-5 py-2 text-right font-medium">Value</th></tr>
        </thead>
        <tbody>
          {items.map((it, i) => (
            <tr key={i} className="border-b border-nd-line-soft last:border-0 hover:bg-nd-fill">
              <td className="mono break-all px-5 py-2 text-nd-fg-3">{nameOf(it.m)}</td>
              <td className="mono px-5 py-2 text-right font-medium text-nd-fg">{it.v ?? '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
