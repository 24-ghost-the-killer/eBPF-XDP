'use client'
import { Suspense, useEffect, useMemo, useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'
import { rangeAbs, toSeries, type RangeResult, type Row } from '@/lib/prom'
import { usePoll } from '@/hooks/usePoll'
import { METRICS, metricById, fmtUnit, fmtTotal } from '@/lib/catalog'
import { summarize, histogram, type Summary } from '@/lib/stats'
import { SERIES } from '@/components/nd/ui'
import { Panel, Chip, Segmented, Badge, Empty, btn } from '@/components/aa/kit'
import { Search, Download, Link2, Check, Table2, Code2, BarChart3, Sigma, LineChart as LineIcon, SearchX } from 'lucide-react'
import { TimeChart } from '@/components/nd/charts'
import { useRange, PRESETS, type PresetId } from '@/components/aa/Shell'

// Explorer: any catalogue metric over the shared window, optionally split by a
// label and overlaid with the previous period. Below the chart: per-series
// statistics, the distribution of one series, the raw data and the PromQL.
// State lives in the URL (?metric=&by=&compare=&range=) so views can be shared.

const ADDITIVE = new Set(['bps', 'pps'])
const MAX_SERIES = 5

function ExplorerInner() {
  const sp = useSearchParams()
  const router = useRouter()
  const rng = useRange()
  const [metricId, setMetricId] = useState(sp.get('metric') ?? 'ingress_bps')
  const [by, setBy] = useState<string>(sp.get('by') ?? '')
  const [compare, setCompare] = useState(sp.get('compare') === '1')
  const [kind, setKind] = useState<'line' | 'area'>('line')
  const [focus, setFocus] = useState<string | null>(null)
  const [showTable, setShowTable] = useState(false)
  const [mq, setMq] = useState('')
  const [copied, setCopied] = useState(false)
  const m = metricById(metricId)
  const split = by && m.dims.includes(by) ? by : null

  // A ?range= deep link selects that preset once.
  useEffect(() => {
    const r = sp.get('range')
    if (r && PRESETS.some((p) => p.id === r)) rng.setPreset(r as PresetId)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  // Mirror the view into the URL so it can be shared.
  useEffect(() => {
    const q = new URLSearchParams({ metric: metricId })
    if (split) q.set('by', split)
    if (compare && !split) q.set('compare', '1')
    if (rng.preset !== 'custom') q.set('range', rng.preset)
    router.replace(`/analytics/explore?${q}`, { scroll: false })
  }, [metricId, split, compare, rng.preset, router])

  const data = usePoll(async () => {
    const w = rng.resolve()
    const expr = m.build(w.rw, split)
    const [cur, prev] = await Promise.all([
      rangeAbs(expr, w.start, w.end, w.step),
      compare && !split ? rangeAbs(expr, w.start - w.span, w.end - w.span, w.step) : Promise.resolve([] as RangeResult[]),
    ])
    return { expr, cur, prev, w }
  }, rng.refreshMs, [metricId, split, compare, rng.key])

  const view = useMemo(() => {
    const d = data.data
    if (!d) return null
    const name = (s: RangeResult) => (split ? s.metric[split] ?? '(none)' : m.label)
    // rank series by mean, keep the top ones; fold the rest into "Other" when summing is meaningful
    let sers = d.cur.map((s) => ({ name: name(s), values: s.values.map(([t, v]) => [t, parseFloat(v)] as [number, number]) }))
    const meanOf = (vals: [number, number][]) => vals.reduce((a, [, v]) => a + (Number.isFinite(v) ? v : 0), 0) / Math.max(1, vals.length)
    sers.sort((a, b) => meanOf(b.values) - meanOf(a.values))
    const total = sers.length
    let note = ''
    if (sers.length > MAX_SERIES) {
      const keep = sers.slice(0, MAX_SERIES - (ADDITIVE.has(m.unit) ? 1 : 0))
      if (ADDITIVE.has(m.unit)) {
        const rest = sers.slice(keep.length)
        const acc = new Map<number, number>()
        for (const s of rest) for (const [t, v] of s.values) if (Number.isFinite(v)) acc.set(t, (acc.get(t) ?? 0) + v)
        keep.push({ name: `Other (${rest.length})`, values: [...acc.entries()].sort((a, b) => a[0] - b[0]) })
        note = `${rest.length} smaller series folded into "Other".`
      } else note = `Showing the top ${MAX_SERIES} of ${total} series by mean.`
      sers = keep
    }
    const rows: RangeResult[] = sers.map((s) => ({ metric: { k: s.name }, values: s.values.map(([t, v]) => [t, String(v)] as [number, string]) }))
    if (d.prev.length) {
      const pv = d.prev[0].values.map(([t, v]) => [t + d.w.span, v] as [number, string])
      rows.push({ metric: { k: 'Previous period' }, values: pv })
    }
    const table: Row[] = toSeries(rows, (x) => x.k)
    const defs = rows.map((r, i) => ({
      key: r.metric.k,
      label: r.metric.k,
      color: r.metric.k === 'Previous period' ? 'var(--nd-dim)' : SERIES[i % SERIES.length],
      dashed: r.metric.k === 'Previous period',
    }))
    const stats: { key: string; color: string; s: Summary | null }[] = defs.map((df) => ({
      key: df.key,
      color: df.color,
      s: summarize(table.map((r) => r[df.key]), d.w.step),
    }))
    return { table, defs, stats, note, w: d.w, expr: d.expr, empty: d.cur.length === 0 }
  }, [data.data, split, m])

  const focusKey = focus && view?.defs.some((d) => d.key === focus) ? focus : view?.defs[0]?.key
  const hist = useMemo(() => {
    if (!view || !focusKey) return []
    return histogram(view.table.map((r) => r[focusKey]).filter((x): x is number => typeof x === 'number'), 24)
  }, [view, focusKey])

  const exportCsv = () => {
    if (!view) return
    const keys = view.defs.map((d) => d.key)
    const esc = (s: string) => `"${s.replace(/"/g, '""')}"`
    const lines = [['time', ...keys].map(esc).join(',')]
    for (const r of view.table) lines.push([new Date(r.t).toISOString(), ...keys.map((k) => (r[k] ?? '').toString())].join(','))
    const url = URL.createObjectURL(new Blob([lines.join('\n')], { type: 'text/csv' }))
    const a = document.createElement('a')
    a.href = url
    a.download = `${m.id}${split ? `-by-${split}` : ''}-${rng.preset}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  const groups = Array.from(new Set(METRICS.map((x) => x.group)))
  const filtered = METRICS.filter((x) => !mq || `${x.label} ${x.group} ${x.help}`.toLowerCase().includes(mq.toLowerCase()))
  const UNIT: Record<string, string> = { bps: 'bit/s', pps: 'pkt/s', bytes: 'bytes', ratio: '%', score: '0–1', level: 'level' }
  const copyLink = () => {
    navigator.clipboard?.writeText(window.location.href)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  return (
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-[280px_minmax(0,1fr)]">
      {/* metric browser */}
      <aside className="xl:sticky xl:top-28 xl:self-start">
        <Panel title="Metrics" sub={`${METRICS.length} series in the catalogue`} bodyClass="px-3 pb-3">
          <div className="relative px-2">
            <Search className="pointer-events-none absolute left-4.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-nd-faint" />
            <input value={mq} onChange={(e) => setMq(e.target.value)} placeholder="Filter metrics…" aria-label="Filter metrics" className={`${btn.input} w-full py-1.5 pl-8`} />
          </div>
          <div className="mt-3 max-h-[60vh] overflow-y-auto pr-1">
            {groups.map((g) => {
              const items = filtered.filter((x) => x.group === g)
              if (!items.length) return null
              return (
                <div key={g} className="mb-3">
                  <div className="px-2 pb-1 text-[11px] font-semibold uppercase tracking-[0.08em] text-nd-faint">{g}</div>
                  <ul className="space-y-0.5">
                    {items.map((x) => (
                      <li key={x.id}>
                        <button
                          onClick={() => { setMetricId(x.id); setFocus(null) }}
                          aria-current={x.id === metricId}
                          className={`flex w-full items-center justify-between gap-2 rounded-lg px-2 py-1.5 text-left text-[13px] transition-colors ${
                            x.id === metricId ? 'bg-nd-fill-2 font-medium text-nd-fg' : 'text-nd-muted hover:bg-nd-fill hover:text-nd-fg'
                          }`}
                        >
                          <span className="truncate">{x.label}</span>
                          <span className="shrink-0 text-[10.5px] text-nd-faint">{UNIT[x.unit]}</span>
                        </button>
                      </li>
                    ))}
                  </ul>
                </div>
              )
            })}
            {!filtered.length && <p className="px-2 py-4 text-center text-[12.5px] text-nd-faint">No metric matches “{mq}”.</p>}
          </div>
        </Panel>
      </aside>

      <div className="min-w-0 space-y-6">
        {/* title + toolbar */}
        <div className="space-y-3">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-[18px] font-semibold tracking-[-0.02em] text-nd-fg">{m.label}</h2>
                <Badge tone="neutral">{m.group}</Badge>
                <Badge tone="neutral">{UNIT[m.unit]}</Badge>
              </div>
              <p className="mt-1 text-[13px] text-nd-dim">{m.help}{view?.note ? ` ${view.note}` : ''}</p>
            </div>
            <div className="flex items-center gap-2">
              <button onClick={copyLink} className={btn.ghost}>{copied ? <Check className="h-3.5 w-3.5" /> : <Link2 className="h-3.5 w-3.5" />}{copied ? 'Copied' : 'Copy link'}</button>
              <button onClick={exportCsv} disabled={!view} className={btn.ghost}><Download className="h-3.5 w-3.5" />Export CSV</button>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-x-5 gap-y-3 rounded-2xl border border-nd-line bg-nd-card px-4 py-3 shadow-nd">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="mr-1 text-[12px] font-medium text-nd-dim">Split by</span>
              <Chip on={!split} onClick={() => { setBy(''); setFocus(null) }}>Total</Chip>
              {m.dims.map((dim) => <Chip key={dim} on={split === dim} onClick={() => { setBy(dim); setFocus(null) }}>{dim}</Chip>)}
              {!m.dims.length && <span className="text-[12px] text-nd-faint">not splittable</span>}
            </div>
            <span className="hidden h-5 w-px bg-nd-line sm:block" />
            <label className={`flex items-center gap-2.5 text-[13px] ${split ? 'cursor-not-allowed opacity-50' : 'cursor-pointer'}`} title={split ? 'Comparison works on the total' : 'Overlay the window before this one'}>
              <button
                role="switch"
                aria-checked={compare && !split}
                disabled={!!split}
                onClick={() => setCompare((c) => !c)}
                className={`relative h-5 w-9 rounded-full transition-colors ${compare && !split ? 'bg-nd-fg' : 'bg-nd-fill-2'}`}
              >
                <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-nd-card shadow-nd transition-all ${compare && !split ? 'left-[18px]' : 'left-0.5'}`} />
              </button>
              <span className="text-nd-fg-3">Compare with previous period</span>
            </label>
            <div className="ml-auto">
              <Segmented label="Chart type" size="sm" value={kind} onChange={setKind} options={[{ id: 'line', label: 'Line' }, { id: 'area', label: 'Area' }] as const} />
            </div>
          </div>
        </div>

        <Panel icon={LineIcon} title={`${m.label}${split ? ` by ${split}` : ''}`} sub={`${rng.label} · ${view ? `${view.w.step}s resolution · ${view.defs.length} series` : 'loading…'}`}>
          {data.error && !view ? (
            <Empty icon={SearchX} title="Query failed" hint={data.error} />
          ) : view?.empty ? (
            <Empty icon={SearchX} title="No data in this window" hint="Try a longer range or another metric." />
          ) : (
            <TimeChart
              kind={kind === 'area' && !compare ? 'area' : 'line'}
              stacked={kind === 'area' && !!split && ADDITIVE.has(m.unit)}
              loading={!view}
              data={view?.table ?? []}
              series={view?.defs ?? []}
              yfmt={(n) => fmtUnit(m.unit, n)}
              spanMs={(view?.w.span ?? 3600) * 1000}
              height={340}
            />
          )}
        </Panel>

        <div className="grid grid-cols-1 gap-6 2xl:grid-cols-3">
          <Panel className="2xl:col-span-2" icon={Sigma} title="Statistics" sub="Per series over the window · select a row to see its distribution" bodyClass="pb-2">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[720px] text-right text-[12.5px]">
                <thead>
                  <tr className="border-y border-nd-line bg-nd-fill text-[11px] font-medium uppercase tracking-[0.06em] text-nd-dim">
                    <th className="px-5 py-2 text-left font-medium">Series</th>
                    {['min', 'mean', 'p50', 'p95', 'p99', 'max', 'latest'].map((h) => <th key={h} className="px-2 py-2 font-medium">{h}</th>)}
                    {ADDITIVE.has(m.unit) && <th className="px-5 py-2 font-medium">total</th>}
                  </tr>
                </thead>
                <tbody className="mono tabular-nums">
                  {!view && [0, 1].map((i) => <tr key={i}><td colSpan={9} className="px-5 py-2"><div className="aa-skeleton h-5 rounded" /></td></tr>)}
                  {(view?.stats ?? []).map(({ key, color, s }) => (
                    <tr
                      key={key}
                      onClick={() => setFocus(key)}
                      className={`cursor-pointer border-b border-nd-line-soft transition-colors last:border-0 hover:bg-nd-fill ${focusKey === key ? 'bg-nd-fill' : ''}`}
                    >
                      <td className="px-5 py-2.5 text-left font-sans">
                        <span className="flex items-center gap-2 text-nd-fg-2">
                          <span className="h-2.5 w-2.5 shrink-0 rounded-[3px]" style={{ background: color }} />
                          <span className="truncate font-medium">{key}</span>
                        </span>
                      </td>
                      {s ? (
                        <>
                          {[s.min, s.mean, s.p50, s.p95, s.p99, s.max, s.last].map((v, i) => <td key={i} className="px-2 py-2.5 text-nd-fg-3">{fmtUnit(m.unit, v)}</td>)}
                          {ADDITIVE.has(m.unit) && <td className="px-5 py-2.5 font-medium text-nd-fg">{fmtTotal(m.unit, s.integral)}</td>}
                        </>
                      ) : (
                        <td colSpan={8} className="px-5 py-2.5 text-nd-faint">no samples</td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>

          <Panel icon={BarChart3} title="Distribution" sub={focusKey ? `${focusKey} · how often each value occurred` : 'Select a series'}>
            {hist.length ? (
              <ResponsiveContainer width="100%" height={230}>
                <BarChart data={hist} margin={{ top: 4, right: 4, bottom: 0, left: 0 }} barCategoryGap={1}>
                  <CartesianGrid stroke="var(--nd-grid)" vertical={false} />
                  <XAxis dataKey="x0" tickFormatter={(v) => fmtUnit(m.unit, v)} tick={{ fill: 'var(--nd-dim)', fontSize: 10.5 }} tickLine={false} axisLine={false} minTickGap={30} />
                  <YAxis allowDecimals={false} width={34} tick={{ fill: 'var(--nd-dim)', fontSize: 10.5 }} tickLine={false} axisLine={false} />
                  <Tooltip
                    cursor={{ fill: 'var(--nd-track)' }}
                    content={({ active, payload }) => {
                      if (!active || !payload?.length) return null
                      const b = payload[0].payload as { x0: number; x1: number; n: number }
                      return (
                        <div className="rounded-xl border border-nd-line bg-nd-tip px-3 py-2 text-[12px] shadow-nd-lg">
                          <div className="text-nd-dim">{fmtUnit(m.unit, b.x0)} – {fmtUnit(m.unit, b.x1)}</div>
                          <div className="mono text-nd-fg">{b.n} sample{b.n === 1 ? '' : 's'}</div>
                        </div>
                      )
                    }}
                  />
                  <Bar dataKey="n" fill="var(--s1)" radius={[4, 4, 0, 0]} isAnimationActive={false} />
                </BarChart>
              </ResponsiveContainer>
            ) : view ? (
              <Empty icon={BarChart3} title="No samples" />
            ) : (
              <div className="aa-skeleton h-[230px] rounded-xl" />
            )}
          </Panel>
        </div>

        <Panel
          icon={Code2}
          title="PromQL"
          sub="The query behind this view"
          actions={<button onClick={() => view && navigator.clipboard?.writeText(view.expr)} className="text-[12px] font-medium text-nd-dim hover:text-nd-fg">Copy</button>}
        >
          <pre className="mono overflow-x-auto whitespace-pre-wrap break-all rounded-xl border border-nd-line bg-nd-fill px-4 py-3 text-[12.5px] leading-relaxed text-nd-fg-3">{view?.expr ?? m.build('60s', split)}</pre>
        </Panel>

        <Panel
          icon={Table2}
          title="Raw data"
          sub={view ? `${view.table.length} samples, newest first` : 'loading…'}
          actions={<button onClick={() => setShowTable((x) => !x)} className={btn.ghost}>{showTable ? 'Hide' : 'Show'} table</button>}
          bodyClass={showTable ? 'pb-2' : 'px-5 pb-5'}
        >
          {showTable && view ? (
            <div className="max-h-[420px] overflow-auto">
              <table className="w-full text-right text-[12px]">
                <thead className="sticky top-0 bg-nd-fill text-[11px] font-medium uppercase tracking-[0.06em] text-nd-dim">
                  <tr><th className="px-5 py-2 text-left font-medium">time</th>{view.defs.map((d) => <th key={d.key} className="px-3 py-2 font-medium">{d.key}</th>)}</tr>
                </thead>
                <tbody className="mono tabular-nums text-nd-fg-3">
                  {[...view.table].reverse().map((r) => (
                    <tr key={r.t} className="border-t border-nd-line-soft hover:bg-nd-fill">
                      <td className="px-5 py-1.5 text-left text-nd-dim">{new Date(r.t).toLocaleString([], { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit' })}</td>
                      {view.defs.map((d) => <td key={d.key} className="px-3 py-1.5">{fmtUnit(m.unit, r[d.key])}</td>)}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-[13px] text-nd-dim">Every sample behind the chart. Use Export CSV to take it elsewhere.</p>
          )}
        </Panel>
      </div>
    </div>
  )
}

export default function ExplorerPage() {
  return (
    <Suspense fallback={<div className="aa-skeleton h-[480px] rounded-2xl" />}>
      <ExplorerInner />
    </Suspense>
  )
}
