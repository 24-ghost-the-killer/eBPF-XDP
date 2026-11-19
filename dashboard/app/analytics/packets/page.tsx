'use client'
// Packet explainer: pick a packet (an example attack, a live capture, or your
// own .pcap file) and see every header field explained, with the bytes it
// comes from highlighted in the hex view.
import { useMemo, useRef, useState } from 'react'
import { Binary, Radio, Upload, Loader2, FlaskConical, Lightbulb } from 'lucide-react'
import { decode, parsePcap, hexLines, EXAMPLES, type Packet, type Field } from '@/lib/packet'
import { Panel, btn } from '@/components/aa/kit'
import { useMe } from '@/components/aa/Shell'

const LAYER_COLOR = ['bg-sky-500/20', 'bg-violet-500/20', 'bg-emerald-500/20', 'bg-amber-500/25', 'bg-rose-500/20', 'bg-zinc-500/15']

export default function PacketsPage() {
  const { can } = useMe()
  const [packets, setPackets] = useState<(Packet & { label?: string; note?: string })[]>(() => EXAMPLES.map((e) => { const b = e.bytes(); return { ts: 0, bytes: b, origLen: e.origLen ?? b.length, label: e.title, note: e.note } }))
  const [source, setSource] = useState('Example attack packets')
  const [sel, setSel] = useState(0)
  const [hover, setHover] = useState<Field | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [filter, setFilter] = useState('all')
  const file = useRef<HTMLInputElement | null>(null)

  const cur = packets[sel]
  const dec = useMemo(() => (cur ? decode(cur.bytes, cur.origLen) : null), [cur])
  const byteLayer = useMemo(() => {
    const m: number[] = []
    dec?.layers.forEach((l, i) => { for (let o = l.off; o < l.off + l.len; o++) m[o] = i })
    return m
  }, [dec])

  const loadExamples = () => {
    setPackets(EXAMPLES.map((e) => { const b = e.bytes(); return { ts: 0, bytes: b, origLen: e.origLen ?? b.length, label: e.title, note: e.note } }))
    setSource('Example attack packets'); setSel(0); setErr('')
  }
  const capture = async () => {
    setBusy(true); setErr('')
    try {
      const r = await fetch('/api/packets', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ count: 30, filter }) })
      const j = await r.json()
      if (j.status !== 'success') throw new Error(j.error || 'capture failed')
      for (let i = 0; i < 30; i++) {
        await new Promise((res) => setTimeout(res, 1500))
        const p = await fetch(`/api/packets?id=${j.id}`, { cache: 'no-store' })
        if (p.status === 200) {
          const list = parsePcap(await p.arrayBuffer())
          if (!list.length) throw new Error('No packets went by in 20 seconds. Try “all”, or generate some traffic.')
          setPackets(list); setSource(`Live capture · ${list.length} packets (${filter})`); setSel(0)
          setBusy(false); return
        }
      }
      throw new Error('The capture service did not answer. Is xdp-sentinel-capture.path installed?')
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'capture failed')
    }
    setBusy(false)
  }
  const open = async (f: File) => {
    setErr('')
    try {
      const list = parsePcap(await f.arrayBuffer())
      if (!list.length) throw new Error('no packets in that file')
      setPackets(list); setSource(`${f.name} · ${list.length} packets`); setSel(0)
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'could not read the file')
    }
  }

  return (
    <div className="space-y-6">
      <Panel icon={Binary} title="Pick packets" sub={source}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" onClick={loadExamples} className={`${btn.ghost} py-1 text-[12.5px]`}><FlaskConical className="h-3.5 w-3.5" /> Examples</button>
            {can('packets.capture') && (
              <>
                <select value={filter} onChange={(e) => setFilter(e.target.value)} className={`${btn.input} py-1 text-[12.5px]`} aria-label="Which packets">
                  {['all', 'tcp', 'udp', 'icmp', 'arp', 'dns'].map((x) => <option key={x} value={x}>{x === 'all' ? 'all packets' : x.toUpperCase()}</option>)}
                </select>
                <button type="button" onClick={capture} disabled={busy} className={`${btn.ghost} py-1 text-[12.5px]`}>
                  {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Radio className="h-3.5 w-3.5" />} {busy ? 'Recording…' : 'Capture 30 live'}
                </button>
              </>
            )}
            <button type="button" onClick={() => file.current?.click()} className={`${btn.ghost} py-1 text-[12.5px]`}><Upload className="h-3.5 w-3.5" /> Open .pcap</button>
            <input ref={file} type="file" accept=".pcap,.cap,application/vnd.tcpdump.pcap" className="hidden" onChange={(e) => e.target.files?.[0] && open(e.target.files[0])} />
          </div>
        } bodyClass="">
        {err && <p className="px-5 pb-3 text-[12.5px] text-st-crit-fg">{err}</p>}
        <ul className="max-h-[240px] overflow-auto border-t border-nd-line-soft">
          {packets.map((p, i) => {
            const d = decode(p.bytes, p.origLen)
            return (
              <li key={i}>
                <button type="button" onClick={() => { setSel(i); setHover(null) }}
                  className={`flex w-full items-center gap-3 px-5 py-1.5 text-left text-[12.5px] ${i === sel ? 'bg-nd-fill' : 'hover:bg-nd-fill/60'}`}>
                  <span className="w-8 shrink-0 text-right font-mono text-nd-faint">{i + 1}</span>
                  {p.label && <span className="w-44 shrink-0 truncate font-medium text-nd-fg">{p.label}</span>}
                  <span className="min-w-0 flex-1 truncate font-mono text-nd-fg-3">{d.summary}</span>
                  <span className="shrink-0 tabular-nums text-nd-faint">{p.origLen} B</span>
                </button>
              </li>
            )
          })}
        </ul>
      </Panel>

      {cur && dec && (
        <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)]">
          <Panel icon={Lightbulb} title={cur.label ?? `Packet ${sel + 1}`} sub={`${dec.length} bytes on the wire${cur.bytes.length < dec.length ? `, first ${cur.bytes.length} recorded` : ''}`}>
            {(cur.note || dec.verdict) && (
              <div className="mb-4 rounded-xl border border-nd-line bg-nd-panel px-4 py-3 text-[13px] leading-relaxed text-nd-fg-3">
                {cur.note && <p>{cur.note}</p>}
                {dec.verdict && <p className={cur.note ? 'mt-1.5' : ''}><b className="text-nd-fg">What it is:</b> {dec.verdict}</p>}
              </div>
            )}
            <div className="space-y-4">
              {dec.layers.map((l, li) => (
                <div key={li}>
                  <div className="mb-1 flex items-center gap-2">
                    <span className={`h-3 w-3 rounded-sm ${LAYER_COLOR[li % LAYER_COLOR.length]}`} />
                    <span className="text-[13.5px] font-semibold text-nd-fg">{l.name}</span>
                    <span className="truncate font-mono text-[12px] text-nd-faint">{l.summary}</span>
                  </div>
                  <ul className="divide-y divide-nd-line-soft rounded-xl border border-nd-line">
                    {l.fields.map((f, fi) => (
                      <li key={fi} onMouseEnter={() => setHover(f)} onMouseLeave={() => setHover(null)}
                        className={`grid grid-cols-[150px_minmax(0,160px)_minmax(0,1fr)] gap-3 px-3 py-1.5 text-[12.5px] ${hover === f ? 'bg-nd-fill' : ''}`}>
                        <span className="text-nd-dim">{f.name}</span>
                        <span className="truncate font-mono text-nd-fg" title={f.value}>{f.value}</span>
                        <span className="text-nd-fg-3">{f.explain}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </Panel>

          <Panel icon={Binary} title="The raw bytes" sub="Hover a field to see where it sits. Colours follow the layers.">
            <div className="overflow-x-auto font-mono text-[12px] leading-[1.7]">
              {hexLines(cur.bytes).map((row) => (
                <div key={row.off} className="flex gap-3 whitespace-nowrap">
                  <span className="w-10 shrink-0 text-nd-faint">{row.off.toString(16).padStart(4, '0')}</span>
                  <span className="flex">
                    {row.bytes.map((x, i) => {
                      const o = row.off + i
                      const inHover = hover && o >= hover.off && o < hover.off + hover.len
                      const li = byteLayer[o]
                      return <span key={i} className={`px-[3px] ${inHover ? 'rounded bg-nd-fg text-nd-bg' : li !== undefined ? LAYER_COLOR[li % LAYER_COLOR.length] : ''} ${i === 7 ? 'mr-2' : ''}`}>{x.toString(16).padStart(2, '0')}</span>
                    })}
                  </span>
                  <span className="text-nd-faint">{row.bytes.map((x) => (x >= 32 && x < 127 ? String.fromCharCode(x) : '·')).join('')}</span>
                </div>
              ))}
            </div>
            {hover && <p className="mt-3 rounded-lg bg-nd-fill px-3 py-2 text-[12.5px] text-nd-fg-3"><b className="text-nd-fg">{hover.name}</b> · bytes {hover.off}–{hover.off + hover.len - 1} · {hover.explain}</p>}
          </Panel>
        </div>
      )}
    </div>
  )
}
