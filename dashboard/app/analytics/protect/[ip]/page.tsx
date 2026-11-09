'use client'
import { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { useParams, useRouter } from 'next/navigation'
import { instantAt, scalar, rangeAbs, toSeries } from '@/lib/prom'
import { usePoll } from '@/hooks/usePoll'
import { fetchAttacks } from '@/lib/attacks'
import { si, pps, bps, duration } from '@/lib/format'
import { Stat, Panel, Badge, Empty } from '@/components/aa/kit'
import { TimeChart } from '@/components/nd/charts'
import { SERIES } from '@/components/nd/ui'
import { useRange, useMe } from '@/components/aa/Shell'
import { CsvButton, PdfButton } from '@/components/aa/export'
import { exportReportsPdf } from '@/lib/report-pdf'
import { downloadCsv } from '@/lib/csv'
import {
  type Svc, type HostMeta, type EditorRef, svcKey, hostKey, fmtSvc, validIp, statusOf, isApplied, fetchLive, notifyProtectChanged,
  useProtect, ServiceEditor, emptyMeta, CLIENT_ID, EditingBadge, reportHref, fmtWhen, NeedsPerm,
} from '@/components/aa/protect'
import { REPORT_KINDS, kindOf, type Report, type ReportKind } from '@/lib/reports'
import {
  Server, Pencil, Check, X, Loader2, AlertTriangle, ShieldOff, ShieldCheck, Lock, Ban, Crosshair, Upload, Download,
  FileText, ScrollText, Send, Trash2, Activity, Fingerprint, ShieldAlert, Info, Plus, ChevronDown, ChevronRight,
} from 'lucide-react'

// One protected host: its nickname + headline statistics, the operator's own
// documentation and log, the allowed services (default-deny), then detailed
// charts. Notes live in protect-meta.json (never touches the dataplane); the
// services edit the protection plan, which the box applies.

// Counter delta over the window that keeps series born inside it.
const delta = (sel: string, R: string) => `clamp_min((sum(${sel}) - sum(${sel} offset ${R})) or sum(${sel}), 0)`
// The per-destination drop map is credited on 1 in 16 drops (dataplane sampling).
const VICTIM_SAMPLE = 16

export default function ProtectedHostPage() {
  const params = useParams<{ ip: string }>()
  const ip = decodeURIComponent(String(params?.ip ?? ''))
  if (!validIp(ip)) {
    return <Empty icon={AlertTriangle} title="Not a valid IPv4 address" hint={<Link href="/analytics/protect" className="underline">Back to Protection</Link>} />
  }
  return <HostView ip={ip} />
}

function HostView({ ip }: { ip: string }) {
  const prot = useProtect()
  const live = usePoll(fetchLive, 10_000)
  const host = prot.hosts.find((h) => h.ip === ip) ?? null
  const iface = host?.iface ?? prot.ingress
  const meta: HostMeta = { ...emptyMeta(), ...prot.meta[ip] }
  const liveSvcs = useMemo(() => {
    for (const i of live.data?.interfaces ?? []) for (const p of i.protected) if (hostKey(i.iface, p.ip) === hostKey(iface, ip)) return new Set(p.services.map(svcKey))
    return undefined
  }, [live.data, iface, ip])
  const applied = !!host && isApplied(host, liveSvcs)
  // Until the first live sample arrives we can't tell live from not-applied.
  const st = live.data ? statusOf(applied, !!liveSvcs) : { label: 'checking…', tone: 'neutral' as const }
  const isMgmt = prot.management.includes(ip)

  if (prot.forbidden) return <Empty icon={Lock} title="You don’t have access to Protection" />

  return (
    <div className="space-y-6">
      <Header ip={ip} meta={meta} host={!!host} iface={iface} st={st} isMgmt={isMgmt} blackholed={!!host && host.services.length === 0} loaded={prot.loaded} />
      <HeadlineStats ip={ip} iface={iface} services={host?.services.length ?? 0} protectedNow={!!host} />

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <ReportsPanel ip={ip} nickname={meta.nickname} reports={meta.reports} presence={prot.presence} />
        <HostLog ip={ip} log={meta.log} />
      </div>

      <Services ip={ip} prot={prot} liveSvcs={liveSvcs} isMgmt={isMgmt} />

      <DetailCharts ip={ip} iface={iface} />
    </div>
  )
}

// ---- header: nickname (editable) + IP + status ---------------------------

async function putMeta(body: Record<string, unknown>): Promise<string | null> {
  try {
    const r = await fetch('/api/protect-meta', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...body, clientId: CLIENT_ID }) })
    if (r.ok) { notifyProtectChanged(); return null }
    const d = await r.json().catch(() => ({}))
    return d?.error || `error ${r.status}`
  } catch { return 'could not reach the server' }
}

function Header({ ip, meta, host, iface, st, isMgmt, blackholed, loaded }: {
  ip: string; meta: HostMeta; host: boolean; iface: string; st: { label: string; tone: any }; isMgmt: boolean; blackholed: boolean; loaded: boolean
}) {
  const canNotes = useMe().can('protect.notes')
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  async function save() {
    setBusy(true); setErr('')
    const e = await putMeta({ ip, nickname: draft })
    setBusy(false)
    if (e) setErr(e)
    else setEditing(false)
  }

  return (
    <div className="rounded-2xl border border-nd-line bg-nd-card p-5 shadow-nd">
      <div className="flex flex-wrap items-start gap-4">
        <span className="grid h-12 w-12 shrink-0 place-items-center rounded-xl bg-nd-fill text-nd-muted"><Server className="h-5 w-5" /></span>
        <div className="min-w-0 flex-1">
          {editing ? (
            <div className="flex flex-wrap items-center gap-2">
              <input autoFocus value={draft} maxLength={40} onChange={(e) => setDraft(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') save(); if (e.key === 'Escape') setEditing(false) }}
                placeholder="Nickname, e.g. Classroom Pi"
                className="w-72 rounded-lg border border-nd-line bg-nd-card px-3 py-1.5 text-[16px] font-semibold text-nd-fg outline-none focus:border-nd-brand" />
              <button onClick={save} disabled={busy} className="inline-flex items-center gap-1 rounded-lg bg-nd-brand px-3 py-1.5 text-[12.5px] font-semibold text-black hover:opacity-90 disabled:opacity-40">
                {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />} Save
              </button>
              <button onClick={() => setEditing(false)} className="grid h-8 w-8 place-items-center rounded-lg border border-nd-line text-nd-muted hover:text-nd-fg"><X className="h-4 w-4" /></button>
            </div>
          ) : (
            <div className="flex flex-wrap items-center gap-2">
              <h2 className={`text-[22px] font-semibold tracking-[-0.02em] ${meta.nickname ? 'text-nd-fg' : 'text-nd-faint'}`}>{meta.nickname || 'No nickname'}</h2>
              {canNotes && <button onClick={() => { setDraft(meta.nickname); setEditing(true); setErr('') }} title="Edit nickname"
                className="grid h-7 w-7 place-items-center rounded-lg text-nd-dim hover:bg-nd-fill hover:text-nd-fg"><Pencil className="h-3.5 w-3.5" /></button>}
            </div>
          )}
          <div className="mt-1 font-mono text-[15px] text-nd-fg-2">{ip}</div>
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            {!loaded ? <div className="aa-skeleton h-5 w-40 rounded-full" /> : host ? (
              <>
                <Badge tone="brand" icon={Server}>{iface}</Badge>
                <Badge tone={st.tone}>{st.label}</Badge>
                {blackholed && <Badge tone="bad" icon={AlertTriangle}>blackholed</Badge>}
              </>
            ) : (
              <Badge tone="warn" icon={ShieldOff}>not protected — all traffic to it passes</Badge>
            )}
            {isMgmt && <Badge tone="warn" icon={ShieldOff}>management</Badge>}
          </div>
          {err && <p className="mt-2 flex items-center gap-1.5 text-[12.5px] text-st-crit-fg"><AlertTriangle className="h-3.5 w-3.5" /> {err}</p>}
        </div>
        <span className="inline-flex flex-wrap gap-2">
          <Link href={`/analytics/audit?q=${encodeURIComponent(ip)}`} title="Everything anyone changed on this host" className="inline-flex items-center gap-1.5 rounded-lg border border-nd-line px-3 py-2 text-[12.5px] font-medium text-nd-fg-3 hover:border-nd-line-strong hover:text-nd-fg">
            <ScrollText className="h-4 w-4" /> Activity
          </Link>
          <Link href={`/analytics/ip?ip=${encodeURIComponent(ip)}`} className="inline-flex items-center gap-1.5 rounded-lg border border-nd-line px-3 py-2 text-[12.5px] font-medium text-nd-fg-3 hover:border-nd-line-strong hover:text-nd-fg">
            <Fingerprint className="h-4 w-4" /> IP lookup
          </Link>
        </span>
      </div>
    </div>
  )
}

function HeadlineStats({ ip, iface, services, protectedNow }: { ip: string; iface: string; services: number; protectedNow: boolean }) {
  const rng = useRange()
  const q = usePoll(async () => {
    const w = rng.resolve()
    const R = `${w.span}s`
    const [vic, tx, rx, deny] = await Promise.all([
      instantAt(delta(`xs_target_packets_total{dst="${ip}"}`, R), w.end),
      instantAt(`sum(increase(xs_talker_tx_bytes_total{ip="${ip}"}[${R}]))`, w.end),
      instantAt(`sum(increase(xs_talker_rx_bytes_total{ip="${ip}"}[${R}]))`, w.end),
      instantAt(`sum(increase(xs_service_packets_total{iface="${iface}",event="deny"}[${R}]))`, w.end),
    ])
    return { vic: (scalar(vic, 0) ?? 0) * VICTIM_SAMPLE, tx: scalar(tx, 0) ?? 0, rx: scalar(rx, 0) ?? 0, deny: scalar(deny, 0) ?? 0, span: w.span }
  }, rng.refreshMs, [ip, iface, rng.key])
  const d = q.data
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-5">
      <Stat label="Dropped, aimed at it" icon={Crosshair} loading={!d} value={si(d?.vic)} sub="attack packets · estimated" color="var(--s2)" />
      <Stat label="Sent" icon={Upload} loading={!d} value={si(d?.tx, 'B')} sub={d ? `avg ${bps((d.tx * 8) / d.span)}` : undefined} color="var(--s1)" />
      <Stat label="Received" icon={Download} loading={!d} value={si(d?.rx, 'B')} sub={d ? `avg ${bps((d.rx * 8) / d.span)}` : undefined} color="var(--s4)" />
      <Stat label="Allowed services" icon={Lock} value={protectedNow ? services : '—'} sub={protectedNow ? 'everything else is dropped' : 'not protected'} color="var(--s3)" />
      <Stat label="Denied on interface" icon={Ban} loading={!d} value={si(d?.deny)} sub={`all protected hosts on ${iface}`} color="var(--s5, var(--s2))" />
    </div>
  )
}

// ---- documentation + log -------------------------------------------------

// The host's reports: a list (newest activity first) with type, status, who
// edited last and who is editing right now; "New report" creates one from a
// template and opens it on its own page.
function ReportsPanel({ ip, nickname, reports, presence }: { ip: string; nickname: string; reports: Report[]; presence: Record<string, EditorRef[]> }) {
  const me = useMe()
  const canWrite = me.can('protect.reports')
  const router = useRouter()
  const [menu, setMenu] = useState(false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const sorted = [...reports].sort((a, b) => b.updatedAt - a.updatedAt)

  async function create(kind: ReportKind) {
    setBusy(true); setErr('')
    try {
      const r = await fetch('/api/protect-meta/reports', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ip, kind, clientId: CLIENT_ID }) })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) { setErr(d?.error || `error ${r.status}`); setBusy(false); return }
      router.push(`${reportHref(ip, d.report.id)}?edit=1`)
    } catch { setErr('could not reach the server'); setBusy(false) }
  }

  return (
    <Panel icon={FileText} title="Reports" sub="setup sheets, incidents, maintenance and audits for this host"
      // Lift above the panels below while the menu is open (each panel animates in
      // its own stacking context, which would otherwise paint over the menu).
      className={menu ? 'relative z-20' : ''}
      actions={<span className="inline-flex items-center gap-1.5">
        <PdfButton label="PDF" disabled={!reports.length} title="All reports for this host in one PDF"
          onClick={() => exportReportsPdf([...reports].sort((a, b) => b.updatedAt - a.updatedAt), { ip, nickname }, me.me?.username ?? '')} />
        <CsvButton label="CSV" disabled={!reports.length} onClick={() => downloadCsv(`reports-${ip}`,
          reports.flatMap((r) => r.sections.map((s, i) => ({ r, s, n: i + 1 }))), [
            { key: 'host', label: 'host', get: () => ip },
            { key: 'report', label: 'report', get: (x) => x.r.title }, { key: 'kind', label: 'type', get: (x) => kindOf(x.r.kind).label },
            { key: 'status', label: 'status', get: (x) => x.r.status },
            { key: 'updatedBy', label: 'last edited by', get: (x) => x.r.updatedBy }, { key: 'updatedAt', label: 'last edited (UTC)', get: (x) => new Date(x.r.updatedAt * 1000).toISOString() },
            { key: 'n', label: 'section #' }, { key: 'heading', label: 'section', get: (x) => x.s.heading }, { key: 'body', label: 'text', get: (x) => x.s.body },
          ], `all ${reports.length} report${reports.length === 1 ? '' : 's'} for ${ip}`, `host:${ip}`)} />
        {!canWrite ? <NeedsPerm label="Write reports" /> :
        <div className="relative">
          <button onClick={() => setMenu((v) => !v)} disabled={busy}
            className="inline-flex items-center gap-1 rounded-lg bg-nd-brand px-2.5 py-1.5 text-[12px] font-semibold text-black hover:opacity-90 disabled:opacity-40">
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />} New report <ChevronDown className="h-3.5 w-3.5" />
          </button>
          {menu && (
            <>
              <button aria-label="Close menu" className="fixed inset-0 z-30 cursor-default" onClick={() => setMenu(false)} />
              <ul className="aa-in absolute right-0 top-[calc(100%+6px)] z-40 w-72 overflow-hidden rounded-xl border border-nd-line bg-nd-card p-1 shadow-nd-lg">
                {REPORT_KINDS.map((k) => (
                  <li key={k.id}>
                    <button onClick={() => { setMenu(false); create(k.id) }} className="flex w-full flex-col rounded-lg px-3 py-2 text-left hover:bg-nd-fill">
                      <span className="text-[13px] font-medium text-nd-fg">{k.label}</span>
                      <span className="text-[11.5px] text-nd-dim">{k.hint}</span>
                    </button>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>}
      </span>}
    >
      {err && <p className="mb-2 flex items-center gap-1.5 text-[12.5px] text-st-crit-fg"><AlertTriangle className="h-3.5 w-3.5" /> {err}</p>}
      {sorted.length === 0 ? (
        <Empty icon={FileText} title="No reports yet" hint="Create a setup report to document what runs on this host." className="py-6" />
      ) : (
        <ul className="max-h-[420px] divide-y divide-nd-line overflow-y-auto rounded-xl border border-nd-line">
          {sorted.map((r) => {
            const editing = (presence[`${ip}#${r.id}`] ?? []).filter((e) => e.clientId !== CLIENT_ID)
            const filled = r.sections.filter((s) => s.body.trim()).length
            return (
              <li key={r.id}>
                <Link href={reportHref(ip, r.id)} className="group flex items-center gap-3 px-3.5 py-3 transition-colors hover:bg-nd-fill">
                  <FileText className="h-4 w-4 shrink-0 text-nd-dim" />
                  <span className="min-w-0 flex-1">
                    <span className="flex flex-wrap items-center gap-1.5">
                      <span className="truncate text-[13.5px] font-medium text-nd-fg">{r.title}</span>
                      <Badge>{kindOf(r.kind).label}</Badge>
                      <Badge tone={r.status === 'final' ? 'good' : 'neutral'}>{r.status}</Badge>
                      <EditingBadge editors={editing} />
                    </span>
                    <span className="mt-0.5 block text-[11.5px] text-nd-dim">
                      {filled}/{r.sections.length} sections filled · edited by {r.updatedBy || 'admin'} · {fmtWhen(r.updatedAt)}
                    </span>
                  </span>
                  <ChevronRight className="h-4 w-4 shrink-0 text-nd-faint" />
                </Link>
              </li>
            )
          })}
        </ul>
      )}
    </Panel>
  )
}

function HostLog({ ip, log }: { ip: string; log: HostMeta['log'] }) {
  const me = useMe()
  const canNotes = me.can('protect.notes')
  const canDelete = me.can('protect.delete')
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [confirm, setConfirm] = useState<string | null>(null)

  async function add() {
    if (!text.trim()) return
    setBusy(true); setErr('')
    try {
      const r = await fetch('/api/protect-meta', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ip, text, clientId: CLIENT_ID }) })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) setErr(d?.error || `error ${r.status}`)
      else { setText(''); notifyProtectChanged() }
    } catch { setErr('could not reach the server') }
    setBusy(false)
  }
  async function remove(id: string) {
    setErr('')
    try {
      const r = await fetch(`/api/protect-meta?ip=${encodeURIComponent(ip)}&id=${encodeURIComponent(id)}&clientId=${CLIENT_ID}`, { method: 'DELETE' })
      if (!r.ok) setErr(`error ${r.status}`)
      else notifyProtectChanged()
    } catch { setErr('could not reach the server') }
    setConfirm(null)
  }
  const fmt = (ts: number) => new Date(ts * 1000).toLocaleString([], { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })

  return (
    <Panel icon={ScrollText} title="Log" sub="dated notes — changes, incidents, what you did" actions={<span className="inline-flex items-center gap-1.5">
      <CsvButton label="Export" disabled={!log.length} onClick={() => downloadCsv(`log-${ip}`, log, [
        { key: 'host', label: 'host', get: () => ip }, { key: 'ts', label: 'time (UTC)', get: (e) => new Date(e.ts * 1000).toISOString() },
        { key: 'author', label: 'author' }, { key: 'text', label: 'entry' },
      ], `${log.length} log entr${log.length === 1 ? 'y' : 'ies'} for ${ip}`, `host:${ip}`)} />
      {!canNotes && <NeedsPerm label="Edit nicknames & log" />}
    </span>}>
      {canNotes && <div className="flex items-start gap-2">
        <textarea value={text} onChange={(e) => setText(e.target.value)} maxLength={2000} rows={2}
          onKeyDown={(e) => { if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) add() }}
          placeholder="e.g. Removed from plan — Twingate replies were being denied"
          className="min-h-[42px] flex-1 resize-y rounded-xl border border-nd-line bg-nd-card px-3 py-2 text-[13px] text-nd-fg outline-none focus:border-nd-brand" />
        <button onClick={add} disabled={busy || !text.trim()} title="Add entry (Ctrl/⌘+Enter)"
          className="inline-flex h-[42px] items-center gap-1.5 rounded-lg bg-nd-brand px-3 text-[12.5px] font-semibold text-black hover:opacity-90 disabled:opacity-40">
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />} Add
        </button>
      </div>}
      {err && <p className="mt-2 flex items-center gap-1.5 text-[12.5px] text-st-crit-fg"><AlertTriangle className="h-3.5 w-3.5" /> {err}</p>}
      {log.length === 0 ? (
        <Empty icon={ScrollText} title="No log entries yet" className="py-6" />
      ) : (
        <ol className="mt-4 max-h-[360px] space-y-2 overflow-y-auto pr-1">
          {log.map((e) => (
            <li key={e.id} className="group rounded-xl border border-nd-line bg-nd-panel px-3.5 py-2.5">
              <div className="flex items-center gap-2 text-[11.5px] text-nd-dim">
                <span className="font-medium text-nd-fg-3">{e.author}</span>
                <span>·</span>
                <span>{fmt(e.ts)}</span>
                <span className="ml-auto">
                  {confirm === e.id ? (
                    <span className="inline-flex items-center gap-1">
                      <button onClick={() => remove(e.id)} className="rounded-md bg-st-crit px-2 py-0.5 text-[11px] font-medium text-white">delete</button>
                      <button onClick={() => setConfirm(null)} className="grid h-5 w-5 place-items-center rounded-md text-nd-faint hover:text-nd-fg"><X className="h-3 w-3" /></button>
                    </span>
                  ) : canDelete && (
                    <button onClick={() => setConfirm(e.id)} title="Delete entry" className="grid h-5 w-5 place-items-center rounded-md text-nd-faint opacity-0 transition-opacity hover:text-st-crit-fg group-hover:opacity-100"><Trash2 className="h-3 w-3" /></button>
                  )}
                </span>
              </div>
              <p className="mt-1 whitespace-pre-wrap break-words text-[13px] text-nd-fg-2">{e.text}</p>
            </li>
          ))}
        </ol>
      )}
    </Panel>
  )
}

// ---- allowed services (edits the protection plan) ------------------------

function Services({ ip, prot, liveSvcs, isMgmt }: {
  ip: string; prot: ReturnType<typeof useProtect>; liveSvcs?: Set<string>; isMgmt: boolean
}) {
  const canPlan = useMe().can('protect.plan')
  const router = useRouter()
  const host = prot.hosts.find((h) => h.ip === ip) ?? null
  const savedSvcs = useMemo(() => host?.services ?? [], [host])
  const [svcs, setSvcs] = useState<Svc[]>(savedSvcs)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')
  const [confirmDel, setConfirmDel] = useState(false)
  const savedJson = JSON.stringify(savedSvcs)
  useEffect(() => { setSvcs(JSON.parse(savedJson)) }, [savedJson])
  const dirty = JSON.stringify(svcs) !== savedJson

  // Save against a FRESH copy of the plan so edits made elsewhere aren't lost.
  async function putPlan(mutate: (hosts: { iface: string; ip: string; services: Svc[] }[]) => { iface: string; ip: string; services: Svc[] }[], msg: string) {
    setBusy(true); setErr(''); setOk('')
    try {
      const cur = await fetch('/api/protect-plan', { cache: 'no-store' }).then((r) => r.json())
      const hosts = mutate((cur?.plan?.hosts ?? []).map((h: any) => ({ iface: h.iface, ip: h.ip, services: h.services ?? [] })))
      const r = await fetch('/api/protect-plan', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ hosts }) })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) setErr(d?.error || `error ${r.status}`)
      else { setOk(msg); notifyProtectChanged() }
    } catch { setErr('could not reach the server') }
    setBusy(false)
  }
  const save = () => putPlan((hs) => hs.map((h) => (h.ip === ip ? { ...h, services: svcs } : h)), 'Saved — the box is applying it; live state refreshes in a few seconds.')
  const protect = () => putPlan((hs) => [...hs.filter((h) => h.ip !== ip), { iface: prot.ingress, ip, services: svcs }], 'Protected — the box is applying it.')
  const unprotect = () => putPlan((hs) => hs.filter((h) => h.ip !== ip), 'Unprotected — all traffic to this host now passes. Its notes are kept.').then(() => setConfirmDel(false))

  const lockedKey = (k: string) => isMgmt && prot.lifeline.some((l) => svcKey(l) === k)

  return (
    <Panel icon={Lock} title="Allowed services"
      sub={host ? `default-deny on ${host.iface} — only these reach the host; everything else is dropped` : 'this host is not protected — choose its services, then protect it'}
      actions={!canPlan ? <NeedsPerm label="Edit protected hosts & ports" /> : host ? (
        <span className="inline-flex items-center gap-1.5">
          {dirty && <span className="text-[12px] text-st-warn-fg">unsaved</span>}
          <button onClick={save} disabled={busy || !dirty} className="inline-flex items-center gap-1 rounded-lg bg-nd-brand px-2.5 py-1.5 text-[12px] font-semibold text-black hover:opacity-90 disabled:opacity-40">
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />} Save &amp; apply
          </button>
          {confirmDel ? (
            <>
              <button onClick={unprotect} disabled={busy} className="rounded-lg bg-st-crit px-2.5 py-1.5 text-[12px] font-medium text-white hover:opacity-90">unprotect host</button>
              <button onClick={() => setConfirmDel(false)} className="grid h-7 w-7 place-items-center rounded-lg border border-nd-line text-nd-muted hover:text-nd-fg"><X className="h-3.5 w-3.5" /></button>
            </>
          ) : (
            <button onClick={() => setConfirmDel(true)} className="inline-flex items-center gap-1 rounded-lg border border-nd-line px-2.5 py-1.5 text-[12px] font-medium text-st-crit-fg hover:border-st-crit/40"><Trash2 className="h-3.5 w-3.5" /> Unprotect</button>
          )}
        </span>
      ) : (
        <button onClick={protect} disabled={busy || svcs.length === 0} title={svcs.length === 0 ? 'add at least one service first' : undefined}
          className="inline-flex items-center gap-1 rounded-lg bg-nd-brand px-2.5 py-1.5 text-[12px] font-semibold text-black hover:opacity-90 disabled:opacity-40">
          {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />} Protect host
        </button>
      )}
    >
      <ServiceEditor
        services={svcs}
        onAdd={(s) => setSvcs((cur) => (cur.some((e) => svcKey(e) === svcKey(s)) ? cur : [...cur, s]))}
        onRemove={(k) => setSvcs((cur) => cur.filter((e) => svcKey(e) !== k))}
        toneFor={host ? (s) => (liveSvcs ? (liveSvcs.has(svcKey(s)) ? 'good' : 'warn') : null) : undefined}
        lockedKey={lockedKey}
        readOnly={!canPlan}
      />
      {host && svcs.length === 0 && <p className="mt-2 flex items-center gap-1 text-[11.5px] text-st-crit-fg"><AlertTriangle className="h-3 w-3" /> No services — this host is fully blackholed until you add one.</p>}
      {isMgmt && <p className="mt-2 flex items-start gap-1 text-[11.5px] text-st-warn-fg"><ShieldOff className="mt-0.5 h-3 w-3 shrink-0" /> Management IP — its lifeline ({prot.lifeline.map(fmtSvc).join(', ') || '—'}) is kept open automatically and can’t be removed.</p>}
      <p className="mt-2 flex items-start gap-1 text-[11px] text-nd-faint"><Info className="mt-0.5 h-3 w-3 shrink-0" /> Replies to connections the host opens itself (e.g. Twingate) are not affected by this list.</p>
      {err && <p className="mt-2 flex items-center gap-1.5 text-[12.5px] text-st-crit-fg"><AlertTriangle className="h-3.5 w-3.5" /> {err}</p>}
      {ok && <p className="mt-2 flex items-center gap-1.5 text-[12.5px] text-st-good-fg"><Check className="h-3.5 w-3.5" /> {ok} {!host && <button onClick={() => router.refresh()} className="underline">refresh</button>}</p>}
    </Panel>
  )
}

// ---- detailed statistics -------------------------------------------------

function DetailCharts({ ip, iface }: { ip: string; iface: string }) {
  const rng = useRange()
  const hist = usePoll(fetchAttacks, 120_000)
  const q = usePoll(async () => {
    const w = rng.resolve()
    const [tx, rx, vic, att, dn, vd] = await Promise.all([
      rangeAbs(`sum(rate(xs_talker_tx_bytes_total{ip="${ip}"}[${w.rw}]))*8`, w.start, w.end, w.step),
      rangeAbs(`sum(rate(xs_talker_rx_bytes_total{ip="${ip}"}[${w.rw}]))*8`, w.start, w.end, w.step),
      rangeAbs(`sum(rate(xs_target_packets_total{dst="${ip}"}[${w.rw}]))*${VICTIM_SAMPLE}`, w.start, w.end, w.step),
      rangeAbs(`sum(rate(xs_attacker_packets_total{src="${ip}"}[${w.rw}]))*${VICTIM_SAMPLE}`, w.start, w.end, w.step),
      rangeAbs(`sum(rate(xs_service_packets_total{iface="${iface}",event="deny"}[${w.rw}]))`, w.start, w.end, w.step),
      rangeAbs(`sum by(verdict)(rate(xs_verdict_packets_total{iface="${iface}",verdict=~"pass|drop"}[${w.rw}]))`, w.start, w.end, w.step),
    ])
    const tag = (r: typeof tx, k: string) => r.map((s) => ({ metric: { k }, values: s.values }))
    return {
      bw: toSeries([...tag(tx, 'sent'), ...tag(rx, 'received')], (m) => m.k),
      drops: toSeries([...tag(vic, 'as_target'), ...tag(att, 'as_source')], (m) => m.k),
      deny: toSeries(dn, () => 'deny'),
      verdict: toSeries(vd, (m) => m.verdict ?? 'drop'),
      spanMs: w.span * 1000,
    }
  }, rng.refreshMs, [ip, iface, rng.key])
  const d = q.data
  const spanMs = d?.spanMs ?? 3_600_000
  const episodes = (hist.data?.attacks ?? []).filter((a) => a.attackers.some((x) => x.ip === ip) || a.victims.some((x) => x.ip === ip))

  return (
    <>
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <Panel icon={Activity} title="Bandwidth" sub="traffic to and from this host · bits per second">
          <TimeChart loading={!d} data={d?.bw ?? []} series={[{ key: 'sent', label: 'Sent', color: SERIES[0] }, { key: 'received', label: 'Received', color: SERIES[3] }]} yfmt={bps} spanMs={spanMs} height={200} />
        </Panel>
        <Panel icon={Crosshair} title="Dropped packets for this host" sub="attack traffic aimed at it, or sent from it · per second (estimated)">
          <TimeChart loading={!d} data={d?.drops ?? []} series={[{ key: 'as_target', label: 'Aimed at it', color: SERIES[1] }, { key: 'as_source', label: 'Sent from it', color: SERIES[4] }]} yfmt={pps} spanMs={spanMs} height={200} />
        </Panel>
        <Panel icon={Ban} title="Service-allowlist denials" sub={`all protected hosts on ${iface} · per second`}>
          <TimeChart loading={!d} data={d?.deny ?? []} series={[{ key: 'deny', label: 'Denied', color: SERIES[1] }]} yfmt={pps} spanMs={spanMs} height={200} />
        </Panel>
        <Panel icon={ShieldCheck} title="Passed vs dropped" sub={`every packet on ${iface} · per second`}>
          <TimeChart loading={!d} data={d?.verdict ?? []} series={[{ key: 'pass', label: 'Passed', color: SERIES[2] }, { key: 'drop', label: 'Dropped', color: SERIES[1] }]} yfmt={pps} spanMs={spanMs} height={200} />
        </Panel>
      </div>
      <Panel icon={ShieldAlert} title="Attack episodes involving this host" sub="from the Attacks history">
        {!hist.data ? (
          <div className="space-y-1.5">{[0, 1].map((i) => <div key={i} className="aa-skeleton h-9 rounded-lg" />)}</div>
        ) : episodes.length === 0 ? (
          <Empty icon={ShieldAlert} title="No attack episodes involved this host" className="py-6" />
        ) : (
          <ul className="divide-y divide-nd-line overflow-hidden rounded-xl border border-nd-line">
            {episodes.slice(0, 20).map((a) => (
              <li key={a.id} className="flex flex-wrap items-center gap-3 px-3.5 py-2.5 text-[12.5px]">
                <Badge tone="bad">{a.vectors[0] ?? 'attack'}</Badge>
                <span className="text-nd-fg-3">{new Date(a.start).toLocaleString()}</span>
                <span className="text-nd-dim">{duration(a.durationSec)} · peak {pps(a.peakPps)} · {Math.round(a.dropShare * 100)}% dropped</span>
                <span className="ml-auto text-nd-dim">{a.victims.some((x) => x.ip === ip) ? 'target' : 'source'}</span>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </>
  )
}
