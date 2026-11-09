'use client'
import { useEffect, useState } from 'react'
import Link from 'next/link'
import { useParams, useRouter, useSearchParams } from 'next/navigation'
import { Badge, Empty } from '@/components/aa/kit'
import { useMe } from '@/components/aa/Shell'
import { CsvButton, PdfButton } from '@/components/aa/export'
import { exportReportsPdf } from '@/lib/report-pdf'
import { downloadCsv } from '@/lib/csv'
import {
  useProtect, CLIENT_ID, EditingBadge, useEditingPresence, hostHref, fmtWhen, validIp, emptyMeta, NeedsPerm,
} from '@/components/aa/protect'
import {
  REPORT_KINDS, kindOf, editOf, type Report, type ReportEdit, type ReportKind, type FieldConflict,
} from '@/lib/reports'
import {
  FileText, Pencil, Check, X, Loader2, AlertTriangle, Printer, Trash2, ArrowUp, ArrowDown, Plus, GitMerge,
  Eye, EyeOff, ArrowLeft, CheckCircle2, CircleDashed, Server,
} from 'lucide-react'

// One report, on its own page. Reads like a document; Edit turns every part
// (title, type, status, sections) editable. Saves are revision-checked: if
// someone else saved meanwhile, the server merges per field and per section,
// and anything both of you changed comes back for you to resolve — nothing is
// ever silently overwritten. Other editors and their saves show up live.

const CONFLICT_START = '<<<<<<< your version'
const CONFLICT_END = '>>>>>>> their version'
const newSectionId = () => `s${Math.random().toString(36).slice(2, 10)}${Date.now().toString(36).slice(-4)}`
const hasMarkers = (e: ReportEdit) => e.sections.some((s) => s.body.includes(CONFLICT_START) || s.body.includes(CONFLICT_END))

export default function ReportPage() {
  const params = useParams<{ ip: string; id: string }>()
  const ip = decodeURIComponent(String(params?.ip ?? ''))
  const id = decodeURIComponent(String(params?.id ?? ''))
  if (!validIp(ip)) return <Empty icon={AlertTriangle} title="Not a valid IPv4 address" />
  return <ReportView ip={ip} id={id} />
}

function ReportView({ ip, id }: { ip: string; id: string }) {
  const router = useRouter()
  const search = useSearchParams()
  const prot = useProtect()
  const access = useMe()
  const canWrite = access.can('protect.reports')
  const canDelete = access.can('protect.delete')
  const meta = { ...emptyMeta(), ...prot.meta[ip] }
  const report = meta.reports.find((r) => r.id === id) ?? null
  const hostName = meta.nickname || ip
  const editors = (prot.presence[`${ip}#${id}`] ?? []).filter((e) => e.clientId !== CLIENT_ID)

  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState<ReportEdit | null>(null)
  const [base, setBase] = useState<{ edit: ReportEdit; rev: number } | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [note, setNote] = useState('')
  const [conflicts, setConflicts] = useState<{ fields: FieldConflict[]; text: number; by: string } | null>(null)
  const [showTheirs, setShowTheirs] = useState(false)
  const [confirmDel, setConfirmDel] = useState(false)

  useEditingPresence(editing, ip, id)

  function startEdit(r: Report) {
    const e = editOf(r)
    setDraft(e); setBase({ edit: editOf(r), rev: r.rev })
    setErr(''); setConflicts(null); setShowTheirs(false); setEditing(true)
  }
  // ?edit=1 (a freshly created report) opens straight into the editor.
  useEffect(() => {
    if (report && canWrite && search.get('edit') === '1' && !editing && !draft) {
      startEdit(report)
      router.replace(window.location.pathname)
    }
  }, [report]) // eslint-disable-line react-hooks/exhaustive-deps

  const dirty = editing && !!draft && !!base && JSON.stringify(draft) !== JSON.stringify(base.edit)
  useEffect(() => {
    if (!dirty) return
    const warn = (e: BeforeUnloadEvent) => { e.preventDefault(); e.returnValue = '' }
    window.addEventListener('beforeunload', warn)
    return () => window.removeEventListener('beforeunload', warn)
  }, [dirty])
  useEffect(() => { if (!note) return; const t = setTimeout(() => setNote(''), 8000); return () => clearTimeout(t) }, [note])

  async function put(edit: ReportEdit, b: { edit: ReportEdit; rev: number }) {
    const r = await fetch('/api/protect-meta/reports', {
      method: 'PUT', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ip, id, report: edit, base: b.edit, baseRev: b.rev, clientId: CLIENT_ID }),
    })
    return { r, d: await r.json().catch(() => ({})) }
  }

  async function save() {
    if (!draft || !base) return
    if (conflicts?.fields.length) { setErr('Choose a version for each highlighted field first.'); return }
    if (hasMarkers(draft)) { setErr('Resolve the marked text first: keep what you want and delete the <<<<<<< / ======= / >>>>>>> lines.'); return }
    setBusy(true); setErr('')
    const otherBy = report?.updatedBy || 'another editor'
    try {
      const { r, d } = await put(draft, base)
      if (r.status === 409 && d?.error === 'conflict') {
        // Rebase onto their version: the merged result becomes the draft, and
        // the next save (after resolving) goes straight through.
        setDraft(d.merged)
        setBase({ edit: editOf(d.current), rev: d.current.rev })
        setConflicts({ fields: d.fieldConflicts || [], text: d.textConflicts || 0, by: d.current.updatedBy || 'someone' })
      } else if (!r.ok) {
        setErr(d?.error || `error ${r.status}`)
      } else {
        setEditing(false); setDraft(null); setBase(null); setConflicts(null)
        if (d.merged) setNote(`Saved — merged with ${otherBy}’s changes.`)
      }
    } catch { setErr('could not reach the server') }
    setBusy(false)
  }

  // Quick status flip from view mode (same revision-checked save path).
  async function setStatus(status: 'draft' | 'final') {
    if (!report) return
    setBusy(true); setErr('')
    try {
      const b = { edit: editOf(report), rev: report.rev }
      const { r, d } = await put({ ...editOf(report), status }, b)
      if (!r.ok) setErr(d?.error === 'conflict' ? 'Someone changed the status at the same time — try again.' : d?.error || `error ${r.status}`)
    } catch { setErr('could not reach the server') }
    setBusy(false)
  }

  async function remove() {
    setBusy(true)
    try {
      const r = await fetch(`/api/protect-meta/reports?ip=${encodeURIComponent(ip)}&id=${encodeURIComponent(id)}&clientId=${CLIENT_ID}`, { method: 'DELETE' })
      if (r.ok) { router.push(hostHref(ip)); return }
      setErr(`error ${r.status}`)
    } catch { setErr('could not reach the server') }
    setBusy(false)
  }

  if (prot.forbidden) return <Empty icon={AlertTriangle} title="You don’t have access to Protection" />
  if (!prot.loaded) return <div className="space-y-3">{[0, 1, 2].map((i) => <div key={i} className="aa-skeleton h-24 rounded-2xl" />)}</div>
  if (!report) {
    return (
      <Empty icon={FileText} title="This report doesn’t exist (it may have been deleted)"
        hint={<Link href={hostHref(ip)} className="underline">Back to {hostName}</Link>} />
    )
  }

  const newerSaved = editing && !!base && report.rev !== base.rev && !conflicts
  const k = kindOf(report.kind)

  return (
    <div className="mx-auto max-w-[920px] space-y-4">
      {/* toolbar */}
      <div className="flex flex-wrap items-center gap-2 print:hidden">
        <Link href={hostHref(ip)} className="inline-flex items-center gap-1.5 rounded-lg px-2 py-1.5 text-[12.5px] text-nd-dim hover:bg-nd-fill hover:text-nd-fg">
          <ArrowLeft className="h-4 w-4" /> {hostName}
        </Link>
        <span className="ml-auto inline-flex flex-wrap items-center gap-1.5">
          <EditingBadge editors={editors} />
          {editing ? (
            <>
              {dirty && <span className="text-[12px] text-st-warn-fg">unsaved</span>}
              <button onClick={save} disabled={busy} className="inline-flex items-center gap-1 rounded-lg bg-nd-brand px-3 py-1.5 text-[12.5px] font-semibold text-black hover:opacity-90 disabled:opacity-40">
                {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />} Save
              </button>
              <button onClick={() => { setEditing(false); setDraft(null); setBase(null); setConflicts(null); setErr('') }}
                className="inline-flex items-center gap-1 rounded-lg border border-nd-line px-3 py-1.5 text-[12.5px] text-nd-fg-3 hover:text-nd-fg"><X className="h-3.5 w-3.5" /> Cancel</button>
            </>
          ) : (
            <>
              {!canWrite && <NeedsPerm label="Write reports" />}
              {canWrite && <button onClick={() => startEdit(report)} className="inline-flex items-center gap-1 rounded-lg bg-nd-brand px-3 py-1.5 text-[12.5px] font-semibold text-black hover:opacity-90"><Pencil className="h-3.5 w-3.5" /> Edit</button>}
              {!canWrite ? null : report.status === 'draft' ? (
                <button onClick={() => setStatus('final')} disabled={busy} className="inline-flex items-center gap-1 rounded-lg border border-nd-line px-3 py-1.5 text-[12.5px] text-nd-fg-3 hover:text-nd-fg"><CheckCircle2 className="h-3.5 w-3.5" /> Mark final</button>
              ) : (
                <button onClick={() => setStatus('draft')} disabled={busy} className="inline-flex items-center gap-1 rounded-lg border border-nd-line px-3 py-1.5 text-[12.5px] text-nd-fg-3 hover:text-nd-fg"><CircleDashed className="h-3.5 w-3.5" /> Back to draft</button>
              )}
              <PdfButton onClick={() => exportReportsPdf([report], { ip, nickname: meta.nickname }, access.me?.username ?? '')} />
              <CsvButton onClick={() => downloadCsv(`report-${hostName}-${report.title}`, report.sections.map((s, i) => ({ ...s, n: i + 1 })), [
                { key: 'host', label: 'host', get: () => ip }, { key: 'nickname', label: 'nickname', get: () => meta.nickname },
                { key: 'title', label: 'report', get: () => report.title }, { key: 'kind', label: 'type', get: () => kindOf(report.kind).label },
                { key: 'status', label: 'status', get: () => report.status },
                { key: 'createdBy', label: 'created by', get: () => report.createdBy }, { key: 'createdAt', label: 'created (UTC)', get: () => new Date(report.createdAt * 1000).toISOString() },
                { key: 'updatedBy', label: 'last edited by', get: () => report.updatedBy }, { key: 'updatedAt', label: 'last edited (UTC)', get: () => new Date(report.updatedAt * 1000).toISOString() },
                { key: 'n', label: 'section #' }, { key: 'heading', label: 'section' }, { key: 'body', label: 'text' },
              ], `report “${report.title}” for ${ip}`, `report:${ip}/${report.id}`)} />
              <button onClick={() => window.print()} className="inline-flex items-center gap-1 rounded-lg border border-nd-line px-3 py-1.5 text-[12.5px] text-nd-fg-3 hover:text-nd-fg"><Printer className="h-3.5 w-3.5" /> Print</button>
              {!canDelete ? null : confirmDel ? (
                <>
                  <button onClick={remove} disabled={busy} className="rounded-lg bg-st-crit px-3 py-1.5 text-[12.5px] font-medium text-white hover:opacity-90">Delete report</button>
                  <button onClick={() => setConfirmDel(false)} className="grid h-8 w-8 place-items-center rounded-lg border border-nd-line text-nd-muted hover:text-nd-fg"><X className="h-3.5 w-3.5" /></button>
                </>
              ) : (
                <button onClick={() => setConfirmDel(true)} title="Delete report" className="grid h-8 w-8 place-items-center rounded-lg border border-nd-line text-st-crit-fg hover:border-st-crit/40"><Trash2 className="h-3.5 w-3.5" /></button>
              )}
            </>
          )}
        </span>
      </div>

      {/* notices */}
      {conflicts && (conflicts.text > 0 || conflicts.fields.length > 0) && (
        <div className="flex items-start gap-2 rounded-xl border border-st-warn/30 bg-st-warn/[0.06] px-4 py-3 text-[12.5px] text-st-warn-fg print:hidden">
          <GitMerge className="mt-0.5 h-4 w-4 shrink-0" />
          <span>
            {conflicts.by} changed the same parts while you were editing. Nothing was lost — everything that didn’t overlap is already merged.
            {conflicts.fields.length > 0 && ' Pick a version for each highlighted field below.'}
            {conflicts.text > 0 && <> Sections marked below contain both versions between <code className="mx-0.5 rounded bg-nd-fill px-1">&lt;&lt;&lt;&lt;&lt;&lt;&lt;</code> and <code className="mx-0.5 rounded bg-nd-fill px-1">&gt;&gt;&gt;&gt;&gt;&gt;&gt;</code> — keep what you want and delete the marker lines.</>}
            {' '}Then Save.
          </span>
        </div>
      )}
      {newerSaved && (
        <div className="flex flex-wrap items-center gap-2 rounded-xl border border-nd-line bg-nd-panel px-4 py-2.5 text-[12.5px] text-nd-fg-3 print:hidden">
          <GitMerge className="h-4 w-4 shrink-0 text-nd-brand" />
          <span className="flex-1">{report.updatedBy || 'Someone'} saved a newer version at {fmtWhen(report.updatedAt)}. Your changes will be merged with theirs when you save.</span>
          <button onClick={() => setShowTheirs((v) => !v)} className="inline-flex items-center gap-1 rounded-lg border border-nd-line px-2 py-1 text-[11.5px] hover:text-nd-fg">
            {showTheirs ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />} {showTheirs ? 'Hide' : 'Show'} their version
          </button>
        </div>
      )}
      {note && <p className="flex items-center gap-1.5 text-[12.5px] text-st-good-fg print:hidden"><GitMerge className="h-3.5 w-3.5" /> {note}</p>}
      {err && <p className="flex items-center gap-1.5 text-[12.5px] text-st-crit-fg print:hidden"><AlertTriangle className="h-3.5 w-3.5" /> {err}</p>}

      {editing && draft ? (
        <>
          {showTheirs && newerSaved && <ReadOnlyReport report={report} hostName={hostName} ip={ip} dimmed />}
          <ReportEditor draft={draft} setDraft={setDraft} conflicts={conflicts?.fields ?? []}
            resolveField={(c, v) => {
              setDraft((d) => {
                if (!d) return d
                if (c.field === 'heading') return { ...d, sections: d.sections.map((s) => (s.id === c.sectionId ? { ...s, heading: v } : s)) }
                return { ...d, [c.field]: v } as ReportEdit
              })
              setConflicts((x) => (x ? { ...x, fields: x.fields.filter((f) => f !== c) } : x))
              setErr('')
            }} />
        </>
      ) : (
        <ReadOnlyReport report={report} hostName={hostName} ip={ip} kindLabel={k.label} />
      )}
    </div>
  )
}

// ---- view ----------------------------------------------------------------

function ReadOnlyReport({ report, hostName, ip, dimmed }: { report: Report; hostName: string; ip: string; kindLabel?: string; dimmed?: boolean }) {
  return (
    <article className={`rounded-2xl border bg-nd-card px-8 py-7 shadow-nd print:border-0 print:px-0 print:shadow-none ${dimmed ? 'border-dashed border-nd-line opacity-80' : 'border-nd-line'}`}>
      {dimmed && <p className="mb-3 text-[11.5px] font-medium uppercase tracking-[0.08em] text-nd-faint">Their saved version</p>}
      <div className="flex flex-wrap items-center gap-1.5">
        <Badge tone="brand" icon={FileText}>{kindOf(report.kind).label} report</Badge>
        <Badge tone={report.status === 'final' ? 'good' : 'neutral'}>{report.status}</Badge>
      </div>
      <h2 className="mt-3 text-[26px] font-semibold leading-tight tracking-[-0.02em] text-nd-fg">{report.title}</h2>
      <p className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[12.5px] text-nd-dim">
        <span className="inline-flex items-center gap-1"><Server className="h-3.5 w-3.5" /> {hostName}{hostName !== ip && <span className="font-mono">({ip})</span>}</span>
        <span>Created by {report.createdBy || 'admin'} · {fmtWhen(report.createdAt)}</span>
        {report.updatedAt !== report.createdAt && <span>Last edited by {report.updatedBy || 'admin'} · {fmtWhen(report.updatedAt)}</span>}
      </p>
      <hr className="my-6 border-nd-line" />
      {report.sections.length === 0 ? (
        <p className="text-[13px] text-nd-faint">This report has no sections yet.</p>
      ) : (
        <div className="space-y-6">
          {report.sections.map((s, i) => (
            <section key={s.id} className="break-inside-avoid">
              <h3 className="text-[15px] font-semibold text-nd-fg"><span className="mr-2 text-nd-faint">{i + 1}.</span>{s.heading || 'Untitled section'}</h3>
              {s.body.trim()
                ? <div className="mt-1.5 whitespace-pre-wrap break-words text-[13.5px] leading-relaxed text-nd-fg-2">{s.body}</div>
                : <p className="mt-1.5 text-[13px] italic text-nd-faint">Not filled in yet.</p>}
            </section>
          ))}
        </div>
      )}
    </article>
  )
}

// ---- edit ----------------------------------------------------------------

function ReportEditor({ draft, setDraft, conflicts, resolveField }: {
  draft: ReportEdit
  setDraft: (fn: (d: ReportEdit | null) => ReportEdit | null) => void
  conflicts: FieldConflict[]
  resolveField: (c: FieldConflict, value: string) => void
}) {
  const upd = (fn: (d: ReportEdit) => ReportEdit) => setDraft((d) => (d ? fn(d) : d))
  const setSec = (id: string, patch: Partial<{ heading: string; body: string }>) =>
    upd((d) => ({ ...d, sections: d.sections.map((s) => (s.id === id ? { ...s, ...patch } : s)) }))
  const move = (i: number, dir: -1 | 1) => upd((d) => {
    const j = i + dir
    if (j < 0 || j >= d.sections.length) return d
    const s = [...d.sections];[s[i], s[j]] = [s[j], s[i]]
    return { ...d, sections: s }
  })
  const fc = (field: FieldConflict['field'], sectionId?: string) => conflicts.find((c) => c.field === field && c.sectionId === sectionId)
  const inputCls = 'w-full rounded-lg border border-nd-line bg-nd-card px-3 py-2 text-nd-fg outline-none focus:border-nd-brand'

  return (
    <div className="space-y-4">
      <div className="rounded-2xl border border-nd-line bg-nd-card p-5 shadow-nd">
        <label className="block text-[12px] text-nd-dim">Title
          <input value={draft.title} maxLength={120} onChange={(e) => upd((d) => ({ ...d, title: e.target.value }))} className={`${inputCls} mt-1 text-[16px] font-semibold`} />
        </label>
        <Choice c={fc('title')} onPick={resolveField} />
        <div className="mt-3 flex flex-wrap items-end gap-4">
          <label className="block text-[12px] text-nd-dim">Type
            <select value={draft.kind} onChange={(e) => upd((d) => ({ ...d, kind: e.target.value as ReportKind }))} className={`${inputCls} mt-1 w-48 text-[13px]`}>
              {REPORT_KINDS.map((k) => <option key={k.id} value={k.id}>{k.label}</option>)}
            </select>
          </label>
          <div className="text-[12px] text-nd-dim">Status
            <div className="mt-1 inline-flex rounded-lg border border-nd-line bg-nd-card p-0.5">
              {(['draft', 'final'] as const).map((st) => (
                <button key={st} onClick={() => upd((d) => ({ ...d, status: st }))}
                  className={`rounded-md px-3 py-1.5 text-[12.5px] font-medium capitalize ${draft.status === st ? 'bg-nd-fill text-nd-fg' : 'text-nd-dim hover:text-nd-fg'}`}>{st}</button>
              ))}
            </div>
          </div>
        </div>
        <Choice c={fc('kind')} onPick={resolveField} />
        <Choice c={fc('status')} onPick={resolveField} />
      </div>

      {draft.sections.map((s, i) => {
        const marked = s.body.includes(CONFLICT_START) || s.body.includes(CONFLICT_END)
        return (
          <div key={s.id} className={`rounded-2xl border bg-nd-card p-4 shadow-nd ${marked ? 'border-st-warn/50' : 'border-nd-line'}`}>
            <div className="flex items-center gap-2">
              <span className="w-6 text-right text-[13px] text-nd-faint">{i + 1}.</span>
              <input value={s.heading} maxLength={120} placeholder="Section heading" onChange={(e) => setSec(s.id, { heading: e.target.value })}
                className="flex-1 rounded-lg border border-transparent bg-transparent px-2 py-1 text-[14.5px] font-semibold text-nd-fg outline-none hover:border-nd-line focus:border-nd-brand" />
              {marked && <Badge tone="warn" icon={GitMerge}>resolve</Badge>}
              <button onClick={() => move(i, -1)} disabled={i === 0} title="Move up" className="grid h-7 w-7 place-items-center rounded-md text-nd-dim hover:bg-nd-fill hover:text-nd-fg disabled:opacity-30"><ArrowUp className="h-3.5 w-3.5" /></button>
              <button onClick={() => move(i, 1)} disabled={i === draft.sections.length - 1} title="Move down" className="grid h-7 w-7 place-items-center rounded-md text-nd-dim hover:bg-nd-fill hover:text-nd-fg disabled:opacity-30"><ArrowDown className="h-3.5 w-3.5" /></button>
              <button onClick={() => upd((d) => ({ ...d, sections: d.sections.filter((x) => x.id !== s.id) }))} title="Remove section" className="grid h-7 w-7 place-items-center rounded-md text-nd-dim hover:bg-nd-fill hover:text-st-crit-fg"><Trash2 className="h-3.5 w-3.5" /></button>
            </div>
            <Choice c={fc('heading', s.id)} onPick={resolveField} />
            <textarea value={s.body} onChange={(e) => setSec(s.id, { body: e.target.value })} maxLength={20000}
              rows={Math.min(24, Math.max(4, s.body.split('\n').length + 1))}
              className="mt-2 w-full resize-y rounded-xl border border-nd-line bg-nd-panel px-3 py-2.5 text-[13px] leading-relaxed text-nd-fg outline-none focus:border-nd-brand" />
          </div>
        )
      })}

      <button onClick={() => upd((d) => ({ ...d, sections: [...d.sections, { id: newSectionId(), heading: '', body: '' }] }))}
        disabled={draft.sections.length >= 30}
        className="inline-flex w-full items-center justify-center gap-1.5 rounded-2xl border border-dashed border-nd-line py-3 text-[13px] font-medium text-nd-dim hover:border-nd-line-strong hover:text-nd-fg disabled:opacity-40">
        <Plus className="h-4 w-4" /> Add section
      </button>
    </div>
  )
}

// Pick-a-version control for a field both editors changed.
function Choice({ c, onPick }: { c?: FieldConflict; onPick: (c: FieldConflict, v: string) => void }) {
  if (!c) return null
  const label = c.field === 'heading' ? 'heading' : c.field
  return (
    <div className="mt-2 flex flex-wrap items-center gap-2 rounded-lg border border-st-warn/30 bg-st-warn/[0.06] px-3 py-2 text-[12px] text-st-warn-fg">
      <GitMerge className="h-3.5 w-3.5" /> Both changed the {label}:
      <button onClick={() => onPick(c, c.mine)} className="rounded-md border border-nd-line bg-nd-card px-2 py-0.5 text-nd-fg hover:border-nd-brand">keep yours: “{c.mine}”</button>
      <button onClick={() => onPick(c, c.theirs)} className="rounded-md border border-nd-line bg-nd-card px-2 py-0.5 text-nd-fg hover:border-nd-brand">keep theirs: “{c.theirs}”</button>
    </div>
  )
}
