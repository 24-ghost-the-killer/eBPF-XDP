// Structured per-host reports (setup sheets, incident reports, maintenance and
// audit records). Pure module — no Node imports — so the browser can use the
// types, kinds and templates, and the server uses the validation + merge.
import { merge3 } from './merge'

export type ReportKind = 'setup' | 'incident' | 'maintenance' | 'audit' | 'note'
export type ReportStatus = 'draft' | 'final'
export interface Section { id: string; heading: string; body: string }
export interface Report {
  id: string
  title: string
  kind: ReportKind
  status: ReportStatus
  sections: Section[]
  rev: number
  createdBy: string
  createdAt: number
  updatedBy: string
  updatedAt: number
}

export const REPORT_KINDS: { id: ReportKind; label: string; hint: string; sections: string[] }[] = [
  { id: 'setup', label: 'Setup', hint: 'what the host is and how it is configured', sections: ['Overview', 'Hardware', 'Services & ports', 'Access', 'Notes'] },
  { id: 'incident', label: 'Incident', hint: 'something went wrong — what, why, what was done', sections: ['Summary', 'Timeline', 'Impact', 'Root cause', 'Actions taken', 'Follow-up'] },
  { id: 'maintenance', label: 'Maintenance', hint: 'a planned change or update', sections: ['What was done', 'Why', 'Changes made', 'Verification', 'Rollback plan'] },
  { id: 'audit', label: 'Audit', hint: 'a review of the host’s security or configuration', sections: ['Scope', 'Findings', 'Recommendations'] },
  { id: 'note', label: 'Note', hint: 'free-form notes', sections: ['Notes'] },
]
export const kindOf = (k: string) => REPORT_KINDS.find((x) => x.id === k) ?? REPORT_KINDS[REPORT_KINDS.length - 1]

export const REPORT_LIMITS = { title: 120, heading: 120, body: 20_000, sections: 30, total: 100_000, perHost: 200 }

export class ReportError extends Error {
  status: number
  constructor(message: string, status = 400) { super(message); this.status = status }
}

const ID_RE = /^[A-Za-z0-9_-]{1,64}$/
const isKind = (k: unknown): k is ReportKind => REPORT_KINDS.some((x) => x.id === k)

export function newReport(kind: ReportKind, title: string, author: string, mkId: () => string): Report {
  const k = kindOf(kind)
  const now = Math.floor(Date.now() / 1000)
  return {
    id: mkId(),
    title: title.trim() || `${k.label} report`,
    kind: k.id,
    status: 'draft',
    sections: k.sections.map((h) => ({ id: mkId(), heading: h, body: '' })),
    rev: 1,
    createdBy: author, createdAt: now, updatedBy: author, updatedAt: now,
  }
}

// Tolerant read of a stored report (never throws; drops what it can't use).
export function cleanReport(raw: any): Report | null {
  if (!raw || typeof raw.id !== 'string' || !ID_RE.test(raw.id)) return null
  const sections: Section[] = Array.isArray(raw.sections)
    ? raw.sections
        .filter((x: any) => x && typeof x.id === 'string' && ID_RE.test(x.id))
        .map((x: any) => ({ id: x.id, heading: String(x.heading ?? ''), body: String(x.body ?? '') }))
    : []
  return {
    id: raw.id,
    title: String(raw.title ?? ''),
    kind: isKind(raw.kind) ? raw.kind : 'note',
    status: raw.status === 'final' ? 'final' : 'draft',
    sections,
    rev: Number(raw.rev) || 1,
    createdBy: String(raw.createdBy ?? ''), createdAt: Number(raw.createdAt) || 0,
    updatedBy: String(raw.updatedBy ?? ''), updatedAt: Number(raw.updatedAt) || 0,
  }
}

// Strict validation of the editable part of a report coming from a client.
export interface ReportEdit { title: string; kind: ReportKind; status: ReportStatus; sections: Section[] }
export function validateEdit(raw: any): ReportEdit {
  const title = String(raw?.title ?? '').trim()
  if (!title) throw new ReportError('the report needs a title')
  if (title.length > REPORT_LIMITS.title) throw new ReportError(`title is longer than ${REPORT_LIMITS.title} characters`)
  if (!isKind(raw?.kind)) throw new ReportError('invalid report type')
  const status: ReportStatus = raw?.status === 'final' ? 'final' : 'draft'
  if (!Array.isArray(raw?.sections)) throw new ReportError('sections must be a list')
  if (raw.sections.length > REPORT_LIMITS.sections) throw new ReportError(`at most ${REPORT_LIMITS.sections} sections`)
  const seen = new Set<string>()
  let total = title.length
  const sections: Section[] = raw.sections.map((x: any) => {
    const id = String(x?.id ?? '')
    if (!ID_RE.test(id) || seen.has(id)) throw new ReportError('invalid or duplicate section id')
    seen.add(id)
    const heading = String(x?.heading ?? '').trim()
    const body = String(x?.body ?? '')
    if (heading.length > REPORT_LIMITS.heading) throw new ReportError(`a section heading is longer than ${REPORT_LIMITS.heading} characters`)
    if (body.length > REPORT_LIMITS.body) throw new ReportError(`a section is longer than ${REPORT_LIMITS.body} characters`)
    total += heading.length + body.length
    return { id, heading, body }
  })
  if (total > REPORT_LIMITS.total) throw new ReportError(`the report is longer than ${REPORT_LIMITS.total} characters`)
  return { title, kind: raw.kind, status, sections }
}

export const editOf = (r: Report | ReportEdit): ReportEdit => ({ title: r.title, kind: r.kind, status: r.status, sections: r.sections.map((s) => ({ ...s })) })

// ---- three-way merge of whole reports -------------------------------------
// Fields: one-sided changes win; identical changes are fine; different changes
// to the same field are conflicts. Section bodies merge line by line (conflict
// markers where both edited the same lines). Sections are matched by id: a new
// section on either side is kept; a deletion wins only if the other side didn't
// edit that section (otherwise it is kept, so no text is ever lost).
export interface FieldConflict { field: 'title' | 'kind' | 'status' | 'heading'; sectionId?: string; mine: string; theirs: string }
export interface ReportMerge { merged: ReportEdit; fieldConflicts: FieldConflict[]; textConflicts: number }

function pick<T>(base: T, mine: T, theirs: T): { v: T; conflict: boolean } {
  if (mine === theirs || theirs === base) return { v: mine, conflict: false }
  if (mine === base) return { v: theirs, conflict: false }
  return { v: theirs, conflict: true } // keep theirs in the result; caller surfaces the choice
}

export function mergeReport(base: ReportEdit, mine: ReportEdit, theirs: ReportEdit): ReportMerge {
  const fieldConflicts: FieldConflict[] = []
  let textConflicts = 0
  const t = pick(base.title, mine.title, theirs.title)
  if (t.conflict) fieldConflicts.push({ field: 'title', mine: mine.title, theirs: theirs.title })
  const k = pick(base.kind, mine.kind, theirs.kind)
  if (k.conflict) fieldConflicts.push({ field: 'kind', mine: mine.kind, theirs: theirs.kind })
  const st = pick(base.status, mine.status, theirs.status)
  if (st.conflict) fieldConflicts.push({ field: 'status', mine: mine.status, theirs: theirs.status })

  const B = new Map(base.sections.map((s) => [s.id, s]))
  const M = new Map(mine.sections.map((s) => [s.id, s]))
  const T = new Map(theirs.sections.map((s) => [s.id, s]))
  const out: Section[] = []
  const mergeOne = (id: string): Section | null => {
    const b = B.get(id), m = M.get(id), th = T.get(id)
    if (m && th) {
      const bb = b ?? { id, heading: '', body: '' }
      const h = pick(bb.heading, m.heading, th.heading)
      if (h.conflict) fieldConflicts.push({ field: 'heading', sectionId: id, mine: m.heading, theirs: th.heading })
      const body = merge3(bb.body, m.body, th.body)
      textConflicts += body.conflicts
      return { id, heading: h.v, body: body.text }
    }
    if (m && !th) {
      // theirs deleted it (or it is new in mine): drop only if mine didn't touch it
      if (b && m.heading === b.heading && m.body === b.body) return null
      return { ...m }
    }
    if (th && !m) {
      if (b && th.heading === b.heading && th.body === b.body) return null
      return { ...th }
    }
    return null
  }
  const done = new Set<string>()
  // Mine's order first; sections only theirs has are slotted in after the
  // section that precedes them in theirs (or at the end).
  for (const s of mine.sections) { const r = mergeOne(s.id); done.add(s.id); if (r) out.push(r) }
  theirs.sections.forEach((s, i) => {
    if (done.has(s.id)) return
    done.add(s.id)
    const r = mergeOne(s.id)
    if (!r) return
    const prev = theirs.sections[i - 1]?.id
    const at = prev ? out.findIndex((x) => x.id === prev) : -1
    if (at >= 0) out.splice(at + 1, 0, r)
    else if (i === 0) out.unshift(r)
    else out.push(r)
  })
  return { merged: { title: t.v, kind: k.v, status: st.v, sections: out }, fieldConflicts, textConflicts }
}
