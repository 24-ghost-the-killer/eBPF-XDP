'use client'
// Export one report, or all of a host's reports, as a PDF (A4) built in the
// browser with jsPDF (loaded only when someone exports). Every export is
// recorded in the audit log.
import type { Report } from './reports'
import { kindOf } from './reports'
import { logEvent } from './client-audit'

export interface PdfHost { ip: string; nickname?: string }

// The built-in PDF fonts cover Latin-1 (incl. æøå); map common typography to it
// and replace anything else, so text never renders as garbage.
function clean(s: string): string {
  return s
    .replace(/[‘’‚′]/g, "'")
    .replace(/[“”„″]/g, '"')
    .replace(/[–—−]/g, '-')
    .replace(/…/g, '...')
    .replace(/[•●▪]/g, '-')
    .replace(/→/g, '->')
    .replace(/ /g, ' ')
    .replace(/\t/g, '    ')
    .replace(/\p{Extended_Pictographic}\uFE0F?/gu, '') // emoji: drop (no glyph in PDF fonts)
    .replace(/[^\n\x20-\x7E\xA0-\xFF]/gu, '?') // anything else unsupported: one ? per character
}
const when = (ts: number) => new Date(ts * 1000).toLocaleString([], { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })
const safeName = (s: string) => s.replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 60) || 'report'

// `output: 'bytes'` returns the PDF instead of downloading it (tests).
export async function exportReportsPdf(reports: Report[], host: PdfHost, exportedBy: string, opts: { output?: 'save' | 'bytes' } = {}): Promise<ArrayBuffer | void> {
  if (!reports.length) return
  const { jsPDF } = await import('jspdf')
  const doc = new jsPDF({ unit: 'mm', format: 'a4', compress: true })
  const W = doc.internal.pageSize.getWidth()
  const H = doc.internal.pageSize.getHeight()
  const M = 18 // margin
  const BOTTOM = H - 18 // keep clear of the footer
  const hostLabel = host.nickname ? `${host.nickname} (${host.ip})` : host.ip
  const exported = new Date()
  let y = M

  const color = { ink: [24, 24, 27] as const, dim: [113, 113, 122] as const, faint: [161, 161, 170] as const, line: [228, 228, 231] as const, brand: [16, 150, 120] as const, warn: [196, 120, 10] as const }
  const setInk = (c: readonly [number, number, number]) => doc.setTextColor(c[0], c[1], c[2])
  const ensure = (h: number) => { if (y + h > BOTTOM) { doc.addPage(); y = M } }
  const text = (s: string, size: number, opts: { bold?: boolean; italic?: boolean; c?: readonly [number, number, number]; gap?: number; indent?: number } = {}) => {
    doc.setFont('helvetica', opts.bold ? 'bold' : opts.italic ? 'italic' : 'normal')
    doc.setFontSize(size)
    setInk(opts.c ?? color.ink)
    const lh = size * 0.3528 * 1.35 // pt -> mm, with line spacing
    const x = M + (opts.indent ?? 0)
    for (const para of clean(s).split('\n')) {
      const lines: string[] = para === '' ? [''] : doc.splitTextToSize(para, W - M - x)
      for (const line of lines) {
        ensure(lh)
        doc.text(line, x, y + lh * 0.75)
        y += lh
      }
    }
    y += opts.gap ?? 0
  }
  const rule = () => { doc.setDrawColor(color.line[0], color.line[1], color.line[2]); doc.setLineWidth(0.3); doc.line(M, y, W - M, y); y += 4 }

  // ---- cover / contents when exporting several reports ----
  if (reports.length > 1) {
    text('xdp-sentinel', 9, { c: color.brand, bold: true, gap: 2 })
    text(`Reports for ${hostLabel}`, 22, { bold: true, gap: 2 })
    text(`${reports.length} reports · exported ${exported.toLocaleString()} by ${exportedBy || 'admin'}`, 10, { c: color.dim, gap: 6 })
    rule()
    reports.forEach((r, i) => {
      text(`${i + 1}.  ${r.title}`, 11.5, { bold: true })
      text(`${kindOf(r.kind).label} · ${r.status} · last edited by ${r.updatedBy || 'admin'}, ${when(r.updatedAt)}`, 9.5, { c: color.dim, indent: 6, gap: 2.5 })
    })
    doc.addPage(); y = M
  }

  // ---- each report ----
  reports.forEach((r, ri) => {
    if (ri > 0) { doc.addPage(); y = M }
    // header line: brand left, type + status right
    doc.setFont('helvetica', 'bold'); doc.setFontSize(9); setInk(color.brand)
    doc.text('xdp-sentinel', M, y + 3)
    const status = r.status === 'final' ? 'FINAL' : 'DRAFT'
    doc.setFontSize(9); setInk(r.status === 'final' ? color.brand : color.warn)
    doc.text(`${kindOf(r.kind).label.toUpperCase()} REPORT · ${status}`, W - M, y + 3, { align: 'right' })
    y += 8
    text(r.title, 20, { bold: true, gap: 3 })

    // details table
    const rows: [string, string][] = [
      ['Host', hostLabel],
      ['Type', `${kindOf(r.kind).label} report`],
      ['Status', r.status === 'final' ? 'Final' : 'Draft'],
      ['Created', `${when(r.createdAt)} by ${r.createdBy || 'admin'}`],
      ['Last edited', `${when(r.updatedAt)} by ${r.updatedBy || 'admin'}`],
      ['Exported', `${exported.toLocaleString()} by ${exportedBy || 'admin'}`],
    ]
    doc.setFontSize(9.5)
    for (const [k, v] of rows) {
      ensure(5.5)
      doc.setFont('helvetica', 'bold'); setInk(color.dim); doc.text(k, M, y + 3.6)
      doc.setFont('helvetica', 'normal'); setInk(color.ink); doc.text(clean(v), M + 28, y + 3.6)
      y += 5.2
    }
    y += 3
    rule()

    if (!r.sections.length) text('This report has no sections.', 10.5, { italic: true, c: color.faint })
    r.sections.forEach((s, i) => {
      ensure(14) // keep a heading with at least its first lines
      text(`${i + 1}.  ${s.heading || 'Untitled section'}`, 13, { bold: true, gap: 1.5 })
      if (s.body.trim()) text(s.body.replace(/\s+$/, ''), 10.5, { gap: 5 })
      else text('Not filled in yet.', 10.5, { italic: true, c: color.faint, gap: 5 })
    })
  })

  // ---- footer on every page ----
  const pages = doc.getNumberOfPages()
  const footLeft = clean(reports.length > 1 ? `xdp-sentinel · ${hostLabel} · ${reports.length} reports` : `xdp-sentinel · ${hostLabel} · ${reports[0].title}`)
  for (let p = 1; p <= pages; p++) {
    doc.setPage(p)
    doc.setDrawColor(color.line[0], color.line[1], color.line[2]); doc.setLineWidth(0.3)
    doc.line(M, H - 12, W - M, H - 12)
    doc.setFont('helvetica', 'normal'); doc.setFontSize(8); setInk(color.faint)
    doc.text(doc.splitTextToSize(footLeft, W - 2 * M - 30)[0], M, H - 8)
    doc.text(`Page ${p} of ${pages}`, W - M, H - 8, { align: 'right' })
  }

  doc.setProperties({
    title: clean(reports.length > 1 ? `Reports for ${hostLabel}` : reports[0].title),
    subject: `xdp-sentinel report(s) for ${hostLabel}`,
    author: exportedBy || 'admin',
    creator: 'xdp-sentinel dashboard',
  })
  const stamp = exported.toISOString().slice(0, 10)
  const file = reports.length > 1
    ? `reports-${safeName(host.nickname || host.ip)}-${stamp}.pdf`
    : `report-${safeName(host.nickname || host.ip)}-${safeName(reports[0].title)}-${stamp}.pdf`
  if (opts.output === 'bytes') return doc.output('arraybuffer')
  doc.save(file)
  logEvent('export', 'export.pdf',
    reports.length > 1 ? `Exported all ${reports.length} reports for ${host.ip} to PDF` : `Exported report “${reports[0].title}” for ${host.ip} to PDF`,
    reports.length > 1 ? `host:${host.ip}` : `report:${host.ip}/${reports[0].id}`, { file, pages })
}
