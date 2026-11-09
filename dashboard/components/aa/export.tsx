'use client'
import { useState } from 'react'
import { Download, FileText, Loader2 } from 'lucide-react'

// Small "Export CSV" button used across pages.
export function CsvButton({ onClick, label = 'Export CSV', disabled, title }: { onClick: () => void; label?: string; disabled?: boolean; title?: string }) {
  return (
    <button type="button" onClick={onClick} disabled={disabled} title={title ?? 'Download as a CSV file (opens in Excel / Sheets)'}
      className="inline-flex items-center gap-1.5 rounded-lg border border-nd-line bg-nd-card px-2.5 py-1.5 text-[12px] font-medium text-nd-fg-3 shadow-nd transition-colors hover:border-nd-line-strong hover:text-nd-fg disabled:opacity-40 print:hidden">
      <Download className="h-3.5 w-3.5" /> {label}
    </button>
  )
}

// "Export PDF" button with a spinner while the PDF is being built.
export function PdfButton({ onClick, label = 'Export PDF', disabled, title }: { onClick: () => Promise<unknown>; label?: string; disabled?: boolean; title?: string }) {
  const [busy, setBusy] = useState(false)
  return (
    <button type="button" disabled={disabled || busy} title={title ?? 'Download as a PDF document'}
      onClick={async () => { setBusy(true); try { await onClick() } finally { setBusy(false) } }}
      className="inline-flex items-center gap-1.5 rounded-lg border border-nd-line bg-nd-card px-2.5 py-1.5 text-[12px] font-medium text-nd-fg-3 shadow-nd transition-colors hover:border-nd-line-strong hover:text-nd-fg disabled:opacity-40 print:hidden">
      {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <FileText className="h-3.5 w-3.5" />} {label}
    </button>
  )
}
