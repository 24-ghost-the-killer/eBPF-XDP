'use client'
import { Download } from 'lucide-react'

// Small "Export CSV" button used across pages.
export function CsvButton({ onClick, label = 'Export CSV', disabled, title }: { onClick: () => void; label?: string; disabled?: boolean; title?: string }) {
  return (
    <button type="button" onClick={onClick} disabled={disabled} title={title ?? 'Download as a CSV file (opens in Excel / Sheets)'}
      className="inline-flex items-center gap-1.5 rounded-lg border border-nd-line bg-nd-card px-2.5 py-1.5 text-[12px] font-medium text-nd-fg-3 shadow-nd transition-colors hover:border-nd-line-strong hover:text-nd-fg disabled:opacity-40 print:hidden">
      <Download className="h-3.5 w-3.5" /> {label}
    </button>
  )
}
