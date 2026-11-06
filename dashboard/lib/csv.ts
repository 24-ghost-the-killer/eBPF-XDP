'use client'
// CSV export: build RFC-4180 CSV in the browser and download it. Every export is
// recorded in the audit log (who exported what, how many rows).
//
// Cells that start with = + - @ (or tab/CR) are prefixed with ' so a spreadsheet
// never runs them as a formula (CSV injection) — values like attacker-controlled
// hostnames or report text can't execute when the file is opened in Excel.
import { logEvent } from './client-audit'

export interface Column<T> { key: string; label: string; get?: (row: T) => unknown }

function cell(v: unknown): string {
  if (v === null || v === undefined) return ''
  let s = v instanceof Date ? v.toISOString() : typeof v === 'object' ? JSON.stringify(v) : String(v)
  if (/^[=+\-@\t\r]/.test(s) && !/^-?\d+(\.\d+)?(e[+-]?\d+)?$/i.test(s)) s = `'${s}`
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

export function toCsv<T>(rows: T[], cols: Column<T>[]): string {
  const head = cols.map((c) => cell(c.label)).join(',')
  const body = rows.map((r) => cols.map((c) => cell(c.get ? c.get(r) : (r as any)[c.key])).join(','))
  return [head, ...body].join('\r\n') + '\r\n'
}

const stamp = () => new Date().toISOString().slice(0, 16).replace(/[:T]/g, '-')
const safeName = (s: string) => s.replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 80) || 'export'

// Download `rows` as <name>-<timestamp>.csv and audit-log the export.
export function downloadCsv<T>(name: string, rows: T[], cols: Column<T>[], what: string, target?: string) {
  const csv = '﻿' + toCsv(rows, cols) // BOM: Excel opens UTF-8 (æøå) correctly
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `${safeName(name)}-${stamp()}.csv`
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
  logEvent('export', 'export.csv', `Exported ${what} to CSV (${rows.length} row${rows.length === 1 ? '' : 's'})`, target, { file: a.download, rows: rows.length })
}

// Time-series rows ({ t: ms, series…: number }) as CSV columns.
export function seriesColumns(keys: string[], labels?: Record<string, string>): Column<Record<string, number>>[] {
  return [
    { key: 't', label: 'time (UTC)', get: (r) => new Date(r.t).toISOString() },
    ...keys.map((k) => ({ key: k, label: labels?.[k] ?? k })),
  ]
}
