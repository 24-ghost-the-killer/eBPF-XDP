// Node-only, tamper-evident audit log of everything done through the dashboard.
//
// One JSON object per line in $DASH_AUDIT_FILE (default: next to the users file,
// /home/test_server/xdp-sentinel-data/audit.log). Each entry carries `prev` (the
// previous entry's hash) and `hash` = sha256(prev + entry-without-hash), so
// editing, deleting or reordering any line breaks the chain from that point on
// and `verifyChain()` reports exactly where. The file is append-only from the
// dashboard's side; at ~20 MB it rotates to audit.log.1 … .5 and the chain
// continues across files.
//
// Writes are synchronous so an entry is on disk before the request that caused
// it returns. Logging never throws into the caller: a full disk must not break
// sign-in, it is reported on stderr instead.
import { appendFileSync, readFileSync, renameSync, statSync, existsSync, mkdirSync, chmodSync, openSync, readSync, closeSync } from 'node:fs'
import { dirname } from 'node:path'
import { createHash, randomUUID } from 'node:crypto'
import type { NextRequest } from 'next/server'

export type AuditCategory = 'auth' | 'access' | 'users' | 'groups' | 'protect' | 'lockdown' | 'notes' | 'reports' | 'export' | 'query' | 'view'
export type AuditResult = 'ok' | 'denied' | 'error' | 'conflict'
export interface AuditEntry {
  id: string
  ts: number // ms
  user: string // '' = not signed in / unknown
  kind?: string // user | kiosk | breakglass | default
  ip: string | null
  ua: string | null
  category: AuditCategory
  action: string // e.g. "user.update"
  target?: string // e.g. "user:Lucas2", "host:192.168.1.107", "report:…"
  summary: string // one human-readable line
  detail?: Record<string, unknown>
  result: AuditResult
  prev: string
  hash: string
}

const MAX_BYTES = 20 * 1024 * 1024
const KEEP = 5
const GENESIS = '0'.repeat(64)

export function auditPath(): string {
  if (process.env.DASH_AUDIT_FILE) return process.env.DASH_AUDIT_FILE
  const users = process.env.DASH_USERS_FILE || '/home/test_server/xdp-sentinel-data/dash-users.json'
  return `${dirname(users)}/audit.log`
}

const g = globalThis as unknown as { __xsAuditLast?: string }

// Last hash of the newest non-empty file (current, or the latest rotation).
function lastHash(): string {
  if (g.__xsAuditLast) return g.__xsAuditLast
  const file = auditPath()
  for (const f of [file, `${file}.1`]) {
    const line = lastLine(f)
    if (line) {
      try { return (g.__xsAuditLast = JSON.parse(line).hash || GENESIS) } catch {}
    }
  }
  return (g.__xsAuditLast = GENESIS)
}

function lastLine(file: string): string | null {
  if (!existsSync(file)) return null
  try {
    const size = statSync(file).size
    if (!size) return null
    const n = Math.min(size, 64 * 1024)
    const buf = Buffer.alloc(n)
    const fd = openSync(file, 'r')
    try { readSync(fd, buf, 0, n, size - n) } finally { closeSync(fd) }
    const lines = buf.toString('utf8').split('\n').filter(Boolean)
    return lines[lines.length - 1] ?? null
  } catch {
    return null
  }
}

export const entryHash = (prev: string, body: Omit<AuditEntry, 'hash'>) =>
  createHash('sha256').update(prev).update(JSON.stringify(body)).digest('hex')

function rotateIfNeeded(file: string) {
  try {
    if (!existsSync(file) || statSync(file).size < MAX_BYTES) return
    for (let i = KEEP - 1; i >= 1; i--) if (existsSync(`${file}.${i}`)) renameSync(`${file}.${i}`, `${file}.${i + 1}`)
    renameSync(file, `${file}.1`)
  } catch (e) {
    console.error('[audit] rotate failed', e)
  }
}

export function clientInfo(req: NextRequest | null): { ip: string | null; ua: string | null } {
  if (!req) return { ip: null, ua: null }
  const ip = req.headers.get('x-forwarded-for')?.split(',')[0].trim() || req.headers.get('x-real-ip') || null
  const ua = (req.headers.get('user-agent') || '').slice(0, 160) || null
  return { ip, ua }
}

export interface AuditInput {
  user: string | null | undefined
  kind?: string
  category: AuditCategory
  action: string
  target?: string
  summary: string
  detail?: Record<string, unknown>
  result?: AuditResult
  ip?: string | null // override (events relayed from the Edge middleware)
  ua?: string | null
}

// Record one event. Never throws.
export function audit(req: NextRequest | null, e: AuditInput): void {
  const file = auditPath()
  try {
    mkdirSync(dirname(file), { recursive: true })
    rotateIfNeeded(file)
    const prev = lastHash()
    const body: Omit<AuditEntry, 'hash'> = {
      id: randomUUID(),
      ts: Date.now(),
      user: e.user || '',
      ...(e.kind ? { kind: e.kind } : {}),
      ...clientInfo(req),
      ...(e.ip !== undefined ? { ip: e.ip } : {}),
      ...(e.ua !== undefined ? { ua: e.ua } : {}),
      category: e.category,
      action: e.action,
      ...(e.target ? { target: e.target } : {}),
      summary: e.summary.slice(0, 500),
      ...(e.detail ? { detail: e.detail } : {}),
      result: e.result ?? 'ok',
      prev,
    }
    const hash = entryHash(prev, body)
    const fresh = !existsSync(file)
    appendFileSync(file, JSON.stringify({ ...body, hash }) + '\n', { mode: 0o600 })
    if (fresh) try { chmodSync(file, 0o600) } catch {}
    g.__xsAuditLast = hash
  } catch (err) {
    console.error('[audit] could not write audit entry', e.action, err)
  }
}

// ---- reading ----------------------------------------------------------------

function readFileEntries(file: string): AuditEntry[] {
  if (!existsSync(file)) return []
  const out: AuditEntry[] = []
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    if (!line) continue
    try { out.push(JSON.parse(line)) } catch { /* corrupt line: surfaced by verifyChain */ }
  }
  return out
}

// All entries, oldest first, across rotated files (oldest file first).
export function readAll(): AuditEntry[] {
  const file = auditPath()
  const files = [...Array.from({ length: KEEP }, (_, i) => `${file}.${KEEP - i}`), file]
  return files.flatMap(readFileEntries)
}

export interface ChainStatus { ok: boolean; entries: number; brokenAt?: { file: string; line: number; id?: string; ts?: number; reason: string } }

// Walk every file and recompute the hash chain.
export function verifyChain(): ChainStatus {
  const file = auditPath()
  const files = [...Array.from({ length: KEEP }, (_, i) => `${file}.${KEEP - i}`), file].filter((f) => existsSync(f))
  let prev: string | null = null
  let n = 0
  for (const f of files) {
    const lines = readFileSync(f, 'utf8').split('\n')
    for (let i = 0; i < lines.length; i++) {
      if (!lines[i]) continue
      let e: AuditEntry
      try { e = JSON.parse(lines[i]) } catch { return { ok: false, entries: n, brokenAt: { file: f, line: i + 1, reason: 'unreadable line' } } }
      const { hash, ...body } = e
      if (prev !== null && e.prev !== prev) return { ok: false, entries: n, brokenAt: { file: f, line: i + 1, id: e.id, ts: e.ts, reason: 'an entry before this one was removed or reordered' } }
      if (entryHash(e.prev, body) !== hash) return { ok: false, entries: n, brokenAt: { file: f, line: i + 1, id: e.id, ts: e.ts, reason: 'this entry was modified' } }
      prev = hash
      n++
    }
  }
  return { ok: true, entries: n }
}
