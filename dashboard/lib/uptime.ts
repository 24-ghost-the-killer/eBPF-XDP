// Service uptime: every minute the dashboard checks each service (ping, a TCP
// port, or an HTTP(S) page) and keeps 24 hours of minute results plus 30 days
// of daily totals. Checks live in uptime.json, results in uptime-history.json
// (both next to the other dashboard data). Started by the first API request
// (the live banner polls on every page, so it runs while anyone uses the
// dashboard or the kiosk shows it).
import { readFileSync, writeFileSync, renameSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import net from 'node:net'
import http from 'node:http'
import https from 'node:https'

const run = promisify(execFile)
export type Kind = 'ping' | 'tcp' | 'http' | 'https'
export interface Check { id: string; name: string; host: string; kind: Kind; port?: number; path?: string; createdAt: number }
interface Hist { recent: [number, 0 | 1, number][]; days: Record<string, [number, number]>; changedAt: number; up: boolean | null }
export interface Status extends Check {
  up: boolean | null; ms: number | null; lastAt: number | null; since: number | null
  day: number | null; month: number | null
  strip: (0 | 1 | null)[] // 96 x 15 minutes, oldest first: 1 up, 0 any failure, null no data
}

function dataDir() {
  const users = process.env.DASH_USERS_FILE || '/home/test_server/xdp-sentinel-data/dash-users.json'
  return dirname(users)
}
const checksPath = () => join(dataDir(), 'uptime.json')
const histPath = () => join(dataDir(), 'uptime-history.json')
function readJson<T>(f: string, d: T): T { try { return JSON.parse(readFileSync(f, 'utf8')) as T } catch { return d } }
function writeJson(f: string, v: unknown) {
  mkdirSync(dirname(f), { recursive: true })
  writeFileSync(`${f}.tmp`, JSON.stringify(v), { mode: 0o640 })
  renameSync(`${f}.tmp`, f)
}

export const readChecks = (): Check[] => readJson<{ checks?: Check[] }>(checksPath(), {}).checks ?? []
export const writeChecks = (checks: Check[]) => writeJson(checksPath(), { checks })
const g = globalThis as unknown as { __xsUptime?: { timer: ReturnType<typeof setInterval>; hist: Record<string, Hist> } }
function hist(): Record<string, Hist> {
  if (!g.__xsUptime) return readJson<Record<string, Hist>>(histPath(), {})
  return g.__xsUptime.hist
}

async function probe(c: Check): Promise<{ ok: boolean; ms: number }> {
  const t0 = Date.now()
  const done = (ok: boolean) => ({ ok, ms: Date.now() - t0 })
  try {
    if (c.kind === 'ping') {
      await run('ping', ['-c', '1', '-W', '2', c.host], { timeout: 4000, env: { ...process.env, PATH: '/usr/bin:/bin:/usr/sbin:/sbin' } })
      return done(true)
    }
    if (c.kind === 'tcp') {
      return await new Promise((res) => {
        const s = net.connect({ host: c.host, port: c.port ?? 80, timeout: 3000 })
        s.once('connect', () => { s.destroy(); res(done(true)) })
        s.once('timeout', () => { s.destroy(); res(done(false)) })
        s.once('error', () => res(done(false)))
      })
    }
    const mod = c.kind === 'https' ? https : http
    return await new Promise((res) => {
      const req = mod.request({ host: c.host, port: c.port, path: c.path || '/', method: 'GET', timeout: 5000, rejectUnauthorized: false, headers: { 'user-agent': 'xdp-sentinel-uptime' } }, (r) => {
        r.resume()
        res(done((r.statusCode ?? 0) < 500))
      })
      req.once('timeout', () => { req.destroy(); res(done(false)) })
      req.once('error', () => res(done(false)))
      req.end()
    })
  } catch {
    return done(false)
  }
}

async function tick() {
  const checks = readChecks()
  const h = hist()
  const now = Date.now()
  const results = await Promise.all(checks.map(probe))
  checks.forEach((c, i) => {
    const r = results[i]
    const e = h[c.id] ?? { recent: [], days: {}, changedAt: now, up: null }
    e.recent.push([now, r.ok ? 1 : 0, r.ms])
    e.recent = e.recent.filter((x) => now - x[0] <= 24 * 3600e3)
    const d = new Date(now).toISOString().slice(0, 10)
    const t = e.days[d] ?? [0, 0]
    e.days[d] = [t[0] + (r.ok ? 1 : 0), t[1] + 1]
    for (const k of Object.keys(e.days)) if (now - Date.parse(k) > 31 * 86400e3) delete e.days[k]
    if (e.up !== r.ok) { e.up = r.ok; e.changedAt = now }
    h[c.id] = e
  })
  for (const id of Object.keys(h)) if (!checks.some((c) => c.id === id)) delete h[id]
  if (g.__xsUptime) g.__xsUptime.hist = h
  try { writeJson(histPath(), h) } catch {}
}

export function startUptime() {
  if (g.__xsUptime) return
  g.__xsUptime = { timer: setInterval(() => { void tick() }, 60_000), hist: readJson<Record<string, Hist>>(histPath(), {}) }
  g.__xsUptime.timer.unref?.()
  setTimeout(() => { void tick() }, 3000).unref?.()
}
export const checkNow = () => tick()

export function statuses(): Status[] {
  const h = hist()
  const now = Date.now()
  return readChecks().map((c) => {
    const e = h[c.id]
    const last = e?.recent[e.recent.length - 1]
    const strip: (0 | 1 | null)[] = Array.from({ length: 96 }, () => null)
    for (const [t, ok] of e?.recent ?? []) {
      const i = 95 - Math.floor((now - t) / (15 * 60e3))
      if (i >= 0 && i < 96) strip[i] = strip[i] === 0 ? 0 : (ok as 0 | 1)
    }
    const dayN = e?.recent.length ?? 0
    const dayUp = e?.recent.filter((x) => x[1]).length ?? 0
    const month = Object.values(e?.days ?? {}).reduce((a, [u, t]) => [a[0] + u, a[1] + t], [0, 0])
    return {
      ...c, up: e?.up ?? null, ms: last ? last[2] : null, lastAt: last ? last[0] : null, since: e?.changedAt ?? null,
      day: dayN ? dayUp / dayN : null, month: month[1] ? month[0] / month[1] : null, strip,
    }
  })
}
