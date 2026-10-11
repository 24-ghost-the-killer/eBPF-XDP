// Prometheus HTTP API client (browser side). All requests go through the
// Next API proxy at /api/prom, so the browser stays same-origin.
const BASE = '/api/prom/api/v1'

export type Metric = Record<string, string>
export interface InstantResult {
  metric: Metric
  value: [number, string]
}
export interface RangeResult {
  metric: Metric
  values: [number, string][]
}
export type Row = { t: number; [key: string]: number }

async function call(path: string) {
  const r = await fetch(`${BASE}${path}`)
  if (!r.ok) throw new Error(`HTTP ${r.status}`)
  const j = await r.json()
  if (j.status !== 'success') throw new Error(j.error || 'query failed')
  return j.data
}

export async function instant(expr: string): Promise<InstantResult[]> {
  const d = await call(`/query?query=${encodeURIComponent(expr)}`)
  return d.result
}

export async function range(
  expr: string,
  minutes = 60,
  step = 30
): Promise<RangeResult[]> {
  const end = Math.floor(Date.now() / 1000)
  const start = end - minutes * 60
  const d = await call(
    `/query_range?query=${encodeURIComponent(expr)}&start=${start}&end=${end}&step=${step}`
  )
  return d.result
}

// First value of an instant result, or the default.
export function scalar(result: InstantResult[], dflt: number | null = null): number | null {
  if (!result || result.length === 0) return dflt
  const v = parseFloat(result[0].value[1])
  return Number.isNaN(v) ? dflt : v
}

// Merge range-query series into recharts rows keyed by timestamp (ms).
export function toSeries(results: RangeResult[], nameFn: (m: Metric) => string): Row[] {
  const map = new Map<number, Row>()
  for (const s of results) {
    const name = nameFn(s.metric)
    for (const [t, v] of s.values) {
      const row: Row = map.get(t) ?? { t: t * 1000 }
      row[name] = parseFloat(v)
      map.set(t, row)
    }
  }
  return Array.from(map.values()).sort((a, b) => a.t - b.t)
}

export interface Talker {
  ip: string
  scope: string
  v: number
}

export function talkers(result: InstantResult[]): Talker[] {
  return result
    .map((s) => ({
      ip: s.metric.ip || '?',
      scope: s.metric.scope || '',
      v: parseFloat(s.value[1]),
    }))
    .filter((t) => !Number.isNaN(t.v))
    .sort((a, b) => b.v - a.v)
}
