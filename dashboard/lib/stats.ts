// Descriptive statistics for a series of samples (nulls/NaN ignored).

export interface Summary {
  n: number
  min: number
  max: number
  mean: number
  p50: number
  p95: number
  p99: number
  std: number
  last: number
  // Σ value × step: for a per-second rate this is the total count over the window.
  integral: number
}

export function quantile(sorted: number[], q: number): number {
  if (!sorted.length) return NaN
  const pos = (sorted.length - 1) * q
  const lo = Math.floor(pos), hi = Math.ceil(pos)
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo)
}

export function summarize(values: (number | null | undefined)[], stepSec: number): Summary | null {
  const v = values.filter((x): x is number => typeof x === 'number' && Number.isFinite(x))
  if (!v.length) return null
  const sorted = [...v].sort((a, b) => a - b)
  const mean = v.reduce((a, b) => a + b, 0) / v.length
  const std = Math.sqrt(v.reduce((a, b) => a + (b - mean) ** 2, 0) / v.length)
  return {
    n: v.length,
    min: sorted[0],
    max: sorted[sorted.length - 1],
    mean,
    p50: quantile(sorted, 0.5),
    p95: quantile(sorted, 0.95),
    p99: quantile(sorted, 0.99),
    std,
    last: v[v.length - 1],
    integral: v.reduce((a, b) => a + b, 0) * stepSec,
  }
}

// Equal-width histogram (bins over [min, max]).
export function histogram(values: number[], bins = 24): { x0: number; x1: number; n: number }[] {
  const v = values.filter((x) => Number.isFinite(x))
  if (!v.length) return []
  const min = Math.min(...v), max = Math.max(...v)
  const w = (max - min) / bins || 1
  const out = Array.from({ length: bins }, (_, i) => ({ x0: min + i * w, x1: min + (i + 1) * w, n: 0 }))
  for (const x of v) out[Math.min(bins - 1, Math.floor((x - min) / w))].n++
  return out
}

// Pick a "nice" query step so a window has roughly `points` samples.
export function niceStep(spanSec: number, points = 240): number {
  const raw = spanSec / points
  const steps = [15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600]
  return steps.find((s) => s >= raw) ?? 21600
}
