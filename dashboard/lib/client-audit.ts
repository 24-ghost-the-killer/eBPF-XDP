'use client'
// Record a browser-side action in the audit log (CSV exports, page views,
// queries run). Server-side changes are logged by the API routes themselves;
// this is only for things the server can't see. Fire-and-forget: never blocks
// or breaks the UI.
export type ClientCategory = 'export' | 'view' | 'query'
export function logEvent(category: ClientCategory, action: string, summary: string, target?: string, detail?: Record<string, unknown>) {
  try {
    fetch('/api/audit', {
      method: 'POST', keepalive: true,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ category, action, summary, target, detail }),
    }).catch(() => {})
  } catch {}
}
