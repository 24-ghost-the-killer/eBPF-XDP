'use client'
// Shared bits for the admin pages (Users and Groups).

export const ADMIN_PAGE = 'users'
export interface PageDef { id: string; label: string }

export async function readError(r: Response): Promise<string> {
  try { const j = await r.json(); return j?.error || `error ${r.status}` } catch { return `error ${r.status}` }
}

// Deterministic accent for a name (group chips, avatars) from the chart ramp.
const ACCENTS = ['var(--s1)', 'var(--s2)', 'var(--s3)', 'var(--s4)', 'var(--s5)']
export function accentFor(name: string): string {
  let h = 0
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0
  return ACCENTS[h % ACCENTS.length]
}
export function initials(name: string): string {
  const parts = name.replace(/[._-]+/g, ' ').trim().split(/\s+/)
  return ((parts[0]?.[0] || '') + (parts[1]?.[0] || '')).toUpperCase() || name.slice(0, 2).toUpperCase()
}
