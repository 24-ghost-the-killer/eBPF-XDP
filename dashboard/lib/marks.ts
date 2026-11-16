// False-alarm marks on attacks: "this was not an attack" + why, by whom, when.
// Kept in attack-marks.json next to the attack archive (one small JSON file).
// Marked attacks stay listed (with a badge) but leave the totals and the globe.
//
// Read with an mtime check on every call, so every route module (list, mark)
// sees the same data without sharing in-process state.
import { readFileSync, statSync, writeFileSync, renameSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'

export const MARK_REASONS = ['download', 'arp_storm', 'loop', 'own_test', 'scan', 'backup', 'other'] as const
export type MarkReason = (typeof MARK_REASONS)[number]
export interface Mark { reason: MarkReason; note?: string; by: string; at: number }

export function marksPath(): string {
  if (process.env.DASH_ATTACK_MARKS) return process.env.DASH_ATTACK_MARKS
  if (process.env.DASH_ATTACKS_ARCHIVE) return join(dirname(process.env.DASH_ATTACKS_ARCHIVE), 'attack-marks.json')
  const users = process.env.DASH_USERS_FILE || '/home/test_server/xdp-sentinel-data/dash-users.json'
  return join(dirname(users), 'attack-marks.json')
}

let cache: { mtime: number; marks: Record<string, Mark> } | null = null
export function readMarks(): Record<string, Mark> {
  const file = marksPath()
  let mtime = 0
  try { mtime = statSync(file).mtimeMs } catch { return (cache = { mtime: 0, marks: {} }).marks }
  if (cache && cache.mtime === mtime) return cache.marks
  try {
    const j = JSON.parse(readFileSync(file, 'utf8'))
    cache = { mtime, marks: j && typeof j.marks === 'object' ? j.marks : {} }
  } catch {
    cache = { mtime, marks: {} }
  }
  return cache.marks
}

function writeMarks(marks: Record<string, Mark>) {
  const file = marksPath()
  mkdirSync(dirname(file), { recursive: true })
  writeFileSync(`${file}.tmp`, JSON.stringify({ version: 1, marks }, null, 1), { mode: 0o640 })
  renameSync(`${file}.tmp`, file)
  cache = null
}

export function setMark(id: number, m: Mark) {
  const marks = { ...readMarks(), [String(id)]: m }
  writeMarks(marks)
}

export function clearMark(id: number): boolean {
  const marks = { ...readMarks() }
  if (!marks[String(id)]) return false
  delete marks[String(id)]
  writeMarks(marks)
  return true
}
