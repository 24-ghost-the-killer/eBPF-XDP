// In-memory brute-force protection for /api/login (Node runtime, one process).
//  * per username: 5 failures within 15 min lock that username for 5 min, then
//    the lock doubles on each further failure, up to 1 h;
//  * per client address (when a proxy forwards it): 20 failures / 15 min -> 15 min;
//  * global: more than 60 failures in a minute pauses all logins for a minute
//    (password spraying across many usernames).
// A successful login clears that username's record. Every failure also costs a
// fixed delay so online guessing is slow even before a lock engages.
interface Rec { fails: number; first: number; until: number; lockMs: number }
const WINDOW = 15 * 60_000
const users = new Map<string, Rec>()
const addrs = new Map<string, Rec>()
let globalFails: number[] = []
let globalUntil = 0

function rec(m: Map<string, Rec>, k: string, now: number): Rec {
  let r = m.get(k)
  if (!r || (now - r.first > WINDOW && r.until < now)) { r = { fails: 0, first: now, until: 0, lockMs: 0 }; m.set(k, r) }
  if (m.size > 5000) for (const [key, v] of m) if (v.until < now && now - v.first > WINDOW) m.delete(key)
  return r
}

// Seconds the caller must wait, or 0 if a login attempt is allowed now.
export function loginBlocked(username: string, addr: string | null): number {
  const now = Date.now()
  const waits = [globalUntil - now]
  const u = users.get(username.toLowerCase())
  if (u) waits.push(u.until - now)
  if (addr) { const a = addrs.get(addr); if (a) waits.push(a.until - now) }
  return Math.max(0, Math.ceil(Math.max(...waits) / 1000))
}

export function loginFailed(username: string, addr: string | null) {
  const now = Date.now()
  const u = rec(users, username.toLowerCase(), now)
  u.fails++
  if (u.fails >= 5) { u.lockMs = Math.min(u.lockMs ? u.lockMs * 2 : 5 * 60_000, 60 * 60_000); u.until = now + u.lockMs }
  if (addr) { const a = rec(addrs, addr, now); a.fails++; if (a.fails >= 20) a.until = now + 15 * 60_000 }
  globalFails = globalFails.filter((t) => now - t < 60_000)
  globalFails.push(now)
  if (globalFails.length > 60) globalUntil = now + 60_000
}

export function loginSucceeded(username: string) {
  users.delete(username.toLowerCase())
}

// An admin reset the password or re-enabled the account: lift the lock now.
export const clearLoginLock = loginSucceeded

export const FAIL_DELAY_MS = 400
