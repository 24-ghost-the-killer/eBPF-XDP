// Node-only user & group store. One JSON file holds both:
//   { "version": 2,
//     "groups": [{ "name", "pages": [permissionId,...] }],
//     "users":  [{ "username", "group", "password": "scrypt$...",
//                  "disabled"?, "createdAt"?, "lastLogin"? }] }
// A group grants a set of permissions (pages + actions, see lib/authz); a user
// belongs to a group. The group key stays "pages" so an older dashboard build
// can still read the file (it simply ignores the action ids).
// Imported only by Node routes, never by middleware (Edge).
//
// Source: DASH_USERS (inline JSON, read-only) or DASH_USERS_FILE (default
// /etc/xdp-sentinel/dash-users.json). Browser management writes DASH_USERS_FILE,
// so that path must be writable by the dashboard user.
//
// Default admin (OPT-IN): only with DASH_DEFAULT_ADMIN=1, and only while no
// enabled stored user is an admin, can you sign in as admin / admin to bootstrap
// a fresh install. Otherwise create the first admin with
//   node scripts/dash-users.mjs add <name> admins
// DASH_PASSWORD, if set, is a break-glass admin.
//
// Sessions carry the user's `epoch`; bumping it (password change, "sign out
// everywhere", disabling) revokes every cookie issued before.

import { readFileSync, writeFileSync, mkdirSync, chmodSync, renameSync, statSync } from 'node:fs'
import { dirname } from 'node:path'
import { scryptSync, timingSafeEqual as nodeTimingSafeEqual, randomBytes } from 'node:crypto'
import { PERM_IDS, ADMIN_PAGE, ACTIONS, effectivePerms, PRESETS, type Session, type SessionKind } from './authz'

export interface Group { name: string; perms: string[] }
export interface StoredUser { username: string; group: string; password: string; disabled?: boolean; createdAt?: number; lastLogin?: number; epoch?: number }
export interface SafeUser { username: string; group: string; disabled: boolean; createdAt: number; lastLogin: number }
export interface Store { groups: Group[]; users: StoredUser[] }

const DEFAULT_FILE = '/etc/xdp-sentinel/dash-users.json'
const DEFAULT_ADMIN_USER = 'admin'
const DEFAULT_ADMIN_PASSWORD = 'admin'
const STORE_VERSION = 3

const preset = (id: string) => [...(PRESETS.find((p) => p.id === id)?.perms ?? [])]
// Seeded when the store has no groups yet; become editable once anything is saved.
const DEFAULT_GROUPS = (): Group[] => [
  { name: 'admins', perms: preset('admin') },
  { name: 'operators', perms: preset('operator') },
  { name: 'viewers', perms: preset('viewer') },
]

function filePath(): string {
  return process.env.DASH_USERS_FILE || DEFAULT_FILE
}
function inlineMode(): boolean {
  return !!(process.env.DASH_USERS && process.env.DASH_USERS.trim())
}

function parseStore(raw: string): Store {
  const data = JSON.parse(raw)
  const ver = Number(data?.version) || 1
  const groups: Group[] = Array.isArray(data?.groups)
    ? data.groups
        .filter((g: any) => g && typeof g.name === 'string')
        .map((g: any) => {
          let perms: string[] = Array.isArray(g.pages) ? g.pages : Array.isArray(g.perms) ? g.perms : []
          // v1 files only had pages, and "Protection" meant full control of it.
          // Keep that: a v1 group with the Protection page gets every Protection
          // action, so upgrading never takes anything away from anyone.
          if (ver < 2) for (const a of ACTIONS) if (perms.includes(a.page)) perms = [...perms, a.id]
          // v3 added the Audit log page: existing admin groups get it.
          if (ver < 3 && perms.includes(ADMIN_PAGE) && !perms.includes('audit')) perms = [...perms, 'audit']
          return { name: g.name, perms: effectivePerms(perms) }
        })
    : []
  const users: StoredUser[] = Array.isArray(data?.users)
    ? data.users
        .filter((u: any) => u && typeof u.username === 'string' && typeof u.password === 'string' && typeof u.group === 'string')
        .map((u: any) => ({
          username: u.username, group: u.group, password: u.password,
          disabled: u.disabled === true || undefined,
          createdAt: Number(u.createdAt) || undefined,
          lastLogin: Number(u.lastLogin) || undefined,
          epoch: Number(u.epoch) || undefined,
        }))
    : []
  return { groups: groups.length ? groups : DEFAULT_GROUPS(), users }
}

let cache: Store | null = null
let cacheMtime = -1

const fileMtime = () => { try { return statSync(filePath()).mtimeMs } catch { return 0 } }

export function loadStore(): Store {
  // Re-read when the file changed on disk (e.g. `dash-users.mjs passwd` on the
  // box), so a CLI password reset works without restarting the dashboard.
  if (cache && (inlineMode() || fileMtime() === cacheMtime)) return cache
  cacheMtime = inlineMode() ? -1 : fileMtime()
  if (inlineMode()) {
    try { cache = parseStore(process.env.DASH_USERS as string) } catch { cache = { groups: DEFAULT_GROUPS(), users: [] } }
    return cache
  }
  try {
    cache = parseStore(readFileSync(filePath(), 'utf8'))
  } catch {
    cache = { groups: DEFAULT_GROUPS(), users: [] }
  }
  return cache
}

const safe = (u: StoredUser): SafeUser => ({ username: u.username, group: u.group, disabled: !!u.disabled, createdAt: u.createdAt || 0, lastLogin: u.lastLogin || 0 })

export function listGroups(): Group[] {
  return loadStore().groups.map((g) => ({ name: g.name, perms: [...g.perms] })).sort((a, b) => a.name.localeCompare(b.name))
}
export function listUsers(): SafeUser[] {
  return loadStore().users.map(safe).sort((a, b) => a.username.localeCompare(b.username))
}
export function permsForGroup(name: string): string[] {
  const g = loadStore().groups.find((x) => x.name === name)
  return g ? [...g.perms] : []
}
/** @deprecated kept for older imports; returns all permissions of the group. */
export const pagesForGroup = permsForGroup

function groupIsAdmin(g: Group | undefined): boolean {
  return !!g && g.perms.includes(ADMIN_PAGE)
}
// Enabled users in an admin group. Disabled admins don't count: they can't sign in.
function countAdminUsers(store: Store): number {
  return store.users.filter((u) => !u.disabled && groupIsAdmin(store.groups.find((g) => g.name === u.group))).length
}
// True while the opt-in built-in admin/admin login is usable: DASH_DEFAULT_ADMIN=1
// and no enabled stored user is an admin yet.
export function usingDefaultAdmin(): boolean {
  return process.env.DASH_DEFAULT_ADMIN === '1' && countAdminUsers(loadStore()) === 0
}
// True when there is no enabled admin at all (shown as a setup hint).
export function noAdminUsers(): boolean {
  return countAdminUsers(loadStore()) === 0
}

// ---- scrypt ----------------------------------------------------------------

export function hashPassword(password: string, N = 16384, r = 8, p = 1): string {
  const salt = randomBytes(16)
  const hash = scryptSync(password, salt, 32, { N, r, p, maxmem: 64 * 1024 * 1024 })
  return `scrypt$${N}$${r}$${p}$${salt.toString('hex')}$${hash.toString('hex')}`
}
export function verifyPassword(password: string, stored: string): boolean {
  const parts = stored.split('$')
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false
  const [, Ns, rs, ps, saltHex, hashHex] = parts
  const N = Number(Ns), r = Number(rs), p = Number(ps)
  if (!Number.isFinite(N) || !Number.isFinite(r) || !Number.isFinite(p)) return false
  try {
    const expected = Buffer.from(hashHex, 'hex')
    const got = scryptSync(password, Buffer.from(saltHex, 'hex'), expected.length, { N, r, p, maxmem: 64 * 1024 * 1024 })
    return got.length === expected.length && nodeTimingSafeEqual(got, expected)
  } catch {
    return false
  }
}

export interface AuthResult { username: string; group: string; perms: string[]; kind: SessionKind; epoch: number }

// A hash to verify against when the username doesn't exist, so a wrong username
// costs the same scrypt time as a wrong password (no user enumeration by timing).
let dummyHash: string | null = null

export function authenticate(username: string, password: string): AuthResult | null {
  const store = loadStore()
  // Exact match first; otherwise a case-insensitive match (usernames are unique
  // case-insensitively), so "lucas2" signs in as "Lucas2".
  const u = store.users.find((x) => x.username === username)
    ?? store.users.find((x) => x.username.toLowerCase() === username.toLowerCase())
  if (!u) verifyPassword(password, (dummyHash ??= hashPassword(randomBytes(12).toString('hex'))))
  if (u && !u.disabled && verifyPassword(password, u.password)) {
    // Record the login (best effort — never block sign-in on a write error).
    if (!inlineMode()) {
      try { persist({ groups: store.groups, users: store.users.map((x) => (x === u ? { ...x, lastLogin: Math.floor(Date.now() / 1000) } : x)) }) } catch {}
    }
    return { username: u.username, group: u.group, perms: permsForGroup(u.group), kind: 'user', epoch: u.epoch || 0 }
  }
  const legacy = process.env.DASH_PASSWORD
  if (legacy && password.length === legacy.length && nodeTimingSafeEqual(Buffer.from(password), Buffer.from(legacy))) {
    return { username: username || 'admin', group: 'admins', perms: [...PERM_IDS], kind: 'breakglass', epoch: 0 }
  }
  if (usingDefaultAdmin() && username === DEFAULT_ADMIN_USER && password === DEFAULT_ADMIN_PASSWORD) {
    return { username: DEFAULT_ADMIN_USER, group: 'admins', perms: [...PERM_IDS], kind: 'default', epoch: 0 }
  }
  return null
}

// ---- live access -----------------------------------------------------------
// Resolve a verified session against the CURRENT store, so a permission change,
// group change, disabled account or deleted user takes effect on the very next
// request instead of when the year-long cookie expires.
export interface Access { username: string; group: string; perms: string[]; kind: SessionKind; epoch: number }

export function liveAccess(s: Session): Access | null {
  const kind: SessionKind = s.k ?? 'user'
  if (kind === 'breakglass') return process.env.DASH_PASSWORD ? { username: s.u, group: s.g, perms: [...PERM_IDS], kind, epoch: 0 } : null
  if (kind === 'default') return usingDefaultAdmin() ? { username: s.u, group: s.g, perms: [...PERM_IDS], kind, epoch: 0 } : null
  if (kind === 'kiosk') {
    const perms = permsForGroup(s.g)
    return { username: 'kiosk', group: s.g, perms: perms.length ? perms : s.p, kind, epoch: 0 }
  }
  const u = loadStore().users.find((x) => x.username === s.u)
  if (u) {
    if (u.disabled || (s.e ?? 0) < (u.epoch || 0)) return null // disabled, or this cookie was revoked
    return { username: u.username, group: u.group, perms: permsForGroup(u.group), kind, epoch: u.epoch || 0 }
  }
  // Tokens issued before sessions carried a kind: a DASH_PASSWORD sign-in under
  // an arbitrary name. (The old year-long default-admin cookies are not honoured.)
  if (!s.k && process.env.DASH_PASSWORD) return { username: s.u, group: s.g, perms: s.p, kind: 'breakglass', epoch: 0 }
  return null
}

// ---- write operations ------------------------------------------------------

export class UserError extends Error {
  status: number
  constructor(message: string, status = 400) { super(message); this.status = status }
}

const NAME_RE = /^[a-zA-Z0-9._-]{1,32}$/
const RESERVED_USERS = new Set(['kiosk'])

function assertWritable() {
  if (inlineMode()) throw new UserError('management is read-only because DASH_USERS is set inline; use DASH_USERS_FILE instead', 409)
}
function persist(store: Store) {
  const file = filePath()
  const out = {
    version: STORE_VERSION,
    groups: store.groups.map((g) => ({ name: g.name, pages: g.perms })),
    users: store.users.map((u) => ({
      username: u.username, group: u.group, password: u.password,
      ...(u.disabled ? { disabled: true } : {}),
      ...(u.createdAt ? { createdAt: u.createdAt } : {}),
      ...(u.lastLogin ? { lastLogin: u.lastLogin } : {}),
      ...(u.epoch ? { epoch: u.epoch } : {}),
    })),
  }
  try {
    mkdirSync(dirname(file), { recursive: true })
    const tmp = `${file}.tmp`
    writeFileSync(tmp, JSON.stringify(out, null, 2) + '\n', { mode: 0o600 })
    try { chmodSync(tmp, 0o600) } catch {}
    renameSync(tmp, file)
  } catch (e: any) {
    throw new UserError(`could not write ${file}: ${e?.code || e?.message || 'error'} (must be writable by the dashboard user)`, 500)
  }
  cache = store
  cacheMtime = fileMtime()
}
function guardAdmins(before: Store, after: Store, msg: string) {
  if (countAdminUsers(before) > 0 && countAdminUsers(after) === 0) throw new UserError(msg, 409)
}

// --- groups ---
export function addGroup(name: string, perms: string[]): Group {
  assertWritable()
  if (!NAME_RE.test(name)) throw new UserError('group name must be 1–32 chars: letters, digits, dot, dash, underscore')
  const store = loadStore()
  if (store.groups.some((g) => g.name === name)) throw new UserError(`group "${name}" already exists`, 409)
  const g: Group = { name, perms: effectivePerms(perms) }
  persist({ ...store, groups: [...store.groups, g] })
  return g
}
export function userEpoch(username: string): number {
  return loadStore().users.find((u) => u.username === username)?.epoch || 0
}

export function updateGroup(name: string, changes: { perms?: string[]; newName?: string }): Group {
  assertWritable()
  const store = loadStore()
  const cur = store.groups.find((g) => g.name === name)
  if (!cur) throw new UserError(`no such group "${name}"`, 404)
  const next: Group = { name: cur.name, perms: changes.perms ? effectivePerms(changes.perms) : [...cur.perms] }
  let users = store.users
  if (changes.newName !== undefined && changes.newName !== name) {
    if (!NAME_RE.test(changes.newName)) throw new UserError('group name must be 1–32 chars: letters, digits, dot, dash, underscore')
    if (store.groups.some((g) => g.name === changes.newName)) throw new UserError(`group "${changes.newName}" already exists`, 409)
    next.name = changes.newName
    users = users.map((u) => (u.group === name ? { ...u, group: changes.newName! } : u)) // members follow the rename
  }
  const after: Store = { groups: store.groups.map((g) => (g.name === name ? next : g)), users }
  guardAdmins(store, after, 'that change would leave no admin — keep "Users & groups" on a group with enabled members')
  persist(after)
  return next
}
export function removeGroup(name: string): void {
  assertWritable()
  const store = loadStore()
  if (!store.groups.some((g) => g.name === name)) throw new UserError(`no such group "${name}"`, 404)
  const members = store.users.filter((u) => u.group === name)
  if (members.length) throw new UserError(`group "${name}" has ${members.length} member(s); move them to another group first`, 409)
  persist({ groups: store.groups.filter((g) => g.name !== name), users: store.users })
}

// --- users ---
export function addUser(username: string, group: string, password: string): SafeUser {
  assertWritable()
  if (!NAME_RE.test(username)) throw new UserError('username must be 1–32 chars: letters, digits, dot, dash, underscore')
  if (RESERVED_USERS.has(username)) throw new UserError(`"${username}" is reserved`)
  if (!password || password.length < 8) throw new UserError('password must be at least 8 characters')
  const store = loadStore()
  if (!store.groups.some((g) => g.name === group)) throw new UserError(`no such group "${group}"`)
  if (store.users.some((u) => u.username.toLowerCase() === username.toLowerCase())) throw new UserError(`user "${username}" already exists`, 409)
  const user: StoredUser = { username, group, password: hashPassword(password), createdAt: Math.floor(Date.now() / 1000) }
  persist({ groups: store.groups, users: [...store.users, user] })
  return safe(user)
}
export function updateUser(username: string, changes: { group?: string; password?: string; disabled?: boolean; revoke?: boolean }): SafeUser {
  assertWritable()
  const store = loadStore()
  const idx = store.users.findIndex((u) => u.username === username)
  if (idx === -1) throw new UserError(`no such user "${username}"`, 404)
  const user = { ...store.users[idx] }
  if (changes.group !== undefined) {
    if (!store.groups.some((g) => g.name === changes.group)) throw new UserError(`no such group "${changes.group}"`)
    user.group = changes.group
  }
  if (changes.password !== undefined) {
    if (!changes.password || changes.password.length < 8) throw new UserError('password must be at least 8 characters')
    user.password = hashPassword(changes.password)
    user.epoch = (user.epoch || 0) + 1 // a new password signs out every existing session
  }
  if (changes.disabled !== undefined) user.disabled = changes.disabled || undefined
  if (changes.revoke) user.epoch = (user.epoch || 0) + 1 // "sign out everywhere"
  const after: Store = { groups: store.groups, users: store.users.map((u, i) => (i === idx ? user : u)) }
  guardAdmins(store, after, 'that would leave no enabled admin — keep at least one admin active')
  persist(after)
  return safe(user)
}
export function removeUser(username: string): void {
  assertWritable()
  const store = loadStore()
  if (!store.users.some((u) => u.username === username)) throw new UserError(`no such user "${username}"`, 404)
  const after: Store = { groups: store.groups, users: store.users.filter((u) => u.username !== username) }
  guardAdmins(store, after, 'cannot remove the last enabled admin')
  persist(after)
}
