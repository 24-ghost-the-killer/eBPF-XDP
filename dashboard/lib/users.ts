// Node-only user & group store. One JSON file holds both:
//   { "groups": [{ "name", "pages": [pageId,...] }],
//     "users":  [{ "username", "group", "password": "scrypt$..." }] }
// A group grants a set of pages (see lib/authz PAGES); a user belongs to a
// group. Imported only by Node routes (/api/login, /api/users*, /api/groups*),
// never by middleware (Edge).
//
// Source: DASH_USERS (inline JSON, read-only) or DASH_USERS_FILE (default
// /etc/xdp-sentinel/dash-users.json). Browser management writes DASH_USERS_FILE,
// so that path must be writable by the dashboard user.
//
// Default admin: until a stored user belongs to an admin group, you can sign in
// as admin / admin (built-in, not written to disk) so the console is reachable
// out of the box. Create a real admin and it stops working. DASH_PASSWORD, if
// set, is always a break-glass admin as well.

import { readFileSync, writeFileSync, mkdirSync, chmodSync } from 'node:fs'
import { dirname } from 'node:path'
import { scryptSync, timingSafeEqual as nodeTimingSafeEqual, randomBytes } from 'node:crypto'
import { PAGE_IDS, ADMIN_PAGE, isPageId } from './authz'

export interface Group { name: string; pages: string[] }
export interface StoredUser { username: string; group: string; password: string }
export interface SafeUser { username: string; group: string }
export interface Store { groups: Group[]; users: StoredUser[] }

const DEFAULT_FILE = '/etc/xdp-sentinel/dash-users.json'
const DEFAULT_ADMIN_USER = 'admin'
const DEFAULT_ADMIN_PASSWORD = 'admin'

// Dashboard pages minus Protection and the admin page.
const DASHBOARD_PAGES = ['overview', 'explore', 'attacks', 'ai', 'ip', 'query']
// Seeded when the store has no groups yet; become editable once anything is saved.
const DEFAULT_GROUPS: Group[] = [
  { name: 'admins', pages: [...PAGE_IDS] },
  { name: 'operators', pages: [...DASHBOARD_PAGES, 'protect'] },
  { name: 'viewers', pages: [...DASHBOARD_PAGES] },
]

function filePath(): string {
  return process.env.DASH_USERS_FILE || DEFAULT_FILE
}
function inlineMode(): boolean {
  return !!(process.env.DASH_USERS && process.env.DASH_USERS.trim())
}

function sanitizePages(pages: unknown): string[] {
  if (!Array.isArray(pages)) return []
  return [...new Set(pages.filter(isPageId))]
}

function parseStore(raw: string): Store {
  const data = JSON.parse(raw)
  const groups: Group[] = Array.isArray(data?.groups)
    ? data.groups
        .filter((g: any) => g && typeof g.name === 'string')
        .map((g: any) => ({ name: g.name, pages: sanitizePages(g.pages) }))
    : []
  const users: StoredUser[] = Array.isArray(data?.users)
    ? data.users
        .filter((u: any) => u && typeof u.username === 'string' && typeof u.password === 'string' && typeof u.group === 'string')
        .map((u: any) => ({ username: u.username, group: u.group, password: u.password }))
    : []
  return { groups: groups.length ? groups : DEFAULT_GROUPS.map((g) => ({ ...g, pages: [...g.pages] })), users }
}

let cache: Store | null = null

export function loadStore(): Store {
  if (cache) return cache
  if (inlineMode()) {
    try { cache = parseStore(process.env.DASH_USERS as string) } catch { cache = { groups: DEFAULT_GROUPS.map((g) => ({ ...g })), users: [] } }
    return cache
  }
  try {
    cache = parseStore(readFileSync(filePath(), 'utf8'))
  } catch {
    cache = { groups: DEFAULT_GROUPS.map((g) => ({ ...g, pages: [...g.pages] })), users: [] }
  }
  return cache
}

export function listGroups(): Group[] {
  return loadStore().groups.map((g) => ({ name: g.name, pages: [...g.pages] })).sort((a, b) => a.name.localeCompare(b.name))
}
export function listUsers(): SafeUser[] {
  return loadStore().users.map((u) => ({ username: u.username, group: u.group })).sort((a, b) => a.username.localeCompare(b.username))
}
export function pagesForGroup(name: string): string[] {
  const g = loadStore().groups.find((x) => x.name === name)
  return g ? [...g.pages] : []
}
function groupIsAdmin(g: Group | undefined): boolean {
  return !!g && g.pages.includes(ADMIN_PAGE)
}
function countAdminUsers(store: Store): number {
  return store.users.filter((u) => groupIsAdmin(store.groups.find((g) => g.name === u.group))).length
}
// True while no stored user is an admin — the built-in admin/admin still works.
export function usingDefaultAdmin(): boolean {
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

export interface AuthResult { username: string; group: string; pages: string[] }

export function authenticate(username: string, password: string): AuthResult | null {
  const store = loadStore()
  const u = store.users.find((x) => x.username === username)
  if (u && verifyPassword(password, u.password)) {
    return { username: u.username, group: u.group, pages: pagesForGroup(u.group) }
  }
  const legacy = process.env.DASH_PASSWORD
  if (legacy && password === legacy) {
    return { username: username || 'admin', group: 'admins', pages: adminPages(store) }
  }
  if (usingDefaultAdmin() && username === DEFAULT_ADMIN_USER && password === DEFAULT_ADMIN_PASSWORD) {
    return { username: DEFAULT_ADMIN_USER, group: 'admins', pages: adminPages(store) }
  }
  return null
}
// Pages for the admin break-glass/default: the `admins` group if present, else all.
function adminPages(store: Store): string[] {
  const g = store.groups.find((x) => x.name === 'admins')
  return g && g.pages.length ? [...g.pages] : [...PAGE_IDS]
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
  try {
    mkdirSync(dirname(file), { recursive: true })
    writeFileSync(file, JSON.stringify(store, null, 2) + '\n', { mode: 0o600 })
    try { chmodSync(file, 0o600) } catch {}
  } catch (e: any) {
    throw new UserError(`could not write ${file}: ${e?.code || e?.message || 'error'} (must be writable by the dashboard user)`, 500)
  }
  cache = store
}

// --- groups ---
export function addGroup(name: string, pages: string[]): Group {
  assertWritable()
  if (!NAME_RE.test(name)) throw new UserError('group name must be 1–32 chars: letters, digits, dot, dash, underscore')
  const store = loadStore()
  if (store.groups.some((g) => g.name === name)) throw new UserError(`group "${name}" already exists`, 409)
  const g: Group = { name, pages: sanitizePages(pages) }
  persist({ ...store, groups: [...store.groups, g] })
  return g
}
export function updateGroup(name: string, pages: string[]): Group {
  assertWritable()
  const store = loadStore()
  if (!store.groups.some((g) => g.name === name)) throw new UserError(`no such group "${name}"`, 404)
  const groups = store.groups.map((g) => (g.name === name ? { name, pages: sanitizePages(pages) } : g))
  const after: Store = { groups, users: store.users }
  if (countAdminUsers(store) > 0 && countAdminUsers(after) === 0) {
    throw new UserError('that change would leave no admin user — keep the admins page on a group with members', 409)
  }
  persist(after)
  return groups.find((g) => g.name === name)!
}
export function removeGroup(name: string): void {
  assertWritable()
  const store = loadStore()
  if (!store.groups.some((g) => g.name === name)) throw new UserError(`no such group "${name}"`, 404)
  const members = store.users.filter((u) => u.group === name)
  if (members.length) throw new UserError(`group "${name}" has ${members.length} member(s); reassign them first`, 409)
  persist({ groups: store.groups.filter((g) => g.name !== name), users: store.users })
}

// --- users ---
export function addUser(username: string, group: string, password: string): SafeUser {
  assertWritable()
  if (!NAME_RE.test(username)) throw new UserError('username must be 1–32 chars: letters, digits, dot, dash, underscore')
  if (RESERVED_USERS.has(username)) throw new UserError(`"${username}" is reserved`)
  if (!password || password.length < 6) throw new UserError('password must be at least 6 characters')
  const store = loadStore()
  if (!store.groups.some((g) => g.name === group)) throw new UserError(`no such group "${group}"`)
  if (store.users.some((u) => u.username === username)) throw new UserError(`user "${username}" already exists`, 409)
  const user: StoredUser = { username, group, password: hashPassword(password) }
  persist({ groups: store.groups, users: [...store.users, user] })
  return { username, group }
}
export function updateUser(username: string, changes: { group?: string; password?: string }): SafeUser {
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
    if (!changes.password || changes.password.length < 6) throw new UserError('password must be at least 6 characters')
    user.password = hashPassword(changes.password)
  }
  const users = store.users.map((u, i) => (i === idx ? user : u))
  const after: Store = { groups: store.groups, users }
  if (countAdminUsers(store) > 0 && countAdminUsers(after) === 0) {
    throw new UserError('cannot move the last admin out of an admin group', 409)
  }
  persist(after)
  return { username: user.username, group: user.group }
}
export function removeUser(username: string): void {
  assertWritable()
  const store = loadStore()
  if (!store.users.some((u) => u.username === username)) throw new UserError(`no such user "${username}"`, 404)
  const users = store.users.filter((u) => u.username !== username)
  if (countAdminUsers(store) > 0 && countAdminUsers({ groups: store.groups, users }) === 0) {
    throw new UserError('cannot remove the last admin user', 409)
  }
  persist({ groups: store.groups, users })
}
