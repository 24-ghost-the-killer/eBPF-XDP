#!/usr/bin/env node
// Manage the dashboard's users & groups file (CLI alternative to the admin
// Users page). One JSON file holds both groups (name + permissions: page ids
// and action ids like protect.plan) and users (username, group, scrypt hash).
//
//   node scripts/dash-users.mjs init                      # seed default groups + admin/admin
//   node scripts/dash-users.mjs list
//   node scripts/dash-users.mjs groups
//   node scripts/dash-users.mjs group-add <name> <perm,perm,...|all|viewer|operator|admin>
//   node scripts/dash-users.mjs group-rm  <name>
//   node scripts/dash-users.mjs add    <username> <group> [password]
//   node scripts/dash-users.mjs passwd <username> [password]
//   node scripts/dash-users.mjs group  <username> <group>
//   node scripts/dash-users.mjs remove <username>
//   node scripts/dash-users.mjs disable|enable <username>
//   node scripts/dash-users.mjs pages                     # list permission ids
// Keep the id lists below in sync with lib/authz.ts (PAGES / ACTIONS / PRESETS).
//
// File: $DASH_USERS_FILE or --file <path> (default /etc/xdp-sentinel/dash-users.json).
// Password may be the last arg, $DASH_NEW_PASSWORD, or a hidden prompt.
// Writing to /etc usually needs sudo.
import { readFileSync, writeFileSync, mkdirSync, chmodSync } from 'node:fs'
import { dirname } from 'node:path'
import { scryptSync, randomBytes } from 'node:crypto'
import { createInterface } from 'node:readline'

const PAGE_IDS = ['overview', 'explore', 'attacks', 'ai', 'protect', 'ip', 'query', 'users', 'audit']
const ACTION_IDS = ['protect.plan', 'protect.lockdown', 'protect.notes', 'protect.reports', 'protect.delete']
const PERM_IDS = [...PAGE_IDS, ...ACTION_IDS]
const MONITOR = ['overview', 'explore', 'attacks', 'ai', 'ip']
const PRESETS = {
  viewer: [...MONITOR, 'protect'],
  operator: [...MONITOR, 'protect', 'query', ...ACTION_IDS],
  admin: [...PERM_IDS],
}
const DEFAULT_GROUPS = [
  { name: 'admins', pages: PRESETS.admin },
  { name: 'operators', pages: PRESETS.operator },
  { name: 'viewers', pages: PRESETS.viewer },
]
const STORE_VERSION = 3
const DEFAULT_FILE = '/etc/xdp-sentinel/dash-users.json'

const argv = process.argv.slice(2)
let file = process.env.DASH_USERS_FILE || DEFAULT_FILE
const fi = argv.indexOf('--file')
if (fi !== -1) { file = argv[fi + 1]; argv.splice(fi, 2) }
const [cmd, ...rest] = argv
const die = (m) => { console.error(m); process.exit(1) }

function hashPassword(password, N = 16384, r = 8, p = 1) {
  const salt = randomBytes(16)
  const hash = scryptSync(password, salt, 32, { N, r, p, maxmem: 64 * 1024 * 1024 })
  return `scrypt$${N}$${r}$${p}$${salt.toString('hex')}$${hash.toString('hex')}`
}
function load() {
  try {
    const d = JSON.parse(readFileSync(file, 'utf8'))
    const groups = Array.isArray(d.groups) ? d.groups : []
    // Same upgrade as the dashboard: a v1 group with Protection keeps full control of it.
    const ver = Number(d.version) || 1
    for (const g of groups) {
      if (!Array.isArray(g.pages)) continue
      if (ver < 2 && g.pages.includes('protect')) g.pages = [...new Set([...g.pages, ...ACTION_IDS])]
      if (ver < 3 && g.pages.includes('users')) g.pages = [...new Set([...g.pages, 'audit'])]
    }
    return { version: STORE_VERSION, groups: groups.length ? groups : DEFAULT_GROUPS.map((g) => ({ ...g, pages: [...g.pages] })), users: Array.isArray(d.users) ? d.users : [] }
  } catch {
    // No file yet: start from the default groups so `add <user> admins` works on a fresh install.
    return { version: STORE_VERSION, groups: DEFAULT_GROUPS.map((g) => ({ ...g, pages: [...g.pages] })), users: [] }
  }
}
function save(store) {
  try { mkdirSync(dirname(file), { recursive: true }) } catch {}
  writeFileSync(file, JSON.stringify(store, null, 2) + '\n', { mode: 0o600 })
  try { chmodSync(file, 0o600) } catch {}
  console.log(`wrote ${store.groups.length} group(s), ${store.users.length} user(s) to ${file}`)
}
function parsePages(spec) {
  if (spec === 'all') return [...PERM_IDS]
  if (PRESETS[spec]) return [...PRESETS[spec]]
  const ps = spec.split(',').map((s) => s.trim()).filter(Boolean)
  const bad = ps.filter((p) => !PERM_IDS.includes(p))
  if (bad.length) die(`unknown permission(s): ${bad.join(', ')} (valid: ${PERM_IDS.join(', ')})`)
  const set = new Set(ps)
  for (const a of ACTION_IDS) if (set.has(a)) set.add(a.split('.')[0]) // an action needs its page
  return PERM_IDS.filter((p) => set.has(p))
}
// Read a line without echoing it. The prompt is written directly, BEFORE output
// is muted (muting readline's output used to hide the prompt itself, so the tool
// looked frozen).
function readHidden(prompt) {
  return new Promise((resolve) => {
    process.stdout.write(prompt)
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true })
    rl._writeToOutput = () => {}
    rl.question('', (a) => { rl.close(); process.stdout.write('\n'); resolve(a) })
  })
}
async function getPassword(arg) {
  if (arg) return arg
  if (process.env.DASH_NEW_PASSWORD) return process.env.DASH_NEW_PASSWORD
  const pw = await readHidden('New password: ')
  if (!pw || pw.length < 8) die('password must be at least 8 characters')
  if (pw !== (await readHidden('Confirm password: '))) die('passwords do not match')
  return pw
}

async function main() {
  const store = load()
  switch (cmd) {
    case 'init': {
      if (!store.groups.length) store.groups = DEFAULT_GROUPS.map((g) => ({ ...g, pages: [...g.pages] }))
      if (!store.users.some((u) => u.group === 'admins')) store.users.push({ username: 'admin', group: 'admins', password: hashPassword('admin') })
      save(store)
      console.log('default admin: admin / admin  — change it now with:  passwd admin')
      break
    }
    case 'pages': console.log(['# pages', ...PAGE_IDS, '# actions', ...ACTION_IDS, '# presets: viewer, operator, admin, all'].join('\n')); break
    case 'groups':
      if (!store.groups.length) { console.log('(no groups)'); break }
      for (const g of store.groups) console.log(`${g.name.padEnd(16)} ${g.pages.join(',')}`)
      break
    case 'list':
      if (!store.users.length) { console.log(`(no users in ${file})`); break }
      for (const u of store.users) console.log(`${u.username.padEnd(20)} ${u.group.padEnd(16)} ${u.disabled ? 'disabled' : 'active'}`)
      break
    case 'group-add': {
      const [name, spec] = rest
      if (!name || !spec) die('usage: group-add <name> <page,page,...|all>')
      if (store.groups.some((g) => g.name === name)) die(`group "${name}" already exists`)
      store.groups.push({ name, pages: parsePages(spec) })
      save(store); break
    }
    case 'group-rm': {
      const [name] = rest
      if (!name) die('usage: group-rm <name>')
      if (store.users.some((u) => u.group === name)) die(`group "${name}" has members; reassign them first`)
      const n = store.groups.length
      store.groups = store.groups.filter((g) => g.name !== name)
      if (store.groups.length === n) die(`no such group "${name}"`)
      save(store); break
    }
    case 'add': {
      const [username, group, pwArg] = rest
      if (!username || !group) die('usage: add <username> <group> [password]')
      if (!store.groups.some((g) => g.name === group)) die(`no such group "${group}" (see: groups)`)
      if (store.users.some((u) => u.username === username)) die(`user "${username}" already exists`)
      store.users.push({ username, group, password: hashPassword(await getPassword(pwArg)), createdAt: Math.floor(Date.now() / 1000) })
      save(store); break
    }
    case 'passwd': {
      const [username, pwArg] = rest
      const u = store.users.find((x) => x.username === username)
      if (!u) die(`no such user "${username}"`)
      u.password = hashPassword(await getPassword(pwArg))
      save(store); break
    }
    case 'group': {
      const [username, group] = rest
      if (!username || !group) die('usage: group <username> <group>')
      const u = store.users.find((x) => x.username === username)
      if (!u) die(`no such user "${username}"`)
      if (!store.groups.some((g) => g.name === group)) die(`no such group "${group}"`)
      u.group = group
      save(store); break
    }
    case 'remove': {
      const [username] = rest
      const n = store.users.length
      store.users = store.users.filter((u) => u.username !== username)
      if (store.users.length === n) die(`no such user "${username}"`)
      save(store); break
    }
    case 'disable':
    case 'enable': {
      const [username] = rest
      const u = store.users.find((x) => x.username === username)
      if (!u) die(`no such user "${username}"`)
      if (cmd === 'disable') u.disabled = true
      else delete u.disabled
      save(store); break
    }
    default:
      die('commands: init | list | groups | pages | group-add | group-rm | add | passwd | group | remove | disable | enable')
  }
}
main()
