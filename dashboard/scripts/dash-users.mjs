#!/usr/bin/env node
// Manage the dashboard's users & groups file (CLI alternative to the admin
// Users page). One JSON file holds both groups (name + pages) and users
// (username, group, scrypt hash).
//
//   node scripts/dash-users.mjs init                      # seed default groups + admin/admin
//   node scripts/dash-users.mjs list
//   node scripts/dash-users.mjs groups
//   node scripts/dash-users.mjs group-add <name> <page,page,...|all>
//   node scripts/dash-users.mjs group-rm  <name>
//   node scripts/dash-users.mjs add    <username> <group> [password]
//   node scripts/dash-users.mjs passwd <username> [password]
//   node scripts/dash-users.mjs group  <username> <group>
//   node scripts/dash-users.mjs remove <username>
//   node scripts/dash-users.mjs pages                     # list page ids
//
// File: $DASH_USERS_FILE or --file <path> (default /etc/xdp-sentinel/dash-users.json).
// Password may be the last arg, $DASH_NEW_PASSWORD, or a hidden prompt.
// Writing to /etc usually needs sudo.
import { readFileSync, writeFileSync, mkdirSync, chmodSync } from 'node:fs'
import { dirname } from 'node:path'
import { scryptSync, randomBytes } from 'node:crypto'
import { createInterface } from 'node:readline'

const PAGE_IDS = ['overview', 'explore', 'attacks', 'ai', 'protect', 'ip', 'query', 'users']
const DASHBOARDS = ['overview', 'explore', 'attacks', 'ai', 'ip', 'query']
const DEFAULT_GROUPS = [
  { name: 'admins', pages: [...PAGE_IDS] },
  { name: 'operators', pages: [...DASHBOARDS, 'protect'] },
  { name: 'viewers', pages: [...DASHBOARDS] },
]
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
    return { groups: Array.isArray(d.groups) ? d.groups : [], users: Array.isArray(d.users) ? d.users : [] }
  } catch { return { groups: [], users: [] } }
}
function save(store) {
  try { mkdirSync(dirname(file), { recursive: true }) } catch {}
  writeFileSync(file, JSON.stringify(store, null, 2) + '\n', { mode: 0o600 })
  try { chmodSync(file, 0o600) } catch {}
  console.log(`wrote ${store.groups.length} group(s), ${store.users.length} user(s) to ${file}`)
}
function parsePages(spec) {
  if (spec === 'all') return [...PAGE_IDS]
  const ps = spec.split(',').map((s) => s.trim()).filter(Boolean)
  const bad = ps.filter((p) => !PAGE_IDS.includes(p))
  if (bad.length) die(`unknown page(s): ${bad.join(', ')} (valid: ${PAGE_IDS.join(', ')})`)
  return [...new Set(ps)]
}
function readHidden(prompt) {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout })
    rl._writeToOutput = (s) => { if (s.includes('\n')) process.stdout.write('\n') }
    rl.question(prompt, (a) => { rl.close(); resolve(a) })
  })
}
async function getPassword(arg) {
  if (arg) return arg
  if (process.env.DASH_NEW_PASSWORD) return process.env.DASH_NEW_PASSWORD
  const pw = await readHidden('New password: ')
  if (!pw || pw.length < 6) die('password must be at least 6 characters')
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
    case 'pages': console.log(PAGE_IDS.join('\n')); break
    case 'groups':
      if (!store.groups.length) { console.log('(no groups)'); break }
      for (const g of store.groups) console.log(`${g.name.padEnd(16)} ${g.pages.join(',')}`)
      break
    case 'list':
      if (!store.users.length) { console.log(`(no users in ${file})`); break }
      for (const u of store.users) console.log(`${u.username.padEnd(20)} ${u.group}`)
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
      store.users.push({ username, group, password: hashPassword(await getPassword(pwArg)) })
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
    default:
      die('commands: init | list | groups | pages | group-add | group-rm | add | passwd | group | remove')
  }
}
main()
