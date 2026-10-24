'use client'
import { useCallback, useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { readError, accentFor, initials, ADMIN_PAGE } from '@/components/aa/admin'
import {
  Users, UserPlus, Trash2, KeyRound, Loader2, AlertTriangle, Check, ShieldAlert, UsersRound, ShieldCheck, X,
} from 'lucide-react'

// Admin page — user accounts and their group, as summary tiles + a roster.
// Group permissions live on the separate Groups page. Gated to `users` admin.

interface Group { name: string; pages: string[] }
interface SafeUser { username: string; group: string }
interface Data { users: SafeUser[]; groups: Group[]; usingDefaultAdmin: boolean }

const btnPrimary = 'inline-flex items-center gap-1.5 rounded-lg bg-nd-brand px-3.5 py-2 text-[13px] font-semibold text-black shadow-nd transition-opacity hover:opacity-90 disabled:opacity-40'
const btnGhost = 'inline-flex items-center gap-1.5 rounded-lg border border-nd-line bg-nd-card px-3 py-1.5 text-[13px] font-medium text-nd-fg-3 shadow-nd transition-colors hover:border-nd-line-strong hover:text-nd-fg disabled:opacity-40'
const inputCls = 'rounded-lg border border-nd-line bg-nd-card px-3 py-2 text-[13px] text-nd-fg shadow-nd outline-none transition-colors placeholder:text-nd-faint focus:border-nd-brand'

export default function UsersPage() {
  const [data, setData] = useState<Data | null>(null)
  const [me, setMe] = useState<string | null>(null)
  const [err, setErr] = useState('')

  const load = useCallback(async () => {
    try {
      const r = await fetch('/api/users', { cache: 'no-store' })
      if (!r.ok) { setErr(await readError(r)); return }
      setData(await r.json()); setErr('')
    } catch { setErr('could not reach the server') }
  }, [])
  useEffect(() => {
    load()
    fetch('/api/me').then((r) => (r.ok ? r.json() : null)).then((d) => { if (d?.username) setMe(d.username) }).catch(() => {})
  }, [load])

  const adminGroups = useMemo(() => new Set((data?.groups ?? []).filter((g) => g.pages.includes(ADMIN_PAGE)).map((g) => g.name)), [data])
  const adminCount = useMemo(() => (data?.users ?? []).filter((u) => adminGroups.has(u.group)).length, [data, adminGroups])

  if (!data) return <p className="py-6 text-center text-[13px] text-nd-dim">{err || 'Loading…'}</p>

  return (
    <div className="space-y-5">
      {data.usingDefaultAdmin && (
        <div className="flex items-start gap-2.5 rounded-xl border border-st-warn/40 bg-st-warn/10 px-4 py-3 text-[13px] text-st-warn-fg">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
          <div><b>Default admin is active.</b> You’re signed in with the built-in <code>admin</code> / <code>admin</code> account. Create a real user in an admin group — the default stops working as soon as one exists.</div>
        </div>
      )}
      {err && <p className="flex items-center gap-2 rounded-lg bg-st-crit/10 px-3 py-2 text-[12.5px] text-st-crit-fg"><AlertTriangle className="h-3.5 w-3.5" /> {err}</p>}

      {/* summary tiles */}
      <div className="grid grid-cols-3 gap-3">
        <Tile icon={Users} label="Users" value={data.users.length} />
        <Tile icon={UsersRound} label="Groups" value={data.groups.length} href="/analytics/groups" />
        <Tile icon={ShieldCheck} label="Admins" value={adminCount} tone="brand" />
      </div>

      <AddUser groups={data.groups} onChanged={load} />

      {/* roster */}
      <div className="overflow-hidden rounded-2xl border border-nd-line bg-nd-card shadow-nd">
        <div className="flex items-center justify-between border-b border-nd-line bg-nd-panel px-5 py-3">
          <span className="text-[13px] font-semibold text-nd-fg">Roster</span>
          <span className="text-[12px] text-nd-dim">{data.users.length} account{data.users.length === 1 ? '' : 's'}</span>
        </div>
        {data.users.length === 0 ? (
          <div className="px-5 py-10 text-center text-[13px] text-nd-dim">No users yet — add one above, in an admin group, to replace the default.</div>
        ) : (
          <ul className="divide-y divide-nd-line">
            {data.users.map((u) => (
              <UserRow key={u.username} user={u} groups={data.groups} isMe={u.username === me} isAdmin={adminGroups.has(u.group)} onChanged={load} />
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}

function Tile({ icon: I, label, value, tone, href }: { icon: any; label: string; value: number; tone?: 'brand'; href?: string }) {
  const body = (
    <div className="flex items-center gap-3 rounded-2xl border border-nd-line bg-nd-card px-4 py-3.5 shadow-nd transition-colors hover:border-nd-line-strong">
      <span className={`grid h-10 w-10 place-items-center rounded-xl ${tone === 'brand' ? 'bg-nd-brand-soft text-nd-brand' : 'bg-nd-fill text-nd-muted'}`}>
        <I className="h-5 w-5" />
      </span>
      <div>
        <div className="text-[22px] font-semibold leading-none tracking-[-0.02em] text-nd-fg">{value}</div>
        <div className="mt-1 text-[12px] text-nd-dim">{label}</div>
      </div>
    </div>
  )
  return href ? <Link href={href}>{body}</Link> : body
}

function AddUser({ groups, onChanged }: { groups: Group[]; onChanged: () => void }) {
  const [username, setUsername] = useState('')
  const [group, setGroup] = useState(groups[0]?.name || '')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [done, setDone] = useState('')
  useEffect(() => { if (!group && groups[0]) setGroup(groups[0].name) }, [groups, group])

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true); setErr(''); setDone('')
    try {
      const r = await fetch('/api/users', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username, group, password }) })
      if (!r.ok) { setErr(await readError(r)); setBusy(false); return }
      setDone(`Added “${username}”`); setUsername(''); setPassword(''); onChanged()
    } catch { setErr('could not reach the server') }
    setBusy(false)
  }

  return (
    <div className="rounded-2xl border border-nd-line bg-nd-panel p-4 shadow-nd">
      <div className="mb-3 flex items-center gap-2 text-[13px] font-semibold text-nd-fg"><UserPlus className="h-4 w-4 text-nd-brand" /> Add user</div>
      <form onSubmit={submit} className="flex flex-wrap items-end gap-3">
        <label className="text-[12px] text-nd-dim">Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" placeholder="username" className={`${inputCls} mt-1 block w-44`} />
        </label>
        <label className="text-[12px] text-nd-dim">Group
          <select value={group} onChange={(e) => setGroup(e.target.value)} className={`${inputCls} mt-1 block w-40`}>
            {groups.map((g) => <option key={g.name} value={g.name}>{g.name}</option>)}
          </select>
        </label>
        <label className="text-[12px] text-nd-dim">Password
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" placeholder="≥ 6 characters" className={`${inputCls} mt-1 block w-52`} />
        </label>
        <button type="submit" disabled={busy || !username || !password || !group} className={btnPrimary}>
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <UserPlus className="h-4 w-4" />} Add
        </button>
        {err && <p className="w-full flex items-center gap-1.5 text-[12.5px] text-st-crit-fg"><AlertTriangle className="h-3.5 w-3.5" /> {err}</p>}
        {done && <p className="w-full flex items-center gap-1.5 text-[12.5px] text-st-good-fg"><Check className="h-3.5 w-3.5" /> {done}</p>}
      </form>
    </div>
  )
}

function UserRow({ user, groups, isMe, isAdmin, onChanged }: { user: SafeUser; groups: Group[]; isMe: boolean; isAdmin: boolean; onChanged: () => void }) {
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [confirmDel, setConfirmDel] = useState(false)
  const [pwOpen, setPwOpen] = useState(false)
  const [pw, setPw] = useState('')

  async function patch(body: object) {
    setBusy(true); setErr('')
    try {
      const r = await fetch(`/api/users/${encodeURIComponent(user.username)}`, { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
      if (!r.ok) { setErr(await readError(r)); setBusy(false); return false }
      setBusy(false); onChanged(); return true
    } catch { setErr('could not reach the server'); setBusy(false); return false }
  }
  async function savePw(e: React.FormEvent) { e.preventDefault(); if (await patch({ password: pw })) { setPw(''); setPwOpen(false) } }
  async function del() {
    setBusy(true); setErr('')
    try {
      const r = await fetch(`/api/users/${encodeURIComponent(user.username)}`, { method: 'DELETE' })
      if (!r.ok) { setErr(await readError(r)); setBusy(false); setConfirmDel(false); return }
      onChanged()
    } catch { setErr('could not reach the server'); setBusy(false); setConfirmDel(false) }
  }

  const known = groups.some((g) => g.name === user.group)
  return (
    <li className="px-5 py-3">
      <div className="flex flex-wrap items-center gap-3">
        <span className="grid h-9 w-9 shrink-0 place-items-center rounded-full text-[12px] font-semibold text-white" style={{ background: accentFor(user.group) }}>
          {initials(user.username)}
        </span>
        <div className="min-w-[7rem] flex-1">
          <span className="flex items-center gap-1.5 text-[13.5px] font-medium text-nd-fg">
            {user.username}
            {isMe && <span className="rounded-full bg-nd-fill px-1.5 py-0.5 text-[10px] text-nd-dim">you</span>}
            {isAdmin && <ShieldCheck className="h-3.5 w-3.5 text-nd-brand" aria-label="admin" />}
          </span>
        </div>
        <span className="inline-flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full" style={{ background: accentFor(user.group) }} />
          <select value={known ? user.group : ''} disabled={busy} onChange={(e) => e.target.value && patch({ group: e.target.value })} className={`${inputCls} w-36 py-1.5`} aria-label={`Group for ${user.username}`}>
            {!known && <option value="">{user.group} (missing)</option>}
            {groups.map((g) => <option key={g.name} value={g.name}>{g.name}</option>)}
          </select>
        </span>
        <button type="button" onClick={() => { setPwOpen((o) => !o); setConfirmDel(false) }} disabled={busy} title="Reset password" className="grid h-8 w-8 place-items-center rounded-lg border border-nd-line bg-nd-card text-nd-muted transition-colors hover:text-nd-fg disabled:opacity-40">
          <KeyRound className="h-4 w-4" />
        </button>
        {confirmDel ? (
          <span className="inline-flex items-center gap-1.5">
            <button type="button" onClick={del} disabled={busy} className="inline-flex items-center gap-1.5 rounded-lg bg-st-crit px-2.5 py-1.5 text-[12.5px] font-medium text-white hover:opacity-90 disabled:opacity-40">
              {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />} Confirm
            </button>
            <button type="button" onClick={() => setConfirmDel(false)} disabled={busy} title="Cancel" className="grid h-8 w-8 place-items-center rounded-lg border border-nd-line bg-nd-card text-nd-muted hover:text-nd-fg"><X className="h-4 w-4" /></button>
          </span>
        ) : (
          <button type="button" onClick={() => { setConfirmDel(true); setPwOpen(false) }} disabled={busy} title="Remove user" className="grid h-8 w-8 place-items-center rounded-lg border border-nd-line bg-nd-card text-st-crit-fg transition-colors hover:border-st-crit/40 disabled:opacity-40">
            <Trash2 className="h-4 w-4" />
          </button>
        )}
      </div>
      {pwOpen && (
        <form onSubmit={savePw} className="mt-2.5 flex flex-wrap items-center gap-2 pl-12">
          <input type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="new-password" placeholder="new password (≥ 6 chars)" className={`${inputCls} w-60`} />
          <button type="submit" disabled={busy || pw.length < 6} className={btnPrimary}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />} Set password
          </button>
        </form>
      )}
      {err && <p className="mt-2 flex items-center gap-1.5 pl-12 text-[12.5px] text-st-crit-fg"><AlertTriangle className="h-3.5 w-3.5" /> {err}</p>}
    </li>
  )
}
