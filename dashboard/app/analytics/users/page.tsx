'use client'
import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import Link from 'next/link'
import {
  readError, accentFor, relTime, summarize, AccessChips, Avatar, AccessTabs, PermissionPreview, btnPrimary, btnGhost, inputCls,
  type Catalog, type Group, type SafeUser,
} from '@/components/aa/admin'
import {
  Users, UserPlus, Trash2, KeyRound, Loader2, AlertTriangle, Check, ShieldAlert, ShieldCheck, X, Search,
  Power, ChevronDown, ChevronRight, Eye, EyeOff, Wand2, UserCheck, UserX, Layers, Lock, LogOut,
} from 'lucide-react'

// Users admin — who can sign in, which group they belong to, and what that lets
// them do. Permissions themselves live on groups (Groups & permissions tab).
// Every change applies on the user's next request; no re-login needed.

interface Data { users: SafeUser[]; groups: Group[]; catalog: Catalog; usingDefaultAdmin: boolean; noAdmin: boolean; me: string | null }
type StatusFilter = 'all' | 'active' | 'disabled'

export default function UsersPage() {
  const [data, setData] = useState<Data | null>(null)
  const [err, setErr] = useState('')
  const [q, setQ] = useState('')
  const [groupF, setGroupF] = useState('')
  const [statusF, setStatusF] = useState<StatusFilter>('all')
  const [adding, setAdding] = useState(false)
  const [open, setOpen] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const r = await fetch('/api/users', { cache: 'no-store' })
      if (!r.ok) { setErr(await readError(r)); return }
      setData(await r.json()); setErr('')
    } catch { setErr('could not reach the server') }
  }, [])
  useEffect(() => { load() }, [load])

  const permsOf = useCallback((g: string) => data?.groups.find((x) => x.name === g)?.perms ?? [], [data])
  const stats = useMemo(() => {
    const u = data?.users ?? []
    return {
      total: u.length,
      active: u.filter((x) => !x.disabled).length,
      disabled: u.filter((x) => x.disabled).length,
      admins: data ? u.filter((x) => !x.disabled && summarize(permsOf(x.group), data.catalog).level === 'admin').length : 0,
      recent: u.filter((x) => x.lastLogin && Date.now() / 1000 - x.lastLogin < 7 * 86400).length,
    }
  }, [data, permsOf])
  const rows = useMemo(() => (data?.users ?? []).filter((u) =>
    (!q || u.username.toLowerCase().includes(q.toLowerCase())) &&
    (!groupF || u.group === groupF) &&
    (statusF === 'all' || (statusF === 'active' ? !u.disabled : u.disabled))), [data, q, groupF, statusF])

  if (!data) return <div className="space-y-4"><AccessTabs />{err ? <ErrLine msg={err} /> : <div className="aa-skeleton h-64 rounded-2xl" />}</div>

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <AccessTabs users={data.users.length} groups={data.groups.length} />
        <button onClick={() => setAdding(true)} className={`${btnPrimary} ml-auto`}><UserPlus className="h-4 w-4" /> Add user</button>
      </div>

      {data.usingDefaultAdmin ? (
        <div className="flex items-start gap-2.5 rounded-xl border border-st-warn/40 bg-st-warn/10 px-4 py-3 text-[13px] text-st-warn-fg">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
          <div><b>The built-in admin / admin login is active</b> (DASH_DEFAULT_ADMIN=1). Add an enabled user to a group with “Users & groups” — the default login stops working as soon as one exists.</div>
        </div>
      ) : data.noAdmin ? (
        <div className="flex items-start gap-2.5 rounded-xl border border-st-warn/40 bg-st-warn/10 px-4 py-3 text-[13px] text-st-warn-fg">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
          <div><b>No enabled admin account.</b> Give at least one active user a group with “Users & groups”.</div>
        </div>
      ) : null}
      {err && <ErrLine msg={err} />}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Tile icon={Users} label="Users" value={stats.total} />
        <Tile icon={UserCheck} label="Active" value={stats.active} tone="good" onClick={() => setStatusF('active')} />
        <Tile icon={UserX} label="Disabled" value={stats.disabled} tone={stats.disabled ? 'warn' : undefined} onClick={() => setStatusF('disabled')} />
        <Tile icon={ShieldCheck} label="Admins" value={stats.admins} tone="brand" />
        <Tile icon={Layers} label="Signed in this week" value={stats.recent} />
      </div>

      <div className="overflow-hidden rounded-2xl border border-nd-line bg-nd-card shadow-nd">
        {/* toolbar */}
        <div className="flex flex-wrap items-center gap-2 border-b border-nd-line bg-nd-panel px-4 py-3">
          <label className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-nd-faint" />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search users" className={`${inputCls} w-56 py-1.5 pl-8`} />
          </label>
          <select value={groupF} onChange={(e) => setGroupF(e.target.value)} className={`${inputCls} py-1.5`} aria-label="Filter by group">
            <option value="">All groups</option>
            {data.groups.map((g) => <option key={g.name} value={g.name}>{g.name}</option>)}
          </select>
          <div className="inline-flex rounded-lg border border-nd-line bg-nd-card p-0.5">
            {(['all', 'active', 'disabled'] as StatusFilter[]).map((s) => (
              <button key={s} onClick={() => setStatusF(s)} className={`rounded-md px-2.5 py-1 text-[12px] font-medium capitalize ${statusF === s ? 'bg-nd-fill text-nd-fg' : 'text-nd-dim hover:text-nd-fg'}`}>{s}</button>
            ))}
          </div>
          <span className="ml-auto text-[12px] text-nd-dim">{rows.length} of {data.users.length}</span>
        </div>

        {/* header */}
        <div className="hidden grid-cols-[minmax(180px,1.2fr)_150px_minmax(200px,1.6fr)_110px_96px_150px] items-center gap-3 border-b border-nd-line px-4 py-2 text-[11px] font-semibold uppercase tracking-[0.06em] text-nd-faint lg:grid">
          <span>User</span><span>Group</span><span>Can do</span><span>Last sign-in</span><span>Status</span><span className="text-right">Actions</span>
        </div>

        {rows.length === 0 ? (
          <div className="px-5 py-12 text-center text-[13px] text-nd-dim">
            {data.users.length === 0 ? 'No users yet — add the first one.' : 'No users match these filters.'}
          </div>
        ) : (
          <ul className="divide-y divide-nd-line">
            {rows.map((u) => (
              <UserRow key={u.username} user={u} data={data} isMe={u.username === data.me}
                open={open === u.username} onToggle={() => setOpen((o) => (o === u.username ? null : u.username))} onChanged={load} />
            ))}
          </ul>
        )}
      </div>

      {adding && <AddUserModal data={data} onClose={() => setAdding(false)} onAdded={() => { setAdding(false); load() }} />}
    </div>
  )
}

function ErrLine({ msg }: { msg: string }) {
  return <p className="flex items-center gap-2 rounded-lg bg-st-crit/10 px-3 py-2 text-[12.5px] text-st-crit-fg"><AlertTriangle className="h-3.5 w-3.5" /> {msg}</p>
}

function Tile({ icon: I, label, value, tone, onClick }: { icon: any; label: string; value: number; tone?: 'brand' | 'good' | 'warn'; onClick?: () => void }) {
  const toneCls = tone === 'brand' ? 'bg-nd-brand-soft text-nd-brand' : tone === 'good' ? 'bg-st-good/10 text-st-good-fg' : tone === 'warn' ? 'bg-st-warn/10 text-st-warn-fg' : 'bg-nd-fill text-nd-muted'
  const Tag = onClick ? 'button' : 'div'
  return (
    <Tag onClick={onClick} className="flex items-center gap-3 rounded-2xl border border-nd-line bg-nd-card px-4 py-3.5 text-left shadow-nd transition-colors hover:border-nd-line-strong">
      <span className={`grid h-10 w-10 shrink-0 place-items-center rounded-xl ${toneCls}`}><I className="h-5 w-5" /></span>
      <div className="min-w-0">
        <div className="text-[22px] font-semibold leading-none tracking-[-0.02em] text-nd-fg">{value}</div>
        <div className="mt-1 truncate text-[12px] text-nd-dim">{label}</div>
      </div>
    </Tag>
  )
}

function UserRow({ user, data, isMe, open, onToggle, onChanged }: {
  user: SafeUser; data: Data; isMe: boolean; open: boolean; onToggle: () => void; onChanged: () => void
}) {
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [note, setNote] = useState('')
  const [mode, setMode] = useState<null | 'pw' | 'del'>(null)
  const [pw, setPw] = useState('')
  const perms = data.groups.find((g) => g.name === user.group)?.perms ?? []
  const known = data.groups.some((g) => g.name === user.group)
  const isAdmin = summarize(perms, data.catalog).level === 'admin'

  async function patch(body: object) {
    setBusy(true); setErr('')
    try {
      const r = await fetch(`/api/users/${encodeURIComponent(user.username)}`, { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
      if (!r.ok) { setErr(await readError(r)); setBusy(false); return false }
      setBusy(false); onChanged(); return true
    } catch { setErr('could not reach the server'); setBusy(false); return false }
  }
  async function del() {
    setBusy(true); setErr('')
    try {
      const r = await fetch(`/api/users/${encodeURIComponent(user.username)}`, { method: 'DELETE' })
      if (!r.ok) { setErr(await readError(r)); setBusy(false); setMode(null); return }
      onChanged()
    } catch { setErr('could not reach the server'); setBusy(false); setMode(null) }
  }

  const iconBtn = 'grid h-8 w-8 place-items-center rounded-lg border border-nd-line bg-nd-card text-nd-muted transition-colors hover:text-nd-fg disabled:opacity-40'
  return (
    <li className={user.disabled ? 'bg-nd-panel/60' : ''}>
      <div className="grid grid-cols-1 items-center gap-3 px-4 py-3 lg:grid-cols-[minmax(180px,1.2fr)_150px_minmax(200px,1.6fr)_110px_96px_150px]">
        <button onClick={onToggle} className="flex min-w-0 items-center gap-3 text-left">
          {open ? <ChevronDown className="h-4 w-4 shrink-0 text-nd-dim" /> : <ChevronRight className="h-4 w-4 shrink-0 text-nd-faint" />}
          <Avatar name={user.username} color={accentFor(user.group)} dim={user.disabled} />
          <span className="min-w-0">
            <span className="flex items-center gap-1.5 text-[13.5px] font-medium text-nd-fg">
              <span className="truncate">{user.username}</span>
              {isMe && <span className="rounded-full bg-nd-fill px-1.5 py-0.5 text-[10px] text-nd-dim">you</span>}
              {isAdmin && <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-nd-brand" aria-label="admin" />}
            </span>
            <span className="block text-[11.5px] text-nd-dim">{user.createdAt ? `added ${relTime(user.createdAt)}` : 'added before tracking'}</span>
          </span>
        </button>
        <span className="inline-flex items-center gap-1.5">
          <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: accentFor(user.group) }} />
          <select value={known ? user.group : ''} disabled={busy} onChange={(e) => e.target.value && patch({ group: e.target.value })} className={`${inputCls} w-full py-1.5`} aria-label={`Group for ${user.username}`}>
            {!known && <option value="">{user.group} (missing)</option>}
            {data.groups.map((g) => <option key={g.name} value={g.name}>{g.name}</option>)}
          </select>
        </span>
        <AccessChips perms={perms} cat={data.catalog} />
        <span className="text-[12.5px] text-nd-fg-3" title={user.lastLogin ? new Date(user.lastLogin * 1000).toLocaleString() : undefined}>{relTime(user.lastLogin)}</span>
        <span>
          {user.disabled
            ? <span className="inline-flex items-center gap-1 rounded-full bg-st-warn/10 px-2 py-0.5 text-[11px] font-medium text-st-warn-fg ring-1 ring-inset ring-st-warn/20"><Lock className="h-3 w-3" /> disabled</span>
            : <span className="inline-flex items-center gap-1 rounded-full bg-st-good/10 px-2 py-0.5 text-[11px] font-medium text-st-good-fg ring-1 ring-inset ring-st-good/20"><span className="h-1.5 w-1.5 rounded-full bg-st-good" /> active</span>}
        </span>
        <span className="flex items-center justify-end gap-1.5">
          <button onClick={() => { setMode((m) => (m === 'pw' ? null : 'pw')); setErr('') }} disabled={busy} title="Reset password (also signs them out everywhere)" className={iconBtn}><KeyRound className="h-4 w-4" /></button>
          <button onClick={async () => { if (await patch({ signOut: true })) setNote(isMe ? 'Signed out of your other sessions — this browser stays signed in until it reloads.' : `${user.username} is signed out on every device.`) }}
            disabled={busy} title="Sign out everywhere (revokes all their sessions)" className={iconBtn}><LogOut className="h-4 w-4" /></button>
          <button onClick={() => patch({ disabled: !user.disabled })} disabled={busy || isMe} title={isMe ? 'You can’t disable yourself' : user.disabled ? 'Enable account' : 'Disable account (signs them out at once)'}
            className={`${iconBtn} ${user.disabled ? '!text-st-good-fg' : ''}`}><Power className="h-4 w-4" /></button>
          <button onClick={() => { setMode((m) => (m === 'del' ? null : 'del')); setErr('') }} disabled={busy || isMe} title={isMe ? 'You can’t delete yourself' : 'Delete user'} className={`${iconBtn} !text-st-crit-fg hover:border-st-crit/40`}><Trash2 className="h-4 w-4" /></button>
        </span>
      </div>

      {note && !mode && !err && <p className="px-4 pb-3 text-[12.5px] text-st-good-fg lg:pl-[4.25rem]"><Check className="mr-1 inline h-3.5 w-3.5" />{note}</p>}
      {(mode || err) && (
        <div className="flex flex-wrap items-center gap-2 px-4 pb-3 lg:pl-[4.25rem]">
          {mode === 'pw' && (
            <form onSubmit={async (e) => { e.preventDefault(); if (await patch({ password: pw })) { setPw(''); setMode(null) } }} className="flex flex-wrap items-center gap-2">
              <PasswordInput value={pw} onChange={setPw} />
              <button type="submit" disabled={busy || pw.length < 8} className={btnPrimary}>{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />} Set password</button>
              <button type="button" onClick={() => setMode(null)} className={btnGhost}>Cancel</button>
            </form>
          )}
          {mode === 'del' && (
            <span className="inline-flex flex-wrap items-center gap-2 text-[12.5px] text-nd-fg-3">
              Delete <b>{user.username}</b> permanently? Disabling keeps the account and can be undone.
              <button onClick={del} disabled={busy} className="inline-flex items-center gap-1.5 rounded-lg bg-st-crit px-2.5 py-1.5 text-[12.5px] font-medium text-white hover:opacity-90 disabled:opacity-40">
                {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />} Delete
              </button>
              <button onClick={() => setMode(null)} className={btnGhost}>Cancel</button>
            </span>
          )}
          {err && <p className="flex w-full items-center gap-1.5 text-[12.5px] text-st-crit-fg"><AlertTriangle className="h-3.5 w-3.5" /> {err}</p>}
        </div>
      )}

      {open && (
        <div className="border-t border-nd-line bg-nd-bg px-4 py-4 lg:pl-[4.25rem]">
          <div className="mb-3 flex flex-wrap items-center gap-2 text-[12.5px] text-nd-dim">
            What <b className="text-nd-fg-2">{user.username}</b> can do, from the group
            <Link href={`/analytics/groups?g=${encodeURIComponent(user.group)}`} className="inline-flex items-center gap-1 font-medium text-nd-brand hover:underline">{user.group} <ChevronRight className="h-3.5 w-3.5" /></Link>
            {user.disabled && <span className="text-st-warn-fg">— currently disabled, so nothing until re-enabled.</span>}
          </div>
          <PermissionPreview perms={perms} cat={data.catalog} />
        </div>
      )}
    </li>
  )
}

function PasswordInput({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const [show, setShow] = useState(false)
  // Random, readable password from the browser's CSPRNG.
  const generate = () => {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789'
    const b = new Uint32Array(14)
    crypto.getRandomValues(b)
    onChange(Array.from(b, (n) => chars[n % chars.length]).join(''))
    setShow(true)
  }
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="relative">
        <input type={show ? 'text' : 'password'} value={value} onChange={(e) => onChange(e.target.value)} autoComplete="new-password" placeholder="at least 8 characters" className={`${inputCls} w-60 pr-9`} />
        <button type="button" onClick={() => setShow((s) => !s)} title={show ? 'Hide' : 'Show'} className="absolute right-2 top-1/2 -translate-y-1/2 text-nd-faint hover:text-nd-fg">{show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</button>
      </span>
      <button type="button" onClick={generate} title="Generate a strong password" className="grid h-9 w-9 place-items-center rounded-lg border border-nd-line bg-nd-card text-nd-muted hover:text-nd-fg"><Wand2 className="h-4 w-4" /></button>
    </span>
  )
}

function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  useEffect(() => {
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', esc)
    return () => document.removeEventListener('keydown', esc)
  }, [onClose])
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-label={title}>
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={onClose} />
      <div className="relative max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-2xl border border-nd-line bg-nd-card shadow-nd-lg">
        <div className="flex items-center justify-between border-b border-nd-line bg-nd-panel px-5 py-3.5">
          <span className="flex items-center gap-2 text-[14px] font-semibold text-nd-fg"><UserPlus className="h-4 w-4 text-nd-brand" /> {title}</span>
          <button onClick={onClose} aria-label="Close" className="grid h-7 w-7 place-items-center rounded-lg border border-nd-line text-nd-muted hover:text-nd-fg"><X className="h-4 w-4" /></button>
        </div>
        {children}
      </div>
    </div>
  )
}

function AddUserModal({ data, onClose, onAdded }: { data: Data; onClose: () => void; onAdded: () => void }) {
  const [username, setUsername] = useState('')
  const [group, setGroup] = useState(data.groups[0]?.name ?? '')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const perms = data.groups.find((g) => g.name === group)?.perms ?? []

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true); setErr('')
    try {
      const r = await fetch('/api/users', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username, group, password }) })
      if (!r.ok) { setErr(await readError(r)); setBusy(false); return }
      onAdded()
    } catch { setErr('could not reach the server'); setBusy(false) }
  }

  return (
    <Modal title="Add user" onClose={onClose}>
      <form onSubmit={submit}>
        <div className="space-y-4 px-5 py-4">
          <div className="flex flex-wrap gap-4">
            <label className="text-[12px] text-nd-dim">Username
              <input autoFocus value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" placeholder="e.g. lucas" className={`${inputCls} mt-1 block w-52`} />
            </label>
            <label className="text-[12px] text-nd-dim">Group
              <select value={group} onChange={(e) => setGroup(e.target.value)} className={`${inputCls} mt-1 block w-48`}>
                {data.groups.map((g) => <option key={g.name} value={g.name}>{g.name}</option>)}
              </select>
            </label>
            <div className="text-[12px] text-nd-dim">Password
              <div className="mt-1"><PasswordInput value={password} onChange={setPassword} /></div>
            </div>
          </div>
          <div>
            <div className="mb-2 flex flex-wrap items-center gap-2 text-[12px] text-nd-dim">
              They will be able to: <AccessChips perms={perms} cat={data.catalog} />
            </div>
            <PermissionPreview perms={perms} cat={data.catalog} />
          </div>
          {err && <p className="flex items-center gap-1.5 text-[12.5px] text-st-crit-fg"><AlertTriangle className="h-3.5 w-3.5" /> {err}</p>}
        </div>
        <div className="flex items-center justify-end gap-2 border-t border-nd-line bg-nd-panel px-5 py-3.5">
          <button type="button" onClick={onClose} className={btnGhost}>Cancel</button>
          <button type="submit" disabled={busy || !username || password.length < 8 || !group} className={btnPrimary}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <UserPlus className="h-4 w-4" />} Add user
          </button>
        </div>
      </form>
    </Modal>
  )
}
