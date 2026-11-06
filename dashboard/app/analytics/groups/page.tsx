'use client'
import { Suspense, useCallback, useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { useSearchParams } from 'next/navigation'
import {
  readError, accentFor, summarize, AccessChips, Avatar, AccessTabs, btnPrimary, btnGhost, inputCls,
  type Catalog, type Group,
} from '@/components/aa/admin'
import {
  UsersRound, Plus, Trash2, Loader2, AlertTriangle, Check, ShieldCheck, ChevronRight, Layers, Copy, Pencil,
  RotateCcw, Sparkles, X, ShieldAlert, Lock,
} from 'lucide-react'

// Groups & permissions — master/detail: groups on the left, the selected
// group's permission editor on the right. Permissions are pages (may open) plus
// actions inside a page (may change things there), laid out by area. Presets
// give one-click starting points. Members get changes on their next request.

interface Data { groups: Group[]; catalog: Catalog }
const NEW = '__new__'

export default function GroupsPage() {
  return <Suspense fallback={<div className="aa-skeleton h-64 rounded-2xl" />}><Groups /></Suspense>
}

function Groups() {
  const search = useSearchParams()
  const [data, setData] = useState<Data | null>(null)
  const [sel, setSel] = useState<string | null>(search.get('g'))
  const [dup, setDup] = useState<Group | null>(null) // source when duplicating
  const [err, setErr] = useState('')

  const load = useCallback(async (keep?: string) => {
    try {
      const r = await fetch('/api/groups', { cache: 'no-store' })
      if (!r.ok) { setErr(await readError(r)); return }
      const d: Data = await r.json()
      setData(d); setErr('')
      setSel((cur) => keep ?? (cur && cur !== NEW && d.groups.some((g) => g.name === cur) ? cur : d.groups[0]?.name ?? null))
    } catch { setErr('could not reach the server') }
  }, [])
  useEffect(() => { load() }, [load])

  if (!data) return <div className="space-y-4"><AccessTabs />{err ? <p className="text-[13px] text-st-crit-fg">{err}</p> : <div className="aa-skeleton h-64 rounded-2xl" />}</div>
  const current = sel === NEW ? null : data.groups.find((g) => g.name === sel) ?? null
  const userCount = data.groups.reduce((n, g) => n + (g.members?.length ?? 0), 0)

  return (
    <div className="space-y-5">
      <AccessTabs users={userCount} groups={data.groups.length} />
      {err && <p className="flex items-center gap-2 rounded-lg bg-st-crit/10 px-3 py-2 text-[12.5px] text-st-crit-fg"><AlertTriangle className="h-3.5 w-3.5" /> {err}</p>}

      <div className="grid gap-4 lg:grid-cols-[300px_1fr]">
        <aside className="h-fit rounded-2xl border border-nd-line bg-nd-card p-2 shadow-nd">
          <div className="px-2 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] text-nd-faint">Groups · {data.groups.length}</div>
          <ul className="space-y-0.5">
            {data.groups.map((g) => {
              const on = g.name === sel
              const sum = summarize(g.perms, data.catalog)
              return (
                <li key={g.name}>
                  <button onClick={() => setSel(g.name)}
                    className={`group flex w-full items-center gap-2.5 rounded-xl px-2.5 py-2 text-left transition-colors ${on ? 'bg-nd-fill-2 ring-1 ring-nd-line' : 'hover:bg-nd-fill'}`}>
                    <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg text-white" style={{ background: accentFor(g.name) }}><Layers className="h-4 w-4" /></span>
                    <span className="min-w-0 flex-1">
                      <span className="flex items-center gap-1.5">
                        <span className="truncate text-[13.5px] font-medium text-nd-fg">{g.name}</span>
                        {sum.level === 'admin' && <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-nd-brand" />}
                      </span>
                      <span className="block truncate text-[11.5px] text-nd-dim">
                        {g.members?.length ?? 0} member{g.members?.length === 1 ? '' : 's'} · {sum.pages} pages · {sum.actions} actions
                      </span>
                    </span>
                    <ChevronRight className={`h-4 w-4 shrink-0 ${on ? 'text-nd-fg-3' : 'text-nd-faint group-hover:text-nd-dim'}`} />
                  </button>
                </li>
              )
            })}
          </ul>
          <button onClick={() => { setDup(null); setSel(NEW) }}
            className={`mt-1 flex w-full items-center gap-2 rounded-xl border border-dashed px-2.5 py-2 text-[13px] font-medium transition-colors ${sel === NEW ? 'border-nd-brand/50 bg-nd-brand/10 text-nd-fg' : 'border-nd-line text-nd-dim hover:border-nd-line-strong hover:text-nd-fg'}`}>
            <Plus className="h-4 w-4" /> New group
          </button>
        </aside>

        <section className="min-w-0">
          {sel === NEW ? (
            <GroupEditor key={`${NEW}${dup?.name ?? ''}`} mode="new" cat={data.catalog} groups={data.groups} onSaved={(n) => { setDup(null); load(n) }}
              group={dup ? { name: `${dup.name}-copy`.slice(0, 32), perms: dup.perms, members: [] } : undefined} />
          ) : current ? (
            <GroupEditor key={current.name} mode="edit" group={current} cat={data.catalog} groups={data.groups} onSaved={(n) => load(n)} onDeleted={() => load()} onDuplicate={() => { setDup(current); setSel(NEW) }} />
          ) : (
            <div className="grid min-h-[240px] place-items-center rounded-2xl border border-dashed border-nd-line bg-nd-panel text-center text-nd-dim">
              <div><UsersRound className="mx-auto mb-2 h-6 w-6 text-nd-faint" /><p className="text-[13px]">Select a group, or create one.</p></div>
            </div>
          )}
        </section>
      </div>
    </div>
  )
}

const sameSet = (a: Set<string>, b: string[]) => a.size === b.length && b.every((x) => a.has(x))

function GroupEditor({ mode, group, cat, groups, onSaved, onDeleted, onDuplicate }: {
  mode: 'new' | 'edit'
  group?: Group
  cat: Catalog
  groups: Group[]
  onSaved: (name: string) => void
  onDeleted?: () => void
  onDuplicate?: () => void
}) {
  const [name, setName] = useState(group?.name ?? '')
  const [renaming, setRenaming] = useState(false)
  const [perms, setPerms] = useState<Set<string>>(() => new Set(group?.perms ?? []))
  const [copyFrom, setCopyFrom] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [confirmDel, setConfirmDel] = useState(false)

  const members = group?.members ?? []
  const permsDirty = mode === 'new' || !sameSet(perms, group!.perms)
  const nameDirty = mode === 'edit' && name.trim() !== group!.name
  const dirty = permsDirty || nameDirty
  const sum = summarize([...perms], cat)
  const removingAdmin = mode === 'edit' && group!.perms.includes(cat.adminPage) && !perms.has(cat.adminPage) && members.length > 0

  const setPage = (pid: string, on: boolean) => setPerms((s) => {
    const n = new Set(s)
    if (on) n.add(pid)
    else { n.delete(pid); for (const a of cat.actions) if (a.page === pid) n.delete(a.id) } // actions need their page
    return n
  })
  const setAction = (id: string, page: string, on: boolean) => setPerms((s) => {
    const n = new Set(s)
    if (on) { n.add(id); n.add(page) } else n.delete(id)
    return n
  })
  const applyPreset = (p: string[]) => setPerms(new Set(p))

  async function save() {
    setBusy(true); setErr('')
    try {
      const r = mode === 'new'
        ? await fetch('/api/groups', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: name.trim(), perms: [...perms] }) })
        : await fetch(`/api/groups/${encodeURIComponent(group!.name)}`, {
            method: 'PATCH', headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ ...(permsDirty ? { perms: [...perms] } : {}), ...(nameDirty ? { name: name.trim() } : {}) }),
          })
      if (!r.ok) { setErr(await readError(r)); setBusy(false); return }
      setBusy(false); setRenaming(false); onSaved(name.trim())
    } catch { setErr('could not reach the server'); setBusy(false) }
  }
  async function del() {
    setBusy(true); setErr('')
    try {
      const r = await fetch(`/api/groups/${encodeURIComponent(group!.name)}`, { method: 'DELETE' })
      if (!r.ok) { setErr(await readError(r)); setBusy(false); setConfirmDel(false); return }
      onDeleted?.()
    } catch { setErr('could not reach the server'); setBusy(false); setConfirmDel(false) }
  }

  return (
    <div className="overflow-hidden rounded-2xl border border-nd-line bg-nd-card shadow-nd">
      {/* header */}
      <div className="flex flex-wrap items-start gap-3 border-b border-nd-line bg-nd-panel px-5 py-4">
        <span className="grid h-11 w-11 shrink-0 place-items-center rounded-xl text-white" style={{ background: name ? accentFor(name) : 'var(--nd-fill-2)' }}><Layers className="h-5 w-5" /></span>
        <div className="min-w-0 flex-1">
          {mode === 'new' || renaming ? (
            <input autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="group name, e.g. teachers" maxLength={32}
              className="w-full max-w-xs rounded-lg border border-nd-line bg-nd-card px-3 py-1.5 text-[15px] font-semibold text-nd-fg outline-none focus:border-nd-brand" />
          ) : (
            <h2 className="flex flex-wrap items-center gap-2 text-[17px] font-semibold tracking-[-0.01em] text-nd-fg">
              {group!.name}
              <button onClick={() => setRenaming(true)} title="Rename group" className="grid h-7 w-7 place-items-center rounded-lg text-nd-dim hover:bg-nd-fill hover:text-nd-fg"><Pencil className="h-3.5 w-3.5" /></button>
            </h2>
          )}
          <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[12px] text-nd-dim">
            <AccessChips perms={[...perms]} cat={cat} max={5} />
            <span>{sum.pages} pages · {sum.actions} actions</span>
          </div>
        </div>
        {mode === 'edit' && (
          <div className="flex items-center -space-x-2" title={members.join(', ') || 'no members'}>
            {members.slice(0, 6).map((m) => <span key={m} className="rounded-full ring-2 ring-nd-panel"><Avatar name={m} color={accentFor(group!.name)} size={8} /></span>)}
            {members.length > 6 && <span className="grid h-8 w-8 place-items-center rounded-full bg-nd-fill text-[11px] text-nd-dim ring-2 ring-nd-panel">+{members.length - 6}</span>}
          </div>
        )}
      </div>

      <div className="space-y-5 px-5 py-5">
        {/* presets / copy */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="inline-flex items-center gap-1 text-[12px] text-nd-dim"><Sparkles className="h-3.5 w-3.5" /> Start from</span>
          {cat.presets.map((p) => {
            const active = sameSet(perms, p.perms)
            return (
              <button key={p.id} onClick={() => applyPreset(p.perms)} title={p.hint}
                className={`rounded-full border px-3 py-1 text-[12px] font-medium transition-colors ${active ? 'border-nd-brand/50 bg-nd-brand/10 text-nd-fg' : 'border-nd-line text-nd-fg-3 hover:border-nd-line-strong hover:text-nd-fg'}`}>
                {p.label}
              </button>
            )
          })}
          {groups.length > 0 && (
            <select value={copyFrom} onChange={(e) => { setCopyFrom(e.target.value); const g = groups.find((x) => x.name === e.target.value); if (g) applyPreset(g.perms) }}
              className={`${inputCls} py-1 text-[12px]`} aria-label="Copy permissions from another group">
              <option value="">Copy from group…</option>
              {groups.filter((g) => g.name !== group?.name).map((g) => <option key={g.name} value={g.name}>{g.name}</option>)}
            </select>
          )}
          <span className="ml-auto flex gap-2 text-[12px]">
            <button onClick={() => setPerms(new Set([...cat.pages.map((p) => p.id), ...cat.actions.map((a) => a.id)]))} className="text-nd-dim hover:text-nd-fg">All</button>
            <span className="text-nd-faint">·</span>
            <button onClick={() => setPerms(new Set())} className="text-nd-dim hover:text-nd-fg">None</button>
          </span>
        </div>

        {/* permission matrix by area */}
        <div className="grid gap-4 xl:grid-cols-2">
          {cat.areas.map((area) => (
            <div key={area.id} className="rounded-xl border border-nd-line">
              <div className="border-b border-nd-line bg-nd-panel px-4 py-2 text-[11.5px] font-semibold uppercase tracking-[0.06em] text-nd-faint">{area.label}</div>
              <ul className="divide-y divide-nd-line">
                {area.pages.map((pid) => {
                  const p = cat.pages.find((x) => x.id === pid)
                  if (!p) return null
                  const on = perms.has(pid)
                  const acts = cat.actions.filter((a) => a.page === pid)
                  return (
                    <li key={pid} className="px-4 py-3">
                      <label className="flex cursor-pointer items-start gap-3">
                        <Toggle on={on} onChange={(v) => setPage(pid, v)} />
                        <span className="min-w-0 flex-1">
                          <span className="flex items-center gap-1.5 text-[13.5px] font-medium text-nd-fg">
                            {p.label}
                            {pid === cat.adminPage && <span className="rounded bg-nd-brand-soft px-1.5 py-0.5 text-[10px] font-semibold uppercase text-nd-brand">admin</span>}
                          </span>
                          <span className="block text-[12px] text-nd-dim">{acts.length ? 'Open the page (read-only)' : p.hint}</span>
                        </span>
                      </label>
                      {acts.length > 0 && (
                        <ul className={`mt-2.5 space-y-1.5 border-l-2 pl-4 ml-[18px] ${on ? 'border-nd-line' : 'border-transparent opacity-50'}`}>
                          {acts.map((a) => (
                            <li key={a.id}>
                              <label className={`flex items-start gap-2.5 ${on ? 'cursor-pointer' : 'cursor-not-allowed'}`} title={on ? undefined : `Turn on “${p.label}” first`}>
                                <input type="checkbox" checked={perms.has(a.id)} disabled={!on} onChange={(e) => setAction(a.id, pid, e.target.checked)}
                                  className="mt-0.5 h-4 w-4 accent-[var(--nd-brand)]" />
                                <span className="min-w-0">
                                  <span className="flex items-center gap-1.5 text-[13px] text-nd-fg-2">
                                    {a.label}
                                    {a.danger && <span className="rounded bg-st-warn/10 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-st-warn-fg">sensitive</span>}
                                  </span>
                                  <span className="block text-[11.5px] text-nd-dim">{a.hint}</span>
                                </span>
                              </label>
                            </li>
                          ))}
                        </ul>
                      )}
                    </li>
                  )
                })}
              </ul>
            </div>
          ))}
        </div>

        {/* members */}
        {mode === 'edit' && (
          <div className="rounded-xl border border-nd-line p-4">
            <div className="mb-2 text-[11.5px] font-semibold uppercase tracking-[0.06em] text-nd-faint">Members · {members.length}</div>
            {members.length === 0 ? (
              <p className="text-[12.5px] text-nd-dim">Nobody is in this group yet. Assign users on the <Link href="/analytics/users" className="text-nd-brand hover:underline">Users</Link> tab.</p>
            ) : (
              <ul className="flex flex-wrap gap-2">
                {members.map((m) => (
                  <li key={m} className="inline-flex items-center gap-2 rounded-full border border-nd-line bg-nd-panel py-1 pl-1 pr-3 text-[12.5px] text-nd-fg-2">
                    <Avatar name={m} color={accentFor(group!.name)} size={7} /> {m}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        {removingAdmin && (
          <p className="flex items-start gap-2 rounded-lg border border-st-warn/30 bg-st-warn/[0.06] px-3 py-2 text-[12.5px] text-st-warn-fg">
            <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" /> Removing “Users & groups” takes admin rights away from {members.length} member{members.length === 1 ? '' : 's'}. The last admin can never be locked out — the save is refused if no admin would remain.
          </p>
        )}
        {(perms.has('protect.plan') || perms.has('protect.lockdown')) && (
          <p className="flex items-start gap-2 text-[12px] text-nd-dim"><Lock className="mt-0.5 h-3.5 w-3.5 shrink-0" /> Sensitive actions change the live firewall. Give them only to people who manage the network.</p>
        )}
      </div>

      {/* footer */}
      <div className="flex flex-wrap items-center gap-2 border-t border-nd-line bg-nd-panel px-5 py-3.5">
        <button onClick={save} disabled={busy || !dirty || !name.trim()} className={btnPrimary}>
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />} {mode === 'new' ? 'Create group' : 'Save changes'}
        </button>
        {mode === 'edit' && dirty && (
          <button onClick={() => { setPerms(new Set(group!.perms)); setName(group!.name); setRenaming(false); setErr('') }} className={btnGhost}><RotateCcw className="h-3.5 w-3.5" /> Revert</button>
        )}
        {mode === 'edit' && <span className="text-[12px] text-nd-dim">{dirty ? 'unsaved changes — members get them as soon as you save' : 'saved'}</span>}
        {mode === 'edit' && (
          <span className="ml-auto inline-flex items-center gap-2">
            <button onClick={onDuplicate} title="New group with these permissions" className={btnGhost}><Copy className="h-3.5 w-3.5" /> Duplicate</button>
            {confirmDel ? (
              <>
                <button onClick={del} disabled={busy} className="inline-flex items-center gap-1.5 rounded-lg bg-st-crit px-3 py-2 text-[13px] font-medium text-white hover:opacity-90 disabled:opacity-40">
                  {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />} Delete group
                </button>
                <button onClick={() => setConfirmDel(false)} className="grid h-9 w-9 place-items-center rounded-lg border border-nd-line text-nd-muted hover:text-nd-fg"><X className="h-4 w-4" /></button>
              </>
            ) : (
              <button onClick={() => setConfirmDel(true)} disabled={members.length > 0} title={members.length ? 'Move its members to another group first' : 'Delete group'}
                className={`${btnGhost} !text-st-crit-fg`}><Trash2 className="h-3.5 w-3.5" /> Delete</button>
            )}
          </span>
        )}
        {err && <p className="flex w-full items-center gap-1.5 text-[12.5px] text-st-crit-fg"><AlertTriangle className="h-3.5 w-3.5" /> {err}</p>}
      </div>
    </div>
  )
}

function Toggle({ on, onChange }: { on: boolean; onChange: (v: boolean) => void }) {
  return (
    <button type="button" role="switch" aria-checked={on} onClick={(e) => { e.preventDefault(); onChange(!on) }}
      className={`relative mt-0.5 h-5 w-9 shrink-0 rounded-full transition-colors ${on ? 'bg-nd-brand' : 'bg-nd-fill-2 ring-1 ring-inset ring-nd-line'}`}>
      <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-white shadow transition-all ${on ? 'left-[18px]' : 'left-0.5'}`} />
    </button>
  )
}
