'use client'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { readError, accentFor, ADMIN_PAGE, type PageDef } from '@/components/aa/admin'
import {
  UsersRound, Plus, Trash2, Loader2, AlertTriangle, Check, ShieldCheck, ChevronRight, Layers,
} from 'lucide-react'

// Admin page — groups & per-page permissions, as a master/detail console:
// a rail of groups on the left, an editor on the right. A group grants a set of
// pages; users inherit their group's pages. Gated to the `users` admin page.

interface Group { name: string; pages: string[]; members?: number }
interface Data { groups: Group[]; pages: PageDef[] }
const NEW = '__new__'

export default function GroupsPage() {
  const [data, setData] = useState<Data | null>(null)
  const [sel, setSel] = useState<string | null>(null)
  const [err, setErr] = useState('')

  const load = useCallback(async (keep?: string) => {
    try {
      const r = await fetch('/api/groups', { cache: 'no-store' })
      if (!r.ok) { setErr(await readError(r)); return }
      const d: Data = await r.json()
      setData(d)
      setErr('')
      setSel((cur) => keep ?? (cur && cur !== NEW && d.groups.some((g) => g.name === cur) ? cur : d.groups[0]?.name ?? null))
    } catch { setErr('could not reach the server') }
  }, [])
  useEffect(() => { load() }, [load])

  if (!data) return <p className="py-6 text-center text-[13px] text-nd-dim">{err || 'Loading…'}</p>

  const current = sel === NEW ? null : data.groups.find((g) => g.name === sel) ?? null

  return (
    <div className="space-y-4">
      {err && <p className="flex items-center gap-2 rounded-lg bg-st-crit/10 px-3 py-2 text-[12.5px] text-st-crit-fg"><AlertTriangle className="h-3.5 w-3.5" /> {err}</p>}

      <div className="grid gap-4 lg:grid-cols-[290px_1fr]">
        {/* rail */}
        <aside className="rounded-2xl border border-nd-line bg-nd-card p-2 shadow-nd">
          <div className="flex items-center justify-between px-2 py-1.5">
            <span className="text-[11px] font-semibold uppercase tracking-[0.08em] text-nd-faint">Groups · {data.groups.length}</span>
          </div>
          <ul className="space-y-0.5">
            {data.groups.map((g) => {
              const on = g.name === sel
              const admin = g.pages.includes(ADMIN_PAGE)
              return (
                <li key={g.name}>
                  <button
                    onClick={() => setSel(g.name)}
                    className={`group flex w-full items-center gap-2.5 rounded-xl px-2.5 py-2 text-left transition-colors ${
                      on ? 'bg-nd-fill-2 ring-1 ring-nd-line' : 'hover:bg-nd-fill'
                    }`}
                  >
                    <span className="grid h-7 w-7 shrink-0 place-items-center rounded-lg text-[12px] font-semibold text-white" style={{ background: accentFor(g.name) }}>
                      <Layers className="h-3.5 w-3.5" />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="flex items-center gap-1.5">
                        <span className="truncate text-[13.5px] font-medium text-nd-fg">{g.name}</span>
                        {admin && <ShieldCheck className="h-3.5 w-3.5 text-nd-brand" />}
                      </span>
                      <span className="text-[11.5px] text-nd-dim">{g.pages.length} pages · {g.members ?? 0} member{g.members === 1 ? '' : 's'}</span>
                    </span>
                    <ChevronRight className={`h-4 w-4 shrink-0 transition-colors ${on ? 'text-nd-fg-3' : 'text-nd-faint group-hover:text-nd-dim'}`} />
                  </button>
                </li>
              )
            })}
          </ul>
          <button
            onClick={() => setSel(NEW)}
            className={`mt-1 flex w-full items-center gap-2 rounded-xl border border-dashed px-2.5 py-2 text-[13px] font-medium transition-colors ${
              sel === NEW ? 'border-nd-brand/50 bg-nd-brand/10 text-nd-fg' : 'border-nd-line text-nd-dim hover:border-nd-line-strong hover:text-nd-fg'
            }`}
          >
            <Plus className="h-4 w-4" /> New group
          </button>
        </aside>

        {/* detail */}
        <section className="min-w-0">
          {sel === NEW ? (
            <GroupEditor key={NEW} mode="new" pages={data.pages} onSaved={(name) => load(name)} />
          ) : current ? (
            <GroupEditor key={current.name} mode="edit" group={current} pages={data.pages} onSaved={() => load()} onDeleted={() => load()} />
          ) : (
            <div className="grid h-full min-h-[240px] place-items-center rounded-2xl border border-dashed border-nd-line bg-nd-panel text-center">
              <div className="text-nd-dim">
                <UsersRound className="mx-auto mb-2 h-6 w-6 text-nd-faint" />
                <p className="text-[13px]">Select a group, or create one.</p>
              </div>
            </div>
          )}
        </section>
      </div>
    </div>
  )
}

function GroupEditor({
  mode, group, pages, onSaved, onDeleted,
}: {
  mode: 'new' | 'edit'
  group?: Group
  pages: PageDef[]
  onSaved: (name: string) => void
  onDeleted?: () => void
}) {
  const [name, setName] = useState(group?.name ?? '')
  const [sel, setSel] = useState<Set<string>>(() => new Set(group?.pages ?? []))
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [confirmDel, setConfirmDel] = useState(false)

  const dirty = useMemo(() => {
    if (mode === 'new') return true
    const base = group!.pages
    return sel.size !== base.length || base.some((p) => !sel.has(p))
  }, [sel, group, mode])

  const toggle = (id: string) => setSel((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n })

  async function save() {
    setBusy(true); setErr('')
    try {
      const r = mode === 'new'
        ? await fetch('/api/groups', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name, pages: [...sel] }) })
        : await fetch(`/api/groups/${encodeURIComponent(group!.name)}`, { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ pages: [...sel] }) })
      if (!r.ok) { setErr(await readError(r)); setBusy(false); return }
      setBusy(false); onSaved(mode === 'new' ? name : group!.name)
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

  const isAdmin = sel.has(ADMIN_PAGE)
  return (
    <div className="overflow-hidden rounded-2xl border border-nd-line bg-nd-card shadow-nd">
      {/* header band */}
      <div className="flex flex-wrap items-center gap-3 border-b border-nd-line bg-nd-panel px-5 py-4">
        <span className={`grid h-10 w-10 place-items-center rounded-xl ${mode === 'new' ? 'bg-nd-fill-2 text-nd-muted' : 'text-white'}`} style={mode === 'new' ? undefined : { background: accentFor(name) }}>
          <Layers className="h-5 w-5" />
        </span>
        <div className="min-w-0 flex-1">
          {mode === 'new' ? (
            <input
              autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="group name"
              className="w-full max-w-xs rounded-lg border border-nd-line bg-nd-card px-3 py-1.5 text-[15px] font-semibold text-nd-fg outline-none focus:border-nd-brand"
            />
          ) : (
            <h2 className="flex items-center gap-2 text-[17px] font-semibold tracking-[-0.01em] text-nd-fg">
              {name} {isAdmin && <span className="rounded-full bg-nd-brand-soft px-2 py-0.5 text-[11px] font-medium text-nd-brand ring-1 ring-inset ring-nd-brand/20">admin</span>}
            </h2>
          )}
          <p className="mt-0.5 text-[12px] text-nd-dim">
            {mode === 'new' ? 'Choose the pages this group may open' : `${sel.size} of ${pages.length} pages · ${group!.members ?? 0} member${group!.members === 1 ? '' : 's'}`}
          </p>
        </div>
      </div>

      {/* permission toggles */}
      <div className="px-5 py-5">
        <div className="mb-2.5 flex items-center justify-between">
          <span className="text-[12px] font-medium uppercase tracking-[0.06em] text-nd-faint">Pages</span>
          <div className="flex gap-2 text-[12px]">
            <button onClick={() => setSel(new Set(pages.map((p) => p.id)))} className="text-nd-dim hover:text-nd-fg">All</button>
            <span className="text-nd-faint">·</span>
            <button onClick={() => setSel(new Set())} className="text-nd-dim hover:text-nd-fg">None</button>
          </div>
        </div>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-3">
          {pages.map((p) => {
            const on = sel.has(p.id)
            return (
              <button
                key={p.id}
                onClick={() => toggle(p.id)}
                aria-pressed={on}
                className={`flex items-center gap-2.5 rounded-xl border px-3 py-2.5 text-left transition-colors ${
                  on ? 'border-nd-brand/50 bg-nd-brand/10' : 'border-nd-line bg-nd-panel hover:border-nd-line-strong'
                }`}
              >
                <span className={`grid h-5 w-5 shrink-0 place-items-center rounded-md border transition-colors ${on ? 'border-nd-brand bg-nd-brand text-black' : 'border-nd-line-strong text-transparent'}`}>
                  <Check className="h-3.5 w-3.5" strokeWidth={3} />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-[13px] font-medium text-nd-fg">{p.label}</span>
                </span>
                {p.id === ADMIN_PAGE && <span className="text-[10px] font-semibold uppercase tracking-wide text-st-warn-fg">admin</span>}
              </button>
            )
          })}
        </div>
      </div>

      {/* footer actions */}
      <div className="flex flex-wrap items-center gap-2 border-t border-nd-line bg-nd-panel px-5 py-3.5">
        <button onClick={save} disabled={busy || !dirty || (mode === 'new' && !name)} className={btnPrimary}>
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />} {mode === 'new' ? 'Create group' : 'Save changes'}
        </button>
        {mode === 'edit' && (
          confirmDel ? (
            <span className="inline-flex items-center gap-1.5">
              <button onClick={del} disabled={busy} className="inline-flex items-center gap-1.5 rounded-lg bg-st-crit px-3 py-2 text-[13px] font-medium text-white hover:opacity-90 disabled:opacity-40">
                {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />} Confirm delete
              </button>
              <button onClick={() => setConfirmDel(false)} disabled={busy} className={btnGhost}>Cancel</button>
            </span>
          ) : (
            <button onClick={() => setConfirmDel(true)} disabled={busy} className={`${btnGhost} ml-auto !text-st-crit-fg`}>
              <Trash2 className="h-3.5 w-3.5" /> Delete group
            </button>
          )
        )}
        {err && <p className="w-full flex items-center gap-1.5 text-[12.5px] text-st-crit-fg"><AlertTriangle className="h-3.5 w-3.5" /> {err}</p>}
      </div>
    </div>
  )
}

const btnPrimary = 'inline-flex items-center gap-1.5 rounded-lg bg-nd-brand px-3.5 py-2 text-[13px] font-semibold text-black shadow-nd transition-opacity hover:opacity-90 disabled:opacity-40'
const btnGhost = 'inline-flex items-center gap-1.5 rounded-lg border border-nd-line bg-nd-card px-3 py-1.5 text-[13px] font-medium text-nd-fg-3 shadow-nd transition-colors hover:border-nd-line-strong hover:text-nd-fg disabled:opacity-40'
