'use client'
import { Suspense, useCallback, useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'next/navigation'
import { Avatar, accentFor, readError, inputCls, btnGhost } from '@/components/aa/admin'
import { CsvButton } from '@/components/aa/export'
import { downloadCsv } from '@/lib/csv'
import {
  History, Search, ShieldCheck, ShieldAlert, KeyRound, Ban, Pencil, Loader2, ChevronDown, ChevronRight, RefreshCw,
  Eye, CheckCircle2, AlertTriangle, Link2,
} from 'lucide-react'

// Audit log — every action taken on the dashboard: sign-ins (and failures),
// user/group/permission changes, protection-plan edits, lockdown, nicknames,
// log entries, reports, CSV exports, queries run, denied attempts and (opt-in)
// page views. Entries are hash-chained on the server; "Verify" recomputes the
// chain and shows whether anything was edited or removed.

interface Entry {
  id: string; ts: number; user: string; kind?: string; ip: string | null; via?: 'twingate'; ua: string | null
  category: string; action: string; target?: string; summary: string; detail?: Record<string, unknown>
  result: 'ok' | 'denied' | 'error' | 'conflict'; prev: string; hash: string
}
interface Summary { total: number; last24h: number; failedLogins24h: number; denied24h: number; changes24h: number; users: string[] }
interface Chain { ok: boolean; entries: number; brokenAt?: { file: string; line: number; ts?: number; reason: string } }

const CATS: { id: string; label: string }[] = [
  { id: 'auth', label: 'Sign-in' }, { id: 'access', label: 'Denied access' }, { id: 'users', label: 'Users' }, { id: 'groups', label: 'Groups' },
  { id: 'protect', label: 'Protection' }, { id: 'lockdown', label: 'Lockdown' }, { id: 'notes', label: 'Nicknames & log' },
  { id: 'reports', label: 'Reports' }, { id: 'export', label: 'Exports' }, { id: 'query', label: 'Queries' }, { id: 'view', label: 'Page views' },
]
const RESULT_CLS: Record<string, string> = {
  ok: 'bg-st-good/10 text-st-good-fg ring-st-good/20',
  denied: 'bg-st-crit/10 text-st-crit-fg ring-st-crit/20',
  error: 'bg-st-warn/10 text-st-warn-fg ring-st-warn/20',
  conflict: 'bg-st-warn/10 text-st-warn-fg ring-st-warn/20',
}
const when = (ms: number) => new Date(ms).toLocaleString([], { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit' })

export default function AuditPage() {
  return <Suspense fallback={<div className="aa-skeleton h-64 rounded-2xl" />}><Audit /></Suspense>
}

function Audit() {
  const sp = useSearchParams()
  const [q, setQ] = useState(sp.get('q') ?? '')
  const [user, setUser] = useState('')
  const [cats, setCats] = useState<string[]>([])
  const [result, setResult] = useState('')
  const [views, setViews] = useState(false)
  const [live, setLive] = useState(true)
  const [entries, setEntries] = useState<Entry[] | null>(null)
  const [summary, setSummary] = useState<Summary | null>(null)
  const [more, setMore] = useState(false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [open, setOpen] = useState<string | null>(null)
  const [chain, setChain] = useState<Chain | null>(null)
  const [verifying, setVerifying] = useState(false)

  const params = useMemo(() => {
    const p = new URLSearchParams({ limit: '200' })
    if (q.trim()) p.set('q', q.trim())
    if (user) p.set('user', user)
    if (cats.length) p.set('category', cats.join(','))
    if (result) p.set('result', result)
    if (views) p.set('views', '1')
    return p
  }, [q, user, cats, result, views])

  const load = useCallback(async () => {
    try {
      const r = await fetch(`/api/audit?${params}`, { cache: 'no-store' })
      if (!r.ok) { setErr(await readError(r)); return }
      const d = await r.json()
      setEntries(d.entries); setSummary(d.summary); setMore(d.more); setErr('')
    } catch { setErr('could not reach the server') }
  }, [params])

  useEffect(() => { const t = setTimeout(load, 250); return () => clearTimeout(t) }, [load])
  useEffect(() => { if (!live) return; const t = setInterval(load, 5000); return () => clearInterval(t) }, [live, load])

  async function loadMore() {
    if (!entries?.length) return
    setBusy(true)
    try {
      const p = new URLSearchParams(params)
      p.set('before', String(entries[entries.length - 1].ts))
      const r = await fetch(`/api/audit?${p}`, { cache: 'no-store' })
      if (r.ok) { const d = await r.json(); setEntries((e) => [...(e ?? []), ...d.entries]); setMore(d.more); setLive(false) }
    } catch {}
    setBusy(false)
  }
  async function verify() {
    setVerifying(true)
    try { const r = await fetch('/api/audit?limit=1&verify=1', { cache: 'no-store' }); if (r.ok) setChain((await r.json()).chain) } catch {}
    setVerifying(false)
  }
  useEffect(() => { verify() }, [])

  const toggleCat = (id: string) => setCats((c) => (c.includes(id) ? c.filter((x) => x !== id) : [...c, id]))

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Tile icon={History} label="Events, last 24 h" value={summary?.last24h} sub="excluding page views" />
        <Tile icon={Pencil} label="Changes, last 24 h" value={summary?.changes24h} sub="users, groups, protection, notes, reports" />
        <Tile icon={KeyRound} label="Failed sign-ins, 24 h" value={summary?.failedLogins24h} tone={summary?.failedLogins24h ? 'warn' : undefined} onClick={() => { setCats(['auth']); setResult('denied') }} />
        <Tile icon={Ban} label="Denied actions, 24 h" value={summary?.denied24h} tone={summary?.denied24h ? 'bad' : undefined} onClick={() => { setCats([]); setResult('denied') }} />
        <button onClick={verify} className="flex items-center gap-3 rounded-2xl border border-nd-line bg-nd-card px-4 py-3.5 text-left shadow-nd hover:border-nd-line-strong" title="Recompute the hash chain over the whole log">
          <span className={`grid h-10 w-10 shrink-0 place-items-center rounded-xl ${!chain ? 'bg-nd-fill text-nd-muted' : chain.ok ? 'bg-st-good/10 text-st-good-fg' : 'bg-st-crit/10 text-st-crit-fg'}`}>
            {verifying ? <Loader2 className="h-5 w-5 animate-spin" /> : chain?.ok === false ? <ShieldAlert className="h-5 w-5" /> : <Link2 className="h-5 w-5" />}
          </span>
          <span className="min-w-0">
            <span className="block text-[15px] font-semibold text-nd-fg">{!chain ? 'Checking…' : chain.ok ? 'Intact' : 'TAMPERED'}</span>
            <span className="block truncate text-[12px] text-nd-dim">{!chain ? 'integrity' : chain.ok ? `${chain.entries.toLocaleString()} entries verified` : chain.brokenAt?.reason}</span>
          </span>
        </button>
      </div>

      {chain && !chain.ok && (
        <div className="flex items-start gap-2 rounded-xl border border-st-crit/40 bg-st-crit/[0.06] px-4 py-3 text-[13px] text-st-crit-fg">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
          <span><b>The audit log was changed outside the dashboard.</b> {chain.brokenAt?.reason} — at line {chain.brokenAt?.line} of <span className="font-mono">{chain.brokenAt?.file}</span>{chain.brokenAt?.ts ? ` (${when(chain.brokenAt.ts)})` : ''}. Entries before that point verified fine.</span>
        </div>
      )}
      {err && <p className="flex items-center gap-2 rounded-lg bg-st-crit/10 px-3 py-2 text-[12.5px] text-st-crit-fg"><AlertTriangle className="h-3.5 w-3.5" /> {err}</p>}

      <div className="overflow-hidden rounded-2xl border border-nd-line bg-nd-card shadow-nd">
        <div className="space-y-2.5 border-b border-nd-line bg-nd-panel px-4 py-3">
          <div className="flex flex-wrap items-center gap-2">
            <label className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-nd-faint" />
              <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search: user, IP, host, text…" className={`${inputCls} w-64 py-1.5 pl-8`} />
            </label>
            <select value={user} onChange={(e) => setUser(e.target.value)} className={`${inputCls} py-1.5`} aria-label="User">
              <option value="">All users</option>
              {(summary?.users ?? []).map((u) => <option key={u} value={u}>{u}</option>)}
            </select>
            <select value={result} onChange={(e) => setResult(e.target.value)} className={`${inputCls} py-1.5`} aria-label="Result">
              <option value="">Any result</option><option value="ok">Succeeded</option><option value="denied">Denied</option><option value="error">Failed</option><option value="conflict">Conflict</option>
            </select>
            <label className="inline-flex cursor-pointer items-center gap-1.5 text-[12.5px] text-nd-fg-3">
              <input type="checkbox" checked={views} onChange={(e) => setViews(e.target.checked)} className="h-4 w-4" /> <Eye className="h-3.5 w-3.5" /> page views
            </label>
            <span className="ml-auto inline-flex items-center gap-2">
              <button onClick={() => setLive((l) => !l)} className={`${btnGhost} ${live ? '!text-st-good-fg' : ''}`} title="Refresh every 5 seconds">
                <RefreshCw className={`h-3.5 w-3.5 ${live ? 'animate-spin [animation-duration:3s]' : ''}`} /> {live ? 'Live' : 'Paused'}
              </button>
              <CsvButton disabled={!entries?.length} onClick={() => entries && downloadCsv('audit-log', entries, [
                { key: 'ts', label: 'time (UTC)', get: (e) => new Date(e.ts).toISOString() },
                { key: 'user', label: 'user' }, { key: 'kind', label: 'session' }, { key: 'category', label: 'category' },
                { key: 'action', label: 'action' }, { key: 'target', label: 'target' }, { key: 'summary', label: 'what happened' },
                { key: 'result', label: 'result' }, { key: 'ip', label: 'client IP' }, { key: 'via', label: 'via', get: (e) => (e.via === 'twingate' ? 'Twingate connector (user address not visible)' : 'direct') }, { key: 'ua', label: 'browser' },
                { key: 'detail', label: 'detail' }, { key: 'hash', label: 'hash' },
              ], `${entries.length} audit log entries`, 'audit-log')} />
            </span>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {CATS.map((c) => {
              const on = cats.includes(c.id)
              return (
                <button key={c.id} onClick={() => toggleCat(c.id)}
                  className={`rounded-full border px-2.5 py-0.5 text-[12px] font-medium transition-colors ${on ? 'border-nd-brand/50 bg-nd-brand/10 text-nd-fg' : 'border-nd-line text-nd-dim hover:text-nd-fg'}`}>{c.label}</button>
              )
            })}
            {(cats.length > 0 || result || user || q) && (
              <button onClick={() => { setCats([]); setResult(''); setUser(''); setQ('') }} className="text-[12px] text-nd-dim underline hover:text-nd-fg">clear filters</button>
            )}
          </div>
        </div>

        {!entries ? (
          <div className="space-y-2 p-4">{[0, 1, 2, 3, 4].map((i) => <div key={i} className="aa-skeleton h-10 rounded-lg" />)}</div>
        ) : entries.length === 0 ? (
          <p className="px-5 py-12 text-center text-[13px] text-nd-dim">No audit entries match these filters.</p>
        ) : (
          <ul className="divide-y divide-nd-line">
            {entries.map((e) => (
              <li key={e.id}>
                <button onClick={() => setOpen((o) => (o === e.id ? null : e.id))} className="grid w-full grid-cols-[16px_150px_minmax(110px,150px)_1fr_auto] items-center gap-3 px-4 py-2.5 text-left hover:bg-nd-fill">
                  {open === e.id ? <ChevronDown className="h-4 w-4 text-nd-dim" /> : <ChevronRight className="h-4 w-4 text-nd-faint" />}
                  <span className="font-mono text-[12px] text-nd-dim" title={new Date(e.ts).toISOString()}>{when(e.ts)}</span>
                  <span className="flex min-w-0 items-center gap-2">
                    {e.user ? <Avatar name={e.user} color={accentFor(e.user)} size={7} /> : <span className="grid h-7 w-7 place-items-center rounded-full bg-nd-fill text-[11px] text-nd-faint">?</span>}
                    <span className="truncate text-[13px] text-nd-fg-2">{e.user || 'anonymous'}</span>
                  </span>
                  <span className="min-w-0">
                    <span className="block truncate text-[13px] text-nd-fg">{e.summary}</span>
                    <span className="block truncate text-[11.5px] text-nd-faint">{CATS.find((c) => c.id === e.category)?.label ?? e.category} · {e.action}{e.via === 'twingate' ? ' · via Twingate' : e.ip ? ` · ${e.ip}` : ''}</span>
                  </span>
                  <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset ${RESULT_CLS[e.result] ?? RESULT_CLS.ok}`}>
                    {e.result === 'ok' ? <CheckCircle2 className="h-3 w-3" /> : <ShieldAlert className="h-3 w-3" />} {e.result === 'ok' ? 'ok' : e.result}
                  </span>
                </button>
                {open === e.id && (
                  <div className="border-t border-nd-line bg-nd-bg px-4 py-3 pl-12 text-[12px]">
                    <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-1">
                      <dt className="text-nd-faint">Time</dt><dd className="font-mono text-nd-fg-3">{new Date(e.ts).toISOString()}</dd>
                      <dt className="text-nd-faint">User</dt><dd className="text-nd-fg-3">{e.user || 'anonymous'}{e.kind && e.kind !== 'user' ? ` (${e.kind})` : ''}</dd>
                      {e.target && <><dt className="text-nd-faint">Target</dt><dd className="font-mono text-nd-fg-3">{e.target}</dd></>}
                      <dt className="text-nd-faint">Client</dt><dd className="text-nd-fg-3">{e.via === 'twingate'
                        ? <span title="Twingate relays each user through its connector, so the user's own address never reaches the dashboard">via Twingate <span className="text-nd-faint">(connector {e.ip}; the user's own address is not visible)</span></span>
                        : (e.ip ?? 'direct (no proxy address)')}{e.ua ? ` · ${e.ua}` : ''}</dd>
                      <dt className="text-nd-faint">Hash</dt><dd className="truncate font-mono text-nd-faint" title={e.hash}>{e.hash}</dd>
                    </dl>
                    {e.detail && <pre className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-nd-line bg-nd-card p-2.5 font-mono text-[11.5px] text-nd-fg-3">{JSON.stringify(e.detail, null, 2)}</pre>}
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
        {more && (
          <div className="border-t border-nd-line px-4 py-3 text-center">
            <button onClick={loadMore} disabled={busy} className={btnGhost}>{busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <History className="h-3.5 w-3.5" />} Load older entries</button>
          </div>
        )}
      </div>
      <p className="flex items-center gap-2 px-1 text-[12px] text-nd-dim"><ShieldCheck className="h-3.5 w-3.5" /> Entries are written by the server as each action happens and chained with SHA-256: removing or editing any line is detected by “Verify”.</p>
    </div>
  )
}

function Tile({ icon: I, label, value, sub, tone, onClick }: { icon: any; label: string; value?: number; sub?: string; tone?: 'warn' | 'bad'; onClick?: () => void }) {
  const cls = tone === 'bad' ? 'bg-st-crit/10 text-st-crit-fg' : tone === 'warn' ? 'bg-st-warn/10 text-st-warn-fg' : 'bg-nd-fill text-nd-muted'
  const Tag = onClick ? 'button' : 'div'
  return (
    <Tag onClick={onClick} className="flex items-center gap-3 rounded-2xl border border-nd-line bg-nd-card px-4 py-3.5 text-left shadow-nd transition-colors hover:border-nd-line-strong">
      <span className={`grid h-10 w-10 shrink-0 place-items-center rounded-xl ${cls}`}><I className="h-5 w-5" /></span>
      <span className="min-w-0">
        <span className="block text-[22px] font-semibold leading-none tracking-[-0.02em] text-nd-fg">{value ?? '–'}</span>
        <span className="mt-1 block truncate text-[12px] text-nd-dim" title={sub}>{label}</span>
      </span>
    </Tag>
  )
}
