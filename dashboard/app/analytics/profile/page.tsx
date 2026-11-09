'use client'
import { Suspense, useCallback, useEffect, useState, type ReactNode } from 'react'
import { useSearchParams } from 'next/navigation'
import { Avatar, accentFor, relTime, PermissionPreview, readError, inputCls, btnPrimary, btnGhost, type Catalog } from '@/components/aa/admin'
import {
  ShieldCheck, ShieldAlert, KeyRound, Smartphone, Loader2, Check, AlertTriangle, Copy, Download, LogOut, History,
  Eye, EyeOff, RefreshCw, X, UserRound, Lock,
} from 'lucide-react'

// Your own account: who you are and what you can do, your password, two-factor
// authentication (authenticator app + recovery codes), your sessions and your
// recent activity. Every change here is written to the audit log.

interface Profile {
  username: string; group: string; perms: string[]; createdAt: number; lastLogin: number
  mfa: { enabled: boolean; enabledAt: number; recoveryLeft: number; required: boolean; pending: boolean }
  activity: { ts: number; action: string; summary: string; result: string; ip: string | null }[]
  catalog: Catalog
}

export default function ProfilePage() {
  return <Suspense fallback={<div className="aa-skeleton h-64 rounded-2xl" />}><ProfileView /></Suspense>
}

async function post(body: Record<string, unknown>) {
  const r = await fetch('/api/profile', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
  if (!r.ok) throw new Error(await readError(r))
  return r.json()
}

function ProfileView() {
  const sp = useSearchParams()
  const [p, setP] = useState<Profile | null>(null)
  const [err, setErr] = useState('')
  const [recoveryNote, setRecoveryNote] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const r = await fetch('/api/profile', { cache: 'no-store' })
      if (!r.ok) { setErr(await readError(r)); return }
      setP(await r.json()); setErr('')
    } catch { setErr('could not reach the server') }
  }, [])
  useEffect(() => {
    load()
    const n = sessionStorage.getItem('xs.recoveryNote')
    if (n !== null) { setRecoveryNote(n); sessionStorage.removeItem('xs.recoveryNote') }
  }, [load])

  if (!p) return err ? <Err msg={err} /> : <div className="aa-skeleton h-64 rounded-2xl" />

  const required = sp.get('setup') === 'required' || (p.mfa.required && !p.mfa.enabled)

  return (
    <div className="mx-auto max-w-[1000px] space-y-5">
      {required && !p.mfa.enabled && (
        <div className="flex items-start gap-2.5 rounded-xl border border-st-warn/40 bg-st-warn/10 px-4 py-3 text-[13px] text-st-warn-fg">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
          <div><b>Your group requires two-factor authentication.</b> Set it up below — the rest of the dashboard stays locked until you do.</div>
        </div>
      )}
      {recoveryNote !== null && (
        <div className="flex items-start gap-2.5 rounded-xl border border-st-warn/40 bg-st-warn/10 px-4 py-3 text-[13px] text-st-warn-fg">
          <KeyRound className="mt-0.5 h-4 w-4 shrink-0" />
          <div>You signed in with a recovery code — <b>{recoveryNote} left</b>. If you lost your phone, turn two-factor off and set it up again with your new phone, or generate new recovery codes.</div>
        </div>
      )}

      {/* account */}
      <section className="flex flex-wrap items-center gap-4 rounded-2xl border border-nd-line bg-nd-card p-5 shadow-nd">
        <Avatar name={p.username} color={accentFor(p.group)} size={10} />
        <div className="min-w-0 flex-1">
          <h2 className="text-[20px] font-semibold tracking-[-0.02em] text-nd-fg">{p.username}</h2>
          <p className="text-[12.5px] text-nd-dim">
            Group <b className="text-nd-fg-2">{p.group}</b> · member since {p.createdAt ? new Date(p.createdAt * 1000).toLocaleDateString() : 'before tracking'} · last sign-in {relTime(p.lastLogin)}
          </p>
        </div>
        <MfaBadge on={p.mfa.enabled} />
      </section>

      <div className="grid gap-5 lg:grid-cols-2">
        <TwoFactor p={p} reload={load} />
        <div className="space-y-5">
          <Password />
          <Sessions />
        </div>
      </div>

      <Card icon={UserRound} title="What you can do" sub={`from your group ${p.group} — ask an admin to change it`}>
        <PermissionPreview perms={p.perms} cat={p.catalog} />
      </Card>

      <Card icon={History} title="Your recent activity" sub="from the audit log — sign-ins and changes you made">
        {p.activity.length === 0 ? <p className="text-[13px] text-nd-dim">Nothing yet.</p> : (
          <ul className="divide-y divide-nd-line rounded-xl border border-nd-line">
            {p.activity.map((a, i) => (
              <li key={i} className="flex flex-wrap items-center gap-3 px-3.5 py-2 text-[12.5px]">
                <span className="w-36 font-mono text-[11.5px] text-nd-dim">{new Date(a.ts).toLocaleString([], { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })}</span>
                <span className="min-w-0 flex-1 truncate text-nd-fg-2">{a.summary}</span>
                {a.result !== 'ok' && <span className="rounded-full bg-st-crit/10 px-2 py-0.5 text-[11px] text-st-crit-fg">{a.result}</span>}
                {a.ip && <span className="font-mono text-[11px] text-nd-faint">{a.ip}</span>}
              </li>
            ))}
          </ul>
        )}
        <p className="mt-2 text-[11.5px] text-nd-faint">Don’t recognise a sign-in? Change your password and sign out everywhere.</p>
      </Card>
    </div>
  )
}

function Err({ msg }: { msg: string }) {
  return <p className="flex items-center gap-2 rounded-lg bg-st-crit/10 px-3 py-2 text-[12.5px] text-st-crit-fg"><AlertTriangle className="h-3.5 w-3.5" /> {msg}</p>
}
function Ok({ msg }: { msg: string }) {
  return <p className="flex items-center gap-1.5 text-[12.5px] text-st-good-fg"><Check className="h-3.5 w-3.5" /> {msg}</p>
}
function MfaBadge({ on }: { on: boolean }) {
  return on
    ? <span className="inline-flex items-center gap-1.5 rounded-full bg-st-good/10 px-3 py-1 text-[12px] font-medium text-st-good-fg ring-1 ring-inset ring-st-good/20"><ShieldCheck className="h-3.5 w-3.5" /> Two-factor on</span>
    : <span className="inline-flex items-center gap-1.5 rounded-full bg-st-warn/10 px-3 py-1 text-[12px] font-medium text-st-warn-fg ring-1 ring-inset ring-st-warn/20"><ShieldAlert className="h-3.5 w-3.5" /> Two-factor off</span>
}
function Card({ icon: I, title, sub, children, actions }: { icon: any; title: string; sub?: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="rounded-2xl border border-nd-line bg-nd-card shadow-nd">
      <header className="flex items-start justify-between gap-3 px-5 pb-3 pt-4">
        <div className="flex items-start gap-2.5">
          <span className="mt-0.5 grid h-7 w-7 place-items-center rounded-lg bg-nd-fill text-nd-muted"><I className="h-3.5 w-3.5" /></span>
          <div><h3 className="text-[14px] font-semibold text-nd-fg">{title}</h3>{sub && <p className="text-[12px] text-nd-dim">{sub}</p>}</div>
        </div>
        {actions}
      </header>
      <div className="px-5 pb-5">{children}</div>
    </section>
  )
}
function CodeInput({ value, onChange, autoFocus }: { value: string; onChange: (v: string) => void; autoFocus?: boolean }) {
  return (
    <input value={value} onChange={(e) => onChange(e.target.value.replace(/\D/g, '').slice(0, 6))} autoFocus={autoFocus}
      inputMode="numeric" autoComplete="one-time-code" placeholder="6-digit code"
      className={`${inputCls} w-40 font-mono tracking-[0.25em]`} />
  )
}
function PasswordField({ value, onChange, placeholder, autoComplete }: { value: string; onChange: (v: string) => void; placeholder: string; autoComplete: string }) {
  const [show, setShow] = useState(false)
  return (
    <span className="relative block">
      <input type={show ? 'text' : 'password'} value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} autoComplete={autoComplete} className={`${inputCls} w-full pr-9`} />
      <button type="button" onClick={() => setShow((s) => !s)} className="absolute right-2 top-1/2 -translate-y-1/2 text-nd-faint hover:text-nd-fg">{show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</button>
    </span>
  )
}

// ---- two-factor ---------------------------------------------------------

function RecoveryCodes({ codes, username, onDone }: { codes: string[]; username: string; onDone: () => void }) {
  const [saved, setSaved] = useState(false)
  const text = `xdp-sentinel recovery codes for ${username}\nGenerated ${new Date().toLocaleString()}\nEach code works ONCE. Keep them somewhere safe (not on the same phone).\n\n${codes.join('\n')}\n`
  const download = () => {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }))
    const a = document.createElement('a'); a.href = url; a.download = `xdp-sentinel-recovery-${username}.txt`; a.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000); setSaved(true)
  }
  return (
    <div className="space-y-3">
      <div className="flex items-start gap-2 rounded-xl border border-st-warn/30 bg-st-warn/[0.06] px-3.5 py-2.5 text-[12.5px] text-st-warn-fg">
        <KeyRound className="mt-0.5 h-4 w-4 shrink-0" />
        <span><b>Save these recovery codes now — they are shown only once.</b> If you lose your phone, each code lets you sign in one time.</span>
      </div>
      <ol className="grid grid-cols-2 gap-1.5 rounded-xl border border-nd-line bg-nd-panel p-3 font-mono text-[13px] text-nd-fg">
        {codes.map((c) => <li key={c} className="text-center">{c}</li>)}
      </ol>
      <div className="flex flex-wrap gap-2">
        <button onClick={download} className={btnGhost}><Download className="h-3.5 w-3.5" /> Download .txt</button>
        <button onClick={() => { navigator.clipboard?.writeText(codes.join('\n')); setSaved(true) }} className={btnGhost}><Copy className="h-3.5 w-3.5" /> Copy</button>
        <button onClick={onDone} disabled={!saved} title={saved ? undefined : 'download or copy them first'} className={`${btnPrimary} ml-auto`}><Check className="h-4 w-4" /> I’ve saved them</button>
      </div>
    </div>
  )
}

function TwoFactor({ p, reload }: { p: Profile; reload: () => void }) {
  const [setup, setSetup] = useState<{ secret: string; uri: string; qr: string } | null>(null)
  const [code, setCode] = useState('')
  const [codes, setCodes] = useState<string[] | null>(null)
  const [mode, setMode] = useState<null | 'disable' | 'regen'>(null)
  const [pw, setPw] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')
  const [showKey, setShowKey] = useState(false)

  const run = async (fn: () => Promise<void>) => { setBusy(true); setErr(''); setOk(''); try { await fn() } catch (e) { setErr(e instanceof Error ? e.message : 'failed') } setBusy(false) }
  const start = () => run(async () => { setSetup(await post({ action: 'mfa_setup' })); setCode('') })
  const confirm = () => run(async () => { const d = await post({ action: 'mfa_enable', code }); setCodes(d.recoveryCodes); setSetup(null); setCode('') })
  const regen = () => run(async () => { const d = await post({ action: 'mfa_recovery', code }); setCodes(d.recoveryCodes); setMode(null); setCode('') })
  const disable = () => run(async () => { await post({ action: 'mfa_disable', password: pw, code }); setMode(null); setPw(''); setCode(''); setOk('Two-factor is off.'); reload() })

  return (
    <Card icon={Smartphone} title="Two-factor authentication" sub="a code from your phone on top of your password"
      actions={<MfaBadge on={p.mfa.enabled} />}>
      {codes ? (
        <RecoveryCodes codes={codes} username={p.username} onDone={() => { setCodes(null); setOk('Two-factor is on. You’ll be asked for a code at every sign-in.'); reload() }} />
      ) : setup ? (
        <div className="space-y-4">
          <ol className="list-decimal space-y-1 pl-5 text-[12.5px] text-nd-fg-3">
            <li>Install an authenticator app (Google or Microsoft Authenticator, Authy, 1Password, Bitwarden…).</li>
            <li>Scan this QR code with it — or type the key by hand.</li>
            <li>Enter the 6-digit code the app shows.</li>
          </ol>
          <div className="flex flex-wrap items-start gap-4">
            <div className="rounded-xl bg-white p-2 shadow-nd [&_svg]:h-44 [&_svg]:w-44" dangerouslySetInnerHTML={{ __html: setup.qr }} />
            <div className="min-w-0 flex-1 space-y-2 text-[12px] text-nd-dim">
              <div>Can’t scan? Enter this key in the app (time-based, 6 digits):</div>
              <div className="flex items-center gap-2">
                <code className="break-all rounded-lg border border-nd-line bg-nd-panel px-2 py-1.5 font-mono text-[12.5px] text-nd-fg">{showKey ? setup.secret.match(/.{1,4}/g)!.join(' ') : '•••• •••• •••• ••••'}</code>
                <button onClick={() => setShowKey((s) => !s)} className="text-nd-dim hover:text-nd-fg" title={showKey ? 'Hide' : 'Show'}>{showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</button>
                <button onClick={() => navigator.clipboard?.writeText(setup.secret)} className="text-nd-dim hover:text-nd-fg" title="Copy"><Copy className="h-4 w-4" /></button>
              </div>
              <div className="pt-2">
                <form onSubmit={(e) => { e.preventDefault(); confirm() }} className="flex flex-wrap items-center gap-2">
                  <CodeInput value={code} onChange={setCode} autoFocus />
                  <button type="submit" disabled={busy || code.length !== 6} className={btnPrimary}>{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />} Turn on</button>
                  <button type="button" onClick={() => setSetup(null)} className={btnGhost}>Cancel</button>
                </form>
              </div>
            </div>
          </div>
        </div>
      ) : p.mfa.enabled ? (
        <div className="space-y-3">
          <p className="text-[13px] text-nd-fg-3">On since {new Date(p.mfa.enabledAt * 1000).toLocaleDateString()}. Every sign-in asks for a code from your app.</p>
          <p className={`text-[12.5px] ${p.mfa.recoveryLeft <= 3 ? 'text-st-warn-fg' : 'text-nd-dim'}`}>
            <KeyRound className="mr-1 inline h-3.5 w-3.5" /> {p.mfa.recoveryLeft} of 10 recovery codes left{p.mfa.recoveryLeft <= 3 ? ' — generate new ones' : ''}.
          </p>
          {mode === null && (
            <div className="flex flex-wrap gap-2">
              <button onClick={() => { setMode('regen'); setErr(''); setOk('') }} className={btnGhost}><RefreshCw className="h-3.5 w-3.5" /> New recovery codes</button>
              {!p.mfa.required && <button onClick={() => { setMode('disable'); setErr(''); setOk('') }} className={`${btnGhost} !text-st-crit-fg`}><X className="h-3.5 w-3.5" /> Turn off</button>}
            </div>
          )}
          {p.mfa.required && <p className="text-[11.5px] text-nd-faint"><Lock className="mr-1 inline h-3 w-3" />Your group requires two-factor, so it can’t be turned off.</p>}
          {mode === 'regen' && (
            <form onSubmit={(e) => { e.preventDefault(); regen() }} className="space-y-2 rounded-xl border border-nd-line bg-nd-panel p-3">
              <p className="text-[12.5px] text-nd-fg-3">Enter a current code from your app. Your old recovery codes will stop working.</p>
              <div className="flex flex-wrap items-center gap-2">
                <CodeInput value={code} onChange={setCode} autoFocus />
                <button type="submit" disabled={busy || code.length !== 6} className={btnPrimary}>{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />} Generate</button>
                <button type="button" onClick={() => setMode(null)} className={btnGhost}>Cancel</button>
              </div>
            </form>
          )}
          {mode === 'disable' && (
            <form onSubmit={(e) => { e.preventDefault(); disable() }} className="space-y-2 rounded-xl border border-st-crit/30 bg-st-crit/[0.04] p-3">
              <p className="text-[12.5px] text-nd-fg-3">Confirm with your password and a current code. Your account will be protected by the password only.</p>
              <PasswordField value={pw} onChange={setPw} placeholder="your password" autoComplete="current-password" />
              <div className="flex flex-wrap items-center gap-2">
                <CodeInput value={code} onChange={setCode} />
                <button type="submit" disabled={busy || !pw || code.length !== 6} className="inline-flex items-center gap-1.5 rounded-lg bg-st-crit px-3.5 py-2 text-[13px] font-semibold text-white hover:opacity-90 disabled:opacity-40">{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <X className="h-4 w-4" />} Turn off two-factor</button>
                <button type="button" onClick={() => setMode(null)} className={btnGhost}>Cancel</button>
              </div>
            </form>
          )}
        </div>
      ) : (
        <div className="space-y-3">
          <p className="text-[13px] text-nd-fg-3">Protect your account with a 6-digit code from an authenticator app on your phone. Even if someone learns your password, they can’t sign in without your phone.</p>
          <button onClick={start} disabled={busy} className={btnPrimary}>{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />} Set up two-factor</button>
        </div>
      )}
      {err && <div className="mt-3"><Err msg={err} /></div>}
      {ok && <div className="mt-3"><Ok msg={ok} /></div>}
    </Card>
  )
}

// ---- password + sessions ---------------------------------------------------

function Password() {
  const [cur, setCur] = useState('')
  const [next, setNext] = useState('')
  const [again, setAgain] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')
  const mismatch = again.length > 0 && next !== again
  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true); setErr(''); setOk('')
    try { await post({ action: 'password', current: cur, next }); setCur(''); setNext(''); setAgain(''); setOk('Password changed. Your other sessions were signed out.') }
    catch (e2) { setErr(e2 instanceof Error ? e2.message : 'failed') }
    setBusy(false)
  }
  return (
    <Card icon={KeyRound} title="Password" sub="at least 8 characters — changing it signs out your other sessions">
      <form onSubmit={submit} className="space-y-2.5">
        <PasswordField value={cur} onChange={setCur} placeholder="current password" autoComplete="current-password" />
        <PasswordField value={next} onChange={setNext} placeholder="new password" autoComplete="new-password" />
        <PasswordField value={again} onChange={setAgain} placeholder="new password again" autoComplete="new-password" />
        {mismatch && <p className="text-[12px] text-st-warn-fg">The new passwords don’t match.</p>}
        <button type="submit" disabled={busy || !cur || next.length < 8 || next !== again} className={btnPrimary}>{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />} Change password</button>
        {err && <Err msg={err} />}
        {ok && <Ok msg={ok} />}
      </form>
    </Card>
  )
}

function Sessions() {
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')
  return (
    <Card icon={LogOut} title="Sessions" sub="every browser where you are signed in">
      <p className="mb-3 text-[12.5px] text-nd-fg-3">Lost a laptop, or signed in on a shared computer? End every session except this one.</p>
      <button disabled={busy} className={btnGhost} onClick={async () => {
        setBusy(true); setErr(''); setMsg('')
        try { await post({ action: 'signout_others' }); setMsg('All your other sessions are signed out.') } catch (e) { setErr(e instanceof Error ? e.message : 'failed') }
        setBusy(false)
      }}>{busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <LogOut className="h-3.5 w-3.5" />} Sign out everywhere else</button>
      {msg && <div className="mt-2"><Ok msg={msg} /></div>}
      {err && <div className="mt-2"><Err msg={err} /></div>}
    </Card>
  )
}
