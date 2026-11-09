'use client'
import { Suspense, useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { Shield, Loader2, Lock, User, Smartphone, KeyRound, ArrowLeft } from 'lucide-react'

// Sign-in. Step 1: username + password. If the account has two-factor on, the
// server answers with a short-lived challenge and step 2 asks for the 6-digit
// authenticator code (or a one-time recovery code). Server messages (lockout,
// expired step) are shown as-is so people know what to do.
function LoginForm() {
  const router = useRouter()
  const params = useSearchParams()
  const [username, setUsername] = useState('')
  const [pw, setPw] = useState('')
  const [challenge, setChallenge] = useState<string | null>(null)
  const [code, setCode] = useState('')
  const [recovery, setRecovery] = useState(false)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const done = () => {
    const next = params.get('next') || '/analytics'
    router.replace(next.startsWith('/') && !next.startsWith('//') ? next : '/analytics')
  }
  const errorOf = async (r: Response, fallback: string) => {
    try { const d = await r.json(); return d?.error || fallback } catch { return fallback }
  }

  async function submitPassword(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true); setErr('')
    try {
      const r = await fetch('/api/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username, password: pw }) })
      if (!r.ok) {
        setErr(r.status === 401 ? 'Wrong username or password' : await errorOf(r, 'Login is unavailable'))
        setBusy(false)
        return
      }
      const d = await r.json()
      if (d?.mfa && d.challenge) { setChallenge(d.challenge); setPw(''); setBusy(false); return }
      done()
    } catch {
      setErr('Network error'); setBusy(false)
    }
  }

  async function submitCode(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true); setErr('')
    try {
      const r = await fetch('/api/login/mfa', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ challenge, code }) })
      if (!r.ok) {
        const d = await r.json().catch(() => ({}))
        setErr(d?.error || 'That code is not right')
        if (d?.restart) { setChallenge(null); setCode('') }
        setBusy(false)
        return
      }
      const d = await r.json()
      if (d?.usedRecovery) sessionStorage.setItem('xs.recoveryNote', String(d.recoveryLeft))
      done()
    } catch {
      setErr('Network error'); setBusy(false)
    }
  }

  const inputCls = 'w-full rounded-xl border border-nd-line bg-nd-bg py-2.5 pl-9 pr-3 text-[14px] text-nd-fg outline-none transition-colors focus:border-nd-brand'
  const header = (
    <div className="mb-6 flex items-center gap-3">
      <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-nd-brand/15 text-nd-brand">
        <Shield className="h-5 w-5" strokeWidth={2.2} />
      </span>
      <div>
        <h1 className="text-[15px] font-semibold tracking-[-0.01em] text-nd-fg">xdp-sentinel</h1>
        <p className="text-[12px] text-nd-dim">{challenge ? 'Two-factor authentication' : 'Sign in to the console'}</p>
      </div>
    </div>
  )

  if (challenge) {
    return (
      <form onSubmit={submitCode} className="w-full max-w-sm rounded-2xl border border-nd-line bg-nd-card p-7 shadow-nd">
        {header}
        <p className="mb-4 text-[13px] text-nd-fg-3">
          {recovery ? 'Enter one of your recovery codes. Each code works once.' : 'Open your authenticator app and enter the 6-digit code for xdp-sentinel.'}
        </p>
        <label htmlFor="code" className="block text-[12px] font-medium text-nd-dim">{recovery ? 'Recovery code' : 'Authentication code'}</label>
        <div className="relative mt-1.5">
          {recovery ? <KeyRound className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-nd-dim" /> : <Smartphone className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-nd-dim" />}
          <input id="code" autoFocus value={code}
            onChange={(e) => setCode(recovery ? e.target.value : e.target.value.replace(/\D/g, '').slice(0, 6))}
            inputMode={recovery ? 'text' : 'numeric'} autoComplete="one-time-code" placeholder={recovery ? 'xxxx-xxxx-xxxx' : '123456'}
            className={`${inputCls} font-mono tracking-[0.25em]`} />
        </div>
        {err && <p className="mt-2.5 text-[12.5px] text-st-crit-fg">{err}</p>}
        <button type="submit" disabled={busy || (recovery ? code.length < 12 : code.length !== 6)}
          className="mt-5 flex w-full items-center justify-center gap-2 rounded-xl bg-nd-brand px-4 py-2.5 text-[13.5px] font-semibold text-black transition-opacity disabled:opacity-50">
          {busy && <Loader2 className="h-4 w-4 animate-spin" />} Verify
        </button>
        <div className="mt-4 flex items-center justify-between text-[12px]">
          <button type="button" onClick={() => { setChallenge(null); setCode(''); setErr('') }} className="inline-flex items-center gap-1 text-nd-dim hover:text-nd-fg"><ArrowLeft className="h-3.5 w-3.5" /> Back</button>
          <button type="button" onClick={() => { setRecovery((r) => !r); setCode(''); setErr('') }} className="text-nd-dim underline hover:text-nd-fg">
            {recovery ? 'Use the authenticator app' : 'Lost your phone? Use a recovery code'}
          </button>
        </div>
      </form>
    )
  }

  return (
    <form onSubmit={submitPassword} className="w-full max-w-sm rounded-2xl border border-nd-line bg-nd-card p-7 shadow-nd">
      {header}
      <label htmlFor="user" className="block text-[12px] font-medium text-nd-dim">Username</label>
      <div className="relative mt-1.5">
        <User className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-nd-dim" />
        <input id="user" type="text" autoFocus autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} className={inputCls} placeholder="username" />
      </div>
      <label htmlFor="pw" className="mt-4 block text-[12px] font-medium text-nd-dim">Password</label>
      <div className="relative mt-1.5">
        <Lock className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-nd-dim" />
        <input id="pw" type="password" autoComplete="current-password" value={pw} onChange={(e) => setPw(e.target.value)} className={inputCls} placeholder="••••••••" />
      </div>
      {err && <p className="mt-2.5 text-[12.5px] text-st-crit-fg">{err}</p>}
      <button type="submit" disabled={busy || !pw}
        className="mt-5 flex w-full items-center justify-center gap-2 rounded-xl bg-nd-brand px-4 py-2.5 text-[13.5px] font-semibold text-black transition-opacity disabled:opacity-50">
        {busy && <Loader2 className="h-4 w-4 animate-spin" />} Sign in
      </button>
    </form>
  )
}

export default function Login() {
  return (
    <div className="nd-dark flex min-h-screen items-center justify-center bg-nd-bg px-4">
      <Suspense fallback={<div className="text-[13px] text-nd-dim">Loading…</div>}>
        <LoginForm />
      </Suspense>
    </div>
  )
}
