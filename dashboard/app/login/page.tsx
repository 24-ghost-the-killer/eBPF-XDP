'use client'
import { Suspense, useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { Shield, Loader2, Lock, User } from 'lucide-react'

function LoginForm() {
  const router = useRouter()
  const params = useSearchParams()
  const [username, setUsername] = useState('')
  const [pw, setPw] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      const r = await fetch('/api/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username, password: pw }),
      })
      if (!r.ok) {
        setErr(r.status === 401 ? 'Wrong username or password' : 'Login is unavailable')
        setBusy(false)
        return
      }
      const next = params.get('next') || '/analytics'
      router.replace(next.startsWith('/') ? next : '/analytics')
    } catch {
      setErr('Network error')
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} className="w-full max-w-sm rounded-2xl border border-nd-line bg-nd-card p-7 shadow-nd">
      <div className="mb-6 flex items-center gap-3">
        <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-nd-brand/15 text-nd-brand">
          <Shield className="h-5 w-5" strokeWidth={2.2} />
        </span>
        <div>
          <h1 className="text-[15px] font-semibold tracking-[-0.01em] text-nd-fg">xdp-sentinel</h1>
          <p className="text-[12px] text-nd-dim">Sign in to the console</p>
        </div>
      </div>

      <label htmlFor="user" className="block text-[12px] font-medium text-nd-dim">Username</label>
      <div className="relative mt-1.5">
        <User className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-nd-dim" />
        <input
          id="user"
          type="text"
          autoFocus
          autoComplete="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          className="w-full rounded-xl border border-nd-line bg-nd-bg py-2.5 pl-9 pr-3 text-[14px] text-nd-fg outline-none transition-colors focus:border-nd-brand"
          placeholder="username"
        />
      </div>

      <label htmlFor="pw" className="mt-4 block text-[12px] font-medium text-nd-dim">Password</label>
      <div className="relative mt-1.5">
        <Lock className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-nd-dim" />
        <input
          id="pw"
          type="password"
          autoComplete="current-password"
          value={pw}
          onChange={(e) => setPw(e.target.value)}
          className="w-full rounded-xl border border-nd-line bg-nd-bg py-2.5 pl-9 pr-3 text-[14px] text-nd-fg outline-none transition-colors focus:border-nd-brand"
          placeholder="••••••••"
        />
      </div>

      {err && <p className="mt-2.5 text-[12.5px] text-st-crit-fg">{err}</p>}

      <button
        type="submit"
        disabled={busy || !pw}
        className="mt-5 flex w-full items-center justify-center gap-2 rounded-xl bg-nd-brand px-4 py-2.5 text-[13.5px] font-semibold text-black transition-opacity disabled:opacity-50"
      >
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
