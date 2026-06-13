import { useState } from 'react'
import type { FormEvent } from 'react'
import { useAuth } from '../auth'

export default function Login() {
  const { signIn } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      await signIn(username, password)
    } catch {
      setError('Those credentials were not accepted.')
      setBusy(false)
    }
  }

  return (
    <div className="dune min-h-screen grid place-items-center px-4">
      {/* heat-shimmer band on the horizon */}
      <div aria-hidden className="shimmer pointer-events-none fixed inset-x-0 bottom-0 h-1/3" />

      <main className="relative w-full max-w-sm">
        <div className="mb-7 text-center">
          <div className="wordmark text-3xl">
            MIR<span className="text-mirage">[</span>AI<span className="text-mirage">]</span>GE
          </div>
          <p className="mt-2 text-sm text-ink-soft">Defensive deception console</p>
        </div>

        <form
          onSubmit={submit}
          className="rounded-[var(--radius)] border border-line-strong bg-surface/85 p-6 shadow-[0_1px_0_#fff_inset,0_18px_40px_-24px_rgba(60,40,12,0.5)] backdrop-blur-sm"
        >
          <label htmlFor="user" className="mb-1.5 block text-xs font-medium uppercase tracking-wide text-ink-soft">
            Username
          </label>
          <input
            id="user"
            type="text"
            value={username}
            onChange={(e) => {
              setUsername(e.target.value)
              if (error) setError('')
            }}
            autoFocus
            autoComplete="username"
            placeholder="admin"
            className="w-full rounded-lg border border-line-strong bg-surface-2 px-3 py-2.5 font-mono text-ink outline-none transition-colors placeholder:text-ink-soft/50 focus:border-sun"
          />

          <label htmlFor="pw" className="mb-1.5 mt-4 block text-xs font-medium uppercase tracking-wide text-ink-soft">
            Password
          </label>
          <input
            id="pw"
            type="password"
            value={password}
            onChange={(e) => {
              setPassword(e.target.value)
              if (error) setError('')
            }}
            autoComplete="current-password"
            aria-invalid={!!error}
            className="w-full rounded-lg border border-line-strong bg-surface-2 px-3 py-2.5 font-mono text-ink outline-none transition-colors focus:border-sun"
          />

          {error && (
            <p role="alert" className="mt-2 text-sm text-alert">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={busy || !password}
            className="mt-5 flex w-full items-center justify-center gap-2 rounded-lg bg-sun px-4 py-2.5 font-semibold text-[#2c2114] transition hover:bg-sun-bright disabled:cursor-not-allowed disabled:opacity-45"
          >
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        <p className="mt-5 text-center text-xs text-ink-soft/80">Their LLM, their bill.</p>
      </main>
    </div>
  )
}
