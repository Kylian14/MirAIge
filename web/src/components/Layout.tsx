import { Outlet, useLocation } from 'react-router-dom'
import Sidebar from './Sidebar'
import { useAuth } from '../auth'
import { useApi, useLiveStream } from '../lib'
import type { Metrics } from '../lib'

const TITLES: Record<string, string> = {
  '/': 'Overview',
  '/engagements': 'Engagements',
  '/detection': 'Detection',
  '/attacks': 'Red team',
  '/users': 'Users',
}

export default function Layout() {
  const { pathname } = useLocation()
  const { identity } = useAuth()
  useLiveStream() // one live connection feeds the query cache for the whole console
  const metrics = useApi<Metrics>('/metrics')
  const sessions = metrics.data?.active_sessions ?? 0
  const engaged = sessions > 0

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-10 flex h-14 items-center justify-between border-b border-line-strong bg-bg/85 px-6 backdrop-blur">
          <h1 className="text-sm font-semibold text-ink">{TITLES[pathname] ?? 'Mir[AI]ge'}</h1>
          <div className="flex items-center gap-3">
            {identity && (
              <span className="hidden items-center gap-1.5 text-xs sm:inline-flex">
                <span className="font-mono text-ink">{identity.username}</span>
                <span className="rounded border border-line-strong bg-surface-2 px-1.5 py-0.5 font-mono uppercase tracking-wide text-ink-soft">
                  {identity.role}
                </span>
              </span>
            )}
            <span
              className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs ${
                engaged ? 'border-ghost/40 bg-ghost/10 text-ghost' : 'border-ok/40 bg-ok/10 text-ok'
              }`}
            >
              <span className={`h-1.5 w-1.5 rounded-full ${engaged ? 'bg-ghost' : 'bg-ok'}`} />
              {engaged ? `${sessions} in the mirage` : 'quiet'}
            </span>
          </div>
        </header>
        <main className="mx-auto w-full max-w-6xl flex-1 space-y-5 px-6 py-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
