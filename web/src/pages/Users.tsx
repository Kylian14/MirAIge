import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { listUsers, createUser, updateUser, deleteUser, roleAtLeast } from '../api'
import type { User } from '../api'
import { useAuth } from '../auth'
import { Panel } from '../components/ui'

const ROLES: User['role'][] = ['viewer', 'operator', 'admin']

const fieldCls =
  'rounded-md border border-line-strong bg-surface-2 px-2.5 py-1.5 font-mono text-sm text-ink outline-none focus:border-mirage'

export default function Users() {
  const { identity } = useAuth()
  const isAdmin = roleAtLeast(identity?.role, 'admin')
  const qc = useQueryClient()

  const { data } = useQuery({
    queryKey: ['/users'],
    queryFn: listUsers,
    enabled: isAdmin,
    refetchInterval: 5000,
  })
  const users = data?.users ?? []
  const managed = data?.managed ?? false

  const [nu, setNu] = useState('')
  const [nrole, setNrole] = useState<User['role']>('viewer')
  const [npw, setNpw] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [pwFor, setPwFor] = useState<string | null>(null)
  const [pwVal, setPwVal] = useState('')
  const [confirmDel, setConfirmDel] = useState<string | null>(null)

  async function run(fn: () => Promise<void>): Promise<void> {
    setError(null)
    try {
      await fn()
      await qc.invalidateQueries({ queryKey: ['/users'] })
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'request failed')
    }
  }

  async function add(): Promise<void> {
    setBusy(true)
    await run(async () => {
      await createUser(nu, nrole, npw)
      setNu('')
      setNpw('')
      setNrole('viewer')
    })
    setBusy(false)
  }

  if (!isAdmin) {
    return (
      <Panel title="Users">
        <p className="px-5 py-6 text-sm text-ink-soft">
          User management requires the <span className="font-mono text-ink">admin</span> role.
        </p>
      </Panel>
    )
  }

  return (
    <>
      {!managed && (
        <Panel title="Users">
          <p className="px-5 py-4 text-sm leading-relaxed text-ink-soft">
            The user store isn’t file-backed, so accounts can’t be edited here — the console is
            running with a single <span className="font-mono text-ink">admin</span> derived from{' '}
            <code className="font-mono text-ink">DASHBOARD_PASSWORD</code>. Mount a{' '}
            <code className="font-mono text-ink">users.json</code> and set{' '}
            <code className="font-mono text-ink">MIRAIGE_USERS_FILE</code> to manage users (see the README).
          </p>
        </Panel>
      )}

      {managed && (
        <Panel title="Add a user">
          <div className="flex flex-wrap items-end gap-3 px-5 py-4">
            <label className="flex flex-col gap-1">
              <span className="text-xs uppercase tracking-wide text-ink-soft">Username</span>
              <input value={nu} onChange={(e) => setNu(e.target.value)} className={`w-40 ${fieldCls}`} />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-xs uppercase tracking-wide text-ink-soft">Role</span>
              <select value={nrole} onChange={(e) => setNrole(e.target.value as User['role'])} className={fieldCls}>
                {ROLES.map((r) => (
                  <option key={r} value={r}>{r}</option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-xs uppercase tracking-wide text-ink-soft">Password</span>
              <input type="password" value={npw} onChange={(e) => setNpw(e.target.value)} className={`w-44 ${fieldCls}`} />
            </label>
            <button
              onClick={add}
              disabled={busy || !nu || !npw}
              className="rounded-md bg-mirage px-3.5 py-1.5 text-sm font-semibold text-surface transition-opacity hover:opacity-90 disabled:opacity-50"
            >
              {busy ? 'Adding…' : 'Add'}
            </button>
          </div>
        </Panel>
      )}

      <Panel title="Users" action={<span className="font-mono text-xs text-ink-soft">{users.length}</span>}>
        {error && <p className="px-5 pt-3 text-sm text-alert">{error}</p>}
        <div className="divide-y divide-line">
          {users.map((u) => {
            const self = u.username === identity?.username
            return (
              <div key={u.username} className="flex flex-wrap items-center gap-3 px-5 py-3">
                <span className="w-40 shrink-0 font-mono text-sm text-ink">
                  {u.username}
                  {self && <span className="ml-1.5 text-xs text-ink-soft">(you)</span>}
                </span>
                <select
                  value={u.role}
                  disabled={!managed}
                  onChange={(e) => run(() => updateUser(u.username, { role: e.target.value as User['role'] }))}
                  className="rounded-md border border-line-strong bg-surface-2 px-2 py-1 font-mono text-xs text-ink outline-none focus:border-mirage disabled:opacity-60"
                >
                  {ROLES.map((r) => (
                    <option key={r} value={r}>{r}</option>
                  ))}
                </select>

                {managed && (
                  <div className="ml-auto flex items-center gap-2">
                    {pwFor === u.username ? (
                      <>
                        <input
                          type="password"
                          autoFocus
                          value={pwVal}
                          onChange={(e) => setPwVal(e.target.value)}
                          placeholder="new password"
                          className="w-40 rounded-md border border-line-strong bg-surface-2 px-2 py-1 font-mono text-xs text-ink outline-none focus:border-mirage"
                        />
                        <button
                          onClick={async () => {
                            await run(() => updateUser(u.username, { password: pwVal }))
                            setPwFor(null)
                            setPwVal('')
                          }}
                          disabled={!pwVal}
                          className="rounded-md border border-line-strong px-2 py-1 text-xs text-ink hover:bg-surface-2 disabled:opacity-50"
                        >
                          Save
                        </button>
                        <button onClick={() => { setPwFor(null); setPwVal('') }} className="text-xs text-ink-soft hover:text-ink">
                          Cancel
                        </button>
                      </>
                    ) : (
                      <button
                        onClick={() => { setPwFor(u.username); setPwVal('') }}
                        className="rounded-md border border-line-strong px-2 py-1 text-xs text-ink-soft transition-colors hover:bg-surface-2 hover:text-ink"
                      >
                        Reset password
                      </button>
                    )}
                    {!self &&
                      (confirmDel === u.username ? (
                        <button
                          onClick={() => { run(() => deleteUser(u.username)); setConfirmDel(null) }}
                          className="rounded-md border border-alert/40 bg-alert/10 px-2 py-1 text-xs text-alert"
                        >
                          Confirm delete
                        </button>
                      ) : (
                        <button
                          onClick={() => setConfirmDel(u.username)}
                          className="rounded-md border border-alert/40 px-2 py-1 text-xs text-alert transition-colors hover:bg-alert/10"
                        >
                          Delete
                        </button>
                      ))}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </Panel>
    </>
  )
}
