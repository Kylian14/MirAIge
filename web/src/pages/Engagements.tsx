import { useState } from 'react'
import type { ReactNode } from 'react'
import { useApi } from '../lib'
import type { Incidents } from '../lib'
import { Panel, StatePill, SkeletonRows } from '../components/ui'
import Drawer from '../components/Drawer'

function Field({ label, value, mono }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="border-b border-line py-2.5 last:border-0">
      <dt className="text-xs uppercase tracking-wide text-ink-soft">{label}</dt>
      <dd className={`mt-0.5 break-all text-sm text-ink ${mono ? 'font-mono' : ''}`}>{value || '—'}</dd>
    </div>
  )
}

export default function Engagements() {
  const incidents = useApi<Incidents>('/incidents')
  const active = incidents.data?.active ?? []
  const [selectedId, setSelectedId] = useState<string | null>(null)
  // resolve against the latest poll so the drawer stays live
  const current = active.find((i) => i.request_id === selectedId) ?? null

  return (
    <>
      <Panel
        title="Live engagements"
        action={<span className="font-mono text-xs text-ink-soft">{active.length} active</span>}
      >
        {incidents.isPending ? (
          <SkeletonRows n={5} />
        ) : active.length === 0 ? (
          <div className="px-5 py-12 text-center">
            <p className="text-ink">The mirage is quiet.</p>
            <p className="mt-1 text-sm text-ink-soft">
              No attackers are being rerouted. A session appears here the moment one is flagged.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs uppercase tracking-wide text-ink-soft">
                  <th className="px-5 py-2 font-medium">Source</th>
                  <th className="px-5 py-2 font-medium">Session</th>
                  <th className="px-5 py-2 font-medium">State</th>
                  <th className="px-5 py-2 font-medium">Persona</th>
                  <th className="px-5 py-2" />
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {active.map((s) => (
                  <tr
                    key={s.request_id}
                    onClick={() => setSelectedId(s.request_id)}
                    className="cursor-pointer transition-colors hover:bg-surface-2/60"
                  >
                    <td className="px-5 py-2.5 font-mono text-ink">{s.attacker_ip}</td>
                    <td className="px-5 py-2.5 font-mono text-ink-soft">
                      {s.attacker_session ? s.attacker_session.slice(0, 14) + '…' : '—'}
                    </td>
                    <td className="px-5 py-2.5">
                      <StatePill state={s.state} />
                    </td>
                    <td className="px-5 py-2.5 text-ink-soft">{s.ghost_persona ?? '—'}</td>
                    <td className="px-5 py-2.5 text-right text-ink-soft/60">›</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Drawer open={!!current} onClose={() => setSelectedId(null)} title="Engagement">
        {current && (
          <>
            <div className="mb-4 flex items-center gap-2">
              <StatePill state={current.state} />
              <span className="font-mono text-sm text-ink">{current.attacker_ip}</span>
            </div>
            <dl>
              <Field label="Session (mg_session)" value={current.attacker_session} mono />
              <Field label="Ghost persona" value={current.ghost_persona} />
              <Field label="Ghost session" value={current.ghost_session_id} mono />
              <Field label="Protected target" value={current.target_instance_id} />
              <Field label="Expires" value={current.expires_at} mono />
              <Field label="Request id" value={current.request_id} mono />
            </dl>
          </>
        )}
      </Drawer>
    </>
  )
}
