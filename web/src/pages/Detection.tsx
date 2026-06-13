import { useApi, fmt } from '../lib'
import type { Stats } from '../lib'
import { Panel, FunnelStep } from '../components/ui'

const COUNTERS: [string, string][] = [
  ['events_total', 'Events screened'],
  ['t0_eliminated', 'T0 — eliminated (Sigma)'],
  ['t0_critical_triggered', 'T0 — critical (Sigma)'],
  ['t1_evaluations', 'T1 — evaluated'],
  ['t1_high_triggered', 'T1 — high confidence'],
  ['t1_benign', 'T1 — benign'],
  ['t2_evaluations', 'T2 — LLM evaluated'],
  ['t2_triggered', 'T2 — LLM triggered'],
  ['cumulative_recon_triggered', 'Cumulative OWASP recon'],
  ['canary_triggered', 'Reverse-PI canary (AI)'],
]

export default function Detection() {
  const stats = useApi<Stats>('/stats')
  const c = stats.data?.counters ?? {}

  return (
    <>
      <Panel title="Cascade">
        <div className="flex items-end gap-4 px-5 py-5">
          <FunnelStep label="Events screened" value={c.events_total} tone="bg-ink/25" />
          <FunnelStep label="T0 eliminated" value={c.t0_eliminated} tone="bg-ok/60" />
          <FunnelStep label="Recon flagged" value={c.cumulative_recon_triggered} tone="bg-watch/70" />
          <FunnelStep label="Canary (AI)" value={c.canary_triggered} tone="bg-alert/70" />
        </div>
      </Panel>

      <Panel title="Counters">
        <dl className="divide-y divide-line">
          {COUNTERS.map(([k, label]) => (
            <div key={k} className="flex items-center justify-between px-5 py-2.5">
              <dt className="text-sm text-ink-soft">{label}</dt>
              <dd className="font-mono text-sm tabular-nums text-ink">{fmt(c[k])}</dd>
            </div>
          ))}
        </dl>
      </Panel>
    </>
  )
}
