import { Link } from 'react-router-dom'
import { useApi, fmt } from '../lib'
import type { Metrics, Stats, Health } from '../lib'
import { Panel, Readout, FunnelStep, HealthPills } from '../components/ui'

export default function Overview() {
  const metrics = useApi<Metrics>('/metrics')
  const stats = useApi<Stats>('/stats')
  const health = useApi<Health>('/health')
  const c = stats.data?.counters ?? {}

  return (
    <>
      <Panel>
        <div className="grid grid-cols-2 divide-line lg:grid-cols-4 lg:divide-x [&>*]:border-b [&>*]:border-line lg:[&>*]:border-b-0">
          <Readout label="Attacker tokens burned" value={fmt(metrics.data?.tokens_served_attacker)} tone="text-alert" big />
          <Readout label="Active engagements" value={fmt(metrics.data?.active_sessions)} tone="text-ghost" big />
          <Readout label="AI canaries tripped" value={fmt(c.canary_triggered)} tone="text-watch" big />
          <Readout label="Events screened" value={fmt(c.events_total)} tone="text-ink" big />
        </div>
      </Panel>

      <div className="grid gap-5 lg:grid-cols-[2fr_1fr]">
        <Panel
          title="Detection cascade"
          action={
            <Link to="/detection" className="text-xs text-mirage hover:underline">
              details
            </Link>
          }
        >
          <div className="flex items-end gap-4 px-5 py-5">
            <FunnelStep label="Events screened" value={c.events_total} tone="bg-ink/25" />
            <FunnelStep label="T0 eliminated" value={c.t0_eliminated} tone="bg-ok/60" />
            <FunnelStep label="Recon flagged" value={c.cumulative_recon_triggered} tone="bg-watch/70" />
            <FunnelStep label="Canary (AI)" value={c.canary_triggered} tone="bg-alert/70" />
          </div>
        </Panel>

        <Panel title="Services">
          <HealthPills backends={health.data?.backends} />
        </Panel>
      </div>
    </>
  )
}
