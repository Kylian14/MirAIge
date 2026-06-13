import type { ReactNode } from 'react'
import { fmt } from '../lib'

export function Panel({ title, action, children }: { title?: string; action?: ReactNode; children: ReactNode }) {
  return (
    <section className="rounded-[var(--radius)] border border-line-strong bg-surface">
      {title && (
        <header className="flex items-center justify-between border-b border-line px-5 py-3">
          <h2 className="text-xs font-semibold uppercase tracking-wide text-ink-soft">{title}</h2>
          {action}
        </header>
      )}
      {children}
    </section>
  )
}

const STATE_TONE: Record<string, string> = {
  monitoring: 'text-ghost bg-ghost/12 border-ghost/30',
  rerouting: 'text-ghost bg-ghost/12 border-ghost/30',
  assigning: 'text-watch bg-watch/12 border-watch/30',
  detecting: 'text-watch bg-watch/12 border-watch/30',
  terminating: 'text-ok bg-ok/12 border-ok/30',
  error: 'text-alert bg-alert/12 border-alert/30',
  rollback: 'text-alert bg-alert/12 border-alert/30',
}
export function StatePill({ state }: { state: string }) {
  const tone = STATE_TONE[state] ?? 'text-ink-soft bg-surface-2 border-line-strong'
  return <span className={`inline-flex rounded-full border px-2 py-0.5 font-mono text-xs ${tone}`}>{state}</span>
}

export function SkeletonRows({ n = 3 }: { n?: number }) {
  return (
    <div className="divide-y divide-line">
      {Array.from({ length: n }).map((_, i) => (
        <div key={i} className="flex items-center gap-4 px-5 py-3">
          <div className="h-4 w-32 animate-pulse rounded bg-line-strong/60" />
          <div className="h-4 w-20 animate-pulse rounded bg-line-strong/40" />
          <div className="ml-auto h-4 w-16 animate-pulse rounded bg-line-strong/40" />
        </div>
      ))}
    </div>
  )
}

export function Readout({ label, value, tone, big }: { label: string; value: ReactNode; tone: string; big?: boolean }) {
  return (
    <div className="px-5 py-4">
      <div className="text-xs uppercase tracking-wide text-ink-soft">{label}</div>
      <div className={`mt-1 font-mono font-semibold tabular-nums ${tone} ${big ? 'text-4xl' : 'text-2xl'}`}>{value}</div>
    </div>
  )
}

export function FunnelStep({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div className="flex-1">
      <div className="font-mono text-2xl font-semibold tabular-nums text-ink">{fmt(value)}</div>
      <div className="mt-0.5 text-xs text-ink-soft">{label}</div>
      <div className={`mt-2 h-1 rounded-full ${tone}`} />
    </div>
  )
}

export function HealthPills({ backends }: { backends?: Record<string, string> }) {
  return (
    <div className="flex flex-wrap gap-2 px-5 py-4">
      {!backends && <span className="text-sm text-ink-soft">Checking…</span>}
      {Object.entries(backends ?? {}).map(([name, st]) => (
        <span
          key={name}
          className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-sm ${
            st === 'ok' ? 'border-ok/40 bg-ok/10 text-ok' : 'border-alert/40 bg-alert/10 text-alert'
          }`}
        >
          <span className={`h-1.5 w-1.5 rounded-full ${st === 'ok' ? 'bg-ok' : 'bg-alert'}`} />
          {name}
        </span>
      ))}
    </div>
  )
}
