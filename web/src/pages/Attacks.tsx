import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { apiGet, apiPost, roleAtLeast } from '../api'
import { useAuth } from '../auth'
import { Panel } from '../components/ui'

// UI level → CLI level (the simulator's --level). "patient" / "bypass" keep the
// page free of "APT" labels while still firing the real apt / apt-bypass paths.
interface Level {
  name: string
  cli: string
  triggers: string
  behaviour: string
}

const LEVELS: Level[] = [
  { name: 'noisy', cli: 'noisy', triggers: 'T0 Sigma', behaviour: 'Scanner UA, high RPS, /.env /.aws paths — caught instantly.' },
  { name: 'evasive', cli: 'evasive', triggers: 'T1 heuristics', behaviour: 'Fixed browser UA, ~500ms timing, ~45% 4xx burst.' },
  { name: 'stealth', cli: 'stealth', triggers: 'T2 only', behaviour: 'High UA rotation, 2–3.5s timing, encoded LFI — T1 barely fires.' },
  { name: 'ai-agent', cli: 'ai-agent', triggers: 'variable', behaviour: 'Real ReAct LLM brain; remembers discovered creds and adapts.' },
  { name: 'patient', cli: 'apt', triggers: 'honest limit', behaviour: 'Ultra-patient 5–15s, multi-IP; may stay under the radar.' },
  { name: 'naive-full', cli: 'naive-full', triggers: 'end-to-end', behaviour: 'Walks the whole Ghost Shell through every mechanism.' },
  { name: 'hardened-agent', cli: 'hardened-agent', triggers: 'end-to-end', behaviour: 'Capped/typed agent — shows the honest 1–5× floor.' },
  { name: 'bypass', cli: 'apt-bypass', triggers: 'end-to-end', behaviour: 'Stops before the Sigma paths — we do not claim to catch everything.' },
]

const DURATIONS = [15, 30, 60, 120]

interface AttackRun {
  id: string
  level: string
  target: string
  duration: number
  source_ip: string
  elapsed: number
  running: boolean
  returncode: number | null
}
interface AttacksResp {
  attacks: AttackRun[]
}

export default function Attacks() {
  const qc = useQueryClient()
  const { identity } = useAuth()
  const canOperate = roleAtLeast(identity?.role, 'operator')
  const [selected, setSelected] = useState<Level>(LEVELS[0])
  const [duration, setDuration] = useState(30)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const { data } = useQuery<AttacksResp>({
    queryKey: ['/attacks'],
    queryFn: () => apiGet<AttacksResp>('/attacks'),
    refetchInterval: 1500,
    enabled: canOperate, // viewers don't poll (the API would 403 anyway)
  })
  const runs = data?.attacks ?? []
  const live = runs.filter((r) => r.running).length

  async function launch(): Promise<void> {
    setBusy(true)
    setError(null)
    try {
      await apiPost('/attacks', { level: selected.cli, duration })
      await qc.invalidateQueries({ queryKey: ['/attacks'] })
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'launch failed')
    } finally {
      setBusy(false)
    }
  }

  async function stop(id: string): Promise<void> {
    try {
      await apiPost(`/attacks/${id}/stop`)
      await qc.invalidateQueries({ queryKey: ['/attacks'] })
    } catch {
      // best-effort — the 1.5s poll will reflect the real state either way
    }
  }

  if (!canOperate) {
    return (
      <Panel title="Red team">
        <p className="px-5 py-6 text-sm text-ink-soft">
          Red-team controls require the <span className="font-mono text-ink">operator</span> role —
          ask an admin to grant it. You can still watch Detection and Engagements react.
        </p>
      </Panel>
    )
  }

  return (
    <>
      <Panel
        title="Launch a red-team run"
        action={<span className="font-mono text-xs text-ink-soft">{selected.cli} → {selected.triggers}</span>}
      >
        <div className="px-5 py-4">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {LEVELS.map((l) => {
              const on = l.name === selected.name
              return (
                <button
                  key={l.name}
                  type="button"
                  onClick={() => setSelected(l)}
                  className={`rounded-[var(--radius)] border px-3 py-2 text-left transition-colors ${
                    on
                      ? 'border-mirage bg-mirage/10 text-ink'
                      : 'border-line-strong bg-surface-2 text-ink-soft hover:border-mirage/50'
                  }`}
                >
                  <div className="font-mono text-sm text-ink">{l.name}</div>
                  <div className="mt-0.5 text-xs text-ink-soft">{l.triggers}</div>
                </button>
              )
            })}
          </div>

          <p className="mt-3 text-sm text-ink-soft">{selected.behaviour}</p>

          <div className="mt-4 flex flex-wrap items-center gap-3">
            <span className="text-xs uppercase tracking-wide text-ink-soft">Duration</span>
            <div className="flex items-center gap-1.5">
              {DURATIONS.map((d) => (
                <button
                  key={d}
                  type="button"
                  onClick={() => setDuration(d)}
                  className={`rounded-md border px-2.5 py-1 font-mono text-xs ${
                    d === duration
                      ? 'border-sun bg-sun/10 text-ink'
                      : 'border-line-strong text-ink-soft hover:border-sun/50'
                  }`}
                >
                  {d}s
                </button>
              ))}
            </div>
            <button
              type="button"
              onClick={launch}
              disabled={busy}
              className="ml-auto rounded-[var(--radius)] bg-mirage px-4 py-2 font-semibold text-surface transition-opacity hover:opacity-90 disabled:opacity-50"
            >
              {busy ? 'Launching…' : `Launch ${selected.name}`}
            </button>
          </div>

          {error && <p className="mt-3 text-sm text-alert">{error}</p>}
          <p className="mt-3 text-xs text-ink-soft">
            Hits the protected portal in DIRECT mode; each launch spoofs a fresh source IP, so it
            lands as its own engagement in <span className="text-ink">Detection</span> and{' '}
            <span className="text-ink">Engagements</span>.
          </p>
        </div>
      </Panel>

      <Panel title="Runs" action={<span className="font-mono text-xs text-ink-soft">{live} live</span>}>
        {runs.length === 0 ? (
          <p className="px-5 py-6 text-sm text-ink-soft">
            No runs yet. Launch one above and watch the cascade react.
          </p>
        ) : (
          <div className="divide-y divide-line">
            {runs.map((r) => {
              const pct = Math.min(100, (r.elapsed / Math.max(1, r.duration)) * 100)
              return (
                <div key={r.id} className="flex items-center gap-4 px-5 py-3">
                  <span className="w-28 shrink-0 font-mono text-sm text-ink">{r.level}</span>
                  <span className="w-28 shrink-0 font-mono text-xs text-ink-soft">{r.source_ip}</span>
                  <div className="flex-1">
                    {r.running && (
                      <div className="h-1 overflow-hidden rounded-full bg-line-strong/40">
                        <div
                          className="h-full bg-mirage transition-[width] duration-700 ease-out"
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    )}
                  </div>
                  <span className="w-24 shrink-0 text-right font-mono text-xs tabular-nums text-ink-soft">
                    {r.running ? `${Math.round(r.elapsed)}s / ${r.duration}s` : `${r.duration}s`}
                  </span>
                  {r.running ? (
                    <button
                      type="button"
                      onClick={() => stop(r.id)}
                      className="shrink-0 rounded-md border border-alert/40 px-2.5 py-1 text-xs text-alert transition-colors hover:bg-alert/10"
                    >
                      Stop
                    </button>
                  ) : (
                    <span
                      className={`inline-flex shrink-0 rounded-full border px-2 py-0.5 font-mono text-xs ${
                        r.returncode === 0
                          ? 'border-ok/30 bg-ok/10 text-ok'
                          : 'border-line-strong bg-surface-2 text-ink-soft'
                      }`}
                    >
                      {r.returncode === 0
                        ? 'done'
                        : r.returncode != null && r.returncode < 0
                          ? 'stopped'
                          : `exit ${r.returncode ?? '—'}`}
                    </span>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </Panel>
    </>
  )
}
