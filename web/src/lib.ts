import { useEffect } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { apiGet, openStream } from './api'

// The live stream (/api/v1/stream) drives updates; this poll is just the
// fallback heartbeat for when the stream is unavailable.
const FALLBACK_POLL_MS = 20000

export function useApi<T>(path: string) {
  return useQuery<T>({ queryKey: [path], queryFn: () => apiGet<T>(path), refetchInterval: FALLBACK_POLL_MS })
}

export const fmt = (n: number | undefined) => (n ?? 0).toLocaleString('en-US')

export interface Metrics {
  tokens_served_attacker: number
  active_sessions: number
}
export interface Stats {
  counters: Record<string, number>
}
export interface Health {
  backends: Record<string, string>
}
export interface Incident {
  request_id: string
  attacker_ip: string
  attacker_session?: string | null
  state: string
  ghost_persona?: string | null
  ghost_session_id?: string | null
  target_instance_id?: string | null
  expires_at?: string | null
}
export interface Incidents {
  active: Incident[]
}

export interface Snapshot {
  stats: Stats | null
  metrics: Metrics | null
  incidents: Incidents | null
}

/** Open the BFF live stream once and feed each snapshot into the query cache, so
 *  every useApi('/stats'|'/metrics'|'/incidents') consumer updates in real time.
 *  Reconnects with a short backoff; stops on unmount. */
export function useLiveStream(): void {
  const qc = useQueryClient()
  useEffect(() => {
    const ctrl = new AbortController()
    let stopped = false
    async function loop() {
      while (!stopped) {
        try {
          await openStream(
            '/stream',
            (obj) => {
              const s = obj as Snapshot
              if (s.stats) qc.setQueryData(['/stats'], s.stats)
              if (s.metrics) qc.setQueryData(['/metrics'], s.metrics)
              if (s.incidents) qc.setQueryData(['/incidents'], s.incidents)
            },
            ctrl.signal,
          )
        } catch {
          // network drop / unauthorized / abort — fall through to the backoff
        }
        if (!stopped) await new Promise((r) => setTimeout(r, 2000))
      }
    }
    loop()
    return () => {
      stopped = true
      ctrl.abort()
    }
  }, [qc])
}
