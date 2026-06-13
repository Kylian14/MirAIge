const TOKEN_KEY = 'miraige_token'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(t: string | null): void {
  if (t) localStorage.setItem(TOKEN_KEY, t)
  else localStorage.removeItem(TOKEN_KEY)
}

export interface Identity {
  username: string
  role: 'viewer' | 'operator' | 'admin'
}

const ROLE_RANK: Record<string, number> = { viewer: 0, operator: 1, admin: 2 }

export function roleAtLeast(role: string | undefined, min: 'viewer' | 'operator' | 'admin'): boolean {
  return (ROLE_RANK[role ?? ''] ?? -1) >= ROLE_RANK[min]
}

export async function login(username: string, password: string): Promise<Identity> {
  const r = await fetch('/api/v1/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  })
  if (!r.ok) throw new Error('bad credentials')
  const data = (await r.json()) as { token: string; username: string; role: Identity['role'] }
  setToken(data.token)
  return { username: data.username, role: data.role }
}

export async function apiGet<T = unknown>(path: string): Promise<T> {
  const r = await fetch(`/api/v1${path}`, {
    headers: { Authorization: `Bearer ${getToken() ?? ''}` },
  })
  if (r.status === 401) {
    setToken(null)
    throw new Error('unauthorized')
  }
  if (!r.ok) throw new Error(`api ${r.status}`)
  return (await r.json()) as T
}

export async function apiSend<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
  const r = await fetch(`/api/v1${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${getToken() ?? ''}`,
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  if (r.status === 401) {
    setToken(null)
    throw new Error('unauthorized')
  }
  if (!r.ok) {
    // surface FastAPI's `detail` (e.g. "cannot demote the last admin") when present
    let detail = `api ${r.status}`
    try {
      const j = (await r.json()) as { detail?: string }
      if (j.detail) detail = j.detail
    } catch {
      // non-JSON body — keep the status code
    }
    throw new Error(detail)
  }
  return (await r.json()) as T
}

export async function apiPost<T = unknown>(path: string, body?: unknown): Promise<T> {
  return apiSend<T>('POST', path, body)
}

export async function me(): Promise<Identity> {
  return apiGet<Identity>('/me')
}

export interface User {
  username: string
  role: Identity['role']
}

export async function listUsers(): Promise<{ users: User[]; managed: boolean }> {
  return apiGet('/users')
}

export async function createUser(username: string, role: User['role'], password: string): Promise<void> {
  await apiSend('POST', '/users', { username, role, password })
}

export async function updateUser(
  username: string,
  body: { role?: User['role']; password?: string },
): Promise<void> {
  await apiSend('PATCH', `/users/${encodeURIComponent(username)}`, body)
}

export async function deleteUser(username: string): Promise<void> {
  await apiSend('DELETE', `/users/${encodeURIComponent(username)}`)
}

/** Read an NDJSON stream from the BFF, invoking `onMessage` per JSON line. Uses
 *  fetch (not EventSource) so the bearer token rides in the Authorization header. */
export async function openStream(
  path: string,
  onMessage: (obj: unknown) => void,
  signal: AbortSignal,
): Promise<void> {
  const r = await fetch(`/api/v1${path}`, {
    headers: { Authorization: `Bearer ${getToken() ?? ''}` },
    signal,
  })
  if (r.status === 401) {
    setToken(null)
    throw new Error('unauthorized')
  }
  if (!r.ok || !r.body) throw new Error(`stream ${r.status}`)
  const reader = r.body.getReader()
  const decoder = new TextDecoder()
  let buf = ''
  for (;;) {
    const { value, done } = await reader.read()
    if (done) break
    buf += decoder.decode(value, { stream: true })
    let nl: number
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim()
      buf = buf.slice(nl + 1)
      if (line) {
        try {
          onMessage(JSON.parse(line))
        } catch {
          // ignore a partial / malformed line
        }
      }
    }
  }
}
