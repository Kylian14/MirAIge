import { createContext, useContext, useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { getToken, setToken as persist, login as apiLogin, me } from './api'
import type { Identity } from './api'

interface AuthCtx {
  token: string | null
  identity: Identity | null
  signIn: (username: string, password: string) => Promise<void>
  signOut: () => void
}

const Ctx = createContext<AuthCtx>({
  token: null,
  identity: null,
  signIn: async () => {},
  signOut: () => {},
})

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setTok] = useState<string | null>(getToken())
  const [identity, setIdentity] = useState<Identity | null>(null)

  // With a persisted token (e.g. after a refresh), resolve who we are. This also
  // validates the token: a 401 clears it and drops us back to the login screen.
  useEffect(() => {
    if (token && !identity) {
      me()
        .then(setIdentity)
        .catch(() => {
          persist(null)
          setTok(null)
        })
    }
  }, [token, identity])

  const signIn = async (username: string, password: string) => {
    const id = await apiLogin(username, password) // persists the token
    setTok(getToken())
    setIdentity(id)
  }

  const signOut = () => {
    persist(null)
    setTok(null)
    setIdentity(null)
  }

  return <Ctx.Provider value={{ token, identity, signIn, signOut }}>{children}</Ctx.Provider>
}

export const useAuth = () => useContext(Ctx)
