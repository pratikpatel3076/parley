/**
 * Non-secret session state for the UI.
 *
 * Zustand is devtools-visible, so this store must never hold the secret key, a
 * password, `wrapKey`, `authSecret`, or decrypted message content. Key material
 * belongs to `vault.ts` only.
 */
import { create } from 'zustand'

import { lock as lockVault } from './vault'

export type SessionStatus = 'signed_out' | 'unlocking' | 'unlocked'

export interface SessionState {
  status: SessionStatus
  username: string | null
  publicKey: string | null
  lastError: string | null
  beginUnlock: () => void
  setUnlocked: (username: string, publicKey: string) => void
  setSignedOut: (lastError?: string | null) => void
  setError: (message: string | null) => void
}

export const useSessionStore = create<SessionState>((set) => ({
  status: 'signed_out',
  username: null,
  publicKey: null,
  lastError: null,
  beginUnlock: () =>
    set({ status: 'unlocking', lastError: null }),
  setUnlocked: (username, publicKey) =>
    set({
      status: 'unlocked',
      username,
      publicKey,
      lastError: null,
    }),
  setSignedOut: (lastError = null) =>
    set({
      status: 'signed_out',
      username: null,
      publicKey: null,
      lastError,
    }),
  setError: (message) => set({ lastError: message }),
}))

/** Lock the vault and clear all session state. */
export function lockSession(): void {
  lockVault()
  useSessionStore.getState().setSignedOut()
}

if (typeof window !== 'undefined') {
  window.addEventListener('session-expired', () => {
    lockSession()
  })
}
