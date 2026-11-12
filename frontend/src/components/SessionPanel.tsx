import { useState } from 'react'

import { logout } from '../api/client'
import { lockSession } from '../session/store'

interface SessionPanelProps {
  username: string
}

export function SessionPanel({ username }: SessionPanelProps) {
  const [busy, setBusy] = useState(false)

  async function handleLogout() {
    if (busy) {
      return
    }
    setBusy(true)
    try {
      await logout()
    } catch {
      // Logging out locally must succeed even if the network does not.
    } finally {
      // Clears both the vault and all non-secret session state.
      lockSession()
      setBusy(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-semibold tracking-tight">Signed in</h2>
        <p className="mt-2 text-sm leading-6 text-slate-400">
          Signed in as <span className="text-slate-200">{username}</span>.
        </p>
      </div>

      <p className="rounded-lg border border-slate-800 bg-slate-950/40 p-4 text-sm leading-6 text-slate-400">
        Chat is not implemented yet. The session vault and authentication flow
        are in place; messaging is the next milestone.
      </p>

      <button
        type="button"
        onClick={handleLogout}
        disabled={busy}
        className="w-full rounded-lg border border-slate-700 px-4 py-2 font-medium text-slate-200 disabled:cursor-not-allowed disabled:text-slate-500"
      >
        {busy ? 'Signing out…' : 'Sign out'}
      </button>
    </div>
  )
}
