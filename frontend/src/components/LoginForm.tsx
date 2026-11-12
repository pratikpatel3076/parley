import { useState, type FormEvent } from 'react'

import { ApiError, login, logout } from '../api/client'
import { USERNAME_PATTERN } from '../crypto/constants'
import { StorageError, WrongPasswordError } from '../crypto/errors'
import { readLastUsername, saveLastUsername } from '../lastUsername'
import { loadCrypto } from '../session/cryptoLoader'
import { getKdfIterations } from '../session/kdfConfig'
import { removeDeviceKey } from '../session/removeDeviceKey'
import { useSessionStore } from '../session/store'
import { unlock } from '../session/vault'

interface LoginFormProps {
  onSwitchToRegister: () => void
}

function loginError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 401) {
      return 'Invalid credentials'
    }
    if (error.status === 0) {
      return 'Could not reach the server'
    }
    return 'Sign in failed'
  }
  if (error instanceof StorageError) {
    return 'Could not read the encrypted key on this device'
  }
  return 'Sign in failed'
}

export function LoginForm({ onSwitchToRegister }: LoginFormProps) {
  const [username, setUsername] = useState(() => readLastUsername())
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [phase, setPhase] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [removeOpen, setRemoveOpen] = useState(false)
  const [removeConfirm, setRemoveConfirm] = useState('')
  const [removing, setRemoving] = useState(false)
  const [removeError, setRemoveError] = useState<string | null>(null)
  const [removeDone, setRemoveDone] = useState(false)

  const canSubmit =
    username.length > 0 && password.length > 0 && !busy

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!canSubmit || busy) {
      return
    }

    const usernameValue = username
    const passwordValue = password
    setPassword('')
    setError(null)
    setBusy(true)

    try {
      setPhase('Loading the crypto engine…')
      const crypto = await loadCrypto()

      const stored = await crypto.loadIdentity(usernameValue)
      if (stored === undefined) {
        setError(
          'This device has no key for that username. Parley does not support multiple devices.',
        )
        return
      }

      setPhase('Unlocking your key…')
      let secretKey: string
      try {
        secretKey = await crypto.unwrapSecretKey(
          stored.wrapped,
          stored.publicKey,
          passwordValue,
        )
      } catch (cause) {
        if (cause instanceof WrongPasswordError) {
          setError('Wrong password')
          return
        }
        throw cause
      }

      setPhase('Signing in…')
      const authSecret = await crypto.deriveAuthSecret(
        passwordValue,
        usernameValue,
        getKdfIterations(),
      )
      const response = await login({ username: usernameValue, authSecret })

      if (
        typeof response.user?.public_key !== 'string' ||
        response.user.public_key !== stored.publicKey
      ) {
        // The server may have substituted the account key. Refuse to open the
        // vault and end the session the login just created.
        await logout().catch(() => {
          // Local refusal is the important part; a failed logout is reported by
          // the error below, not by unlocking with the wrong key.
        })
        setError(
          'The server reports a different key for this account than this device holds',
        )
        return
      }
      if (
        typeof response.user.username !== 'string' ||
        response.user.username !== usernameValue
      ) {
        await logout().catch(() => {
          // See above.
        })
        setError(
          'The server returned a different username than the one submitted',
        )
        return
      }

      unlock({
        username: response.user.username,
        publicKey: stored.publicKey,
        secretKey,
      })
      saveLastUsername(response.user.username)
      useSessionStore
        .getState()
        .setUnlocked(response.user.username, stored.publicKey)
    } catch (cause) {
      setError(loginError(cause))
    } finally {
      setBusy(false)
      setPhase(null)
    }
  }

  async function handleRemoveKey() {
    if (removing) {
      return
    }
    if (removeConfirm !== username) {
      setRemoveError('Type the username exactly to confirm.')
      return
    }
    if (!USERNAME_PATTERN.test(username)) {
      setRemoveError('Enter a valid username first.')
      return
    }

    setRemoving(true)
    setRemoveError(null)
    try {
      await removeDeviceKey(username)
      setRemoveDone(true)
      setRemoveOpen(false)
      setRemoveConfirm('')
      setPassword('')
      setError(null)
    } catch {
      setRemoveError('Could not remove the local key from this device')
    } finally {
      setRemoving(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-semibold tracking-tight">Sign in</h2>
        <p className="mt-2 text-sm leading-6 text-slate-400">
          Your password is checked locally before any network request touches
          the server.
        </p>
      </div>

      <form className="space-y-5" onSubmit={handleSubmit} noValidate>
        <div className="space-y-2">
          <label
            className="block text-sm font-medium text-slate-200"
            htmlFor="login-username"
          >
            Username
          </label>
          <input
            id="login-username"
            name="username"
            type="text"
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            className="w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-slate-100 outline-none focus:border-sky-500"
            disabled={busy}
          />
        </div>

        <div className="space-y-2">
          <label
            className="block text-sm font-medium text-slate-200"
            htmlFor="login-password"
          >
            Password
          </label>
          <input
            id="login-password"
            name="password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            className="w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-slate-100 outline-none focus:border-sky-500"
            disabled={busy}
          />
        </div>

        {phase !== null ? (
          <p className="text-sm text-sky-300" aria-live="polite">
            {phase}
          </p>
        ) : null}

        {error !== null ? (
          <p role="alert" aria-live="assertive" className="text-sm text-rose-300">
            {error}
          </p>
        ) : null}

        <button
          type="submit"
          disabled={!canSubmit}
          className="w-full rounded-lg bg-sky-500 px-4 py-2 font-medium text-slate-950 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
        >
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>

      <button
        type="button"
        className="text-sm text-sky-300 underline-offset-4 hover:underline"
        onClick={onSwitchToRegister}
        disabled={busy}
      >
        Create an account
      </button>

      <div className="space-y-3 border-t border-slate-800 pt-5">
        {removeDone ? (
          <p role="status" className="text-sm text-emerald-300">
            Removed this device&rsquo;s key for {username}.
          </p>
        ) : null}

        <button
          type="button"
          className="text-sm text-rose-300 underline-offset-4 hover:underline disabled:cursor-not-allowed disabled:text-slate-500"
          onClick={() => {
            setRemoveOpen((open) => !open)
            setRemoveConfirm('')
            setRemoveError(null)
            setRemoveDone(false)
          }}
          disabled={busy || removing || username.length === 0}
        >
          Remove this device&rsquo;s key for {username || '…'}
        </button>

        {removeOpen ? (
          <div className="space-y-3 rounded-lg border border-rose-900/60 bg-rose-950/20 p-4">
            <p className="text-sm leading-6 text-rose-200">
              This deletes the encrypted key and contact pins stored in this
              browser for <span className="font-medium">{username}</span>. It
              does not contact the server and cannot be undone. If the account
              exists, you will need to register it again with a new key.
            </p>
            <label
              className="block text-sm font-medium text-slate-200"
              htmlFor="login-remove-confirm"
            >
              Type {username} to confirm
            </label>
            <input
              id="login-remove-confirm"
              name="removeConfirm"
              type="text"
              autoComplete="off"
              autoCapitalize="none"
              spellCheck={false}
              value={removeConfirm}
              onChange={(event) => setRemoveConfirm(event.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-slate-100 outline-none focus:border-rose-500"
              disabled={removing}
            />
            {removeError !== null ? (
              <p role="alert" className="text-sm text-rose-300">
                {removeError}
              </p>
            ) : null}
            <div className="flex gap-3">
              <button
                type="button"
                onClick={handleRemoveKey}
                disabled={removing || removeConfirm !== username}
                className="rounded-lg bg-rose-500 px-4 py-2 text-sm font-medium text-slate-950 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
              >
                {removing ? 'Removing…' : 'Remove key'}
              </button>
              <button
                type="button"
                onClick={() => {
                  setRemoveOpen(false)
                  setRemoveConfirm('')
                  setRemoveError(null)
                }}
                disabled={removing}
                className="rounded-lg border border-slate-700 px-4 py-2 text-sm font-medium text-slate-200"
              >
                Cancel
              </button>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  )
}
