import { useEffect, useState, type FormEvent } from 'react'

import { ApiError } from '../api/client'
import { register } from '../api/client'
import { USERNAME_PATTERN } from '../crypto/constants'
import {
  InvalidInputError,
  StorageError,
  WeakPasswordError,
} from '../crypto/errors'
import {
  checkPassword,
  type PasswordCheckResult,
} from '../crypto/password'
import { saveLastUsername } from '../lastUsername'
import { loadCrypto } from '../session/cryptoLoader'
import { getKdfIterations } from '../session/kdfConfig'
import { useSessionStore } from '../session/store'
import { unlock } from '../session/vault'

interface RegisterFormProps {
  onSwitchToLogin: () => void
}

const POSSIBLE_SUCCESS_MESSAGE =
  "Registration may have succeeded. Try logging in. If login says invalid credentials, use 'Remove this device's key' and register again."

const DEFINITIVE_FAILURE_STATUSES = new Set([400, 409, 413, 422, 429])

/**
 * A failure is definitive only when the server refused the request with a
 * status that cannot have created the account, or when no request was sent.
 * Network failures, timeouts, 5xx, and failures after a success response leave
 * the local key in place so a retry can still log in.
 */
function isDefinitiveFailure(error: unknown, requestSent: boolean): boolean {
  if (!requestSent) {
    return true
  }
  return (
    error instanceof ApiError &&
    DEFINITIVE_FAILURE_STATUSES.has(error.status)
  )
}

function registrationError(error: unknown): string {
  if (error instanceof ApiError) {
    switch (error.status) {
      case 400:
        return 'The server rejected the registration'
      case 409:
        return 'That username is taken'
      case 413:
        return 'The registration request was too large'
      case 422:
        return 'The server rejected the username or key'
      case 429:
        return 'Too many attempts. Try again later.'
      case 0:
        return 'Could not reach the server'
      default:
        return 'Registration failed'
    }
  }
  if (error instanceof WeakPasswordError) {
    return error.message
  }
  if (error instanceof StorageError) {
    return 'Could not store the encrypted key on this device'
  }
  if (error instanceof InvalidInputError) {
    return error.message
  }
  return 'Registration failed'
}

export function RegisterForm({ onSwitchToLogin }: RegisterFormProps) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [acknowledged, setAcknowledged] = useState(false)
  const [busy, setBusy] = useState(false)
  const [phase, setPhase] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [strength, setStrength] = useState<PasswordCheckResult | null>(null)
  const [checking, setChecking] = useState(false)

  const usernameValid = USERNAME_PATTERN.test(username)
  const usernameInvalid = username.length > 0 && !usernameValid
  const passwordsMatch = password === confirmPassword
  const canSubmit =
    usernameValid &&
    password.length > 0 &&
    passwordsMatch &&
    strength?.ok === true &&
    !checking &&
    acknowledged &&
    !busy

  useEffect(() => {
    if (password.length === 0) {
      setStrength(null)
      setChecking(false)
      return
    }

    let cancelled = false
    setChecking(true)
    checkPassword(password, usernameValid ? username : 'parley')
      .then((result) => {
        if (!cancelled) {
          setStrength(result)
        }
      })
      .catch(() => {
        if (!cancelled) {
          setStrength(null)
        }
      })
      .finally(() => {
        if (!cancelled) {
          setChecking(false)
        }
      })

    return () => {
      cancelled = true
    }
  }, [password, username, usernameValid])

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!canSubmit || busy) {
      return
    }

    const usernameValue = username
    const passwordValue = password
    // Clear password fields immediately; the in-flight flow keeps local copies.
    setPassword('')
    setConfirmPassword('')
    setError(null)
    setBusy(true)

    let saved = false
    let requestSent = false
    let serverResponded = false
    try {
      setPhase('Loading the crypto engine…')
      const crypto = await loadCrypto()

      const existing = await crypto.loadIdentity(usernameValue)
      if (existing !== undefined) {
        setError(
          'This device already has a key for that username. Refusing to overwrite it.',
        )
        return
      }

      setPhase('Generating your key…')
      const identity = await crypto.generateIdentity()

      setPhase('Protecting your key with your password…')
      const wrapped = await crypto.wrapSecretKey(
        identity.secretKey,
        identity.publicKey,
        passwordValue,
        { iterations: getKdfIterations() },
      )

      await crypto.saveIdentity({
        username: usernameValue,
        publicKey: identity.publicKey,
        wrapped,
      })
      saved = true

      setPhase('Creating your account…')
      const authSecret = await crypto.deriveAuthSecret(
        passwordValue,
        usernameValue,
        getKdfIterations(),
      )
      requestSent = true
      const response = await register({
        username: usernameValue,
        authSecret,
        publicKey: identity.publicKey,
      })
      // The request resolved, so the server may have created the account. From
      // this point on, the local key must never be deleted automatically.
      serverResponded = true

      if (
        typeof response.user?.public_key !== 'string' ||
        response.user.public_key !== identity.publicKey
      ) {
        setError(
          'The server reports a different key for this account than this device holds. Refusing to unlock. The local key was kept.',
        )
        return
      }
      if (
        typeof response.user.username !== 'string' ||
        response.user.username !== usernameValue
      ) {
        setError(
          'The server returned a different username than the one submitted. Refusing to unlock. The local key was kept.',
        )
        return
      }

      unlock({
        username: response.user.username,
        publicKey: identity.publicKey,
        secretKey: identity.secretKey,
      })
      saveLastUsername(response.user.username)
      useSessionStore
        .getState()
        .setUnlocked(response.user.username, identity.publicKey)
    } catch (cause) {
      const definitive =
        !serverResponded && isDefinitiveFailure(cause, requestSent)
      if (saved && definitive) {
        let cleanupFailed = false
        try {
          const crypto = await loadCrypto()
          await crypto.deleteIdentity(usernameValue)
        } catch {
          cleanupFailed = true
        }
        setError(
          cleanupFailed
            ? 'Registration failed and the local key could not be removed. Clear this site’s data before trying again.'
            : registrationError(cause),
        )
      } else if (saved) {
        // Network error, timeout, 5xx, or a failure after the server responded.
        setError(POSSIBLE_SUCCESS_MESSAGE)
      } else {
        setError(registrationError(cause))
      }
    } finally {
      setBusy(false)
      setPhase(null)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-semibold tracking-tight">Create account</h2>
        <p className="mt-2 text-sm leading-6 text-slate-400">
          Your password protects a key stored only on this device.
        </p>
      </div>

      <form className="space-y-5" onSubmit={handleSubmit} noValidate>
        <div className="space-y-2">
          <label
            className="block text-sm font-medium text-slate-200"
            htmlFor="register-username"
          >
            Username
          </label>
          <input
            id="register-username"
            name="username"
            type="text"
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            aria-invalid={usernameInvalid}
            aria-describedby={
              usernameInvalid ? 'register-username-error' : undefined
            }
            className="w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-slate-100 outline-none focus:border-sky-500"
            disabled={busy}
          />
          {usernameInvalid ? (
            <p
              id="register-username-error"
              className="text-xs text-rose-300"
            >
              3-32 lowercase letters, digits, or underscores.
            </p>
          ) : null}
        </div>

        <div className="space-y-2">
          <label
            className="block text-sm font-medium text-slate-200"
            htmlFor="register-password"
          >
            Password
          </label>
          <input
            id="register-password"
            name="password"
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            className="w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-slate-100 outline-none focus:border-sky-500"
            disabled={busy}
          />
        </div>

        <div className="space-y-2">
          <label
            className="block text-sm font-medium text-slate-200"
            htmlFor="register-confirm-password"
          >
            Confirm password
          </label>
          <input
            id="register-confirm-password"
            name="confirmPassword"
            type="password"
            autoComplete="new-password"
            value={confirmPassword}
            onChange={(event) => setConfirmPassword(event.target.value)}
            className="w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-slate-100 outline-none focus:border-sky-500"
            disabled={busy}
          />
          {confirmPassword.length > 0 && !passwordsMatch ? (
            <p className="text-xs text-rose-300">Passwords do not match.</p>
          ) : null}
        </div>

        <div className="space-y-2" aria-live="polite">
          <p className="text-xs uppercase tracking-[0.2em] text-slate-500">
            Password strength
          </p>
          <progress
            aria-label="Password strength"
            className="h-2 w-full overflow-hidden rounded"
            max={4}
            value={strength?.score ?? 0}
          />
          {checking ? (
            <p className="text-xs text-slate-400">checking…</p>
          ) : null}
          {!checking && strength !== null ? (
            <>
              {strength.feedback.warning !== null ? (
                <p className="text-xs text-amber-300">
                  {strength.feedback.warning}
                </p>
              ) : null}
              {strength.feedback.suggestions.length > 0 ? (
                <ul className="list-inside list-disc text-xs text-slate-400">
                  {strength.feedback.suggestions.map((suggestion) => (
                    <li key={suggestion}>{suggestion}</li>
                  ))}
                </ul>
              ) : null}
              {!strength.ok ? (
                <p className="text-xs text-slate-400">
                  Use at least 12 characters with a score of 3 or better.
                </p>
              ) : null}
            </>
          ) : null}
        </div>

        <label className="flex items-start gap-3 text-sm leading-6 text-slate-300">
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(event) => setAcknowledged(event.target.checked)}
            className="mt-1 h-4 w-4 rounded border-slate-600 bg-slate-950"
            disabled={busy}
          />
          <span>
            I understand that losing this device or forgetting this password
            permanently loses my identity and message history. There is no
            recovery.
          </span>
        </label>

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
          {busy ? 'Creating account…' : 'Create account'}
        </button>
      </form>

      <button
        type="button"
        className="text-sm text-sky-300 underline-offset-4 hover:underline"
        onClick={onSwitchToLogin}
        disabled={busy}
      >
        Back to sign in
      </button>
    </div>
  )
}
