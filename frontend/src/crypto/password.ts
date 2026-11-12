/**
 * Password strength policy.
 *
 * The zxcvbn dictionaries are large, so they are loaded with dynamic imports the
 * first time a check is needed. The login screen paints without downloading
 * them; the registration form shows a "checking…" state until the check
 * resolves.
 *
 * `checkPassword` reports its result. `assertStrongPassword` is the throwing
 * wrapper for call sites that must not continue on a weak password.
 */
import type { ZxcvbnFactory, ZxcvbnResult } from '@zxcvbn-ts/core'

import { MIN_PASSWORD_LENGTH, MIN_PASSWORD_SCORE } from './constants'
import { InvalidInputError, WeakPasswordError } from './errors'

export interface PasswordFeedback {
  warning: string | null
  suggestions: string[]
}

export interface PasswordCheckResult {
  ok: boolean
  score: number
  feedback: PasswordFeedback
}

let zxcvbnPromise: Promise<ZxcvbnFactory> | null = null

function loadZxcvbn(): Promise<ZxcvbnFactory> {
  if (zxcvbnPromise === null) {
    zxcvbnPromise = Promise.all([
      import('@zxcvbn-ts/core'),
      import('@zxcvbn-ts/language-common'),
      import('@zxcvbn-ts/language-en'),
    ])
      .then(([core, common, english]) => {
        return new core.ZxcvbnFactory({
          dictionary: {
            ...common.dictionary,
            ...english.dictionary,
          },
          graphs: common.adjacencyGraphs,
          translations: english.translations,
        })
      })
      .catch((error: unknown) => {
        // Allow a later attempt after a transient chunk-load failure.
        zxcvbnPromise = null
        throw error
      })
  }
  return zxcvbnPromise
}

function evaluate(
  zxcvbn: ZxcvbnFactory,
  password: string,
  username: string,
): ZxcvbnResult {
  return zxcvbn.check(password, [username])
}

/**
 * Check a password against the length and zxcvbn policy.
 *
 * A short or weak password returns `ok: false`; malformed arguments throw
 * {@link InvalidInputError}.
 */
export async function checkPassword(
  password: string,
  username: string,
): Promise<PasswordCheckResult> {
  if (typeof password !== 'string') {
    throw new InvalidInputError('password must be a string')
  }
  if (typeof username !== 'string' || username.length === 0) {
    throw new InvalidInputError('username must be a non-empty string')
  }

  const zxcvbn = await loadZxcvbn()
  const result = evaluate(zxcvbn, password, username)
  const longEnough = password.length >= MIN_PASSWORD_LENGTH
  const strongEnough = result.score >= MIN_PASSWORD_SCORE
  return {
    ok: longEnough && strongEnough,
    score: result.score,
    feedback: {
      warning: result.feedback.warning,
      suggestions: [...result.feedback.suggestions],
    },
  }
}

/** Throw {@link WeakPasswordError} unless {@link checkPassword} accepts. */
export async function assertStrongPassword(
  password: string,
  username: string,
): Promise<PasswordCheckResult> {
  const result = await checkPassword(password, username)
  if (!result.ok) {
    throw new WeakPasswordError(
      result.feedback.warning ??
        `Password must be at least ${MIN_PASSWORD_LENGTH} characters and score at least ${MIN_PASSWORD_SCORE}`,
    )
  }
  return result
}
