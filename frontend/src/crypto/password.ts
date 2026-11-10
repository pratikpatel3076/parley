/**
 * Password strength policy.
 *
 * `checkPassword` is a pure check that reports its result. `assertStrongPassword`
 * is the throwing wrapper for call sites that must not continue on a weak
 * password.
 */
import { ZxcvbnFactory, type ZxcvbnResult } from '@zxcvbn-ts/core'
import {
  adjacencyGraphs,
  dictionary as commonDictionary,
} from '@zxcvbn-ts/language-common'
import {
  dictionary as englishDictionary,
  translations,
} from '@zxcvbn-ts/language-en'

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

const zxcvbn = new ZxcvbnFactory({
  dictionary: { ...commonDictionary, ...englishDictionary },
  graphs: adjacencyGraphs,
  translations,
})

function evaluate(password: string, username: string): ZxcvbnResult {
  return zxcvbn.check(password, [username])
}

/**
 * Check a password against the length and zxcvbn policy.
 *
 * A short or weak password returns `ok: false`; malformed arguments throw
 * {@link InvalidInputError}.
 */
export function checkPassword(
  password: string,
  username: string,
): PasswordCheckResult {
  if (typeof password !== 'string') {
    throw new InvalidInputError('password must be a string')
  }
  if (typeof username !== 'string' || username.length === 0) {
    throw new InvalidInputError('username must be a non-empty string')
  }

  const result = evaluate(password, username)
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
export function assertStrongPassword(
  password: string,
  username: string,
): PasswordCheckResult {
  const result = checkPassword(password, username)
  if (!result.ok) {
    throw new WeakPasswordError(
      result.feedback.warning ??
        `Password must be at least ${MIN_PASSWORD_LENGTH} characters and score at least ${MIN_PASSWORD_SCORE}`,
    )
  }
  return result
}
