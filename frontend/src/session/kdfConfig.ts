/**
 * KDF work factor for the UI.
 *
 * Production always uses the protocol constant. Component tests may lower it so
 * password derivation does not dominate the suite. The setter refuses to run
 * outside Vitest's test mode.
 */
import { PBKDF2_ITERATIONS } from '../crypto/constants'

let iterations = PBKDF2_ITERATIONS

/** Current PBKDF2 iteration count for auth-secret and key-wrapping calls. */
export function getKdfIterations(): number {
  return iterations
}

/**
 * Override the work factor. Test mode only; production code must never call it.
 */
export function setKdfIterations(value: number): void {
  if (import.meta.env.MODE !== 'test') {
    throw new Error('setKdfIterations is only available in test mode')
  }
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error('iterations must be a positive integer')
  }
  iterations = value
}
