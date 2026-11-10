/**
 * Password-derived authentication secret.
 *
 * The password itself never leaves the device. The server only ever sees this
 * base64 value, and only transiently during register/login.
 */
import {
  DOMAIN_AUTH,
  AUTH_SECRET_BYTES,
  PBKDF2_ITERATIONS,
  USERNAME_PATTERN,
} from './constants'
import { InvalidInputError } from './errors'
import { pbkdf2Sha256, requirePositiveInteger, toBase64, utf8, zero } from './internal'
import { ready } from './sodium'

/** Validate a username exactly as the backend does. */
export function assertUsername(username: string): string {
  if (typeof username !== 'string' || !USERNAME_PATTERN.test(username)) {
    throw new InvalidInputError(
      'username must be 3-32 lowercase ASCII characters matching ^[a-z0-9_]{3,32}$',
    )
  }
  return username
}

/**
 * Derive the 32-byte auth secret as canonical standard base64.
 *
 * @param password raw user password; NFKC-normalised before use
 * @param username account name; also used as the PBKDF2 salt suffix
 * @param iterations test-only override of {@link PBKDF2_ITERATIONS}
 */
export async function deriveAuthSecret(
  password: string,
  username: string,
  iterations: number = PBKDF2_ITERATIONS,
): Promise<string> {
  assertUsername(username)
  requirePositiveInteger(iterations, 'iterations')
  await ready()

  const salt = utf8(`${DOMAIN_AUTH}:${username}`)
  let derived: Uint8Array | null = null
  try {
    derived = await pbkdf2Sha256(password, salt, iterations)
    if (derived.length !== AUTH_SECRET_BYTES) {
      throw new InvalidInputError('PBKDF2 produced an unexpected key length')
    }
    return toBase64(derived)
  } finally {
    zero(derived)
  }
}
