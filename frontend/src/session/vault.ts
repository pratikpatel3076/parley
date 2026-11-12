/**
 * In-memory session vault.
 *
 * The unwrapped secret key lives only in a module-level base64 string. It is
 * deliberately absent from React state, Zustand, localStorage, sessionStorage,
 * IndexedDB, cookies, the URL, and logs.
 *
 * The key is decoded once on unlock to validate its length, then that byte copy
 * is overwritten and dropped. No second byte copy is retained. JavaScript
 * strings cannot be wiped, so `lock()` drops the reference while the engine may
 * still retain the string bytes until they are collected. This is best effort,
 * matching the protocol's memory notes.
 */
import { InvalidInputError, ParleyError } from '../crypto/errors'

/** Thrown when a caller requests key material while the vault is locked. */
export class VaultLockedError extends ParleyError {
  constructor(message = 'The vault is locked') {
    super(message)
  }
}

export interface VaultIdentity {
  username: string
  publicKey: string
}

export interface UnlockInput extends VaultIdentity {
  secretKey: string
}

const SECRET_KEY_BYTES = 32

let identity: VaultIdentity | null = null
let secretKeyText: string | null = null

function decodeSecretKey(value: string): Uint8Array {
  if (typeof value !== 'string' || value.length === 0) {
    throw new InvalidInputError('secretKey must be a non-empty base64 string')
  }

  let decoded: string
  try {
    decoded = atob(value)
  } catch {
    throw new InvalidInputError('secretKey must be valid base64')
  }

  const bytes = new Uint8Array(decoded.length)
  for (let index = 0; index < decoded.length; index += 1) {
    bytes[index] = decoded.charCodeAt(index)
  }
  if (bytes.length !== SECRET_KEY_BYTES) {
    bytes.fill(0)
    throw new InvalidInputError(
      `secretKey must decode to ${SECRET_KEY_BYTES} bytes`,
    )
  }
  return bytes
}

/** Open the vault with an unwrapped identity. Replaces any previous session. */
export function unlock(input: UnlockInput): void {
  if (typeof input.username !== 'string' || input.username.length === 0) {
    throw new InvalidInputError('username must be a non-empty string')
  }
  if (typeof input.publicKey !== 'string' || input.publicKey.length === 0) {
    throw new InvalidInputError('publicKey must be a non-empty string')
  }

  const bytes = decodeSecretKey(input.secretKey)
  try {
    lock()
    identity = { username: input.username, publicKey: input.publicKey }
    secretKeyText = input.secretKey
  } finally {
    // Only used for validation; do not keep a second copy of the key.
    bytes.fill(0)
  }
}

/** Close the vault and drop the key reference. */
export function lock(): void {
  secretKeyText = null
  identity = null
}

/** Whether key material is currently held in memory. */
export function isUnlocked(): boolean {
  return identity !== null && secretKeyText !== null
}

/** Return the base64 secret key, or throw when locked. */
export function getSecretKey(): string {
  if (secretKeyText === null) {
    throw new VaultLockedError()
  }
  return secretKeyText
}

/** Return the non-secret identity fields, or throw when locked. */
export function getIdentity(): VaultIdentity {
  if (identity === null) {
    throw new VaultLockedError()
  }
  return { username: identity.username, publicKey: identity.publicKey }
}
