/**
 * Typed errors raised by the Parley client crypto layer.
 *
 * Callers must branch on these classes rather than on message strings. No
 * function in this directory fails silently or returns a sentinel default.
 */

/** Base class so callers can catch any Parley-specific failure. */
export class ParleyError extends Error {
  constructor(message: string) {
    super(message)
    this.name = new.target.name
  }
}

/** Ciphertext failed authentication, or could not be decoded. */
export class DecryptionError extends ParleyError {
  constructor(message = 'Message could not be decrypted') {
    super(message)
  }
}

/** A pinned contact key differs from the key the server returned. */
export class KeyChangedError extends ParleyError {
  readonly username: string
  readonly pinnedKey: string
  readonly seenKey: string

  constructor(username: string, pinnedKey: string, seenKey: string) {
    super(
      `The public key for ${username} changed; acknowledge the change before sending`,
    )
    this.username = username
    this.pinnedKey = pinnedKey
    this.seenKey = seenKey
  }
}

/** The supplied password did not unwrap the stored private key. */
export class WrongPasswordError extends ParleyError {
  constructor(message = 'Wrong password') {
    super(message)
  }
}

/** The authenticated envelope id or version did not match the outer id. */
export class EnvelopeMismatchError extends ParleyError {
  constructor(message = 'Decrypted envelope does not match the outer message') {
    super(message)
  }
}

/** An argument was missing, malformed, or outside an allowed limit. */
export class InvalidInputError extends ParleyError {
  constructor(message: string) {
    super(message)
  }
}

/** A password failed the strength policy. */
export class WeakPasswordError extends ParleyError {
  constructor(message = 'Password is too weak') {
    super(message)
  }
}

/** IndexedDB was unavailable or a storage operation failed. */
export class StorageError extends ParleyError {
  constructor(message = 'Local storage operation failed') {
    super(message)
  }
}
