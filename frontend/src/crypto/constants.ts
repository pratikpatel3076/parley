/**
 * Protocol constants shared by the client crypto modules.
 *
 * These values are part of the wire contract in docs/PROTOCOL.md. Changing any
 * of them changes what other clients can read, so treat them as versioned.
 */

/** PBKDF2-SHA-256 work factor for both the auth secret and the wrap key. */
export const PBKDF2_ITERATIONS = 600_000

/** Domain separation labels. They are never sent on the wire. */
export const DOMAIN_AUTH = 'parley/auth/v1'
export const DOMAIN_WRAP = 'parley/wrap/v1'
export const DOMAIN_SAFETY = 'parley/safety/v1'

/** Envelope format version written inside the encrypted plaintext. */
export const ENVELOPE_VERSION = 1

/** Version of the wrapped-key blob written to IndexedDB. */
export const WRAPPED_KEY_VERSION = 1

/** KDF identifier recorded in a wrapped-key blob. */
export const KDF_PBKDF2_SHA256 = 'pbkdf2-sha256'

/** Usernames accepted by the backend: 3-32 lowercase ASCII runes. */
export const USERNAME_PATTERN = /^[a-z0-9_]{3,32}$/

/** Raw byte sizes used by the protocol. */
export const KEY_BYTES = 32
export const NONCE_BYTES = 24
export const SALT_BYTES = 16
export const IV_BYTES = 12
export const AUTH_SECRET_BYTES = 32

/** Maximum UTF-8 plaintext body accepted by encryptMessage. */
export const MAX_PLAINTEXT_BYTES = 60_000

/** Maximum envelope size, comfortably below the backend's 64 KiB limit. */
export const MAX_ENVELOPE_BYTES = 64_000

/** Password policy. */
export const MIN_PASSWORD_LENGTH = 12
export const MIN_PASSWORD_SCORE = 3
