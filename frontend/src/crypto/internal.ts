/**
 * Internal encoding, validation, and KDF helpers.
 *
 * Nothing here is part of the public barrel export. Every failure becomes a
 * typed error from `errors.ts`.
 */
import { InvalidInputError } from './errors'
import { sodium } from './sodium'

const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/
const BASE64_ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

/**
 * A Uint8Array backed by a plain ArrayBuffer.
 *
 * TypeScript 5.9 distinguishes ArrayBuffer- from SharedArrayBuffer-backed
 * views; Web Crypto only accepts the former. libsodium's typings use the wider
 * default, so sodium output is narrowed at the boundary with {@link asBytes}.
 */
export type Bytes = Uint8Array<ArrayBuffer>

export function asBytes(value: Uint8Array): Bytes {
  return value as unknown as Bytes
}

/**
 * Pure-JS standard base64 encoding.
 *
 * libsodium's `to_base64` rejects Uint8Arrays created in another JS realm,
 * which jsdom/vitest can produce. Encoding here avoids that and only ever feeds
 * plain bytes into sodium through `from_base64`.
 */
function encodeBase64(bytes: Uint8Array): string {
  let output = ''
  for (let index = 0; index < bytes.length; index += 3) {
    const hasSecond = index + 1 < bytes.length
    const hasThird = index + 2 < bytes.length
    const first = bytes[index]
    const second = hasSecond ? bytes[index + 1] : 0
    const third = hasThird ? bytes[index + 2] : 0

    output += BASE64_ALPHABET[first >> 2]
    output += BASE64_ALPHABET[((first & 0x03) << 4) | (second >> 4)]
    output += hasSecond
      ? BASE64_ALPHABET[((second & 0x0f) << 2) | (third >> 6)]
      : '='
    output += hasThird ? BASE64_ALPHABET[third & 0x3f] : '='
  }
  return output
}

/** Copy bytes into a libsodium-owned buffer. */
export function toSodiumBytes(bytes: Uint8Array): Bytes {
  return asBytes(
    sodium.from_base64(
      encodeBase64(bytes),
      sodium.base64_variants.ORIGINAL,
    ),
  )
}

/** UTF-8 encode into a libsodium-owned buffer. */
export function utf8(text: string): Bytes {
  return toSodiumBytes(new TextEncoder().encode(text))
}

/** Standard padded base64 encode. */
export function toBase64(bytes: Uint8Array): string {
  return encodeBase64(bytes)
}

/** Strict standard padded base64 decode. */
export function fromBase64(value: string, field: string): Bytes {
  if (typeof value !== 'string' || !BASE64.test(value)) {
    throw new InvalidInputError(`${field} must be standard base64`)
  }
  // Every non-empty encoding is a whole number of four-character quanta.
  if (value.length > 0 && value.length % 4 !== 0) {
    throw new InvalidInputError(`${field} must use padded base64`)
  }
  if (value.length === 0) {
    return asBytes(new Uint8Array(0))
  }
  let bytes: Bytes
  try {
    bytes = asBytes(
      sodium.from_base64(value, sodium.base64_variants.ORIGINAL),
    )
  } catch {
    throw new InvalidInputError(`${field} must be standard base64`)
  }
  // Reject non-canonical encodings: same bytes must re-encode to the same text.
  if (toBase64(bytes) !== value) {
    throw new InvalidInputError(`${field} must use canonical padded base64`)
  }
  return bytes
}

/** Decode base64 and require an exact decoded length. */
export function fixedBytes(value: string, field: string, length: number): Bytes {
  const bytes = fromBase64(value, field)
  if (bytes.length !== length) {
    throw new InvalidInputError(`${field} must decode to ${length} bytes`)
  }
  return bytes
}

/** Normalise a password exactly as the protocol requires. */
export function normalizePassword(password: string): string {
  if (typeof password !== 'string') {
    throw new InvalidInputError('password must be a string')
  }
  if (password.length === 0) {
    throw new InvalidInputError('password must not be empty')
  }
  return password.normalize('NFKC')
}

/** Require a non-empty string argument. */
export function requireString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new InvalidInputError(`${field} must be a non-empty string`)
  }
  return value
}

/** Require a positive safe integer argument. */
export function requirePositiveInteger(value: unknown, field: string): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value <= 0
  ) {
    throw new InvalidInputError(`${field} must be a positive integer`)
  }
  return value
}

/** Overwrite a byte buffer. JavaScript strings cannot be erased this way. */
export function zero(...buffers: Array<Uint8Array | null | undefined>): void {
  for (const buffer of buffers) {
    if (buffer !== null && buffer !== undefined) {
      try {
        sodium.memzero(buffer)
      } catch {
        // jsdom/vitest can give the test realm a different Uint8Array class
        // than the one libsodium captured, so its `instanceof` check fails.
        // Falling back keeps the wipe best-effort instead of crashing crypto.
        buffer.fill(0)
      }
    }
  }
}

/** PBKDF2-SHA-256 to 32 raw bytes, with the password buffer zeroed. */
export async function pbkdf2Sha256(
  password: string,
  salt: Bytes,
  iterations: number,
): Promise<Bytes> {
  const subtle = globalThis.crypto?.subtle
  if (subtle === undefined) {
    throw new InvalidInputError('Web Crypto subtle is not available')
  }

  const normalized = normalizePassword(password)
  const passwordBytes = utf8(normalized)
  try {
    const baseKey = await subtle.importKey(
      'raw',
      passwordBytes,
      'PBKDF2',
      false,
      ['deriveBits'],
    )
    const bits = await subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt,
        iterations,
        hash: 'SHA-256',
      },
      baseKey,
      256,
    )
    return new Uint8Array(bits)
  } finally {
    zero(passwordBytes)
  }
}
