/**
 * Identity keypair generation and password-based private-key wrapping.
 *
 * Only the wrapped blob (`WrappedKey`) is ever persisted. The raw secret key
 * bytes and the derived AES key exist for the duration of a call and are then
 * dropped; see the memory note in docs/THREAT_MODEL.md.
 */
import {
  DOMAIN_WRAP,
  IV_BYTES,
  KDF_PBKDF2_SHA256,
  KEY_BYTES,
  PBKDF2_ITERATIONS,
  SALT_BYTES,
  WRAPPED_KEY_VERSION,
} from './constants'
import { InvalidInputError, WrongPasswordError } from './errors'
import {
  asBytes,
  fixedBytes,
  fromBase64,
  normalizePassword,
  pbkdf2Sha256,
  requirePositiveInteger,
  toBase64,
  utf8,
  zero,
  type Bytes,
} from './internal'
import { ready, sodium } from './sodium'

export interface WrappedKey {
  v: 1
  kdf: typeof KDF_PBKDF2_SHA256
  iterations: number
  salt: string
  iv: string
  ciphertext: string
}

export interface Identity {
  publicKey: string
  secretKey: string
}

export interface WrapOptions {
  /** Test-only override of {@link PBKDF2_ITERATIONS}. */
  iterations?: number
}

/** Maximum PBKDF2 iteration count accepted when unlocking a stored blob. */
const MAX_WRAP_ITERATIONS = 10_000_000

/** 32-byte secret key plus the 16-byte AES-GCM tag. */
const WRAPPED_CIPHERTEXT_BYTES = KEY_BYTES + 16

/** Generate a fresh crypto_box keypair, returned as standard base64. */
export async function generateIdentity(): Promise<Identity> {
  await ready()
  const pair = sodium.crypto_box_keypair()
  const publicBytes = pair.publicKey
  const secretBytes = pair.privateKey
  try {
    return {
      publicKey: toBase64(publicBytes),
      secretKey: toBase64(secretBytes),
    }
  } finally {
    // The base64 strings remain, but the raw buffers are no longer needed.
    zero(secretBytes)
  }
}

/** Rebuild the PBKDF2 salt from its public domain prefix plus the random salt. */
function wrapSalt(randomSalt: Uint8Array): Bytes {
  const prefix = utf8(`${DOMAIN_WRAP}:`)
  const salt = new Uint8Array(prefix.length + randomSalt.length)
  salt.set(prefix, 0)
  salt.set(randomSalt, prefix.length)
  return salt
}

/** AAD binds the blob to exactly one public key. */
function wrapAad(publicKeyBytes: Uint8Array): Bytes {
  const domain = utf8(DOMAIN_WRAP)
  const aad = new Uint8Array(domain.length + publicKeyBytes.length)
  aad.set(domain, 0)
  aad.set(publicKeyBytes, domain.length)
  return aad
}

async function aesKeyFromPassword(
  password: string,
  salt: Bytes,
  iterations: number,
): Promise<CryptoKey> {
  const subtle = globalThis.crypto?.subtle
  if (subtle === undefined) {
    throw new InvalidInputError('Web Crypto subtle is not available')
  }
  const raw = await pbkdf2Sha256(password, salt, iterations)
  try {
    return await subtle.importKey('raw', raw, 'AES-GCM', false, [
      'encrypt',
      'decrypt',
    ])
  } finally {
    zero(raw)
  }
}

/**
 * Wrap a secret key with a password-derived AES-256-GCM key.
 *
 * The random 16-byte salt is stored in the blob; the PBKDF2 salt is
 * `UTF-8("parley/wrap/v1:") || salt`. The AAD is
 * `UTF-8("parley/wrap/v1") || publicKey`, so a blob moved to another identity
 * fails to unwrap.
 */
export async function wrapSecretKey(
  secretKey: string,
  publicKey: string,
  password: string,
  options: WrapOptions = {},
): Promise<WrappedKey> {
  const iterations = requirePositiveInteger(
    options.iterations ?? PBKDF2_ITERATIONS,
    'iterations',
  )
  const secretBytes = fixedBytes(secretKey, 'secretKey', KEY_BYTES)
  const publicBytes = fixedBytes(publicKey, 'publicKey', KEY_BYTES)
  const normalized = normalizePassword(password)
  await ready()

  const randomSalt = asBytes(sodium.randombytes_buf(SALT_BYTES))
  const salt = wrapSalt(randomSalt)
  const iv = asBytes(sodium.randombytes_buf(IV_BYTES))
  const aad = wrapAad(publicBytes)

  try {
    const key = await aesKeyFromPassword(normalized, salt, iterations)
    const subtle = globalThis.crypto?.subtle
    if (subtle === undefined) {
      throw new InvalidInputError('Web Crypto subtle is not available')
    }
    const encrypted = await subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: aad,
        tagLength: 128,
      },
      key,
      secretBytes,
    )

    return {
      v: WRAPPED_KEY_VERSION,
      kdf: KDF_PBKDF2_SHA256,
      iterations,
      salt: toBase64(randomSalt),
      iv: toBase64(iv),
      ciphertext: toBase64(new Uint8Array(encrypted)),
    }
  } finally {
    zero(secretBytes, publicBytes, salt, aad)
  }
}

/**
 * Unwrap a stored secret key.
 *
 * Any AES-GCM authentication failure (wrong password, wrong public key, or a
 * tampered blob) becomes {@link WrongPasswordError}; structurally invalid
 * blobs become {@link InvalidInputError}.
 */
export async function unwrapSecretKey(
  blob: WrappedKey,
  publicKey: string,
  password: string,
): Promise<string> {
  validateWrappedKey(blob)
  const publicBytes = fixedBytes(publicKey, 'publicKey', KEY_BYTES)
  const randomSalt = fixedBytes(blob.salt, 'salt', SALT_BYTES)
  const iv = fixedBytes(blob.iv, 'iv', IV_BYTES)
  const ciphertext = fromBase64(blob.ciphertext, 'ciphertext')
  const normalized = normalizePassword(password)
  await ready()

  const salt = wrapSalt(randomSalt)
  const aad = wrapAad(publicBytes)
  let plaintext: ArrayBuffer
  try {
    const key = await aesKeyFromPassword(
      normalized,
      salt,
      blob.iterations,
    )
    const subtle = globalThis.crypto?.subtle
    if (subtle === undefined) {
      throw new InvalidInputError('Web Crypto subtle is not available')
    }
    plaintext = await subtle.decrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: aad,
        tagLength: 128,
      },
      key,
      ciphertext,
    )
  } catch (error) {
    if (error instanceof InvalidInputError) {
      throw error
    }
    throw new WrongPasswordError()
  } finally {
    zero(publicBytes, randomSalt, salt, aad)
  }

  const secretBytes = new Uint8Array(plaintext)
  try {
    if (secretBytes.length !== KEY_BYTES) {
      throw new InvalidInputError('Wrapped key does not contain a 32-byte key')
    }
    return toBase64(secretBytes)
  } finally {
    zero(secretBytes)
  }
}

function validateWrappedKey(blob: WrappedKey): void {
  if (typeof blob !== 'object' || blob === null) {
    throw new InvalidInputError('wrapped key must be an object')
  }
  if (blob.v !== WRAPPED_KEY_VERSION) {
    throw new InvalidInputError('unsupported wrapped key version')
  }
  if (blob.kdf !== KDF_PBKDF2_SHA256) {
    throw new InvalidInputError('unsupported wrapped key KDF')
  }
  if (
    typeof blob.iterations !== 'number' ||
    !Number.isInteger(blob.iterations) ||
    blob.iterations < 1 ||
    blob.iterations > MAX_WRAP_ITERATIONS
  ) {
    throw new InvalidInputError(
      `iterations must be an integer between 1 and ${MAX_WRAP_ITERATIONS}`,
    )
  }
  validateFixedBase64(blob.salt, 'salt', SALT_BYTES)
  validateFixedBase64(blob.iv, 'iv', IV_BYTES)
  validateFixedBase64(
    blob.ciphertext,
    'ciphertext',
    WRAPPED_CIPHERTEXT_BYTES,
  )
}

function validateFixedBase64(
  value: unknown,
  field: string,
  length: number,
): void {
  if (typeof value !== 'string') {
    throw new InvalidInputError(`${field} must be a string`)
  }
  const bytes = fixedBytes(value, field, length)
  zero(bytes)
}
