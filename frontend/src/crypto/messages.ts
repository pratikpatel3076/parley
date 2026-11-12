/**
 * Authenticated plaintext envelope and crypto_box message encryption.
 *
 * The server sees only nonce + ciphertext. The inner envelope carries the
 * client message id plus the sender and recipient public keys, so a server that
 * swaps ciphertexts between message rows or reflects a message back to its
 * sender is detected after decryption.
 */
import {
  ENVELOPE_VERSION,
  KEY_BYTES,
  MAX_ENVELOPE_BYTES,
  MAX_PLAINTEXT_BYTES,
  NONCE_BYTES,
} from './constants'
import {
  DecryptionError,
  EnvelopeMismatchError,
  InvalidInputError,
} from './errors'
import {
  fixedBytes,
  fromBase64,
  requireString,
  toBase64,
  utf8,
  zero,
} from './internal'
import { ready, sodium } from './sodium'

export interface EncryptedMessage {
  nonce: string
  ciphertext: string
}

export interface DecryptedMessage {
  plaintext: string
  timestamp: number
}

export interface EncryptMessageInput {
  plaintext: string
  clientMessageId: string
  recipientPublicKey: string
  senderPublicKey: string
  senderSecretKey: string
}

export interface DecryptReceivedInput {
  nonce: string
  ciphertext: string
  clientMessageId: string
  senderPublicKey: string
  recipientPublicKey: string
  recipientSecretKey: string
}

export interface DecryptSentInput {
  nonce: string
  ciphertext: string
  clientMessageId: string
  recipientPublicKey: string
  senderPublicKey: string
  senderSecretKey: string
}

interface Envelope {
  v: number
  id: string
  ts: number
  from: string
  to: string
  body: string
}

function envelopeBytes(envelope: Envelope): Uint8Array {
  return utf8(JSON.stringify(envelope))
}

/**
 * Encrypt a plaintext into the wire `{nonce, ciphertext}` pair.
 *
 * The plaintext is wrapped in the v1 envelope before encryption. An empty body
 * is allowed; an oversized body is rejected before any crypto work.
 */
export async function encryptMessage(
  input: EncryptMessageInput,
): Promise<EncryptedMessage> {
  if (typeof input.plaintext !== 'string') {
    throw new InvalidInputError('plaintext must be a string')
  }
  const plaintext = input.plaintext
  const clientMessageId = requireString(
    input.clientMessageId,
    'clientMessageId',
  )
  const recipientPublicKey = fixedBytes(
    input.recipientPublicKey,
    'recipientPublicKey',
    KEY_BYTES,
  )
  const senderPublicKey = fixedBytes(
    input.senderPublicKey,
    'senderPublicKey',
    KEY_BYTES,
  )
  const senderSecretKey = fixedBytes(
    input.senderSecretKey,
    'senderSecretKey',
    KEY_BYTES,
  )
  await ready()

  const derivedPublicKey = sodium.crypto_scalarmult_base(senderSecretKey)
  try {
    if (!equalBytes(derivedPublicKey, senderPublicKey)) {
      throw new InvalidInputError(
        'senderPublicKey does not match senderSecretKey',
      )
    }
  } finally {
    zero(derivedPublicKey)
  }

  const bodyBytes = utf8(plaintext)
  try {
    if (bodyBytes.length > MAX_PLAINTEXT_BYTES) {
      throw new InvalidInputError(
        `plaintext must be at most ${MAX_PLAINTEXT_BYTES} UTF-8 bytes`,
      )
    }
  } finally {
    zero(bodyBytes)
  }

  const envelope: Envelope = {
    v: ENVELOPE_VERSION,
    id: clientMessageId,
    ts: Date.now(),
    from: toBase64(senderPublicKey),
    to: toBase64(recipientPublicKey),
    body: plaintext,
  }
  const plaintextBytes = envelopeBytes(envelope)
  const nonce = sodium.randombytes_buf(NONCE_BYTES)
  try {
    if (plaintextBytes.length > MAX_ENVELOPE_BYTES) {
      throw new InvalidInputError(
        `envelope must be at most ${MAX_ENVELOPE_BYTES} bytes`,
      )
    }
    const ciphertext = sodium.crypto_box_easy(
      plaintextBytes,
      nonce,
      recipientPublicKey,
      senderSecretKey,
    )
    return {
      nonce: toBase64(nonce),
      ciphertext: toBase64(ciphertext),
    }
  } finally {
    zero(
      plaintextBytes,
      senderPublicKey,
      recipientPublicKey,
      senderSecretKey,
      nonce,
    )
  }
}

/**
 * Decrypt a message this device received.
 *
 * The sender's public key and this device's secret key are the box pair. The
 * authenticated envelope must name the same sender and this device's own public
 * key, so a reflected or redirected ciphertext is rejected.
 */
export async function decryptReceived(
  input: DecryptReceivedInput,
): Promise<DecryptedMessage> {
  return decrypt(
    input.nonce,
    input.ciphertext,
    input.clientMessageId,
    input.senderPublicKey,
    input.recipientSecretKey,
    input.senderPublicKey,
    input.recipientPublicKey,
  )
}

/**
 * Decrypt a message this device sent, for local history.
 *
 * crypto_box is symmetric, so sender secret + recipient public recovers it.
 * The envelope must still name this device as the sender and the recorded
 * recipient as the recipient.
 */
export async function decryptSent(
  input: DecryptSentInput,
): Promise<DecryptedMessage> {
  return decrypt(
    input.nonce,
    input.ciphertext,
    input.clientMessageId,
    input.recipientPublicKey,
    input.senderSecretKey,
    input.senderPublicKey,
    input.recipientPublicKey,
  )
}

async function decrypt(
  nonceText: string,
  ciphertextText: string,
  clientMessageId: string,
  publicKeyText: string,
  secretKeyText: string,
  expectedFromText: string,
  expectedToText: string,
): Promise<DecryptedMessage> {
  const clientId = requireString(clientMessageId, 'clientMessageId')
  const nonce = fixedBytes(nonceText, 'nonce', NONCE_BYTES)
  const ciphertext = fromBase64(ciphertextText, 'ciphertext')
  const publicKey = fixedBytes(publicKeyText, 'publicKey', KEY_BYTES)
  const secretKey = fixedBytes(secretKeyText, 'secretKey', KEY_BYTES)
  const expectedFrom = fixedBytes(
    expectedFromText,
    'senderPublicKey',
    KEY_BYTES,
  )
  const expectedTo = fixedBytes(
    expectedToText,
    'recipientPublicKey',
    KEY_BYTES,
  )
  await ready()

  let plaintext: Uint8Array
  try {
    plaintext = sodium.crypto_box_open_easy(
      ciphertext,
      nonce,
      publicKey,
      secretKey,
    )
  } catch {
    throw new DecryptionError()
  } finally {
    zero(publicKey, secretKey, nonce, ciphertext)
  }

  try {
    const envelope = parseEnvelope(plaintext)
    if (envelope.v !== ENVELOPE_VERSION) {
      throw new EnvelopeMismatchError('Unsupported envelope version')
    }
    const envelopeFrom = envelopeKeyBytes(envelope.from, 'from')
    const envelopeTo = envelopeKeyBytes(envelope.to, 'to')
    try {
      if (
        !equalBytes(envelopeFrom, expectedFrom) ||
        !equalBytes(envelopeTo, expectedTo)
      ) {
        throw new EnvelopeMismatchError()
      }
    } finally {
      zero(envelopeFrom, envelopeTo)
    }
    if (envelope.id !== clientId) {
      throw new EnvelopeMismatchError()
    }
    return { plaintext: envelope.body, timestamp: envelope.ts }
  } finally {
    zero(plaintext, expectedFrom, expectedTo)
  }
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false
  }
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) {
      return false
    }
  }
  return true
}

function envelopeKeyBytes(value: string, field: string): Uint8Array {
  try {
    return fixedBytes(value, field, KEY_BYTES)
  } catch {
    throw new EnvelopeMismatchError(`Envelope ${field} is invalid`)
  }
}

function parseEnvelope(bytes: Uint8Array): Envelope {
  let parsed: unknown
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes))
  } catch {
    throw new EnvelopeMismatchError('Envelope is not valid JSON')
  }

  if (typeof parsed !== 'object' || parsed === null) {
    throw new EnvelopeMismatchError('Envelope is not an object')
  }
  const candidate = parsed as Partial<Envelope>
  if (
    typeof candidate.v !== 'number' ||
    typeof candidate.id !== 'string' ||
    typeof candidate.ts !== 'number' ||
    !Number.isFinite(candidate.ts) ||
    typeof candidate.from !== 'string' ||
    typeof candidate.to !== 'string' ||
    typeof candidate.body !== 'string'
  ) {
    throw new EnvelopeMismatchError('Envelope fields are invalid')
  }

  return {
    v: candidate.v,
    id: candidate.id,
    ts: candidate.ts,
    from: candidate.from,
    to: candidate.to,
    body: candidate.body,
  }
}
