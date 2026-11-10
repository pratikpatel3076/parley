/**
 * Authenticated plaintext envelope and crypto_box message encryption.
 *
 * The server sees only nonce + ciphertext. The inner envelope carries the
 * client message id, so a server that swaps ciphertexts between message rows is
 * detected after decryption.
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
  senderSecretKey: string
}

export interface DecryptReceivedInput {
  nonce: string
  ciphertext: string
  clientMessageId: string
  senderPublicKey: string
  recipientSecretKey: string
}

export interface DecryptSentInput {
  nonce: string
  ciphertext: string
  clientMessageId: string
  recipientPublicKey: string
  senderSecretKey: string
}

interface Envelope {
  v: number
  id: string
  ts: number
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
  const senderSecretKey = fixedBytes(
    input.senderSecretKey,
    'senderSecretKey',
    KEY_BYTES,
  )
  await ready()

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
    zero(plaintextBytes, senderSecretKey, recipientPublicKey, nonce)
  }
}

/**
 * Decrypt a message this device received.
 *
 * The sender's public key and this device's secret key are the box pair.
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
  )
}

/**
 * Decrypt a message this device sent, for local history.
 *
 * crypto_box is symmetric, so sender secret + recipient public recovers it.
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
  )
}

async function decrypt(
  nonceText: string,
  ciphertextText: string,
  clientMessageId: string,
  publicKeyText: string,
  secretKeyText: string,
): Promise<DecryptedMessage> {
  const clientId = requireString(clientMessageId, 'clientMessageId')
  const nonce = fixedBytes(nonceText, 'nonce', NONCE_BYTES)
  const ciphertext = fromBase64(ciphertextText, 'ciphertext')
  const publicKey = fixedBytes(publicKeyText, 'publicKey', KEY_BYTES)
  const secretKey = fixedBytes(secretKeyText, 'secretKey', KEY_BYTES)
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
    if (envelope.id !== clientId) {
      throw new EnvelopeMismatchError()
    }
    return { plaintext: envelope.body, timestamp: envelope.ts }
  } finally {
    zero(plaintext)
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
    typeof candidate.body !== 'string'
  ) {
    throw new EnvelopeMismatchError('Envelope fields are invalid')
  }

  return {
    v: candidate.v,
    id: candidate.id,
    ts: candidate.ts,
    body: candidate.body,
  }
}
