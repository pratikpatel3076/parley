/**
 * Safety numbers and contact key pinning.
 *
 * The safety number is a BLAKE2b-512 hash over a domain label and the two
 * public keys in sorted byte order, rendered as 12 groups of 5 decimal digits.
 * Both parties compute the same value for the same pair of keys.
 */
import { DOMAIN_SAFETY, KEY_BYTES } from './constants'
import { InvalidInputError, KeyChangedError } from './errors'
import { fixedBytes, toSodiumBytes, utf8, zero } from './internal'
import { ready, sodium } from './sodium'
import { getContact, putContact, type StoredContact } from './storage'

const GROUPS = 12
const GROUP_DIGITS = 5
const GROUP_MODULUS = 100_000

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const length = Math.min(left.length, right.length)
  for (let index = 0; index < length; index += 1) {
    if (left[index] !== right[index]) {
      return left[index] - right[index]
    }
  }
  return left.length - right.length
}

/**
 * Render the 12-group safety number for two base64 public keys.
 *
 * Input order does not matter; keys are sorted by their raw byte order.
 */
export async function safetyNumber(
  publicKeyA: string,
  publicKeyB: string,
): Promise<string> {
  const first = fixedBytes(publicKeyA, 'publicKeyA', KEY_BYTES)
  const second = fixedBytes(publicKeyB, 'publicKeyB', KEY_BYTES)
  await ready()

  const [low, high] =
    compareBytes(first, second) <= 0 ? [first, second] : [second, first]
  const domain = utf8(DOMAIN_SAFETY)
  const concatenated = new Uint8Array(
    domain.length + low.length + high.length,
  )
  concatenated.set(domain, 0)
  concatenated.set(low, domain.length)
  concatenated.set(high, domain.length + low.length)
  const input = toSodiumBytes(concatenated)

  let digest: Uint8Array | null = null
  try {
    digest = sodium.crypto_generichash(64, input, null)
    const groups: string[] = []
    for (let index = 0; index < GROUPS; index += 1) {
      const offset = index * 4
      const value =
        digest[offset] * 0x1000000 +
        digest[offset + 1] * 0x10000 +
        digest[offset + 2] * 0x100 +
        digest[offset + 3]
      groups.push(String(value % GROUP_MODULUS).padStart(GROUP_DIGITS, '0'))
    }
    return groups.join(' ')
  } finally {
    zero(first, second, input, digest)
  }
}

/**
 * Pin a contact key on first sight, or verify a later sighting.
 *
 * Returns the stored contact. Throws {@link KeyChangedError} when a different
 * key is already pinned.
 */
export async function pinOrCheckContact(
  owner: string,
  username: string,
  publicKey: string,
): Promise<StoredContact> {
  const bytes = fixedBytes(publicKey, 'publicKey', KEY_BYTES)
  zero(bytes)

  const existing = await getContact(owner, username)
  if (existing === undefined) {
    const contact: StoredContact = {
      owner,
      username,
      publicKey,
      firstSeen: Date.now(),
      verified: false,
    }
    await putContact(contact)
    return contact
  }

  if (existing.publicKey !== publicKey) {
    throw new KeyChangedError(username, existing.publicKey, publicKey)
  }
  return existing
}

/**
 * Explicitly replace a pinned key after the user has compared safety numbers.
 *
 * The new pin starts unverified; the original first-seen time is preserved.
 */
export async function acknowledgeKeyChange(
  owner: string,
  username: string,
  newPublicKey: string,
): Promise<StoredContact> {
  const bytes = fixedBytes(newPublicKey, 'publicKey', KEY_BYTES)
  zero(bytes)

  const existing = await getContact(owner, username)
  if (existing === undefined) {
    throw new InvalidInputError(
      'Cannot acknowledge a key change for an unpinned contact',
    )
  }
  if (existing.publicKey === newPublicKey) {
    throw new InvalidInputError('The new key matches the pinned key')
  }

  const updated: StoredContact = {
    ...existing,
    publicKey: newPublicKey,
    verified: false,
  }
  await putContact(updated)
  return updated
}
