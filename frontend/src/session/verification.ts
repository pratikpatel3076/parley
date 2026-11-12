/**
 * Safety-number verification helpers for the UI.
 *
 * The safety number is computed from the locally pinned contact key, never
 * from a key the server presents on a later request. Everything goes through
 * the lazy crypto loader so the chat bundle does not pull libsodium into the
 * entry chunk.
 */
import { loadCrypto } from './cryptoLoader'

export interface VerificationSnapshot {
  /** The locally pinned key used for the safety number. */
  pinnedKey: string
  /** 12 groups of 5 digits, space separated. */
  safetyNumber: string
  verified: boolean
}

/**
 * Read the pinned contact and compute its safety number with our public key.
 * Returns null when no key has been pinned for the contact yet.
 */
export async function readVerification(
  owner: string,
  peer: string,
  myPublicKey: string,
): Promise<VerificationSnapshot | null> {
  const crypto = await loadCrypto()
  const contact = await crypto.getContact(owner, peer)
  if (contact === undefined) {
    return null
  }
  const number = await crypto.safetyNumber(myPublicKey, contact.publicKey)
  return {
    pinnedKey: contact.publicKey,
    safetyNumber: number,
    verified: contact.verified,
  }
}

/** Persist the verified flag for an already pinned contact. */
export async function setContactVerified(
  owner: string,
  peer: string,
  verified: boolean,
): Promise<void> {
  const crypto = await loadCrypto()
  await crypto.setVerified(owner, peer, verified)
}
