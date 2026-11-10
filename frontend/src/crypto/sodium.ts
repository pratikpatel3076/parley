/**
 * Single asynchronous initialisation point for libsodium-wrappers.
 *
 * Import `ready` instead of touching `sodium.ready` directly so every module
 * shares one promise and cannot race the WASM initialisation.
 */
import sodium from 'libsodium-wrappers'

let readyPromise: Promise<void> | null = null

/** Resolve once libsodium is initialised. Safe to call repeatedly. */
export function ready(): Promise<void> {
  if (readyPromise === null) {
    readyPromise = sodium.ready.then(() => undefined)
  }
  return readyPromise
}

export { sodium }
