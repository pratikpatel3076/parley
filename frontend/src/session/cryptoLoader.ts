/**
 * Lazy entry point to the crypto layer.
 *
 * A static import from `../crypto` pulls in libsodium at module evaluation time.
 * The auth screens call this loader only when the user submits, so the login
 * screen paints before libsodium is downloaded and initialised.
 */

let modulePromise: Promise<typeof import('../crypto')> | null = null

export function loadCrypto(): Promise<typeof import('../crypto')> {
  if (modulePromise === null) {
    modulePromise = import('../crypto')
      .then(async (module) => {
        await module.ready()
        return module
      })
      .catch((error: unknown) => {
        modulePromise = null
        throw error
      })
  }
  return modulePromise
}
