import '@testing-library/jest-dom/vitest'
import 'fake-indexeddb/auto'
import { webcrypto } from 'node:crypto'

// jsdom exposes crypto.getRandomValues but not always crypto.subtle. The
// wrapping and auth-secret code needs Web Crypto's PBKDF2 and AES-GCM, so use
// Node's implementation in the test environment.
if (!globalThis.crypto?.subtle) {
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: webcrypto,
  })
}
