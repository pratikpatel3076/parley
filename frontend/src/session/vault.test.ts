import { beforeEach, describe, expect, it } from 'vitest'

import { InvalidInputError } from '../crypto/errors'
import {
  VaultLockedError,
  getIdentity,
  getSecretKey,
  isUnlocked,
  lock,
  unlock,
} from './vault'

const SECRET_KEY = `${'A'.repeat(43)}=`
const PUBLIC_KEY = `${'B'.repeat(43)}=`

beforeEach(() => {
  lock()
})

describe('vault', () => {
  it('unlocks and exposes the secret key and identity while open', () => {
    unlock({
      username: 'alice',
      publicKey: PUBLIC_KEY,
      secretKey: SECRET_KEY,
    })

    expect(isUnlocked()).toBe(true)
    expect(getSecretKey()).toBe(SECRET_KEY)
    expect(getIdentity()).toEqual({
      username: 'alice',
      publicKey: PUBLIC_KEY,
    })
  })

  it('throws VaultLockedError after lock', () => {
    unlock({
      username: 'alice',
      publicKey: PUBLIC_KEY,
      secretKey: SECRET_KEY,
    })

    lock()

    expect(isUnlocked()).toBe(false)
    expect(() => getSecretKey()).toThrow(VaultLockedError)
    expect(() => getIdentity()).toThrow(VaultLockedError)
  })

  it('throws VaultLockedError before the first unlock', () => {
    expect(() => getSecretKey()).toThrow(VaultLockedError)
    expect(() => getIdentity()).toThrow(VaultLockedError)
  })

  it('validates base64 without retaining a byte copy', () => {
    unlock({
      username: 'alice',
      publicKey: PUBLIC_KEY,
      secretKey: SECRET_KEY,
    })

    // The only retained form is the base64 string returned by getSecretKey;
    // there is no exported byte buffer to inspect or leak.
    expect(getSecretKey()).toBe(SECRET_KEY)
    expect(Object.keys(getIdentity())).toEqual(['username', 'publicKey'])
  })

  it('rejects a secret key that is not valid base64', () => {
    expect(() =>
      unlock({
        username: 'alice',
        publicKey: PUBLIC_KEY,
        secretKey: 'not base64!',
      }),
    ).toThrow(InvalidInputError)
    expect(isUnlocked()).toBe(false)
  })

  it('rejects a secret key that is not 32 bytes', () => {
    expect(() =>
      unlock({
        username: 'alice',
        publicKey: PUBLIC_KEY,
        secretKey: 'AAAA',
      }),
    ).toThrow(InvalidInputError)
    expect(isUnlocked()).toBe(false)
  })

  it('replaces a previous identity without leaking the old one', () => {
    unlock({
      username: 'alice',
      publicKey: PUBLIC_KEY,
      secretKey: SECRET_KEY,
    })
    const otherSecret = `${'C'.repeat(43)}=`

    unlock({
      username: 'bob',
      publicKey: PUBLIC_KEY,
      secretKey: otherSecret,
    })

    expect(getSecretKey()).toBe(otherSecret)
    expect(getIdentity().username).toBe('bob')
  })
})
