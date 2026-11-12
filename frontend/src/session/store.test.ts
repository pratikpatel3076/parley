import { beforeEach, describe, expect, it } from 'vitest'

import { isUnlocked, unlock } from './vault'
import { lockSession, useSessionStore } from './store'

const SECRET_KEY = `${'A'.repeat(43)}=`
const PUBLIC_KEY = `${'B'.repeat(43)}=`

beforeEach(() => {
  lockSession()
})

describe('session store', () => {
  it('never contains the secret key or key-shaped fields', () => {
    unlock({
      username: 'alice',
      publicKey: PUBLIC_KEY,
      secretKey: SECRET_KEY,
    })
    useSessionStore.getState().setUnlocked('alice', PUBLIC_KEY)

    const serialized = JSON.stringify(useSessionStore.getState())

    expect(serialized).not.toContain(SECRET_KEY)
    expect(serialized).not.toContain('secretKey')
    expect(serialized).toContain('"status":"unlocked"')
    expect(serialized).toContain('"username":"alice"')
  })

  it('locks the vault and resets on session-expired', () => {
    unlock({
      username: 'alice',
      publicKey: PUBLIC_KEY,
      secretKey: SECRET_KEY,
    })
    useSessionStore.getState().setUnlocked('alice', PUBLIC_KEY)

    window.dispatchEvent(new Event('session-expired'))

    expect(isUnlocked()).toBe(false)
    const state = useSessionStore.getState()
    expect(state.status).toBe('signed_out')
    expect(state.username).toBeNull()
    expect(state.publicKey).toBeNull()
  })

  it('resets the store on lockSession', () => {
    unlock({
      username: 'alice',
      publicKey: PUBLIC_KEY,
      secretKey: SECRET_KEY,
    })
    useSessionStore.getState().setUnlocked('alice', PUBLIC_KEY)

    lockSession()

    expect(isUnlocked()).toBe(false)
    expect(useSessionStore.getState().status).toBe('signed_out')
  })
})
