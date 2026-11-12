import { afterEach, describe, expect, it, vi } from 'vitest'

import { PBKDF2_ITERATIONS } from '../crypto/constants'
import { getKdfIterations, setKdfIterations } from './kdfConfig'

afterEach(() => {
  vi.unstubAllEnvs()
  setKdfIterations(PBKDF2_ITERATIONS)
})

describe('kdfConfig', () => {
  it('defaults to the production iteration count', () => {
    expect(getKdfIterations()).toBe(PBKDF2_ITERATIONS)
    expect(getKdfIterations()).toBe(600_000)
  })

  it('allows an override in test mode', () => {
    setKdfIterations(1_000)
    expect(getKdfIterations()).toBe(1_000)
  })

  it('rejects a non-positive or non-integer override', () => {
    expect(() => setKdfIterations(0)).toThrow()
    expect(() => setKdfIterations(1.5)).toThrow()
  })

  it('throws when called outside test mode', () => {
    vi.stubEnv('MODE', 'production')
    expect(() => setKdfIterations(1_000)).toThrow(
      'setKdfIterations is only available in test mode',
    )
  })
})
