import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  ApiError,
  SESSION_EXPIRED_EVENT,
  apiFetch,
  getUserKey,
  login,
  logout,
  register,
} from './client'

function jsonResponse(status: number, body: unknown): Response {
  const text = JSON.stringify(body)
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => text,
  } as Response
}

const fetchMock = vi.fn()

function calls(): Array<[string, RequestInit | undefined]> {
  return fetchMock.mock.calls as Array<[string, RequestInit | undefined]>
}

function refreshCalls(): number {
  return calls().filter(([url]) => url === '/api/v1/auth/refresh').length
}

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('apiFetch single-flight refresh', () => {
  it('produces exactly one refresh call for concurrent 401 responses', async () => {
    const seen = new Map<string, number>()
    let refreshes = 0

    fetchMock.mockImplementation(async (input: string) => {
      const url = String(input)
      if (url === '/api/v1/auth/refresh') {
        refreshes += 1
        return jsonResponse(200, { status: 'ok' })
      }
      const count = (seen.get(url) ?? 0) + 1
      seen.set(url, count)
      if (count === 1) {
        return jsonResponse(401, { detail: 'Not authenticated' })
      }
      return jsonResponse(200, { username: 'alice', public_key: 'AAAA' })
    })

    await Promise.all([getUserKey('alice'), getUserKey('bob')])

    expect(refreshes).toBe(1)
    expect(refreshCalls()).toBe(1)
  })

  it('retries the original request once after a successful refresh', async () => {
    let originalCalls = 0

    fetchMock.mockImplementation(async (input: string) => {
      const url = String(input)
      if (url === '/api/v1/auth/refresh') {
        return jsonResponse(200, { status: 'ok' })
      }
      originalCalls += 1
      if (originalCalls === 1) {
        return jsonResponse(401, { detail: 'Not authenticated' })
      }
      return jsonResponse(200, { username: 'alice', public_key: 'AAAA' })
    })

    const result = await getUserKey('alice')

    expect(result).toEqual({ username: 'alice', public_key: 'AAAA' })
    expect(calls()).toHaveLength(3)
    expect(calls()[2][0]).toBe('/api/v1/users/alice/key')
    expect(calls()[2][1]?.credentials).toBe('include')
  })

  it('retries once after a 401 refresh, then emits session-expired', async () => {
    const expired = vi.fn()
    window.addEventListener(SESSION_EXPIRED_EVENT, expired)

    fetchMock.mockImplementation(async (input: string) => {
      const url = String(input)
      if (url === '/api/v1/auth/refresh') {
        return jsonResponse(401, { detail: 'Invalid refresh token' })
      }
      return jsonResponse(401, { detail: 'Not authenticated' })
    })

    try {
      const error = await getUserKey('alice').catch((cause: unknown) => cause)

      expect(error).toBeInstanceOf(ApiError)
      expect((error as ApiError).status).toBe(401)
      expect(expired).toHaveBeenCalledTimes(1)
      // Initial request, refresh, one retry. No loop.
      expect(calls()).toHaveLength(3)
    } finally {
      window.removeEventListener(SESSION_EXPIRED_EVENT, expired)
    }
  })

  it('accepts a retry that succeeds after a 401 refresh', async () => {
    const expired = vi.fn()
    window.addEventListener(SESSION_EXPIRED_EVENT, expired)
    let originalCalls = 0

    fetchMock.mockImplementation(async (input: string) => {
      const url = String(input)
      if (url === '/api/v1/auth/refresh') {
        return jsonResponse(401, { detail: 'Invalid refresh token' })
      }
      originalCalls += 1
      if (originalCalls === 1) {
        return jsonResponse(401, { detail: 'Not authenticated' })
      }
      return jsonResponse(200, { username: 'alice', public_key: 'AAAA' })
    })

    try {
      const result = await getUserKey('alice')

      expect(result).toEqual({ username: 'alice', public_key: 'AAAA' })
      expect(expired).not.toHaveBeenCalled()
      expect(calls()).toHaveLength(3)
    } finally {
      window.removeEventListener(SESSION_EXPIRED_EVENT, expired)
    }
  })
})

describe('auth endpoints', () => {
  it('never refreshes after a login 401', async () => {
    fetchMock.mockImplementation(async () =>
      jsonResponse(401, { detail: 'Invalid credentials' }),
    )

    const error = await login({
      username: 'alice',
      authSecret: 'AAAA',
    }).catch((cause: unknown) => cause)

    expect(error).toBeInstanceOf(ApiError)
    expect((error as ApiError).status).toBe(401)
    expect(calls()).toHaveLength(1)
    expect(refreshCalls()).toBe(0)
  })

  it('never refreshes after a register 409', async () => {
    fetchMock.mockImplementation(async () =>
      jsonResponse(409, { detail: 'Username is already taken' }),
    )

    const error = await register({
      username: 'alice',
      authSecret: 'AAAA',
      publicKey: 'BBBB',
    }).catch((cause: unknown) => cause)

    expect(error).toBeInstanceOf(ApiError)
    expect((error as ApiError).status).toBe(409)
    expect(refreshCalls()).toBe(0)
  })

  it('never refreshes after a logout 401', async () => {
    fetchMock.mockImplementation(async () =>
      jsonResponse(401, { detail: 'Not authenticated' }),
    )

    await expect(logout()).rejects.toBeInstanceOf(ApiError)
    expect(calls()).toHaveLength(1)
    expect(refreshCalls()).toBe(0)
  })
})

describe('safe errors', () => {
  it('never includes the request body in an error', async () => {
    const secret = 'auth-secret-value-that-must-not-leak'
    fetchMock.mockImplementation(async () =>
      jsonResponse(422, { detail: 'authSecret is invalid' }),
    )

    const error = await apiFetch('/api/v1/users/alice/key', {
      method: 'POST',
      body: JSON.stringify({ authSecret: secret }),
    }).catch((cause: unknown) => cause)

    expect(error).toBeInstanceOf(ApiError)
    const serialized = `${(error as Error).name}:${(error as Error).message}`
    expect(serialized).not.toContain(secret)
    expect((error as ApiError).message).toBe('authSecret is invalid')
  })
})
