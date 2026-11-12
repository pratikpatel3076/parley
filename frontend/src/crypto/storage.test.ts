import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

function openRequest(
  failingHandler: 'onerror' | 'onblocked',
): IDBOpenDBRequest {
  const request: Record<string, unknown> = {
    result: undefined,
    onupgradeneeded: null,
    onsuccess: null,
    onerror: null,
    onblocked: null,
  }
  Object.defineProperty(request, failingHandler, {
    configurable: true,
    set(handler: () => void) {
      handler()
    },
  })
  return request as unknown as IDBOpenDBRequest
}

beforeEach(() => {
  vi.resetModules()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('storage failure mapping', () => {
  it('maps an IndexedDB open error to StorageError', async () => {
    vi.stubGlobal('indexedDB', {
      open: () => openRequest('onerror'),
    })

    const { StorageError } = await import('./errors')
    const { loadIdentity } = await import('./storage')

    await expect(loadIdentity('alice')).rejects.toBeInstanceOf(StorageError)
  })

  it('maps a blocked upgrade to StorageError', async () => {
    vi.stubGlobal('indexedDB', {
      open: () => openRequest('onblocked'),
    })

    const { StorageError } = await import('./errors')
    const { loadIdentity } = await import('./storage')

    await expect(loadIdentity('alice')).rejects.toBeInstanceOf(StorageError)
  })

  it('maps a throwing transaction to StorageError without leaking DOMException', async () => {
    const raw = new DOMException('simulated transaction failure', 'UnknownError')
    const fakeDb = {
      transaction() {
        throw raw
      },
    }
    const request: Record<string, unknown> = {
      result: fakeDb,
      onupgradeneeded: null,
      onsuccess: null,
      onerror: null,
      onblocked: null,
    }
    Object.defineProperty(request, 'onsuccess', {
      configurable: true,
      set(handler: () => void) {
        handler()
      },
    })
    vi.stubGlobal('indexedDB', { open: () => request })

    const { StorageError } = await import('./errors')
    const { loadIdentity } = await import('./storage')

    const error = await loadIdentity('alice').catch((cause: unknown) => cause)
    expect(error).toBeInstanceOf(StorageError)
    expect(error).not.toBe(raw)
    expect((error as Error).name).toBe('StorageError')
  })

  it('maps a failing read request to StorageError', async () => {
    const request = {
      onsuccess: null,
      onerror: null,
    }
    Object.defineProperty(request, 'onerror', {
      configurable: true,
      set(handler: () => void) {
        handler()
      },
    })
    const store = {
      get: () => request,
    }
    const transaction = {
      objectStore: () => store,
      oncomplete: null,
      onerror: null,
      onabort: null,
    }
    const fakeDb = {
      transaction: () => transaction,
    }
    const open = {
      result: fakeDb,
      onupgradeneeded: null,
      onsuccess: null,
      onerror: null,
      onblocked: null,
    }
    Object.defineProperty(open, 'onsuccess', {
      configurable: true,
      set(handler: () => void) {
        handler()
      },
    })
    vi.stubGlobal('indexedDB', { open: () => open })

    const { StorageError } = await import('./errors')
    const { loadIdentity } = await import('./storage')

    await expect(loadIdentity('alice')).rejects.toBeInstanceOf(StorageError)
  })
})
