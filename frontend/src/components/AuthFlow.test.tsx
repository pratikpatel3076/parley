import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import App from '../App'
import {
  deleteIdentity,
  generateIdentity,
  getContact,
  loadIdentity,
  pinOrCheckContact,
  saveIdentity,
  wrapSecretKey,
  type Identity,
} from '../crypto'
import { PBKDF2_ITERATIONS } from '../crypto/constants'
import { setKdfIterations } from '../session/kdfConfig'
import { lockSession, useSessionStore } from '../session/store'
import { getSecretKey, isUnlocked, lock } from '../session/vault'

const STRONG_PASSWORD = 'Xk7#mQ2!vL9$pR4@zN8&'
const USERNAME = 'alice'

const fetchMock = vi.fn()

function jsonResponse(status: number, body: unknown): Response {
  const text = JSON.stringify(body)
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => text,
  } as Response
}

function calls(): Array<[string, RequestInit | undefined]> {
  return fetchMock.mock.calls as Array<[string, RequestInit | undefined]>
}

async function createStoredIdentity(
  password: string,
): Promise<Identity> {
  const identity = await generateIdentity()
  const wrapped = await wrapSecretKey(
    identity.secretKey,
    identity.publicKey,
    password,
    { iterations: 1 },
  )
  await saveIdentity({
    username: USERNAME,
    publicKey: identity.publicKey,
    wrapped,
  })
  return identity
}

function openRegisterScreen(): void {
  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: 'Create an account' }))
}

function fillRegister(password: string, confirm = password): void {
  fireEvent.change(screen.getByLabelText('Username'), {
    target: { value: USERNAME },
  })
  fireEvent.change(screen.getByLabelText('Password'), {
    target: { value: password },
  })
  fireEvent.change(screen.getByLabelText('Confirm password'), {
    target: { value: confirm },
  })
}

function registerButton(): HTMLElement {
  return screen.getByRole('button', { name: 'Create account' })
}

async function waitForStrength(): Promise<void> {
  await waitFor(() => {
    expect(screen.queryByText('checking…')).not.toBeInTheDocument()
  })
}

async function submitRegistration(): Promise<void> {
  fireEvent.click(screen.getByRole('checkbox'))
  await waitForStrength()
  await waitFor(() => {
    expect(registerButton()).toBeEnabled()
  })
  fireEvent.click(registerButton())
}

function fillLogin(password: string): void {
  fireEvent.change(screen.getByLabelText('Username'), {
    target: { value: USERNAME },
  })
  fireEvent.change(screen.getByLabelText('Password'), {
    target: { value: password },
  })
  fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
}

beforeEach(() => {
  setKdfIterations(1)
  lockSession()
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
  localStorage.clear()
})

afterEach(async () => {
  vi.unstubAllGlobals()
  setKdfIterations(PBKDF2_ITERATIONS)
  lock()
  await deleteIdentity(USERNAME)
})

describe('register', () => {
  it('refuses a weak password and an unchecked acknowledgement', async () => {
    openRegisterScreen()

    fillRegister('password')
    fireEvent.click(screen.getByRole('checkbox'))
    await waitForStrength()
    expect(registerButton()).toBeDisabled()

    fillRegister(STRONG_PASSWORD)
    fireEvent.click(screen.getByRole('checkbox'))
    await waitForStrength()
    expect(registerButton()).toBeDisabled()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('refuses to overwrite an existing local identity', async () => {
    const existing = await createStoredIdentity(STRONG_PASSWORD)

    openRegisterScreen()
    fillRegister(STRONG_PASSWORD)
    await submitRegistration()

    expect(
      await screen.findByText(/already has a key for that username/i),
    ).toBeInTheDocument()
    expect(fetchMock).not.toHaveBeenCalled()

    const stored = await loadIdentity(USERNAME)
    expect(stored?.publicKey).toBe(existing.publicKey)
  })

  it('deletes the local identity it created when registration fails', async () => {
    fetchMock.mockImplementation(async () =>
      jsonResponse(409, { detail: 'Username is already taken' }),
    )

    openRegisterScreen()
    fillRegister(STRONG_PASSWORD)
    await submitRegistration()

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'That username is taken',
    )
    expect(await loadIdentity(USERNAME)).toBeUndefined()
    expect(isUnlocked()).toBe(false)
  })

  it('deletes the local identity after a definitive 422', async () => {
    fetchMock.mockImplementation(async () =>
      jsonResponse(422, { detail: 'Invalid publicKey' }),
    )

    openRegisterScreen()
    fillRegister(STRONG_PASSWORD)
    await submitRegistration()

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The server rejected the username or key',
    )
    expect(await loadIdentity(USERNAME)).toBeUndefined()
  })

  it('keeps the local identity after a network error', async () => {
    fetchMock.mockImplementation(async () => {
      throw new TypeError('Failed to fetch')
    })

    openRegisterScreen()
    fillRegister(STRONG_PASSWORD)
    await submitRegistration()

    expect(await screen.findByRole('alert')).toHaveTextContent(
      /Registration may have succeeded/,
    )
    expect(await loadIdentity(USERNAME)).toBeDefined()
  })

  it('keeps the local identity when a 201 reports a different key', async () => {
    const other = await generateIdentity()
    fetchMock.mockImplementation(async () =>
      jsonResponse(201, {
        user: {
          id: 'user-id',
          username: USERNAME,
          public_key: other.publicKey,
          created_at: '2026-01-01T00:00:00Z',
        },
      }),
    )

    openRegisterScreen()
    fillRegister(STRONG_PASSWORD)
    await submitRegistration()

    expect(await screen.findByRole('alert')).toHaveTextContent(
      /different key for this account/,
    )
    const stored = await loadIdentity(USERNAME)
    expect(stored).toBeDefined()
    expect(stored?.publicKey).not.toBe(other.publicKey)
    expect(isUnlocked()).toBe(false)
  })

  it('keeps the local identity when a 201 reports a different username', async () => {
    fetchMock.mockImplementation(
      async (_input: string, init: RequestInit | undefined) => {
        const body = JSON.parse(String(init?.body)) as {
          publicKey: string
        }
        return jsonResponse(201, {
          user: {
            id: 'user-id',
            username: 'someone_else',
            public_key: body.publicKey,
            created_at: '2026-01-01T00:00:00Z',
          },
        })
      },
    )

    openRegisterScreen()
    fillRegister(STRONG_PASSWORD)
    await submitRegistration()

    expect(await screen.findByRole('alert')).toHaveTextContent(
      /different username/,
    )
    expect(await loadIdentity(USERNAME)).toBeDefined()
    expect(isUnlocked()).toBe(false)
  })

  it('clears the password fields after submit', async () => {
    fetchMock.mockImplementation(async () =>
      jsonResponse(409, { detail: 'Username is already taken' }),
    )

    openRegisterScreen()
    fillRegister(STRONG_PASSWORD)
    await submitRegistration()

    await screen.findByRole('alert')

    expect(screen.getByLabelText('Password')).toHaveValue('')
    expect(screen.getByLabelText('Confirm password')).toHaveValue('')
  })
})

describe('login', () => {
  it('checks the password locally and never calls fetch when it is wrong', async () => {
    await createStoredIdentity(STRONG_PASSWORD)

    render(<App />)
    fillLogin('definitely-the-wrong-password')

    expect(await screen.findByRole('alert')).toHaveTextContent('Wrong password')
    expect(fetchMock).not.toHaveBeenCalled()
    expect(screen.getByLabelText('Password')).toHaveValue('')
    expect(isUnlocked()).toBe(false)
  })

  it('unlocks the vault on success', async () => {
    const identity = await createStoredIdentity(STRONG_PASSWORD)
    fetchMock.mockImplementation(async () =>
      jsonResponse(200, {
        user: {
          id: 'user-id',
          username: USERNAME,
          public_key: identity.publicKey,
          created_at: '2026-01-01T00:00:00Z',
        },
      }),
    )

    render(<App />)
    fillLogin(STRONG_PASSWORD)

    expect(
      await screen.findByRole('heading', { name: 'Signed in' }),
    ).toBeInTheDocument()
    expect(isUnlocked()).toBe(true)
    expect(getSecretKey()).toBe(identity.secretKey)

    const body = calls()[0][1]?.body
    expect(typeof body).toBe('string')
    expect(body as string).not.toContain(STRONG_PASSWORD)
    expect(JSON.stringify(useSessionStore.getState())).not.toContain(
      identity.secretKey,
    )
  })

  it('refuses to unlock when the server reports a different key', async () => {
    await createStoredIdentity(STRONG_PASSWORD)
    const other = await generateIdentity()

    fetchMock.mockImplementation(async (input: string) => {
      const url = String(input)
      if (url === '/api/v1/auth/logout') {
        return jsonResponse(200, { status: 'ok' })
      }
      return jsonResponse(200, {
        user: {
          id: 'user-id',
          username: USERNAME,
          public_key: other.publicKey,
          created_at: '2026-01-01T00:00:00Z',
        },
      })
    })

    render(<App />)
    fillLogin(STRONG_PASSWORD)

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The server reports a different key for this account than this device holds',
    )
    expect(isUnlocked()).toBe(false)
    expect(
      calls().some(([url]) => url === '/api/v1/auth/logout'),
    ).toBe(true)
  })
})

describe('remove this device key', () => {
  it('requires the typed username, deletes the identity and pins, and never calls fetch', async () => {
    await createStoredIdentity(STRONG_PASSWORD)
    const contact = await generateIdentity()
    await pinOrCheckContact(USERNAME, 'bob', contact.publicKey)
    expect(await getContact(USERNAME, 'bob')).toBeDefined()

    render(<App />)
    fireEvent.change(screen.getByLabelText('Username'), {
      target: { value: USERNAME },
    })

    fireEvent.click(
      screen.getByRole('button', {
        name: /Remove this device.s key for alice/,
      }),
    )

    const removeButton = screen.getByRole('button', { name: 'Remove key' })
    expect(removeButton).toBeDisabled()

    fireEvent.change(screen.getByLabelText(`Type ${USERNAME} to confirm`), {
      target: { value: 'not-alice' },
    })
    expect(removeButton).toBeDisabled()

    fireEvent.change(screen.getByLabelText(`Type ${USERNAME} to confirm`), {
      target: { value: USERNAME },
    })
    fireEvent.click(removeButton)

    expect(
      await screen.findByText(`Removed this device’s key for ${USERNAME}.`),
    ).toBeInTheDocument()
    expect(await loadIdentity(USERNAME)).toBeUndefined()
    expect(await getContact(USERNAME, 'bob')).toBeUndefined()
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('logout', () => {
  it('calls the logout endpoint and locks the vault', async () => {
    fetchMock.mockImplementation(async () =>
      jsonResponse(200, { status: 'ok' }),
    )
    useSessionStore.getState().setUnlocked(USERNAME, 'public-key')

    render(<App />)
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))

    expect(
      await screen.findByRole('heading', { name: 'Sign in' }),
    ).toBeInTheDocument()
    expect(calls()).toHaveLength(1)
    expect(calls()[0][0]).toBe('/api/v1/auth/logout')
    expect(isUnlocked()).toBe(false)
    expect(useSessionStore.getState().status).toBe('signed_out')
  })

  it('still signs out locally when the network fails', async () => {
    fetchMock.mockImplementation(async () => {
      throw new TypeError('Failed to fetch')
    })
    useSessionStore.getState().setUnlocked(USERNAME, 'public-key')

    render(<App />)
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))

    await waitFor(() => {
      expect(useSessionStore.getState().status).toBe('signed_out')
    })
    expect(isUnlocked()).toBe(false)
  })
})
