import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import App from '../App'
import {
  deleteIdentity,
  generateIdentity,
  loadIdentity,
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
  it('refuses a weak password and an unchecked acknowledgement', () => {
    openRegisterScreen()

    fillRegister('password')
    fireEvent.click(screen.getByRole('checkbox'))
    expect(registerButton()).toBeDisabled()

    fillRegister(STRONG_PASSWORD)
    fireEvent.click(screen.getByRole('checkbox'))
    expect(registerButton()).toBeDisabled()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('refuses to overwrite an existing local identity', async () => {
    const existing = await createStoredIdentity(STRONG_PASSWORD)

    openRegisterScreen()
    fillRegister(STRONG_PASSWORD)
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(registerButton())

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
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(registerButton())

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'That username is taken',
    )
    expect(await loadIdentity(USERNAME)).toBeUndefined()
    expect(isUnlocked()).toBe(false)
  })

  it('clears the password fields after submit', async () => {
    fetchMock.mockImplementation(async () =>
      jsonResponse(409, { detail: 'Username is already taken' }),
    )

    openRegisterScreen()
    fillRegister(STRONG_PASSWORD)
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(registerButton())

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
