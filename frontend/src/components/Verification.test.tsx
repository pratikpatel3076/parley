import {
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  acknowledgeKeyChange,
  generateIdentity,
  getContact,
  pinOrCheckContact,
  safetyNumber,
  setVerified,
} from '../crypto'
import type { Conversation } from '../messaging/store'
import { useMessagingStore } from '../messaging/store'
import { lockSession, useSessionStore } from '../session/store'
import { ChatScreen } from './ChatScreen'

const engine = vi.hoisted(() => ({
  start: vi.fn(),
  stop: vi.fn(),
  openConversation: vi.fn(),
  send: vi.fn(),
  retry: vi.fn(),
  acknowledgePeerKeyChange: vi.fn(),
}))

vi.mock('../messaging/engine', () => ({
  getMessageEngine: () => engine,
}))

let counter = 0

function usernames(): { owner: string; peer: string } {
  counter += 1
  return { owner: `alice${counter}`, peer: `bob${counter}` }
}

function conversation(
  peer: string,
  overrides: Partial<Conversation> = {},
): Conversation {
  return {
    peer,
    items: [],
    blocked: null,
    lastError: null,
    peerKey: null,
    safetyNumber: null,
    ...overrides,
  }
}

function setConversation(item: Conversation): void {
  useMessagingStore.setState({
    conversations: { [item.peer]: item },
  })
}

function digits(value: string | null | undefined): string {
  return (value ?? '').replace(/\D/g, '')
}

async function pin(
  owner: string,
  peer: string,
  key: string,
): Promise<void> {
  await pinOrCheckContact(owner, peer, key)
}

async function openPanel(
  owner: string,
  peer: string,
  myPublicKey: string,
): Promise<ReturnType<typeof render>> {
  useSessionStore.getState().setUnlocked(owner, myPublicKey)
  setConversation(conversation(peer))
  const view = render(<ChatScreen username={owner} />)
  fireEvent.click(screen.getByRole('button', { name: 'Verify' }))
  await screen.findByRole('dialog', { name: `Verify ${peer}` })
  return view
}

beforeEach(async () => {
  engine.start.mockReset().mockResolvedValue(undefined)
  engine.stop.mockReset()
  engine.openConversation.mockReset().mockResolvedValue(undefined)
  engine.send.mockReset().mockResolvedValue('client-id')
  engine.retry.mockReset().mockResolvedValue(undefined)
  engine.acknowledgePeerKeyChange.mockReset().mockResolvedValue(undefined)
  useMessagingStore.getState().clear()
  lockSession()
})

afterEach(() => {
  useMessagingStore.getState().clear()
  lockSession()
})

describe('safety number verification', () => {
  it('shows the same number for alice about bob and bob about alice', async () => {
    const { owner: aliceName, peer: bobName } = usernames()
    const [alice, bob] = await Promise.all([
      generateIdentity(),
      generateIdentity(),
    ])
    await pin(aliceName, bobName, bob.publicKey)
    await pin(bobName, aliceName, alice.publicKey)

    const first = await openPanel(aliceName, bobName, alice.publicKey)
    const fromAlice = digits(
      (await screen.findByLabelText(`Safety number with ${bobName}`))
        .textContent,
    )
    first.unmount()

    await openPanel(bobName, aliceName, bob.publicKey)
    const fromBob = digits(
      (await screen.findByLabelText(`Safety number with ${aliceName}`))
        .textContent,
    )

    expect(fromAlice).toHaveLength(60)
    expect(fromAlice).toBe(fromBob)
  })

  it('requires the checkbox before marking a contact verified', async () => {
    const { owner, peer } = usernames()
    const [alice, bob] = await Promise.all([
      generateIdentity(),
      generateIdentity(),
    ])
    await pin(owner, peer, bob.publicKey)

    await openPanel(owner, peer, alice.publicKey)

    const mark = await screen.findByRole('button', {
      name: 'Mark as verified',
    })
    expect(mark).toBeDisabled()
    fireEvent.click(mark)
    expect((await getContact(owner, peer))?.verified).toBe(false)

    fireEvent.click(
      screen.getByRole('checkbox', {
        name: /I compared these numbers with my contact/,
      }),
    )
    expect(mark).toBeEnabled()
    fireEvent.click(mark)

    await waitFor(async () => {
      expect((await getContact(owner, peer))?.verified).toBe(true)
    })
    expect(
      screen.getByRole('button', { name: 'Remove verification' }),
    ).toBeInTheDocument()
  })

  it('persists verification across a messaging store reset', async () => {
    const { owner, peer } = usernames()
    const [alice, bob] = await Promise.all([
      generateIdentity(),
      generateIdentity(),
    ])
    await pin(owner, peer, bob.publicKey)
    await setVerified(owner, peer, true)

    const first = await openPanel(owner, peer, alice.publicKey)
    await waitFor(() => {
      expect(screen.getByRole('status')).toHaveTextContent('Verified')
    })
    expect(
      await screen.findByRole('button', { name: 'Remove verification' }),
    ).toBeInTheDocument()

    first.unmount()
    useMessagingStore.getState().clear()
    setConversation(conversation(peer))
    await openPanel(owner, peer, alice.publicKey)

    await waitFor(() => {
      expect(screen.getByRole('status')).toHaveTextContent('Verified')
    })
    expect(
      await screen.findByRole('button', { name: 'Remove verification' }),
    ).toBeInTheDocument()
  })

  it('uses the pinned key even when the server presents a different key', async () => {
    const { owner, peer } = usernames()
    const [alice, bob, carol] = await Promise.all([
      generateIdentity(),
      generateIdentity(),
      generateIdentity(),
    ])
    await pin(owner, peer, bob.publicKey)

    const pinned = await safetyNumber(alice.publicKey, bob.publicKey)
    const seen = await safetyNumber(alice.publicKey, carol.publicKey)
    setConversation(
      conversation(peer, {
        blocked: {
          pinnedKey: bob.publicKey,
          seenKey: carol.publicKey,
          pinnedSafetyNumber: pinned,
          seenSafetyNumber: seen,
        },
      }),
    )
    useSessionStore.getState().setUnlocked(owner, alice.publicKey)
    render(<ChatScreen username={owner} />)
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }))

    const shown = await screen.findByLabelText(`Safety number with ${peer}`)
    expect(digits(shown.textContent)).toBe(digits(pinned))
    expect(digits(shown.textContent)).not.toBe(digits(seen))
    expect(screen.getByRole('status')).toHaveTextContent('Unverified')
  })

  it('resets verification and changes the number after a key change is accepted', async () => {
    const { owner, peer } = usernames()
    const [alice, bob, carol] = await Promise.all([
      generateIdentity(),
      generateIdentity(),
      generateIdentity(),
    ])
    await pin(owner, peer, bob.publicKey)
    await setVerified(owner, peer, true)

    const oldNumber = await safetyNumber(alice.publicKey, bob.publicKey)
    const newNumber = await safetyNumber(alice.publicKey, carol.publicKey)
    setConversation(
      conversation(peer, {
        blocked: {
          pinnedKey: bob.publicKey,
          seenKey: carol.publicKey,
          pinnedSafetyNumber: oldNumber,
          seenSafetyNumber: newNumber,
        },
      }),
    )
    useSessionStore.getState().setUnlocked(owner, alice.publicKey)

    engine.acknowledgePeerKeyChange.mockImplementation(async () => {
      await acknowledgeKeyChange(owner, peer, carol.publicKey)
      useMessagingStore.getState().setBlocked(peer, null)
      useMessagingStore.getState().setPeerSecurity(peer, {
        peerKey: carol.publicKey,
        safetyNumber: newNumber,
      })
    })

    render(<ChatScreen username={owner} />)
    expect(screen.getByRole('status')).toHaveTextContent('Unverified')

    fireEvent.click(
      screen.getByRole('button', { name: 'I compared the safety numbers' }),
    )

    await waitFor(async () => {
      expect((await getContact(owner, peer))?.verified).toBe(false)
    })
    await waitFor(() => {
      expect(screen.getByRole('status')).toHaveTextContent('Unverified')
    })

    fireEvent.click(screen.getByRole('button', { name: 'Verify' }))
    const shown = await screen.findByLabelText(`Safety number with ${peer}`)
    expect(digits(shown.textContent)).toBe(digits(newNumber))
    expect(digits(shown.textContent)).not.toBe(digits(oldNumber))
  })

  it('removes verification through the crypto layer', async () => {
    const { owner, peer } = usernames()
    const [alice, bob] = await Promise.all([
      generateIdentity(),
      generateIdentity(),
    ])
    await pin(owner, peer, bob.publicKey)
    await setVerified(owner, peer, true)

    await openPanel(owner, peer, alice.publicKey)
    fireEvent.click(
      await screen.findByRole('button', { name: 'Remove verification' }),
    )

    await waitFor(async () => {
      expect((await getContact(owner, peer))?.verified).toBe(false)
    })
    expect(
      await screen.findByRole('button', { name: 'Mark as verified' }),
    ).toBeDisabled()
    await waitFor(() => {
      expect(screen.getByRole('status')).toHaveTextContent('Unverified')
    })
  })
})
