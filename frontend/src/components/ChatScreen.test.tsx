import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { Conversation, OutgoingPayload } from '../messaging/store'
import { useMessagingStore } from '../messaging/store'
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

const USERNAME = 'alice'

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

function setConversations(...list: Conversation[]): void {
  useMessagingStore.setState({
    conversations: Object.fromEntries(list.map((item) => [item.peer, item])),
  })
}

const pending: OutgoingPayload = {
  clientMessageId: 'client-1',
  recipient: 'bob',
  nonce: 'nonce',
  ciphertext: 'ciphertext',
  clientTs: '2026-01-01T00:00:00.000Z',
}

beforeEach(() => {
  useMessagingStore.getState().clear()
  engine.start.mockReset().mockResolvedValue(undefined)
  engine.stop.mockReset()
  engine.openConversation.mockReset().mockResolvedValue(undefined)
  engine.send.mockReset().mockResolvedValue('client-id')
  engine.retry.mockReset().mockResolvedValue(undefined)
  engine.acknowledgePeerKeyChange.mockReset().mockResolvedValue(undefined)
})

afterEach(() => {
  useMessagingStore.getState().clear()
})

describe('ChatScreen', () => {
  it('starts and stops the engine with the screen', () => {
    const view = render(<ChatScreen username={USERNAME} />)

    expect(engine.start).toHaveBeenCalledTimes(1)
    expect(engine.stop).not.toHaveBeenCalled()

    view.unmount()

    expect(engine.stop).toHaveBeenCalledTimes(1)
  })

  it('renders message bodies as plain text', () => {
    setConversations(
      conversation('bob', {
        items: [
          {
            kind: 'message',
            id: 'row-1',
            clientMessageId: 'client-1',
            direction: 'in',
            body: '<img src=x onerror="alert(1)">',
            createdAt: '2026-01-01T00:00:00.000Z',
          },
        ],
      }),
    )

    const { container } = render(<ChatScreen username={USERNAME} />)

    expect(
      within(screen.getByRole('list', { name: 'Messages' })).getByText(
        '<img src=x onerror="alert(1)">',
      ),
    ).toBeInTheDocument()
    expect(container.querySelector('img')).toBeNull()
    expect(screen.getByRole('heading', { name: 'bob' })).toBeInTheDocument()
  })

  it('sends plain text to the selected conversation', async () => {
    setConversations(conversation('bob'))

    render(<ChatScreen username={USERNAME} />)

    fireEvent.change(screen.getByLabelText('Message'), {
      target: { value: 'hello bob' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Send' }))

    await waitFor(() => {
      expect(engine.send).toHaveBeenCalledWith('bob', 'hello bob')
    })
    expect(screen.getByLabelText('Message')).toHaveValue('')
  })

  it('shows both safety numbers and blocks sending after a key change', async () => {
    setConversations(
      conversation('bob', {
        blocked: {
          pinnedKey: 'pinned-key',
          seenKey: 'seen-key',
          pinnedSafetyNumber: '11111 22222',
          seenSafetyNumber: '33333 44444',
        },
      }),
    )

    render(<ChatScreen username={USERNAME} />)

    expect(
      screen.getByText('The public key for bob changed'),
    ).toBeInTheDocument()
    expect(screen.getByText('11111 22222')).toBeInTheDocument()
    expect(screen.getByText('33333 44444')).toBeInTheDocument()
    expect(screen.getByLabelText('Message')).toBeDisabled()

    fireEvent.click(
      screen.getByRole('button', { name: 'I compared the safety numbers' }),
    )

    await waitFor(() => {
      expect(engine.acknowledgePeerKeyChange).toHaveBeenCalledWith('bob')
    })
  })

  it('reports a rejected retry without leaving the button stuck', async () => {
    setConversations(
      conversation('bob', {
        items: [
          {
            kind: 'message',
            id: 'local-client-1',
            clientMessageId: 'client-1',
            direction: 'out',
            body: 'hello',
            createdAt: '2026-01-01T00:00:00.000Z',
            status: 'failed',
            failure: 'Could not reach the server.',
            pending,
          },
        ],
      }),
    )
    engine.retry.mockRejectedValue(new Error('payload dropped'))

    render(<ChatScreen username={USERNAME} />)

    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))

    expect(
      await screen.findByText('This message could not be retried.'),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Retry' })).toBeEnabled()
  })

  it('opens a conversation by username', async () => {
    render(<ChatScreen username={USERNAME} />)

    fireEvent.change(screen.getByLabelText('Open a conversation'), {
      target: { value: 'bob' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Open' }))

    await waitFor(() => {
      expect(engine.openConversation).toHaveBeenCalledWith('bob')
    })
    expect(screen.getByLabelText('Open a conversation')).toHaveValue('')
  })

  it('rejects an invalid username before calling the engine', () => {
    render(<ChatScreen username={USERNAME} />)

    fireEvent.change(screen.getByLabelText('Open a conversation'), {
      target: { value: 'Not A Username' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Open' }))

    expect(
      screen.getByText(
        'Usernames are 3–32 lowercase letters, digits, or underscores.',
      ),
    ).toBeInTheDocument()
    expect(engine.openConversation).not.toHaveBeenCalled()
  })
})
