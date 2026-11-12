import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  MAX_PAGES_PER_SYNC,
  MessageParseError,
  acknowledgeMessage,
  fetchAllPages,
  fetchInboxPage,
  fetchSentPage,
  sendMessage,
  type MessageRow,
} from './api'

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

const CLIENT_ID = '2f1b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d'

function row(overrides: Partial<MessageRow> = {}): MessageRow {
  return {
    id: '11111111-1111-4111-8111-111111111111',
    sender: 'alice',
    recipient: 'bob',
    clientMessageId: CLIENT_ID,
    nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    ciphertext: 'ZmFrZQ==',
    clientTs: '2026-01-01T00:00:00Z',
    createdAt: '2026-01-01T00:00:01Z',
    ackedAt: null,
    ...overrides,
  }
}

function wireRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const value = row(overrides as Partial<MessageRow>)
  return {
    id: value.id,
    sender: value.sender,
    recipient: value.recipient,
    client_message_id: value.clientMessageId,
    nonce: value.nonce,
    ciphertext: value.ciphertext,
    client_ts: value.clientTs,
    created_at: value.createdAt,
    acked_at: value.ackedAt,
    ...overrides,
  }
}

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('sendMessage', () => {
  it('posts the documented snake_case body and parses 201', async () => {
    fetchMock.mockImplementation(async () =>
      jsonResponse(201, {
        id: '22222222-2222-4222-8222-222222222222',
        client_message_id: CLIENT_ID,
        created_at: '2026-01-01T00:00:02Z',
        ignored: 'extra',
      }),
    )

    const result = await sendMessage({
      recipient: 'bob',
      clientMessageId: CLIENT_ID,
      nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      ciphertext: 'ZmFrZQ==',
      clientTs: '2026-01-01T00:00:00Z',
    })

    expect(result).toEqual({
      id: '22222222-2222-4222-8222-222222222222',
      clientMessageId: CLIENT_ID,
      createdAt: '2026-01-01T00:00:02Z',
    })
    expect(calls()[0][0]).toBe('/api/v1/messages')
    expect(calls()[0][1]?.method).toBe('POST')
    expect(JSON.parse(String(calls()[0][1]?.body))).toEqual({
      recipient: 'bob',
      client_message_id: CLIENT_ID,
      nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      ciphertext: 'ZmFrZQ==',
      client_ts: '2026-01-01T00:00:00Z',
    })
  })

  it('accepts a 200 replay response with the original id', async () => {
    fetchMock.mockImplementation(async () =>
      jsonResponse(200, {
        id: '22222222-2222-4222-8222-222222222222',
        client_message_id: CLIENT_ID,
        created_at: '2026-01-01T00:00:02Z',
      }),
    )

    await expect(
      sendMessage({
        recipient: 'bob',
        clientMessageId: CLIENT_ID,
        nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        ciphertext: 'ZmFrZQ==',
        clientTs: '2026-01-01T00:00:00Z',
      }),
    ).resolves.toMatchObject({ clientMessageId: CLIENT_ID })
  })

  it('rejects a response with a missing required field', async () => {
    fetchMock.mockImplementation(async () =>
      jsonResponse(201, { id: 'x', created_at: '2026-01-01T00:00:00Z' }),
    )

    await expect(
      sendMessage({
        recipient: 'bob',
        clientMessageId: CLIENT_ID,
        nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        ciphertext: 'ZmFrZQ==',
        clientTs: '2026-01-01T00:00:00Z',
      }),
    ).rejects.toBeInstanceOf(MessageParseError)
  })
})

describe('inbox and sent pages', () => {
  it('parses a backend-shaped inbox page and ignores unknown fields', async () => {
    fetchMock.mockImplementation(async () =>
      jsonResponse(200, {
        messages: [wireRow({ extra: 'ignored' })],
        next_cursor: 'cursor-2',
      }),
    )

    const page = await fetchInboxPage('cursor-1')

    expect(page.messages).toEqual([row()])
    expect(page.nextCursor).toBe('cursor-2')
    expect(calls()[0][0]).toBe(
      '/api/v1/messages/inbox?after=cursor-1',
    )
  })

  it('parses a sent page with a null cursor', async () => {
    fetchMock.mockImplementation(async () =>
      jsonResponse(200, { messages: [], next_cursor: null }),
    )

    const page = await fetchSentPage()

    expect(page).toEqual({ messages: [], nextCursor: null })
    expect(calls()[0][0]).toBe('/api/v1/messages/sent')
  })

  it('rejects a row with a non-string ciphertext', async () => {
    fetchMock.mockImplementation(async () =>
      jsonResponse(200, {
        messages: [wireRow({ ciphertext: 42 })],
        next_cursor: null,
      }),
    )

    await expect(fetchInboxPage()).rejects.toBeInstanceOf(MessageParseError)
  })

  it('requires acked_at to be present and nullable', async () => {
    const missing = wireRow()
    delete missing.acked_at
    fetchMock.mockImplementationOnce(async () =>
      jsonResponse(200, { messages: [missing], next_cursor: null }),
    )

    await expect(fetchInboxPage()).rejects.toBeInstanceOf(MessageParseError)

    fetchMock.mockImplementationOnce(async () =>
      jsonResponse(200, {
        messages: [wireRow({ acked_at: 5 })],
        next_cursor: null,
      }),
    )
    await expect(fetchInboxPage()).rejects.toBeInstanceOf(MessageParseError)
  })

  it('rejects a non-array messages field', async () => {
    fetchMock.mockImplementation(async () =>
      jsonResponse(200, { messages: {}, next_cursor: null }),
    )

    await expect(fetchInboxPage()).rejects.toBeInstanceOf(MessageParseError)
  })
})

describe('fetchAllPages', () => {
  it('follows cursors until null and reports every page', async () => {
    const fetchPage = vi
      .fn()
      .mockResolvedValueOnce({ items: ['a'], nextCursor: 'c1' })
      .mockResolvedValueOnce({ items: ['b'], nextCursor: 'c2' })
      .mockResolvedValueOnce({ items: ['c'], nextCursor: null })

    const result = await fetchAllPages(fetchPage)

    expect(result).toEqual({
      items: ['a', 'b', 'c'],
      nextCursor: null,
      pages: 3,
      capped: false,
    })
    expect(fetchPage.mock.calls).toEqual([[undefined], ['c1'], ['c2']])
  })

  it('stops when the server repeats the input cursor', async () => {
    const fetchPage = vi
      .fn()
      .mockResolvedValue({ items: [], nextCursor: 'same' })

    const result = await fetchAllPages(fetchPage, 'same')

    expect(result).toMatchObject({ pages: 1, capped: false })
  })

  it('enforces the 50-page cap', async () => {
    const fetchPage = vi.fn(async (after?: string) => ({
      items: [after ?? 'start'],
      nextCursor: `cursor-${Number(after?.split('-')[1] ?? 0) + 1}`,
    }))

    const result = await fetchAllPages(fetchPage, 'cursor-0')

    expect(result.pages).toBe(MAX_PAGES_PER_SYNC)
    expect(result.capped).toBe(true)
    expect(fetchPage).toHaveBeenCalledTimes(MAX_PAGES_PER_SYNC)
    expect(result.nextCursor).toBe(`cursor-${MAX_PAGES_PER_SYNC}`)
  })
})

describe('acknowledgeMessage', () => {
  it('posts to the message ack path and parses the response', async () => {
    fetchMock.mockImplementation(async () =>
      jsonResponse(200, {
        id: '11111111-1111-4111-8111-111111111111',
        acked_at: '2026-01-01T00:00:03Z',
      }),
    )

    const result = await acknowledgeMessage(
      '11111111-1111-4111-8111-111111111111',
    )

    expect(result).toEqual({
      id: '11111111-1111-4111-8111-111111111111',
      ackedAt: '2026-01-01T00:00:03Z',
    })
    expect(calls()[0][0]).toBe(
      '/api/v1/messages/11111111-1111-4111-8111-111111111111/ack',
    )
    expect(calls()[0][1]?.method).toBe('POST')
  })
})
