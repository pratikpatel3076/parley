/**
 * Typed client for the Parley message endpoints.
 *
 * The server treats nonce and ciphertext as opaque bytes. This module only
 * validates the transport shape: required fields, strict primitive types, and
 * cursor pagination. Unknown fields are ignored so a server can add fields
 * without breaking an older client.
 */
import { apiFetch } from '../api/client'

const API_BASE = '/api/v1'

/** Hard cap on cursor pages fetched in one sync pass. */
export const MAX_PAGES_PER_SYNC = 50

/** A response did not match the documented message shape. */
export class MessageParseError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'MessageParseError'
  }
}

export interface MessageRow {
  id: string
  sender: string
  recipient: string
  clientMessageId: string
  nonce: string
  ciphertext: string
  clientTs: string
  createdAt: string
  ackedAt: string | null
}

export interface SendMessageInput {
  recipient: string
  clientMessageId: string
  nonce: string
  ciphertext: string
  clientTs: string
}

export interface SendMessageResult {
  id: string
  clientMessageId: string
  createdAt: string
}

export interface MessagePage {
  messages: MessageRow[]
  nextCursor: string | null
}

export interface Page<T> {
  items: T[]
  nextCursor: string | null
}

export interface AllPages<T> {
  items: T[]
  nextCursor: string | null
  pages: number
  /** True when the cap stopped the walk before the server was exhausted. */
  capped: boolean
}

function record(value: unknown, context: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new MessageParseError(`${context} must be an object`)
  }
  return value as Record<string, unknown>
}

function stringField(
  source: Record<string, unknown>,
  field: string,
  context: string,
): string {
  const value = source[field]
  if (typeof value !== 'string') {
    throw new MessageParseError(`${context}.${field} must be a string`)
  }
  return value
}

function nullableStringField(
  source: Record<string, unknown>,
  field: string,
  context: string,
): string | null {
  if (!(field in source)) {
    throw new MessageParseError(`${context}.${field} is required`)
  }
  const value = source[field]
  if (value !== null && typeof value !== 'string') {
    throw new MessageParseError(`${context}.${field} must be a string or null`)
  }
  return value
}

function parseMessageRow(value: unknown, index: number): MessageRow {
  const context = `messages[${index}]`
  const row = record(value, context)
  return {
    id: stringField(row, 'id', context),
    sender: stringField(row, 'sender', context),
    recipient: stringField(row, 'recipient', context),
    clientMessageId: stringField(row, 'client_message_id', context),
    nonce: stringField(row, 'nonce', context),
    ciphertext: stringField(row, 'ciphertext', context),
    clientTs: stringField(row, 'client_ts', context),
    createdAt: stringField(row, 'created_at', context),
    ackedAt: nullableStringField(row, 'acked_at', context),
  }
}

function parseMessagePage(value: unknown): MessagePage {
  const page = record(value, 'response')
  const messages = page.messages
  if (!Array.isArray(messages)) {
    throw new MessageParseError('response.messages must be an array')
  }
  const nextCursor = nullableStringField(page, 'next_cursor', 'response')
  return {
    messages: messages.map(parseMessageRow),
    nextCursor,
  }
}

function parseSendResponse(value: unknown): SendMessageResult {
  const response = record(value, 'response')
  return {
    id: stringField(response, 'id', 'response'),
    clientMessageId: stringField(
      response,
      'client_message_id',
      'response',
    ),
    createdAt: stringField(response, 'created_at', 'response'),
  }
}

function inboxPath(after?: string): string {
  return after === undefined
    ? `${API_BASE}/messages/inbox`
    : `${API_BASE}/messages/inbox?after=${encodeURIComponent(after)}`
}

function sentPath(after?: string): string {
  return after === undefined
    ? `${API_BASE}/messages/sent`
    : `${API_BASE}/messages/sent?after=${encodeURIComponent(after)}`
}

/** Fetch one inbox page. `after` is the opaque cursor from the prior page. */
export async function fetchInboxPage(after?: string): Promise<MessagePage> {
  const data = await apiFetch<unknown>(inboxPath(after))
  return parseMessagePage(data)
}

/** Fetch one sent-history page. */
export async function fetchSentPage(after?: string): Promise<MessagePage> {
  const data = await apiFetch<unknown>(sentPath(after))
  return parseMessagePage(data)
}

/**
 * Follow cursors until the server is exhausted or the hard page cap is hit.
 *
 * The returned `nextCursor` is where the next sync pass should resume. A
 * repeated or null cursor ends the walk; the server uses the input cursor for
 * an empty page.
 */
export async function fetchAllPages<T>(
  fetchPage: (after?: string) => Promise<Page<T>>,
  after?: string,
  maxPages = MAX_PAGES_PER_SYNC,
): Promise<AllPages<T>> {
  if (!Number.isSafeInteger(maxPages) || maxPages < 1) {
    throw new MessageParseError('maxPages must be a positive integer')
  }

  const items: T[] = []
  let cursor = after
  let pages = 0

  while (pages < maxPages) {
    const page = await fetchPage(cursor)
    pages += 1
    items.push(...page.items)
    const next = page.nextCursor
    if (next === null || next === cursor) {
      return { items, nextCursor: next, pages, capped: false }
    }
    cursor = next
  }

  return { items, nextCursor: cursor ?? null, pages, capped: true }
}

/** Send one encrypted message. A retry must reuse the exact same payload. */
export async function sendMessage(
  input: SendMessageInput,
): Promise<SendMessageResult> {
  const data = await apiFetch<unknown>(`${API_BASE}/messages`, {
    method: 'POST',
    body: JSON.stringify({
      recipient: input.recipient,
      client_message_id: input.clientMessageId,
      nonce: input.nonce,
      ciphertext: input.ciphertext,
      client_ts: input.clientTs,
    }),
  })
  return parseSendResponse(data)
}

/** Mark a received message as acknowledged. Idempotent server-side. */
export async function acknowledgeMessage(
  id: string,
): Promise<{ id: string; ackedAt: string | null }> {
  const data = await apiFetch<unknown>(
    `${API_BASE}/messages/${encodeURIComponent(id)}/ack`,
    { method: 'POST' },
  )
  const response = record(data, 'response')
  return {
    id: stringField(response, 'id', 'response'),
    ackedAt: nullableStringField(response, 'acked_at', 'response'),
  }
}
