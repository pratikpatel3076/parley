import { randomUUID } from 'node:crypto'

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../api/client'
import {
  InvalidInputError,
  KeyChangedError,
  decryptReceived,
  decryptSent,
  encryptMessage,
  generateIdentity,
  getContact,
  pinOrCheckContact,
  ready,
  type Identity,
} from '../crypto'
import { lockSession, useSessionStore } from '../session/store'
import { isUnlocked, lock, unlock } from '../session/vault'
import {
  MAX_PAGES_PER_SYNC,
  type MessageRow,
  type SendMessageInput,
  type SendMessageResult,
} from './api'
import { MessageEngine, type EngineDeps } from './engine'
import { clearMessaging, useMessagingStore } from './store'

const engines: MessageEngine[] = []

interface FakeServer {
  keys: Map<string, string>
  inbox: MessageRow[]
  sent: MessageRow[]
  inboxCalls: Array<string | undefined>
  sentCalls: Array<string | undefined>
  sendCalls: SendMessageInput[]
  ackCalls: string[]
  sendQueue: Array<Error | null>
  ackQueue: Array<Error | null>
  inboxFailures: number
  endlessInbox: boolean
  endlessPage: number
  ignoreCursor: boolean
  inboxGate: Promise<void> | null
  pageSize: number
}

function createServer(): FakeServer {
  return {
    keys: new Map(),
    inbox: [],
    sent: [],
    inboxCalls: [],
    sentCalls: [],
    sendCalls: [],
    ackCalls: [],
    sendQueue: [],
    ackQueue: [],
    inboxFailures: 0,
    endlessInbox: false,
    endlessPage: 0,
    ignoreCursor: false,
    inboxGate: null,
    pageSize: 100,
  }
}

interface PageResult {
  messages: MessageRow[]
  nextCursor: string | null
}

function pageOf(
  rows: MessageRow[],
  after: string | undefined,
  pageSize: number,
): PageResult {
  const parsed = after === undefined ? 0 : Number(after)
  const start = Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : 0
  const slice = rows.slice(start, start + pageSize)
  return {
    messages: slice,
    nextCursor:
      slice.length > 0 ? String(start + slice.length) : (after ?? null),
  }
}

class ManualClock {
  now = 0
  readonly delays: number[] = []
  private nextId = 1
  private tasks: Array<{
    id: number
    at: number
    callback: () => void | Promise<void>
  }> = []

  setTimer = (
    callback: () => void | Promise<void>,
    milliseconds: number,
  ): number => {
    const id = this.nextId
    this.nextId += 1
    this.tasks.push({ id, at: this.now + milliseconds, callback })
    this.delays.push(milliseconds)
    return id
  }

  clearTimer = (handle: unknown): void => {
    const id = handle as number
    this.tasks = this.tasks.filter((task) => task.id !== id)
  }

  pending(): number {
    return this.tasks.length
  }

  async advance(milliseconds: number): Promise<void> {
    this.now += milliseconds
    for (;;) {
      const due = this.tasks
        .filter((task) => task.at <= this.now)
        .sort((left, right) => left.at - right.at)
      if (due.length === 0) {
        return
      }
      const task = due[0]
      this.tasks = this.tasks.filter((item) => item.id !== task.id)
      await task.callback()
    }
  }
}

interface Harness {
  owner: string
  peer: string
  alice: Identity
  bob: Identity
  carol: Identity
  server: FakeServer
  clock: ManualClock
  visibility: { visible: boolean }
  waits: number[]
  encryptSpy: ReturnType<typeof vi.fn>
  decryptSpy: ReturnType<typeof vi.fn>
  engine: MessageEngine
}

async function createHarness(): Promise<Harness> {
  const [alice, bob, carol] = await Promise.all([
    generateIdentity(),
    generateIdentity(),
    generateIdentity(),
  ])
  const suffix = Math.random().toString(36).slice(2, 8)
  const owner = `alice${suffix}`
  const peer = `bob${suffix}`

  unlock({
    username: owner,
    publicKey: alice.publicKey,
    secretKey: alice.secretKey,
  })
  useSessionStore.getState().setUnlocked(owner, alice.publicKey)
  clearMessaging()

  const server = createServer()
  server.keys.set(owner, alice.publicKey)
  server.keys.set(peer, bob.publicKey)

  const clock = new ManualClock()
  const waits: number[] = []
  const visibility = { visible: true }
  const encryptSpy = vi.fn(
    (input: Parameters<typeof encryptMessage>[0]) => encryptMessage(input),
  )
  const decryptSpy = vi.fn(
    (input: Parameters<typeof decryptReceived>[0]) => decryptReceived(input),
  )

  const deps: Partial<EngineDeps> = {
    getUserKey: vi.fn(async (username: string) => {
      const key = server.keys.get(username)
      if (key === undefined) {
        throw new ApiError(404, 'Not found')
      }
      return { username, public_key: key }
    }),
    fetchInboxPage: vi.fn(async (after?: string) => {
      server.inboxCalls.push(after)
      if (server.inboxGate !== null) {
        await server.inboxGate
      }
      if (server.inboxFailures > 0) {
        server.inboxFailures -= 1
        throw new ApiError(0, 'Could not reach the server')
      }
      if (server.endlessInbox) {
        server.endlessPage += 1
        return {
          messages: [],
          nextCursor: `cursor-${server.endlessPage}`,
        }
      }
      if (server.ignoreCursor) {
        return { messages: server.inbox, nextCursor: null }
      }
      return pageOf(server.inbox, after, server.pageSize)
    }),
    fetchSentPage: vi.fn(async (after?: string) => {
      server.sentCalls.push(after)
      return pageOf(server.sent, after, server.pageSize)
    }),
    sendMessage: vi.fn(
      async (input: SendMessageInput): Promise<SendMessageResult> => {
        server.sendCalls.push(input)
        const next = server.sendQueue.shift()
        if (next instanceof Error) {
          throw next
        }
        return {
          id: `server-${server.sendCalls.length}`,
          clientMessageId: input.clientMessageId,
          createdAt: '2026-01-01T00:00:01Z',
        }
      },
    ),
    acknowledgeMessage: vi.fn(async (id: string) => {
      server.ackCalls.push(id)
      const next = server.ackQueue.shift()
      if (next instanceof Error) {
        throw next
      }
      return { id, ackedAt: '2026-01-01T00:00:02Z' }
    }),
    encryptMessage: encryptSpy,
    decryptReceived: decryptSpy,
    decryptSent: vi.fn(
      (input: Parameters<typeof decryptSent>[0]) => decryptSent(input),
    ),
    now: () => clock.now,
    randomUUID: () => randomUUID(),
    isVisible: () => visibility.visible,
    wait: async (milliseconds: number) => {
      waits.push(milliseconds)
    },
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer,
  }

  const engine = new MessageEngine({
    pollIntervalMs: 5_000,
    maxPollIntervalMs: 60_000,
    sendRetryDelaysMs: [10, 20, 30],
    ackRetryDelaysMs: [10],
    jitterMs: () => 0,
    deps,
  })
  engines.push(engine)

  return {
    owner,
    peer,
    alice,
    bob,
    carol,
    server,
    clock,
    visibility,
    waits,
    encryptSpy,
    decryptSpy,
    engine,
  }
}

async function makeRow(options: {
  from: Identity
  to: Identity
  sender: string
  recipient: string
  body: string
  createdAt?: string
  clientMessageId?: string
  id?: string
}): Promise<MessageRow> {
  const clientMessageId = options.clientMessageId ?? randomUUID()
  const createdAt = options.createdAt ?? '2026-01-01T00:00:00Z'
  const encrypted = await encryptMessage({
    plaintext: options.body,
    clientMessageId,
    recipientPublicKey: options.to.publicKey,
    senderPublicKey: options.from.publicKey,
    senderSecretKey: options.from.secretKey,
  })
  return {
    id: options.id ?? randomUUID(),
    sender: options.sender,
    recipient: options.recipient,
    clientMessageId,
    nonce: encrypted.nonce,
    ciphertext: encrypted.ciphertext,
    clientTs: createdAt,
    createdAt,
    ackedAt: null,
  }
}

function tamper(value: string): string {
  const bytes = Buffer.from(value, 'base64')
  bytes[0] ^= 0xff
  return bytes.toString('base64')
}

function conversation(peer: string) {
  return useMessagingStore.getState().conversations[peer]
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void
  const promise = new Promise<void>((done) => {
    resolve = done
  })
  return { promise, resolve }
}

beforeEach(async () => {
  await ready()
  clearMessaging()
  lockSession()
})

afterEach(() => {
  for (const engine of engines.splice(0)) {
    engine.stop()
  }
  lockSession()
  clearMessaging()
  vi.restoreAllMocks()
})

describe('sync scheduling', () => {
  it('shares one in-flight pass between concurrent callers', async () => {
    const harness = await createHarness()
    const gate = deferred()
    harness.server.inboxGate = gate.promise

    const started = harness.engine.start()
    const first = harness.engine.syncNow()
    const second = harness.engine.syncNow()

    expect(first).toBe(second)
    gate.resolve()
    await started
    expect(harness.server.inboxCalls).toHaveLength(1)
  })

  it('grows the backoff on errors and resets it after success', async () => {
    const harness = await createHarness()
    harness.server.inboxFailures = 3

    await harness.engine.start()
    expect(harness.clock.delays).toEqual([5_000])
    expect(useMessagingStore.getState().lastSyncError).toContain(
      'Could not reach',
    )

    await harness.clock.advance(5_000)
    expect(harness.clock.delays).toEqual([5_000, 10_000])

    await harness.clock.advance(10_000)
    expect(harness.clock.delays).toEqual([5_000, 10_000, 20_000])

    await harness.clock.advance(20_000)
    expect(harness.clock.delays).toEqual([
      5_000, 10_000, 20_000, 5_000,
    ])
    expect(useMessagingStore.getState().lastSyncError).toBeNull()
    expect(harness.engine.isRunning()).toBe(true)
  })

  it('pauses while hidden and polls immediately on resume', async () => {
    const harness = await createHarness()
    await harness.engine.start()
    expect(harness.clock.pending()).toBe(1)

    harness.visibility.visible = false
    document.dispatchEvent(new Event('visibilitychange'))
    expect(harness.clock.pending()).toBe(0)

    const before = harness.server.inboxCalls.length
    harness.visibility.visible = true
    document.dispatchEvent(new Event('visibilitychange'))
    await harness.engine.syncNow()

    expect(harness.server.inboxCalls.length).toBeGreaterThan(before)
    expect(harness.clock.pending()).toBe(1)
  })

  it('stops and clears the store when the session locks', async () => {
    const harness = await createHarness()
    await harness.engine.start()
    expect(harness.engine.isRunning()).toBe(true)

    lockSession()

    expect(harness.engine.isRunning()).toBe(false)
    expect(harness.clock.pending()).toBe(0)
    expect(useMessagingStore.getState().conversations).toEqual({})
  })

  it('stops when the vault is locked without a session-store change', async () => {
    const harness = await createHarness()
    await harness.engine.start()

    lock()
    expect(isUnlocked()).toBe(false)
    await harness.engine.syncNow()

    expect(harness.engine.isRunning()).toBe(false)
    expect(useMessagingStore.getState().conversations).toEqual({})
  })

  it('stops at the 50-page cursor cap', async () => {
    const harness = await createHarness()
    harness.server.endlessInbox = true

    await harness.engine.start()

    expect(harness.server.inboxCalls).toHaveLength(MAX_PAGES_PER_SYNC)
    expect(harness.server.sentCalls).toHaveLength(1)
  })

  it('resumes from the last cursor without decrypting or acking again', async () => {
    const harness = await createHarness()
    harness.server.inbox = [
      await makeRow({
        from: harness.bob,
        to: harness.alice,
        sender: harness.peer,
        recipient: harness.owner,
        body: 'one',
      }),
      await makeRow({
        from: harness.bob,
        to: harness.alice,
        sender: harness.peer,
        recipient: harness.owner,
        body: 'two',
      }),
    ]

    await harness.engine.start()
    expect(harness.server.inboxCalls).toEqual([undefined, '2'])
    expect(harness.server.ackCalls).toHaveLength(2)
    expect(harness.decryptSpy).toHaveBeenCalledTimes(2)

    await harness.engine.syncNow()

    expect(harness.server.inboxCalls).toEqual([undefined, '2', '2'])
    expect(harness.decryptSpy).toHaveBeenCalledTimes(2)
    expect(harness.server.ackCalls).toHaveLength(2)
  })

  it('keeps a stored cursor when a poll returns an empty page with no cursor', async () => {
    const harness = await createHarness()
    harness.server.inbox = [
      await makeRow({
        from: harness.bob,
        to: harness.alice,
        sender: harness.peer,
        recipient: harness.owner,
        body: 'only',
      }),
    ]

    await harness.engine.start()
    expect(harness.server.inboxCalls).toEqual([undefined, '1'])

    harness.server.ignoreCursor = true
    harness.server.inbox = []
    await harness.engine.syncNow()
    expect(harness.server.inboxCalls).toEqual([undefined, '1', '1'])

    harness.server.ignoreCursor = false
    await harness.engine.syncNow()
    expect(harness.server.inboxCalls).toEqual([undefined, '1', '1', '1'])
    expect(harness.server.ackCalls).toHaveLength(1)
  })
})

describe('inbox ingestion', () => {
  it('decrypts a message, deduplicates it, and acks only once', async () => {
    const harness = await createHarness()
    harness.server.ignoreCursor = true
    harness.server.inbox = [
      await makeRow({
        from: harness.bob,
        to: harness.alice,
        sender: harness.peer,
        recipient: harness.owner,
        body: 'hello',
      }),
    ]

    await harness.engine.start()
    let items = conversation(harness.peer)?.items ?? []
    expect(items).toHaveLength(1)
    expect(items[0]).toMatchObject({
      kind: 'message',
      direction: 'in',
      body: 'hello',
    })

    await harness.engine.syncNow()
    items = conversation(harness.peer)?.items ?? []
    expect(items).toHaveLength(1)
    expect(harness.server.ackCalls).toHaveLength(1)
  })

  it('shows an error row for tampered and reflected ciphertext', async () => {
    const harness = await createHarness()
    const good = await makeRow({
      from: harness.bob,
      to: harness.alice,
      sender: harness.peer,
      recipient: harness.owner,
      body: 'hello',
    })
    const bad = await makeRow({
      from: harness.bob,
      to: harness.alice,
      sender: harness.peer,
      recipient: harness.owner,
      body: 'tampered',
    })
    bad.ciphertext = tamper(bad.ciphertext)
    const reflected = await makeRow({
      from: harness.alice,
      to: harness.bob,
      sender: harness.peer,
      recipient: harness.owner,
      body: 'reflected',
    })
    harness.server.inbox = [good, bad, reflected]

    await harness.engine.start()

    const items = conversation(harness.peer)?.items ?? []
    const messages = items.filter((item) => item.kind === 'message')
    const errors = items.filter((item) => item.kind === 'error')
    expect(messages).toHaveLength(1)
    expect(messages[0]).toMatchObject({ body: 'hello' })
    expect(errors.map((item) => item.reason).sort()).toEqual([
      'decryption_failed',
      'envelope_mismatch',
    ])
    // Only the row that decrypted and was stored may be acknowledged.
    expect(harness.server.ackCalls).toEqual([good.id])
  })

  it('retries a failed ack on the next pass without hiding the message', async () => {
    const harness = await createHarness()
    harness.server.inbox = [
      await makeRow({
        from: harness.bob,
        to: harness.alice,
        sender: harness.peer,
        recipient: harness.owner,
        body: 'delivered',
      }),
    ]
    harness.server.ackQueue = [
      new ApiError(0, 'offline'),
      new ApiError(0, 'offline'),
    ]

    await harness.engine.start()
    let items = conversation(harness.peer)?.items ?? []
    // An ack failure after retries must not add an error row or replace the
    // decrypted message. The id stays queued for the next pass.
    expect(items).toHaveLength(1)
    expect(items[0]).toMatchObject({
      kind: 'message',
      body: 'delivered',
    })
    expect(items.some((item) => item.kind === 'error')).toBe(false)
    expect(harness.server.ackCalls).toHaveLength(2)

    harness.server.ackQueue = [null]
    await harness.engine.syncNow()
    items = conversation(harness.peer)?.items ?? []
    expect(items).toHaveLength(1)
    expect(items.some((item) => item.kind === 'error')).toBe(false)
    expect(harness.server.ackCalls).toHaveLength(3)
  })

  it('decrypts sent history with the pinned recipient key', async () => {
    const harness = await createHarness()
    harness.server.sent = [
      await makeRow({
        from: harness.alice,
        to: harness.bob,
        sender: harness.owner,
        recipient: harness.peer,
        body: 'sent earlier',
      }),
    ]

    await harness.engine.start()

    expect(conversation(harness.peer)?.items[0]).toMatchObject({
      kind: 'message',
      direction: 'out',
      body: 'sent earlier',
    })
  })
})

describe('key changes', () => {
  it('blocks decryption and sending until the new key is acknowledged', async () => {
    const harness = await createHarness()
    await pinOrCheckContact(
      harness.owner,
      harness.peer,
      harness.bob.publicKey,
    )
    harness.server.keys.set(harness.peer, harness.carol.publicKey)

    const oldRow = await makeRow({
      from: harness.bob,
      to: harness.alice,
      sender: harness.peer,
      recipient: harness.owner,
      body: 'old key',
    })
    const newRow = await makeRow({
      from: harness.carol,
      to: harness.alice,
      sender: harness.peer,
      recipient: harness.owner,
      body: 'new key',
    })
    harness.server.inbox = [oldRow, newRow]

    await harness.engine.start()

    let current = conversation(harness.peer)
    expect(current?.blocked).toMatchObject({
      pinnedKey: harness.bob.publicKey,
      seenKey: harness.carol.publicKey,
    })
    expect(current?.blocked?.pinnedSafetyNumber).toBeTruthy()
    expect(current?.blocked?.seenSafetyNumber).toBeTruthy()
    expect(current?.items).toHaveLength(2)
    expect(current?.items).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: 'error', reason: 'key_changed' }),
        expect.objectContaining({ kind: 'error', reason: 'key_changed' }),
      ]),
    )
    // A blocked peer's rows stay unacked until the user accepts the new key.
    expect(harness.server.ackCalls).toHaveLength(0)

    await expect(
      harness.engine.send(harness.peer, 'blocked'),
    ).rejects.toBeInstanceOf(KeyChangedError)

    await harness.engine.acknowledgePeerKeyChange(harness.peer)

    current = conversation(harness.peer)
    expect(current?.blocked).toBeNull()
    expect(current?.safetyNumber).toBeTruthy()
    expect(current?.items).toContainEqual(
      expect.objectContaining({ kind: 'message', body: 'new key' }),
    )
    // The row encrypted with the accepted key is now shown and acked once;
    // the row encrypted with the old key remains an unacked error.
    expect(harness.server.ackCalls).toEqual([newRow.id])

    await harness.engine.syncNow()
    expect(harness.server.ackCalls).toEqual([newRow.id])

    expect((await getContact(harness.owner, harness.peer))?.publicKey).toBe(
      harness.carol.publicKey,
    )
  })

  it('refreshes the safety number when a conversation opens', async () => {
    const harness = await createHarness()
    await harness.engine.start()

    await harness.engine.openConversation(harness.peer)

    const current = conversation(harness.peer)
    expect(current?.peerKey).toBe(harness.bob.publicKey)
    expect(current?.safetyNumber).toMatch(/^\d{5}( \d{5}){11}$/)
  })
})

describe('sending', () => {
  it('retries with a byte-identical payload and encrypts once', async () => {
    const harness = await createHarness()
    harness.server.sendQueue = [
      new ApiError(0, 'offline'),
      new ApiError(503, 'down'),
      null,
    ]

    await harness.engine.start()
    const clientMessageId = await harness.engine.send(
      harness.peer,
      'hello',
    )

    expect(harness.server.sendCalls).toHaveLength(3)
    expect(harness.server.sendCalls[0]).toEqual(
      harness.server.sendCalls[1],
    )
    expect(harness.server.sendCalls[1]).toEqual(
      harness.server.sendCalls[2],
    )
    expect(harness.server.sendCalls[0]).toMatchObject({
      recipient: harness.peer,
      clientMessageId,
      clientTs: '1970-01-01T00:00:00.000Z',
    })
    expect(harness.encryptSpy).toHaveBeenCalledTimes(1)
    expect(harness.waits).toEqual([10, 20])

    const message = conversation(harness.peer)?.items.find(
      (item) => item.kind === 'message',
    )
    expect(message).toMatchObject({
      direction: 'out',
      body: 'hello',
      status: 'sent',
    })
  })

  it('does not retry a 4xx and drops the retry payload', async () => {
    const harness = await createHarness()
    harness.server.sendQueue = [new ApiError(422, 'invalid input')]

    await harness.engine.start()
    const clientMessageId = await harness.engine.send(
      harness.peer,
      'hello',
    )

    expect(harness.server.sendCalls).toHaveLength(1)
    const message = conversation(harness.peer)?.items.find(
      (item) => item.kind === 'message',
    )
    expect(message).toMatchObject({
      status: 'failed',
      failure: 'invalid input',
    })
    await expect(
      harness.engine.retry(clientMessageId),
    ).rejects.toBeInstanceOf(InvalidInputError)
  })

  it('marks a 409 as failed without retrying', async () => {
    const harness = await createHarness()
    harness.server.sendQueue = [new ApiError(409, 'conflict')]

    await harness.engine.start()
    await harness.engine.send(harness.peer, 'hello')

    expect(harness.server.sendCalls).toHaveLength(1)
    const message = conversation(harness.peer)?.items.find(
      (item) => item.kind === 'message',
    )
    expect(message).toMatchObject({ status: 'failed', failure: 'conflict' })
  })

  it('manually retries the same payload after network retries run out', async () => {
    const harness = await createHarness()
    harness.server.sendQueue = [
      new ApiError(0, 'offline'),
      new ApiError(0, 'offline'),
      new ApiError(0, 'offline'),
      new ApiError(0, 'offline'),
    ]

    await harness.engine.start()
    const clientMessageId = await harness.engine.send(
      harness.peer,
      'hello',
    )
    expect(harness.server.sendCalls).toHaveLength(4)

    harness.server.sendQueue = [null]
    await harness.engine.retry(clientMessageId)

    expect(harness.server.sendCalls).toHaveLength(5)
    for (const call of harness.server.sendCalls) {
      expect(call).toEqual(harness.server.sendCalls[0])
    }
    const message = conversation(harness.peer)?.items.find(
      (item) => item.kind === 'message',
    )
    expect(message).toMatchObject({ status: 'sent' })
  })

  it('reconciles a timed-out send with the sent history row', async () => {
    const harness = await createHarness()
    harness.server.sendQueue = [null]

    await harness.engine.start()
    const clientMessageId = await harness.engine.send(
      harness.peer,
      'hello',
    )

    harness.server.sent = [
      await makeRow({
        from: harness.alice,
        to: harness.bob,
        sender: harness.owner,
        recipient: harness.peer,
        body: 'hello',
        clientMessageId,
      }),
    ]
    await harness.engine.syncNow()

    const messages = (conversation(harness.peer)?.items ?? []).filter(
      (item) => item.kind === 'message',
    )
    expect(messages).toHaveLength(1)
    expect(messages[0]).toMatchObject({ status: 'sent', body: 'hello' })
  })
})
