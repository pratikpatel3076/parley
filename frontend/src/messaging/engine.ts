/**
 * Message engine: polling, decryption, deduplication, and retry-safe sending.
 *
 * The engine keeps no plaintext or ciphertext outside memory. Cursors are
 * advanced only after a row is displayed (as a message or a visible error).
 * Sends reuse one encrypted payload for every retry so the server's
 * `(sender, client_message_id)` idempotency check sees byte-identical input.
 */
import { ApiError, getUserKey } from '../api/client'
import {
  EnvelopeMismatchError,
  InvalidInputError,
  KeyChangedError,
} from '../crypto/errors'
import type {
  acknowledgeKeyChange,
  decryptReceived,
  decryptSent,
  encryptMessage,
  pinOrCheckContact,
  safetyNumber,
} from '../crypto'
import { loadCrypto } from '../session/cryptoLoader'
import { useSessionStore } from '../session/store'
import {
  VaultLockedError,
  getIdentity,
  getSecretKey,
  isUnlocked,
} from '../session/vault'
import {
  acknowledgeMessage,
  fetchAllPages,
  fetchInboxPage,
  fetchSentPage,
  sendMessage,
  type MessageRow,
  type SendMessageInput,
  type SendMessageResult,
} from './api'
import {
  clearMessaging,
  useMessagingStore,
  type ChatMessage,
  type MessageReason,
  type OutgoingPayload,
} from './store'

const DEFAULT_POLL_INTERVAL_MS = 5_000
const DEFAULT_MAX_POLL_INTERVAL_MS = 60_000
const DEFAULT_SEND_RETRY_DELAYS_MS = [500, 1_000, 2_000]
const DEFAULT_ACK_RETRY_DELAYS_MS = [500, 1_000]
const MAX_JITTER_MS = 1_000

/** Every side effect the engine performs, injectable for tests. */
export interface EngineDeps {
  getIdentity: typeof getIdentity
  getSecretKey: typeof getSecretKey
  isUnlocked: typeof isUnlocked
  getUserKey: typeof getUserKey
  encryptMessage: typeof encryptMessage
  decryptReceived: typeof decryptReceived
  decryptSent: typeof decryptSent
  pinOrCheckContact: typeof pinOrCheckContact
  acknowledgeKeyChange: typeof acknowledgeKeyChange
  safetyNumber: typeof safetyNumber
  fetchInboxPage: typeof fetchInboxPage
  fetchSentPage: typeof fetchSentPage
  sendMessage: typeof sendMessage
  acknowledgeMessage: typeof acknowledgeMessage
  now: () => number
  randomUUID: () => string
  isVisible: () => boolean
  wait: (milliseconds: number) => Promise<void>
  setTimer: (callback: () => void | Promise<void>, milliseconds: number) => unknown
  clearTimer: (handle: unknown) => void
}

export interface MessageEngineOptions {
  pollIntervalMs?: number
  maxPollIntervalMs?: number
  sendRetryDelaysMs?: number[]
  ackRetryDelaysMs?: number[]
  jitterMs?: () => number
  deps?: Partial<EngineDeps>
}

function randomUuid(): string {
  if (
    typeof crypto !== 'undefined' &&
    typeof crypto.randomUUID === 'function'
  ) {
    return crypto.randomUUID()
  }

  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  bytes[6] = (bytes[6] & 0x0f) | 0x40
  bytes[8] = (bytes[8] & 0x3f) | 0x80
  const hex = Array.from(bytes, (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('')
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20),
  ].join('-')
}

function defaultDeps(): EngineDeps {
  return {
    getIdentity,
    getSecretKey,
    isUnlocked,
    getUserKey,
    encryptMessage: async (...args) =>
      (await loadCrypto()).encryptMessage(...args),
    decryptReceived: async (...args) =>
      (await loadCrypto()).decryptReceived(...args),
    decryptSent: async (...args) => (await loadCrypto()).decryptSent(...args),
    pinOrCheckContact: async (...args) =>
      (await loadCrypto()).pinOrCheckContact(...args),
    acknowledgeKeyChange: async (...args) =>
      (await loadCrypto()).acknowledgeKeyChange(...args),
    safetyNumber: async (...args) => (await loadCrypto()).safetyNumber(...args),
    fetchInboxPage,
    fetchSentPage,
    sendMessage,
    acknowledgeMessage,
    now: () => Date.now(),
    randomUUID: randomUuid,
    isVisible: () =>
      typeof document === 'undefined' ||
      document.visibilityState !== 'hidden',
    wait: (milliseconds) =>
      new Promise((resolve) => {
        setTimeout(resolve, milliseconds)
      }),
    setTimer: (callback, milliseconds) =>
      setTimeout(() => {
        void callback()
      }, milliseconds),
    clearTimer: (handle) => {
      clearTimeout(handle as ReturnType<typeof setTimeout>)
    },
  }
}

function isRetryable(error: unknown): boolean {
  return (
    error instanceof ApiError && (error.status === 0 || error.status >= 500)
  )
}

function describeError(error: unknown): string {
  if (error instanceof Error && error.message.length > 0) {
    return error.message
  }
  return 'Unexpected error'
}

function reasonFor(error: unknown): MessageReason {
  if (error instanceof EnvelopeMismatchError) {
    return 'envelope_mismatch'
  }
  if (error instanceof InvalidInputError) {
    return 'invalid_input'
  }
  return 'decryption_failed'
}

function findMessage(
  peer: string,
  clientMessageId: string,
): ChatMessage | undefined {
  const conversation = useMessagingStore.getState().conversations[peer]
  if (conversation === undefined) {
    return undefined
  }
  return conversation.items.find(
    (item): item is ChatMessage =>
      item.kind === 'message' &&
      item.direction === 'out' &&
      item.clientMessageId === clientMessageId,
  )
}

export class MessageEngine {
  private readonly deps: EngineDeps
  private readonly pollIntervalMs: number
  private readonly maxPollIntervalMs: number
  private readonly sendRetryDelaysMs: number[]
  private readonly ackRetryDelaysMs: number[]
  private readonly jitterMs: () => number

  private running = false
  private attached = false
  private generation = 0
  private backoffMs: number
  private timer: unknown = null
  private syncPromise: Promise<void> | null = null
  private unsubscribeSession: (() => void) | null = null

  private inboxCursor: string | null | undefined
  private sentCursor: string | null | undefined
  private readonly pendingSends = new Map<string, OutgoingPayload>()
  private readonly pendingAcks = new Set<string>()
  private readonly ackedIds = new Set<string>()
  private readonly keyChangedPeers = new Set<string>()

  constructor(options: MessageEngineOptions = {}) {
    const pollIntervalMs =
      options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS
    const maxPollIntervalMs =
      options.maxPollIntervalMs ?? DEFAULT_MAX_POLL_INTERVAL_MS
    if (!Number.isFinite(pollIntervalMs) || pollIntervalMs <= 0) {
      throw new InvalidInputError('pollIntervalMs must be positive')
    }
    if (!Number.isFinite(maxPollIntervalMs) || maxPollIntervalMs < pollIntervalMs) {
      throw new InvalidInputError(
        'maxPollIntervalMs must be at least pollIntervalMs',
      )
    }

    this.deps = { ...defaultDeps(), ...options.deps }
    this.pollIntervalMs = pollIntervalMs
    this.maxPollIntervalMs = maxPollIntervalMs
    this.sendRetryDelaysMs = [
      ...(options.sendRetryDelaysMs ?? DEFAULT_SEND_RETRY_DELAYS_MS),
    ]
    this.ackRetryDelaysMs = [
      ...(options.ackRetryDelaysMs ?? DEFAULT_ACK_RETRY_DELAYS_MS),
    ]
    this.jitterMs = options.jitterMs ?? (() => Math.floor(Math.random() * (MAX_JITTER_MS + 1)))
    this.backoffMs = pollIntervalMs
  }

  /** True while the poll loop is active. */
  isRunning(): boolean {
    return this.running
  }

  /** Start polling. The first sync runs immediately. */
  async start(): Promise<void> {
    if (this.running) {
      await this.syncNow()
      return
    }
    this.generation += 1
    this.running = true
    this.backoffMs = this.pollIntervalMs
    this.attach()
    await this.syncNow()
  }

  /** Stop polling, drop all pending plaintext/ciphertext, and clear the store. */
  stop(): void {
    this.generation += 1
    this.running = false
    this.clearScheduled()
    this.detach()
    this.pendingSends.clear()
    this.pendingAcks.clear()
    this.ackedIds.clear()
    this.keyChangedPeers.clear()
    this.inboxCursor = undefined
    this.sentCursor = undefined
    this.backoffMs = this.pollIntervalMs
    this.syncPromise = null
    this.store().setSyncing(false)
    this.store().setSyncError(null)
    clearMessaging()
  }

  /**
   * Run one sync pass. Concurrent callers share the same in-flight pass.
   */
  syncNow(): Promise<void> {
    if (this.syncPromise !== null) {
      return this.syncPromise
    }
    if (!this.running) {
      return Promise.resolve()
    }

    this.clearScheduled()
    const generation = this.generation
    const promise = this.runSync(generation)
    this.syncPromise = promise
    void promise.finally(() => {
      if (this.syncPromise === promise) {
        this.syncPromise = null
      }
    })
    return promise
  }

  /**
   * Encrypt once and send. Delivery failures leave a `failed` row with the
   * payload retained for {@link retry}.
   */
  async send(peer: string, body: string): Promise<string> {
    this.assertUnlocked()
    const generation = this.generation

    const existing = this.store().conversations[peer]
    if (existing?.blocked !== null && existing?.blocked !== undefined) {
      throw new KeyChangedError(
        peer,
        existing.blocked.pinnedKey,
        existing.blocked.seenKey,
      )
    }

    const peerKey = await this.resolvePeerKeyFresh(peer, generation)
    if (!this.isCurrent(generation)) {
      throw new VaultLockedError()
    }
    if (peerKey === null) {
      const blocked = this.store().conversations[peer]?.blocked
      throw new KeyChangedError(
        peer,
        blocked?.pinnedKey ?? '',
        blocked?.seenKey ?? '',
      )
    }

    const identity = this.deps.getIdentity()
    const secretKey = this.deps.getSecretKey()
    const clientMessageId = this.deps.randomUUID()
    const clientTs = new Date(this.deps.now()).toISOString()
    const encrypted = await this.deps.encryptMessage({
      plaintext: body,
      clientMessageId,
      recipientPublicKey: peerKey,
      senderPublicKey: identity.publicKey,
      senderSecretKey: secretKey,
    })
    if (!this.isCurrent(generation)) {
      throw new VaultLockedError()
    }

    const payload: OutgoingPayload = {
      clientMessageId,
      recipient: peer,
      nonce: encrypted.nonce,
      ciphertext: encrypted.ciphertext,
      clientTs,
    }
    this.pendingSends.set(clientMessageId, payload)

    this.store().ensureConversation(peer)
    this.store().addOrReplaceMessage(peer, {
      kind: 'message',
      id: `local-${clientMessageId}`,
      clientMessageId,
      direction: 'out',
      body,
      createdAt: clientTs,
      status: 'sending',
      pending: payload,
    })

    await this.deliverAndUpdate(payload, generation)
    return clientMessageId
  }

  /** Retry a failed send with the exact same nonce and ciphertext. */
  async retry(clientMessageId: string): Promise<void> {
    this.assertUnlocked()
    const generation = this.generation
    const payload = this.pendingSends.get(clientMessageId)
    if (payload === undefined) {
      throw new InvalidInputError(
        'This message can no longer be retried; its encrypted payload was dropped',
      )
    }

    const blocked = this.store().conversations[payload.recipient]?.blocked
    if (blocked !== null && blocked !== undefined) {
      throw new KeyChangedError(
        payload.recipient,
        blocked.pinnedKey,
        blocked.seenKey,
      )
    }

    this.store().updateMessage(payload.recipient, clientMessageId, {
      status: 'sending',
      failure: undefined,
    })
    await this.deliverAndUpdate(payload, generation)
  }

  /**
   * Load a conversation and refresh the peer's pinned key and safety number.
   * A key change is stored as a block rather than silently accepted.
   */
  async openConversation(peer: string): Promise<void> {
    this.store().ensureConversation(peer)
    if (!this.deps.isUnlocked()) {
      return
    }

    const generation = this.generation
    try {
      await this.resolvePeerKeyFresh(peer, generation)
    } catch (error) {
      if (this.isCurrent(generation)) {
        this.store().setConversationError(peer, describeError(error))
      }
    }
  }

  /** Accept the new peer key after the user compares both safety numbers. */
  async acknowledgePeerKeyChange(peer: string): Promise<void> {
    this.assertUnlocked()
    const blocked = this.store().conversations[peer]?.blocked
    if (blocked === null || blocked === undefined) {
      throw new InvalidInputError('There is no key change to acknowledge')
    }

    const identity = this.deps.getIdentity()
    await this.deps.acknowledgeKeyChange(
      identity.username,
      peer,
      blocked.seenKey,
    )

    this.keyChangedPeers.add(peer)
    this.store().setBlocked(peer, null)
    this.store().setPeerSecurity(peer, {
      peerKey: blocked.seenKey,
      safetyNumber: blocked.seenSafetyNumber,
    })

    // Re-read history so rows that were hidden while blocked can decrypt with
    // the newly accepted key. Deduplication keeps already-visible rows stable.
    this.inboxCursor = undefined
    this.sentCursor = undefined
    if (this.running) {
      await this.syncNow()
    }
  }

  private store() {
    return useMessagingStore.getState()
  }

  private assertUnlocked(): void {
    if (!this.deps.isUnlocked()) {
      throw new VaultLockedError()
    }
  }

  private isCurrent(generation: number): boolean {
    return generation === this.generation
  }

  private attach(): void {
    if (this.attached) {
      return
    }
    this.attached = true

    if (typeof document !== 'undefined') {
      document.addEventListener(
        'visibilitychange',
        this.handleVisibilityChange,
      )
    }
    this.unsubscribeSession = useSessionStore.subscribe(
      (state, previous) => {
        if (
          state.status === 'signed_out' &&
          previous.status !== 'signed_out'
        ) {
          this.stop()
        }
      },
    )
  }

  private detach(): void {
    if (!this.attached) {
      return
    }
    this.attached = false
    if (typeof document !== 'undefined') {
      document.removeEventListener(
        'visibilitychange',
        this.handleVisibilityChange,
      )
    }
    this.unsubscribeSession?.()
    this.unsubscribeSession = null
  }

  private readonly handleVisibilityChange = (): void => {
    if (!this.running) {
      return
    }
    if (this.deps.isVisible()) {
      this.backoffMs = this.pollIntervalMs
      this.clearScheduled()
      void this.syncNow()
      return
    }
    this.clearScheduled()
  }

  private clearScheduled(): void {
    if (this.timer !== null) {
      this.deps.clearTimer(this.timer)
      this.timer = null
    }
  }

  private schedule(delayMs: number): void {
    if (!this.running || !this.deps.isVisible()) {
      return
    }
    this.clearScheduled()
    const delay = delayMs + Math.max(0, this.jitterMs())
    this.timer = this.deps.setTimer(() => this.syncNow(), delay)
  }

  private async runSync(generation: number): Promise<void> {
    if (!this.running || !this.isCurrent(generation)) {
      return
    }
    if (!this.deps.isUnlocked()) {
      this.stop()
      return
    }

    this.store().setSyncing(true)
    try {
      await this.syncPass(generation)
      if (!this.running || !this.isCurrent(generation)) {
        return
      }
      this.store().setSyncError(null)
      this.backoffMs = this.pollIntervalMs
      this.schedule(this.pollIntervalMs)
    } catch (error) {
      if (!this.running || !this.isCurrent(generation)) {
        return
      }
      this.store().setSyncError(describeError(error))
      const delay = this.backoffMs
      this.backoffMs = Math.min(
        this.backoffMs * 2,
        this.maxPollIntervalMs,
      )
      this.schedule(delay)
    } finally {
      if (this.running && this.isCurrent(generation)) {
        this.store().setSyncing(false)
      }
    }
  }

  private async syncPass(generation: number): Promise<void> {
    const identity = this.deps.getIdentity()
    const secretKey = this.deps.getSecretKey()
    const keyCache = new Map<string, string | null>()

    for (const id of [...this.pendingAcks]) {
      if (!this.isCurrent(generation)) {
        return
      }
      await this.ackWithRetry(id)
    }

    const inbox = await fetchAllPages<MessageRow>(async (after) => {
      const page = await this.deps.fetchInboxPage(after)
      return { items: page.messages, nextCursor: page.nextCursor }
    }, this.inboxCursor ?? undefined)

    if (!this.isCurrent(generation)) {
      return
    }
    for (const row of inbox.items) {
      await this.ingestInbox(
        row,
        identity.username,
        identity.publicKey,
        secretKey,
        keyCache,
        generation,
      )
      if (!this.isCurrent(generation)) {
        return
      }
    }
    if (inbox.nextCursor !== null) {
      this.inboxCursor = inbox.nextCursor
    }

    const sent = await fetchAllPages<MessageRow>(async (after) => {
      const page = await this.deps.fetchSentPage(after)
      return { items: page.messages, nextCursor: page.nextCursor }
    }, this.sentCursor ?? undefined)

    if (!this.isCurrent(generation)) {
      return
    }
    for (const row of sent.items) {
      await this.ingestSent(
        row,
        identity.username,
        identity.publicKey,
        secretKey,
        keyCache,
        generation,
      )
      if (!this.isCurrent(generation)) {
        return
      }
    }
    if (sent.nextCursor !== null) {
      this.sentCursor = sent.nextCursor
    }
  }

  private async ingestInbox(
    row: MessageRow,
    owner: string,
    ownPublicKey: string,
    secretKey: string,
    keyCache: Map<string, string | null>,
    generation: number,
  ): Promise<void> {
    const peer = row.sender
    this.store().ensureConversation(peer)

    if (this.store().hasMessage(peer, 'in', row.clientMessageId)) {
      await this.ackIfNeeded(row)
      return
    }

    const peerKey = await this.resolvePeerKey(
      peer,
      owner,
      ownPublicKey,
      keyCache,
      generation,
    )
    if (!this.isCurrent(generation)) {
      return
    }
    if (peerKey === null) {
      this.store().addErrorRow(peer, {
        kind: 'error',
        id: row.id,
        clientMessageId: row.clientMessageId,
        direction: 'in',
        reason: 'key_changed',
        createdAt: row.createdAt,
      })
      return
    }

    let stored = false
    try {
      const decrypted = await this.deps.decryptReceived({
        nonce: row.nonce,
        ciphertext: row.ciphertext,
        clientMessageId: row.clientMessageId,
        senderPublicKey: peerKey,
        recipientPublicKey: ownPublicKey,
        recipientSecretKey: secretKey,
      })
      if (!this.isCurrent(generation)) {
        return
      }
      this.store().addOrReplaceMessage(peer, {
        kind: 'message',
        id: row.id,
        clientMessageId: row.clientMessageId,
        direction: 'in',
        body: decrypted.plaintext,
        createdAt: row.createdAt,
      })
      stored = true
    } catch (error) {
      if (!this.isCurrent(generation)) {
        return
      }
      this.store().addErrorRow(peer, {
        kind: 'error',
        id: row.id,
        clientMessageId: row.clientMessageId,
        direction: 'in',
        reason: reasonFor(error),
        createdAt: row.createdAt,
      })
    }

    // Acknowledge only after decryption and storage succeeded. The ack is
    // deliberately outside the try/catch above: a failed ack is queued for the
    // next pass and must never turn a displayed message into an error row.
    // Error rows and blocked-peer rows stay unacked so a later re-sync can
    // process them after the user accepts a changed key.
    if (stored) {
      await this.ackIfNeeded(row)
    }
  }

  private async ingestSent(
    row: MessageRow,
    owner: string,
    ownPublicKey: string,
    secretKey: string,
    keyCache: Map<string, string | null>,
    generation: number,
  ): Promise<void> {
    const peer = row.recipient
    this.store().ensureConversation(peer)

    const existing = findMessage(peer, row.clientMessageId)
    if (existing !== undefined) {
      // A send that timed out may still have committed on the server. Reconcile
      // the local echo with the server row instead of adding a duplicate.
      if (existing.status !== 'sent') {
        this.store().updateMessage(peer, row.clientMessageId, {
          id: row.id,
          createdAt: row.createdAt,
          status: 'sent',
          failure: undefined,
          pending: undefined,
        })
        this.pendingSends.delete(row.clientMessageId)
      }
      return
    }

    const peerKey = await this.resolvePeerKey(
      peer,
      owner,
      ownPublicKey,
      keyCache,
      generation,
    )
    if (!this.isCurrent(generation)) {
      return
    }
    if (peerKey === null) {
      // Keep the block visible; history re-syncs after acknowledgement.
      return
    }

    try {
      const decrypted = await this.deps.decryptSent({
        nonce: row.nonce,
        ciphertext: row.ciphertext,
        clientMessageId: row.clientMessageId,
        recipientPublicKey: peerKey,
        senderPublicKey: ownPublicKey,
        senderSecretKey: secretKey,
      })
      if (!this.isCurrent(generation)) {
        return
      }
      this.store().addOrReplaceMessage(peer, {
        kind: 'message',
        id: row.id,
        clientMessageId: row.clientMessageId,
        direction: 'out',
        body: decrypted.plaintext,
        createdAt: row.createdAt,
      })
    } catch (error) {
      if (!this.isCurrent(generation)) {
        return
      }
      this.store().addErrorRow(peer, {
        kind: 'error',
        id: row.id,
        clientMessageId: row.clientMessageId,
        direction: 'out',
        reason: this.keyChangedPeers.has(peer)
          ? 'sent_before_key_change'
          : reasonFor(error),
        createdAt: row.createdAt,
      })
    }
  }

  private async resolvePeerKey(
    peer: string,
    owner: string,
    ownPublicKey: string,
    cache: Map<string, string | null>,
    generation: number,
  ): Promise<string | null> {
    const cached = cache.get(peer)
    if (cached !== undefined) {
      return cached
    }

    const conversation = this.store().conversations[peer]
    if (conversation?.blocked !== null && conversation?.blocked !== undefined) {
      cache.set(peer, null)
      return null
    }

    const key = await this.fetchPeerKey(peer)
    try {
      const contact = await this.deps.pinOrCheckContact(owner, peer, key)
      cache.set(peer, contact.publicKey)
      return contact.publicKey
    } catch (error) {
      if (error instanceof KeyChangedError) {
        if (!this.isCurrent(generation)) {
          return null
        }
        await this.recordKeyChange(
          peer,
          ownPublicKey,
          error.pinnedKey,
          error.seenKey,
          generation,
        )
        cache.set(peer, null)
        return null
      }
      throw error
    }
  }

  private async resolvePeerKeyFresh(
    peer: string,
    generation?: number,
  ): Promise<string | null> {
    const identity = this.deps.getIdentity()
    const key = await this.fetchPeerKey(peer)
    try {
      const contact = await this.deps.pinOrCheckContact(
        identity.username,
        peer,
        key,
      )
      const safety = await this.safety(identity.publicKey, key)
      if (generation !== undefined && !this.isCurrent(generation)) {
        throw new VaultLockedError()
      }
      this.store().setBlocked(peer, null)
      this.store().setPeerSecurity(peer, {
        peerKey: contact.publicKey,
        safetyNumber: safety,
      })
      return contact.publicKey
    } catch (error) {
      if (error instanceof KeyChangedError) {
        if (generation !== undefined && !this.isCurrent(generation)) {
          throw new VaultLockedError()
        }
        await this.recordKeyChange(
          peer,
          identity.publicKey,
          error.pinnedKey,
          error.seenKey,
          generation,
        )
        return null
      }
      throw error
    }
  }

  private async fetchPeerKey(peer: string): Promise<string> {
    const response = await this.deps.getUserKey(peer)
    if (
      typeof response !== 'object' ||
      response === null ||
      typeof response.public_key !== 'string' ||
      response.public_key.length === 0
    ) {
      throw new InvalidInputError('The server returned an invalid public key')
    }
    return response.public_key
  }

  private async recordKeyChange(
    peer: string,
    ownPublicKey: string,
    pinnedKey: string,
    seenKey: string,
    generation?: number,
  ): Promise<void> {
    this.keyChangedPeers.add(peer)
    const pinnedSafetyNumber = await this.safety(ownPublicKey, pinnedKey)
    const seenSafetyNumber = await this.safety(ownPublicKey, seenKey)
    if (generation !== undefined && !this.isCurrent(generation)) {
      return
    }
    this.store().setBlocked(peer, {
      pinnedKey,
      seenKey,
      pinnedSafetyNumber,
      seenSafetyNumber,
    })
  }

  private async safety(
    ownPublicKey: string,
    peerPublicKey: string,
  ): Promise<string | null> {
    try {
      return await this.deps.safetyNumber(ownPublicKey, peerPublicKey)
    } catch {
      return null
    }
  }

  private async ackIfNeeded(row: MessageRow): Promise<void> {
    if (row.ackedAt !== null) {
      this.ackedIds.add(row.id)
      this.pendingAcks.delete(row.id)
      return
    }
    if (this.ackedIds.has(row.id)) {
      return
    }
    await this.ackWithRetry(row.id)
  }

  private async ackWithRetry(id: string): Promise<void> {
    let attempt = 0
    for (;;) {
      try {
        await this.deps.acknowledgeMessage(id)
        this.ackedIds.add(id)
        this.pendingAcks.delete(id)
        return
      } catch (error) {
        if (!isRetryable(error)) {
          // A 403/404 will not become valid by retrying.
          this.pendingAcks.delete(id)
          return
        }
        if (attempt >= this.ackRetryDelaysMs.length) {
          this.pendingAcks.add(id)
          return
        }
        await this.deps.wait(this.ackRetryDelaysMs[attempt])
        attempt += 1
      }
    }
  }

  private async deliver(payload: OutgoingPayload): Promise<SendMessageResult> {
    const input: SendMessageInput = {
      recipient: payload.recipient,
      clientMessageId: payload.clientMessageId,
      nonce: payload.nonce,
      ciphertext: payload.ciphertext,
      clientTs: payload.clientTs,
    }

    let attempt = 0
    for (;;) {
      try {
        return await this.deps.sendMessage(input)
      } catch (error) {
        if (!isRetryable(error) || attempt >= this.sendRetryDelaysMs.length) {
          throw error
        }
        await this.deps.wait(this.sendRetryDelaysMs[attempt])
        attempt += 1
      }
    }
  }

  private async deliverAndUpdate(
    payload: OutgoingPayload,
    generation: number,
  ): Promise<void> {
    try {
      const result = await this.deliver(payload)
      if (!this.isCurrent(generation)) {
        return
      }
      this.store().updateMessage(
        payload.recipient,
        payload.clientMessageId,
        {
          id: result.id,
          createdAt: result.createdAt,
          status: 'sent',
          failure: undefined,
          pending: undefined,
        },
      )
      this.pendingSends.delete(payload.clientMessageId)
    } catch (error) {
      if (!this.isCurrent(generation)) {
        return
      }
      this.store().updateMessage(
        payload.recipient,
        payload.clientMessageId,
        {
          status: 'failed',
          failure: describeError(error),
        },
      )
      if (!isRetryable(error)) {
        // A 4xx (including 409) cannot succeed by replaying the payload.
        this.pendingSends.delete(payload.clientMessageId)
      }
    }
  }
}

let defaultEngine: MessageEngine | null = null

/** Shared engine used by the chat screen. */
export function getMessageEngine(): MessageEngine {
  if (defaultEngine === null) {
    defaultEngine = new MessageEngine()
  }
  return defaultEngine
}
