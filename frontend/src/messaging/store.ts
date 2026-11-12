/**
 * In-memory message state.
 *
 * Plaintext lives only here and in the engine's pending send payloads. It is
 * deliberately not persisted to localStorage, sessionStorage, IndexedDB,
 * cookies, the URL, or logs. `clear()` runs on lock/logout.
 */
import { create } from 'zustand'

import { useSessionStore } from '../session/store'

export type MessageStatus = 'sending' | 'sent' | 'failed'

export type MessageReason =
  | 'decryption_failed'
  | 'envelope_mismatch'
  | 'invalid_input'
  | 'sent_before_key_change'
  | 'key_changed'

export interface OutgoingPayload {
  clientMessageId: string
  recipient: string
  nonce: string
  ciphertext: string
  clientTs: string
}

export interface ChatMessage {
  kind: 'message'
  id: string
  clientMessageId: string
  direction: 'in' | 'out'
  body: string
  /** Server `created_at`; for a local echo, the client send time. */
  createdAt: string
  status?: MessageStatus
  failure?: string
  pending?: OutgoingPayload
}

export interface ChatError {
  kind: 'error'
  id: string
  clientMessageId: string
  direction: 'in' | 'out'
  reason: MessageReason
  createdAt: string
}

export type ChatItem = ChatMessage | ChatError

export interface BlockedPeer {
  pinnedKey: string
  seenKey: string
  pinnedSafetyNumber: string | null
  seenSafetyNumber: string | null
}

export interface PeerSecurity {
  peerKey: string | null
  safetyNumber: string | null
}

export interface Conversation {
  peer: string
  items: ChatItem[]
  blocked: BlockedPeer | null
  lastError: string | null
  peerKey: string | null
  safetyNumber: string | null
}

interface MessagingState {
  conversations: Record<string, Conversation>
  syncing: boolean
  lastSyncError: string | null
  ensureConversation: (peer: string) => void
  addOrReplaceMessage: (peer: string, message: ChatMessage) => void
  addErrorRow: (peer: string, error: ChatError) => void
  updateMessage: (
    peer: string,
    clientMessageId: string,
    patch: Partial<ChatMessage>,
  ) => void
  hasMessage: (
    peer: string,
    direction: 'in' | 'out',
    clientMessageId: string,
  ) => boolean
  setBlocked: (peer: string, blocked: BlockedPeer | null) => void
  setPeerSecurity: (peer: string, security: PeerSecurity) => void
  setConversationError: (peer: string, message: string | null) => void
  setSyncing: (syncing: boolean) => void
  setSyncError: (message: string | null) => void
  clear: () => void
}

function timeOf(value: string): number {
  const parsed = Date.parse(value)
  return Number.isFinite(parsed) ? parsed : 0
}

function sortItems(items: ChatItem[]): ChatItem[] {
  return [...items].sort((left, right) => {
    const delta = timeOf(left.createdAt) - timeOf(right.createdAt)
    if (delta !== 0) {
      return delta
    }
    return left.id.localeCompare(right.id)
  })
}

function emptyConversation(peer: string): Conversation {
  return {
    peer,
    items: [],
    blocked: null,
    lastError: null,
    peerKey: null,
    safetyNumber: null,
  }
}

function replaceConversation(
  state: MessagingState,
  peer: string,
  conversation: Conversation,
): MessagingState {
  return {
    ...state,
    conversations: { ...state.conversations, [peer]: conversation },
  }
}

export const useMessagingStore = create<MessagingState>((set, get) => ({
  conversations: {},
  syncing: false,
  lastSyncError: null,

  ensureConversation: (peer) => {
    if (get().conversations[peer] !== undefined) {
      return
    }
    set((state) => replaceConversation(state, peer, emptyConversation(peer)))
  },

  addOrReplaceMessage: (peer, message) => {
    set((state) => {
      const conversation =
        state.conversations[peer] ?? emptyConversation(peer)
      const existingIndex = conversation.items.findIndex(
        (item) =>
          item.kind === 'message' &&
          item.direction === message.direction &&
          item.clientMessageId === message.clientMessageId,
      )
      let items: ChatItem[]
      if (existingIndex >= 0) {
        items = conversation.items.map((item, index) =>
          index === existingIndex
            ? ({ ...item, ...message } as ChatMessage)
            : item,
        )
      } else {
        items = [...conversation.items, message]
      }
      // A later successful decrypt replaces an earlier error for the same row.
      items = items.filter(
        (item) =>
          !(
            item.kind === 'error' &&
            item.direction === message.direction &&
            item.clientMessageId === message.clientMessageId
          ),
      )
      return replaceConversation(state, peer, {
        ...conversation,
        items: sortItems(items),
      })
    })
  },

  addErrorRow: (peer, error) => {
    set((state) => {
      const conversation =
        state.conversations[peer] ?? emptyConversation(peer)
      if (conversation.items.some((item) => item.id === error.id)) {
        return state
      }
      // Do not add an error beside an already-displayed message for the row.
      if (
        conversation.items.some(
          (item) =>
            item.kind === 'message' &&
            item.direction === error.direction &&
            item.clientMessageId === error.clientMessageId,
        )
      ) {
        return state
      }
      return replaceConversation(state, peer, {
        ...conversation,
        items: sortItems([...conversation.items, error]),
      })
    })
  },

  updateMessage: (peer, clientMessageId, patch) => {
    set((state) => {
      const conversation = state.conversations[peer]
      if (conversation === undefined) {
        return state
      }
      return replaceConversation(state, peer, {
        ...conversation,
        items: sortItems(
          conversation.items.map((item) =>
            item.kind === 'message' &&
            item.direction === 'out' &&
            item.clientMessageId === clientMessageId
              ? { ...item, ...patch }
              : item,
          ),
        ),
      })
    })
  },

  hasMessage: (peer, direction, clientMessageId) => {
    const conversation = get().conversations[peer]
    if (conversation === undefined) {
      return false
    }
    return conversation.items.some(
      (item) =>
        item.kind === 'message' &&
        item.direction === direction &&
        item.clientMessageId === clientMessageId,
    )
  },

  setBlocked: (peer, blocked) => {
    set((state) => {
      const conversation =
        state.conversations[peer] ?? emptyConversation(peer)
      return replaceConversation(state, peer, { ...conversation, blocked })
    })
  },

  setPeerSecurity: (peer, security) => {
    set((state) => {
      const conversation =
        state.conversations[peer] ?? emptyConversation(peer)
      return replaceConversation(state, peer, {
        ...conversation,
        peerKey: security.peerKey,
        safetyNumber: security.safetyNumber,
      })
    })
  },

  setConversationError: (peer, message) => {
    set((state) => {
      const conversation =
        state.conversations[peer] ?? emptyConversation(peer)
      return replaceConversation(state, peer, {
        ...conversation,
        lastError: message,
      })
    })
  },

  setSyncing: (syncing) => set({ syncing }),

  setSyncError: (message) => set({ lastSyncError: message }),

  clear: () =>
    set({ conversations: {}, syncing: false, lastSyncError: null }),
}))

/** Drop all decrypted history when the session ends. */
export function clearMessaging(): void {
  useMessagingStore.getState().clear()
}

if (typeof window !== 'undefined') {
  useSessionStore.subscribe((state, previous) => {
    if (state.status === 'signed_out' && previous.status !== 'signed_out') {
      clearMessaging()
    }
  })
}
