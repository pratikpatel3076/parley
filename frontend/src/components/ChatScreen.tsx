import { useEffect, useState, type FormEvent } from 'react'

import { logout } from '../api/client'
import { USERNAME_PATTERN } from '../crypto/constants'
import { getMessageEngine } from '../messaging/engine'
import { useMessagingStore } from '../messaging/store'
import { lockSession, useSessionStore } from '../session/store'
import { ConversationList } from './chat/ConversationList'
import { ConversationView } from './chat/ConversationView'

interface ChatScreenProps {
  username: string
}

export function ChatScreen({ username }: ChatScreenProps) {
  const engine = getMessageEngine()
  const publicKey = useSessionStore((state) => state.publicKey)
  const conversations = useMessagingStore((state) => state.conversations)
  const syncing = useMessagingStore((state) => state.syncing)
  const lastSyncError = useMessagingStore((state) => state.lastSyncError)

  const [selected, setSelected] = useState<string | null>(null)
  const [peerInput, setPeerInput] = useState('')
  const [newError, setNewError] = useState<string | null>(null)
  const [signingOut, setSigningOut] = useState(false)

  useEffect(() => {
    void engine.start()
    return () => {
      engine.stop()
    }
  }, [engine])

  useEffect(() => {
    if (selected !== null && conversations[selected] !== undefined) {
      return
    }
    const first = Object.values(conversations)[0]
    if (first !== undefined) {
      setSelected(first.peer)
    }
  }, [conversations, selected])

  const conversation =
    selected === null ? undefined : conversations[selected]

  async function openConversation(
    event: FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault()
    const peer = peerInput.trim()
    if (!USERNAME_PATTERN.test(peer)) {
      setNewError(
        'Usernames are 3–32 lowercase letters, digits, or underscores.',
      )
      return
    }
    if (peer === username) {
      setNewError('You cannot open a conversation with yourself.')
      return
    }
    setNewError(null)
    await engine.openConversation(peer)
    setSelected(peer)
    setPeerInput('')
  }

  async function signOut(): Promise<void> {
    if (signingOut) {
      return
    }
    setSigningOut(true)
    try {
      await logout()
    } catch {
      // Logging out locally must succeed even when the network does not.
    } finally {
      engine.stop()
      lockSession()
      setSigningOut(false)
    }
  }

  return (
    <main className="flex min-h-screen flex-col bg-slate-950 text-slate-100 md:flex-row">
      <aside className="flex w-full shrink-0 flex-col border-b border-slate-800 bg-slate-950 md:h-screen md:w-80 md:border-b-0 md:border-r">
        <div className="px-4 py-5">
          <p className="text-xs font-medium uppercase tracking-[0.35em] text-slate-500">
            Portfolio project
          </p>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight">
            Parley
          </h1>
          <h2 className="mt-4 text-sm font-semibold text-slate-200">
            Signed in
          </h2>
          <p className="mt-1 text-sm text-slate-400">
            as <span className="text-slate-200">{username}</span>
          </p>
        </div>

        <form
          onSubmit={(event) => void openConversation(event)}
          className="border-y border-slate-800 px-4 py-3"
        >
          <label
            htmlFor="open-peer"
            className="text-xs font-medium uppercase tracking-wide text-slate-500"
          >
            Open a conversation
          </label>
          <div className="mt-2 flex gap-2">
            <input
              id="open-peer"
              value={peerInput}
              onChange={(event) => setPeerInput(event.target.value)}
              placeholder="username"
              autoComplete="off"
              spellCheck={false}
              className="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500"
            />
            <button
              type="submit"
              className="rounded-lg border border-slate-700 px-3 py-2 text-sm font-medium text-slate-200"
            >
              Open
            </button>
          </div>
          {newError !== null ? (
            <p role="alert" className="mt-2 text-xs text-rose-400">
              {newError}
            </p>
          ) : null}
        </form>

        <nav
          aria-label="Conversations"
          className="min-h-0 flex-1 overflow-y-auto py-3"
        >
          <ConversationList
            conversations={Object.values(conversations)}
            selected={selected}
            onSelect={setSelected}
          />
        </nav>

        <div className="mt-auto space-y-3 border-t border-slate-800 px-4 py-4">
          <p className="text-xs text-slate-500">
            {syncing
              ? 'Syncing…'
              : 'Polling every 5 seconds while this tab is visible.'}
          </p>
          {lastSyncError !== null ? (
            <p role="alert" className="text-xs text-amber-300">
              Sync paused: {lastSyncError}. Retrying with backoff.
            </p>
          ) : null}
          <button
            type="button"
            onClick={() => void signOut()}
            disabled={signingOut}
            className="w-full rounded-lg border border-slate-700 px-4 py-2 text-sm font-medium text-slate-200 disabled:cursor-not-allowed disabled:text-slate-500"
          >
            {signingOut ? 'Signing out…' : 'Sign out'}
          </button>
          <p className="text-xs leading-5 text-slate-600">
            Experimental, not audited. See THREAT_MODEL.
          </p>
        </div>
      </aside>

      <section className="min-h-0 flex-1 md:h-screen">
        {conversation !== undefined ? (
          <ConversationView
            conversation={conversation}
            username={username}
            myPublicKey={publicKey ?? ''}
            onSend={async (body) => {
              await engine.send(conversation.peer, body)
            }}
            onRetry={(clientMessageId) =>
              engine.retry(clientMessageId)
            }
            onAcknowledgeKeyChange={() =>
              engine.acknowledgePeerKeyChange(conversation.peer)
            }
          />
        ) : (
          <div className="flex h-full min-h-64 items-center justify-center px-6 text-center">
            <p className="max-w-sm text-sm leading-6 text-slate-500">
              Select a conversation, or open one by username. Messages are
              end-to-end encrypted in this browser; nothing is stored locally.
            </p>
          </div>
        )}
      </section>
    </main>
  )
}
