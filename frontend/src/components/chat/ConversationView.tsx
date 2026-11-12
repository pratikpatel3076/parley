import { useState } from 'react'

import type {
  ChatError,
  ChatItem,
  ChatMessage,
  Conversation,
} from '../../messaging/store'
import { Composer } from './Composer'
import { KeyChangeBanner } from './KeyChangeBanner'

interface ConversationViewProps {
  conversation: Conversation
  username: string
  onSend: (body: string) => Promise<void>
  onRetry: (clientMessageId: string) => Promise<void>
  onAcknowledgeKeyChange: () => Promise<void>
}

function formatTime(value: string): string {
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) {
    return ''
  }
  return parsed.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
  })
}

function errorText(error: ChatError): string {
  switch (error.reason) {
    case 'decryption_failed':
      return 'This message could not be decrypted. It may have been tampered with.'
    case 'envelope_mismatch':
      return 'This message failed its sender or recipient check.'
    case 'invalid_input':
      return 'This message had an invalid envelope.'
    case 'key_changed':
      return 'Received while the contact key was unverified. Compare the safety number above.'
    case 'sent_before_key_change':
      return 'This sent message was encrypted with an older contact key and can no longer be decrypted.'
    default:
      return 'This message could not be displayed.'
  }
}

function MessageRow({
  message,
  retrying,
  onRetry,
}: {
  message: ChatMessage
  retrying: boolean
  onRetry: (clientMessageId: string) => Promise<void>
}) {
  const outgoing = message.direction === 'out'
  return (
    <li
      className={`flex ${outgoing ? 'justify-end' : 'justify-start'}`}
    >
      <div
        className={`max-w-[80%] rounded-2xl px-4 py-2 text-sm leading-6 ${
          outgoing
            ? 'bg-slate-100 text-slate-950'
            : 'bg-slate-800 text-slate-100'
        }`}
      >
        <p className="whitespace-pre-wrap break-words">{message.body}</p>
        <div
          className={`mt-1 flex items-center gap-2 text-xs ${
            outgoing ? 'text-slate-600' : 'text-slate-400'
          }`}
        >
          <span>{formatTime(message.createdAt)}</span>
          {outgoing ? (
            <span>
              {message.status === 'sending'
                ? 'Sending…'
                : message.status === 'failed'
                  ? 'Failed'
                  : 'Sent'}
            </span>
          ) : null}
        </div>
        {message.status === 'failed' ? (
          <div className="mt-1 flex items-center gap-2 text-xs text-rose-600">
            {message.failure !== undefined ? (
              <span>{message.failure}</span>
            ) : null}
            {message.pending !== undefined ? (
              <button
                type="button"
                onClick={() => void onRetry(message.clientMessageId)}
                disabled={retrying}
                className="rounded border border-rose-400 px-2 py-0.5 font-semibold disabled:opacity-60"
              >
                {retrying ? 'Retrying…' : 'Retry'}
              </button>
            ) : null}
          </div>
        ) : null}
      </div>
    </li>
  )
}

function ErrorRow({ error }: { error: ChatError }) {
  return (
    <li className="flex justify-center">
      <p
        role="note"
        className="max-w-[85%] rounded-lg border border-amber-800/60 bg-amber-950/30 px-3 py-2 text-center text-xs leading-5 text-amber-200"
      >
        {errorText(error)}
      </p>
    </li>
  )
}

export function ConversationView({
  conversation,
  username,
  onSend,
  onRetry,
  onAcknowledgeKeyChange,
}: ConversationViewProps) {
  const [retrying, setRetrying] = useState<string | null>(null)
  const [retryError, setRetryError] = useState<string | null>(null)

  async function retry(clientMessageId: string): Promise<void> {
    setRetrying(clientMessageId)
    setRetryError(null)
    try {
      await onRetry(clientMessageId)
    } catch {
      setRetryError('This message could not be retried.')
    } finally {
      setRetrying(null)
    }
  }

  const blocked = conversation.blocked !== null

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="border-b border-slate-800 px-5 py-4">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h2 className="text-lg font-semibold tracking-tight">
            {conversation.peer}
          </h2>
          <p className="text-xs text-slate-500">Signed in as {username}</p>
        </div>
        {conversation.safetyNumber !== null ? (
          <div className="mt-2">
            <p className="text-xs uppercase tracking-wide text-slate-500">
              Safety number
            </p>
            <code
              aria-label={`Safety number with ${conversation.peer}`}
              className="mt-1 block break-words font-mono text-xs text-slate-400"
            >
              {conversation.safetyNumber}
            </code>
          </div>
        ) : null}
      </header>

      {conversation.blocked !== null ? (
        <KeyChangeBanner
          peer={conversation.peer}
          pinnedSafetyNumber={conversation.blocked.pinnedSafetyNumber}
          seenSafetyNumber={conversation.blocked.seenSafetyNumber}
          onAcknowledge={onAcknowledgeKeyChange}
        />
      ) : null}

      {conversation.lastError !== null ? (
        <p
          role="alert"
          className="mx-4 mt-3 rounded-lg border border-rose-900/60 bg-rose-950/30 px-3 py-2 text-sm text-rose-200"
        >
          {conversation.lastError}
        </p>
      ) : null}

      {retryError !== null ? (
        <p
          role="alert"
          className="mx-4 mt-3 rounded-lg border border-rose-900/60 bg-rose-950/30 px-3 py-2 text-sm text-rose-200"
        >
          {retryError}
        </p>
      ) : null}

      <ol
        aria-label="Messages"
        className="min-h-0 flex-1 space-y-3 overflow-y-auto px-4 py-4"
      >
        {conversation.items.length === 0 ? (
          <li className="py-10 text-center text-sm text-slate-500">
            No messages yet. Say hello.
          </li>
        ) : (
          conversation.items.map((item: ChatItem) =>
            item.kind === 'message' ? (
              <MessageRow
                key={item.id}
                message={item}
                retrying={retrying === item.clientMessageId}
                onRetry={retry}
              />
            ) : (
              <ErrorRow key={item.id} error={item} />
            ),
          )
        )}
      </ol>

      <Composer
        disabled={blocked}
        disabledReason={
          blocked
            ? 'Compare the safety number and accept the new key before sending.'
            : undefined
        }
        onSend={onSend}
      />
    </div>
  )
}
