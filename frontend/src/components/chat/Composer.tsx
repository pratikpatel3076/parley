import { useState, type FormEvent, type KeyboardEvent } from 'react'

import { ApiError } from '../../api/client'
import { MAX_PLAINTEXT_BYTES } from '../../crypto/constants'
import { KeyChangedError } from '../../crypto/errors'
import { VaultLockedError } from '../../session/vault'

interface ComposerProps {
  disabled: boolean
  disabledReason?: string
  onSend: (body: string) => Promise<void>
}

function sendErrorText(error: unknown): string {
  if (error instanceof KeyChangedError) {
    return 'The contact key changed. Compare the safety number before sending.'
  }
  if (error instanceof VaultLockedError) {
    return 'The session is locked. Sign in again.'
  }
  if (error instanceof ApiError) {
    if (error.status === 404) {
      return 'That username does not exist.'
    }
    if (error.status === 0) {
      return 'Could not reach the server.'
    }
    return error.message
  }
  if (error instanceof Error && error.message.length > 0) {
    return error.message
  }
  return 'The message could not be sent.'
}

export function Composer({
  disabled,
  disabledReason,
  onSend,
}: ComposerProps) {
  const [body, setBody] = useState('')
  const [sending, setSending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const byteLength = new TextEncoder().encode(body).length
  const tooLong = byteLength > MAX_PLAINTEXT_BYTES
  const canSend =
    !disabled && !sending && !tooLong && body.trim().length > 0

  async function submit(): Promise<void> {
    if (!canSend) {
      return
    }
    const text = body
    setBody('')
    setError(null)
    setSending(true)
    try {
      await onSend(text)
    } catch (caught) {
      // Restore the text only when the message was never handed to the engine.
      setBody(text)
      setError(sendErrorText(caught))
    } finally {
      setSending(false)
    }
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault()
    void submit()
  }

  function handleKeyDown(
    event: KeyboardEvent<HTMLTextAreaElement>,
  ): void {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault()
      void submit()
    }
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="border-t border-slate-800 bg-slate-950/60 p-4"
    >
      {disabled && disabledReason !== undefined ? (
        <p className="mb-2 text-xs text-amber-300">{disabledReason}</p>
      ) : null}
      <div className="flex items-end gap-3">
        <label htmlFor="message-body" className="sr-only">
          Message
        </label>
        <textarea
          id="message-body"
          value={body}
          onChange={(event) => setBody(event.target.value)}
          onKeyDown={handleKeyDown}
          rows={2}
          disabled={disabled}
          placeholder={disabled ? 'Sending is blocked' : 'Write a message'}
          className="min-h-12 flex-1 resize-y rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 disabled:cursor-not-allowed disabled:opacity-60"
        />
        <button
          type="submit"
          disabled={!canSend}
          className="rounded-lg bg-slate-100 px-4 py-2 text-sm font-semibold text-slate-950 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
        >
          {sending ? 'Sending…' : 'Send'}
        </button>
      </div>
      <div className="mt-1 flex items-center justify-between gap-3 text-xs text-slate-500">
        <span>Enter sends, Shift+Enter adds a line.</span>
        <span className={tooLong ? 'text-rose-400' : undefined}>
          {byteLength.toLocaleString()} /{' '}
          {MAX_PLAINTEXT_BYTES.toLocaleString()} bytes
        </span>
      </div>
      {tooLong ? (
        <p role="alert" className="mt-1 text-xs text-rose-400">
          This message is too long.
        </p>
      ) : null}
      {error !== null ? (
        <p role="alert" className="mt-1 text-xs text-rose-400">
          {error}
        </p>
      ) : null}
    </form>
  )
}
