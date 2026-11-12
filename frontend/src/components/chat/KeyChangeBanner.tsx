import { useState } from 'react'

interface KeyChangeBannerProps {
  peer: string
  pinnedSafetyNumber: string | null
  seenSafetyNumber: string | null
  onAcknowledge: () => Promise<void>
}

export function KeyChangeBanner({
  peer,
  pinnedSafetyNumber,
  seenSafetyNumber,
  onAcknowledge,
}: KeyChangeBannerProps) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function acknowledge(): Promise<void> {
    if (busy) {
      return
    }
    setBusy(true)
    setError(null)
    try {
      await onAcknowledge()
    } catch {
      setError('Could not accept the new key. Try again.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div
      role="alert"
      className="m-4 rounded-xl border border-amber-700/60 bg-amber-950/40 p-4 text-sm leading-6 text-amber-100"
    >
      <p className="font-semibold text-amber-200">
        The public key for {peer} changed
      </p>
      <p className="mt-2">
        Sending and automatic decryption are blocked until you compare the
        safety numbers out of band. Only continue if the new number matches what{' '}
        {peer} reads to you.
      </p>

      <dl className="mt-3 grid gap-2 sm:grid-cols-2">
        <div>
          <dt className="text-xs uppercase tracking-wide text-amber-400">
            Previous
          </dt>
          <dd className="mt-1 break-words font-mono text-xs">
            {pinnedSafetyNumber ?? 'Unavailable'}
          </dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-amber-400">
            New
          </dt>
          <dd className="mt-1 break-words font-mono text-xs">
            {seenSafetyNumber ?? 'Unavailable'}
          </dd>
        </div>
      </dl>

      <button
        type="button"
        onClick={() => void acknowledge()}
        disabled={busy}
        className="mt-4 rounded-lg bg-amber-500 px-3 py-2 text-sm font-semibold text-amber-950 disabled:cursor-not-allowed disabled:opacity-60"
      >
        {busy ? 'Accepting…' : 'I compared the safety numbers'}
      </button>
      {error !== null ? (
        <p role="alert" className="mt-2 text-xs text-amber-300">
          {error}
        </p>
      ) : null}
    </div>
  )
}
