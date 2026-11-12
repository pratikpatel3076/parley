import { useEffect, useState } from 'react'

import {
  readVerification,
  setContactVerified,
  type VerificationSnapshot,
} from '../../session/verification'

interface VerificationPanelProps {
  open: boolean
  owner: string
  peer: string
  myPublicKey: string
  onClose: () => void
  onChanged: () => void
}

function rowsOf(number: string): string[][] {
  const groups = number.split(' ')
  return [groups.slice(0, 4), groups.slice(4, 8), groups.slice(8, 12)]
}

export function VerificationPanel({
  open,
  owner,
  peer,
  myPublicKey,
  onClose,
  onChanged,
}: VerificationPanelProps) {
  const [snapshot, setSnapshot] = useState<
    VerificationSnapshot | null | undefined
  >(undefined)
  const [checked, setChecked] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!open) {
      return
    }
    let active = true
    setSnapshot(undefined)
    setChecked(false)
    setError(null)
    void readVerification(owner, peer, myPublicKey)
      .then((next) => {
        if (active) {
          setSnapshot(next)
        }
      })
      .catch(() => {
        if (active) {
          setSnapshot(null)
          setError('Could not read the pinned contact key.')
        }
      })
    return () => {
      active = false
    }
  }, [open, owner, peer, myPublicKey])

  if (!open) {
    return null
  }

  async function update(verified: boolean): Promise<void> {
    if (busy || snapshot === null || snapshot === undefined) {
      return
    }
    if (verified && !checked) {
      return
    }
    setBusy(true)
    setError(null)
    try {
      await setContactVerified(owner, peer, verified)
      const next = await readVerification(owner, peer, myPublicKey)
      setSnapshot(next)
      setChecked(false)
      onChanged()
    } catch {
      setError('Could not update verification. Try again.')
    } finally {
      setBusy(false)
    }
  }

  const verified = snapshot?.verified === true

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={`Verify ${peer}`}
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 px-4 py-8"
    >
      <div className="w-full max-w-xl rounded-2xl border border-slate-700 bg-slate-900 p-6 text-slate-100 shadow-2xl">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h3 className="text-lg font-semibold">Verify {peer}</h3>
            <p className="mt-1 text-xs text-slate-400">
              You ({owner}) and {peer}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300"
          >
            Close
          </button>
        </div>

        {snapshot === undefined ? (
          <p className="mt-6 text-sm text-slate-400">Reading pinned key…</p>
        ) : snapshot === null ? (
          <p className="mt-6 text-sm text-amber-200">
            No key is pinned for {peer} yet. Send or receive a message first.
          </p>
        ) : (
          <>
            <div
              aria-label={`Safety number with ${peer}`}
              className="mt-5 rounded-xl border border-slate-700 bg-slate-950 px-4 py-4 font-mono text-sm tracking-widest text-slate-100"
            >
              {rowsOf(snapshot.safetyNumber).map((row, index) => (
                <div
                  key={index}
                  className="grid grid-cols-4 gap-x-4 gap-y-2 py-0.5"
                >
                  {row.map((group, groupIndex) => (
                    <span key={`${index}-${groupIndex}`}>{group}</span>
                  ))}
                </div>
              ))}
            </div>

            <p className="mt-4 text-sm leading-6 text-slate-300">
              Compare this number with {peer} in person, or over a call where
              you recognise their voice. Do not compare it through Parley or any
              other channel the server controls. Verified only means the numbers
              matched at that time.
            </p>

            <p className="mt-3 text-xs leading-5 text-slate-500">
              This number is computed from the key pinned on this device, not
              from a key the server presents now.
            </p>

            {verified ? (
              <button
                type="button"
                onClick={() => void update(false)}
                disabled={busy}
                className="mt-5 rounded-lg border border-slate-600 px-4 py-2 text-sm font-medium text-slate-200 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {busy ? 'Updating…' : 'Remove verification'}
              </button>
            ) : (
              <>
                <label className="mt-5 flex items-start gap-2 text-sm leading-6 text-slate-300">
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={(event) => setChecked(event.target.checked)}
                    className="mt-1"
                  />
                  <span>
                    I compared these numbers with my contact through a channel I
                    trust
                  </span>
                </label>
                <button
                  type="button"
                  onClick={() => void update(true)}
                  disabled={!checked || busy}
                  className="mt-4 rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-emerald-950 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {busy ? 'Saving…' : 'Mark as verified'}
                </button>
              </>
            )}
          </>
        )}

        {error !== null ? (
          <p role="alert" className="mt-3 text-xs text-rose-300">
            {error}
          </p>
        ) : null}
      </div>
    </div>
  )
}
