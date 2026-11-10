import { useEffect } from 'react'

import { useAppStore } from './stores/appStore'

export default function App() {
  const status = useAppStore((state) => state.status)
  const setReady = useAppStore((state) => state.setReady)

  useEffect(() => {
    setReady()
  }, [setReady])

  return (
    <main className="flex min-h-screen items-center justify-center bg-slate-950 px-6 text-slate-100">
      <section className="w-full max-w-xl rounded-2xl border border-slate-800 bg-slate-900/70 p-10 shadow-xl">
        <p className="text-xs font-medium uppercase tracking-[0.35em] text-slate-400">
          Portfolio project
        </p>
        <h1 className="mt-4 text-4xl font-semibold tracking-tight">Parley</h1>
        <p className="mt-4 text-base leading-7 text-slate-300">
          1:1 end-to-end encrypted messaging. The protocol is not implemented
          yet; this page only proves the frontend scaffold boots.
        </p>
        <p className="mt-6 inline-flex rounded-full border border-slate-700 px-3 py-1 text-xs text-slate-400">
          store: {status}
        </p>
      </section>
    </main>
  )
}
