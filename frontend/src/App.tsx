import { useState } from 'react'

import { LoginForm } from './components/LoginForm'
import { RegisterForm } from './components/RegisterForm'
import { SessionPanel } from './components/SessionPanel'
import { useSessionStore } from './session/store'

type Screen = 'login' | 'register'

export default function App() {
  const status = useSessionStore((state) => state.status)
  const username = useSessionStore((state) => state.username)
  const [screen, setScreen] = useState<Screen>('login')

  const signedIn = status === 'unlocked' && username !== null

  return (
    <main className="flex min-h-screen flex-col items-center justify-center bg-slate-950 px-6 py-12 text-slate-100">
      <section className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900/70 p-8 shadow-xl sm:p-10">
        <p className="text-xs font-medium uppercase tracking-[0.35em] text-slate-400">
          Portfolio project
        </p>
        <h1 className="mt-3 text-3xl font-semibold tracking-tight">Parley</h1>
        <p className="mt-3 text-sm leading-6 text-slate-400">
          1:1 end-to-end encrypted messaging. Your password unlocks a key that
          never leaves this device.
        </p>

        <div className="mt-8">
          {signedIn ? (
            <SessionPanel username={username} />
          ) : screen === 'login' ? (
            <LoginForm onSwitchToRegister={() => setScreen('register')} />
          ) : (
            <RegisterForm onSwitchToLogin={() => setScreen('login')} />
          )}
        </div>
      </section>

      <footer className="mt-8 text-xs text-slate-500">
        Experimental, not audited. See THREAT_MODEL.
      </footer>
    </main>
  )
}
