import { create } from 'zustand'

type AppStatus = 'idle' | 'ready'

interface AppState {
  status: AppStatus
  setReady: () => void
}

export const useAppStore = create<AppState>((set) => ({
  status: 'idle',
  setReady: () => set({ status: 'ready' }),
}))
