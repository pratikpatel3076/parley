import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        // Keep the browser's Origin header intact: the backend requires an
        // exact-match Origin for every state-changing request.
        changeOrigin: false,
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: './src/test/setup.ts',
    css: true,
    // The password-strength import and the 1000-nonce loop can take several
    // seconds on a loaded CI runner; the default 5s is too tight.
    testTimeout: 15_000,
  },
})
