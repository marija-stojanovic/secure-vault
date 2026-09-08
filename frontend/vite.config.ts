import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const configDirectory = dirname(fileURLToPath(import.meta.url))

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    https: {
      pfx: readFileSync(resolve(configDirectory, 'certificates/frontend.p12')),
      passphrase: process.env.FRONTEND_TLS_KEYSTORE_PASSWORD ?? 'securevault',
    },
  },
})
