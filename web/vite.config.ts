import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// In dev, /api is proxied to the BFF (services/api on :8000). In prod the SPA is
// built to static assets and served behind the same origin as the BFF.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      '/api': { target: process.env.MIRAIGE_API ?? 'http://localhost:8000', changeOrigin: true },
    },
  },
  build: { outDir: 'dist' },
})
