import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { fileURLToPath } from 'node:url'

// https://vite.dev/config/
export default defineConfig({
  // Tailwind v4 is scoped to the administration area: src/admin-ui/admin.css is the
  // only stylesheet that imports it, and it deliberately omits Tailwind's preflight.
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  server: {
    host: '0.0.0.0',
    port: 5173,
    strictPort: false,
    allowedHosts: ['localhost', '127.0.0.1', '0.0.0.0'],
  },
})
