import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Build outputs to web/dist, which the Go binary embeds.
export default defineConfig({
  plugins: [react()],
  build: { outDir: 'dist', emptyOutDir: true },
  server: { proxy: { '/admin': 'http://localhost:8080', '/mcp': 'http://localhost:8080' } },
})
