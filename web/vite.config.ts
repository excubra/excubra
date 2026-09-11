import path from "node:path"
import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"
import tailwindcss from "@tailwindcss/vite"

// The console SPA. Built assets are embedded into the Go binary (internal/server/console/webdist)
// and served below /app/ by the overlay listener; the API lives below /api/.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: "/app/",
  resolve: { alias: { "@": path.resolve(__dirname, "./src") } },
  build: { outDir: "../internal/server/console/webdist", emptyOutDir: true, sourcemap: false },
  server: { port: 5173, proxy: { "/api": "http://127.0.0.1:18080", "/login": "http://127.0.0.1:18080", "/logout": "http://127.0.0.1:18080" } },
})
