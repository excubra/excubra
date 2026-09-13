import path from "node:path"
import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"
import tailwindcss from "@tailwindcss/vite"

// The console SPA: the console. Built assets are embedded into the Go binary
// (internal/server/console/webdist) and served at the root by the overlay listener;
// the API lives below /api/, the login form and its assets are server-rendered.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: "/",
  resolve: { alias: { "@": path.resolve(__dirname, "./src") } },
  build: { outDir: "../internal/server/console/webdist", emptyOutDir: false, sourcemap: false },
  server: { port: 5173, proxy: { "/api": "http://127.0.0.1:18080", "/login": "http://127.0.0.1:18080", "/logout": "http://127.0.0.1:18080", "/static": "http://127.0.0.1:18080" } },
})
