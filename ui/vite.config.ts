import { resolve } from "node:path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": resolve(import.meta.dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:3000",
        changeOrigin: false,
      },
      "/health": {
        target: "http://localhost:3000",
        changeOrigin: false,
      },
      "/healthz": {
        target: "http://localhost:3000",
        changeOrigin: false,
      },
    },
  },
  build: {
    target: "es2022",
    cssCodeSplit: true,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) return undefined
          if (id.includes("@tanstack")) return "data-vendor"
          if (id.includes("motion") || id.includes("framer-motion")) return "motion-vendor"
          if (
            id.includes("/react/") ||
            id.includes("react-dom") ||
            id.includes("scheduler")
          ) {
            return "react-vendor"
          }
          if (id.includes("@base-ui") || id.includes("lucide-react") || id.includes("sonner")) {
            return "ui-vendor"
          }
          return undefined
        },
      },
    },
  },
})

