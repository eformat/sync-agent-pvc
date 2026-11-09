import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The daemon serves this build via rust-embed: index.html at "/" and every
// other asset under "/assets/*", so the build must emit relative "./assets/…"
// references (base './'). The dev proxy forwards /api (including the SSE
// stream) to the locally running daemon.
export default defineConfig({
  base: "./",
  plugins: [react()],
  build: {
    outDir: "dist",
  },
  server: {
    proxy: {
      "/api": {
        target: "http://127.0.0.1:7391",
        changeOrigin: false,
      },
    },
  },
});
