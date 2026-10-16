import path from "path";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/health": "http://localhost:8000",
      "/graph": "http://localhost:8000",
      "/scenarios": "http://localhost:8000",
      "/incidents": "http://localhost:8000",
      "/actions": "http://localhost:8000",
      "/replays": "http://localhost:8000",
      "/admin": "http://localhost:8000",
    },
  },
});
