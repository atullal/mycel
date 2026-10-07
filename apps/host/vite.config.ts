import { defineConfig } from "vite";

// No React plugin: esbuild's automatic JSX runtime is all we need, which keeps
// the dependency tree small. (No fast refresh; full reloads in dev.)
export default defineConfig({
  esbuild: { jsx: "automatic" },
  // Tauri expects a fixed port and must see Rust errors in the terminal.
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: process.env.TAURI_DEV_HOST || false,
    watch: { ignored: ["**/src-tauri/**"] },
  },
  envPrefix: ["VITE_", "TAURI_ENV_"],
  build: {
    target: "es2022",
    sourcemap: false,
    chunkSizeWarningLimit: 800,
  },
});
