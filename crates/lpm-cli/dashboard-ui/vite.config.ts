import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

// Static, same-origin build:
// - `base: './'` so the bundle works from any path without absolute URLs.
// - `modulePreload.polyfill: false` keeps Vite from injecting its inline
//   preload script, so the output has no inline <script> at all.
export default defineConfig({
  plugins: [react()],
  base: './',
  build: {
    target: 'es2020',
    modulePreload: { polyfill: false },
    cssCodeSplit: false,
    outDir: '../src/commands/skills/dashboard',
    emptyOutDir: true,
    rollupOptions: {
      output: {
        entryFileNames: 'assets/dashboard.js',
        assetFileNames: 'assets/dashboard.[ext]',
        inlineDynamicImports: true,
      },
    },
  },
  test: {
    environment: 'happy-dom',
  },
});
