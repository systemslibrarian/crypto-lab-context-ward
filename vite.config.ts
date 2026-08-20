// `defineConfig` comes from vitest/config, not vite: the `test` key below is
// vitest's, and vite's own config type does not declare it.
import { defineConfig } from 'vitest/config'

export default defineConfig({
  base: '/crypto-lab-context-ward/',
  build: { target: 'es2022', assetsInlineLimit: 0 },
  test: { include: ['src/**/*.test.ts'], globals: true },
})
