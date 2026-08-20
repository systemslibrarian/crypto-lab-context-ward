import { defineConfig } from 'vite'

export default defineConfig({
  base: '/crypto-lab-context-ward/',
  build: { target: 'es2022', assetsInlineLimit: 0 },
  test: { include: ['src/**/*.test.ts'], globals: true },
})
