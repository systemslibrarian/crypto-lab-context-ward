import { defineConfig } from '@playwright/test'

// Port 4671: chosen from the 4600-4700 range the template reserves, and NOT the
// Vite default 4173 -- a shared port means `reuseExistingServer` can silently
// scan a sibling lab's preview instead of this one.
const BASE = 'http://localhost:4671/crypto-lab-context-ward/'

export default defineConfig({
  testDir: './e2e',
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  use: {
    baseURL: BASE,
    colorScheme: 'dark',
  },
  webServer: {
    // `npm run build` FIRST. `preview` serves whatever is already in dist/, so
    // without the build in front a run tests a stale bundle -- and a build that
    // FAILS leaves the previous good bundle in place, so the whole suite passes
    // green against source that no longer compiles.
    command: 'npm run build && npm run preview -- --port 4671 --strictPort',
    url: BASE,
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
  },
})
