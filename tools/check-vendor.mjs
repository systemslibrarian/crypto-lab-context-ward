// Offline integrity check for the vendored @noble/ed25519 sources.
// Runs as part of `npm test` and in CI before the build, so an edited or
// swapped vendor file fails loudly rather than shipping.
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const dir = 'vendor/noble-ed25519'
const sums = readFileSync(join(dir, 'SHA256SUMS'), 'utf8')
  .split('\n')
  .filter(Boolean)
  .map((line) => {
    const [hash, name] = line.trim().split(/\s+/)
    return { hash, name }
  })

let failed = false
for (const { hash, name } of sums) {
  const actual = createHash('sha256').update(readFileSync(join(dir, name))).digest('hex')
  if (actual !== hash) {
    console.error(`vendor integrity FAILED for ${dir}/${name}\n  expected ${hash}\n  actual   ${actual}`)
    failed = true
  } else {
    console.log(`vendor integrity OK: ${dir}/${name}`)
  }
}
if (failed) {
  console.error('See vendor/noble-ed25519/INTEGRITY.md to re-verify against the npm tarball.')
  process.exit(1)
}
