/**
 * Validates verification/CLAIMS.yaml against the repository.
 *
 * A claims file that has drifted from the code is worse than no claims file:
 * it reads as verified and is not. This checker enforces the v0.2 rules that
 * can be checked mechanically:
 *
 *   1. Every `code_anchor.snippet` appears VERBATIM in `code_anchor.file`.
 *   2. Every anchor snippet is at most three lines.
 *   3. Every claim below `high` confidence has an `open_question` bearing on it.
 *   4. Every file named in `evidence:` that looks like a path actually exists.
 *   5. `audit_mode.confirmed` is unset -- setting it is a human act.
 *   6. `extraction_hash` is PENDING until a machine audit sets it.
 */
import { readFileSync, existsSync } from 'node:fs'
import { load as yamlLoad } from 'js-yaml'

const doc = yamlLoad(readFileSync('verification/CLAIMS.yaml', 'utf8'))
const problems = []
const note = (m) => problems.push(m)

const SECTIONS = [
  'invariants',
  'security_behaviors',
  'negative_claims',
  'threat_model',
  'parameters',
]

const claims = SECTIONS.flatMap((s) => (doc[s] ?? []).map((c) => ({ ...c, section: s })))
const openQuestions = doc.open_questions ?? []
const bearing = new Set(openQuestions.flatMap((q) => q.bearing_on_claims ?? []))

if (claims.length === 0) note('no claims found')

for (const c of claims) {
  const where = `${c.section}/${c.id ?? '(missing id)'}`

  if (!c.id) note(`${where}: missing id`)
  if (!c.claim) note(`${where}: missing claim text`)
  if (!c.implementation_provenance) note(`${where}: missing implementation_provenance`)

  // Rule 3 -- forced open_question below high confidence.
  if (c.confidence !== 'high' && !bearing.has(c.id)) {
    note(`${where}: confidence is "${c.confidence}" but no open_question bears on it`)
  }

  // Rules 1 and 2 -- the anchor.
  const a = c.code_anchor
  if (!a?.file || !a?.snippet) {
    note(`${where}: missing code_anchor`)
    continue
  }
  if (!existsSync(a.file)) {
    note(`${where}: code_anchor file does not exist: ${a.file}`)
    continue
  }
  const snippet = a.snippet.replace(/\n$/, '')
  const lines = snippet.split('\n').length
  if (lines > 3) note(`${where}: anchor snippet is ${lines} lines; the limit is 3`)
  if (!readFileSync(a.file, 'utf8').includes(snippet)) {
    note(`${where}: anchor snippet NOT found verbatim in ${a.file}\n      ${JSON.stringify(snippet)}`)
  }

  // Rule 4 -- evidence paths.
  for (const e of c.evidence ?? []) {
    const path = String(e).split(/\s+#/)[0].trim().split(/\s+/)[0]
    if (/^(src|fixtures|docs|vendor|verification|e2e)\//.test(path) && !existsSync(path)) {
      note(`${where}: evidence path does not exist: ${path}`)
    }
  }
}

// Rules 5 and 6.
if (doc.audit_mode?.confirmed != null) {
  note('audit_mode.confirmed is set; this file is hand-written and must not claim a machine audit')
}
if (doc.extraction_hash !== 'PENDING') {
  note(`extraction_hash must be PENDING until a machine audit sets it (found: ${doc.extraction_hash})`)
}

// The two claims the brief requires by name.
for (const required of ['NEG-1', 'THREAT-1']) {
  if (!claims.some((c) => c.id === required)) note(`required claim ${required} is missing`)
}

if (problems.length) {
  console.error(`CLAIMS.yaml: ${problems.length} problem(s)\n`)
  for (const p of problems) console.error(`  - ${p}`)
  process.exit(1)
}
console.log(
  `CLAIMS.yaml OK: ${claims.length} claims across ${SECTIONS.length} sections, ` +
    `${openQuestions.length} open questions, all anchors matched verbatim.`,
)
