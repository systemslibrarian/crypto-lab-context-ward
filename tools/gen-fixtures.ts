/**
 * Regenerates /fixtures from the act definitions.
 *
 * The fixtures are COMMITTED and pinned. `verification/verify.py` reads them and
 * recomputes every value from the prose spec in `docs/MATH.md` without importing
 * anything from `src/`. Running this script must be a no-op on a clean tree; CI
 * asserts exactly that.
 *
 * Non-ASCII vectors are written as explicit escapes where the exact code points
 * matter: hand-typed accented text is ambiguous between composed and decomposed
 * forms, and two of these vectors exist precisely to pin that difference.
 */
import { mkdirSync, writeFileSync } from 'node:fs'
import { buildActs } from '../src/acts/index.ts'
import { kit, SEEDS } from '../src/acts/kit.ts'
import { verifyTranscript } from '../src/verify.ts'
import { enc, fromHex, toHex, ZERO32 } from '../src/bytes.ts'
import { leafHash, ROLES } from '../src/envelope.ts'
import { chainStep } from '../src/chain.ts'
import { deriveRoleKey, seal } from '../src/seal.ts'
import { attest } from '../src/attest.ts'
import { runAgent } from '../src/agent-mock.ts'

const OUT = 'fixtures'
const J = (o: unknown) => JSON.stringify(o, null, 2) + '\n'

/** U+0065 U+0301 -- "e" plus COMBINING ACUTE ACCENT. */
const DECOMPOSED_E = String.fromCharCode(0x65, 0x301)
/** U+00E9 -- LATIN SMALL LETTER E WITH ACUTE, a single code point. */
const COMPOSED_E = String.fromCharCode(0xe9)
/** An embedded NUL, built rather than typed so it survives every editor. */
const NUL_VECTOR = 'a' + String.fromCharCode(0) + 'b'

interface ManifestEntry {
  file: string
  kind: 'transcript' | 'vectors'
  expect: 'ok' | 'fail'
  expect_codes: string[]
  agent_compromised?: boolean
  note: string
}

async function main() {
  mkdirSync(OUT + '/transcripts', { recursive: true })
  mkdirSync(OUT + '/vectors', { recursive: true })
  const manifest: ManifestEntry[] = []
  const acts = await buildActs()

  // --- One fixture per act, in the state the visitor first sees it. --------
  for (const a of acts) {
    const t = await a.build()
    const r = await verifyTranscript(t)
    const file = `transcripts/act${a.label}.json`
    writeFileSync(`${OUT}/${file}`, J(t))
    manifest.push({
      file,
      kind: 'transcript',
      expect: r.ok ? 'ok' : 'fail',
      expect_codes: [...new Set(r.findings.map((f) => f.code))].sort(),
      agent_compromised: runAgent(t, a.task).compromised,
      note: `Act ${a.label}: ${a.title}. ${a.question}`,
    })
  }

  // --- One fixture per named failure, so verify.py exercises every branch. -
  for (const a of acts) {
    for (const c of a.tampers) {
      const t = await c.apply(await a.build())
      const r = await verifyTranscript(t)
      const file = `transcripts/tampered-act${a.label}-${c.id}.json`
      writeFileSync(`${OUT}/${file}`, J(t))
      manifest.push({
        file,
        kind: 'transcript',
        expect: r.ok ? 'ok' : 'fail',
        expect_codes: [...new Set(r.findings.map((f) => f.code))].sort(),
        agent_compromised: runAgent(t, a.task).compromised,
        note:
          `Act ${a.label} tamper control "${c.label}" -- advertised failure: ` +
          `${c.expect ?? 'NONE (stays green)'}.`,
      })
    }
  }

  // --- Encoding vectors, including the ones a second implementation trips on.
  const encVectors = [
    { name: 'empty', s: '', note: 'zero length, still length-prefixed' },
    { name: 'ascii', s: 'ticket_db', note: 'plain ASCII' },
    { name: 'latin1-supplement', s: 'caf' + COMPOSED_E, note: 'U+00E9, two-byte UTF-8' },
    { name: 'cjk', s: '発注書', note: 'three-byte UTF-8 (Japanese)' },
    {
      name: 'astral-musical',
      s: '\u{1D11E}',
      note: 'U+1D11E, four-byte UTF-8, a surrogate PAIR in UTF-16',
    },
    { name: 'astral-emoji', s: '\u{1F512}', note: 'U+1F512, four-byte UTF-8' },
    { name: 'mixed', s: 'a\u{1F512}' + COMPOSED_E + '発', note: 'mixed widths in one string' },
    {
      name: 'combining-not-normalised',
      s: DECOMPOSED_E,
      note: 'U+0065 U+0301 (decomposed) -- must NOT fold to U+00E9; no normalisation is performed',
    },
    {
      name: 'precomposed-not-normalised',
      s: COMPOSED_E,
      note: 'U+00E9 (composed) -- a DIFFERENT encoding from the decomposed form above, by design',
    },
    { name: 'newlines', s: 'line1\nline2\r\n', note: 'control characters pass through unchanged' },
    { name: 'embedded-nul', s: NUL_VECTOR, note: 'an embedded NUL is data, not a terminator' },
  ].map((v) => ({ ...v, enc_hex: toHex(enc(v.s)), utf8_len: enc(v.s).length - 4 }))

  const rejectVectors = [
    { name: 'lone-high-surrogate', s: 'a\ud800b', reason: 'unpaired high surrogate U+D800' },
    { name: 'lone-low-surrogate', s: 'a\udc00b', reason: 'unpaired low surrogate U+DC00' },
    {
      name: 'trailing-high-surrogate',
      s: 'ab\ud83d',
      reason: 'unpaired high surrogate at end of string',
    },
    { name: 'reversed-pair', s: '\udc00\ud800', reason: 'low surrogate before high surrogate' },
  ]

  writeFileSync(
    `${OUT}/vectors/encoding.json`,
    J({
      note:
        'enc(s) = uint32be(byte_len(utf8(s))) || utf8(s). No Unicode normalisation. ' +
        'Every string in `reject` MUST be refused rather than encoded with U+FFFD substituted. ' +
        'The two `not-normalised` vectors are canonically equivalent text with deliberately ' +
        'different encodings; an implementation that normalises will produce equal enc_hex.',
      accept: encVectors,
      reject: rejectVectors,
    }),
  )
  manifest.push({
    file: 'vectors/encoding.json',
    kind: 'vectors',
    expect: 'ok',
    expect_codes: [],
    note: 'Cross-implementation encoding vectors: non-ASCII, astral-plane, and rejected unpaired surrogates.',
  })

  // --- Protocol vectors: leaf, chain, role key, tag, signature. ------------
  const k = await kit()
  const sessionBytes = fromHex(SEEDS.session)
  const sessionKey = fromHex(SEEDS.sessionKey)

  const sample = {
    v: 1,
    session: SEEDS.session,
    seq: 7,
    role: 'tool_result' as const,
    tool: 'ticket_db',
    body: 'caf' + COMPOSED_E + ' \u{1D11E} 発注書\nline two',
    prev: 'f'.repeat(64),
  }
  const leaf = await leafHash(sample)
  const hPrev = fromHex('a'.repeat(64))
  const chainFromZero = await chainStep(ZERO32, leaf)
  const chainFromPrev = await chainStep(hPrev, leaf)

  const roleKeys: Record<string, string> = {}
  const tags: Record<string, string> = {}
  for (const r of ROLES) {
    roleKeys[r] = toHex(await deriveRoleKey(sessionKey, sessionBytes, r))
    tags[r] = toHex(await seal(sessionKey, sessionBytes, r, chainFromPrev))
  }

  writeFileSync(
    `${OUT}/vectors/protocol.json`,
    J({
      note:
        'Intermediate values for a single envelope, so a second implementation can localise a ' +
        'mismatch instead of only observing that the final tag differs. The HKDF salt is the ' +
        'RAW 32 session bytes, NOT the 64-character hex string -- that is the single place ' +
        'the two representations diverge and the likeliest source of a mismatch.',
      session_key: SEEDS.sessionKey,
      session_bytes: SEEDS.session,
      envelope: sample,
      leaf: toHex(leaf),
      chain_from_zero: toHex(chainFromZero),
      chain_from_prev: { h_prev: toHex(hPrev), h_n: toHex(chainFromPrev) },
      role_keys: roleKeys,
      // Every role's tag over the SAME chain head. All six differ: that is role
      // separation, and salting HKDF with the hex string instead of the raw
      // bytes changes all six without changing their distinctness.
      tags_over_chain_from_prev: tags,
      tool_attestation: {
        tool: 'ticket_db',
        public_key: toHex(k.ticketDb.publicKey),
        secret_key_seed: SEEDS.toolTicketDb,
        session: sample.session,
        seq: sample.seq,
        leaf: toHex(leaf),
        signature: toHex(await attest(k.ticketDb.secretKey, sample.session, sample.seq, leaf)),
      },
    }),
  )
  manifest.push({
    file: 'vectors/protocol.json',
    kind: 'vectors',
    expect: 'ok',
    expect_codes: [],
    note: 'Per-step protocol vectors: leaf, chain, per-role HKDF keys, per-role tags, Ed25519 attestation.',
  })

  writeFileSync(
    `${OUT}/MANIFEST.json`,
    J({
      note:
        'Generated by `npm run fixtures`. Committed and pinned. `verification/verify.py` reads ' +
        'this manifest and checks each entry against values it recomputes from docs/MATH.md, ' +
        'importing nothing from src/.',
      protocol_version: 1,
      generated_by: 'tools/gen-fixtures.ts',
      entries: manifest,
    }),
  )

  const green = manifest.filter((m) => m.kind === 'transcript' && m.expect === 'ok').length
  const red = manifest.filter((m) => m.kind === 'transcript' && m.expect === 'fail').length
  const hostileGreen = manifest.filter((m) => m.agent_compromised && m.expect === 'ok').length
  console.log(
    `fixtures: ${manifest.length} entries -- ${green} verify clean, ${red} named failures, ` +
      `${hostileGreen} of the clean ones carry a payload the scripted agent obeys.`,
  )
}

await main()
