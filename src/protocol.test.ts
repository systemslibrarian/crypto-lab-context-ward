import { describe, expect, it } from 'vitest'
import { fromHex, toHex, ZERO32, ZERO_PREV } from './bytes.ts'
import { assertWellFormed, leafHash, PROTOCOL_VERSION, ROLES, type Envelope } from './envelope.ts'
import { chainHashesHex, chainStep } from './chain.ts'
import { deriveRoleKey, seal, sealTag, verifySeal } from './seal.ts'
import { attest, verifyAttestation } from './attest.ts'
import { ed25519PublicKey } from './primitives.ts'
import { SEEDS } from './acts/kit.ts'

const SESSION = SEEDS.session
const SESSION_BYTES = fromHex(SEEDS.session)
const SESSION_KEY = fromHex(SEEDS.sessionKey)

function env(over: Partial<Envelope> = {}): Envelope {
  return {
    v: PROTOCOL_VERSION,
    session: SESSION,
    seq: 0,
    role: 'tool_result',
    tool: 'ticket_db',
    body: 'hello',
    prev: ZERO_PREV,
    ...over,
  }
}

describe('leaf hashing', () => {
  it('is deterministic', async () => {
    expect(toHex(await leafHash(env()))).toBe(toHex(await leafHash(env())))
  })

  it('covers every field it displays', async () => {
    const base = toHex(await leafHash(env()))
    for (const [field, value] of [
      ['v', 2],
      ['seq', 1],
      ['role', 'system'],
      ['tool', 'other_tool'],
      ['body', 'hello '],
      ['session', SEEDS.priorSession],
    ] as const) {
      const changed = toHex(await leafHash(env({ [field]: value } as Partial<Envelope>)))
      expect(changed, `changing ${field} must change the leaf`).not.toBe(base)
    }
  })

  it('does NOT cover prev — prev is a display mirror', async () => {
    const a = await leafHash(env({ seq: 1, prev: 'a'.repeat(64) }))
    const b = await leafHash(env({ seq: 1, prev: 'b'.repeat(64) }))
    expect(toHex(a)).toBe(toHex(b))
  })

  it('hashes tool=null and tool="" identically, as enc(tool ?? "") requires', async () => {
    const a = toHex(await leafHash(env({ role: 'runtime', tool: null })))
    const b = toHex(await leafHash(env({ role: 'runtime', tool: '' })))
    expect(b).toBe(a)
  })
})

describe('well-formedness', () => {
  it('rejects a bad session, seq, role and prev', () => {
    expect(() => assertWellFormed(env({ session: 'nope' }))).toThrow()
    expect(() => assertWellFormed(env({ session: SESSION.toUpperCase() }))).toThrow()
    expect(() => assertWellFormed(env({ seq: -1 }))).toThrow()
    expect(() => assertWellFormed(env({ role: 'admin' as never }))).toThrow()
    expect(() => assertWellFormed(env({ prev: 'ff' }))).toThrow()
  })
  it('imposes no role/tool consistency rule — every role may carry a tool name', () => {
    // `tool` is authenticated by the leaf like every other field. A surprising
    // role/tool pairing is a thing the verifier REPORTS, not a parse error, and
    // the ROLE_MISMATCH probe depends on such an envelope reaching the seal check.
    for (const r of ROLES) {
      expect(() => assertWellFormed(env({ role: r, tool: 't' })), r).not.toThrow()
    }
  })
})

describe('chain', () => {
  it('starts from 32 zero bytes', async () => {
    const leaf = await leafHash(env())
    const [h0] = await chainHashesHex([env()])
    expect(h0).toBe(toHex(await chainStep(ZERO32, leaf)))
  })

  it('binds order — swapping two segments changes the head', async () => {
    const a = env({ seq: 0, body: 'first' })
    const b = env({ seq: 1, body: 'second', prev: ZERO_PREV })
    const fwd = await chainHashesHex([a, b])
    const rev = await chainHashesHex([b, a])
    expect(fwd[1]).not.toBe(rev[1])
  })
})

describe('host seal — role separation', () => {
  it('derives a DIFFERENT key per role', async () => {
    const keys = new Set<string>()
    for (const r of ROLES) keys.add(toHex(await deriveRoleKey(SESSION_KEY, SESSION_BYTES, r)))
    expect(keys.size).toBe(ROLES.length)
  })

  it('REQUIRED: a tool_result tag does NOT verify as a system tag', async () => {
    const h = await chainStep(ZERO32, await leafHash(env()))
    const toolTag = await seal(SESSION_KEY, SESSION_BYTES, 'tool_result', h)
    expect(await verifySeal(SESSION_KEY, SESSION_BYTES, 'tool_result', h, toolTag)).toBe(true)
    expect(await verifySeal(SESSION_KEY, SESSION_BYTES, 'system', h, toolTag)).toBe(false)
  })

  it('no tag verifies under any role other than its own', async () => {
    const h = await chainStep(ZERO32, await leafHash(env()))
    for (const made of ROLES) {
      const tag = await seal(SESSION_KEY, SESSION_BYTES, made, h)
      for (const tried of ROLES) {
        const ok = await verifySeal(SESSION_KEY, SESSION_BYTES, tried, h, tag)
        expect(ok, `${made} tag under ${tried}`).toBe(made === tried)
      }
    }
  })

  it('uses the RAW session bytes as HKDF salt, not the hex string', async () => {
    const hexAsSalt = new TextEncoder().encode(SESSION)
    const withRaw = await deriveRoleKey(SESSION_KEY, SESSION_BYTES, 'system')
    const { hkdfSha256 } = await import('./primitives.ts')
    const withHex = await hkdfSha256(
      SESSION_KEY,
      hexAsSalt,
      new TextEncoder().encode('cw/v1/role/system'),
      32,
    )
    expect(toHex(withRaw)).not.toBe(toHex(withHex))
  })

  it('binds the tag to the chain head', async () => {
    const k = await deriveRoleKey(SESSION_KEY, SESSION_BYTES, 'system')
    const h1 = await chainStep(ZERO32, await leafHash(env({ role: 'system', tool: null })))
    const h2 = await chainStep(ZERO32, await leafHash(env({ role: 'system', tool: null, body: 'x' })))
    expect(toHex(await sealTag(k, 'system', h1))).not.toBe(toHex(await sealTag(k, 'system', h2)))
  })
})

describe('tool attestation', () => {
  const sk = fromHex(SEEDS.toolTicketDb)

  it('verifies under the matching public key', async () => {
    const pk = await ed25519PublicKey(sk)
    const leaf = await leafHash(env())
    const sig = await attest(sk, SESSION, 0, leaf)
    expect(await verifyAttestation(pk, SESSION, 0, leaf, sig)).toBe(true)
  })

  it('binds the session — the same signature fails in another session', async () => {
    const pk = await ed25519PublicKey(sk)
    const leaf = await leafHash(env())
    const sig = await attest(sk, SESSION, 0, leaf)
    expect(await verifyAttestation(pk, SEEDS.priorSession, 0, leaf, sig)).toBe(false)
  })

  it('binds the sequence number', async () => {
    const pk = await ed25519PublicKey(sk)
    const leaf = await leafHash(env())
    const sig = await attest(sk, SESSION, 0, leaf)
    expect(await verifyAttestation(pk, SESSION, 1, leaf, sig)).toBe(false)
  })

  it('fails under a different tool key', async () => {
    const other = await ed25519PublicKey(fromHex(SEEDS.toolWebFetch))
    const leaf = await leafHash(env())
    const sig = await attest(sk, SESSION, 0, leaf)
    expect(await verifyAttestation(other, SESSION, 0, leaf, sig)).toBe(false)
  })

  it('returns false rather than throwing on a malformed signature', async () => {
    const pk = await ed25519PublicKey(sk)
    expect(await verifyAttestation(pk, SESSION, 0, await leafHash(env()), new Uint8Array(64))).toBe(
      false,
    )
  })
})
