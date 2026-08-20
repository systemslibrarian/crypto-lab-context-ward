import { describe, expect, it } from 'vitest'
import { buildActs, type Act } from './index.ts'
import { verifyTranscript, type FailureCode } from '../verify.ts'
import { runAgent } from '../agent-mock.ts'

const acts = await buildActs()
const byId = new Map(acts.map((a) => [a.id, a]))
function act(id: string): Act {
  const a = byId.get(id)
  if (!a) throw new Error(`no act ${id}`)
  return a
}

describe('every act builds and verifies to its stated verdict', () => {
  it.each(acts.map((a) => [a.label, a] as const))('act %s', async (_label, a) => {
    const t = await a.build()
    const r = await verifyTranscript(t)
    if (a.verdict === 'caught') {
      expect(r.ok).toBe(false)
      expect(r.findings.length).toBeGreaterThan(0)
    } else {
      // 'clean' and 'green-but-fooled' must BOTH be fully green. That is the
      // whole point of the corrected teaching flow: the crypto does not go red
      // just because the content is hostile.
      expect(r.findings, `act ${a.label} findings`).toEqual([])
      expect(r.ok).toBe(true)
    }
  })
})

describe('the corrected teaching flow', () => {
  const green = ['act2', 'act3', 'act4', 'act8a', 'act8b']

  it.each(green)('%s is cryptographically GREEN and the agent is still compromised', async (id) => {
    const a = act(id)
    const t = await a.build()
    const r = await verifyTranscript(t)
    expect(r.ok, `${id} must verify clean`).toBe(true)

    const run = runAgent(t, a.task)
    expect(run.compromised, `${id} must compromise the scripted agent`).toBe(true)
    expect(run.actionsTaken.length).toBeGreaterThan(0)
  })

  it('act 1 is green AND uncompromised — the baseline', async () => {
    const a = act('act1')
    const t = await a.build()
    expect((await verifyTranscript(t)).ok).toBe(true)
    expect(runAgent(t, a.task).compromised).toBe(false)
  })

  it('act 5 is the one the crypto genuinely prevents', async () => {
    const a = act('act5')
    const r = await verifyTranscript(await a.build())
    const codes = new Set(r.findings.map((f) => f.code))
    expect(codes.has('SESSION_MISMATCH'), 'replay must fail on session binding').toBe(true)
    expect(codes.has('CHAIN_BREAK'), 'replay must also break the chain').toBe(true)
  })

  it('the spliced act 5 segment carries a genuine signature — it fails on BINDING, not forgery', async () => {
    const t = await act('act5').build()
    const spliced = t.segments[2]
    expect(spliced?.sig, 'the spliced segment is signed').toBeTruthy()
    // Its signature is real; it simply covers the OTHER session's identifier.
    const { verifyAttestation } = await import('../attest.ts')
    const { fromHex } = await import('../bytes.ts')
    const { leafHash } = await import('../envelope.ts')
    const { SEEDS } = await import('./kit.ts')
    const pk = fromHex(t.pinned_tool_keys['ticket_db'] as string)
    const leaf = await leafHash(spliced!.envelope)
    expect(await verifyAttestation(pk, SEEDS.priorSession, 2, leaf, fromHex(spliced!.sig!))).toBe(true)
    expect(await verifyAttestation(pk, t.session, 2, leaf, fromHex(spliced!.sig!))).toBe(false)
  })
})

describe('every tamper control produces the failure it advertises', () => {
  const cases = acts.flatMap((a) => a.tampers.map((c) => [a.label, c.label, a, c] as const))

  it.each(cases)('act %s — %s', async (_al, _cl, a, control) => {
    const clean = await a.build()
    const tampered = await control.apply(clean)
    const r = await verifyTranscript(tampered)

    if (control.expect === null) {
      // The compromised-host control. Advertised as producing NO failure, and
      // this assertion is what keeps that claim honest.
      expect(r.findings, 'this control must stay fully green').toEqual([])
      expect(r.ok).toBe(true)
      return
    }
    const codes = r.findings.map((f) => f.code)
    expect(codes, `expected ${control.expect}, got ${codes.join(',') || 'none'}`).toContain(
      control.expect as FailureCode,
    )
  })
})

describe('the compromised-host control', () => {
  it('mints a valid system seal AND cannot re-sign the tool attestation', async () => {
    const a = act('act6')
    const control = a.tampers.find((c) => c.id === 'compromised-host')!
    const clean = await a.build()
    const forged = await control.apply(clean)
    const r = await verifyTranscript(forged)

    expect(r.ok, 'every host seal verifies').toBe(true)
    const seg = forged.segments[2]!
    expect(seg.envelope.role).toBe('system')
    // The tool attestation is gone rather than forged: the attacker holds
    // K_session, not the tool's Ed25519 secret key.
    expect(seg.sig).toBeNull()
    expect(clean.segments[2]!.sig).toBeTruthy()
  })

  it('changes what the agent does — the forged system segment is obeyed', async () => {
    const a = act('act6')
    const control = a.tampers.find((c) => c.id === 'compromised-host')!
    const clean = await a.build()
    expect(runAgent(clean, a.task).compromised).toBe(false)
    expect(runAgent(await control.apply(clean), a.task).compromised).toBe(true)
  })
})

describe('the agent mock is independent of the verifier', () => {
  it('behaves identically on a clean and a tampered transcript', async () => {
    const a = act('act2')
    const clean = await a.build()
    const tampered = await a.tampers[0]!.apply(clean)
    expect((await verifyTranscript(clean)).ok).toBe(true)
    expect((await verifyTranscript(tampered)).ok).toBe(false)
    // Same directives followed either way: obedience and integrity are
    // unrelated questions, and the mock never consults the verifier.
    expect(runAgent(tampered, a.task).actionsTaken).toEqual(runAgent(clean, a.task).actionsTaken)
  })

  it('ignores directives in a role its policy does not treat as authoritative', async () => {
    const { Host } = await import('../host.ts')
    const { SEEDS } = await import('./kit.ts')
    const h = Host.fromHexSeeds(SEEDS.session, SEEDS.sessionKey)
    await h.append({ role: 'user', body: 'hello\n>> ACTION: do the bad thing' })
    expect(runAgent(h.transcript(), 'x').compromised).toBe(false)
  })
})
