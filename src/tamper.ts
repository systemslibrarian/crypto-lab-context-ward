/**
 * Tamper controls.
 *
 * Each control takes a sealed transcript and returns a modified COPY, so the
 * original stays available for side-by-side comparison. Every control is
 * annotated with the failure the verifier is expected to name -- and two of
 * them are annotated `null`, because they produce no failure at all. Those two
 * are the exhibit's point.
 */
import { fromHex, toHex, ZERO32, ZERO_PREV } from './bytes.ts'
import { chainStep } from './chain.ts'
import { leafHash } from './envelope.ts'
import type { Role } from './envelope.ts'
import { seal } from './seal.ts'
import type { FailureCode, SealedSegment, Transcript } from './verify.ts'

export function clone(t: Transcript): Transcript {
  return JSON.parse(JSON.stringify(t)) as Transcript
}

export interface TamperControl {
  id: string
  label: string
  /** What the verifier should name, or `null` where every check still passes. */
  expect: FailureCode | null
  /** Shown beside the result so the lesson is not left to inference. */
  lesson: string
  apply: (t: Transcript) => Promise<Transcript> | Transcript
}

/** Relabel a segment's role after it was sealed. */
export function relabelRole(t: Transcript, index: number, role: Role): Transcript {
  const c = clone(t)
  const seg = c.segments[index]
  if (seg) seg.envelope.role = role
  return c
}

/** Edit a segment's body after it was sealed. */
export function editBody(t: Transcript, index: number, body: string): Transcript {
  const c = clone(t)
  const seg = c.segments[index]
  if (seg) seg.envelope.body = body
  return c
}

/** Remove a segment, leaving a hole in the sequence. */
export function dropSegment(t: Transcript, index: number): Transcript {
  const c = clone(t)
  c.segments.splice(index, 1)
  return c
}

/** Swap two segments, leaving their `seq` values in place. */
export function reorder(t: Transcript, i: number, j: number): Transcript {
  const c = clone(t)
  const a = c.segments[i]
  const b = c.segments[j]
  if (a && b) {
    c.segments[i] = b
    c.segments[j] = a
  }
  return c
}

/** Corrupt a segment's `prev` mirror. */
export function breakChain(t: Transcript, index: number): Transcript {
  const c = clone(t)
  const seg = c.segments[index]
  if (seg) {
    const b = fromHex(seg.envelope.prev)
    b[0] = ((b[0] as number) ^ 0xff) & 0xff
    seg.envelope.prev = toHex(b)
  }
  return c
}

/** Flip a bit in a tool attestation. */
export function corruptSignature(t: Transcript, index: number): Transcript {
  const c = clone(t)
  const seg = c.segments[index]
  if (seg?.sig) {
    const b = fromHex(seg.sig)
    b[0] = ((b[0] as number) ^ 0x01) & 0xff
    seg.sig = toHex(b)
  }
  return c
}

/** Claim an unsupported protocol version. */
export function bumpVersion(t: Transcript, index: number): Transcript {
  const c = clone(t)
  const seg = c.segments[index]
  if (seg) seg.envelope.v = 2
  return c
}

/**
 * Splice a validly signed segment from a DIFFERENT session into this one.
 *
 * The segment's Ed25519 signature is genuine and still verifies as a signature
 * -- over the old session's identifier. That is the point: `sig` covers
 * `session` and `seq`, so old signed content cannot silently become new-session
 * content. Act 5.
 */
export function spliceForeignSegment(
  t: Transcript,
  foreign: SealedSegment,
  atIndex: number,
): Transcript {
  const c = clone(t)
  c.segments.splice(atIndex, 0, JSON.parse(JSON.stringify(foreign)) as SealedSegment)
  return c
}

/**
 * COMPROMISED HOST.
 *
 * Anyone holding `K_session` can derive `K_system` and mint a valid `system`
 * tag for content they wrote. This returns a transcript that passes every host
 * seal check, because role separation assumes a trusted host and this host is
 * not one.
 *
 * The tool attestation layer is untouched by this, which is the distinction
 * worth taking away: Ed25519 is where a real trust boundary is crossed.
 */
export async function forgeAsCompromisedHost(
  t: Transcript,
  index: number,
  role: Role,
  body: string,
): Promise<Transcript> {
  const c = clone(t)
  const seg = c.segments[index]
  if (!seg) return c
  seg.envelope.role = role
  seg.envelope.body = body
  seg.envelope.tool = null
  seg.sig = null
  seg.tool_key = null

  // Re-seal this segment and every segment after it: the attacker holds
  // K_session, so re-deriving the chain forward costs them nothing.
  const sessionBytes = fromHex(c.session)
  const sessionKey = fromHex(c.session_key)

  let h: Uint8Array = ZERO32
  for (let i = 0; i < c.segments.length; i++) {
    const s = c.segments[i] as SealedSegment
    s.envelope.prev = i === 0 ? ZERO_PREV : toHex(h)
    const leaf = await leafHash(s.envelope)
    h = await chainStep(h, leaf)
    s.tag = toHex(await seal(sessionKey, sessionBytes, s.envelope.role, h))
    if (i > index && s.sig) {
      // Downstream tool attestations were made over the ORIGINAL leaves. The
      // attacker cannot re-sign them, so they are dropped rather than forged --
      // which is precisely the residue a compromised host cannot clean up.
      s.sig = null
      s.tool_key = null
    }
  }
  return c
}
