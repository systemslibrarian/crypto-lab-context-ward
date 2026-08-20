/**
 * The in-lab verifier.
 *
 * Every check produces a NAMED failure rather than a bare boolean, because the
 * exhibit's whole argument is that different failures mean different things --
 * and that a green result means something much narrower than visitors expect.
 *
 * Ordering matters. `v` is rejected BEFORE any cryptography runs, so an
 * unsupported version can never reach a code path that might interpret its
 * fields. Everything else the inspector displays is covered by `leaf_n`. There
 * are no displayed-but-unauthenticated fields; see CLAIMS.yaml `INV-4`.
 */
import { bytesEqual, fromHex, toHex, ZERO32, ZERO_PREV } from './bytes.ts'
import { chainStep } from './chain.ts'
import {
  assertWellFormed,
  isRole,
  leafHash,
  PROTOCOL_VERSION,
  ROLES,
  type Envelope,
  type Role,
} from './envelope.ts'
import { seal } from './seal.ts'
import { verifyAttestation } from './attest.ts'

export type FailureCode =
  | 'V_REJECTED'
  | 'MALFORMED'
  | 'SESSION_MISMATCH'
  | 'SEQ_GAP'
  | 'CHAIN_BREAK'
  | 'ROLE_MISMATCH'
  | 'BAD_TAG'
  | 'BAD_SIGNATURE'
  | 'UNPINNED_TOOL'

/** Human-facing names, used verbatim in the UI so a failure is nameable on sight. */
export const FAILURE_NAMES: Record<FailureCode, string> = {
  V_REJECTED: 'version rejected',
  MALFORMED: 'malformed envelope',
  SESSION_MISMATCH: 'session mismatch',
  SEQ_GAP: 'seq gap',
  CHAIN_BREAK: 'chain break',
  ROLE_MISMATCH: 'role mismatch',
  BAD_TAG: 'bad tag',
  BAD_SIGNATURE: 'bad signature',
  UNPINNED_TOOL: 'unpinned tool key',
}

export interface Finding {
  code: FailureCode
  /** Index into the segment list, or -1 for transcript-level findings. */
  index: number
  seq: number | null
  detail: string
}

export interface SealedSegment {
  envelope: Envelope
  /** hex(tag_n), 32 bytes. */
  tag: string
  /** hex(sig_n), 64 bytes. Present for tool_result segments. */
  sig?: string | null
  /** Name of the tool whose pinned public key should verify `sig`. */
  tool_key?: string | null
}

export interface Transcript {
  v: number
  /** 64 lowercase hex characters; `fromHex(session)` is the HKDF salt. */
  session: string
  /** hex(K_session). Disclosed in fixtures so an independent verifier can recompute. */
  session_key: string
  /** Tool name -> hex(Ed25519 public key), pinned by the agent. */
  pinned_tool_keys: Record<string, string>
  segments: SealedSegment[]
}

export interface SegmentResult {
  index: number
  seq: number
  role: Role
  tool: string | null
  /** hex(leaf_n). */
  leaf: string
  /** hex(H_n) as recomputed by this verifier, independent of any stored value. */
  chain: string
  sealOk: boolean
  /** `null` when the segment carries no attestation (no tool signature expected). */
  attestationOk: boolean | null
  findings: Finding[]
}

export interface VerifyResult {
  ok: boolean
  findings: Finding[]
  segments: SegmentResult[]
  /** hex(H_n) of the final segment, or the all-zero sentinel for an empty transcript. */
  head: string
}

function f(code: FailureCode, index: number, seq: number | null, detail: string): Finding {
  return { code, index, seq, detail }
}

/**
 * Verify a sealed transcript from scratch.
 *
 * Nothing stored in the transcript is trusted as an input to a check: leaves,
 * chain hashes and tags are all recomputed, and the stored `prev` is compared
 * against the recomputation rather than used in place of it.
 */
export async function verifyTranscript(t: Transcript): Promise<VerifyResult> {
  const findings: Finding[] = []
  const segments: SegmentResult[] = []

  // --- Pre-cryptographic version gate. Runs before anything else. ---------
  if (t.v !== PROTOCOL_VERSION) {
    findings.push(
      f('V_REJECTED', -1, null, `transcript v=${String(t.v)}; this verifier accepts only v=1`),
    )
    return { ok: false, findings, segments, head: ZERO_PREV }
  }
  if (!/^[0-9a-f]{64}$/.test(t.session)) {
    findings.push(f('MALFORMED', -1, null, 'transcript session is not 64 lowercase hex characters'))
    return { ok: false, findings, segments, head: ZERO_PREV }
  }

  const sessionBytes = fromHex(t.session)
  const sessionKey = fromHex(t.session_key)

  let h: Uint8Array = ZERO32
  let expectedSeq = 0

  for (let i = 0; i < t.segments.length; i++) {
    const seg = t.segments[i] as SealedSegment
    const e = seg.envelope
    const local: Finding[] = []

    // Version gate, per segment, still before any hashing.
    if (e.v !== PROTOCOL_VERSION) {
      local.push(f('V_REJECTED', i, e.seq ?? null, `segment v=${String(e.v)}; only v=1 is accepted`))
      findings.push(...local)
      break // the chain cannot meaningfully continue past an uninterpretable segment
    }

    try {
      assertWellFormed(e)
    } catch (err) {
      local.push(f('MALFORMED', i, e.seq ?? null, (err as Error).message))
      findings.push(...local)
      break
    }

    if (e.session !== t.session) {
      local.push(
        f(
          'SESSION_MISMATCH',
          i,
          e.seq,
          `segment carries session ${e.session.slice(0, 16)}...; transcript is ${t.session.slice(0, 16)}...`,
        ),
      )
    }

    if (e.seq !== expectedSeq) {
      local.push(f('SEQ_GAP', i, e.seq, `expected seq ${expectedSeq}, found ${e.seq}`))
    }
    expectedSeq = e.seq + 1

    // `prev` is a display mirror. Recompute H_(n-1) and require the mirror to match.
    const hPrev = h
    const expectedPrev = bytesEqual(h, ZERO32) && i === 0 ? ZERO_PREV : toHex(h)
    if (e.prev !== expectedPrev) {
      local.push(
        f(
          'CHAIN_BREAK',
          i,
          e.seq,
          `prev is ${e.prev.slice(0, 16)}...; recomputed H_${i - 1} is ${expectedPrev.slice(0, 16)}...`,
        ),
      )
    }

    const leaf = await leafHash(e)
    h = await chainStep(h, leaf)

    // --- Host seal -------------------------------------------------------
    let sealOk = false
    let tagBytes: Uint8Array | null = null
    try {
      tagBytes = fromHex(seg.tag)
    } catch {
      local.push(f('MALFORMED', i, e.seq, 'tag is not lowercase hex'))
    }
    if (tagBytes) {
      sealOk = bytesEqual(await seal(sessionKey, sessionBytes, e.role, h), tagBytes)
      if (!sealOk) {
        // Distinguish a relabelled role from an unrelated bad tag.
        //
        // `role` is covered by `leaf_n`, so a relabel moves the chain head as
        // well as the seal key. Probing the tag against the CURRENT head under
        // other roles would therefore never match. To name a relabel we have to
        // ask the counterfactual properly: recompute the leaf and the chain
        // step as they would have been under each candidate role, and see
        // whether the stored tag verifies against THAT head.
        let verifiedAs: Role | null = null
        for (const r of ROLES) {
          if (r === e.role) continue
          const asRole = await chainStep(hPrev, await leafHash({ ...e, role: r }))
          if (bytesEqual(await seal(sessionKey, sessionBytes, r, asRole), tagBytes)) {
            verifiedAs = r
            break
          }
        }
        if (verifiedAs) {
          local.push(
            f(
              'ROLE_MISMATCH',
              i,
              e.seq,
              `presented as ${e.role}, but it was sealed as ${verifiedAs}`,
            ),
          )
        } else {
          local.push(
            f('BAD_TAG', i, e.seq, `seal does not cover this segment as sealed (role ${e.role})`),
          )
        }
      }
    }

    // --- Tool attestation ------------------------------------------------
    let attestationOk: boolean | null = null
    if (seg.sig != null) {
      const keyName = seg.tool_key ?? e.tool
      const pinned = keyName ? t.pinned_tool_keys[keyName] : undefined
      if (!pinned) {
        attestationOk = false
        local.push(
          f('UNPINNED_TOOL', i, e.seq, `no pinned public key for tool ${String(keyName)}`),
        )
      } else {
        try {
          attestationOk = await verifyAttestation(
            fromHex(pinned),
            e.session,
            e.seq,
            leaf,
            fromHex(seg.sig),
          )
        } catch {
          attestationOk = false
        }
        if (!attestationOk) {
          local.push(
            f('BAD_SIGNATURE', i, e.seq, `Ed25519 attestation from ${String(keyName)} does not verify`),
          )
        }
      }
    }

    segments.push({
      index: i,
      seq: e.seq,
      role: isRole(e.role) ? e.role : ('system' as Role),
      tool: e.tool,
      leaf: toHex(leaf),
      chain: toHex(h),
      sealOk,
      attestationOk,
      findings: local,
    })
    findings.push(...local)
  }

  return {
    ok: findings.length === 0,
    findings,
    segments,
    head: segments.length ? (segments[segments.length - 1] as SegmentResult).chain : ZERO_PREV,
  }
}
