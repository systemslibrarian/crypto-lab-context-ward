/**
 * Envelope shape and leaf hashing.
 *
 *   { v:1, session, seq, role, tool, body, prev }
 *
 *   leaf_n = SHA256( enc("cw/v1/leaf") || uint32be(v) || enc(session)
 *                    || uint32be(seq) || enc(role) || enc(tool ?? "")
 *                    || enc(body) )
 *
 * `prev` is deliberately NOT an input to `leaf_n`. It is a display mirror so the
 * inspector can draw the link between segments; the chain hash is the
 * authoritative binding. See `docs/MATH.md`.
 */
import { cat, enc, u32be, toHex, EncodingError } from './bytes.ts'
import { sha256 } from './primitives.ts'

/** The protocol version this implementation speaks. Nothing else is accepted. */
export const PROTOCOL_VERSION = 1

/**
 * Where a segment came from. The role is covered by the leaf hash AND bound
 * into the host seal's derived key, so a segment cannot be relabelled after
 * sealing without detection.
 */
export const ROLES = ['system', 'user', 'tool_result', 'runtime', 'state', 'retrieved'] as const
export type Role = (typeof ROLES)[number]

export function isRole(x: unknown): x is Role {
  return typeof x === 'string' && (ROLES as readonly string[]).includes(x)
}

export interface Envelope {
  v: number
  /** 64 lowercase hex characters. The hex string itself is what `enc()` covers. */
  session: string
  /** uint32, monotonic from 0. */
  seq: number
  role: Role
  /** Tool name for `tool_result` segments; `null` elsewhere. Encoded as `""` when absent. */
  tool: string | null
  body: string
  /** hex(H_(n-1)); 64 zero characters at seq 0. Display mirror, not a leaf input. */
  prev: string
}

const LEAF_LABEL = 'cw/v1/leaf'

/**
 * Compute `leaf_n` for an envelope.
 *
 * Note this hashes whatever `v` it is handed -- `v` is covered by the leaf so
 * that a version claim cannot be swapped silently. Rejecting `v !== 1` is a
 * separate, earlier step performed by the verifier before any cryptography
 * runs; see `verifySegment` in `verify.ts`.
 */
export async function leafHash(e: Envelope): Promise<Uint8Array> {
  return sha256(
    cat(
      enc(LEAF_LABEL),
      u32be(e.v),
      enc(e.session),
      u32be(e.seq),
      enc(e.role),
      enc(e.tool ?? ''),
      enc(e.body),
    ),
  )
}

export async function leafHashHex(e: Envelope): Promise<string> {
  return toHex(await leafHash(e))
}

/** Structural validation, performed before any hashing. */
export function assertWellFormed(e: Envelope): void {
  if (!/^[0-9a-f]{64}$/.test(e.session)) {
    throw new EncodingError('session must be 64 lowercase hex characters')
  }
  if (!Number.isInteger(e.seq) || e.seq < 0 || e.seq > 0xffff_ffff) {
    throw new EncodingError(`seq out of uint32 range: ${e.seq}`)
  }
  if (!isRole(e.role)) throw new EncodingError(`unknown role: ${String(e.role)}`)
  if (!/^[0-9a-f]{64}$/.test(e.prev)) {
    throw new EncodingError('prev must be 64 lowercase hex characters')
  }
  // Deliberately NO role/tool consistency rule. `tool` is covered by `leaf_n`
  // like every other displayed field, so a role/tool pairing that looks wrong
  // is an authenticated oddity, not a structural defect -- and treating it as
  // malformed would short-circuit the role probe in `verify.ts` that names a
  // relabelled segment for what it is.
}
