/**
 * The host seal -- a role-separated HMAC over the chain head.
 *
 *   K_role = HKDF-SHA256(ikm = K_session, salt = session_bytes,
 *                        info = "cw/v1/role/" || role, L = 32)
 *   tag_n  = HMAC-SHA256(K_role, enc("cw/v1/seal") || enc(role) || H_n)
 *
 * Note the salt is the RAW 32 session bytes, not the 64-character hex string
 * that `enc(session)` covers elsewhere. This is the single place the two
 * representations diverge and it is the most likely source of a
 * cross-implementation mismatch, so it is called out in `docs/MATH.md` and
 * pinned by a fixture.
 *
 * What this establishes: the host asserts that this segment, with this role,
 * sits at this position in this transcript. What it does NOT establish: that
 * the host is honest. Anyone holding `K_session` can derive every `K_role` and
 * mint any tag they like -- which is Act 6's compromised-host control, and the
 * reason Ed25519 attestation exists as a separate layer.
 */
import { cat, enc, bytesEqual } from './bytes.ts'
import type { Role } from './envelope.ts'
import { hkdfSha256, hmacSha256 } from './primitives.ts'

const ROLE_INFO_PREFIX = 'cw/v1/role/'
const SEAL_LABEL = 'cw/v1/seal'

/** `K_role = HKDF-SHA256(K_session, session_bytes, "cw/v1/role/"||role, 32)`. */
export async function deriveRoleKey(
  sessionKey: Uint8Array,
  sessionBytes: Uint8Array,
  role: Role,
): Promise<Uint8Array> {
  // info is the label bytes directly, NOT enc()-wrapped: HKDF already carries
  // its own length discipline and the role set is a fixed, prefix-free vocabulary.
  return hkdfSha256(sessionKey, sessionBytes, new TextEncoder().encode(ROLE_INFO_PREFIX + role), 32)
}

/** `tag_n = HMAC-SHA256(K_role, enc("cw/v1/seal") || enc(role) || H_n)`. */
export async function sealTag(roleKey: Uint8Array, role: Role, chainHash: Uint8Array) {
  return hmacSha256(roleKey, cat(enc(SEAL_LABEL), enc(role), chainHash))
}

export async function seal(
  sessionKey: Uint8Array,
  sessionBytes: Uint8Array,
  role: Role,
  chainHash: Uint8Array,
): Promise<Uint8Array> {
  return sealTag(await deriveRoleKey(sessionKey, sessionBytes, role), role, chainHash)
}

export async function verifySeal(
  sessionKey: Uint8Array,
  sessionBytes: Uint8Array,
  role: Role,
  chainHash: Uint8Array,
  tag: Uint8Array,
): Promise<boolean> {
  return bytesEqual(await seal(sessionKey, sessionBytes, role, chainHash), tag)
}
