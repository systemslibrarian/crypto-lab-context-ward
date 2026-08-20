/**
 * Tool attestation -- the actual trust boundary.
 *
 *   sig_n = Ed25519.sign(sk_tool, enc("cw/v1/tool") || enc(session)
 *                        || uint32be(seq) || leaf_n)
 *
 * Two primitives, two jobs:
 *   HMAC    -- the HOST asserts transcript membership and role.
 *   Ed25519 -- an EXTERNAL TOOL asserts what that tool emitted.
 *
 * The signature covers `session` and `seq`, which is what makes a validly
 * signed segment from an earlier session unusable in a new one (Act 5).
 */
import { cat, enc, u32be } from './bytes.ts'
import { ed25519Sign, ed25519Verify } from './primitives.ts'

const TOOL_LABEL = 'cw/v1/tool'

export function attestationMessage(session: string, seq: number, leaf: Uint8Array): Uint8Array {
  return cat(enc(TOOL_LABEL), enc(session), u32be(seq), leaf)
}

export async function attest(
  toolSecretKey: Uint8Array,
  session: string,
  seq: number,
  leaf: Uint8Array,
): Promise<Uint8Array> {
  return ed25519Sign(attestationMessage(session, seq, leaf), toolSecretKey)
}

export async function verifyAttestation(
  toolPublicKey: Uint8Array,
  session: string,
  seq: number,
  leaf: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  return ed25519Verify(signature, attestationMessage(session, seq, leaf), toolPublicKey)
}
