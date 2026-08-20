/**
 * The hash chain.
 *
 *   H_(-1) = 32 zero bytes
 *   H_n    = SHA256( enc("cw/v1/chain") || H_(n-1) || leaf_n )
 *
 * `H_n` is the authoritative binding between a segment and everything before
 * it. The envelope's `prev` field mirrors `hex(H_(n-1))` for display; the
 * verifier recomputes `H_(n-1)` independently and requires the mirror to match.
 */
import { cat, enc, toHex, ZERO32 } from './bytes.ts'
import { leafHash, type Envelope } from './envelope.ts'
import { sha256 } from './primitives.ts'

const CHAIN_LABEL = 'cw/v1/chain'

export async function chainStep(prevHash: Uint8Array, leaf: Uint8Array): Promise<Uint8Array> {
  return sha256(cat(enc(CHAIN_LABEL), prevHash, leaf))
}

/**
 * Fold a list of envelopes into the running chain, returning `H_n` for each.
 * Performs no validation -- this is the constructor's view. The verifier's
 * view, which checks rather than assumes, lives in `verify.ts`.
 */
export async function chainHashes(envelopes: readonly Envelope[]): Promise<Uint8Array[]> {
  const out: Uint8Array[] = []
  let h: Uint8Array = ZERO32
  for (const e of envelopes) {
    h = await chainStep(h, await leafHash(e))
    out.push(h)
  }
  return out
}

export async function chainHashesHex(envelopes: readonly Envelope[]): Promise<string[]> {
  return (await chainHashes(envelopes)).map(toHex)
}
