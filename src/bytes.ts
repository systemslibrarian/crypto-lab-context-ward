/**
 * Encoding rules for the Context Ward wire format.
 *
 * These rules are binding on BOTH implementations -- this file and
 * `verification/verify.py`. They are specified in prose in `docs/MATH.md`;
 * verify.py is written from that prose and shares no code path with this file.
 *
 * The core rule is length-prefixed concatenation, NOT JSON canonicalisation:
 *
 *     enc(s) = uint32be(byte_len(utf8(s))) || utf8(s)
 *
 * Strings are sequences of Unicode scalar values. No Unicode normalisation is
 * performed. Unpaired UTF-16 surrogates are rejected rather than substituted.
 */

/** Raised when a value cannot be encoded under the rules above. */
export class EncodingError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'EncodingError'
  }
}

/**
 * Reject any string containing an unpaired UTF-16 surrogate.
 *
 * This check exists because `TextEncoder` does NOT fail on lone surrogates --
 * it silently substitutes U+FFFD. That substitution is exactly the kind of
 * quiet input-mangling that lets two implementations disagree about what they
 * hashed while both believe they succeeded, so the protocol rejects instead.
 */
export function assertNoLoneSurrogates(s: string): void {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c >= 0xd800 && c <= 0xdbff) {
      // High surrogate: the next unit must be a low surrogate.
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : NaN
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new EncodingError(
          `unpaired high surrogate U+${c.toString(16).toUpperCase()} at UTF-16 index ${i}`,
        )
      }
      i++ // consume the low surrogate
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      throw new EncodingError(
        `unpaired low surrogate U+${c.toString(16).toUpperCase()} at UTF-16 index ${i}`,
      )
    }
  }
}

const TE = new TextEncoder()

/** Strict UTF-8 encoding. Throws on unpaired surrogates rather than substituting. */
export function utf8(s: string): Uint8Array {
  assertNoLoneSurrogates(s)
  return TE.encode(s)
}

/** Big-endian uint32. Throws outside `[0, 2^32)`. */
export function u32be(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffff_ffff) {
    throw new EncodingError(`value out of uint32 range: ${n}`)
  }
  const out = new Uint8Array(4)
  new DataView(out.buffer).setUint32(0, n, false)
  return out
}

/** `enc(s) = uint32be(byte_len(utf8(s))) || utf8(s)`. */
export function enc(s: string): Uint8Array {
  const body = utf8(s)
  return cat(u32be(body.length), body)
}

/** Concatenate byte arrays. */
export function cat(...parts: Uint8Array[]): Uint8Array {
  let total = 0
  for (const p of parts) total += p.length
  const out = new Uint8Array(total)
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.length
  }
  return out
}

/** Lowercase hex. */
export function toHex(b: Uint8Array): string {
  let s = ''
  for (const byte of b) s += byte.toString(16).padStart(2, '0')
  return s
}

/** Parse lowercase hex. Strict: rejects odd length, uppercase, and non-hex bytes. */
export function fromHex(h: string): Uint8Array {
  if (h.length % 2 !== 0) throw new EncodingError(`hex string has odd length ${h.length}`)
  if (!/^[0-9a-f]*$/.test(h)) throw new EncodingError('hex string must be lowercase [0-9a-f]')
  const out = new Uint8Array(h.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16)
  return out
}

/** Constant-time-ish equality. Not a security boundary here, but avoids early exit. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number)
  return diff === 0
}

/** 32 zero bytes -- the `H_(-1)` sentinel. */
export const ZERO32 = new Uint8Array(32)

/** 64 zero characters -- the `prev` sentinel displayed at `seq === 0`. */
export const ZERO_PREV = '0'.repeat(64)
