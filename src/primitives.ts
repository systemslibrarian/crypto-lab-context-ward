/**
 * The only cryptographic primitives in the exhibit.
 *
 * SHA-256, HMAC-SHA-256 and HKDF-SHA-256 come from WebCrypto (`crypto.subtle`).
 * Ed25519 comes from the vendored @noble/ed25519 (see vendor/noble-ed25519/).
 * Nothing here is hand-rolled and nothing is simulated.
 */
import * as ed from '../vendor/noble-ed25519/index.js'

const subtle = globalThis.crypto.subtle

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest('SHA-256', data as BufferSource))
}

export async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const k = await subtle.importKey(
    'raw',
    key as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  return new Uint8Array(await subtle.sign('HMAC', k, data as BufferSource))
}

/** HKDF-SHA-256 (extract-and-expand), returning `length` bytes. */
export async function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  const k = await subtle.importKey('raw', ikm as BufferSource, 'HKDF', false, ['deriveBits'])
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: salt as BufferSource, info: info as BufferSource },
    k,
    length * 8,
  )
  return new Uint8Array(bits)
}

export async function ed25519PublicKey(secretKey: Uint8Array): Promise<Uint8Array> {
  return ed.getPublicKeyAsync(secretKey)
}

export async function ed25519Sign(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
  return ed.signAsync(message, secretKey)
}

export async function ed25519Verify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): Promise<boolean> {
  try {
    return await ed.verifyAsync(signature, message, publicKey)
  } catch {
    // Malformed points/scalars throw rather than returning false. For a
    // verifier, "it did not verify" is the correct reading of both.
    return false
  }
}

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n)
  globalThis.crypto.getRandomValues(b)
  return b
}
