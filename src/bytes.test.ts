import { describe, expect, it } from 'vitest'
import {
  assertNoLoneSurrogates,
  bytesEqual,
  cat,
  enc,
  EncodingError,
  fromHex,
  toHex,
  u32be,
  utf8,
} from './bytes.ts'

describe('enc — length-prefixed concatenation', () => {
  it('prefixes the BYTE length, not the character or UTF-16 length', () => {
    expect(toHex(enc(''))).toBe('00000000')
    expect(toHex(enc('a'))).toBe('0000000161')
    // "é" is one scalar, one JS char, but TWO UTF-8 bytes.
    expect(toHex(enc('é'))).toBe('00000002c3a9')
    // "𝄞" (U+1D11E) is one scalar, TWO UTF-16 units, FOUR UTF-8 bytes.
    expect(toHex(enc('\u{1D11E}'))).toBe('00000004f09d849e')
  })

  it('is unambiguous under concatenation — the property JSON canonicalisation lacks', () => {
    // Without a length prefix, ("ab","c") and ("a","bc") would collide.
    expect(toHex(cat(enc('ab'), enc('c')))).not.toBe(toHex(cat(enc('a'), enc('bc'))))
  })

  it('does not normalise', () => {
    // U+00E9 vs U+0065 U+0301 — canonically equivalent, deliberately NOT equal here.
    const composed = 'é'
    const decomposed = 'é'
    expect(composed.normalize('NFC')).toBe(decomposed.normalize('NFC'))
    expect(toHex(enc(composed))).not.toBe(toHex(enc(decomposed)))
  })
})

describe('surrogate handling', () => {
  it('accepts a well-formed surrogate pair', () => {
    expect(() => assertNoLoneSurrogates('\u{1F512}')).not.toThrow()
    expect(utf8('\u{1F512}').length).toBe(4)
  })

  it('rejects an unpaired HIGH surrogate rather than substituting U+FFFD', () => {
    expect(() => utf8('a\ud800b')).toThrow(EncodingError)
    // Demonstrate what the rejection is protecting against: TextEncoder is silent.
    expect(new TextEncoder().encode('a\ud800b')).toEqual(new Uint8Array([0x61, 0xef, 0xbf, 0xbd, 0x62]))
  })

  it('rejects an unpaired LOW surrogate', () => {
    expect(() => utf8('a\udc00b')).toThrow(EncodingError)
  })

  it('rejects a high surrogate at end of string', () => {
    expect(() => utf8('ab\ud83d')).toThrow(/unpaired high surrogate U\+D83D/)
  })
})

describe('u32be', () => {
  it('encodes big-endian', () => {
    expect(toHex(u32be(0))).toBe('00000000')
    expect(toHex(u32be(1))).toBe('00000001')
    expect(toHex(u32be(0xffffffff))).toBe('ffffffff')
  })
  it('rejects out-of-range values', () => {
    expect(() => u32be(-1)).toThrow(EncodingError)
    expect(() => u32be(0x1_0000_0000)).toThrow(EncodingError)
    expect(() => u32be(1.5)).toThrow(EncodingError)
  })
})

describe('hex', () => {
  it('round-trips', () => {
    const b = new Uint8Array([0x00, 0x0f, 0xff, 0xa5])
    expect(fromHex(toHex(b))).toEqual(b)
  })
  it('is strict about case and shape', () => {
    expect(() => fromHex('AB')).toThrow(EncodingError)
    expect(() => fromHex('abc')).toThrow(EncodingError)
    expect(() => fromHex('zz')).toThrow(EncodingError)
  })
})

describe('bytesEqual', () => {
  it('compares content and length', () => {
    expect(bytesEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true)
    expect(bytesEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false)
    expect(bytesEqual(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false)
  })
})
