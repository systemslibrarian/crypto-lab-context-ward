# Vendored dependency: @noble/ed25519

`index.js` and `index.d.ts` in this directory are verbatim copies of
`package/index.js` and `package/index.d.ts` from the published npm tarball. They
are vendored rather than installed so the exhibit has no runtime dependency
resolution and so the exact bytes that ship are reviewable in-tree.

The published `index.ts` is deliberately NOT the file vendored here. It does not
compile under this repository's `strict` + `noUncheckedIndexedAccess` settings,
and editing it to make it compile would break the byte-for-byte correspondence
with the tarball that this document exists to assert. The shipped `index.js` is
what upstream publishes for consumption; `index.d.ts` carries its types.

| field | value |
| --- | --- |
| package | `@noble/ed25519` |
| version | `3.1.0` |
| source | `https://registry.npmjs.org/@noble/ed25519/-/ed25519-3.1.0.tgz` |
| tarball SHA-512 (npm `dist.integrity`) | `sha512-pfcObRY3CtvwfaG9Mt5XqZdKmAQppl37tHUeuBhDUbiwJBCVY4/A4lbMvb1xKhMDx96AqAqZpMWuBX1HulhX4g==` |
| tarball SHA-256 | `94277f770e3152f15b3d573cdc1d26dc6ebe1288a81157fc155186f81f890c2f` |
| retrieved | 2026-08-20 |
| licence | MIT (`LICENSE`, copied alongside) |

## Verifying this copy

```sh
curl -sL -o ed25519-3.1.0.tgz \
  https://registry.npmjs.org/@noble/ed25519/-/ed25519-3.1.0.tgz
# expect the SHA-256 in the table above
sha256sum ed25519-3.1.0.tgz
# expect the SHA-512 in the table above, base64-encoded, as npm records it
echo "sha512-$(openssl dgst -sha512 -binary ed25519-3.1.0.tgz | base64 -w0)"
tar xzf ed25519-3.1.0.tgz
diff package/index.js   vendor/noble-ed25519/index.js     # expect no output
diff package/index.d.ts vendor/noble-ed25519/index.d.ts   # expect no output
```

Per-file digests are recorded in `SHA256SUMS`; `sha256sum -c SHA256SUMS` from
this directory checks them.

`tools/check-vendor.mjs` performs the `diff` half of that check offline against
`SHA256SUMS`, and runs as part of `npm test` and in CI before the build.

## Why this library

Ed25519 signing is the one primitive in the protocol that WebCrypto cannot be
relied on to provide across the browsers this exhibit targets. Everything else
-- SHA-256, HMAC-SHA-256, HKDF-SHA-256 -- comes from `crypto.subtle` directly.
No cryptographic primitive in this repository is hand-rolled.

Version 3.x resolves SHA-512 through `hashes.sha512Async`, which defaults to
WebCrypto, so the vendored file pulls in no further dependencies. The exhibit
uses only the async API (`getPublicKeyAsync`, `signAsync`, `verifyAsync`) for
that reason.
