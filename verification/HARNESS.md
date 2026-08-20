# Verification harness

## What this directory is for

`verify.py` is a **second implementation** of the protocol in `docs/MATH.md`. It
exists so that the exhibit's claims rest on two independent derivations rather
than on one piece of code agreeing with itself.

The core rule: **the verifier must not share a code path with the lab.**

* No import from `src/`, direct or transitive.
* No transpiled, bundled or generated artefact of the TypeScript is read.
* No value stored in a fixture is used as an *input* to a check. Leaves, chain
  hashes, role keys and tags are recomputed from the spec; stored values are
  only ever compared against the recomputation.
* The expected outcomes recorded in `fixtures/MANIFEST.json` are compared
  against outcomes `verify.py` derives independently.

A test that re-derives a value the same way the source does will happily agree
with a bug. Two implementations written from a prose spec can still both be
wrong, but they cannot be wrong *in the same way by construction*, which is the
failure mode this arrangement removes.

## Interface contract

```
python3 verification/verify.py [FIXTURES_DIR] [-v|--verbose]
```

| | |
| --- | --- |
| `FIXTURES_DIR` | defaults to `./fixtures`, resolved from the working directory |
| exit `0` | every check passed |
| exit `1` | at least one check failed; failures are printed as `FAIL <name>: <detail>` |
| exit `2` | the harness could not run (missing manifest, unsupported `protocol_version`) |
| stdout | one line per failure, then a summary, then the NEG-1 report |
| network | none, ever |

`verify.py` reads `MANIFEST.json` and dispatches on each entry's `kind`:

* `transcript` — runs the full verification and compares the **set** of failure
  codes against `expect_codes`. A clean fixture that produces any finding fails,
  and a fixture expected to fail that verifies clean also fails.
* `vectors` — recomputes every published intermediate value.

## Local-only vector resolution

Every path in `MANIFEST.json` is resolved **relative to `FIXTURES_DIR`** and is
required to stay inside it. Vectors are never fetched, never resolved against a
URL, and never read from a location the manifest could point at outside the
tree. A fixture set is a directory you can inspect, not a name you look up.

This matters more than it sounds: a verifier that fetched its own test vectors
would be trusting the network to tell it whether it was correct.

## Running it

```sh
python3 -m pip install -r verification/requirements.txt
python3 verification/verify.py            # expects ./fixtures
python3 verification/verify.py -v         # print passing checks too
```

Dependencies are Python 3.9+ and `cryptography`. Nothing else.

## Regenerating fixtures

```sh
npm run fixtures
```

Fixtures are committed and pinned. Regeneration must be a **no-op on a clean
tree** — CI runs `npm run fixtures` and fails if anything changed, which catches
a source edit that silently moves a hash without anyone updating the fixture.

## Proving the harness has teeth

A green run is not evidence until it has been watched to fail. Each mutation
below was applied to `verify.py`, confirmed to fail, and reverted:

| mutation | expected result | observed |
| --- | --- | --- |
| HKDF salt uses the hex string instead of the raw session bytes | every seal fails | 31 checks failed, all `BAD_TAG` |
| `utf8()` applies NFC normalisation | the two normalisation vectors collide | `encoding/combining-not-normalised` and `encoding/no-normalisation` failed |
| lone-surrogate rejection removed, `errors="replace"` | all four reject-vectors encode | 4 `encoding/reject/*` failures |
| pre-cryptographic version gate disabled | `V_REJECTED` no longer reported | `tampered-act7-bump-version.json` failure codes differ |

The equivalent discipline for the TypeScript side is in the repository README
under **Build & Verify**.

## A real cross-implementation caveat

`@noble/ed25519` verifies under **ZIP-215** semantics by default; Python's
`cryptography` follows **RFC 8032**. The two differ on small-order points and
non-canonical encodings.

Every signature in `fixtures/` is honestly generated, so both libraries accept
all of them and the difference never arises here. But it is a genuine
divergence between the two implementations, not a theoretical one, and this
exhibit does not ship adversarial signature vectors that would expose it. A
production system would have to pin one semantics explicitly.

Recorded as `OQ-3` in `CLAIMS.yaml` rather than left implicit.

## What a green run does and does not mean

A green run means the two implementations agree on every fixture, and that the
fixtures include the encoding edge cases most likely to make them disagree.

It does **not** mean the transcripts are safe to act on. Six fixtures verify
completely clean while carrying content that compromises the scripted agent, and
`verify.py` prints them by name every time it runs — see the `NEG-1` block at
the end of its output. If that block ever disappears, `verify.py` fails: the
negative claim is evidenced by the harness, not merely documented near it.
