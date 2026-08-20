# The Context Ward envelope protocol, v1

This document is the specification. `verification/verify.py` was written from
this text and shares no code path with `src/`; where the two implementations
disagree, this document decides.

Throughout, `||` is byte concatenation and `SHA256` is FIPS 180-4 SHA-256.

---

## 1. String and encoding rules

These rules bind **both** implementations.

Strings are sequences of Unicode scalar values. **No Unicode normalisation is
performed.** Unpaired UTF-16 surrogates **must be rejected**. Length is the byte
length of the strict UTF-8 encoding.

```
enc(s) = uint32be(byte_len(utf8(s))) || utf8(s)
```

`uint32be(n)` is the big-endian four-byte encoding of `n`, defined for
`0 <= n < 2^32`.

### 1.1 Why length-prefixed concatenation and not JSON canonicalisation

The obvious way to hash a structured record is to serialise it canonically and
hash the bytes. Every canonicalisation scheme then has to answer a long list of
questions — key ordering, duplicate keys, number formatting, escape-sequence
choice, whitespace, whether `1.0` and `1` are the same, what to do with
non-characters — and every one of those answers is a place two implementations
can differ while both believe they are canonical. That divergence is an attack
surface, not merely an interoperability nuisance: an attacker who finds two
inputs that one implementation considers identical and another does not has
found a way to make a signature mean two different things.

Length-prefixed concatenation removes the question instead of answering it.
There is no syntax to disagree about, because there is no syntax. The encoding
is injective by construction: given `enc(a) || enc(b)`, the boundary between `a`
and `b` is recoverable from the prefix, so no two distinct field sequences share
an encoding. This is the same reasoning behind TupleHash in NIST SP 800-185 and
behind the length-prefixed transcripts in TLS 1.3.

The cost is that the encoding is not human-readable. That is an acceptable
trade for a format whose whole job is to be hashed, and the exhibit's inspector
renders the fields separately anyway.

### 1.2 Why normalisation is refused rather than applied

Normalising would make `U+00E9` and `U+0065 U+0301` hash alike. That sounds
helpful and is not: it means the bytes a tool emitted are not the bytes that
were authenticated, so the signature attests to a *transformation* of the
tool's output rather than to the output. An implementation that normalises will
pass every fixture in `fixtures/vectors/encoding.json` except the pair named
`combining-not-normalised` / `precomposed-not-normalised`, which exist to catch
exactly this.

### 1.3 Why lone surrogates are rejected rather than substituted

`TextEncoder` in JavaScript and `str.encode(errors="replace")` in Python both
turn an unpaired surrogate into `U+FFFD` without complaint. Two implementations
that substitute silently can hash different things while both report success —
and an attacker who can inject a lone surrogate controls where that divergence
happens. Rejection turns a silent disagreement into a loud one.

---

## 2. Session representation

This is the single place where two representations of the same value are both
in play, and it is the likeliest source of a cross-implementation mismatch.

```
session_bytes = 32 random bytes
session       = lowercase_hex(session_bytes)     # 64 characters
enc(session)  = enc() applied to the 64-character lowercase hex STRING
HKDF salt     = session_bytes                    # the RAW 32 bytes
```

So: everywhere `session` appears inside a hashed or signed message, it is the
**hex string**, encoded with `enc()` like any other string. The **only** place
the raw bytes are used is the HKDF salt in §5.

An implementation that salts HKDF with the hex string produces a completely
different set of role keys, and therefore a completely different set of tags,
while every leaf and chain hash still matches. `fixtures/vectors/protocol.json`
publishes the per-role keys separately from the tags so this failure localises
immediately instead of appearing only as "the final tag differs".

---

## 3. The envelope

```
{ v, session, seq, role, tool, body, prev }
```

| field | type | meaning |
| --- | --- | --- |
| `v` | uint32 | protocol version; `1` is the only accepted value |
| `session` | 64 lowercase hex chars | session identifier, per §2 |
| `seq` | uint32 | position in the transcript, monotonic from `0` |
| `role` | enum | one of `system`, `user`, `tool_result`, `runtime`, `state`, `retrieved` |
| `tool` | string or null | the tool that produced this segment, where one did |
| `body` | string | the content |
| `prev` | 64 lowercase hex chars | `hex(H_(n-1))`; 64 zero characters at `seq 0` |

There is **no nonce field**. `session` and `seq` together already make each leaf
unique within a session, and a nonce would be one more displayed field to
authenticate for no gain.

There is deliberately **no role/tool consistency rule**. A `system` segment
carrying a `tool` name is odd, but `tool` is authenticated by the leaf like
every other field, so an odd pairing is something the verifier **reports**, not
a parse error. Treating it as malformed would also short-circuit the role probe
in §7.6 before it can name a relabelled segment for what it is.

---

## 4. Leaf and chain

```
leaf_n = SHA256( enc("cw/v1/leaf") || uint32be(v) || enc(session)
                 || uint32be(seq) || enc(role) || enc(tool ?? "")
                 || enc(body) )

H_(-1) = 32 zero bytes
H_n    = SHA256( enc("cw/v1/chain") || H_(n-1) || leaf_n )
```

`enc(tool ?? "")` means a null `tool` and an empty-string `tool` hash
identically. This is intentional and harmless: nothing in the protocol
distinguishes them, and the domain separator plus the surrounding length
prefixes prevent the empty encoding from colliding with a neighbouring field.

The two labels `cw/v1/leaf` and `cw/v1/chain` are domain separators. Because
they are themselves `enc()`-wrapped, a leaf hash can never be mistaken for a
chain hash even if an attacker controls a `body` that happens to begin with the
other label's bytes.

### 4.1 `prev` is a display mirror, not a chain input

`prev` is **not** an input to `leaf_n`. The chain hash `H_n` is the
authoritative binding between a segment and its history; `prev` exists so the
inspector can draw the link between two segments without recomputing the whole
chain to do it.

The verifier therefore **recomputes `H_(n-1)` independently and requires
`prev == hex(H_(n-1))`**. It never uses the stored `prev` in place of the
recomputation. A verifier that folded `prev` into the leaf would be authenticating
the attacker's claim about history rather than history itself.

### 4.2 Version handling

`v` is covered by `leaf_n`, so a version claim cannot be swapped silently. It is
**also** rejected before any cryptographic operation runs: a verifier must
refuse `v != 1` and stop, rather than hashing an envelope whose fields it does
not know how to interpret.

This gives the invariant recorded as `INV-4` in `CLAIMS.yaml`: **every field the
inspector displays is either covered by `leaf_n` or explicitly rejected before
verification.** There are no displayed-but-unauthenticated fields.

---

## 5. The host seal

```
K_role = HKDF-SHA256(ikm  = K_session,
                     salt = session_bytes,          # RAW bytes -- see §2
                     info = "cw/v1/role/" || role,
                     L    = 32)

tag_n  = HMAC-SHA256(K_role, enc("cw/v1/seal") || enc(role) || H_n)
```

`info` is the label bytes directly, **not** `enc()`-wrapped. HKDF already
carries its own internal length discipline, and the role vocabulary is a fixed,
prefix-free set, so no role's info string is a prefix of another's.

`role` is bound twice — once through `K_role` and once inside the HMAC message.
The redundancy is deliberate: the derivation binds the *key* to the role, and
the message binds the *claim* to the role, so neither a key-substitution nor a
message-substitution attack has anywhere to go.

**Required property.** A `tool_result` tag must not verify as a `system` tag.
`src/protocol.test.ts` asserts this for the specific pair the brief names, and
also for all thirty-six ordered role pairs.

### 5.1 What the seal establishes, and what it does not

The seal is the **host** asserting: *this segment, with this role, sits at this
position in this transcript.*

It establishes nothing whatever about whether the host is honest. Anyone holding
`K_session` derives every `K_role` and mints any tag they like. Role separation
assumes a **trusted host**; it is a defence against substitution and
post-sealing tampering, not against a compromised host. This is recorded as
`THREAT-1` in `CLAIMS.yaml`, and Act 6's compromised-host control demonstrates
it producing a fully green panel.

---

## 6. Tool attestation

Each mock tool holds an Ed25519 keypair and the agent pins its public key.

```
sig_n = Ed25519.sign(sk_tool, enc("cw/v1/tool") || enc(session)
                              || uint32be(seq) || leaf_n)
```

**Two primitives, two jobs:**

| | asserts | held by | survives a compromised host? |
| --- | --- | --- | --- |
| HMAC seal | transcript membership and role | the host | no |
| Ed25519 | what this tool emitted | the tool | yes |

The signature covers `session` and `seq`. That is what makes a validly signed
segment from an earlier session unusable in a new one: the signature is genuine,
it simply attests to a position in a different transcript. Act 5 is this, and it
is the attack the cryptography genuinely prevents.

---

## 7. Verification

A verifier processes segments in order, maintaining `H` (initially 32 zero
bytes) and `expected_seq` (initially `0`). Nothing stored in the transcript is
used as an *input* to a check; stored values are only ever compared against
recomputations.

The named failures below are part of the specification, not an implementation
detail — `fixtures/MANIFEST.json` records them per fixture and both
implementations must agree on which fire.

### 7.1 `V_REJECTED`
`v != 1`, at transcript or segment level. Checked **before** any hashing.
Verification stops.

### 7.2 `MALFORMED`
`session` or `prev` is not 64 lowercase hex characters, `seq` is outside
`[0, 2^32)`, `role` is not in the enumeration, or `tag` is not lowercase hex.
Verification stops at the offending segment.

### 7.3 `SESSION_MISMATCH`
`envelope.session != transcript.session`.

### 7.4 `SEQ_GAP`
`envelope.seq != expected_seq`. Covers dropped segments, duplicated segments and
reorderings alike; the detail string names both the expected and the found value.

### 7.5 `CHAIN_BREAK`
`envelope.prev != hex(H_(n-1))`, where `H_(n-1)` is the verifier's own
recomputation. At `seq 0`, `H_(-1)` is the all-zero sentinel and `prev` must be
64 zero characters.

### 7.6 `ROLE_MISMATCH`
The tag does not verify under the presented role, **but** it does verify under
some other role `r`.

Testing this correctly is subtle. `role` is covered by `leaf_n`, so relabelling
a segment moves the chain head as well as the seal key. Probing the stored tag
against the *current* head under other roles would therefore never match, and
the finding would be unreachable. The probe must ask the counterfactual
properly: for each candidate role `r`, recompute

```
leaf'  = leaf_hash(envelope with role replaced by r)
H'     = SHA256( enc("cw/v1/chain") || H_(n-1) || leaf' )
```

and test the stored tag against `seal(K_r, r, H')`. A match names `r` as the
role the segment was actually sealed under.

### 7.7 `BAD_TAG`
The tag does not verify under the presented role and no other role explains it.
This is what a post-sealing edit to `body` produces.

### 7.8 `BAD_SIGNATURE`
A segment carries a `sig` and the Ed25519 verification against the pinned public
key fails.

### 7.9 `UNPINNED_TOOL`
A segment carries a `sig` but names a tool the agent has not pinned a key for.

---

## 8. What the protocol does not do

Stated here because it belongs in the specification, not only in the
threat model.

The construction answers two questions well:

* **Was this context altered?** — the hash chain and the seal answer this.
* **Who supplied it?** — the Ed25519 attestation answers this.

It does not answer, and cannot be extended to answer by adding more
cryptography:

* **Should the model obey it?**

A signature over hostile content is a valid signature over hostile content.
Every check in §7 can pass on a transcript that compromises the agent
completely — that is Acts 2, 3, 4, 8a and 8b, and `verify.py` prints the list of
fixtures for which it holds every time it runs. The limitation is recorded as a
**verified claim** (`NEG-1` in `CLAIMS.yaml`) rather than a caveat, because a
caveat can be skimmed past and a failing check cannot.
