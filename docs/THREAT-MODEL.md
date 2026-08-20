# Threat model

The exhibit separates three questions that visitors routinely conflate:

| question | answered by | in scope? |
| --- | --- | --- |
| Was this context altered? | hash chain, HMAC seal | **yes** |
| Who supplied it? | Ed25519 tool attestation | **yes** |
| Should the model obey it? | nothing here | **no** |

Everything below follows from that split.

---

## Assumptions

1. **The host is trusted.** It holds `K_session`, derives every `K_role`, and
   seals every segment. The seal layer's guarantees are guarantees *about a
   transcript kept by an honest host*, not guarantees against the host.
2. **Pinned tool public keys are correct and were obtained out of band.** The
   exhibit does not model key distribution.
3. **Tool secret keys are held only by their tools** — except where an act
   explicitly says otherwise (Act 8b).
4. **The primitives are secure.** SHA-256 is collision- and
   preimage-resistant, HMAC-SHA-256 is a secure MAC, HKDF-SHA-256 is a secure
   KDF, and Ed25519 is EUF-CMA secure.
5. **The verifier runs somewhere the attacker does not control.** A verifier the
   attacker owns reports whatever they want.

---

## In scope

### Integrity of context
Any change to `v`, `session`, `seq`, `role`, `tool` or `body` after sealing is
detected. Every field the inspector displays is covered by `leaf_n`, or rejected
before verification begins (`v`). There are no displayed-but-unauthenticated
fields.

### Provenance
A segment carrying a valid Ed25519 attestation was emitted by the holder of that
tool's pinned key. A segment without one carries no such claim, and the panel
says so rather than leaving the absence to be inferred.

### Ordering and completeness
`seq` is covered by the leaf and the chain binds each segment to its
predecessor. Reordering, dropping and duplicating segments are all detected and
individually named.

### Replay and cross-session splicing
Tool signatures cover `session` and `seq`. A validly signed segment from another
session fails both on `SESSION_MISMATCH` and on `CHAIN_BREAK`. **This is the
attack the cryptography genuinely prevents**, and it is worth being precise that
it is a *binding* problem — binding problems are solvable, which is why this one
is solved.

### Role attribution under a trusted host
`K_role` is derived per role and `role` is bound inside the HMAC message as
well. A `tool_result` cannot be promoted to `system` after sealing. Relabelling
is detected and named as `ROLE_MISMATCH` rather than reported as a generic
failure.

---

## Out of scope

### Semantic safety — the central one
The protocol says nothing about whether content should be acted upon. Acts 2, 3,
4, 8a and 8b all pass **every** cryptographic check while the scripted agent is
fully compromised. `verify.py` prints the list of such fixtures on every run.

Adding more cryptography does not shrink this gap. Authenticity is a claim about
*origin and integrity*; safety is a claim about *meaning*. They are different
kinds of statement, and no signature scheme converts one into the other.

### Model compliance
Whether a model obeys, ignores or reports an injected instruction is a property
of the model and its surrounding policy. The agent here is a deterministic mock
implementing one stated policy, chosen because it is a policy real systems
commonly adopt. **Nothing in this exhibit measures any real model's behaviour.**

### A compromised or malicious host
Whoever holds `K_session` can derive `K_system` and mint valid tags for content
they wrote. Act 6's compromised-host control does exactly this and produces a
fully green panel.

The one thing such an attacker cannot do is forge a **tool attestation** — they
do not hold the tool's Ed25519 secret key. In the exhibit's control, downstream
signatures are therefore dropped rather than forged, and their absence is the
only residue. Ed25519 is where a real trust boundary is crossed; the HMAC layer
is bookkeeping by comparison, and useful only to the extent the bookkeeper is
honest.

### A compromised or malicious tool
Pinning answers "is this the key I expected?" It never answers "is the thing
holding it trustworthy?" A stolen key, a tool that was always hostile, and a
tool that turned hostile after being approved are all indistinguishable from an
honest tool at the verification layer. This is Act 8b.

### An honest tool relaying hostile content
The common case, and the one that generalises: most tools spend their lives
faithfully relaying content somebody else wrote. A web fetcher retrieving a
poisoned page signs the poisoned page, correctly. This is Act 8a.

### Confidentiality
Nothing here is encrypted. Envelopes are authenticated, not private. The fixtures
publish `K_session` deliberately so an independent verifier can recompute tags.

### Availability, side channels, key distribution, key rotation
Not modelled. In particular the exhibit's `K_session` and tool keys are fixed
test constants committed to a public repository; they protect nothing.

---

## Summary

The construction does real work against **tampering, reordering, replay and role
substitution, under a trusted host**. It does no work at all against **hostile
content that arrived through a legitimate channel**, and the exhibit is built to
make that boundary impossible to miss rather than easy to overlook.
