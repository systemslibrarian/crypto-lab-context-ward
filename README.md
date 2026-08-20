# Context Ward

**Context injection + cryptographic context provenance.**

Context Ward uses cryptographic envelopes to explore which context-manipulation
failures can be detected structurally. It does not claim cryptography solves
prompt injection.

**Live demo:** <https://systemslibrarian.github.io/crypto-lab-context-ward/>

---

## What It Is

An agent's context window is a pile of text from wildly different sources — the
operator's instructions, tool output, runtime error strings, retrieved web
pages, notes the agent saved to itself last turn — flattened into one stream
with nothing marking where each piece came from.

This exhibit seals every segment of that stream into an authenticated structure
and then lets you attack it:

* a **SHA-256 hash chain** binding each segment to its position and history,
* a **role-separated HMAC-SHA-256 seal** derived per role through
  **HKDF-SHA-256**, so a segment cannot be relabelled after the fact,
* an **Ed25519 attestation** from each tool over the content it emitted, against
  a public key the agent pinned in advance.

All of it is real. SHA-256, HMAC and HKDF come from WebCrypto; Ed25519 comes
from a vendored, hash-pinned copy of `@noble/ed25519`. Nothing is hand-rolled
and nothing is simulated.

The exhibit exists to separate three questions that get conflated constantly:

| question | answered by | verdict |
| --- | --- | --- |
| Was this context altered? | hash chain, HMAC seal | **cryptography answers this** |
| Who supplied it? | Ed25519 tool attestation | **cryptography answers this** |
| Should the model obey it? | nothing here | **cryptography cannot answer this** |

**The agent is a deterministic scripted mock.** There is no model, no API key
field, and no network call — the page ships with `connect-src 'none'` in its
CSP, so the browser itself forbids one. The mock implements one stated trust
policy: content in an authoritative-role segment is treated as instruction.
Watching it comply is not a measurement of any real model's behaviour, and the
page says so persistently rather than in a footnote.

**Not production crypto — a teaching demo.** The session key and every tool key
are fixed constants committed to this public repository. They protect nothing.

## Exhibits

The demo runs as eight acts. Acts 2, 3, 4, 8a and 8b ship **fully green**: the
cryptography does not go red merely because the content is hostile, and
pretending otherwise would be the central dishonesty this exhibit is built to
avoid.

1. **Baseline** — a clean turn. Every check passes and nothing hostile happened.
2. **Injection via tool output** — a ticket contains instructions aimed at the
   agent. `ticket_db` returns it faithfully. `SOURCE: TOOL_RESULT`, all checks
   green, agent compromised. Tamper controls: relabel the role, edit the body
   after sealing — both go red.
3. **Injection via runtime result** — the payload rides in on a Python
   traceback. `SOURCE: RUNTIME`, the channel nobody sanitises.
4. **Injection via persisted state** — a scratchpad note restored across a turn
   boundary, re-read as the agent's own conclusion. `SOURCE: STATE`.
5. **Splice and replay** — **this is what the cryptography genuinely prevents.**
   A validly signed `tool_result` from an earlier session, spliced into this
   one, fails on `SESSION_MISMATCH` and `CHAIN_BREAK`. Its signature is real; it
   attests to a position in a different transcript.
6. **Provenance and integrity mechanisms** — what each primitive asserts, and
   a **compromised-host** control that derives `K_system` from `K_session` and
   mints a valid `system` tag. Every seal verifies. The one thing the attacker
   cannot do is re-sign the tool attestation.
7. **Chain and session binding** — reorder, drop, corrupt the `prev` link, claim
   protocol v2. Each produces its own named failure, never a generic "invalid".
8. **What the crypto does not buy you** — the climax, and reachable straight
   from the demo path.
   * **8a — honest tool, hostile payload.** `web_fetch` retrieves a poisoned
     page and signs exactly what it retrieved. The common case, and the one that
     generalises.
   * **8b — malicious or compromised tool.** The pinned key is doing its job
     perfectly; the thing holding it is hostile.

   Both land an all-green verification panel beside a compromised agent. The
   verdict badge reads **VERIFIED — AND COMPROMISED** in alarm colouring, not
   green, because a forged-but-accepted result is not a success.

Two depths throughout: **Demo** for the guided acts, **Full lab** for the
byte-level envelope inspector, the `enc()` breakdown showing the exact bytes
that get hashed, and the raw sealed transcript.

## When to Use It

Use this construction when you need to answer **integrity and provenance**
questions about an agent's context:

* proving a transcript was not edited after the fact, for audit or incident
  review;
* proving which tool produced a given piece of context;
* preventing content from one session being replayed into another;
* preventing a `tool_result` from being promoted to `system` in storage.

**Do NOT use it as a prompt-injection defence.** It is not one. Every act from
2 onward except 5 demonstrates content passing every check and compromising the
agent anyway. If you deploy authenticated context and conclude injection is
handled, you have made things worse by adding confidence without adding safety.

Also do not use it where you need **confidentiality** — envelopes are
authenticated, not encrypted — or where the **host itself** is in your threat
model. Role separation assumes a trusted host, and Act 6 shows what happens when
that assumption fails.

## What Can Go Wrong

Failures the exhibit names specifically, each with its own tamper control:

| failure | means |
| --- | --- |
| `V_REJECTED` | unsupported protocol version, refused before any cryptography runs |
| `MALFORMED` | structurally invalid envelope |
| `SESSION_MISMATCH` | a segment from another conversation |
| `SEQ_GAP` | something dropped, duplicated or reordered |
| `CHAIN_BREAK` | the `prev` link disagrees with the recomputed `H_(n-1)` |
| `ROLE_MISMATCH` | sealed as one role, presented as another |
| `BAD_TAG` | the seal no longer covers this content |
| `BAD_SIGNATURE` | the tool attestation does not verify |
| `UNPINNED_TOOL` | signed by a key the agent never pinned |

And the failures it **cannot** name, because there is nothing structurally wrong
with them: hostile content in a correctly signed segment, a compromised host
minting its own seals, and a tool whose key is genuine and whose intent is not.

Implementation traps this repo hit and fixed, documented rather than quietly
patched:

* **`ROLE_MISMATCH` was unreachable.** `role` is covered by `leaf_n`, so
  relabelling moves the chain head as well as the seal key — probing the stored
  tag against the *current* head under other roles can never match. Naming a
  relabel requires recomputing the counterfactual leaf and chain step per
  candidate role. See `docs/MATH.md` §7.6 and `CLAIMS.yaml` `SEC-4`.
* **The HKDF salt is the raw 32 session bytes, not the hex string.** Getting this
  wrong leaves every leaf and chain hash correct while every tag differs.
* **Two CSS specificity bugs** caught by the accessibility gate: a link that was
  distinguishable by colour alone, and a pressed tamper button rendering salmon
  text on a gold fill at 1.9:1.

## Real-World Usage

The provenance-and-integrity layer here is close to the *authenticated context*
primitive in **arXiv:2602.10481**, which formalises tamper-evident hash chains
over dynamic LLM inputs. That paper reports 100% detection across six attack
categories — for its **full layered system**, semantic validation included, not
for the hash chain alone. This exhibit implements only the chain, and Act 8 is a
demonstration of why the paper's other defences exist.

The attack surface is the one surveyed empirically in **arXiv:2506.02040** for
the MCP ecosystem: tool poisoning, puppet attacks, rug pulls, and exploitation
via malicious external resources. That fourth category is Act 8a exactly.

Full citations, each verified against its arXiv abstract page and cited for what
it actually supports, are in `docs/PRIOR-ART.md`.

## How to Run Locally

```sh
npm install
npm run dev            # http://localhost:5173/crypto-lab-context-ward/
```

To run the independent verifier over the committed fixtures:

```sh
python3 -m pip install -r verification/requirements.txt
python3 verification/verify.py
```

## Related Demos

Other Crypto Lab exhibits in the ATTACKS category, and the hash/signature
primitives this one composes, are indexed at
<https://crypto-lab.systemslibrarian.dev/>.

## Build & Verify

```sh
npm test               # vendor integrity + claims check + 68 unit tests
npm run build          # tsc --noEmit && vite build
npm run test:a11y      # 22 Playwright specs: 10 accessibility, 12 claims
npm run verify:py      # 64 independent checks over 28 committed fixtures
npm run check:fixtures # regeneration must be a no-op on a clean tree
```

**68 unit tests** cover the encoding rules (including astral-plane characters and
rejected unpaired surrogates), leaf and chain construction, role separation
across all 36 ordered role pairs, session and sequence binding of Ed25519
attestations, and — for every one of the 17 tamper controls — that the verifier
produces the specific failure that control advertises.

**Test vectors** live in `fixtures/vectors/`. `encoding.json` pins the
cross-implementation edge cases: non-ASCII, astral-plane, composed versus
decomposed forms that must **not** be normalised together, and four unpaired
surrogates that must be rejected rather than silently replaced with U+FFFD.
`protocol.json` publishes every intermediate value — leaf, chain, per-role HKDF
keys, per-role tags, attestation — so a second implementation can localise a
mismatch instead of only observing that the final tag differs.

**`verification/verify.py` is a second implementation**, written from the prose
spec in `docs/MATH.md`. It imports nothing from `src/`, recomputes every value
rather than trusting any stored one, and shares no code path with the lab. It
was mutation-tested: salting HKDF with the hex string fails 31 checks,
normalising strings collapses the two normalisation vectors, dropping the
surrogate rejection fails all four reject-vectors, and disabling the version
gate changes the reported failure codes.

The TypeScript side was mutation-tested too. The sharpest result: dropping
`role` from `leaf_n` in `src/envelope.ts` failed one unit test **and 36 checks
in `verify.py`** — a change made only in the browser implementation produced an
immediate, loud disagreement with a verifier that had not changed. Both tables
are in `verification/HARNESS.md`.

**`verification/CLAIMS.yaml`** records 20 claims across five sections, each
anchored to a verbatim snippet of the code it describes. `npm run check:claims`
fails the build if an anchor drifts. Among them are two the exhibit would be
dishonest without:

* **`NEG-1`** — *authenticated context does not prevent semantic injection*,
  evidenced by six fixtures on which `verify.py` returns all-green while the
  scripted agent is compromised. `verify.py` prints them by name on every run
  **and fails if none exist**: the limitation is a verified claim, not a caveat.
* **`THREAT-1`** — *role separation assumes a trusted host*, evidenced by a
  fixture the compromised-host control produces that verifies completely clean.

**Accessibility is gated in CI.** WCAG 2.1 A/AA via `@axe-core/playwright`
against the production build, blocking the deploy. The gate emulates
reduced-motion before navigation rather than injecting `animation:none`, drives
the real controls instead of force-revealing hidden ones, runs the WCAG tag set
and the extra rules as separate analyses (chained, the second silently replaces
the first), asserts axe's `incomplete` bucket alongside `violations`, and
computes text and non-text contrast arithmetically so a colour axe declined to
judge is still judged.

**Documentation:** `docs/MATH.md` (the specification, including why the encoding
is length-prefixed concatenation rather than JSON canonicalisation),
`docs/THREAT-MODEL.md` (what is in scope and what is emphatically not), and
`docs/PRIOR-ART.md`.

## Performance

Everything runs in the browser and finishes in well under a frame. The heaviest
operation is Ed25519 keygen and signing for three mock tools at startup, a few
milliseconds in total; verification of a complete transcript is a handful of
SHA-256 and HMAC calls plus one signature check per signed segment. The
production bundle is roughly 46 kB of JavaScript and 12 kB of CSS before gzip.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
