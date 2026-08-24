# Prior art

Every paper below was checked against its arXiv abstract page on **2026-08-20**,
and each is cited for what it actually supports. Where a paper's title has
changed between versions, the current title is given and the change noted —
citing a superseded title is how a reference becomes unverifiable.

The **Field incidents** section near the end is held to a different and weaker
standard, and says so: those are vendor disclosure writeups, not peer-reviewed
work. They are segregated rather than interleaved so that nothing there inherits
the standard of the entries above it.

There is deliberately **no coined attack name** here. The framing is *context
injection + cryptographic context provenance*, which describes what the exhibit
shows using vocabulary that already exists.

---

## arXiv:2405.20234 — Hidden in Plain Sight: Exploring Chat History Tampering in Interactive Language Models

<https://arxiv.org/abs/2405.20234> · v3, last revised 6 September 2024

**Cited at Act 4 (injection via persisted state).**

Studies manipulation of the *recorded conversation history* of an interactive
LLM rather than the live prompt — content that entered once and is re-read
later as though it were the system's own record. Act 4 is that shape: a
scratchpad note restored across a turn boundary, which the agent then treats as
its own prior conclusion.

> **Title note.** Earlier versions, and some indexes still, carry the title
> *"Context Injection Attacks on Large Language Models."* The v3 title is the one
> above. Anyone citing the older title is citing the same work.

---

## arXiv:2506.02040 — Beyond the Protocol: Unveiling Attack Vectors in the Model Context Protocol (MCP) Ecosystem

<https://arxiv.org/abs/2506.02040> · v4, last revised 14 September 2025

**Cited at Acts 8a and 8b.**

An end-to-end empirical evaluation of attacks against the MCP ecosystem. It
identifies four categories: **Tool Poisoning**, **Puppet**, **Rug Pull**, and
**Exploitation via Malicious External Resources** — and that fourth category is
precisely Act 8a's distinction. An honest tool relaying a hostile resource is a
different failure from a hostile tool, and the paper treats it as one.

The first three map onto Act 8b. The paper also reports uploading malicious
servers to three aggregation platforms successfully, and a user study in which
participants could not identify malicious servers — which is the practical
reason "the key is the one I pinned" is a weaker statement than it sounds.

---

## arXiv:2602.10481 — Protecting Context and Prompts: Deterministic Security for Non-Deterministic AI

<https://arxiv.org/abs/2602.10481> · v1, submitted 11 February 2026

**Closest prior art for this exhibit's defence layer.**

Introduces *authenticated prompts* and *authenticated context* as primitives
giving cryptographically verifiable provenance across LLM workflows, with
authenticated context using **tamper-evident hash chains** to protect the
integrity of dynamic inputs. That is the same construction this exhibit builds
and inspects.

The paper goes considerably further than this exhibit does: it adds a policy
algebra with proven theorems, and five complementary defences including
LLM-based semantic validation, reporting 100% detection with zero false
positives across six attack categories.

> **Read the scope carefully.** The reported detection figures cover the *full
> layered system*, semantic validation included — not the hash chain alone. This
> exhibit implements only the provenance-and-integrity layer, and Act 8 is a
> demonstration of why that layer alone is not sufficient. Nothing here
> contradicts the paper; the exhibit is showing what the paper's *other* four
> defences exist to cover.

---

## arXiv:2506.09956 — LLMail-Inject: A Dataset from a Realistic Adaptive Prompt Injection Challenge

<https://arxiv.org/abs/2506.09956> · v1, submitted 11 June 2025

**Cited for the instruction/data problem.**

A dataset from an adaptive prompt-injection challenge in a realistic email-assistant
setting, where participants worked to get injected instructions past defences.
The value here is the *adaptive* framing: defences are evaluated against
attackers who see them and adjust, which is the right standard for judging any
claim that a mitigation "handles" injection.

---

## OWASP LLM01 — Prompt Injection

<https://genai.owasp.org/llmrisk/llm01-prompt-injection/>

**Cited for the mitigation framing.**

OWASP's guidance lists separating and identifying external content as a useful
mitigation — the practice this exhibit implements in its strongest form, with
cryptographic provenance rather than delimiters. OWASP is explicit that this
**reduces but does not eliminate** the instruction/data problem, and does not
describe it as a solution. Act 8 is that caveat made visible.

---

## Related constructions this borrows from

Not prior art for the attack, but for the mechanics:

* **NIST SP 800-185 (TupleHash)** — unambiguous hashing of a sequence of strings
  via length prefixes. `enc()` is the same idea; see `docs/MATH.md` §1.1.
* **RFC 5869 (HKDF)** — extract-and-expand, used here for per-role key
  separation.
* **RFC 8032 (Ed25519)** — the signature scheme used for tool attestation.
* **Certificate Transparency (RFC 6962)** — the leaf/interior domain-separation
  discipline (`cw/v1/leaf` versus `cw/v1/chain`) is the same defence against
  confusing a leaf hash for an internal node.

---

## Field incidents

Everything above is peer-reviewed or standards-track. What follows is not: these
are vendor disclosure writeups, which is a different and weaker evidence class,
and they are kept in their own section rather than mixed into the list above so
that nothing here inherits a standard it does not meet. Each entry leads with a
CVE where one was assigned, because the identifier will outlive the URL. All
three were checked on **2026-08-24**.

**None of these would have been prevented by the construction in this exhibit.
That is why they are here.** The exhibit's central risk is a reader concluding
that authenticated context handles injection. Act 8 argues otherwise from a
scripted mock; these are the same argument made against shipping products.

---

### Cryptographic Context Injection — Grok and Gemini

<https://adversa.ai/blog/cryptographic-context-injection-grok-data-theft/> ·
Adversa AI, 20 August 2026 · no CVE assigned

**Cited at Act 3 (injection via runtime result).**

The payload is AES-256-GCM ciphertext. Guardrails inspect text but do not
execute it, so at inspection time the plaintext does not exist anywhere to be
inspected — the writeup's framing is that strong encryption cannot be shortcut
in-weights, so recovery is forced through the code runtime. The model then
decrypts the payload inside its own sandbox and treats the result as its own
runtime output. The authors call this **trust laundering**: the plaintext
inherits a credibility it would not have been given had it been pasted into the
prompt directly. On Grok this reportedly reached zero-click exfiltration of the
user's name, location, subscription tier and chat history from nothing more than
a request to summarise a page.

Act 3 is that shape. A payload arrives through the runtime channel — the one
channel nobody thinks to treat as untrusted, because it appears to originate
from the system itself. An envelope over that segment would have sealed it
correctly and verified green. `SOURCE: RUNTIME` would have been an accurate
label, and accuracy is the entirety of what the seal offers.

> **Name collision, stated deliberately.** "Cryptographic context injection"
> there means *encryption used to smuggle a payload past a filter*. This exhibit
> uses cryptography to *authenticate* context. The two point in opposite
> directions and the phrases are nearly identical. This document does not adopt
> the name — see the note at the top of this file about coined names — and cites
> the mechanism instead.

**Disclosure status.** Reported to xAI on 3 June 2026 via HackerOne; per the
writeup, acknowledged without specifics or a mitigation timeline and still
reproducible on 19 August 2026. Not filed with Google, whose programme scopes
jailbreaks out; the authors observe the vector's success rate against Google's
agents fell significantly by August without being able to attribute the change.
Unlike the two entries below, this one describes behaviour that may still be
live.

---

### CoSnitch — Microsoft 365 Copilot · CVE-2026-24301

<https://www.varonis.com/blog/cosnitch> · Varonis Threat Labs · disclosed to
Microsoft December 2025, patched 18 August 2026

**Cited at Act 4 (injection via persisted state).**

Two parts. The `?q=` URL parameter combined with an undocumented `?autorun=1`
caused an attacker-supplied prompt to execute on page load, with no click and no
confirmation. Separately, prompt injection hidden in webpage metadata
manipulated Copilot's **persistent memory across sessions**.

That second part is Act 4, and specifically **not** Act 5. In a replay the
attacker moves a sealed segment between transcripts, which is exactly what
`SESSION_MISMATCH` and `CHAIN_BREAK` exist to name. Here nothing moves: the host
legitimately writes the poisoned note during one session and legitimately reads
it back in the next, and both segments seal correctly under their own session
keys. The chain is intact, every check is green, and the content is hostile.
This is the distinction Act 5 and Act 4 are built to hold apart, appearing in a
shipped product.

Worth noting separately for how it was found. The researchers questioned Copilot
about its own deep-link parameters until it named the undocumented one — the
refusals themselves carried usable detail. No provenance scheme addresses a
system that will describe its own attack surface on request.

---

### SearchLeak — Microsoft 365 Copilot · CVE-2026-42824

<https://www.varonis.com/blog/searchleak> · Varonis Threat Labs · remediated by
Microsoft, rated critical

**Cited in the negative, at "Do NOT use it as a prompt-injection defence".**

A chain of three: the `q` URL parameter interpreted as instructions rather than
as search text, an `<img>` tag in Copilot's streaming response firing before
output sanitisation ran, and a server-side fetch through a CSP-allowlisted Bing
image endpoint carrying the stolen data out in the request path. Only the first
link is an instruction/data problem. The other two are a rendering-order problem
and an egress problem.

It is included precisely because it marks the honest boundary of this exhibit's
relevance. Envelope verification has nothing to say about two of the three
links, and sealing the first would not have broken the chain either. A
construction that answers *was this altered* and *who supplied it* answers
neither *should this render* nor *where may this connect*.

---

**One sampling caveat.** Two of the three entries are the same research team
working on the same product. That reflects who publishes this kind of writeup,
not a finding that Microsoft 365 Copilot is uniquely affected. Treat the
distribution of these three as evidence about disclosure practice, and only
their mechanisms as evidence about the failure modes.

---

## An open question

Whether provenance labels help a *model* at all — as opposed to helping a human
auditor or an automated policy layer — is not something this exhibit tests, and
it cannot be tested with a scripted mock. The agent here is deterministic by
design; establishing whether a real model conditions on a `SOURCE: TOOL_RESULT`
label would need an actual evaluation against actual models. This is recorded as
an open question in `verification/CLAIMS.yaml` rather than answered.
