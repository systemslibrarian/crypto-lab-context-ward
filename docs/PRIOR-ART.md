# Prior art

Every entry below was checked against its arXiv abstract page on **2026-08-20**,
and each is cited for what it actually supports. Where a paper's title has
changed between versions, the current title is given and the change noted —
citing a superseded title is how a reference becomes unverifiable.

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

## An open question

Whether provenance labels help a *model* at all — as opposed to helping a human
auditor or an automated policy layer — is not something this exhibit tests, and
it cannot be tested with a scripted mock. The agent here is deterministic by
design; establishing whether a real model conditions on a `SOURCE: TOOL_RESULT`
label would need an actual evaluation against actual models. This is recorded as
an open question in `verification/CLAIMS.yaml` rather than answered.
