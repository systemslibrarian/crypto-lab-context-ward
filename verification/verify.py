#!/usr/bin/env python3
"""
verify.py -- an independent verifier for the Context Ward envelope protocol.

This file exists to be a SECOND implementation. It is written from the prose
specification in `docs/MATH.md` and it imports nothing from `src/`. If the two
implementations disagree, at least one of them is wrong, and the disagreement is
visible rather than absorbed by shared code.

Concretely, that means:

  * No transpiled, bundled or generated artefact from the TypeScript is read.
  * No value stored in a fixture is trusted as an INPUT to a check. Leaves,
    chain hashes, role keys and tags are all recomputed; stored values are only
    ever compared against the recomputation.
  * The expected outcomes in `fixtures/MANIFEST.json` are compared against
    outcomes this file derives on its own.

Dependencies: Python 3.9+ and `cryptography` (see requirements.txt). Usage:

    python3 verification/verify.py                # defaults to ./fixtures
    python3 verification/verify.py path/to/fixtures
    python3 verification/verify.py --verbose
"""

from __future__ import annotations

import argparse
import binascii
import hashlib
import hmac
import json
import os
import sys
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTOCOL_VERSION = 1

ROLES: Tuple[str, ...] = (
    "system",
    "user",
    "tool_result",
    "runtime",
    "state",
    "retrieved",
)

LEAF_LABEL = "cw/v1/leaf"
CHAIN_LABEL = "cw/v1/chain"
SEAL_LABEL = "cw/v1/seal"
TOOL_LABEL = "cw/v1/tool"
ROLE_INFO_PREFIX = "cw/v1/role/"

ZERO32 = b"\x00" * 32
ZERO_PREV = "0" * 64


# ---------------------------------------------------------------------------
# Encoding rules (docs/MATH.md, "String and encoding rules")
# ---------------------------------------------------------------------------


class EncodingError(ValueError):
    """A value cannot be encoded under the protocol's string rules."""


def assert_no_lone_surrogates(s: str) -> None:
    """
    Reject unpaired UTF-16 surrogates.

    Python stores lone surrogates happily -- `json.loads` will hand back
    '\\ud800' without complaint -- and only refuses at encode time. The protocol
    requires rejection rather than substitution, so this check is explicit
    rather than left to whatever the encoder happens to do.
    """
    i = 0
    n = len(s)
    while i < n:
        c = ord(s[i])
        if 0xD800 <= c <= 0xDBFF:
            nxt = ord(s[i + 1]) if i + 1 < n else -1
            if not (0xDC00 <= nxt <= 0xDFFF):
                raise EncodingError(
                    "unpaired high surrogate U+%04X at UTF-16 index %d" % (c, i)
                )
            i += 2
            continue
        if 0xDC00 <= c <= 0xDFFF:
            raise EncodingError(
                "unpaired low surrogate U+%04X at UTF-16 index %d" % (c, i)
            )
        i += 1


def utf8(s: str) -> bytes:
    """Strict UTF-8. No normalisation is performed, by design."""
    assert_no_lone_surrogates(s)
    try:
        return s.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:  # pragma: no cover -- belt and braces
        raise EncodingError(str(exc)) from exc


def u32be(n: int) -> bytes:
    if not isinstance(n, int) or isinstance(n, bool) or n < 0 or n > 0xFFFFFFFF:
        raise EncodingError("value out of uint32 range: %r" % (n,))
    return n.to_bytes(4, "big")


def enc(s: str) -> bytes:
    """enc(s) = uint32be(byte_len(utf8(s))) || utf8(s)"""
    b = utf8(s)
    return u32be(len(b)) + b


def unhex(h: str) -> bytes:
    if not isinstance(h, str) or len(h) % 2 != 0:
        raise EncodingError("hex string has odd length or wrong type: %r" % (h,))
    if any(ch not in "0123456789abcdef" for ch in h):
        raise EncodingError("hex string must be lowercase [0-9a-f]")
    return binascii.unhexlify(h)


# ---------------------------------------------------------------------------
# Protocol (docs/MATH.md, "Leaf and chain", "Host seal", "Tool attestation")
# ---------------------------------------------------------------------------


def leaf_hash(e: Dict[str, Any]) -> bytes:
    """
    leaf_n = SHA256( enc("cw/v1/leaf") || uint32be(v) || enc(session)
                     || uint32be(seq) || enc(role) || enc(tool ?? "")
                     || enc(body) )

    `prev` is deliberately absent: it is a display mirror, not a leaf input.
    """
    tool = e.get("tool")
    return hashlib.sha256(
        enc(LEAF_LABEL)
        + u32be(e["v"])
        + enc(e["session"])
        + u32be(e["seq"])
        + enc(e["role"])
        + enc("" if tool is None else tool)
        + enc(e["body"])
    ).digest()


def chain_step(prev_hash: bytes, leaf: bytes) -> bytes:
    """H_n = SHA256( enc("cw/v1/chain") || H_(n-1) || leaf_n ), H_(-1) = 32 zero bytes."""
    return hashlib.sha256(enc(CHAIN_LABEL) + prev_hash + leaf).digest()


def derive_role_key(session_key: bytes, session_bytes: bytes, role: str) -> bytes:
    """
    K_role = HKDF-SHA256(ikm=K_session, salt=session_bytes,
                         info="cw/v1/role/"||role, L=32)

    The salt is the RAW 32 session bytes, NOT the 64-character hex string that
    enc(session) covers elsewhere. This is the one place the two representations
    diverge and it is the likeliest cross-implementation mismatch.
    """
    return HKDF(
        algorithm=_hashes.SHA256(),
        length=32,
        salt=session_bytes,
        info=(ROLE_INFO_PREFIX + role).encode("utf-8"),
    ).derive(session_key)


def seal_tag(role_key: bytes, role: str, chain_hash: bytes) -> bytes:
    """tag_n = HMAC-SHA256(K_role, enc("cw/v1/seal") || enc(role) || H_n)"""
    return hmac.new(
        role_key, enc(SEAL_LABEL) + enc(role) + chain_hash, hashlib.sha256
    ).digest()


def seal(session_key: bytes, session_bytes: bytes, role: str, chain_hash: bytes) -> bytes:
    return seal_tag(derive_role_key(session_key, session_bytes, role), role, chain_hash)


def attestation_message(session: str, seq: int, leaf: bytes) -> bytes:
    """enc("cw/v1/tool") || enc(session) || uint32be(seq) || leaf_n"""
    return enc(TOOL_LABEL) + enc(session) + u32be(seq) + leaf


def verify_attestation(
    public_key: bytes, session: str, seq: int, leaf: bytes, signature: bytes
) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, attestation_message(session, seq, leaf)
        )
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------------------
# Transcript verification
# ---------------------------------------------------------------------------

FAILURE_CODES = (
    "V_REJECTED",
    "MALFORMED",
    "SESSION_MISMATCH",
    "SEQ_GAP",
    "CHAIN_BREAK",
    "ROLE_MISMATCH",
    "BAD_TAG",
    "BAD_SIGNATURE",
    "UNPINNED_TOOL",
)

HEX64 = set("0123456789abcdef")


def _is_hex64(s: Any) -> bool:
    return isinstance(s, str) and len(s) == 64 and all(c in HEX64 for c in s)


def assert_well_formed(e: Dict[str, Any]) -> None:
    if not _is_hex64(e.get("session")):
        raise EncodingError("session must be 64 lowercase hex characters")
    seq = e.get("seq")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0 or seq > 0xFFFFFFFF:
        raise EncodingError("seq out of uint32 range: %r" % (seq,))
    if e.get("role") not in ROLES:
        raise EncodingError("unknown role: %r" % (e.get("role"),))
    if not _is_hex64(e.get("prev")):
        raise EncodingError("prev must be 64 lowercase hex characters")
    # Deliberately no role/tool consistency rule -- see docs/MATH.md.


class Finding:
    __slots__ = ("code", "index", "seq", "detail")

    def __init__(self, code: str, index: int, seq: Optional[int], detail: str):
        assert code in FAILURE_CODES, code
        self.code = code
        self.index = index
        self.seq = seq
        self.detail = detail

    def __repr__(self) -> str:
        where = "transcript" if self.index < 0 else "segment %d" % self.index
        return "%s at %s: %s" % (self.code, where, self.detail)


def verify_transcript(t: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []

    # Pre-cryptographic version gate. Runs before anything else, so an
    # unsupported version never reaches code that would interpret its fields.
    if t.get("v") != PROTOCOL_VERSION:
        findings.append(
            Finding("V_REJECTED", -1, None,
                    "transcript v=%r; this verifier accepts only v=1" % (t.get("v"),))
        )
        return findings
    if not _is_hex64(t.get("session")):
        findings.append(
            Finding("MALFORMED", -1, None,
                    "transcript session is not 64 lowercase hex characters")
        )
        return findings

    session = t["session"]
    session_bytes = unhex(session)
    session_key = unhex(t["session_key"])
    pinned: Dict[str, str] = t.get("pinned_tool_keys") or {}

    h = ZERO32
    expected_seq = 0

    for i, seg in enumerate(t.get("segments") or []):
        e = seg["envelope"]

        if e.get("v") != PROTOCOL_VERSION:
            findings.append(
                Finding("V_REJECTED", i, e.get("seq"),
                        "segment v=%r; only v=1 is accepted" % (e.get("v"),))
            )
            break

        try:
            assert_well_formed(e)
        except EncodingError as exc:
            findings.append(Finding("MALFORMED", i, e.get("seq"), str(exc)))
            break

        if e["session"] != session:
            findings.append(
                Finding("SESSION_MISMATCH", i, e["seq"],
                        "segment carries session %s...; transcript is %s..."
                        % (e["session"][:16], session[:16]))
            )

        if e["seq"] != expected_seq:
            findings.append(
                Finding("SEQ_GAP", i, e["seq"],
                        "expected seq %d, found %d" % (expected_seq, e["seq"]))
            )
        expected_seq = e["seq"] + 1

        # `prev` is a display mirror: recompute H_(n-1) and require a match.
        h_prev = h
        expected_prev = ZERO_PREV if (i == 0 and h == ZERO32) else h.hex()
        if e["prev"] != expected_prev:
            findings.append(
                Finding("CHAIN_BREAK", i, e["seq"],
                        "prev is %s...; recomputed H_%d is %s..."
                        % (e["prev"][:16], i - 1, expected_prev[:16]))
            )

        leaf = leaf_hash(e)
        h = chain_step(h, leaf)

        # --- Host seal ---------------------------------------------------
        try:
            tag = unhex(seg["tag"])
        except EncodingError:
            findings.append(Finding("MALFORMED", i, e["seq"], "tag is not lowercase hex"))
            tag = None

        if tag is not None and not hmac.compare_digest(
            seal(session_key, session_bytes, e["role"], h), tag
        ):
            # `role` is covered by leaf_n, so a relabel moves the chain head as
            # well as the seal key. To name a relabel we recompute the leaf and
            # chain step as they would have been under each candidate role.
            verified_as = None
            for r in ROLES:
                if r == e["role"]:
                    continue
                alt = dict(e)
                alt["role"] = r
                as_role = chain_step(h_prev, leaf_hash(alt))
                if hmac.compare_digest(
                    seal(session_key, session_bytes, r, as_role), tag
                ):
                    verified_as = r
                    break
            if verified_as is not None:
                findings.append(
                    Finding("ROLE_MISMATCH", i, e["seq"],
                            "presented as %s, but it was sealed as %s"
                            % (e["role"], verified_as))
                )
            else:
                findings.append(
                    Finding("BAD_TAG", i, e["seq"],
                            "seal does not cover this segment as sealed (role %s)" % e["role"])
                )

        # --- Tool attestation --------------------------------------------
        sig_hex = seg.get("sig")
        if sig_hex is not None:
            key_name = seg.get("tool_key") or e.get("tool")
            pub = pinned.get(key_name) if key_name else None
            if not pub:
                findings.append(
                    Finding("UNPINNED_TOOL", i, e["seq"],
                            "no pinned public key for tool %r" % (key_name,))
                )
            else:
                ok = False
                try:
                    ok = verify_attestation(unhex(pub), e["session"], e["seq"], leaf, unhex(sig_hex))
                except EncodingError:
                    ok = False
                if not ok:
                    findings.append(
                        Finding("BAD_SIGNATURE", i, e["seq"],
                                "Ed25519 attestation from %r does not verify" % (key_name,))
                    )

    return findings


# ---------------------------------------------------------------------------
# Vector checks
# ---------------------------------------------------------------------------


def check_encoding_vectors(doc: Dict[str, Any], report: "Report") -> None:
    for v in doc["accept"]:
        name = v["name"]
        try:
            got = enc(v["s"]).hex()
        except EncodingError as exc:
            report.fail("encoding/%s" % name, "expected to encode, got %s" % exc)
            continue
        if got != v["enc_hex"]:
            report.fail("encoding/%s" % name,
                        "enc mismatch\n    fixture: %s\n    recomputed: %s" % (v["enc_hex"], got))
        elif len(utf8(v["s"])) != v["utf8_len"]:
            report.fail("encoding/%s" % name, "utf8_len mismatch")
        else:
            report.ok("encoding/%s" % name)

    # The two canonically-equivalent vectors must encode DIFFERENTLY. An
    # implementation that normalises passes every other vector and fails here.
    by_name = {v["name"]: v for v in doc["accept"]}
    a = by_name.get("combining-not-normalised")
    b = by_name.get("precomposed-not-normalised")
    if a and b:
        if enc(a["s"]).hex() == enc(b["s"]).hex():
            report.fail("encoding/no-normalisation",
                        "decomposed and composed forms encoded identically -- "
                        "this implementation normalises, and must not")
        else:
            report.ok("encoding/no-normalisation")

    for v in doc["reject"]:
        name = v["name"]
        try:
            enc(v["s"])
        except EncodingError:
            report.ok("encoding/reject/%s" % name)
        else:
            report.fail("encoding/reject/%s" % name,
                        "expected rejection (%s) but the string encoded" % v["reason"])


def check_protocol_vectors(doc: Dict[str, Any], report: "Report") -> None:
    session_bytes = unhex(doc["session_bytes"])
    session_key = unhex(doc["session_key"])
    e = doc["envelope"]

    leaf = leaf_hash(e)
    report.compare("protocol/leaf", doc["leaf"], leaf.hex())

    report.compare("protocol/chain_from_zero", doc["chain_from_zero"],
                   chain_step(ZERO32, leaf).hex())

    cfp = doc["chain_from_prev"]
    h_n = chain_step(unhex(cfp["h_prev"]), leaf)
    report.compare("protocol/chain_from_prev", cfp["h_n"], h_n.hex())

    for role, expected in doc["role_keys"].items():
        report.compare("protocol/role_key/%s" % role, expected,
                       derive_role_key(session_key, session_bytes, role).hex())

    tags = doc["tags_over_chain_from_prev"]
    for role, expected in tags.items():
        report.compare("protocol/tag/%s" % role, expected,
                       seal(session_key, session_bytes, role, h_n).hex())

    # Role separation, restated as an assertion rather than trusted from the
    # fixture: no two roles may produce the same tag over the same chain head.
    if len(set(tags.values())) != len(tags):
        report.fail("protocol/role-separation", "two roles produced the same tag")
    else:
        report.ok("protocol/role-separation")

    # And the tag for one role must not verify as another.
    system_tag = unhex(tags["system"])
    tool_tag = unhex(tags["tool_result"])
    if hmac.compare_digest(seal(session_key, session_bytes, "system", h_n), tool_tag):
        report.fail("protocol/tool-tag-is-not-system-tag",
                    "a tool_result tag verified as a system tag")
    else:
        report.ok("protocol/tool-tag-is-not-system-tag")
    if not hmac.compare_digest(seal(session_key, session_bytes, "system", h_n), system_tag):
        report.fail("protocol/system-tag-verifies", "the system tag did not verify as itself")
    else:
        report.ok("protocol/system-tag-verifies")

    att = doc["tool_attestation"]
    # Re-derive the public key from the published seed rather than trusting it.
    derived_pub = (
        Ed25519PrivateKey.from_private_bytes(unhex(att["secret_key_seed"]))
        .public_key()
        .public_bytes_raw()
    )
    report.compare("protocol/tool_public_key", att["public_key"], derived_pub.hex())

    if verify_attestation(derived_pub, att["session"], att["seq"], unhex(att["leaf"]),
                          unhex(att["signature"])):
        report.ok("protocol/tool_signature")
    else:
        report.fail("protocol/tool_signature", "the published signature did not verify")

    # Session and sequence binding: the same signature must NOT verify elsewhere.
    if verify_attestation(derived_pub, att["session"], att["seq"] + 1,
                          unhex(att["leaf"]), unhex(att["signature"])):
        report.fail("protocol/seq-binding", "the signature verified at the wrong seq")
    else:
        report.ok("protocol/seq-binding")

    other_session = "0" * 64
    if verify_attestation(derived_pub, other_session, att["seq"], unhex(att["leaf"]),
                          unhex(att["signature"])):
        report.fail("protocol/session-binding", "the signature verified in another session")
    else:
        report.ok("protocol/session-binding")


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


class Report:
    def __init__(self, verbose: bool = False):
        self.passed = 0
        self.failures: List[str] = []
        self.verbose = verbose

    def ok(self, name: str) -> None:
        self.passed += 1
        if self.verbose:
            print("  ok    %s" % name)

    def fail(self, name: str, detail: str) -> None:
        self.failures.append("%s: %s" % (name, detail))
        print("  FAIL  %s: %s" % (name, detail))

    def compare(self, name: str, expected: str, actual: str) -> None:
        if expected == actual:
            self.ok(name)
        else:
            self.fail(name, "\n    fixture:    %s\n    recomputed: %s" % (expected, actual))


def check_transcript(path: str, entry: Dict[str, Any], report: Report) -> None:
    with open(path, "r", encoding="utf-8") as fh:
        t = json.load(fh)

    findings = verify_transcript(t)
    codes: Set[str] = set(f.code for f in findings)
    expect_ok = entry["expect"] == "ok"
    expect_codes: Set[str] = set(entry.get("expect_codes") or [])
    name = entry["file"]

    if expect_ok and findings:
        report.fail(name, "expected a clean verification, got: %s"
                    % "; ".join(repr(f) for f in findings))
        return
    if not expect_ok and not findings:
        report.fail(name, "expected failures %s, but verification was clean"
                    % sorted(expect_codes))
        return
    if codes != expect_codes:
        report.fail(name, "failure codes differ\n    manifest:   %s\n    recomputed: %s"
                    % (sorted(expect_codes), sorted(codes)))
        return

    report.ok("%s (%s)" % (name, "clean" if expect_ok else ", ".join(sorted(codes))))


def main(argv: Sequence[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("fixtures", nargs="?", default="fixtures",
                    help="path to the fixtures directory (default: ./fixtures)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="print every passing check, not only failures")
    args = ap.parse_args(list(argv))

    root = args.fixtures
    manifest_path = os.path.join(root, "MANIFEST.json")
    if not os.path.isfile(manifest_path):
        print("no manifest at %s" % manifest_path, file=sys.stderr)
        return 2

    with open(manifest_path, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)

    if manifest.get("protocol_version") != PROTOCOL_VERSION:
        print("manifest declares protocol_version=%r; this verifier implements v%d"
              % (manifest.get("protocol_version"), PROTOCOL_VERSION), file=sys.stderr)
        return 2

    report = Report(verbose=args.verbose)
    entries = manifest["entries"]

    print("verify.py -- independent re-derivation from docs/MATH.md")
    print("%d manifest entries under %s/\n" % (len(entries), root))

    hostile_green: List[str] = []

    for entry in entries:
        path = os.path.join(root, entry["file"])
        if not os.path.isfile(path):
            report.fail(entry["file"], "missing")
            continue
        if entry["kind"] == "transcript":
            check_transcript(path, entry, report)
            if entry["expect"] == "ok" and entry.get("agent_compromised"):
                hostile_green.append(entry["file"])
        else:
            with open(path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
            if entry["file"].endswith("encoding.json"):
                check_encoding_vectors(doc, report)
            elif entry["file"].endswith("protocol.json"):
                check_protocol_vectors(doc, report)
            else:
                report.fail(entry["file"], "unrecognised vector file")

    print("\n%d checks passed, %d failed" % (report.passed, len(report.failures)))

    # The negative claim, stated by the verifier itself rather than left to a
    # reader of the docs. See CLAIMS.yaml NEG-1.
    if hostile_green:
        print(
            "\nNEG-1: %d fixture(s) verified COMPLETELY CLEAN while carrying a payload\n"
            "       the scripted agent obeys. Authenticated context does not prevent\n"
            "       semantic injection; these are the fixtures that demonstrate it:"
            % len(hostile_green)
        )
        for f in hostile_green:
            print("         %s" % f)
    else:
        report.fail("NEG-1", "no hostile-but-valid fixture found -- the negative claim "
                             "in CLAIMS.yaml has lost its evidence")

    if report.failures:
        print("\nFAILED")
        return 1
    print("\nOK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
