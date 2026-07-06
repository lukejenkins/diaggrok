"""Zero-PII leak scanner for public diaggrok artifacts (Chunk 5, D11).

The single source of truth for "what counts as a PII leak" in a published
carve. Extends the historical proof-clean token set (capture paths, session
stamps, IMEI) to the four classes found leaking through the shipped proof
tree: cell-dumps/home paths, firmware SHA-256, and geographic coordinates.

Cell identity (cell-ID/ECI/TAC) and *decimal* geographic coordinates are
deliberately NOT free-text-matched here — both are indistinguishable from
legitimate values by pattern alone. A fabricated synthetic cell-ID looks
identical to a real one, and a bare decimal like ``0.514444`` (1 knot in m/s)
or a GNSS C/N0 ratio is indistinguishable from a latitude. So these two
classes are handled STRUCTURALLY on the proof tree (scrub by field-key:
``latitude``/``longitude``, ``serving_cellid``/``eci``/``tac``) and, for the
public corpus, by the risk-tier policy (tier-1 codes ship synthetic values).
Only the *unambiguous* NMEA coordinate form (a direction letter is present)
is free-text-matched here. See the spec's Risk-tier section and Task 3.
"""
import re

LEAK_RES: list[re.Pattern] = [
    # capture / dump / home filesystem paths
    re.compile(r"~?/?(?:Users/[\w.-]+/)?cell-captures/[\w./-]+"),
    re.compile(r"~?/?(?:Users/[\w.-]+/)?cell-dumps/[\w./-]+"),
    re.compile(r"/(?:root|home/[\w.-]+|Users/[\w.-]+)/[\w./-]+"),
    # firmware SHA-256: a STANDALONE ``sha256`` marker word immediately
    # followed by a hex run. Marker-anchored on purpose — a bare 64-hex run
    # over-blocked legit constants (e.g. the Qualcomm-baseline pubkey hash in
    # diag_0x1d15.py's _PUBKEY_SHA256), and a bare ``sha256\b`` matched inside
    # identifiers like ``_PUBKEY_SHA256`` (word-char before). The ``(?<![\w])``
    # / ``(?![\w])`` boundaries require ``sha256`` to be its own word, so a
    # firmware-provenance SHA is still caught while code identifiers are not.
    re.compile(r"(?<![\w])sha256(?![\w])[\s:=]*[0-9a-f]{6,}", re.I),
    # geographic coordinates: ONLY the unambiguous NMEA ddmm.mmmm[NSEW] form
    # (a direction letter disambiguates it from an ordinary decimal). Real
    # sentences comma-separate the hemisphere (``4045.648,N``) and can be
    # lowercase, so allow an optional comma/whitespace and match case-insensitively.
    # Bare decimal lat/long is handled structurally by field-key in the proof-tree
    # scrub (Task 3) — a free-text \d+.\d{4,} regex false-positives on GNSS
    # constants/measurements like 0.514444 (knots->m/s) and C/N0 ratios.
    re.compile(r"\b\d{3,5}\.\d{3,}\s*,?\s*[NSEW]\b", re.I),
    # session stamps + IMEI (retained from proof_leak_tokens). Only the LABELED
    # IMEI form is matched — a bare ``\d{15}`` over-blocked any 15-digit literal
    # (e.g. ``earfcn=123456789012345``); a real IMEI leak carries its label.
    # (The *unlabeled* Luhn-valid IMEI is handled report-only below — see
    # ``_unlabeled_imeis`` — because a bare digit run is also a legal integer
    # literal and MUST NOT be rewritten by the carve redactor.)
    re.compile(r"\b\d{8}T\d{6}Z-[\w.-]+"),
    re.compile(r"\bIMEI(?:SV)?\b[:\s=-]*\d{14,16}", re.I),
    # capture-artifact PATH FRAGMENTS (#N). The #N redactor + this scanner
    # only anchored on *absolute* private roots (``/root``/``cell-captures``/…),
    # so a bare RELATIVE capture path — e.g. a recipe row that mislabels a
    # ``chipset_family`` with ``wardriving/2026-03-26_lm960_verizon/capture.dlf.zst``
    # — slipped through both. These fragments leak survey/session stamps, carrier
    # names, firmware strings, and any IMEI riding inside a capture filename. Two
    # forms, both requiring a ``/`` (a real path, never a bare ``.dlf`` format
    # mention) or a distinctive corpus-dir marker, so a legit identifier/literal
    # can never match:
    #   (a) any path component ending in a capture-artifact extension
    re.compile(r"[\w.-]+/[\w./-]*\."
               r"(?:normalized\.)?(?:dlf|hdlc|qmdl2?|isf|bin)"
               r"(?:\.zst|\.gz|\.xz)?", re.I),
    #   (b) a known private corpus session directory + anything under it
    re.compile(r"\b(?:wardriving|surveys|edge_cases|gnss_comparison)"
               r"[\w-]*/[\w./-]+", re.I),
]


# ── Internal workflow-provenance refs (#N) — CARVE-BOUNDARY, not leak_tokens ─
# Our own ``/5gov*`` validation-command slugs and ``session <hex>`` lab refs
# leaked to the public repo through published-decoder version-comment changelog
# blocks (23 + 22 files). They must be stripped from the PUBLIC carve — but they
# are DELIBERATELY NOT a ``leak_tokens`` / ``LEAK_RES`` class: the PRIVATE
# ground-truth proof tree legitimately records them as the RE-provenance audit
# trail (which validation session grounded a field), and the whole-tree leak
# invariant (test_whole_tree_proof_leaks_clean) would force-scrub that trail if
# these were treated as PII. So they live here as a SHARED pattern set the carve
# redactor and the publish gate import (one source of truth, #N item 2),
# applied only at the public-carve boundary — mirroring how the host/firmware
# VALUE denylists are gate/carve-scoped rather than baked into leak_tokens.
# ``session`` requires a following 4+ hex run so the plain English word
# (``RRC session``, ``session establishment cause``) never trips.
SESSION_REF_RES: list[re.Pattern] = [
    re.compile(r"/5go\w*"),
    re.compile(r"\bsession\s+[0-9a-f]{4,}\b"),
]


def session_refs(text: str) -> list[str]:
    """Internal workflow-provenance refs (``/5gov*`` slugs, ``session <hex>``)
    present in ``text`` — deduped, order-preserving. Used by the carve redactor
    and publish gate to keep these out of PUBLIC artifacts. Deliberately NOT part
    of ``leak_tokens`` (see the SESSION_REF_RES rationale above)."""
    out: list[str] = []
    for rx in SESSION_REF_RES:
        for m in rx.findall(text):
            if m not in out:
                out.append(m)
    return out


def _luhn_ok(digits: str) -> bool:
    """True if ``digits`` (a run of decimal chars) satisfies the Luhn checksum.
    Every valid IMEI/IMEISV is Luhn-valid; a random 15-digit value (an EARFCN,
    a cell-id, a timestamp) is only ~10% likely to pass by chance, so Luhn is a
    clean discriminator that avoids the ``earfcn=...`` false positive the labeled
    IMEI rule was narrowed to dodge."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# Exactly-15-digit runs (canonical IMEI length), not part of a longer number.
_IMEI15_RE = re.compile(r"(?<!\d)\d{15}(?!\d)")


def _unlabeled_imeis(text: str) -> list[str]:
    """Unlabeled but Luhn-valid 15-digit runs — a bare IMEI with no ``IMEI:``
    label (e.g. embedded in a capture filename). REPORT-ONLY: surfaced by
    ``leak_tokens`` so the fail-closed gate refuses, but deliberately NOT in
    ``LEAK_RES`` — the carve redactor rewrites ``LEAK_RES`` hits in place, and a
    bare digit run is a legal integer literal that must not be corrupted into a
    ``<redacted-pii>`` marker. So this class fails the gate for a human to
    resolve rather than being silently auto-rewritten."""
    return [m.group() for m in _IMEI15_RE.finditer(text) if _luhn_ok(m.group())]


def leak_tokens(text: str) -> list[str]:
    """All PII leak tokens present in ``text`` (empty list = clean).
    Deduped, order-preserving. Note: this is a SUPERSET of the ``LEAK_RES``
    regex hits — it also reports unlabeled Luhn-valid IMEIs (``_unlabeled_imeis``),
    which are intentionally absent from ``LEAK_RES`` (report-only, never
    redacted — see that helper). The carve gate keys off ``leak_tokens``, so the
    stricter side is the gate, which is the fail-closed-correct direction."""
    out: list[str] = []
    for rx in LEAK_RES:
        for m in rx.findall(text):
            if m not in out:
                out.append(m)
    for tok in _unlabeled_imeis(text):
        if tok not in out:
            out.append(tok)
    return out
