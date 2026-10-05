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
    # over-blocked legit constants (e.g. the baseline public-key hash in
    # diag_0x1d15.py's _PUBKEY_SHA256), and a bare ``sha256\b`` matched inside
    # identifiers like ``_PUBKEY_SHA256`` (word-char before). The ``(?<![\w])``
    # / ``(?![\w])`` boundaries require ``sha256`` to be its own word, so a
    # firmware-provenance SHA is still caught while code identifiers are not.
    re.compile(r"(?<![\w])sha256(?![\w])[\s:=]*[0-9a-f]{6,}", re.I),
    # geographic coordinates: ONLY the unambiguous direction-letter form (the
    # trailing N/S/E/W disambiguates it from an ordinary decimal). Real
    # sentences comma-separate the hemisphere (``4045.648,N``), so allow an
    # optional comma/whitespace.
    # Bare decimal lat/long is handled structurally by field-key in the proof-tree
    # scrub (Task 3) — a free-text \d+.\d{4,} regex false-positives on GNSS
    # constants/measurements like 0.514444 (knots->m/s) and C/N0 ratios.
    #
    # The integer part is ``\d{1,5}``, not the NMEA ``ddmm`` width ``\d{3,5}``:
    # latitude is bounded at ±90°, so a decimal-degree latitude has only 1-2
    # integer digits, and the narrower width could never match one. The
    # direction letter is what makes this rule safe to auto-redact at all.
    #
    # The case-insensitive form is split in two. Case-insensitively, ``[NSEW]``
    # also matches the SI **second** suffix and the scientific-notation ``e``:
    # ``0.000 s``, ``65.536 s``, ``1.205e-7`` would all read as hemispheres.
    #
    # The discriminator is **spacing, not case** — which matters, because
    # lowercase NMEA is a real, separately-tested finding (``4045.648n``), not a
    # speculative allowance, so dropping ``re.I`` outright would discard a known
    # leak class. Every lowercase unit or exponent match has **whitespace**
    # before the letter or is an exponent continuation; the real NMEA forms are
    # letter-ADJACENT
    # (``4045.648n``, ``4045.648,n``). So:
    #   - whitespace allowed  -> hemisphere must be UPPERCASE
    #   - lowercase allowed   -> letter must be adjacent (optional comma, no space)
    # The ``(?![+-]?\d)`` tail on both kills the exponent form (``1.205e-7``,
    # ``1.205E-7``), which is the one adjacent-lowercase false positive.
    re.compile(r"\b\d{1,5}\.\d{3,}\s*,?\s*[NSEW]\b(?![+-]?\d)"),
    re.compile(r"\b\d{1,5}\.\d{3,},?[nsew]\b(?![+-]?\d)"),
    # session stamps + IMEI (retained from proof_leak_tokens). Only the LABELED
    # IMEI form is matched — a bare ``\d{15}`` over-blocked any 15-digit literal
    # (e.g. ``earfcn=123456789012345``); a real IMEI leak carries its label.
    # (The *unlabeled* Luhn-valid IMEI is handled report-only below — see
    # ``_unlabeled_imeis`` — because a bare digit run is also a legal integer
    # literal and MUST NOT be rewritten by the carve redactor.)
    re.compile(r"\b\d{8}T\d{6}Z-[\w.-]+"),
    re.compile(r"\bIMEI(?:SV)?\b[:\s=-]*\d{14,16}", re.I),
    # capture-artifact PATH FRAGMENTS. The rules above anchor on *absolute*
    # roots (``/root``/``cell-captures``/…); a bare RELATIVE capture path, e.g.
    # ``wardriving/<date>_<modem>_<carrier>/capture.dlf.zst``, needs its own
    # rule. These fragments leak survey/session stamps, carrier
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


# ── Internal workflow-provenance refs — CARVE-BOUNDARY, not leak_tokens ──────
# Validation-command slugs (``/5gov*``) and ``session <hex>`` lab refs are
# stripped from a public carve but are deliberately NOT a ``leak_tokens`` /
# ``LEAK_RES`` class: private ground-truth proof records legitimately keep them
# as the provenance audit trail, and treating them as PII would force-scrub
# that trail. They live here as a shared pattern set that the carve redactor
# and the publish gate both import, applied only at the public-carve boundary.
# ``session`` requires a following 4+ hex run so the plain English word
# (``RRC session``, ``session establishment cause``) never trips.
SESSION_REF_RES: list[re.Pattern] = [
    re.compile(r"/5go\w*"),
    # Canonical 4+-hex session IDs, incl. all-letter-hex (``session beef``). The
    # trailing ``\b`` is what spares legit prose: ``session cadence`` matches the
    # hex run ``cade`` but the following ``nce`` (word chars) denies the ``\b``,
    # so no match.
    # ``re.I`` because a sentence-initial ``Session 5a3c`` is the most common
    # way the ref is written in prose.
    re.compile(r"\bsession\s+[0-9a-f]{4,}\b", re.I),
    # Compound run-tags — ``session b113xsrc`` — where a non-hex
    # suffix (``xsrc``) denies the ``\b`` on the rule above and the tag slips by.
    # Match the hex core + alphanumeric suffix, but ONLY when the tag contains a
    # digit (the ``(?=[0-9a-z]*\d)`` lookahead). That gate is what keeps
    # ``session cadence`` (all-letter, no digit) from tripping, while all-letter-
    # hex IDs like ``session beef`` stay covered by the boundary rule above.
    re.compile(r"\bsession\s+(?=[0-9a-z]*\d)[0-9a-f]{4,}[0-9a-z]*\b"),
    # ``session``-prefixed capture timestamps — a bare
    # ``YYYYMMDDTHHMMSSZ`` with no trailing ``-``, so LEAK_RES's capture-stamp
    # rule (``\d{8}T\d{6}Z-[\w.-]+``, which requires the ``-``) also misses it.
    re.compile(r"\bsession\s+\d{8}T\d{6}Z\b"),
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

#: The synthetic IMEIs fixtures standardise on. ``123456789012345`` is
#: not Luhn-valid so it would pass the checksum anyway; ``000000000000000`` IS
#: Luhn-valid, so for that one this allowlist is genuinely load-bearing.
#:
#: ``123456789012347`` is the first one's **Luhn-valid twin** (same 14 digits,
#: correct check digit) — what a fixture reaches for when the code under test
#: validates the IMEI, so the canonical placeholder cannot be used.
IMEI_PLACEHOLDERS = frozenset({"123456789012345", "123456789012347",
                               "000000000000000"})


def _embedded_in_hex_run(text: str, start: int, end: int) -> bool:
    """True if a digit run is a slice of a LONGER hex token (a payload blob).

    This is the main false-positive class for the IMEI rule: a test vector such
    as ``...8ea607000101040100ff...`` contains ``607000101040100``, a 15-digit
    run that is **also Luhn-valid**, and parser tests are full of wire-format
    hex.

    ``_IMEI15_RE``'s ``(?<!\\d)(?!\\d)`` boundaries only exclude adjacent
    *decimal* digits; the neighbours here are ``a`` and ``f``. An IMEI is
    exactly 15 digits and is never a substring of a longer hex token, so
    expanding over ``[0-9a-fA-F]`` and requiring the expansion to be the match
    itself is exact — no length heuristic, no tuning knob.
    """
    s, e = start, end
    while s > 0 and text[s - 1] in "0123456789abcdefABCDEF":
        s -= 1
    while e < len(text) and text[e] in "0123456789abcdefABCDEF":
        e += 1
    return (s, e) != (start, end)


def _unlabeled_imeis(text: str) -> list[str]:
    """Unlabeled but Luhn-valid 15-digit runs — a bare IMEI with no ``IMEI:``
    label (e.g. embedded in a capture filename). REPORT-ONLY: surfaced by
    ``leak_tokens`` so the fail-closed gate refuses, but deliberately NOT in
    ``LEAK_RES`` — the carve redactor rewrites ``LEAK_RES`` hits in place, and a
    bare digit run is a legal integer literal that must not be corrupted into a
    ``<redacted-pii>`` marker. So this class fails the gate for a human to
    resolve rather than being silently auto-rewritten. Two filters keep it
    quiet on non-identifiers: the placeholder allowlist and the hex-run guard."""
    return [m.group() for m in _IMEI15_RE.finditer(text)
            if _luhn_ok(m.group())
            and m.group() not in IMEI_PLACEHOLDERS
            and not _embedded_in_hex_run(text, m.start(), m.end())]


# ── Subscriber identifiers — shapes shared with other carve gates ────────────
# One definition, imported by every gate that needs them, so the scanners
# cannot drift in which classes they know about.
#
# They are REPORT-ONLY for the same reason ``_unlabeled_imeis`` is: each is a
# bare digit run, and a bare digit run is a legal integer literal. Putting them
# in ``LEAK_RES`` would let the carve redactor rewrite source in place.

#: ITU: ``89`` + issuer/account digits. 19-20 total is the shipped range.
_ICCID_RE = re.compile(r"(?<!\d)89\d{17,18}(?!\d)")
#: North-American MCCs (310-316).
_IMSI_RE = re.compile(r"(?<!\d)31[0-6]\d{12}(?!\d)")
#: E.164 restricted to the NANP form with an explicit ``+``. A bare 10-digit run
#: is indistinguishable from an EARFCN/cell-id and would be pure noise.
_E164_RE = re.compile(r"(?<![\w+])\+1[2-9]\d{2}[2-9]\d{6}(?!\d)")

#: ``(rule, regex, why)`` — iterated by this module and by other gates, so
#: they cannot drift in *which* classes they know about.
SUBSCRIBER_RULES = (
    ("iccid", _ICCID_RE, "ITU ICCID shape (89 + 17-18 digits)"),
    ("imsi", _IMSI_RE, "IMSI shape with a North-American MCC (310-316)"),
    ("phone", _E164_RE, "E.164 NANP subscriber number"),
)


def subscriber_tokens(text: str) -> list[str]:
    """ICCID / IMSI / E.164 tokens in ``text`` — deduped, order-preserving.
    Report-only (see the note above); folded into ``leak_tokens``."""
    out: list[str] = []
    for _rule, rx, _why in SUBSCRIBER_RULES:
        for m in rx.finditer(text):
            if m.group() not in out:
                out.append(m.group())
    return out


# ── High-precision coordinate shape ───────────────────────────────────────────
# Only the SHAPE rule lives here. A value denylist of known positions must not:
# this module ships with the library, so any value written here would be
# published by the leak detector itself.

#: A decimal in plausible degree range. On its own this is unusable — see the
#: two structural filters below, which are what make it precise.
_DECIMAL_RE = re.compile(r"(?<![\w.])(-?\d{1,3}\.\d{4,})(?![\w.])")

_PI = 3.141592653589793


def _is_dyadic(literal: str) -> bool:
    """True if the decimal literal is exactly ``k / 2**n``.

    This is what makes a coordinate rule usable in a DIAG tree at all. Every
    RSRP/RSRQ/RSSI value a fixed-point DIAG field produces is a dyadic rational
    by construction of the encoding (``-115.515625`` = -115 - 33/64), and those
    values sit squarely inside longitude range. In a typical tree about four
    fifths of the in-range decimals are dyadic, so one predicate removes most of
    the noise structurally rather than by threshold-tuning. A GPS double is
    dyadic only by accident.
    """
    from fractions import Fraction
    denom = Fraction(literal).denominator
    return denom & (denom - 1) == 0


def _is_round_radian(value: float) -> bool:
    """True if the value is a round radian count converted to degrees.

    The second false-positive family: synthetic GNSS fixtures are built
    as ``rad * 180 / PI`` from round radian values, so ``28.64788975654116``
    (0.5 rad) and ``-57.29577951308232`` (1 rad) are full-precision non-dyadic
    decimals in degree range — and entirely synthetic. Recognising the
    *construction* keeps a tree's own synthetic-coordinate idiom out of the
    report without allowlisting any file or any literal.
    """
    rad = value * _PI / 180.0
    return abs(rad - round(rad, 4)) < 1e-9


def high_precision_coordinates(text: str) -> list[str]:
    """Decimal literals with the shape of a real GPS double — deduped.

    In degree range, >= 10 fractional digits, non-dyadic, not a round-radian
    conversion, not pi. Report-only: a bare decimal is a legal float literal and
    must never be auto-rewritten by the carve redactor.
    """
    out: list[str] = []
    for m in _DECIMAL_RE.finditer(text):
        literal = m.group(1)
        if len(literal.split(".")[1]) < 10:
            continue
        value = float(literal)
        if not (-180.0 <= value <= 180.0):
            continue
        # π is compared with a TOLERANCE, not ``==``: a hand-typed π literal is
        # often truncated (``3.14159265358979``). Any literal within 1e-9 of π
        # is π.
        if (_is_dyadic(literal) or _is_round_radian(value)
                or abs(abs(value) - _PI) < 1e-9):
            continue
        if literal not in out:
            out.append(literal)
    return out


def leak_tokens(text: str) -> list[str]:
    """All PII leak tokens present in ``text`` (empty list = clean).
    Deduped, order-preserving. Note: this is a SUPERSET of the ``LEAK_RES``
    regex hits — it also reports unlabeled Luhn-valid IMEIs (``_unlabeled_imeis``),
    which are intentionally absent from ``LEAK_RES`` (report-only, never
    redacted — see that helper). The carve gate keys off ``leak_tokens``, so the
    stricter side is the gate, which is the fail-closed-correct direction.

    The report-only set also covers subscriber identifiers and GPS-shaped
    decimals: ICCID, IMSI, E.164, and high-precision coordinates. All are bare digit runs, so all stay OUT of
    ``LEAK_RES`` for the ``_unlabeled_imeis`` reason — the gate refuses and a
    human scrubs, rather than the redactor rewriting a legal literal in place."""
    out: list[str] = []
    for rx in LEAK_RES:
        for m in rx.findall(text):
            if m not in out:
                out.append(m)
    for report_only in (_unlabeled_imeis(text), subscriber_tokens(text),
                        high_precision_coordinates(text)):
        for tok in report_only:
            if tok not in out:
                out.append(tok)
    return out
