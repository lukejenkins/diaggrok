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
    # geographic coordinates: ONLY the unambiguous direction-letter form (the
    # trailing N/S/E/W disambiguates it from an ordinary decimal). Real
    # sentences comma-separate the hemisphere (``4045.648,N``), so allow an
    # optional comma/whitespace.
    # Bare decimal lat/long is handled structurally by field-key in the proof-tree
    # scrub (Task 3) — a free-text \d+.\d{4,} regex false-positives on GNSS
    # constants/measurements like 0.514444 (knots->m/s) and C/N0 ratios.
    #
    # ⛔ Integer width was ``\d{3,5}`` until 2026-08-04 (#N) — the NMEA ``ddmm``
    # width, which silently assumed every coordinate is written in NMEA form.
    # **Latitude is bounded at ±90°, so a DECIMAL-degree latitude always has 1-2
    # integer digits and could never satisfy it.** The rule was structurally
    # incapable of matching any latitude on Earth in decimal form, and matched a
    # longitude only when |lon| >= 100. That is not a tuning miss, and the
    # published artifact froze the asymmetry into one sentence: a parser docstring
    # shipped reading ``<bench lat> N / -<redacted-pii> W`` — same line, same
    # position, longitude redacted and latitude shipped, because only the
    # longitude cleared three integer digits. Widening to ``\d{1,5}`` changes
    # only the NMEA-width assumption; the direction letter, which is what makes
    # this rule safe to auto-redact at all, is untouched.
    #
    # ⛔ The case-insensitive form was SPLIT IN TWO in the same pass, because
    # widening the integer width exposed a collision the old floor was
    # accidentally hiding. Case-insensitively, ``[NSEW]`` matches the SI
    # **second** suffix and the scientific-notation ``e``: ``0.000 s``,
    # ``65.536 s``, ``531.525 s``, ``1.205e-7`` all read as hemispheres, and four
    # ground-truth TOMLs duly reddened the whole-tree proof-clean invariant.
    #
    # The discriminator is **spacing, not case** — which matters, because
    # lowercase NMEA is a real, separately-tested finding (``4045.648n``), not a
    # speculative allowance, so dropping ``re.I`` outright would have discarded a
    # known leak class to fix a new one. Measured over the diaggrok source,
    # tools, and data trees: every one of the 62 lowercase matches is a unit or
    # an exponent, and every one of them has **whitespace** before the letter or
    # is an exponent continuation; the real NMEA forms are letter-ADJACENT
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
    # Canonical 4+-hex session IDs, incl. all-letter-hex (``session beef``). The
    # trailing ``\b`` is what spares legit prose: ``session cadence`` matches the
    # hex run ``cade`` but the following ``nce`` (word chars) denies the ``\b``,
    # so no match.
    # ⛔ ``re.I`` added 2026-08-03 (#N). Every rule in this set was
    # case-SENSITIVE, so a SENTENCE-INITIAL ``Session 5a3c`` — the single most
    # common way this ref is actually written in prose — evaded all of them.
    # Found while building the kismet PII gate a positive control: the gate
    # reported 10 session refs on a tree a hand count said had 11, and the
    # missing one was capitalised. It is not confined to kismet: roughly ten
    # ``Session <hex>`` refs sit in ALREADY-PUBLISHED diaggrok parser
    # docstrings, which this set is the detector for. A capitalisation is not a
    # different token, and a detector that thinks it is reports a true count of
    # the wrong question.
    re.compile(r"\bsession\s+[0-9a-f]{4,}\b", re.I),
    # (#N gap 1) Compound run-tags — ``session b113xsrc`` — where a non-hex
    # suffix (``xsrc``) denies the ``\b`` on the rule above and the tag slips by.
    # Match the hex core + alphanumeric suffix, but ONLY when the tag contains a
    # digit (the ``(?=[0-9a-z]*\d)`` lookahead). That gate is what keeps
    # ``session cadence`` (all-letter, no digit) from tripping, while all-letter-
    # hex IDs like ``session beef`` stay covered by the boundary rule above.
    re.compile(r"\bsession\s+(?=[0-9a-z]*\d)[0-9a-f]{4,}[0-9a-z]*\b"),
    # (#N gap 2) ``session``-prefixed capture timestamps — a bare
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

#: The synthetic IMEIs the trees standardised on (#N). ``123456789012345`` is
#: not Luhn-valid so it would pass the checksum anyway; ``000000000000000`` IS
#: Luhn-valid, so for that one this allowlist is genuinely load-bearing.
IMEI_PLACEHOLDERS = frozenset({"123456789012345", "000000000000000"})


def _embedded_in_hex_run(text: str, start: int, end: int) -> bool:
    """True if a digit run is a slice of a LONGER hex token (a payload blob).

    ⛔ The measured false-positive class for the IMEI rule, and it is not
    hypothetical: kp's ``diagspec/wirein_selftest_0xb97f.cpp`` carries the test
    vector ``...8ea607000101040100ff...``, in which ``607000101040100`` is a
    15-digit run **and Luhn-valid**. Both trees are full of such vectors — the
    diaggrok parser tests are nothing but wire-format hex.

    ``_IMEI15_RE``'s ``(?<!\\d)(?!\\d)`` boundaries only exclude adjacent
    *decimal* digits; the neighbours here are ``a`` and ``f``. An IMEI is
    exactly 15 digits and is never a substring of a longer hex token, so
    expanding over ``[0-9a-fA-F]`` and requiring the expansion to be the match
    itself is exact — no length heuristic, no tuning knob.

    Shared here rather than left in ``kp_leak_gate`` (#N): the constraint is a
    property of hex test vectors, not of kp.
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
    resolve rather than being silently auto-rewritten.

    Hardened 2026-08-04 (#N) with the two filters ``kp_leak_gate`` had and
    this side did not: the placeholder allowlist and the hex-run guard."""
    return [m.group() for m in _IMEI15_RE.finditer(text)
            if _luhn_ok(m.group())
            and m.group() not in IMEI_PLACEHOLDERS
            and not _embedded_in_hex_run(text, m.start(), m.end())]


# ── Subscriber identifiers (#N) — shapes, shared with the kp gate ──────────
# These three classes lived ONLY in ``tools/kp_leak_gate.py``, which gates the
# single kp -> public-kismet carve. This module is what ``carvelib.gate()`` calls
# for the FIVE chp -> public carves (diaggrok, diagmunge, diaggulp, diagbarf,
# diaggpsd), so the weaker scanner was guarding the larger surface. Promoted here
# as the single source of truth; the kp gate imports them back.
#
# ⚠️ They are REPORT-ONLY for the same reason ``_unlabeled_imeis`` is: each is a
# bare digit run, and a bare digit run is a legal integer literal. Putting them
# in ``LEAK_RES`` would let the carve redactor rewrite source in place.

#: ITU: ``89`` + issuer/account digits. 19-20 total is the shipped range.
_ICCID_RE = re.compile(r"(?<!\d)89\d{17,18}(?!\d)")
#: North-American MCCs are the only ones this bench can produce (310-316).
_IMSI_RE = re.compile(r"(?<!\d)31[0-6]\d{12}(?!\d)")
#: E.164 restricted to the NANP form with an explicit ``+``. A bare 10-digit run
#: is indistinguishable from an EARFCN/cell-id and would be pure noise.
_E164_RE = re.compile(r"(?<![\w+])\+1[2-9]\d{2}[2-9]\d{6}(?!\d)")

#: ``(rule, regex, why)`` — iterated by both this module and the kp gate, so the
#: two cannot drift in *which* classes they know about.
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


# ── High-precision coordinate shape (#N) — promoted from the kp gate ──────
# ⛔ The VALUE denylist of known bench positions deliberately does NOT live here.
# ``hostname_denylist.py`` states the rule in as many words: an enumerable value
# list must NOT be "baked into the (publicly-carved) diaggrok.pii_scan detector."
# This module is copied verbatim into every public carve
# (``diaggrok_extract.py:601``), so a bench latitude written here would be
# published BY the leak detector. The values live in the chp-private
# ``data/diag/public/coordinate_denylist.yaml``; only the SHAPE rule is here.

#: A decimal in plausible degree range. On its own this is unusable — see the
#: two structural filters below, which are what make it precise.
_DECIMAL_RE = re.compile(r"(?<![\w.])(-?\d{1,3}\.\d{4,})(?![\w.])")

_PI = 3.141592653589793


def _is_dyadic(literal: str) -> bool:
    """True if the decimal literal is exactly ``k / 2**n``.

    ⛔ This is what makes a coordinate rule usable in a DIAG tree at all. Every
    RSRP/RSRQ/RSSI value a fixed-point DIAG field produces is a dyadic rational
    by construction of the encoding (``-115.515625`` = -115 - 33/64), and those
    values sit squarely inside longitude range. Measured over kp's publishable
    set: **88 in-range decimals, of which 71 are dyadic** — one predicate removes
    four fifths of the noise structurally rather than by threshold-tuning. A GPS
    double is dyadic only by accident.
    """
    from fractions import Fraction
    denom = Fraction(literal).denominator
    return denom & (denom - 1) == 0


def _is_round_radian(value: float) -> bool:
    """True if the value is a round radian count converted to degrees.

    The second measured false-positive family: synthetic GNSS fixtures are built
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
        # ⚠️ π is compared with a TOLERANCE, not ``==`` (#N). The exact form
        # missed ``3.14159265358979`` — π truncated one digit short, which is how
        # a hand-typed π literal usually appears — and diaggpsd's
        # ``dump_pos_report.py`` carries exactly that, so the carve gate went red
        # on a math constant. Any literal within 1e-9 of π is π.
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

    The report-only set grew on 2026-08-04 (#N) to the subscriber identifiers
    and GPS-shaped decimals the kp gate already knew about: ICCID, IMSI, E.164,
    and high-precision coordinates. All are bare digit runs, so all stay OUT of
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
