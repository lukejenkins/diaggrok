"""GNSS NMEA batch (log code 0x1CB2).

Batched NMEA-over-DIAG: multiple NMEA sentences concatenated into a
single record.  Distinct from 0x1384 (``diag_0x1384.py``), which
carries one sentence per record.  0x1CB2 emits a ~1 Hz burst containing
every GSV/GGA/RMC/GSA/VTG/GNS sentence produced by the location engine
for that epoch.

Each burst typically carries 9-16 sentences covering all supported
constellations: GPS (``$GP``), GLONASS (``$GL``), Galileo (``$GA``),
BeiDou (``$GB``), QZSS (``$GQ``), and combined-GNSS (``$GN``).

Relationship to the AT NMEA port: a corpus comparison across three
splitter-paired LG290P RM520N-GL R03A03 captures (2026-04-21,
2026-04-27, 2026-04-28) shows the AT NMEA port emits the **same**
talker-ID set and the same sentence types — the per-sentence counts
match the DIAG 0x1CB2 stream within ~1% (window-edge effects only).
0x1CB2 is therefore a DIAG-domain mirror of the AT NMEA stream on this
firmware, not a content superset.  Its actual advantage over AT NMEA is
*temporal*: each record is one location-engine epoch with the engine's
own ``timestamp_ms`` clock, instead of host wallclock-on-receipt
timestamps.  See the discussion in #N for the splitter-paired
falsification of the original "superset advantage" claim.

## Layout (variable size — 13-byte header + NMEA block)

    [0]      u8   version                (observed 2 across every record)
    [1:9]    u64  timestamp_ms           (monotonic 1 ms counter; aligned
                                          with other GNSS codes' ts)
    [9:13]   u32  block_length           (bytes in the NMEA block; always
                                          equals ``len(payload) - 13``)
    [13:]    ascii NMEA sentences, each ``$...*XX`` + ``\r\n``

## Observed corpus

RM520N-GL (SDX62) firmware RM520NGLAAR03A03M4G across four sessions:
2026-04-21 (662 records), 2026-04-22 wardrive (1,250), 2026-04-23
5-modem wardrive (2,330), 2026-04-27 LG290P-paired (616), and
2026-04-28 LG290P-paired (620).  Sizes 552-987 B driven by how many
SVs are in view at each epoch (GSV payload varies with SV count).
``version==2`` and ``block_length == len(payload) - 13`` hold across
every record (5,478/5,478 audited).  ``payload[11:13]`` (the high half
of the u32 ``block_length``) is also zero across every record on this
firmware, but the field is correctly typed as ``u32`` per its position.

A corpus-wide ``.scan.json`` walk on 2026-05-02 (and a direct
``iter_records`` re-probe on 2026-05-25 across 11 LG290P-paired
GNSS-active captures — 5,072,511 DIAG records / ~1,350 MB
decompressed, 4 non-SDX62 chipset families) confirms 0x1CB2 is
emitted **only** by RM520N-GL R03A03 SDX62.  Per the 2026-05-25
direct probe, the same captures all carry the per-sentence NMEA
sibling 0x1384 (286-7,315 records each) — the modems use the DIAG
NMEA encapsulation surface, they just do not use the batched 0x1CB2
variant.  Per-chipset zero-counts (modems / total DIAG records audited
/ 0x1384 records observed / 0x1CB2 records observed):

    MDM9x07 (EG12-GT, EG18-NA, EP06-A)      1,178,329 / 9,085 / 0
    MDM9x50/SWI9X50C (EM7511 x 2 firmwares)   720,264 / 14,284 / 0
    SDX20 (LM960 x 3 carriers)              1,347,780 / 8,638 / 0
    SDX55 (RM500Q-AE, FN980m x 2)           1,826,138 / 10,283 / 0

This is direct ``diaggrok.dlf.iter_records`` evidence (not sidecar
inference), so it resists the "sidecar predates parser registration"
failure mode.  Closure under #N's "≥2 QCA generations OR documented
exclusivity proof" pathway is operator-gated; the evidence trail is
present and reproducible via ``probe_0x1cb2_cross_chipset`` in the
session log.

## 100% decode

Every byte of the payload is accounted for: 13 header bytes + N bytes of
ASCII NMEA.  The NMEA sentences themselves are parsed per-talker via
``parse_nmea_sentence`` imported from ``diag_0x1384`` — giving fully
structured access to GGA/RMC/GSV/GSA/VTG/GNS content without duplicating
that sentence-layer logic.

## Invariants enforced (v2)

The parser hard-rejects (returns ``None``) on any of:

- ``data[0] != 2`` — version byte must match the corpus invariant.
- ``HEADER_SIZE + block_length != len(data)`` — body length must EXACTLY
  match the declared ``block_length`` (no trailing padding, no
  truncation).  The v1 parser silently clamped on mismatch; v2 fails
  loud per the project's DIAG-decode size-vs-format trap rule — a
  future firmware that reuses the same 13-byte header layout but
  carries a different ``block_length`` convention will return
  ``None`` rather than silently mis-parsing.

Per-sentence NMEA 0183 §5.3 XOR-checksum validity is computed (count
surfaced as ``sentences_checksum_valid``) but does NOT cause record
rejection — malformed sentences are observable data, not parser
failure.  This count being less than ``sentence_count`` on a fresh
capture is the regression signal.

## Issue tracking

Tracked by GH issue #N.  Per ``libs/diaggrok/AGENTS.md``'s
"100% decode + ≥2 QCA generations" rule, closure also accepts a
documented cross-generation exclusivity proof; the 2026-05-25
direct ``iter_records`` probe (see "Observed corpus" above) provides
that proof across 4 non-SDX62 chipset families.  Operator-gated
on whether the exclusivity-proof arm is sufficient.

=== names-block:start (auto-generated by tools/inject_names_block_parsers.py) ===

Names by source (from sources/DIAG_LOG_INDEX.yaml):
    canonical: LOG_GNSS_CLIENT_API_NMEA_REPORT
        source: qxdm_itemtype_list_zukgit_2025_04_03 (authority: community)
    aliases: (none recorded)

Source-precedence (#N): vendor_official > observation >
community (specification) > community (reference).
=== names-block:end ===
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.parsers.diag_0x1384 import parse_nmea_sentence
from diaggrok.registry import register

HEADER_SIZE = 13
EXPECTED_VERSION = 2


@dataclass
class Diag0x1CB2:
    """GNSS NMEA batch (log code 0x1CB2)."""

    log_time: int
    version: int
    timestamp_ms: int
    block_length: int
    sentences: list[str] = field(default_factory=list)
    parsed: list[Any] = field(default_factory=list)
    talkers: list[str] = field(default_factory=list)
    sentences_checksum_valid: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1CB2',
            'log_time': self.log_time,
            'version': self.version,
            'timestamp_ms': self.timestamp_ms,
            'block_length': self.block_length,
            'sentence_count': len(self.sentences),
            'sentences_checksum_valid': self.sentences_checksum_valid,
            'talkers': self.talkers,
            'sentences': self.sentences,
            'parsed': [p.to_dict() for p in self.parsed if p is not None],
        }


def _verify_nmea_checksum(sentence: str) -> bool:
    """Return True iff sentence has a well-formed ``*XX`` suffix whose
    XOR-checksum matches the body between ``$`` and ``*``.

    NMEA 0183 §5.3: the checksum is the bitwise XOR of all ASCII bytes
    between (but not including) the leading ``$`` and trailing ``*``,
    rendered as two uppercase hex digits. Sentences without a ``*`` or
    with a malformed suffix are not valid — return False rather than
    silently passing.
    """
    if not sentence.startswith('$'):
        return False
    star = sentence.rfind('*')
    if star < 1 or star + 3 > len(sentence):
        return False
    suffix = sentence[star + 1:star + 3]
    try:
        expected = int(suffix, 16)
    except ValueError:
        return False
    actual = 0
    for ch in sentence[1:star]:
        actual ^= ord(ch)
    return actual == expected


# --- Ground-truth recipe (#N) ------------------------------------------
# 0x1CB2 is the *batched* NMEA-over-DIAG mirror of the AT NMEA port. The
# parser docstring records a splitter-paired falsification (#N): across
# three LG290P-paired RM520N-GL R03A03 captures the AT NMEA port emits the
# SAME talker-ID set and the SAME sentence types, with per-sentence counts
# matching the DIAG stream within ~1% (window-edge only). So the AT NMEA
# port IS the ground-truth source — this recipe is unusually strong (content
# equality, not a raw→physical scale hunt). The one field that AT cannot
# ground is timestamp_ms: that GNSS-engine epoch clock is exactly 0x1CB2's
# advantage over AT NMEA (host wallclock-on-receipt), so it is flagged as
# having no AT reference.

@register(
    0x1CB2, domain="gnss",
    name="0x1CB2",
    description=(
        "Batched NMEA-over-DIAG (multiple sentences per record). "
        "13B header (version u8 + u64 timestamp_ms + u32 block_length) + "
        "ASCII NMEA block. DIAG-domain mirror of the AT NMEA stream on the "
        "validated SDX62 R03A03 corpus — same talker IDs and sentence "
        "types as the AT port. Adds per-epoch GNSS-engine timestamps that "
        "AT NMEA's host wallclock can't provide."
    ),
    version=2,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE from RM520N-GL SDX62 (RM520NGLAAR03A03M4G) "
        "across five splitter-paired LG290P / wardrive sessions "
        "(2026-04-21 / -22 / -23 / -27 / -28); 5,478 records validated, "
        "version==2 and block_length==len(payload)-13 in 100% of records. "
        "v2 promotion: (a) header fully decoded (version, u64 timestamp_ms, "
        "u32 block_length); (b) NMEA body split + per-sentence structural "
        "parse via parse_nmea_sentence (talkers, parsed sentence list); "
        "(c) layer-2 invariant — block_length must exactly equal "
        "len(payload)-13 (silent-clamp behavior from v1 replaced with "
        "hard reject per the project's DIAG-decode size-vs-format trap); "
        "(d) per-sentence NMEA 0183 §5.3 XOR-checksum verification, "
        "surfaced as sentences_checksum_valid."
    ),
    source_url="",
    fields_identified=7,
    fields_parsed=7,
    issues=(),
    primary_issue=None,
    field_invariants={"version": {"enum": [EXPECTED_VERSION]}},
    # WiGLE tagging (#N NMEA-carrier focus list): parsed: list[Any] carries
    # NmeaGGA/NmeaRMC/NmeaGNS dataclasses (via parse_nmea_sentence imported
    # from diag_0x1384) that expose latitude/longitude/utc_time/num_satellites/
    # hdop at dataclass level. Sibling of 0x1384; same role assignment on the
    # same parsed-sentence surface. ~1 Hz burst cadence; 5,478 records
    # validated on RM520N-GL SDX62.
    wigle_direct=True,
    wigle_roles=("position", "gnss-quality", "timing-anchor:periodic"),
    # ASCII audit (#N slice 6): the body IS an NMEA sentence block —
    # `$GBGSA,A,1,…*20`, `$GQGSA`, `$GNGSA`, `$GPVTG` (frac 1.0 on the
    # RM520N-GL SDX62 wardrive corpus). Tagged on the empirical NMEA carriage.
    ascii_kinds=("nmea",),
)
def parse_0x1cb2(log_time: int, data: bytes) -> Diag0x1CB2 | None:
    if len(data) < HEADER_SIZE:
        return None

    version = data[0]
    if version != EXPECTED_VERSION:
        return None
    timestamp_ms = unpack_from('<Q', data, 1)[0]
    block_length = unpack_from('<I', data, 9)[0]

    # Layer-2 invariant (5,478/5,478 across the SDX62 R03A03 corpus):
    # block_length must EXACTLY match the remaining payload — no trailing
    # padding, no clamping. A mismatch means we are looking at a record
    # whose layout we have not validated; reject rather than silently
    # truncate. See core-memory: DIAG-decode size-vs-format trap.
    if HEADER_SIZE + block_length != len(data):
        return None
    body = data[HEADER_SIZE:]

    text = body.decode('ascii', errors='replace')
    sentences: list[str] = []
    for line in text.split('\r\n'):
        line = line.strip('\r\n\x00 ')
        if line.startswith('$'):
            sentences.append(line)

    talkers = [s.split(',', 1)[0] for s in sentences]
    parsed = [parse_nmea_sentence(s) for s in sentences]
    sentences_checksum_valid = sum(1 for s in sentences if _verify_nmea_checksum(s))

    return Diag0x1CB2(
        log_time=log_time,
        version=version,
        timestamp_ms=timestamp_ms,
        block_length=block_length,
        sentences=sentences,
        parsed=[p for p in parsed if p is not None],
        talkers=talkers,
        sentences_checksum_valid=sentences_checksum_valid,
    )
