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
RM520N-GL captures paired with an LG290P reference receiver through an
NMEA splitter shows the AT NMEA port emits the **same** talker-ID set and
the same sentence types — the per-sentence counts match the DIAG 0x1CB2
stream within ~1% (window-edge effects only).  0x1CB2 is therefore a
DIAG-domain mirror of the AT NMEA stream on this firmware, not a content
superset.  Its advantage over AT NMEA is *temporal*: each record carries a
modem-side UTC ``timestamp_ms`` instead of host wallclock-on-receipt.

## F3 grounding (v0x02)

All **60** F3-bearing captures that emit 0x1CB2 v0x02 were joined capture-wide
(34,599 records). Two keys, because this log's DIAG timestamp is not a safe
join key (a client-side stream can lag the engine):

* **Sentences: grounded.** On the 20 captures where the Quectel GPS AT
  forwarder prints what it receives (``quectel_gps_atc.c`` ``nmea: %s``),
  **59,974** of the records' sentences appear in the F3 **verbatim** (10,145
  records), typically 1-4 ms of DIAG time from the record. The NMEA block is
  the forwarder's own NMEA stream, character for character.
* **``timestamp_ms`` is not the engine epoch.** On the 49 captures carrying
  the engine's ``ple_proc.c`` ``@tow_msec=%d`` print, ``timestamp_ms`` mapped
  to GPS TOW sits a capture-specific constant away from it (-111,722 s,
  +418,145 s, +174,397 s, +242,167 s, ...), with ~15 s jumps inside a
  capture. Two millisecond clocks co-varying 1:1 is not by itself a
  grounding. Where the engine's own time is resolved (warm/cold-start
  captures that also print ``gm_core.c Got position update ... FixTime``),
  the record's TOW is ~101-102 ms (p50) after the fix epoch, never equal to
  it. So ``timestamp_ms`` is a UTC system-clock stamp taken just after the
  fix, not the engine's epoch time. It reads absolute UTC ms once the clock
  is set.

## Layout (variable size — 13-byte header + NMEA block)

    [0]      u8   version                (observed 2 across every record)
    [1:9]    u64  timestamp_ms           (UTC system-clock ms, stamped ~100 ms
                                          after the fix — see above; e.g.
                                          1782614563628 matches the capture
                                          wallclock to the second. Before the
                                          clock is set it reads small values,
                                          e.g. ~1.9e6 — a relative/uptime ms.)
    [9:13]   u32  block_length           (bytes in the NMEA block; always
                                          equals ``len(payload) - 13``)
    [13:]    ascii NMEA sentences, each ``$...*XX`` + ``\r\n``

## Observed corpus

RM520N-GL (SDX62) across two firmware builds: 5,478 records from five
drive / LG290P-paired captures on the older build, and 2,245 records across
7 F3-armed captures on the newer build (475/475 parsed and 1,904/1,904
sentence-checksums valid on a single capture).  Sizes 552-987 B driven by
how many SVs are in view at each epoch (GSV payload varies with SV count).
``version==2`` and ``block_length == len(payload) - 13`` hold across
every record on both builds.  ``payload[11:13]`` (the high half
of the u32 ``block_length``) is also zero across every record on this
firmware, but the field is correctly typed as ``u32`` per its position.

A corpus-wide scan and a direct ``iter_records`` probe across 11
LG290P-paired GNSS-active captures — 5,072,511 DIAG records / ~1,350 MB
decompressed, 4 non-SDX62 chipset families — find 0x1CB2 emitted **only**
by RM520N-GL SDX62 (both firmware builds).  Both builds are the same
chipset, so this is one generation, two firmware builds.  The same
non-SDX62 captures all carry the per-sentence NMEA sibling 0x1384
(286-7,315 records each) — those modems use the DIAG NMEA encapsulation
surface, they just do not use the batched 0x1CB2 variant.  Per-chipset
zero-counts (modems / total DIAG records audited / 0x1384 records observed
/ 0x1CB2 records observed):

    MDM9x07 (EG12-GT, EG18-NA, EP06-A)      1,178,329 / 9,085 / 0
    MDM9x50/SWI9X50C (EM7511 x 2 firmwares)   720,264 / 14,284 / 0
    SDX20 (LM960 x 3 carriers)              1,347,780 / 8,638 / 0
    SDX55 (RM500Q-AE, FN980m x 2)           1,826,138 / 10,283 / 0

This is direct ``diaggrok.dlf.iter_records`` evidence, not inference from
scan metadata.

## 100% decode

Every byte of the payload is accounted for: 13 header bytes + N bytes of
ASCII NMEA.  The NMEA sentences themselves are parsed per-talker via
``parse_nmea_sentence`` imported from ``diag_0x1384`` — giving fully
structured access to GGA/RMC/GSV/GSA/VTG/GNS content without duplicating
that sentence-layer logic.

## Invariants enforced

The parser hard-rejects (returns ``None``) on any of:

- ``data[0] != 2`` — version byte must match the corpus invariant.
- ``HEADER_SIZE + block_length != len(data)`` — body length must EXACTLY
  match the declared ``block_length`` (no trailing padding, no
  truncation).  A future firmware that reuses the same 13-byte header
  layout but carries a different ``block_length`` convention will return
  ``None`` rather than silently mis-parsing.

Per-sentence NMEA 0183 §5.3 XOR-checksum validity is computed (count
surfaced as ``sentences_checksum_valid``) but does NOT cause record
rejection — malformed sentences are observable data, not parser
failure.  This count being less than ``sentence_count`` on a fresh
capture is the regression signal.

Log name: LOG_GNSS_CLIENT_API_NMEA_REPORT
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


# --- Ground-truth recipe ------------------------------------------------
# 0x1CB2 is the *batched* NMEA-over-DIAG mirror of the AT NMEA port: across
# three LG290P-paired RM520N-GL captures the AT NMEA port emits the same
# talker-ID set and the same sentence types, with per-sentence counts
# matching the DIAG stream within ~1% (window-edge only). So the AT NMEA
# port is the ground-truth source — content equality, not a raw->physical
# scale hunt. The one field AT cannot ground is timestamp_ms; F3 shows it is
# a UTC system-clock stamp taken ~100 ms after the fix (see docstring), which
# is still a modem-side timestamp that AT NMEA's host wallclock lacks.

@register(
    0x1CB2, domain="gnss",
    name="0x1CB2",
    description=(
        "Batched NMEA-over-DIAG (multiple sentences per record). "
        "13B header (version u8 + u64 timestamp_ms + u32 block_length) + "
        "ASCII NMEA block. DIAG-domain mirror of the AT NMEA stream on the "
        "validated SDX62 corpus (RM520N-GL, two firmware builds) — same "
        "talker IDs and sentence types as the AT port. timestamp_ms is a "
        "modem-side UTC system-clock stamp (~100 ms after the fix), which "
        "AT NMEA's host wallclock can't provide."
    ),
    version=2,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE from RM520N-GL SDX62 across five LG290P-paired / drive "
        "captures (5,478 records; version==2 and block_length==len(payload)-13 "
        "in 100% of records), plus a second firmware build. Header fully "
        "decoded (version, u64 timestamp_ms, u32 block_length); NMEA body split "
        "and parsed per sentence via parse_nmea_sentence (talkers, parsed "
        "sentence list); block_length must exactly equal len(payload)-13 (hard "
        "reject otherwise); per-sentence NMEA 0183 §5.3 XOR-checksum surfaced "
        "as sentences_checksum_valid. F3-grounded v0x02 on 60 F3-bearing "
        "captures (34,599 records): 59,974 record sentences printed verbatim "
        "by quectel_gps_atc.c 'nmea: %s' (20 captures). timestamp_ms is not "
        "the engine epoch — capture-specific constant offsets to ple_proc.c "
        "tow_msec, and ~101 ms after gm_core.c FixTime where the engine time "
        "is resolved; it is a UTC system-clock stamp."
    ),
    source_url="",
    fields_identified=7,
    fields_parsed=7,
    issues=(),
    primary_issue=None,
    field_invariants={"version": {"enum": [EXPECTED_VERSION]}},
    # WiGLE tagging (NMEA carrier): parsed: list[Any] carries
    # NmeaGGA/NmeaRMC/NmeaGNS dataclasses (via parse_nmea_sentence imported
    # from diag_0x1384) that expose latitude/longitude/utc_time/num_satellites/
    # hdop at dataclass level. Sibling of 0x1384; same role assignment on the
    # same parsed-sentence surface. ~1 Hz burst cadence; 5,478 records
    # validated on RM520N-GL SDX62.
    wigle_direct=True,
    wigle_roles=("position", "gnss-quality", "timing-anchor:periodic"),
    # ASCII audit: the body is an NMEA sentence block —
    # `$GBGSA,A,1,…*20`, `$GQGSA`, `$GNGSA`, `$GPVTG` (frac 1.0 on the
    # RM520N-GL SDX62 drive corpus). Tagged on the empirical NMEA carriage.
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

    # Layer-2 invariant (5,478/5,478 across the SDX62 corpus):
    # block_length must EXACTLY match the remaining payload — no trailing
    # padding, no clamping. A mismatch means a record whose layout has not
    # been validated; reject rather than silently truncate.
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
