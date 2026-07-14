"""GNSS SV aggregate report parser (0x1544).

Variable-length GNSS log code emitted alongside per-SV measurement reports.
Observed on SDX20 V2 (EG18-NA) and SDX55 (FN980m) at ~9 Hz.  The 28-byte
header is parsed; the variable-length body carries either a TLV-wrapped
NMEA sentence or a binary per-SV tracking table (both tagged 0x01 —
discriminated by ASCII validity).

RE history:
- 2026-04-12 #N: initial clean-room RE from FN980m SDX55 and EG18-NA
  SDX20 V2 DLF captures.  Header layout confirmed by u16@24 = body_len
  invariant across 1,210 records on two chipsets.
- 2026-04-20 #N (v2): **NMEA-TLV body format identified** for the
  majority of records across all four observed chipsets:

    | Chipset            | Records | NMEA body |  % |
    |---|---:|---:|---:|
    | em7511 MDM9650     | 20,172  | 16,500+   | 82% |
    | eg18na SDX20 V2    |  5,104  |  3,958    | 78% |
    | lm960  SDX20       |  6,567  |  4,910    | 75% |
    | fn980m SDX55       |    681  |    381    | 56% |

- 2026-04-21 #N (v3): **Binary-body per-SV tracking table format
  identified** for records where tag=0x01 but the payload is non-ASCII.
  The format is an 8-byte body header followed by a table of 28-byte
  per-SV slots.  Decoded fields:

      slot[+0]   u8         constellation_code  0xff=GPS, 0xfb=GLONASS,
                                                 0x9b=SBAS
      slot[+8]   u8         sv_id               PRN / slot number
      slot[+16]  f32LE      elevation_deg
      slot[+20]  f32LE      azimuth_deg
      slot[+24]  f32LE      cn0_db_hz

  484B body → 17 SV slots; 456B body → 16 slots; 7B body → no slots
  (idle / keepalive).  On em7511 MDM9650 01.14.22.00 (19,172-record
  corpus) this decoded cleanly on 829 non-NMEA binary bodies
  (484B + 456B sizes).  Per-SV floats are sensible GNSS ranges on
  every slot inspected (elevation 0-90°, azimuth 0-360°, CN0 25-45
  dB·Hz on active SVs).

- 2026-04-21 #N (v4): SV-slot byte gaps decoded — signal_type [4],
  is_primary_family [10], tracking_flag [11], elevation_class [15];
  body-header fields body_seq_flag [3] and body_slot_count_echo [7]
  exposed.  See SvSlot dataclass docstring for the full slot layout.
- 2026-04-21 #N (v5): three remaining body-header bytes exposed as
  raw u8 (body_header_signature [4] / body_header_measurement [5] /
  body_header_enum [6]) on 5,391-record corpus.
- 2026-04-23 #N (v6): cross-chipset semantic interpretation of body-
  header bytes 4/5/6 — body[4] = ME format code (0x10 modern / 0x02
  compact); body[5] = body size echo, redundant with slot count via
  (slots*28+1) mod 256 for sig=0x10 (99.7% match); body[6] = receiver
  capability class, strictly partitions chipset families.  Exposed via
  me_format_code / body_size_echo_valid / receiver_class properties.
- 2026-05-05 #N (v7): FN980m wardriving-mode periodic-bundle sub-
  record discriminator added — 4 sub-kinds keyed by (body_len,
  body[1], body[3]).  See _FN980_PERIODIC_BUNDLE at module scope.
- 2026-05-11 #N (v8): T0→T1 semantic promotion of three header
  fields via DIAG-only cross-chipset correlation across 5 chipsets,
  55,257 records — counter2 promoted to body_format_subcode (100%
  body_kind purity per-firmware); constellation_mask documented as
  active-band bitmask (popcount ≠ num_constellations);
  sequence_counter documented as GLOBAL u8-wrapping frame counter
  (per-substream monotonicity loss is interleaving, not different
  semantics).  ref_value left at T0 — polymorphic across firmwares,
  per-firmware RE deferred.  See "v8 — header-field semantic
  interpretation" section below for the cross-chipset value tables.
- 2026-05-15 #N (v8.1, docs-only): ref_value formally classified as
  "intentionally polymorphic" per Option (b) of the issue's acceptance
  criteria — see module-level ``_REF_VALUE_INTERPRETATIONS`` lookup
  table and ``interpret_ref_value(chipset_family, value)`` helper.
  Three of five chipset families (sierra_mdm9650, sierra_sdx55,
  sdx20_legacy) now have T1 ``unix_time_like`` classification with
  documented hypotheses; sdx62_quectel and fn980_wardriving remain T0
  ``mixed`` pending per-record discriminator RE. No parsed-field
  changes; raw u32 still emitted as ``ref_value`` on the dataclass.

NMEA body layout (3-byte TLV + payload):

    off  type  name          notes
    0    u8    tag           0x01 = NMEA-ASCII content marker
    1    u16   nmea_len      length of NMEA sentence (including \r\n)
    3    byte[nmea_len]      NMEA sentence text, e.g.
                             ``$GPVTG,297.3,T,285.7,M,0.0,N,0.0,K,A*24\r\n``

Observed sentence types include standard talkers: GNGSA, GPGSV, GLGSV,
GAGSV, GPGGA, GAGGA, GNGNS, GPVTG, GAVTG, GPRMC, GARMC, GPGSA, GAGSA,
GPGLL, GPDTM, plus proprietary ``$PQGSA`` on some firmwares.

Binary-body per-SV layout (offsets relative to body, not record):

    off  type  name                  notes
    0    u8    tag                   always 0x01 (same tag as NMEA)
    1    u8    body_sub_format
    2..7 bytes body_header_reserved
    8+i*28     28-byte SV slot       for i in 0..(body_len-8)//28 - 1

Slot record (offsets within slot):

    +0   u8    constellation_code    0xff=GPS, 0xfb=GLONASS, 0x9b=SBAS
    +8   u8    sv_id                 PRN / slot number
    +16  f32LE elevation_deg
    +20  f32LE azimuth_deg
    +24  f32LE cn0_db_hz

## Header layout (28 bytes)

    Byte  0:     u8   version                (always 2)
    Byte  1:     u8   sub_type               (0, 1, 2 — correlates with body structure)
    Byte  2:     u8   sequence_counter        (wrapping u8 counter, increments per record)
    Byte  3:     u8   flags                   (observed: 0, 1, 34)
    Byte  4:     u8   num_constellations      (3, 4, 11, 16 — correlates with body size)
    Bytes 5..7:  u8   reserved[3]             (always 0)
    Byte  8:     u8   format_type             (1 or 2 — discriminates body layout)
    Bytes 9..11: u8   reserved[3]             (always 0)
    Bytes 12..13: u16  constellation_mask      (e.g., 18=0x12, 91=0x5B, 145=0x91)
    Bytes 14..15: u8   reserved[2]             (always 0)
    Bytes 16..19: u32  ref_value               (varies — possible time or config ref)
    Bytes 20..23: u32  counter2                (BODY FORMAT SUBCODE — see v8 note below)
    Bytes 24..25: u16  body_len                (exact body length = payload_size - 28)
    Bytes 26..27: u8   reserved[2]             (varies)

v8 (2026-05-11 #N) — header-field semantic interpretation:

The original v1-v7 work decoded every byte STRUCTURALLY (offset, type,
width) without naming what most header bytes MEAN.  v8 fills in three
T0-placeholder names using DIAG-only statistical correlation across
five chipsets (em7511 MDM9650, em9190 SDX55, lm960 SDX20, fn980 SDX55
wardriving, rm520ngl SDX62), totalling 55,257 records:

- ``counter2`` (u32 @ 20-23) is in fact a **body-format subcode** — a
  per-firmware classifier whose value 100%-purely predicts which body
  shape the record carries.  Cross-chipset value table:

      counter2  em7511   em9190    lm960   fn980-wd  rm520ngl
      --------  -------  --------  ------  --------  --------
        36      unknown  unknown   unknown bundle    -
        37      bin_sv   idle      bin_sv  idle      -
        38      nmea     nmea      -       -         (16 binsv)
        44      idle     idle      idle    -         -
        134     -        -         -       bundle    -

  Promoted via the ``body_format_subcode`` property (aliases counter2;
  see TestV8BodyFormatSubcode).  The integer-value semantics are firmware-
  specific (not a universal taxonomy) — they're an INTRINSIC firmware
  classifier emitted alongside the body, not an interpretation we derive.

- ``constellation_mask`` (u16 @ 12-13) is a bitmask of active
  constellation/band slots, NOT a popcount of constellations.  Empirical
  per-chipset values:

      em7511 single-band:    0x0049 (bits 0,3,6 — 3 active slots)
      em9190 multi-band:     0x0091 (bits 0,4,7 — 3 active slots)
      lm960  GLO+SBAS only:  0x0048 (bits 3,6 — 2 active slots)
      fn980  wardriving:     0x0091 / 0x015b (multi-mode)
      rm520ngl SDX62:        0x0006 / 0x009b (multi-config)

  The popcount of the mask is NOT equal to ``num_constellations`` — the
  latter is a fixed allocation count (8 or 16) reflecting receiver
  capacity, while the mask shows the actually-emitted band slots.

- ``sequence_counter`` (u8 @ 2) is a **global u8-wrapping frame index**
  across ALL body-format subcodes within a capture, NOT a per-substream
  counter.  Verified: on em7511 the dominant counter2=38 stream is 93%
  delta==1 because the non-dominant 884+478+422 ≈ 10% records of other
  subcodes interleave and "consume" frame indices.  All 256 values are
  observed in long captures (full u8 wrap).

- ``ref_value`` (u32 @ 16-19) is **formally polymorphic across chipset
  families** — no single semantic interpretation fits the observed
  corpus. The parser keeps the raw u32 on the dataclass; downstream
  consumers that want to assign meaning must call
  ``interpret_ref_value(chipset_family, value)`` and check the returned
  ``class`` ('unix_time_like' / 'mixed'). 3 of 5 chipset families
  (sierra_mdm9650, sierra_sdx55, sdx20_legacy) are at T1 with
  ``unix_time_like`` class; the SDX20 case is firmware-build-date-baked
  rather than live almanac time. SDX62 (rm520ngl) and FN980m
  wardriving remain T0 ``mixed`` — each appears to use a per-record
  discriminator (suspected counter2/body_format_subcode) that gates a
  different interpretation per record. Closing #N via Option (b):
  the polymorphism is now machine-readable via
  ``_REF_VALUE_INTERPRETATIONS`` rather than buried in a docstring.

Not present on RM520N-GL (SDX62) — partially superseded by v8 finding:
RM520N-GL DOES emit 0x1544 (12,919 records in 2026-05-10 gnss_comparison
capture), just with predominantly counter2=34 (unknown body shape) and
counter2=38 (16 binary_sv records).  The earlier "not present" claim
reflected an older firmware/capture-mode where the SDX62 didn't emit this
code.

=== names-block:start (auto-generated by tools/inject_names_block_parsers.py) ===

Names by source (from sources/DIAG_LOG_INDEX.yaml):
    canonical: LOG_QMI_MCS_QCSI_PKT
        source: qxdm_itemtype_list_zukgit_2025_04_03 (authority: community)
    aliases: (none recorded)

Source-precedence (#N): vendor_official > observation >
community (specification) > community (reference).
=== names-block:end ===
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import calcsize, unpack_from
from typing import Any

from diaggrok.registry import register

LOG_GNSS_SV_AGGREGATE = 0x1544

_HDR_FMT = '<BBBBBBBBBBBBHHIIHBB'
_HDR_SZ = calcsize(_HDR_FMT)
assert _HDR_SZ == 28, f"Expected 28, got {_HDR_SZ}"


_TAG_01 = 0x01  # body tag — distinguishes NMEA-ASCII (v2) from binary-SV (v3)

_SV_SLOT_SIZE = 28
_SV_BODY_HEADER_SIZE = 8

# v7 (2026-05-05, #N): FN980m SDX55 wardriving-mode periodic bundle.
#
# In field operation the FN980m firmware (38.03.282-P0H.000700) emits a
# periodic 5-record bundle that replaces the static-mode 0x1544 stream:
# four "data" records of distinct sizes + one 4B idle marker, repeated
# at ~1Hz throughout the wardriving capture (4×1166 + 1166 idle =
# 5,830 of 6,111 records, 95.4%).
#
# The bundle's four data sizes are byte[0]=0x01-tagged but neither
# NMEA-decode nor binary_sv-decode match.  Per #N <redacted-ref>, the
# discriminator is the (body[1], body[3]) pair plus body_len:
#
#   body_len  body[1]  body[3]   role (per <redacted-ref>)
#   --------  -------  -------   -------------------------------------
#   290       1        1         sub-record 1/4 (largest)
#   126       1        2         sub-record 2/4
#   129       1        3         sub-record 3/4
#   323       4        1         sub-record 4/4 (different kind — likely
#                                summary/footer; byte[1] discriminates
#                                from the byte[1]=1 trio)
#
# Bytes [11..23] of sub-records 1..3 share a 13-byte invariant
# fingerprint (`0c 00 27 d8 60 bf 7d 90 b3 42 01 00 00`) — looks like
# a chipset/firmware/RTC-snapshot identifier.  Sub-record 4 has
# different content there (different role).
#
# The 5th cycle entry (4B idle) already classifies as 'idle' via the
# body_len <= 8 fall-through.  We label only the 4 data sizes here.
#
# Tight criteria: only label records that match BOTH the size and the
# (byte[1], byte[3]) discriminator triple.  Rare interjections (sizes
# 21, 157, 11) and the wider FN980m static-mode variants are NOT
# labelled — they stay 'unknown' until further RE.
_FN980_PERIODIC_BUNDLE: dict[tuple[int, int, int], int] = {
    (290, 1, 1): 1,
    (126, 1, 2): 2,
    (129, 1, 3): 3,
    (323, 4, 1): 4,
}

# Constellation-code → human-readable label.  Empirically-derived labels
# from em7511 MDM9650 01.14.22.00 corpus; SV IDs in each group match the
# expected PRN / slot ranges for the named constellation (GPS 1-32,
# GLONASS 1-24, SBAS 120-158).
_CONSTELLATION_CODES = {
    0xff: 'GPS',
    0xfb: 'GLONASS',
    0x9b: 'SBAS',
}


# ─────────────────────────────────────────────────────────────────────
# `ref_value` (u32 @ 16-19) — formally polymorphic across chipset
# families (#N v8 left at T0; #N closes via Option (b)).
#
# `ref_value` is structurally a raw u32 little-endian field. Its
# *semantic* meaning is firmware-defined and varies across chipsets —
# no single T2+ interpretation fits the observed corpus. Downstream
# consumers MUST check the chipset family before assigning meaning to
# the raw value; use ``interpret_ref_value()`` below as the canonical
# resolver.
#
# Per-firmware semantic classes observed (2026-05-11 cross-chipset
# DIAG-only analysis, captures from gnss_sv_aggregate v8 RE pass):
#
#   sierra_mdm9650    'unix_time_like'    Two distinct Unix-time-like u32
#   sierra_sdx55      'unix_time_like'    snapshots per capture; values
#                                         resolve to 2019-04..2020-06 UTC;
#                                         consistent with almanac /
#                                         ephemeris reference time.
#   sdx20_legacy      'unix_time_like'    Single old timestamp per capture
#                                         (lm960 SDX20: 0x2f58c200 ≈
#                                         1995-03-04 UTC — likely
#                                         embedded firmware build date,
#                                         NOT current almanac time).
#   sdx62_quectel     'mixed'             Small-int dominant (0x06) with
#                                         occasional large u32 (0xe1854ac0
#                                         class) — likely a polymorphic
#                                         field whose interpretation
#                                         further depends on a secondary
#                                         discriminator (suspected
#                                         body_format_subcode / counter2,
#                                         per #N research-question 3).
#   fn980_wardriving  'mixed'             3-value mix with a Unix-time-
#                                         class value plus 2 small ints
#                                         (0x2c, 0x43); behaves like a
#                                         per-record interpretation
#                                         switch — suspected discriminator
#                                         is `body_format_subcode` again.
#
# This table is the source-of-truth lookup. Each entry's `class` field is
# the bound the parser will commit to today; `notes` carry the per-family
# RE state in case future work upgrades any to T2 via cross-checked
# almanac-fetch correlation or per-record discriminator decoding.
_REF_VALUE_INTERPRETATIONS: dict[str, dict[str, Any]] = {
    'sierra_mdm9650': {
        'class': 'unix_time_like',
        'sample_values': [0x5ee24480, 0x5ed4ecb0],
        'sample_decode': ['~2020-06-11 UTC', '~2020-06-01 UTC'],
        'hypothesis': 'almanac/ephemeris reference time',
        'tier': 'T1',
        'notes': (
            'em7511 highsignal capture flips ref_value mid-capture '
            '(11,541 vs 8,631 records) — likely an XTRA-data refresh '
            'boundary. T2 promotion would require correlating with '
            'AT!GPSXTRADATA? polls in a paired AT+DIAG capture.'
        ),
    },
    'sierra_sdx55': {
        'class': 'unix_time_like',
        'sample_values': [0x5cc7d680],
        'sample_decode': ['~2019-04-30 UTC'],
        'hypothesis': 'almanac/ephemeris reference time',
        'tier': 'T1',
        'notes': 'em9190 SDX55 — single value per capture observed; same family as MDM9650.',
    },
    'sdx20_legacy': {
        'class': 'unix_time_like',
        'sample_values': [0x2f58c200],
        'sample_decode': ['~1995-03-04 UTC'],
        'hypothesis': 'embedded firmware build date (NOT current almanac time)',
        'tier': 'T1',
        'notes': (
            'lm960 SDX20 — fixed 1995 epoch suggests this is a '
            'firmware-baked constant, not a live reference. Distinct '
            'from MDM9650/SDX55 behavior despite sharing the same '
            'unix_time_like class.'
        ),
    },
    'sdx62_quectel': {
        'class': 'mixed',
        'sample_values': [0x06, 0xe1854ac0, 0xe21b5ae0],
        'sample_decode': None,
        'hypothesis': (
            'small-int dominant (mode_id / agps_state) + large-u32 '
            'minority; secondary discriminator suspected'
        ),
        'tier': 'T0',
        'notes': (
            'rm520ngl SDX62 — small-int 0x06 dominates with rare '
            'large-u32 values. Per-record discriminator unidentified; '
            'cross-correlate with body_format_subcode (#N RQ-3).'
        ),
    },
    'fn980_wardriving': {
        'class': 'mixed',
        'sample_values': [0x20b0f580, 0x2c, 0x43],
        'sample_decode': None,
        'hypothesis': (
            'per-record interpretation switch — Unix-time-like in '
            'some records, mode-ID-like in others; discriminator '
            'suspected to be body_format_subcode'
        ),
        'tier': 'T0',
        'notes': (
            'Telit FN980m wardriving-mode capture (38.03.282-P0H.000700). '
            'Mix of one Unix-time-class value with 2 small ints — '
            'inconsistent with single-meaning across records. '
            'Decoding the per-record discriminator would T1-promote.'
        ),
    },
}


def interpret_ref_value(
    chipset_family: str,
    ref_value: int,
) -> dict[str, Any] | None:
    """Resolve the semantic interpretation of `ref_value` for a chipset.

    `ref_value` (u32 @ 16-19 of the 0x1544 header) is polymorphic — its
    meaning depends on which chipset family emitted the record. The
    parser keeps the raw u32 so the field is round-trippable, but
    downstream consumers that want to assign meaning should call this
    helper rather than guessing.

    Parameters
    ----------
    chipset_family : str
        Canonical family key. One of: ``sierra_mdm9650``, ``sierra_sdx55``,
        ``sdx20_legacy``, ``sdx62_quectel``, ``fn980_wardriving``.
    ref_value : int
        The raw u32 value from the parsed record's ``ref_value`` field.

    Returns
    -------
    dict | None
        Interpretation metadata: ``{'class', 'tier', 'hypothesis', ...}``
        for known families; ``None`` for unknown families (consumer
        should treat the value as opaque and not assign meaning).

    Notes
    -----
    The returned dict does NOT carry a decoded value — only the
    interpretation class plus the per-family hypothesis. To actually
    decode a unix_time_like value, the caller can pass ``ref_value`` to
    ``datetime.fromtimestamp(value, tz=UTC)`` after this helper
    confirms the class. For 'mixed' families, the caller should inspect
    the parsed record's ``counter2`` (body_format_subcode) and other
    fields before committing to a meaning.
    """
    entry = _REF_VALUE_INTERPRETATIONS.get(chipset_family)
    if entry is None:
        return None
    return dict(entry)


@dataclass
class SvSlot:
    """One row of the binary-body per-SV tracking table (28B stride).

    All float-valued fields are f32 little-endian.  Elevation is in
    degrees above the horizon (0..90).  Azimuth is in degrees clockwise
    from true north (0..360).  CN0 is in dB·Hz (typically 25..50 on
    active SVs; 0 when the SV is visible-but-not-tracked).

    Slot byte layout (14694-slot corpus from em7511 01.14.22.00 2026-04-21):

    ```
    off  type  name                       notes
     0   u8    constellation_code         0xff=GPS, 0xfb=GLONASS, 0x9b=SBAS
     1..3      reserved_zeros
     4   u8    signal_type                1=L1_GPS, 5=L1_GLONASS, 3=L1_SBAS
                                          (100% correlated with constellation)
     5..7      reserved_zeros
     8   u8    sv_id                      GPS 1-32 / GLO 65-88 / SBAS 120-158
     9         reserved_zero
    10   u8    is_primary_family          1 iff constellation == GPS; 0
                                          otherwise (band / service flag)
    11   u8    tracking_flag              2 = visible-only (CN0 == 0),
                                          3 = tracking (CN0 > 0)
                                          100% correlation with CN0 state
    12..14     reserved_zeros
    15   u8    elevation_class            3 = high-elev (≥19°), 2 = low-elev
                                          (<30°), 0 = no-elevation (SBAS)
    16   f32   elevation_deg              0..90
    20   f32   azimuth_deg                0..360
    24   f32   cn0_db_hz                  0 or 25..50
    ```

    All 28 bytes are now accounted for (18 named + 10 invariant reserved).
    """
    constellation_code: int        # raw byte (0xff / 0xfb / 0x9b / …)
    constellation_name: str | None  # 'GPS' / 'GLONASS' / 'SBAS' / None
    signal_type: int                # u8 @ 4 (1/5/3 per constellation)
    sv_id: int
    is_primary_family: int          # u8 @ 10 (1 iff GPS)
    tracking_flag: int              # u8 @ 11 (2=no-signal, 3=tracking)
    elevation_class: int            # u8 @ 15 (0/2/3)
    elevation_deg: float
    azimuth_deg: float
    cn0_db_hz: float

    def to_dict(self) -> dict[str, Any]:
        return {
            'constellation_code': self.constellation_code,
            'constellation_name': self.constellation_name,
            'signal_type': self.signal_type,
            'sv_id': self.sv_id,
            'is_primary_family': self.is_primary_family,
            'tracking_flag': self.tracking_flag,
            'elevation_class': self.elevation_class,
            'elevation_deg': self.elevation_deg,
            'azimuth_deg': self.azimuth_deg,
            'cn0_db_hz': self.cn0_db_hz,
        }


@dataclass
class Diag0x1544:
    """GNSS SV aggregate report (0x1544).

    Header + body parser.  The body can be one of four things, all
    starting with tag=0x01:
      1. NMEA-ASCII (TLV-wrapped sentence)
      2. Binary per-SV tracking table (8-byte body header + 28-byte slots)
      3. Idle / keepalive (7-byte body, no slots, no sentence)
      4. FN980m periodic bundle sub-record (#N, v7) — wardriving-mode
         5-record cycle, identified by (body_len, body[1], body[3])

    ``body_kind`` captures which interpretation was applied.  ``body_raw``
    is always preserved for downstream consumers.
    """
    log_time: int
    version: int
    sub_type: int
    sequence_counter: int
    flags: int
    num_constellations: int
    format_type: int
    constellation_mask: int
    ref_value: int
    counter2: int
    body_len: int
    body_raw: bytes
    # Discriminator: 'nmea' | 'binary_sv' | 'idle' | 'fn980_periodic_bundle'
    # | 'unknown'
    body_kind: str = 'unknown'
    # Sub-kind index 1..4 when body_kind == 'fn980_periodic_bundle' (#N);
    # None on every other body_kind.  Indexes the role within the 5-record
    # cycle: 1=290B, 2=126B, 3=129B, 4=323B.
    body_sub_kind: int | None = None
    # NMEA decode (populated when body_kind == 'nmea')
    body_tag: int | None = None           # 0x01 = tag byte (all variants)
    nmea_sentence: str | None = None      # e.g. "$GPVTG,297.3,T,...*24"
    nmea_sentence_type: str | None = None  # e.g. "GPVTG", "GNGSA"
    # Binary-SV decode (populated when body_kind == 'binary_sv')
    #   body_seq_flag: body[3] toggles 0/1 across consecutive records;
    #     looks like a sequence / fresh-data flag (even/odd split, no
    #     correlation with tracking-slot ratio).
    #   body_slot_count_echo: body[7] — echoes slot count, always equals
    #     len(sv_slots). Redundant with body_len but useful for corruption
    #     detection (mismatch would flag a malformed body).
    body_seq_flag: int | None = None
    body_slot_count_echo: int | None = None
    # v5 (2026-04-21p) — three body-header bytes exposed as raw u8.
    # v6 (2026-04-23) — semantic interpretation confirmed by
    # cross-chipset correlation on 2,028 binary_sv records × 4 chipsets
    # (em7511 MDM9650, lm960 SDX20, fn980m SDX55, eg18na SDX20 V2):
    #
    #   body[4] body_header_signature — MEASUREMENT ENGINE FORMAT CODE
    #     0x10 (modern, 1,939 records): em7511 + lm960 + eg18na
    #     0x02 (compact, 89 records): fn980m SDX55 enum=0 only
    #     Strictly binds (sig, enum) pairs: (0x10, {1,2,4}) and
    #     (0x02, 0) — no crossover observed.  See me_format_code alias.
    #
    #   body[5] body_header_measurement — BODY SIZE ECHO (corruption check)
    #     For sig=0x10: meas = (slot_count * 28 + 1) mod 256 — verified
    #       on 1,933/1,939 records (99.7%).  The 6 "mismatches" are the
    #       enum=4 wide-capture outliers (slots=99) with a different
    #       formula, not noise.
    #     For sig=0x02: meas is constant 1 across all 89 records
    #       (slots=28).
    #     Fully redundant with slot count — use body_size_echo_valid for
    #     transport-corruption detection.  See body_size_echo_valid.
    #
    #   body[6] body_header_enum — RECEIVER CAPABILITY CLASS
    #     Strongly per-chipset-family.  Observed:
    #       enum=0  → fn980m SDX55 (slots=28)
    #       enum=1  → em7511 MDM9650 + lm960 SDX20 (slots 11..18)
    #       enum=2  → eg18na SDX20 V2 (slots 20..21)
    #       enum=4  → fn980m SDX55 wide-capture (slots=99)
    #     No overlap across chipset families in 2,028 records.  The
    #     original v5 comment's {3, 5} values were not observed in this
    #     audit; the live enum set is {0, 1, 2, 4}.
    body_header_signature: int | None = None
    body_header_measurement: int | None = None
    body_header_enum: int | None = None
    sv_slots: list[SvSlot] | None = None

    @property
    def me_format_code(self) -> int | None:
        """Semantic alias for body_header_signature — Measurement Engine
        format code.  0x10 = modern, 0x02 = compact."""
        return self.body_header_signature

    @property
    def receiver_class(self) -> int | None:
        """Semantic alias for body_header_enum — receiver capability
        class; strongly per-chipset-family."""
        return self.body_header_enum

    @property
    def body_format_subcode(self) -> int:
        """v8 semantic alias for ``counter2`` — firmware-emitted body-format
        classifier.  Predicts ``body_kind`` with 100% purity for the
        majority subcode values within a single capture; per-firmware
        meaning varies (see parser-module docstring v8 note for the
        cross-chipset value table)."""
        return self.counter2

    @property
    def body_size_echo_valid(self) -> bool | None:
        """True iff the body_size_echo byte (body[5]) is consistent with
        the slot count for the observed me_format_code.

        Returns None on non-binary_sv records (echo byte is only
        populated in the binary_sv variant).
        """
        if self.body_header_signature is None or self.sv_slots is None:
            return None
        n = len(self.sv_slots)
        expected: int | None
        if self.body_header_signature == 0x10 and n != 99:
            expected = (n * 28 + 1) & 0xFF
        elif self.body_header_signature == 0x02:
            expected = 1
        else:
            # Format class with no known echo formula yet (e.g. sig=0x10
            # enum=4 wide-capture or any other unobserved pairing).
            return None
        return self.body_header_measurement == expected

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            'type': 'Diag0x1544',
            'log_time': self.log_time,
            'version': self.version,
            'sub_type': self.sub_type,
            'sequence_counter': self.sequence_counter,
            'flags': self.flags,
            'num_constellations': self.num_constellations,
            'format_type': self.format_type,
            'constellation_mask': self.constellation_mask,
            'ref_value': self.ref_value,
            'counter2': self.counter2,
            # v8 (#N): semantic alias — counter2 is firmware's intrinsic
            # body-format classifier.  Always exported (derived).
            'body_format_subcode': self.body_format_subcode,
            'body_len': self.body_len,
            'body_bytes': len(self.body_raw),
            'body_kind': self.body_kind,
            'body_tag': self.body_tag,
        }
        if self.body_sub_kind is not None:
            out['body_sub_kind'] = self.body_sub_kind
        if self.nmea_sentence is not None:
            out['nmea_sentence'] = self.nmea_sentence
            out['nmea_sentence_type'] = self.nmea_sentence_type
        if self.sv_slots is not None:
            out['sv_slots'] = [s.to_dict() for s in self.sv_slots]
            out['body_seq_flag'] = self.body_seq_flag
            out['body_slot_count_echo'] = self.body_slot_count_echo
            out['body_header_signature'] = self.body_header_signature
            out['body_header_measurement'] = self.body_header_measurement
            out['body_header_enum'] = self.body_header_enum
            # v6 semantic aliases + integrity check (all derived)
            out['me_format_code'] = self.me_format_code
            out['receiver_class'] = self.receiver_class
            out['body_size_echo_valid'] = self.body_size_echo_valid
        return out


def _decode_nmea_tlv(body: bytes) -> tuple[int | None, str | None, str | None]:
    """Decode an NMEA TLV body if present.

    Returns (body_tag, nmea_sentence, nmea_sentence_type) — all None on
    non-NMEA bodies.  TLV layout:

        body[0]       = tag byte (0x01 = NMEA-ASCII)
        body[1..2]    = u16 LE length of the NMEA text
        body[3..3+L]  = ASCII NMEA sentence (typically ends with CRLF)
    """
    if len(body) < 3:
        return None, None, None
    tag = body[0]
    if tag != _TAG_01:
        return None, None, None
    nmea_len = unpack_from('<H', body, 1)[0]
    if nmea_len == 0 or 3 + nmea_len > len(body):
        return tag, None, None
    raw = body[3:3 + nmea_len]
    # NMEA sentences start with '$'.  If not, it's another tag-0x01 payload
    # (non-NMEA) — don't decode as a sentence.
    if not raw.startswith(b'$'):
        return tag, None, None
    try:
        sentence = raw.rstrip(b'\r\n').decode('ascii')
    except UnicodeDecodeError:
        return tag, None, None
    # Sentence type is the 5-char talker+sentence code following '$'
    # e.g. "$GPVTG,..." -> "GPVTG"
    stype = None
    comma = sentence.find(',')
    if 2 <= comma <= 8:
        stype = sentence[1:comma]
    return tag, sentence, stype


def _decode_binary_sv_table(body: bytes) -> list[SvSlot] | None:
    """Decode the binary-body per-SV tracking table.

    Returns a list of SvSlot entries on success, or None if the body
    doesn't match the binary-SV format (wrong length, bad tag, etc.).

    Valid binary-SV bodies have length = 8 + N*28 for some N >= 1.
    The 8-byte body header is skipped — its structure is still under RE.
    """
    if len(body) < _SV_BODY_HEADER_SIZE + _SV_SLOT_SIZE:
        return None
    if body[0] != _TAG_01:
        return None
    slots_region = len(body) - _SV_BODY_HEADER_SIZE
    if slots_region % _SV_SLOT_SIZE != 0:
        return None
    n_slots = slots_region // _SV_SLOT_SIZE
    slots: list[SvSlot] = []
    for i in range(n_slots):
        off = _SV_BODY_HEADER_SIZE + i * _SV_SLOT_SIZE
        cc = body[off]
        sig_type = body[off + 4]
        sv_id = body[off + 8]
        is_primary = body[off + 10]
        tracking = body[off + 11]
        elev_class = body[off + 15]
        elevation_deg = unpack_from('<f', body, off + 16)[0]
        azimuth_deg = unpack_from('<f', body, off + 20)[0]
        cn0_db_hz = unpack_from('<f', body, off + 24)[0]
        slots.append(SvSlot(
            constellation_code=cc,
            constellation_name=_CONSTELLATION_CODES.get(cc),
            signal_type=sig_type,
            sv_id=sv_id,
            is_primary_family=is_primary,
            tracking_flag=tracking,
            elevation_class=elev_class,
            elevation_deg=elevation_deg,
            azimuth_deg=azimuth_deg,
            cn0_db_hz=cn0_db_hz,
        ))
    return slots


# ---------------------------------------------------------------------------
# Ground-truth recipe (#N) — v=0x02, RM520N-GL (Quectel SDX62)
# ---------------------------------------------------------------------------
# 0x1544 is among the cleanest GNSS grounding targets in the corpus: in its
# `binary_sv` body it decodes a real per-SV sky table (sv_id / elevation /
# azimuth / C/N0), and in its `nmea` body it carries a literal NMEA sentence.
# Both map by DIRECT comparison to the modem's own GNSS surface — the per-SV
# table to `AT+QGPSGNMEA="GSV"`/`"GSA"`, the embedded sentence to whichever
# QGPSGNMEA talker matches `nmea_sentence_type`. The header counters/format
# bytes are structural (no physical-quantity AT source) and are deliberately
# left out of the field_map — grounding them would overclaim.

@register(
    LOG_GNSS_SV_AGGREGATE, domain="gnss",
    name="0x1544",
    description=(
        "Variable-length GNSS SV aggregate report (0x1544) — header + "
        "quad-mode body decode: NMEA sentence, binary per-SV tracking "
        "table, idle/keepalive, or FN980m wardriving-mode periodic "
        "bundle sub-record (all tag=0x01)."
    ),
    version=9,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "v1/v2: Clean-room RE from FN980m SDX55 + EG18-NA SDX20 V2 DLF "
        "captures (#N).  v2: NMEA-ASCII TLV body decode.  v3 "
        "(2026-04-21): binary-body per-SV tracking table decode "
        "(constellation_code / sv_id / elevation / azimuth / CN0) + "
        "body_kind discriminator.  v4 (2026-04-21): slot-byte gaps "
        "decoded — signal_type [4], is_primary_family [10], "
        "tracking_flag [11], elevation_class [15]; body-header fields "
        "body_seq_flag [3] and body_slot_count_echo [7] exposed.  "
        "Validated on 14694-slot corpus from 884 binary-SV bodies "
        "(em7511 MDM9650 01.14.22.00).  v5 (2026-04-21p): three "
        "remaining body-header bytes exposed on 5,391-record corpus.  "
        "v6 (2026-04-23): semantic interpretation confirmed by "
        "cross-chipset correlation on 2,028 binary_sv records × 4 "
        "chipsets.  body[4] = ME format code (0x10 modern, 0x02 "
        "compact); body[5] = body size echo, redundant with slot "
        "count via (slots*28+1) mod 256 for sig=0x10 — 99.7% match; "
        "body[6] = receiver capability class, strictly partitions "
        "chipset families.  v7 (2026-05-05, #N): FN980m wardriving "
        "periodic-bundle sub-record discriminator added — 4 sub-kinds "
        "keyed by (body_len, body[1], body[3]): (290,1,1)→1, "
        "(126,1,2)→2, (129,1,3)→3, (323,4,1)→4.  Surfaces the 95.4% "
        "of FN980m wardriving 0x1544 records that were previously "
        "classified as 'unknown'.  v8 (2026-05-11): T0→T1 semantic "
        "promotion of three header fields via DIAG-only cross-chipset "
        "statistical correlation (5 chipsets, 55,257 records).  "
        "counter2 promoted to body_format_subcode — firmware-intrinsic "
        "body-format classifier with 100% purity → body_kind for the "
        "majority subcode values per capture.  constellation_mask "
        "documented as active-band bitmask (popcount ≠ "
        "num_constellations).  sequence_counter documented as GLOBAL "
        "u8-wrapping frame counter across all subcodes.  ref_value "
        "left at T0 — polymorphic across firmwares."
    ),
    source_url="",
    # v=5 field count: 11 header + 7 body-header (tag, seq_flag,
    # slot_count_echo, signature, measurement, enum, discriminator) +
    # 10 slot fields (×N slots) + NMEA alternative (sentence, type) =
    # 19 + 7 = 26 parsed / 26 identified on binary_sv variant (every
    # byte of slot + body header named).  NMEA variant: 15 parsed /
    # 15 identified.  (#N)
    fields_parsed=26,
    fields_identified=26,
    # version=0x02 confirmed across 451,819 records / 188 captures /
    # 4+ chipset generations (MDM9x07 / MDM9x30 / MDM9650 / SDX20 /
    # SDX20 V2 / SDX55 / SDX62) by 2026-05-08 corpus walk. Per
    # core-memories rule "size invariance ≠ format invariance": this
    # invariant declaration is REQUIRED, not optional — without it a
    # future v=0x03 record with the same byte count would silently
    # mis-parse as v=0x02 and emit garbage downstream. (#N)
    field_invariants={
        "version": {"enum": [0x02]},
    },
    # WiGLE tagging: chain-1 row #N of #N Phase 6 cluster 1.  Per-SV
    # cn0_db_hz + tracking_flag + sky-geometry (elevation_deg /
    # azimuth_deg) + sv_id + constellation_name are exposed at the
    # SvSlot dataclass level (lines 419-476) — these are the raw inputs
    # the receiver runs its fix-quality interpretation on, which is
    # exactly what WiGLE's GNSS-capture quality columns reflect.  No
    # identity / position / PCI-EARFCN at dataclass level: position
    # lives in 0x1476 (Phase 3), not here.
    wigle_direct=True,
    wigle_roles=("gnss-quality",),
    ascii_kinds=("config-token", "identifier", "nmea"),  # config dump ALSO embeds device IMEI (15-digit) (#N); nmea path ($GPVTG/$GNVTG/$GBVTG, +CGPSINFO) confirmed cross-vendor in the Telit+SIMCom slice (FN980m + SIM8202G-M2)
    # #N is the canonical "decode GNSS SV Aggregate" diag-decode tracker for
    # THIS code (sub-issues #N/#N; the RE history above is all #N); #N
    # is the wigle-tagging bulk issue. Was issues=() with the real decode
    # tracker only in the docstring — fixed so #N is discoverable from metadata
    # (see the project-wide audit).
    issues=(),
    primary_issue=None,
)
def parse_0x1544(log_time: int, data: bytes) -> Diag0x1544 | None:
    """Parse a GNSS SV Aggregate (0x1544) log payload.

    Returns None if the payload is too short for the header.
    """
    if len(data) < _HDR_SZ:
        return None

    (version, sub_type, sequence_counter, flags,
     num_constellations, _r0, _r1, _r2,
     format_type, _r3, _r4, _r5,
     constellation_mask, _r6,
     ref_value, counter2,
     body_len, _r7, _r8) = unpack_from(_HDR_FMT, data)

    # Layer-1 version gate (#N, #N audit family). Mirrors the
    # field_invariants enum at parse time so a future v=0x03 record
    # rejects early instead of populating a Diag0x1544 whose body-
    # discrimination logic below was tuned against the 451,819-record
    # v=0x02 corpus. Cheap belt-and-suspenders next to the layer-2
    # invariant.
    if version != 0x02:
        return None

    body_raw = data[_HDR_SZ:_HDR_SZ + body_len] if body_len > 0 else b''
    body_tag, nmea_sentence, nmea_sentence_type = _decode_nmea_tlv(body_raw)

    # Discriminate body sub-format.  NMEA wins when a valid sentence is
    # present; otherwise try binary-SV; otherwise idle / fn980-bundle /
    # unknown.
    body_kind = 'unknown'
    body_sub_kind: int | None = None
    sv_slots = None
    body_seq_flag: int | None = None
    body_slot_count_echo: int | None = None
    body_header_signature: int | None = None
    body_header_measurement: int | None = None
    body_header_enum: int | None = None
    if nmea_sentence is not None:
        body_kind = 'nmea'
    elif body_len > 0:
        sv_slots = _decode_binary_sv_table(body_raw)
        if sv_slots is not None:
            body_kind = 'binary_sv'
            # Body-header fields valid only on binary-SV variant
            body_seq_flag = body_raw[3]
            body_slot_count_echo = body_raw[7]
            body_header_signature = body_raw[4]
            body_header_measurement = body_raw[5]
            body_header_enum = body_raw[6]
        elif body_len <= 8:
            # Too short to hold any SV slots — treat as idle/keepalive.
            body_kind = 'idle'
        elif (
            body_len >= 4
            and body_raw[0] == _TAG_01
            and (sub_kind := _FN980_PERIODIC_BUNDLE.get(
                (body_len, body_raw[1], body_raw[3])
            )) is not None
        ):
            # #N: FN980m wardriving-mode 5-record cycle sub-record.
            body_kind = 'fn980_periodic_bundle'
            body_sub_kind = sub_kind

    return Diag0x1544(
        log_time=log_time,
        version=version,
        sub_type=sub_type,
        sequence_counter=sequence_counter,
        flags=flags,
        num_constellations=num_constellations,
        format_type=format_type,
        constellation_mask=constellation_mask,
        ref_value=ref_value,
        counter2=counter2,
        body_len=body_len,
        body_raw=body_raw,
        body_kind=body_kind,
        body_sub_kind=body_sub_kind,
        body_tag=body_tag,
        nmea_sentence=nmea_sentence,
        nmea_sentence_type=nmea_sentence_type,
        body_seq_flag=body_seq_flag,
        body_slot_count_echo=body_slot_count_echo,
        body_header_signature=body_header_signature,
        body_header_measurement=body_header_measurement,
        body_header_enum=body_header_enum,
        sv_slots=sv_slots,
    )
