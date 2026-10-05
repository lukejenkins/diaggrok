"""0x1482 — GNSS measurement data (107 B / 115 B size variants).

See the module body for the field map and the per-offset evidence.

Log name: LOG_GNSS_PDSM_POSITION_REPORT_CALLBACK_C
Also known as: LOG_GAN_SMS_START
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


# ---------------------------------------------------------------------------
# 0x1482 — GNSS measurement data (size-variant: 107B MDM9x07/9x30, 115B others)
# ---------------------------------------------------------------------------
# Cross-generation analysis:
#
#   Dataset: 4 × 1-record fixtures + a 455-record EM7511 capture
#            (high-signal GNSS session alongside an LG290P reference).
#
#   Header (8 bytes, cross-chipset-stable):
#     [0]     version         = 0x00 (u8, observed=0 only)
#     [1:3]   subtype         = 0x0da3 (u16LE, every generation)
#     [3]     byte_3          = 0x00 (u8, const)
#     [4]     byte_4          = 0x00 (u8, const across 4 fixtures; const in 455-rec em7511 corpus)
#     [5:8]   tick_counter_lo = u24LE, values cluster ~7.68M across 4 fixtures
#                               — appears to be a modem-persistent tick counter
#                               (em7511 455-rec corpus: 3 distinct values in [5],
#                                byte[6] varies across generations but const within
#                                corpus, byte[7]=0x75 invariant)
#
#   Inter-block area [8:17]:
#     [8]     byte_8          = 0x00 const
#     [9]     counter_b9      = u8, varies across generations + within corpus
#     [10:13] sig_9ac1fe      = constant signature 9a c1 fe across ALL generations
#     [13:16] varying_counter = u24LE — high-variance counter (em7511 corpus:
#                               254 distinct values in byte[13] alone — high-entropy)
#     [16]    header_signature= 0x57 const across all 5 generations (already parsed)
#
#   Body substructure at [16:] — 8-byte stride hypothesis:
#     Cross-fixture constant-byte alignment reveals repeating marker bytes at
#     [22]=0x05, [30]=0x02, [33:35]=0x27 0x12, [38]=0x3a, [41:43]=0x66 0xb0,
#     [44]=0x00.  Delta between [22]→[30]→[38] is a consistent 8 bytes,
#     suggesting a table of 8-byte slots where byte-0 of each slot is a
#     type tag (0x05 / 0x02 / 0x3a / 0x66 ...).  Slots [17:25], [25:33],
#     [33:41], [41:49] follow this pattern with matching leading markers.
#     Exact per-slot decoding still TBD — would need a larger cross-chipset
#     multi-record corpus to disambiguate dynamic vs static fields.
#
#   Constant-marker inventory (cross-chipset stable, 55 bytes within 107B common):
#     0-4, 7, 8, 10-12, 16, 22, 25-27, 30, 33, 34, 38, 41, 42, 44, 46-54,
#     60, 61, 64, 65, 67-69, 71-73, 75-77, 79-81, 89, 99-101, 103-106
#     (51% of the 107B common region is format-level constant.)
#
#   Size variants:
#     107B: MC7455 (MDM9x30), EP06A (MDM9x07), FN980m (SDX55)
#     115B: EM9190 (SDX55), EM7511 (MDM9650) — 8 extra bytes vs 107B.
#     The 8-byte delta lines up with the slot-stride hypothesis (1 extra slot
#     at the tail).  The size_class label '115_sdx55' is a size tag, not a
#     chipset tag (MDM9650 also emits the 115 B class).

# Cross-chipset signature markers (empirically stable — see docstring).
_SIG_9AC1FE = bytes.fromhex('9ac1fe')           # at offset 10..13
_MARKER_2712 = 0x1227                           # u16LE at offset 33..35
_MARKER_B066 = 0xb066                           # u16LE at offset 41..43
_HEADER_SIG_57 = 0x57                           # byte at offset 16
_MEAS_TAG_0009 = 0x0009                         # u16LE at offset 60..62 (array header)

# Cross-chipset body constants in the [17..106] region, checked on 4
# generations (MDM9x30 MC7455, MDM9x07 EP06A, SDX55 EM9190, MDM9650
# EM7511). The core set ([26] [30] [38] [49] [50]) comes from per-byte
# variance on a 575-record EM9190 drive capture, cross-checked against the
# other chipsets' single-record fixtures; a per-offset check on all 4
# fixtures adds the zero bytes in the "reserved/padding" zones around the
# active slot-stride markers. Session-invariant-only bytes such as
# [58][59][90], which vary between sessions/chipsets, are excluded, as are
# offsets covered by other validators (sig_1227 covers [33][34], sig_b066
# covers [41][42], meas_tag_0009 covers [60][61], meas_count_* cover
# [62][66][70][74][78][82][86]).
#
# Byte [27] is not in the set: it is 0x00 on the 4 fixtures above but 0x01
# on every one of 930 FN980 (SDX55) records — firmware drift, not chipset
# drift (see ``byte_27``). Markers [25][47][51..54] fail on a few FN980
# records (4-9 each, all in state-transition captures: warm GNSS restart,
# full reboot post-reset). They are kept: each holds during steady-state
# operation, and strictly on the 4 non-FN980 fixtures.
_GNSS_1482_BODY_MARKERS: tuple[tuple[int, int], ...] = (
    # core markers
    (26, 0x00), (30, 0x02), (38, 0x3A), (49, 0x00), (50, 0x00),
    # pre-[33] region ([27] excluded: firmware-specific, see byte_27)
    (22, 0x05), (25, 0x00),
    # [44..54] zero-padding block
    (44, 0x00), (46, 0x00), (47, 0x00), (48, 0x00),
    (51, 0x00), (52, 0x00), (53, 0x00), (54, 0x00),
    # [64..81] zero-padding block
    (64, 0x00), (65, 0x00), (67, 0x00), (68, 0x00), (69, 0x00),
    (71, 0x00), (72, 0x00), (73, 0x00),
    (75, 0x00), (76, 0x00), (77, 0x00),
    (79, 0x00), (80, 0x00), (81, 0x00),
    # [89..106] zero-padding block (guarded by sz > 106)
    (89, 0x00), (99, 0x00), (100, 0x00), (101, 0x00),
    (103, 0x00), (104, 0x00), (105, 0x00), (106, 0x00),
)

# Byte [27] is firmware-specific, not chipset-specific. Exposed as a
# dedicated parser field so downstream consumers can fingerprint the
# firmware variant. Observed:
#   0x00: MC7455 (MDM9x30), EP06A (MDM9x07), EM9190 (SDX55),
#         EM7511 (MDM9650)
#   0x01: FN980 (SDX55)
# The split across two SDX55 modems (EM9190 vs FN980) shows this is a
# firmware-build identifier, not a chipset-family marker.
_GNSS_1482_BYTE_27_OFFSET = 27

# Per-firmware fingerprint at payload offsets [88..98], from two SDX55
# single-record fixtures (EM9190 vs FN980) plus multi-record captures on
# EM9190, FN980, MC7455 and RM520N-GL. Per-record analysis shows the
# [94..96] byte triple is **100 % stable across every record of a given
# capture**, while [91..93] holds a per-record counter — the slot at
# [88..98] is a 3-byte firmware tag wrapped in counter/marker bytes.
#
# 115B size-class layout (SDX55/SDX62 family):
#   [88][89] = 00 00 (slot lead, stable)
#   [90]     = marker byte (0x04 on EM9190/FN980 SDX55, 0x0f on RM520N-GL SDX62)
#   [91..93] = u24LE-style counter (per-record varying)
#   [94..96] = stable 3-byte firmware fingerprint
#   [97]     = 0x00 or 0x01 (firmware-specific)
#   [98]     = either stable or near-stable per firmware
#
# 107B size-class layout (MDM9x07/MDM9x30 family):
#   [88]     = stable firmware fingerprint byte (0xc7 MC7455, 0xe5 EP06A
#              from single-record fixture)
#   [89..93] = mostly zeros with a small counter at [90]
#   [94]     = stable byte (0x07 dominant on MC7455 / 90 %, MDM9x07 fixture)
#   [95..98] = zero padding
#
# Single-record fixture bytes do not always match what the same firmware
# emits across a multi-record capture (FN980: fixture [94..96]=2a da 6e,
# capture ea 7c a8). The ``*_corpus`` entries below are the empirical
# multi-record signatures; the ``*_fixture`` entries keep the
# single-record bytes for auditability.
_GNSS_1482_FW_FINGERPRINTS: dict[str, dict[str, object]] = {
    "EM9190 SWIX55C_03.17.04": {
        "size_class": "115_sdx55",
        "modems": ("EM9190 (Sierra, SDX55)",),
        "byte_27": 0x00,                       # firmware-variant byte
        "bytes_88_89": (0x00, 0x00),
        "byte_90_fixture": 0x05,               # gnss_1482_em9190.bin (single-record fixture)
        "byte_90_corpus": 0x04,                # multi-record capture — N=88 stable
        "bytes_94_96_fixture": (0x2a, 0xc8, 0xf4),
        "bytes_94_96_corpus": (0x2a, 0xc8, 0xf4),  # 100 % stable across N=88
        "byte_97": 0x00,
        "evidence": "fixture + N=88 corpus agree on [94..96]=2a c8 f4; differ on [90] (fixture state-dependent)",
    },
    "FN980 38.03.282-P0H.000700": {
        "size_class": "115_sdx55",
        "modems": ("FN980m (Telit, SDX55)",),
        "byte_27": 0x01,                       # FN980 unique within the SDX55 family
        "bytes_88_89": (0x00, 0x00),
        "byte_90_fixture": 0x04,
        "byte_90_corpus": 0x04,
        "bytes_94_96_fixture": (0x2a, 0xda, 0x6e),
        "bytes_94_96_corpus": (0xea, 0x7c, 0xa8),  # multi-record corpus N=71, 100 % stable
        "byte_97": 0x01,
        "byte_98": 0x03,
        "evidence": "fixture and multi-record corpus diverge at [94..96]; fixture captured a different session than the corpus. Both share the FN980-discriminating byte_27=0x01.",
    },
    "RM520N-GL (SDX62)": {
        "size_class": "115_sdx55",
        "modems": ("RM520N-GL (Quectel, SDX62)",),
        "byte_27": 0x00,
        "bytes_88_89": (0x00, 0x00),
        "byte_90_corpus": 0x0f,                # distinguishes SDX62 layout from SDX55 [90]=0x04
        "bytes_94_96_corpus": (0xea, 0x97, 0x5f),
        "byte_97": 0x01,
        "evidence": "no single-record fixture; RM520N-GL multi-record capture N=915, [94..96] 100 % stable",
    },
    "MC7455 SWI9X30C_02.24.03.00": {
        "size_class": "107_mdm9x",
        "modems": ("MC7455 (Sierra, MDM9x30)",),
        "byte_27": 0x00,
        "byte_88": 0xc7,                       # 100 % stable on both fixture and corpus
        "byte_94_fixture": 0x01,               # gnss_1482_mc7455.bin (state-dependent low-byte)
        "byte_94_corpus_dominant": 0x07,       # multi-record live GNSS capture — 90.5 %
        "evidence": "fixture+corpus agree on byte_88=0xc7; byte[94] varies in the [0x01..0x07] range across records",
    },
    "EP06A 01.009.01.009 (single fixture)": {
        "size_class": "107_mdm9x",
        "modems": ("EP06A (Quectel, MDM9x07)",),
        "byte_27": 0x00,
        "byte_88": 0xe5,
        "byte_94_fixture": 0x07,
        "evidence": "single-record fixture; multi-record EP06A corpus had no 0x1482 records emitted (capture was non-GNSS-active)",
    },
    "EM7511 (single fixture)": {
        "size_class": "115_sdx55",
        "modems": ("EM7511 (Sierra, MDM9650)",),
        "byte_27": 0x00,
        "bytes_88_89": (0x00, 0x00),
        "byte_90_fixture": 0x10,               # EM7511 single fixture's [90]
        "bytes_94_96_fixture": (0xea, 0x8e, 0x22),
        "byte_97": 0x01,
        "byte_98": 0x03,
        "evidence": "single-record fixture gnss_1482_em7511_sierra_mdm9650.bin",
    },
}


@dataclass
class Diag0x1482:
    """GNSS measurement data (0x1482) — 107B/115B size-variant.

    Per-byte variance analysis across 1339 × 115B records from 4 chipsets
    (em7511 × 745, lm960 × 332, eg18na × 191, fn980m × 71) surfaced a
    count-array at payload offsets 62, 66, 70, 74, 78, 82, 86 — each a u8
    with u24 zero padding (4-byte stride, 7 entries total).  Array
    prefixed by a u16LE tag at [60..61] = 0x0009 (verified constant
    across corpus).

    **These are not per-constellation SV counts** (GPS, GLO, GAL, BDS,
    QZSS, SBAS, IRNSS), despite the seven-entry shape.  Pearson
    correlation against LG290P MSM7 ground truth across 1,158 records on
    4 chipset families (FN980 SDX55, RM500Q SDX24, EP06A MDM9x07, LM960
    Telit MDM962x) gives **no strong correlation (|r| ≥ 0.9)** and
    **every non-NaN r is negative** — meas_count_X goes DOWN as the
    reference sees MORE satellites.  Three fields (2, 3, 5) anti-
    correlate with overall sky coverage (|r| ≈ 0.6–0.83 across multiple
    constellations simultaneously), consistent with a SHARED inverse
    signal — search-candidates / unacquired-SVs / signal-quality /
    queue-depth.  Field names are kept for offset stability; the
    semantics are **open**.

    The u16LE at payload [35..36] (``sub_counter``) is high-entropy across
    the 1339-record corpus — 219 × 10 distinct byte combinations — and
    likely holds a per-record sequence or GPS millisecond counter.
    """
    log_time: int
    version: int
    subtype: int              # u16LE at [1:3] — 0x0da3 observed across all gens
    byte_3: int               # observed 0 across every record
    byte_4: int               # observed 0 across every record
    tick_counter_lo: int      # u24LE at [5:8] — ~7.68M-range persistent counter
    counter_b9: int           # byte 9 — varies per generation + per record
    sig_9ac1fe_ok: bool       # bytes [10:13] match expected 9a c1 fe signature
    varying_counter: int      # u24LE at [13:16] — high-entropy counter
    header_signature: int     # byte 16 — 0x57 across 5 chipset generations
    sig_1227_ok: bool         # u16LE at [33:35] matches 0x1227 (bytes 27 12)
    sig_b066_ok: bool         # u16LE at [41:43] matches 0xb066 (bytes 66 b0)
    sub_counter: int          # u16LE at [35:37] — high-entropy sequence/ms counter
    meas_tag_0009_ok: bool    # u16LE at [60:62] matches 0x0009 (array header tag)
    meas_count_0: int         # u8 at [62] — count 0 (semantics open, see above)
    meas_count_1: int         # u8 at [66] — count 1
    meas_count_2: int         # u8 at [70] — count 2
    meas_count_3: int         # u8 at [74] — count 3
    meas_count_4: int         # u8 at [78] — count 4
    meas_count_5: int         # u8 at [82] — count 5
    meas_count_6: int         # u8 at [86] — count 6
    sig_body_markers_ok: bool # every cross-chipset body constant in
                              # _GNSS_1482_BODY_MARKERS present (core markers +
                              # [44..54] + [64..81] + [89..106] zero-padding).
    # Named small-integer fields at [17..21]. All vary per chipset and likely
    # per record; typed u8s so downstream consumers can track them without
    # re-parsing.
    byte_17: int              # u8 at [17] — small integer, observed in [0x05..0x1f]
                              #   (FN980 emits 0x08 steady-state but reaches
                              #   0x1f during state-transition records)
    byte_18: int              # u8 at [18] — small integer (MC7455 anomaly 0x10, others 0x05)
    byte_19: int              # u8 at [19] — small integer (MC7455 anomaly 0x0e, others 0x05)
    byte_20: int              # u8 at [20] — small integer (MC7455 0x3d, others 0x3f)
    byte_21: int              # u8 at [21] — per-chipset distinct (0x6d..0x86 observed)
    # Firmware-specific byte. 0x00 on MC7455/EP06A/EM9190/EM7511; 0x01 on
    # FN980 (SDX55). Splits within the SDX55 family (EM9190 vs FN980) ⇒
    # firmware-build identifier, not a chipset-family marker.
    byte_27: int              # u8 at [27] — firmware variant identifier
    size_class: str           # '107_mdm9x' | '115_sdx55' | 'unknown'
    payload_size: int
    body_raw: bytes

    @property
    def meas_counts(self) -> list[int]:
        """All 7 measurement counts as a list — convenience for aggregators."""
        return [self.meas_count_0, self.meas_count_1, self.meas_count_2,
                self.meas_count_3, self.meas_count_4, self.meas_count_5,
                self.meas_count_6]

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1482',
            'log_time': self.log_time,
            'version': self.version,
            'subtype': self.subtype,
            'byte_3': self.byte_3,
            'byte_4': self.byte_4,
            'tick_counter_lo': self.tick_counter_lo,
            'counter_b9': self.counter_b9,
            'sig_9ac1fe_ok': self.sig_9ac1fe_ok,
            'varying_counter': self.varying_counter,
            'header_signature': self.header_signature,
            'sig_1227_ok': self.sig_1227_ok,
            'sig_b066_ok': self.sig_b066_ok,
            'sub_counter': self.sub_counter,
            'meas_tag_0009_ok': self.meas_tag_0009_ok,
            'meas_counts': self.meas_counts,
            'sig_body_markers_ok': self.sig_body_markers_ok,
            'byte_17': self.byte_17,
            'byte_18': self.byte_18,
            'byte_19': self.byte_19,
            'byte_20': self.byte_20,
            'byte_21': self.byte_21,
            'byte_27': self.byte_27,
            'size_class': self.size_class,
            'payload_size': self.payload_size,
        }


# ---------------------------------------------------------------------------
# Ground-truth recipe — v=0, RM520N-GL (Quectel SDX62, 115B class)
# ---------------------------------------------------------------------------
# The one groundable handle on 0x1482 is `meas_counts` (7 × u8). They are not
# per-constellation counts: LG290P MSM7 correlation across 1,158 records
# finds |r| < 0.9 for any per-constellation pairing, but the counts move
# TOGETHER with overall sky coverage (|r| ~ 0.6..0.83) — i.e. they track
# total tracked-SV depth, not a specific constellation. This recipe encodes exactly that falsifiable shape:
# do the meas_counts track the total number of SVs in view (GSV) / used (GSA)?
# Everything else 0x1482 decodes is counters/markers/firmware-IDs with no
# physical-quantity AT source, so the field_map carries the single honest
# anchor and nothing more.

#: Attested size classes: 107 B base layout, 115 B = base + one 8 B slot.
_SIZE_107 = 107
_SIZE_115 = 115


@register(
    0x1482, domain="gnss",
    name="0x1482",
    description="GNSS measurement data (0x1482) — 107B/115B size-variant",
    version=11,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE across MC7455 (MDM9x30), EP06A (MDM9x07), EM9190 and "
        "FN980 (SDX55), EM7511 (MDM9650) and RM520N-GL (SDX62). Header: "
        "byte[0] == 0x00 and u16LE subtype 0x0da3 at [1:3] are universal "
        "across 5 chipset fixtures and a 1339-record corpus, and gate the "
        "parser before any other byte access; tick_counter_lo, "
        "varying_counter, counter_b9 and byte_4 are extracted alongside "
        "cross-chipset signature validators (9a c1 fe at [10:13], 0x57 at "
        "[16], 0x1227 at [33:35], 0xb066 at [41:43]). Body: a 7-entry count "
        "array at [62, 66, 70, 74, 78, 82, 86] (u8 + u24 zero padding) "
        "prefixed by u16LE tag 0x0009 at [60:62], and a high-entropy "
        "sub_counter u16LE at [35:37], validated on a 1339-record corpus "
        "across 4 chipsets; the counts anti-correlate with LG290P sky "
        "coverage and are not per-constellation SV counts. "
        "sig_body_markers_ok bundles the cross-chipset body constants found "
        "by per-byte variance on a 575-record EM9190 drive capture plus a "
        "per-offset check on 4 fixtures; bytes [17..21] are exposed as named "
        "u8 fields. Byte [27] is a firmware-build identifier, not a chipset "
        "marker (EM9190 SDX55 = 0x00, FN980 SDX55 = 0x01 on all 930 FN980 "
        "records), so it is a field rather than a marker. Payloads shorter "
        "than the 107 B base layout, or 108..114 B (a partial extra 8 B "
        "slot), return None. Remaining gaps: ~30 bytes of per-record payload "
        "in [17..50] and the meaning of the count array."
    ),
    source_url="",
    issues=(),
    # Remaining opaque: ~30 bytes of per-record payload in [17..50]
    # (the non-constant slots).
    fields_parsed=30,
    fields_identified=31,
    field_invariants={
        # byte 0 + subtype + sz + header_signature are corpus constants
        # across 5 chipsets / 1339+ records. Parser-body gate covers byte 0 + subtype; layer-2 adds
        # defense-in-depth on payload_size + header_signature.
        "version": {"enum": [0]},
        "subtype": {"enum": [0x0da3]},
        "header_signature": {"enum": [0x57]},
        "payload_size": {"enum": [107, 115]},
        # byte_27 is a firmware-build discriminator with two observed
        # values across 5 chipsets and the 930-record FN980 corpus: 0x00 on
        # Sierra/Quectel modems (MC7455, EP06A, EM9190, EM7511) and 0x01 on
        # Telit FN980. The split is vendor-correlated (Sierra + Quectel =
        # 0x00, Telit = 0x01 across 8 modems / 5 chipsets). Enum-lock so a
        # third value (a new vendor stack or a firmware-rev struct
        # migration) surfaces via check_invariants() rather than silently
        # flowing through as an opaque u8.
        "byte_27": {"enum": [0x00, 0x01]},
    },
)
def parse_0x1482(log_time: int, data: bytes) -> Diag0x1482 | None:
    if len(data) < 17:
        return None
    # Hard gate on byte 0 + subtype magic BEFORE any other byte access, so
    # the signature validators (u16 at [33], [41]) never run on a foreign
    # payload. Corpus across 5 fixtures
    # (5 chipsets, 1339+ records) is unanimous: byte[0] == 0x00 and
    # bytes[1:3] u16LE == 0x0da3 (subtype = ASCII 'sub-type' marker).
    if data[0] != 0x00:
        return None
    if unpack_from('<H', data, 1)[0] != 0x0da3:
        return None
    sz = len(data)
    # The layout is the 107 B base (body markers run
    # through [106]) plus, on the 115 B class, one extra 8-byte slot. A record
    # shorter than 107 B, or one with a partial extra slot (108..114 B), is
    # truncated: return None (registry WARN) instead of a record whose
    # length-guarded fields silently read 0 / False. Longer payloads (>115 B)
    # are still accepted and labelled size_class='unknown'.
    if sz < _SIZE_107 or _SIZE_107 < sz < _SIZE_115:
        return None
    if sz == 107:
        cls = '107_mdm9x'
    elif sz == 115:
        cls = '115_sdx55'
    else:
        cls = 'unknown'
    # Signature validators guarded by length — short/unknown payloads return False.
    sig_1227_ok = sz >= 35 and unpack_from('<H', data, 33)[0] == _MARKER_2712
    sig_b066_ok = sz >= 43 and unpack_from('<H', data, 41)[0] == _MARKER_B066
    # u24LE extraction via (u16 | u8<<16) — avoids a struct padding allocation.
    tick_counter_lo = data[5] | (data[6] << 8) | (data[7] << 16)
    varying_counter = data[13] | (data[14] << 8) | (data[15] << 16)
    # sub_counter, meas_tag, and the 7-entry measurement count array.
    # Length-guarded: 115B variant has the array at payload [62..90]; the
    # 107B variant truncates the last slot, so we safely read up to the
    # available payload size.
    sub_counter = unpack_from('<H', data, 35)[0] if sz >= 37 else 0
    meas_tag_ok = sz >= 62 and unpack_from('<H', data, 60)[0] == _MEAS_TAG_0009
    # Bundled body-marker validator — each check is bounded by the payload
    # size so the 107B variant (which lacks [107+]) doesn't spuriously fail.
    sig_body_markers_ok = all(
        sz > off and data[off] == val for off, val in _GNSS_1482_BODY_MARKERS
    )
    def _cnt(off: int) -> int:
        return data[off] if sz > off else 0
    # [17..21] as named u8 fields. Length-guarded like _cnt.
    def _u8(off: int) -> int:
        return data[off] if sz > off else 0
    return Diag0x1482(
        log_time=log_time,
        version=data[0],
        subtype=unpack_from('<H', data, 1)[0],
        byte_3=data[3],
        byte_4=data[4],
        tick_counter_lo=tick_counter_lo,
        counter_b9=data[9],
        sig_9ac1fe_ok=data[10:13] == _SIG_9AC1FE,
        varying_counter=varying_counter,
        header_signature=data[16],
        sig_1227_ok=sig_1227_ok,
        sig_b066_ok=sig_b066_ok,
        sub_counter=sub_counter,
        meas_tag_0009_ok=meas_tag_ok,
        meas_count_0=_cnt(62),
        meas_count_1=_cnt(66),
        meas_count_2=_cnt(70),
        meas_count_3=_cnt(74),
        meas_count_4=_cnt(78),
        meas_count_5=_cnt(82),
        meas_count_6=_cnt(86),
        sig_body_markers_ok=sig_body_markers_ok,
        byte_17=_u8(17),
        byte_18=_u8(18),
        byte_19=_u8(19),
        byte_20=_u8(20),
        byte_21=_u8(21),
        byte_27=_u8(27),
        size_class=cls,
        payload_size=sz,
        body_raw=data[16:],
    )


