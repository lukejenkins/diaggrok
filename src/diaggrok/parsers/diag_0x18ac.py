"""GNSS GTS time-update parser (0x18AC = LOG_GNSS_GTS_TIME_UPDATE).

0x18AC is NOT an LTE ML1 inter-frequency measurement, despite the legacy
class and constant names kept in this module. It is ``LOG_GNSS_GTS_TIME_UPDATE``
(sibling 0x18AB is listed as "GNSS GTS log"). Every record is one GTS (GNSS
Time Service, ``gts.c``) time source's (previous → updated) GPS-time pair.
Grounded byte-exact against the firmware's own ``gts.c`` F3 time-update print
on four silicon families:

    gts.c:1370 (SDX20)  "TSrc %d MSrc %d OMs %u OBias %f UpMs %u UpBias %f Diff %f Tunc %f"
    gts.c:1550 (MDM9150) "T %d M %d OMs %u OB %f UMs %u UB %f D %f Tu %f"
    gts.c:1753 (SDX55)  "T %d OMs %u OB %f UMs %u UB %f D %f Tu %f"

    v0x01 LM960 SDX20:     348/348 cell[0] == (TSrc, OMs, OBias) exact;
                           348/348 cell[1].ms == UpMs; byte1 == MSrc 348/348
    v0x01 RIS-9260 MDM9150: 477/477 (same three joins; 12 edge records lack F3)
                           — the RIS-9260 is an RSU appliance built around the
                           WNC 81UMV91M21 modem, so it counts as ONE MDM9150
                           device.
    v0x01 EG18-NA SDX20:   27/32 exact (T,OMs,OB), 32/32 UMs + MSrc
    v0x04 RM500Q SDX55:    2036/2036 cells == (T,OMs,OB) or (T,UMs)
    v0x04 CFW-3212 SDX62:  667 cells' exact (GPS week, ms, bias) printed by gts.c

The GPS week matches the calendar date of every capture (weeks 2422-2433 in
the corpus), and the intra +17 u64 advances at 19.2000 MHz (QTimer/XO) per
GPS second on all v0x01 silicon. Per-TSrc chaining: cell[0] of record N is
byte-identical to cell[1] of the previous record from the same TSrc (346/346
LM960, 3479/3479 EG12-GT).

Legacy field names:
    - ``magic_a`` (intra +3, 0x09 / 0x05) is the HIGH BYTE OF THE GPS WEEK
      (0x09 for weeks 2304-2559; 0x05 = week 1398, an unset GPS clock) — not
      a format constant and not a per-build value. It is not gated: it rolls
      to 0x0A at GPS week 2560 (late Jan 2029).
    - ``meas_f32`` / ``meas_raw`` / ``meas_high_byte`` are the GTS
      sub-millisecond bias (``bias_ms``) in ms, not a neighbour measurement.
      lte_LL1_meas_ncell.c NB_MEAS prints that fall inside the same capture
      window do not join per record, so they do not label this word.
    - The v=1 ``num_carriers`` byte is the GTS module source (MSrc,
      ``module_src``).
    - The ``LteMl1InterFreq*`` class names and ``LOG_LTE_ML1_INTER_FREQ_MEAS``
      are kept so existing imports, recipes and the Kaitai mirror keep
      resolving; new consumers should use the GTS field names.

Record framing (both versions carry two cells, PREVIOUS then UPDATED time):

    v=0x01 / 70B  — SDX20 / older silicon:
        [0]      u8   version = 0x01
        [1]      u8   module_src (legacy num_carriers; observed 0x01/0x02/0x03)
        [2..35]  cell record 1 (34B)
        [36..69] cell record 2 (34B)
    v=0x04 / 119B — SDX55+ / SDX62:
        [0]      u8   version = 0x04
        [1]      u8   num_carriers (1 on all 49,943 records / 5 chipsets)
        [2]      u8   num_cells (observed 0x01, 0x02, 0x03, 0x16; tracks the
                      cell TSrc 1:1 — CANDIDATE module source, since the SDX55
                      F3 print has no M field)
        [3..60]  cell record 1 (58B)
        [61..118] cell record 2 (58B)

No v=0x02/0x03/0x05+ is observed in any capture (131 captures, 341,742
records: v=0x01 34.4%, v=0x04 65.6%); the registry's field_invariants enum
locks the recognition envelope.

Per-cell anchors: a populated cell has the 0x01 marker at intra +0 (v=1
entry_marker) and magic_b == 0x01 (v=1 intra +16, v=4 intra +20), 100%
across ~1.18M v=1 records / 14 modem families and ~50K v=4 records from 5
chipsets (Inseego M2000, Sierra EM9190, Telit FN980m, Quectel RM500Q,
Quectel RM520N-GL). The v=4 intra +19 byte (``state_byte_19``) takes
{0x3e, 0x3f, 0x40} with a per-chipset split (M2000 0x3f, EM9190 0x40,
Quectel/Telit mixed) and is not gated.

There is no PCI / RSRP / RSRQ in this log, so ``entries`` is always empty
and WiGLE aggregation skips the code. 0x18AB is parsed by its own module.

Log name: LOG_GNSS_GTS_TIME_UPDATE
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

LOG_GNSS_GTS_TIME_UPDATE = 0x18AC
# Legacy (misidentified) name — kept so existing imports keep resolving.
LOG_LTE_ML1_INTER_FREQ_MEAS = LOG_GNSS_GTS_TIME_UPDATE

# GTS time-record prefix — identical layout at the head of every v=1 (34B) and
# v=4 (58B) cell (F3-grounded against gts.c time-update prints):
#   intra +0  u8   valid flag (0x01; v=4 also shows 0x00 on ~300 populated cells)
#   intra +1  u8   TSrc — GTS time-source id (F3 "TSrc"/"T")
#   intra +2  u16  GPS week (its high byte is the old "magic_a")
#   intra +4  u32  GPS milliseconds-of-week (F3 "OMs"/"UpMs")
#   intra +8  f32  sub-ms bias, ms (F3 "OBias"/"UpBias"; the old "meas_f32")
_GTS_TSRC_OFF = 1
_GTS_WEEK_OFF = 2
_GTS_MS_OFF = 4
_GTS_BIAS_OFF = 8
# v=1-only tail (34B cell), grounded on SDX20 + MDM9150:
#   intra +12 f32  time uncertainty, ms (F3 "Tunc"; UncBound = Tunc_new + this)
#   intra +17 u64  QTimer count latched with the time, 19.2 MHz
#   intra +25 f32  CANDIDATE — populated only for TSrc 1 (LTE, MSrc 2); not in
#                  any F3 print, so exposed raw/unnamed
_V1_TUNC_OFF = 12
_V1_QTIMER_OFF = 17
_V1_AUX_F32_OFF = 25

# v=4 framing constants. The 58-byte cell-record stride and the anchors below
# are cross-chipset-validated against ~50K v=4 records spanning Inseego
# M2000, Sierra EM9190, Telit FN980m, Quectel RM500Q, and Quectel RM520N-GL
# (4 SDX55 vendors + 1 SDX62). Other apparent constants on a single M2000
# reference (offsets +5, +10, +22) do not hold across vendors.
_V4_RECORD_SIZE = 119
_V4_OUTER_HEADER_SIZE = 3
_V4_CELL_SIZE = 58
_V4_NUM_CELLS = 2
_V4_MAGIC_A_OFF = 6   # intra-cell +3 (cell1 abs 6, cell2 abs 64)
# intra-cell +3 is the HIGH BYTE OF THE GPS WEEK — 0x09 for weeks 2304-2559,
# 0x05 on one RM520N-GL build (week 0x0576 = 1398: GPS clock unset). It is
# NOT gated (a gate on the observed set would reject every record from GPS
# week 2560, late Jan 2029). The populated-slot anchor is intra+20 (magic_b)
# == 0x01 alone; the field is still surfaced as magic_a for legacy consumers.
_V4_MAGIC_B_OFF = 23  # intra-cell +20 (cell1 abs 23, cell2 abs 81)
_V4_MAGIC_B_VAL = 0x01

# v=4 per-cell byte surfaces. Both offsets are intra-cell — add the cell base
# (3 / 61) for the absolute offset.
_V4_MEAS_WORD_OFF = 8         # intra +8..+11: the full f32-LE measurement word
_V4_MEAS_HIGH_BYTE_OFF = 11   # IEEE 754 byte-3 of an f32-LE at +8..+11
_V4_STATE_BYTE_19_OFF = 19    # cross-vendor anchor candidate (∈ {0x3e, 0x3f, 0x40})

# v=1 framing constants. Validated on 18,561 records across 4 captures / 3
# chipset families (LM960 Telit SDX20, MC7411 Sierra MDM9x07, EG18-NA Quectel
# SDX20 V2): every anchor below holds at 100.0% on every capture.
_V1_RECORD_SIZE = 70
_V1_OUTER_HEADER_SIZE = 2
_V1_CELL_SIZE = 34
_V1_NUM_CELLS = 2
# Intra-cell offsets shared with v=4:
_V1_ENTRY_MARKER_OFF = 0    # intra +0 == 0x01 (cell1 abs 2, cell2 abs 36)
_V1_ENTRY_MARKER_VAL = 0x01
_V1_MAGIC_A_OFF = 3         # intra +3: GPS-week high byte (0x09 for 2024-2029); NOT gated
_V1_MAGIC_B_OFF = 16        # intra +16 == 0x01 (cell1 abs 18, cell2 abs 52)
_V1_MAGIC_B_VAL = 0x01
# Legacy surfaces (the GTS bias word) — not invariant-enforced:
_V1_MEAS_WORD_OFF = 8        # intra +8..+11: the full f32-LE bias word
_V1_MEAS_HIGH_BYTE_OFF = 11  # f32-LE sign+exp byte, bimodal 0x3e/0xbe (mirrors v=4)


@dataclass
class LteMl1InterFreqEntry:
    """Legacy inter-frequency entry shape; never populated for 0x18AC."""
    earfcn: int
    pci: int
    rsrp: float
    rsrq: float

    def to_dict(self) -> dict[str, Any]:
        return {
            'earfcn': self.earfcn,
            'pci': self.pci,
            'rsrp': self.rsrp,
            'rsrq': self.rsrq,
        }


@dataclass
class LteMl1InterFreqV4Cell:
    """v=4 per-cell record (58B intra-cell): one GTS time record.

    The GTS prefix (``tsrc``, ``gps_week``, ``gps_ms``, ``bias_ms``) is
    F3-grounded on 2036/2036 RM500Q-AE SDX55 cells against gts.c:1753.
    Legacy surfaces kept for compatibility:

    - `meas_high_byte` (intra +11) / `meas_raw` / `meas_f32` (intra +8..+11):
      the f32-LE sub-ms bias word (== ``bias_ms``). Its top byte is bimodal
      {0x3e, 0xbe} because the bias is a small signed value (~0.125–0.5 ms).
    - `magic_a` (intra +3): the GPS-week high byte (== ``gps_week >> 8``).
    - `state_byte_19` (intra +19): observed cross-vendor enum
      {0x3e, 0x3f, 0x40}. Per-chipset bimodal — not a hard invariant;
      semantics unknown.
    """
    index: int
    abs_offset: int
    magic_a: int  # intra +3, GPS-week high byte (legacy name)
    magic_b: int  # intra +20, 0x01 on every populated cell across 5 vendors
    meas_high_byte: int  # intra +11, f32-LE sign+exp byte (bimodal 0x3e/0xbe)
    meas_raw: int        # intra +8..+11 as a LE u32 — the WHOLE f32 word (its
                         # MSB == meas_high_byte); the low 3 bytes carry the
                         # magnitude.
    meas_f32: float      # intra +8..+11 as f32-LE, rounded 6 dp. LEGACY NAME —
                         # it is the GTS sub-ms bias (== bias_ms), not dBm and
                         # not a neighbour measurement.
    state_byte_19: int   # intra +19, enum {0x3e, 0x3f, 0x40}
    raw: bytes
    # GTS time-record prefix — F3-grounded 2036/2036 cells on RM500Q-AE SDX55
    # against gts.c:1753 "T %d OMs %u OB %f UMs %u UB %f ...".
    # meas_f32 above == bias_ms (legacy name); magic_a == gps_week >> 8.
    tsrc: int = 0
    gps_week: int = 0
    gps_ms: int = 0
    bias_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            'index': self.index,
            'abs_offset': self.abs_offset,
            'magic_a': self.magic_a,
            'magic_b': self.magic_b,
            'meas_high_byte': self.meas_high_byte,
            'meas_raw': self.meas_raw,
            'meas_f32': self.meas_f32,
            'state_byte_19': self.state_byte_19,
            'tsrc': self.tsrc,
            'gps_week': self.gps_week,
            'gps_ms': self.gps_ms,
            'bias_ms': self.bias_ms,
            'raw_hex': self.raw.hex(),
        }


@dataclass
class LteMl1InterFreqV1Cell:
    """v=1 per-cell record (34B intra-cell): one GTS time record.

    The GTS fields are F3-grounded byte-exact against gts.c on LM960 SDX20
    (348/348), the RIS-9260 MDM9150 (477/477) and EG18-NA SDX20 (27/32).
    The structural anchors (intra +0 == 0x01, intra +16 == 0x01) hold on
    18,561 v=1 records across LM960 Telit SDX20, MC7411 Sierra MDM9x07 and
    EG18-NA Quectel SDX20 V2.

    `meas_high_byte` / `meas_raw` / `meas_f32` (intra +8..+11) are legacy
    names for the f32-LE sub-ms bias word (== ``bias_ms``); `magic_a` is
    the GPS-week high byte.
    """
    index: int
    abs_offset: int
    entry_marker: int     # intra +0,  0x01 on every populated cell
    magic_a: int          # intra +3,  GPS-week high byte (legacy name)
    magic_b: int          # intra +16, 0x01 on every populated cell
    meas_high_byte: int   # intra +11, f32-LE sign+exp byte (bimodal 0x3e/0xbe)
    meas_raw: int         # intra +8..+11 as a LE u32 — the WHOLE f32 word
                          # (MSB == meas_high_byte).
    meas_f32: float       # intra +8..+11 as f32-LE, rounded 6 dp. LEGACY NAME —
                          # it is the GTS sub-ms bias (== bias_ms), not a
                          # measurement.
    raw: bytes
    # GTS time record — F3-grounded byte-exact on LM960 SDX20 (348/348),
    # RIS-9260 MDM9150 (477/477), EG18-NA SDX20 (27/32).
    tsrc: int = 0             # intra +1  GTS time-source id (F3 TSrc/T)
    gps_week: int = 0         # intra +2  u16 (magic_a == gps_week >> 8)
    gps_ms: int = 0           # intra +4  u32 GPS ms-of-week (OMs / UpMs)
    bias_ms: float = 0.0      # intra +8  f32 sub-ms bias (OBias / UpBias)
    tunc_ms: float = 0.0      # intra +12 f32 time uncertainty (Tunc)
    qtimer_19m2: int = 0      # intra +17 u64 QTimer @ 19.2 MHz latched with the time
    aux_f32_25: float = 0.0   # intra +25 f32 CANDIDATE, TSrc-1 (LTE) only; unnamed

    def to_dict(self) -> dict[str, Any]:
        return {
            'index': self.index,
            'abs_offset': self.abs_offset,
            'entry_marker': self.entry_marker,
            'magic_a': self.magic_a,
            'magic_b': self.magic_b,
            'meas_high_byte': self.meas_high_byte,
            'meas_raw': self.meas_raw,
            'meas_f32': self.meas_f32,
            'tsrc': self.tsrc,
            'gps_week': self.gps_week,
            'gps_ms': self.gps_ms,
            'bias_ms': self.bias_ms,
            'tunc_ms': self.tunc_ms,
            'qtimer_19m2': self.qtimer_19m2,
            'aux_f32_25': self.aux_f32_25,
            'raw_hex': self.raw.hex(),
        }


@dataclass
class Diag0x18AC:
    """GNSS GTS time update (0x18AC); legacy class name kept for imports."""
    log_time: int
    version: int
    num_carriers: int
    entries: list[LteMl1InterFreqEntry] = field(default_factory=list)
    # v=4-only: outer-header num_cells + cell records + flattened anchor
    # values for registry-side check_invariants() enforcement.
    num_cells: int | None = None
    v4_cells: list[LteMl1InterFreqV4Cell] = field(default_factory=list)
    cell1_magic_a: int | None = None
    cell1_magic_b: int | None = None
    cell2_magic_a: int | None = None
    cell2_magic_b: int | None = None
    # v=4-only mirror of num_carriers so the field_invariants enum {1}
    # only applies to v=4 records (v=1's byte 1 is the module source,
    # which takes several values, and would otherwise be falsely
    # rejected). check_invariants() ignores None for v=1.
    v4_num_carriers: int | None = None
    # v=1-only: 2x 34B cell records + flattened anchor values for
    # registry-side check_invariants() enforcement. All None on v=4.
    v1_cells: list[LteMl1InterFreqV1Cell] = field(default_factory=list)
    v1_cell1_entry_marker: int | None = None
    v1_cell1_magic_a: int | None = None
    v1_cell1_magic_b: int | None = None
    v1_cell2_entry_marker: int | None = None
    v1_cell2_magic_a: int | None = None
    v1_cell2_magic_b: int | None = None
    # v=1: outer byte1 is the GTS module source (F3 "MSrc"/"M", 348/348 +
    # 477/477 + 32/32), the legacy num_carriers key. None on v=4.
    module_src: int | None = None
    # v=1: True when cell[0] (the PREVIOUS time of this TSrc) is all-zero —
    # the first update of a time source after boot; then v1_cells holds only
    # the updated time.
    v1_prev_empty: bool = False

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'type': 'Diag0x18AC',
            'log_time': self.log_time,
            'version': self.version,
            'num_carriers': self.num_carriers,
            'entries': [e.to_dict() for e in self.entries],
        }
        if self.version == 0x04:
            d['num_cells'] = self.num_cells
            d['v4_cells'] = [c.to_dict() for c in self.v4_cells]
            d['cell1_magic_a'] = self.cell1_magic_a
            d['cell1_magic_b'] = self.cell1_magic_b
            d['cell2_magic_a'] = self.cell2_magic_a
            d['cell2_magic_b'] = self.cell2_magic_b
            d['v4_num_carriers'] = self.v4_num_carriers
        elif self.version == 0x01:
            d['v1_cells'] = [c.to_dict() for c in self.v1_cells]
            d['v1_cell1_entry_marker'] = self.v1_cell1_entry_marker
            d['v1_cell1_magic_a'] = self.v1_cell1_magic_a
            d['v1_cell1_magic_b'] = self.v1_cell1_magic_b
            d['v1_cell2_entry_marker'] = self.v1_cell2_entry_marker
            d['v1_cell2_magic_a'] = self.v1_cell2_magic_a
            d['v1_cell2_magic_b'] = self.v1_cell2_magic_b
            d['module_src'] = self.module_src
            d['v1_prev_empty'] = self.v1_prev_empty
        return d


def _v4_no_time_slot(data: bytes, off: int) -> bool:
    """A v=4 cell reporting a time source with NO GPS time yet.

    Foxconn T99W640 builds emit, during boot, 119 B records whose updated
    cell has an all-zero GTS prefix (tsrc 0, week 0, ms 0, bias 0: intra
    +0..+19), the 0x01 marker at intra +20, and a non-zero u64 at intra +21
    — the slot where every accepted v=4 cell carries its latch count
    (~25-27 s at 19.2 MHz on these boot captures, repeated unchanged record
    to record; 34 records across 14 captures). Week 0's high byte is 0, so
    the ``magic_a != 0`` half-empty guard alone would read these as INVALID.
    Accepted ONLY in this exact shape: any other non-zero byte in +0..+19
    with magic_a 0x00 stays INVALID, so the half-empty guard still holds.
    The +21 u64 is not decoded as a QTimer here: that reading is grounded on
    v=1 (+17) only.
    """
    return (not any(data[off:off + 20])
            and data[off + 20] == _V4_MAGIC_B_VAL
            and any(data[off + 21:off + 29]))


def _gts_prefix(data: bytes, off: int) -> dict[str, Any]:
    """Decode the GTS time-record prefix shared by v=1 and v=4 cells."""
    return {
        'tsrc': data[off + _GTS_TSRC_OFF],
        'gps_week': unpack_from('<H', data, off + _GTS_WEEK_OFF)[0],
        'gps_ms': unpack_from('<I', data, off + _GTS_MS_OFF)[0],
        'bias_ms': round(unpack_from('<f', data, off + _GTS_BIAS_OFF)[0], 6),
    }


# Validation note: the RM520N-GL (SDX62) emits v=0x04. The GTS fields can be
# checked against the firmware's own gts.c time-update F3 prints (or a host
# GNSS time source); magic_a/magic_b are structural, not separately grounded.

@register(LOG_GNSS_GTS_TIME_UPDATE, domain="gnss",
    name="0x18AC",
    description="GNSS GTS time update — one time source's previous/updated GPS time (week, ms, bias, Tunc, QTimer)",
    version=18,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE on SDX20/SDX55/SDX62 and MDM9150 captures. v=4 (119B): "
        "3B outer header + 2x 58B cell records, validated on ~50K records "
        "across 5 vendors (SDX55 + SDX62), num_carriers == 1 on all 49,943 "
        "anchors-passed records. v=1 (70B): the same 2-cell skeleton with 34B "
        "cells, validated on 18,561 records across LM960 Telit SDX20, MC7411 "
        "Sierra MDM9x07 and EG18-NA Quectel SDX20 V2, with the populated-cell "
        "anchors 100% across ~1.18M v=1 records. Identity: "
        "LOG_GNSS_GTS_TIME_UPDATE — the cells are GTS time records (TSrc, GPS "
        "week, ms-of-week, sub-ms bias, Tunc, 19.2 MHz QTimer), grounded "
        "byte-exact against gts.c F3 time-update prints on SDX20 (348/348), "
        "MDM9150 (477/477), SDX55 (2036/2036 cells) and SDX62 (667 cells); "
        "there is no PCI/RSRP/RSRQ in this log. The GPS-week high byte (legacy "
        "magic_a) is not gated; a v=1 record whose previous cell is all zero "
        "(first update of a source after boot) and a v=4 'no GPS time yet' "
        "boot cell are accepted."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=24,  # aux_f32_25 is parsed but unnamed (CANDIDATE)
    fields_parsed=25,
    field_invariants={
        "version": {"enum": [0x01, 0x04]},
        # v4_num_carriers: invariantly 1 across 49,943 v=4 records / 5
        # chipsets / 4 vendors. Scoped to v=4 via the v4_num_carriers field
        # (None on v=1 records, whose byte 1 is the module source). A future
        # multi-carrier v=4 firmware variant will correctly fail this gate
        # rather than emit silent garbage from a wrong-shaped body decode.
        "v4_num_carriers": {"enum": [1]},
        # magic_a (v=4 intra+3 / v=1 intra+3) is the GPS-week high byte —
        # DATA, not an anchor, so it has no enum invariant.
        # v=4 58B-stride anchor: magic_b (intra+20) == 0x01 is the
        # cross-firmware constant (every capture examined). Only populated
        # on v=4 records; check_invariants() ignores None.
        "cell1_magic_b": {"enum": [_V4_MAGIC_B_VAL]},
        "cell2_magic_b": {"enum": [_V4_MAGIC_B_VAL]},
        # v=1 34B-stride anchors — cross-chipset validated on 18,561 records
        # across 3 chipset families (LM960 / MC7411 / EG18-NA). Only
        # populated on v=1 records; check_invariants() ignores None for v=4.
        "v1_cell1_entry_marker": {"enum": [_V1_ENTRY_MARKER_VAL]},
        "v1_cell1_magic_b":      {"enum": [_V1_MAGIC_B_VAL]},
        "v1_cell2_entry_marker": {"enum": [_V1_ENTRY_MARKER_VAL]},
        "v1_cell2_magic_b":      {"enum": [_V1_MAGIC_B_VAL]},
    },
    # GPS time ↔ QTimer pairs: a periodic timing anchor, not a cell
    # observation.
    wigle_direct=False,
    wigle_roles=("timing-anchor:periodic",),
)
def parse_0x18ac(log_time: int, data: bytes) -> Diag0x18AC | None:
    """Parse 0x18AC — GNSS GTS time update (LOG_GNSS_GTS_TIME_UPDATE).

    Both versions carry two GTS time cells — the PREVIOUS and the UPDATED
    time of one time source — each starting with the shared prefix decoded
    by _gts_prefix(). "magic_a" is the GPS-week high byte and is not gated;
    "num_carriers" (v=1) is the module source; "num_cells" (v=4) tracks the
    cell TSrc 1:1 (CANDIDATE module source — the SDX55 F3 print has no M).

    Header (both variants):
        [0]    u8   version (0x01 on SDX20 / older, 0x04 on SDX55+ / SDX62)
        [1]    u8   num_carriers (v=1: module source)

    Records whose version byte isn't in {0x01, 0x04} return None — the body
    layout is version-specific and decoding an unknown version against the
    wrong layout would produce silent garbage.

    v=0x04 framing (119B, SDX55+ / SDX62), cross-chipset-validated:
        [0]      u8   version = 0x04
        [1]      u8   num_carriers
        [2]      u8   num_cells  (observed values: 0x01, 0x02, 0x03)
        [3..60]  cell record 1  (58B)
        [61..118] cell record 2 (58B)

    A populated v=4 cell has magic_b (intra +20) == 0x01; an empty slot is
    zero padding (intra +3 and +20 both 0x00). Anything else hard-rejects
    the record.

    v=0x01 framing (70B, SDX20 / older), cross-chipset-validated:
        [0]      u8   version = 0x01
        [1]      u8   num_carriers (observed 0x01/0x02/0x03; not invariant)
        [2..35]  cell record 1 (34B)
        [36..69] cell record 2 (34B)

    A populated v=1 cell has entry_marker (intra +0) == 0x01 and magic_b
    (intra +16) == 0x01. The updated cell must be populated; the previous
    cell may be all zero. Anything else hard-rejects the record.
    """
    if len(data) < 2:
        return None

    version = data[0]
    if version not in (0x01, 0x04):
        return None
    num_carriers = data[1]

    entries: list[LteMl1InterFreqEntry] = []

    if version == 0x04:
        if len(data) != _V4_RECORD_SIZE:
            return None
        # Per-slot gate. ~50K records confirm a POPULATED slot carries
        # magic_b (intra+20) == 0x01. On single-populated-cell records one
        # 58B slot is zero-padding whose anchors are BOTH 0x00 — perfectly
        # correlated (intra+3==0x00 iff intra+20==0x00 on the empty slot;
        # e.g. an EM9291 SDX65 build emits records that use only the cell-2
        # slot). Each slot is one of:
        #   POPULATED — magic_b == 0x01 (magic_a is the GPS-week high byte —
        #               data, not an anchor)
        #   EMPTY     — magic_a == 0x00 and magic_b == 0x00 (padding)
        #   INVALID   — anything else → hard-reject (format-invariance guard)
        # At least one slot must be populated; an all-padding record is not a
        # usable time update and is rejected.
        cell1_off = _V4_OUTER_HEADER_SIZE
        cell2_off = _V4_OUTER_HEADER_SIZE + _V4_CELL_SIZE
        c1ma = data[_V4_MAGIC_A_OFF]
        c1mb = data[_V4_MAGIC_B_OFF]
        c2ma = data[_V4_MAGIC_A_OFF + _V4_CELL_SIZE]
        c2mb = data[_V4_MAGIC_B_OFF + _V4_CELL_SIZE]
        # magic_a != 0x00 keeps the half-empty guard: a 0x00 week-high-byte
        # with magic_b == 0x01 is INVALID — EXCEPT the "no GPS time yet" cell
        # (_v4_no_time_slot): week 0 legitimately has high byte 0.
        c1_pop = c1mb == _V4_MAGIC_B_VAL and (
            c1ma != 0x00 or _v4_no_time_slot(data, cell1_off))
        c2_pop = c2mb == _V4_MAGIC_B_VAL and (
            c2ma != 0x00 or _v4_no_time_slot(data, cell2_off))
        c1_empty = c1ma == 0x00 and c1mb == 0x00
        c2_empty = c2ma == 0x00 and c2mb == 0x00
        if (not c1_pop and not c1_empty) or (not c2_pop and not c2_empty):
            return None
        if not c1_pop and not c2_pop:
            return None  # both slots empty padding — no measurement
        num_cells = data[2]
        v4_cells = [
            LteMl1InterFreqV4Cell(
                index=idx,
                abs_offset=off,
                magic_a=data[off + _V4_MAGIC_A_OFF - _V4_OUTER_HEADER_SIZE],
                magic_b=data[off + _V4_MAGIC_B_OFF - _V4_OUTER_HEADER_SIZE],
                meas_high_byte=data[off + _V4_MEAS_HIGH_BYTE_OFF],
                meas_raw=int.from_bytes(
                    data[off + _V4_MEAS_WORD_OFF:off + _V4_MEAS_WORD_OFF + 4], 'little'),
                meas_f32=round(unpack_from('<f', data, off + _V4_MEAS_WORD_OFF)[0], 6),
                state_byte_19=data[off + _V4_STATE_BYTE_19_OFF],
                raw=bytes(data[off:off + _V4_CELL_SIZE]),
                **_gts_prefix(data, off),
            )
            for idx, off, pop in ((0, cell1_off, c1_pop), (1, cell2_off, c2_pop))
            if pop
        ]
        # Record-level magic fields feed check_invariants(); an empty slot's
        # magic stays None so the enum invariant skips it. check_invariants()
        # ignores None — same as the v=1 path.
        return Diag0x18AC(
            log_time=log_time,
            version=version,
            num_carriers=num_carriers,
            entries=entries,  # always empty: no cell measurements in this log
            num_cells=num_cells,
            v4_cells=v4_cells,
            cell1_magic_a=c1ma if c1_pop else None,
            cell1_magic_b=c1mb if c1_pop else None,
            cell2_magic_a=c2ma if c2_pop else None,
            cell2_magic_b=c2mb if c2_pop else None,
            v4_num_carriers=num_carriers,
        )

    # version == 0x01 — 70B SDX20-era body. Same 2-cell skeleton as v=4 but
    # with 34B per-cell records.
    if len(data) != _V1_RECORD_SIZE:
        return None
    v1_cell1_off = _V1_OUTER_HEADER_SIZE
    v1_cell2_off = _V1_OUTER_HEADER_SIZE + _V1_CELL_SIZE
    c1_marker = data[v1_cell1_off + _V1_ENTRY_MARKER_OFF]
    c1_ma     = data[v1_cell1_off + _V1_MAGIC_A_OFF]
    c1_mb     = data[v1_cell1_off + _V1_MAGIC_B_OFF]
    c2_marker = data[v1_cell2_off + _V1_ENTRY_MARKER_OFF]
    c2_ma     = data[v1_cell2_off + _V1_MAGIC_A_OFF]
    c2_mb     = data[v1_cell2_off + _V1_MAGIC_B_OFF]
    # Per-cell gate. A populated GTS time cell carries entry_marker
    # (intra+0) == 0x01 and magic_b (intra+16) == 0x01 — both 100% across
    # ~1.18M v=1 records / 14 modem families. magic_a (intra+3) is the
    # GPS-week high byte and is NOT gated (it rolls 0x09 → 0x0A at GPS week
    # 2560). cell[1] (the UPDATED time) must be populated; cell[0] (the
    # PREVIOUS time of this TSrc) may be entirely zero — the first update of
    # a source after boot (~53 corpus records). Anything else hard-rejects
    # (format guard).

    if (c2_marker != _V1_ENTRY_MARKER_VAL or c2_mb != _V1_MAGIC_B_VAL
            or c2_ma == 0x00):
        return None
    prev_empty = not any(data[v1_cell1_off:v1_cell1_off + _V1_CELL_SIZE])
    if not prev_empty and (c1_marker != _V1_ENTRY_MARKER_VAL
                           or c1_mb != _V1_MAGIC_B_VAL or c1_ma == 0x00):
        return None

    def _v1_cell(idx: int, off: int) -> LteMl1InterFreqV1Cell:
        return LteMl1InterFreqV1Cell(
            index=idx,
            abs_offset=off,
            entry_marker=data[off + _V1_ENTRY_MARKER_OFF],
            magic_a=data[off + _V1_MAGIC_A_OFF],
            magic_b=data[off + _V1_MAGIC_B_OFF],
            meas_high_byte=data[off + _V1_MEAS_HIGH_BYTE_OFF],
            meas_raw=int.from_bytes(
                data[off + _V1_MEAS_WORD_OFF:off + _V1_MEAS_WORD_OFF + 4], 'little'),
            meas_f32=round(unpack_from('<f', data, off + _V1_MEAS_WORD_OFF)[0], 6),
            raw=bytes(data[off:off + _V1_CELL_SIZE]),
            tunc_ms=round(unpack_from('<f', data, off + _V1_TUNC_OFF)[0], 6),
            qtimer_19m2=int.from_bytes(
                data[off + _V1_QTIMER_OFF:off + _V1_QTIMER_OFF + 8], 'little'),
            aux_f32_25=round(unpack_from('<f', data, off + _V1_AUX_F32_OFF)[0], 6),
            **_gts_prefix(data, off),
        )

    v1_cells = ([] if prev_empty else [_v1_cell(0, v1_cell1_off)]) + [
        _v1_cell(1, v1_cell2_off)]
    return Diag0x18AC(
        log_time=log_time,
        version=version,
        num_carriers=num_carriers,
        entries=entries,  # always empty for v=1 (no cell measurements exist)
        v1_cells=v1_cells,
        v1_cell1_entry_marker=None if prev_empty else c1_marker,
        v1_cell1_magic_a=None if prev_empty else c1_ma,
        v1_cell1_magic_b=None if prev_empty else c1_mb,
        v1_cell2_entry_marker=c2_marker,
        v1_cell2_magic_a=c2_ma,
        v1_cell2_magic_b=c2_mb,
        module_src=num_carriers,
        v1_prev_empty=prev_empty,
    )
