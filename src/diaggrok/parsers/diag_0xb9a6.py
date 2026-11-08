"""0xB9A6 — NR cell acquisition timeline: per-stage frame + USTMR stamps, RF config id, target cell.

Emitted once per NR cell add / change on an EN-DC camp, at the END of the
acquisition: the record's ``total`` stage closes 0.4-0.6 ms before its DIAG
timestamp, and 0xB9BE / 0xB9BF (the same acquisition's request / confirm)
follow 0.4 ms later. Its per-capture count equals 0xB9BE's in every capture.

| version | silicon | records | emitters | sizes |
|---|---|--:|---|---|
| v0x01 | SDX55 | 57 | FX2000 (39), M2000 (14), RM500Q-AE (4) | 256 / 272 |
| v0x02 | SDX55 (newer builds) | 41 | R500L5 (40), FT980m (1) | 264 / 280 |
| v0x02 | SDX65 | 3 | M3100 | 504 (264 B + 240 B zero padding) |

The corpus is 101 records in 26 captures, and 101/101 decode with
``layout_valid``.

Layout (little-endian, payload-relative; ``H`` = header length, 36 for v0x01,
44 for v0x02)::

     0  u8   version          0x01 / 0x02
     1  u8   reserved_b1      0x00 on every record
     2  u16  tag              0x0002 on every record (0xB9BE's tag too)
   v0x02 only, inserted here (shifts the rest by 8):
     4  u32  v2_time_word     acquired NR cell time, 0xB9BE's u32 packing
     8  u32  v2_field_8       = config_id, or ahead of it by 1-6 (see below)
   common block (offsets for v0x01; +8 for v0x02):
     4  u32  hdr_word_4       0x00202000 (55) / 0 (2) on v0x01
     8  u32  hdr_word_8       0
    12  u32  hdr_word_12      0
    16  u32  config_id        RF config id of the acquisition's tune
    20  u32  hdr_word_20      0x80200001 (v0x01) / 0x00010041 (v0x02)
    24  u32  hdr_word_24      0
    28  u32  hdr_word_28      0x8020 (or 0 on some v0x02)
    32  u32  hdr_word_32      0x10000
     H  7 x 28 B  stage slots, index 0..6 (slot 6 = total)
  H+196 cell list (variable, see below)

### `config_id` — GROUNDED, F3 (v0x01 10/10, v0x02 1/1)

The firmware's own label for this value is the RF config id. Every v0x01 record
in the FX2000 rat-lock capture (10/10) prints its own value at
``rflte_mc_config.c:1268 "Move to the latest scouting config_id N"`` and
``nrfw_cmd_proc_sys.c:2033 "NRFW Tune: config id N tune needed 1"`` (12 ms
before the record). One NR add costs five config ids, which is why consecutive
records step by 5. The v0x02 offset is @24, and it is checked on its own record.
The R500L5 COPS-dereg record (config_id 695) has
``rflte_mc_config.c:1306 "... config_id 695"`` and ``nrfw_cmd_proc_sys.c:2350
"NRFW Tune: config id 695"`` (-12.4 ms) in its window. The same record's
``total`` ends 0.47 ms before it, and its end word (sfn 153, subframe 4)
matches ``RX_IU_TIME_UPDATE sysframe = 153`` at -4.70 ms. That makes the v0x02
F3 check n=1, on top of the 44/44 structural joins below.

The ``0x60`` events label the target cell and are silent on everything else.
On 10/10 FX2000 rat-lock records, ``EVENT_NR5G_RRC_HO_STARTED_V2`` (-58 ms) and
``EVENT_NR5G_RRC_NEW_CELL_IND_V2`` (+15 ms) carry the target's SSB NR-ARFCN
(and its PCI, which this record does not hold).

### Stage slot (28 B) — GROUNDED

::

     0  u32  index            0..6, equal to the slot position on every record
     4  u32  start time word  u16 form (shared decode with 0xB9BE)
     8  u32  end time word
    12  u32  ustmr_start      19.2 MHz USTMR, 24-bit
    16  u32  ustmr_end
    20  u32  duration_raw     i16 in the low half: frame-time end - start
    24  u32  ticks_raw        u32(ustmr_end - ustmr_start)

* **USTMR stamps.** They are the low 24 bits of the 19.2 MHz counter that MCPM
  F3 prints in full (``begin time = 0x542c538e8``). Projecting that F3 counter
  onto the record's DIAG clock puts the ``total`` stage's end 0.38-0.62 ms
  before the record's timestamp on 10/10 FX2000 records, with no gaps between
  consecutive stages. The firmware subtracts in 32 bits, so a stage that
  straddles the 24-bit wrap stores ``ticks_raw`` = 0xFF......; ``ustmr_ticks``
  is the masked, correct span.
* **Time words.** These use the 0xB9BE u16 form: sfn in bits 0-9, subframe in
  bits 10-13, a flag in byte 2 and a time base in byte 3.
  ``time_base`` 1 (0 on the two 15 kHz n71 records, as with 0xB9BE's
  ``time_hi``, so possibly the SSB numerology) is the acquired NR cell's frame
  timing. The ``total`` end word's sfn/subframe matches
  ``nrfw_rx_iu_tasks.c:1305 "RX_IU_TIME_UPDATE: ... sysframe = N,
  fr_unit_slotn = 0"`` projected forward, on 10/10 FX2000 records (residual
  -0.26..-0.31 ms, the subframe truncation) and 1/1 R500L5 v0x02 record. The
  following 0xB9BE's time word, logged 0.4 ms later, is the same frame time or
  one subframe later on 101/101 pairs (35 equal, 66 one later), in both of
  0xB9BE's packings.
  ``time_base`` = 5 is a pre-acquisition base. Its sfn starts at 1023 on every
  record that uses it, and it is not named further. One R500L5 post-reboot
  record is timed in base 1 throughout, and its ``total`` duration (34) is a
  real same-base length that matches its USTMR span.
* **duration.** The low 16 bits are a signed frame-time difference reduced to
  [-5120, 5120) ms. When both ends share a time base it is the stage's length,
  which agrees with ``ustmr_ticks / 19200`` within 1 ms (190/190). On the
  ``total`` slot the two ends are in different bases, so the value is a
  base-offset artifact and not a duration; use ``ustmr_ticks``.
  ``duration_ms`` is the signed low 16 bits (249/249 match the reduction).
* Slot 1 is all-zero on every record. Slots 4 and 5 are all-zero except on
  the M3100 (SDX65), where both are populated in time base 1. Slot 5 obeys
  the arithmetic above. Slot 4 does not. Its ``ustmr_end`` is exactly 124800
  ticks (6.5 ms) BEFORE its ``ustmr_start`` (3/3), its start equals the
  ``total`` end, and its duration / ticks are not end - start. It is surfaced
  raw. Slot 2 has a start and an all-zero end on some records (stage opened,
  never closed), including all three M3100 records.

### Cell list — the target cell is GROUNDED

A sequence of entries, each a ``u32 cell_id`` followed by a 16 B body. An entry
whose id is 0 has no body. On 256/264 B records the list is ``[0][target]``,
and on 272/280 B records it is ``[other][target]``. The last entry with a body
is the cell being acquired. The M3100 follows its ``[0][target]`` with 240
zero bytes (60 zero words), which are counted as ``pad_words`` and not as
empty entries::

     0  u32  cell_id          CANDIDATE id; target ids step +1 per acquisition
     4  u32  cell_word_4      packed, unnamed (0x104140, 0x254140, 0x185230 ...)
     8  u32  ssb_arfcn        SSB NR-ARFCN
    12  u32  ul_centre_arfcn  UL carrier centre NR-ARFCN
    16  u32  cell_word_16     0x1f (30 kHz cells) / 0x13 (the 15 kHz n71 cell)

* ``ssb_arfcn``: the target's equals the following 0xB9BE's ``nr_arfcn`` (which
  is grounded against the RRC reconfiguration) on 101/101 records.
* ``ul_centre_arfcn``: equals ``frequencyInfoUL.absoluteFrequencyPointA +
  carrierBandwidth * 12 * SCS / 2`` in raster units, per QCSuper's decode of
  the co-timed RRC reconfiguration. This holds on FX2000 n41 (521310 -> 528186,
  501390 -> 509250), M2000 n41 (-> 528144 / 509202, following M2000's different
  pointA), R500L5 n77 (653952 -> 655320) and M2000 n71 (125530 -> 135600 =
  678 MHz). n71 is FDD, and its UL sits 46 MHz above DL, so the word is the UL
  centre and not the DL centre. F3 labels the TDD value as well:
  ``mc_msgr.c:3301 "NR5G PRX Active Band 191, Chan 528180, Freq 2640930 Hz,
  BW 90000000 Hz"`` (2640930 kHz / 5 = 528186).

### Unnamed / CANDIDATE

``hdr_word_*``, ``cell_word_4`` and ``cell_word_16`` are surfaced raw.

On v0x02, ``hdr_word_4`` is 0x2039 / 0x203c (one-cell list), 0x2031 or
0x2021 (two-cell list), and its bits split the 44 records cleanly. Bit 0x08 is
set exactly when the list has one cell. Bit 0x10 is set exactly when
``v2_field_8`` equals ``config_id``. On the 0x2021 records (R500L5 drives),
``v2_field_8`` runs 1-6 ahead and keeps climbing across consecutive records
while ``config_id`` stays fixed. That reads like "latest config id at emission"
vs "the acquisition's tune config id", but it has no F3 check on v0x02, so the
field stays unnamed (CANDIDATE).

``v2_time_word`` (v0x02 only) is the acquired NR cell's time in 0xB9BE v0x02's
u32 packing. Its sfn/subframe equals the ``total`` stage's end word on 44/44
v0x02 records (R500L5 and M3100), and that end word is the F3-grounded NR
cell time described above.

Primary DIAG log-code tracker.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.parsers._nr_acq_b9be_b9bf import TimeWord, decode_time_u16, decode_time_u32
from diaggrok.registry import register

_VERSION_V1 = 0x01
_VERSION_V2 = 0x02
_VERSIONS = (_VERSION_V1, _VERSION_V2)
#: version -> (header length, attested payload sizes)
_LAYOUT = {
    _VERSION_V1: (36, (256, 272)),
    _VERSION_V2: (44, (264, 280, 504)),
}
_SIZES = sorted({s for _, sizes in _LAYOUT.values() for s in sizes})
_N_STAGES = 7
_STAGE_SIZE = 28
_TOTAL_STAGE = 6
_CELL_BODY = 16
#: USTMR ticks per millisecond (19.2 MHz)
USTMR_TICKS_PER_MS = 19_200


@dataclass(frozen=True)
class AcqStage:
    """One 28 B stage slot."""

    index: int
    populated: bool
    start: TimeWord
    end: TimeWord
    ustmr_start: int
    ustmr_end: int
    duration_raw: int
    duration_ms: int
    ticks_raw: int
    ustmr_ticks: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "populated": self.populated,
            "start_time_word_raw": self.start.raw,
            "start_sfn": self.start.sfn,
            "start_subframe": self.start.subframe,
            "start_time_flag": self.start.time_flag,
            "start_time_base": self.start.time_hi,
            "end_time_word_raw": self.end.raw,
            "end_sfn": self.end.sfn,
            "end_subframe": self.end.subframe,
            "end_time_flag": self.end.time_flag,
            "end_time_base": self.end.time_hi,
            "ustmr_start": self.ustmr_start,
            "ustmr_end": self.ustmr_end,
            "duration_raw": self.duration_raw,
            "duration_ms": self.duration_ms,
            "ticks_raw": self.ticks_raw,
            "ustmr_ticks": self.ustmr_ticks,
            "elapsed_ms": self.ustmr_ticks / USTMR_TICKS_PER_MS,
        }


@dataclass(frozen=True)
class AcqCell:
    """One cell-list entry with a body (id != 0)."""

    cell_id: int
    cell_word_4: int
    ssb_arfcn: int
    ul_centre_arfcn: int
    cell_word_16: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "cell_id": self.cell_id,
            "cell_word_4": self.cell_word_4,
            "ssb_arfcn": self.ssb_arfcn,
            "ul_centre_arfcn": self.ul_centre_arfcn,
            "cell_word_16": self.cell_word_16,
        }


def _decode_stage(data: bytes, off: int) -> AcqStage:
    index, tws, twe, us, ue, dur, ticks = unpack_from("<7I", data, off)
    low = dur & 0xFFFF
    return AcqStage(
        index=index,
        populated=any((tws, twe, us, ue, dur, ticks)),
        start=decode_time_u16(tws),
        end=decode_time_u16(twe),
        ustmr_start=us,
        ustmr_end=ue,
        duration_raw=dur,
        duration_ms=low - 0x10000 if low & 0x8000 else low,
        ticks_raw=ticks,
        ustmr_ticks=ticks & 0xFFFFFF,
    )


def _decode_cells(data: bytes, off: int) -> tuple[list[AcqCell], int, int, bool]:
    """Walk the cell list.

    Returns (cells with a body, empty entries before the last cell, zero pad
    words after it, consumed exactly).
    """
    cells: list[AcqCell] = []
    zeros = 0  # zero ids since the last cell
    empty = 0
    while off + 4 <= len(data):
        cell_id = unpack_from("<I", data, off)[0]
        off += 4
        if cell_id == 0:
            zeros += 1
            continue
        if off + _CELL_BODY > len(data):
            return cells, empty + zeros, 0, False
        w4, ssb, ul, w16 = unpack_from("<4I", data, off)
        off += _CELL_BODY
        cells.append(AcqCell(cell_id, w4, ssb, ul, w16))
        empty, zeros = empty + zeros, 0
    return cells, empty, zeros, off == len(data)


@dataclass
class Diag0xB9A6:
    """0xB9A6 — NR cell acquisition timeline (v0x01 256/272 B, v0x02 264/280 B)."""

    log_time: int
    version: int
    reserved_b1: int
    tag: int
    v2_time_word: TimeWord | None
    v2_field_8: int | None
    hdr_word_4: int
    hdr_word_8: int
    hdr_word_12: int
    config_id: int
    hdr_word_20: int
    hdr_word_24: int
    hdr_word_28: int
    hdr_word_32: int
    stages: list[AcqStage]
    cells: list[AcqCell]
    empty_cell_entries: int
    #: zero words after the last cell (60 on the M3100's 504 B records)
    pad_words: int
    #: False when a slot index differs from its position, the cell list does
    #: not end exactly at the payload end, or it holds no cell. Fail-visible.
    layout_valid: bool
    payload_size: int
    target: AcqCell | None = field(init=False)
    total: AcqStage = field(init=False)

    def __post_init__(self) -> None:
        self.target = self.cells[-1] if self.cells else None
        self.total = self.stages[_TOTAL_STAGE]

    def to_dict(self) -> dict[str, Any]:
        tw = self.v2_time_word
        return {
            "type": "Diag0xB9A6",
            "log_time": self.log_time,
            "version": self.version,
            "reserved_b1": self.reserved_b1,
            "tag": self.tag,
            "v2_time_word_raw": tw.raw if tw else None,
            "v2_sfn": tw.sfn if tw else None,
            "v2_subframe": tw.subframe if tw else None,
            "v2_field_8": self.v2_field_8,
            "hdr_word_4": self.hdr_word_4,
            "hdr_word_8": self.hdr_word_8,
            "hdr_word_12": self.hdr_word_12,
            "config_id": self.config_id,
            "hdr_word_20": self.hdr_word_20,
            "hdr_word_24": self.hdr_word_24,
            "hdr_word_28": self.hdr_word_28,
            "hdr_word_32": self.hdr_word_32,
            "stages": [s.to_dict() for s in self.stages],
            "total_elapsed_ms": self.total.ustmr_ticks / USTMR_TICKS_PER_MS,
            "nr_sfn": self.total.end.sfn,
            "nr_subframe": self.total.end.subframe,
            "cells": [c.to_dict() for c in self.cells],
            "empty_cell_entries": self.empty_cell_entries,
            "pad_words": self.pad_words,
            "target_ssb_arfcn": self.target.ssb_arfcn if self.target else None,
            "target_ul_centre_arfcn": self.target.ul_centre_arfcn if self.target else None,
            "layout_valid": self.layout_valid,
            "payload_size": self.payload_size,
        }


@register(
    0xB9A6,
    name="0xB9A6",
    description=(
        "0xB9A6 — NR cell acquisition timeline (v0x01 256/272 B SDX55; v0x02 "
        "264/280 B R500L5, 504 B zero-padded M3100 SDX65): RF config_id (F3 "
        "'NRFW Tune: config id'), 7 stage slots of frame-time + 19.2 MHz USTMR "
        "stamps (total ends 0.5 ms before the record; end sfn = NRFW sysframe), "
        "and a cell list whose last entry is the target: SSB NR-ARFCN (= 0xB9BE, "
        "0x60 NR5G RRC HO events) + UL carrier-centre NR-ARFCN (QCSuper RRC + F3)"
    ),
    version=1,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Corpus RE: 101 records / 26 captures (v0x01 FX2000, M2000, RM500Q-AE; "
        "v0x02 R500L5, FT980m, M3100), 101/101 decode layout_valid. config_id printed by "
        "rflte_mc_config.c and nrfw_cmd_proc_sys.c 'NRFW Tune: config id' on "
        "v0x01 10/10 and v0x02 1/1. USTMR stamps vs MCPM F3 19.2 MHz counter: "
        "total ends 0.38-0.62 ms before the record. Total end sfn/subframe vs "
        "nrfw_rx_iu_tasks.c sysframe 11/11, vs 0xB9BE time word 101/101, and = "
        "v0x02 header time word 44/44. Slot arithmetic: ticks = u32(end-start), "
        "duration = i16 frame delta. Target ssb_arfcn = 0xB9BE nr_arfcn 101/101 "
        "and the 0x60 EVENT_NR5G_RRC_HO_STARTED_V2 / NEW_CELL_IND_V2 payload "
        "10/10; ul_centre_arfcn = UL pointA + BW/2 per QCSuper RRC on n41 / "
        "n77 / n71 (FDD), and F3 mc_msgr.c:3301."
    ),
    source_url="",
    issues=(),
    fields_identified=9,
    fields_parsed=24,
    wigle_direct=False,
    wigle_roles=("rat-context",),
    field_invariants={
        "version": {"enum": list(_VERSIONS)},
        "payload_size": {"enum": _SIZES},
    },
)
def parse_0xb9a6(log_time: int, data: bytes) -> Diag0xB9A6 | None:
    if not data:
        return None
    if data[0] not in _VERSIONS:
        return None
    version = data[0]
    hdr_len, sizes = _LAYOUT[version]
    if len(data) not in sizes:
        return None

    if version == _VERSION_V2:
        v2_time_word = decode_time_u32(unpack_from("<I", data, 4)[0])
        v2_field_8 = unpack_from("<I", data, 8)[0]
        common = 12
    else:
        v2_time_word = None
        v2_field_8 = None
        common = 4
    h = unpack_from("<8I", data, common)

    stages = [_decode_stage(data, hdr_len + i * _STAGE_SIZE) for i in range(_N_STAGES)]
    cells, empty, pad, exact = _decode_cells(data, hdr_len + _N_STAGES * _STAGE_SIZE)
    layout_valid = (
        exact
        and bool(cells)
        and all(s.index == i for i, s in enumerate(stages))
    )

    return Diag0xB9A6(
        log_time=log_time,
        version=version,
        reserved_b1=data[1],
        tag=unpack_from("<H", data, 2)[0],
        v2_time_word=v2_time_word,
        v2_field_8=v2_field_8,
        hdr_word_4=h[0],
        hdr_word_8=h[1],
        hdr_word_12=h[2],
        config_id=h[3],
        hdr_word_20=h[4],
        hdr_word_24=h[5],
        hdr_word_28=h[6],
        hdr_word_32=h[7],
        stages=stages,
        cells=cells,
        empty_cell_entries=empty,
        pad_words=pad,
        layout_valid=layout_valid,
        payload_size=len(data),
    )
