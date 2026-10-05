"""0x1D20 — GNSS-engine clock-stamped record with a per-block array.

The code sits in the NR5G ML1 range, but its header is F3-grounded as a GNSS
clock (FCount / GPS TOW ms / GPS week); see "F3 grounding" below. The field
keys ``sys_time`` / ``slot_time`` / ``arfcn_candidate`` are kept for schema
stability (a Kaitai schema pins them), not for their meaning.

Paired with 0x1D5E by the composite key ``(sys_time, slot_time)``, validated
187/187 across timestamp-paired samples in a 5-modem drive corpus:

    0x1D20[4:8]   ==  0x1D5E[4:8]    (sys_time u32)
    0x1D20[8:12]  ==  0x1D5E[10:14]  (slot_time u32 — note 0x1D5E inserts
                                       a 2-byte field at [8:10])

Use this composite key downstream to join an 0x1D20 record with its
companion 0x1D5E record without relying on stream order. It is a GNSS
``(FCount, TOW)`` pair.

=== Variable-size layout — count-prefixed block array ===

The record is a **fixed 52-byte header followed by a stride-20 array of
blocks**. Every observed payload size lies on the grid ``52 + 20*N`` with
no exceptions — RM520N-GL SDX62 emits N=0..15 (sizes 52..352) and Sierra
EM9291 SDX62 emits N=25..28 (sizes 552..612). Validation across 4 captures
(two RM520N-GL drive / GNSS-comparison captures, 597 + 308 records; two
EM9291 reboot / boot-plus-GNSS captures, 3 + 3 records): **0 stride
violations**, and the count byte at header offset 31 equals ``N+1`` for
every N>=1 record (911/911) and 0 for the empty 52B form.

Header (52B):
  [0]      u8    version (== 1, corpus-wide invariant)
  [4:8]    u32   sys_time   — GNSS engine FCount; paired key with 0x1D5E[4:8]
  [8:12]   u32   slot_time  — GPS time-of-week ms; paired key with 0x1D5E[10:14]
  [12:24]  3x f32 — observed 1.0/3.0 (filter-gain candidates)
  [24:26]  u16   arfcn_candidate — GPS week number (F3-grounded). Not an
                 NR-ARFCN despite the key name: a u16 cannot hold an FR1
                 NR-ARFCN (e.g. 501390 on n41), and the value sits at
                 ~2415..2426 across months and four chipset generations,
                 stepping by one per week.
  [31]     u8    reported_cell_count — == number of blocks + 1 when >=1
                 block is present, 0 for the empty form. The decoded block
                 count is size-derived ((size-52)//20); this field is the
                 firmware's corroborating count, and a payload too short for
                 its N blocks returns None (truncation fails loudly).
  [26:31],[32:52] — header tail, still unexplained, preserved in raw_payload.

Per-block entry (20B each), characterized over 5,465 blocks from one drive:
  [0]      u8    index  — 17 distinct values, range 6..84 (NOT a full
                 0..1007 PCI, and not the GNSS PRNs printed in the same
                 window)
  [1:8]    7B    packed flags + one MSB-varying slot (not a clean float)
  [8:12]   f32   metric_a — 100% finite, range [-2.04, +1.89], mean +0.47.
                 Real signed measurement; physical quantity unknown.
  [12:16]  4B    packed (mostly 0, one MSB-varying byte)
  [16:20]  f32   metric_b — 100% finite, range [0, +1.60], often exactly 0.0.
                 Second measurement candidate; semantics unknown.

=== F3 grounding (v0x01): the header is a GNSS clock ===

The firmware's own GNSS-engine prints carry the header's three numbers
verbatim, within ±2.3 ms of the record. Worked example, a CFW-3212
capture::

    0x1D20  u32@4 = 460664060   u32@8 = 75918420   u16@24 = 2423 (0x0977)
    +1.14 ms  mc_clock.c  ClockPut_GPS: FC 460664060 Wk 2423 Ms 75918420 TBias -0.3630 ...
    +1.21 ms  gts.c       GpsMeTime. W 2423 Ms 75918420 ... RefFC 460664060 ...
    -2.24 ms  mc_gnssmeasreport.c  L1Gps_MBlk(1Hz) - 9 SVs,FC 460667060,Wk 2423,Ms 75921420,...

So, under the keys kept for schema stability:

* ``sys_time`` (u32@4) is the GNSS measurement-engine **FCount** (the
  engine's ms frame counter, ``FC`` / ``FCount``).
* ``slot_time`` (u32@8) is **GPS time-of-week in ms** (``Ms``).
* ``arfcn_candidate`` (u16@24) is the **GPS week number** (``Wk``).

Corpus measurement (±10 ms window, control at record time ±5 s): all **22**
F3-bearing captures that emit v0x01 were joined (up to 60 records each;
1,026 records). **915** records have a print carrying the identical FCount,
TOW ms AND week; 47 more match FCount alone (a print without ``Ms``/``Wk``
was nearest); 64 have no clock print in the window (60 of them in one M3100
survey). The 2,052 control points match **0**. 21/22 captures ground,
spanning CFW-3212 / RG520N (SDX62), RM520N-GL (SDX62), T99W640 (SDX72) and
Inseego M3100.

So this is not an NR5G ML1 per-cell measurement record: it is stamped with
the GNSS engine's clock and co-fires with GNSS navigation / measurement
prints (``gnss_gpm_api.cpp`` "GPM All", ``nf_kf*.c``,
``mc_gnssmeasreport.c``), not NR5G ML1 ones. The 20 B array is NOT
grounded: its ``index`` values (e.g. 15/23/66/81/82/48/53/54/55) do not line
up with the PRNs the nav filter prints in the same window
(16/18/27/29/32/67/68/...), so ``index`` / ``metric_a`` / ``metric_b`` stay
raw placeholders.

Naming a float by its offset is not a semantic decode: ``metric_a`` /
``metric_b`` are typed placeholders for measurements whose meaning is still
unknown. The array *framing* (count, stride, per-block field map) is fully
recovered and cross-generation-validated; the per-measurement *semantics*
remain open.
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

# Ground-truth recipe. ONE version: v=0x01 (corpus-wide).
#
# The header is F3-grounded as a GNSS clock (FCount / GPS TOW ms / GPS week;
# see the docstring). The 20 B array FRAMING is fully recovered (52B header +
# stride-20 blocks); what's open is the per-block SEMANTICS — metric_a /
# metric_b are finite f32s of unknown meaning. The RM520N-GL is the dominant
# emitter (N=0..15); the Sierra EM9291 is the cross-chipset confirmer
# (N=25..28).
#
# Caveats baked into the field map:
#  * Pair with 0x1D5E by (sys_time, slot_time) (validated 187/187).
#  * `index` (block byte 0) ranges 6..84 and does not match the GNSS PRNs
#    printed in the same window; it is not a full 0..1007 PCI either.
#  * metric_a range [-2.04, +1.89] and metric_b range [0, +1.60] are
#    NORMALISED floats, not dBm, so all measurement fields stay hypothesis.
#  * No emission is seen on stationary NR5G camps with GNSS off.
_HEADER_LEN = 52
_BLOCK_LEN = 20


@dataclass
class Diag0x1D20:
    """0x1D20 — GNSS-engine clock-stamped record.

    Fixed 52B header + a stride-20 array of blocks (see the module docstring
    for the byte map). The 52B form (``N == 0``) carries no blocks; larger
    variants append one 20-byte block each.

    ``cells`` is the decoded array; each entry exposes the
    ``index`` byte plus the two finite f32 measurement candidates
    (``metric_a`` / ``metric_b``) and the raw 20-byte block for the bytes
    whose layout is not yet pinned (``[1:8]`` / ``[12:16]``).
    """

    log_time: int
    version: int
    sys_time: int            # u32 @ 4 — GNSS FCount; paired key (187/187)
    slot_time: int           # u32 @ 8 — GPS TOW ms; paired key (187/187)
    arfcn_candidate: int     # u16 @ 24 — GPS week (F3-grounded); legacy key,
                             # NOT an ARFCN.
    reported_cell_count: int  # u8 @ 31 — firmware count == len(cells)+1 / 0
    cells: list[dict[str, Any]]  # stride-20 blocks
    payload_size: int
    raw_payload: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x1D20",
            "log_time": self.log_time,
            "version": self.version,
            "sys_time": self.sys_time,
            "slot_time": self.slot_time,
            "arfcn_candidate": self.arfcn_candidate,
            "reported_cell_count": self.reported_cell_count,
            "num_cells": len(self.cells),
            "cells": self.cells,
            "payload_size": self.payload_size,
            "raw_payload": self.raw_payload.hex(),
        }


@register(0x1D20,
    name="0x1D20",
    description=("GNSS-engine clock-stamped record, filed as NR5G ML1 (52B header: FCount u32@4, "
                 "GPS TOW ms u32@8, GPS week u16@24 — F3-grounded; + stride-20 array, ungrounded; "
                 "paired key with 0x1D5E)"),
    version=3, author="Luke Jenkins", author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Header F3-grounded v0x01: the GNSS engine's own prints carry it verbatim "
        "within +-2.3 ms — sys_time u32@4 == FCount ('ClockPut_GPS: FC', "
        "'L1Gps_MBlk(1Hz) ... FC'), slot_time u32@8 == GPS TOW ms ('Ms'), "
        "arfcn_candidate u16@24 == GPS week ('Wk'); 915/1,026 records across "
        "21/22 F3-bearing captures (CFW-3212/RG520N, RM520N-GL, T99W640, M3100) "
        "carry all three verbatim, control 0/2,052. Keys are unchanged for "
        "schema stability; this is not an NR5G ML1 per-cell record (no emission "
        "on stationary NR5G camps with GNSS off). 14,047 records across four "
        "chipset generations: RM520N-GL SDX62 (N=0..15, sizes 52..352), Sierra "
        "EM9291 SDX65 (N=25..28, sizes 552..612), Foxconn T99W640 SDX72, RG520N "
        "(CFW-3212). Variable tail decoded as a stride-20 array (52 + 20*N): 0 "
        "stride violations across all generations; header offset-31 count == "
        "N+1 corroborated 911/911; truncated payloads return None (registry "
        "WARN). All records version=0x01. Paired with 0x1D5E. The 20 B array "
        "(index/metric_a/metric_b) stays ungrounded."
    ),
    issues=(),
    fields_identified=8, fields_parsed=8,
    # Layer-2 version invariant: the corpus across all captures and
    # generations reports `version=0x01` invariantly. Declared here so audit tooling
    # can enforce the bound without scraping the parser body; the Layer-1
    # gate below (`data[0] != 1`) is the byte-0-first enforcement.
    field_invariants={
        "version": {"enum": [1]},
    },
)
def parse_0x1d20(log_time: int, data: bytes) -> Diag0x1D20 | None:
    if len(data) < _HEADER_LEN:
        return None
    if data[0] != 1:           # byte-0-first version gate
        return None
    # The firmware count @31 (N+1, or 0 for the empty form)
    # declares N blocks; if N x 20 B does not fit, the record is truncated ->
    # None (registry WARN) instead of silently dropping the last cell.
    declared_blocks = data[31] - 1 if data[31] else 0
    if _HEADER_LEN + declared_blocks * _BLOCK_LEN > len(data):
        return None
    n_blocks = (len(data) - _HEADER_LEN) // _BLOCK_LEN
    cells: list[dict[str, Any]] = []
    for i in range(n_blocks):
        base = _HEADER_LEN + i * _BLOCK_LEN
        blk = data[base:base + _BLOCK_LEN]
        cells.append({
            "index": blk[0],
            "metric_a": round(unpack_from("<f", blk, 8)[0], 6),
            "metric_b": round(unpack_from("<f", blk, 16)[0], 6),
            "raw": blk.hex(),
        })
    return Diag0x1D20(
        log_time=log_time,
        version=data[0],
        sys_time=unpack_from("<I", data, 4)[0],
        slot_time=unpack_from("<I", data, 8)[0],
        arfcn_candidate=unpack_from("<H", data, 24)[0],
        reported_cell_count=data[31],
        cells=cells,
        payload_size=len(data),
        raw_payload=bytes(data),
    )
