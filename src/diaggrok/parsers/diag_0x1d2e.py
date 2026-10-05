"""0x1D2E — LOG_1D2E cell-array record, TRM antenna-state / lmtsmgr carrier list.

Two versions, both decoded and F3-grounded: v0x01 (packed) and v0x02
(naturally aligned).

*v0x02 (Foxconn T99W640 / SDX72)* is the v0x01 struct with naturally-aligned
fields: an **80 B header** (the 0x0D / 0x0F markers and the four 0x8000 words
widen to u32 at [55] / [59] / [63:79]; ``n_counters`` at [79]; ``ff ff`` tags
at [3], [19], [39]), **40 B cells** (``value`` u16 at +12, after the +10
byte's pad) and the **same 37 B trailer** (mask = 2**N - 1). So
``payload_size = 117 + 40*N``: 157/197/237/277 B for N = 1..4, on 257/257
clean corpus records. See :func:`_parse_v2`.

*F3 (enrichment, not raw co-occurrence).* Both versions are emitted ~1.2-1.4k
ticks after the limits manager's ``lmtsmgr_task.c:490 "TRM ANT update
received"`` / ``lmtsmgr_core.c:9861 "Processing ant state update from TRM"``:
v0x02 36/86 records vs 3/8000 random instants (4 T99W640 captures); v0x01
37/123 vs 0/2000 (one RM520N-GL capture). ~3k ticks after,
``lmtsmgr_cmd.c:1506 "Received new freq list Tech 0, Band 131, NumEntries
K"`` gives **K == 2 * n_counters on 20/20 v0x02 records** (N = 1..4) and
1/1 v0x01. So ``n_counters`` is the number of LTE carriers in the TRM ->
lmtsmgr frequency list (two entries each; the coex entries carry freq /
bandwidth / dir). The cell internals are NOT labelled by any F3 site, so
they stay raw. Raw co-occurrence over a ±8k-tick window is dominated by
data-services / QoS / bearer / RF-power prints, which is why enrichment
against random instants, not co-occurrence, is the attribution test.

*The "anomaly" family is a +36 B extension, in both versions.* v0x01
196/233/270 B = the clean 160/197/234 B + 36 (``data[48]`` = 2/3/4), and v0x02
273 B = 237 + 36. Not decoded; rejected, so the registry WARNs.

**Not a GNSS record.** The canonical name is ``RESERVED`` (no subsystem
hint), and nothing in the record or its co-temporal F3 points at GNSS (a
218-to-19 ratio of non-GNSS to GNSS source files around each emission).

**Variable-length structure.** An RM520N-GL record carries a single data
cell (123 B), but a Sierra EM9291 (SDX65) edge-case suite emits the same
log code at **five payload sizes** following a clean ``86 + 37·N`` ladder.
Structural RE across both modems shows the record is a **49-byte header
followed by an array of 37-byte cells**, not a fixed record:

    payload_size = 86 + 37 * n_counters
                 = 49 + 37 * (n_counters + 1)

i.e. ``n_counters`` "counter" cells plus exactly one "trailer" cell.

The cell count is encoded **three** redundant ways that all agree — a
strong cross-validation of the model:

  * ``data[48]``  = ``n_counters``                (the length prefix)
  * ``data[11]``  = ``n_counters - 1``            (redundant length field)
  * trailer cell ``[+1]`` = ``2**n_counters - 1`` (presence bitmask:
                                                   01, 03, 07, 0f for N=1..4)

Observed size ladder (clean family, ``(size-86) % 37 == 0``):

    size  n_counters  n_cells  modems
    ----  ----------  -------  ------------------------------
     123       1          2     RM520N-GL (SDX62), EM9291 (SDX65)
     160       2          3     EM9291
     197       3          4     EM9291
     234       4          5     EM9291

A separate RM520N-GL ``v=0x01`` **anomaly family** at sizes
{196, 233, 269, 270, 307} does **not** fit the 37-byte cell stride
(``(size-86) % 37`` is 35 or 36, not 0). It is *not* rare — 233B alone is
1,635 records in a set of correlation captures and 269B is 598. Its header
breaks the redundant-length contract (``data[11] != data[48] - 1``) and
carries a different magic (``0x3933`` vs RM520's ``0x8737``), so it is a
genuinely distinct layout, not a clean record off-by-a-byte. Rejected here
(documented, not silently size-gated).

Layout (little-endian):

  Header — 49 B, ``data[0:49]``
    [0]        u8      version          = 0x01
    [1]        u8      subversion       = 0x01
    [2..11]    10 B    reserved (zero)
    [11]       u8      n_counters_m1    = n_counters - 1  (redundant length)
    [12..18]   6 B     reserved (zero)
    [18..23]   5 B     tag1             = FF FF 00 <0x06 RM520 | 0x08 Sierra> 00
    [23..28]   5 B     tag2             = (same shape as tag1)
    [28..30]   u16LE   field_pre        = 0x0000
    [30..32]   u16LE   magic            modem-specific: 0x8737 RM520, 0x04B7 Sierra
    [32]       u8      field_32         modem-specific: 0x0A RM520, 0x0C Sierra
    [33..38]   5 B     reserved (zero)
    [38]       u8      marker_0d        = 0x0D (13)
    [39]       u8      marker_0f        = 0x0F (15)
    [40]       u8      reserved (zero)
    [41]       u8      = 0x80
    [42..45]   modem-specific (RM520: 0x80 at 43 too; Sierra: zero)
    [45]       u8      = 0x80
    [46..48]   reserved (zero)
    [48]       u8      n_counters       (the length prefix)

  Counter cell — 37 B, ``data[49 + 37*k : 49 + 37*(k+1)]`` for k in 0..N-1
    [+0]       u8      index            = k (0-based)
    [+1..11]   modem-specific reserved/flags
    [+11..13]  u16LE   value            the per-cell datum (RM520 cell-0
                                        observed 0x300 / 0x310 / 0x3D0)
    [+13..37]  modem-specific trailer (typically `01` at +20, `0xFF` at +28)

  Trailer cell — 37 B, ``data[49 + 37*N : 86 + 37*N]`` (always present)
    [+0]       u8      = 0x01
    [+1]       u8      mask             = 2**n_counters - 1
    [+5]       u8      = 0x04
    [+8]       u8      = 0x0C
    [+12..14]          = 01 02
    [+33]      u8      checksum-like    (varies: 0x83, 0xA8, 0xBF, ...)

Counter-cell internals beyond ``index`` and ``value`` vary by modem and
firmware, so they are exposed as raw bytes rather than decoded into named
fields — see ``CounterCell.raw`` and ``Diag0x1D2E.trailer_raw``.
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

_HEADER_LEN = 49
_CELL_LEN = 37
_MIN_LEN = _HEADER_LEN + _CELL_LEN  # 86 — one counter would make 123; a
#   record always has >=1 counter + 1 trailer, so the smallest valid record
#   is 86 + 37 = 123. _MIN_LEN gates the "header + trailer-only" floor.

# v0x02 (T99W640 / SDX72): the same record with naturally-aligned fields.
_V2_HEADER_LEN = 80
_V2_CELL_LEN = 40
_TRAILER_LEN = 37                     # packed in both versions
_V2_BASE = _V2_HEADER_LEN + _TRAILER_LEN  # 117: payload_size = 117 + 40*N


@dataclass
class CounterCell:
    """One 37-byte counter cell of a 0x1D2E record."""
    index: int       # cell [+0] — 0-based position
    value: int       # u16LE @ cell [+11] (v0x01) / [+12] (v0x02, aligned)
    raw: bytes       # full 37-byte (v0x01) / 40-byte (v0x02) cell

    def to_dict(self) -> dict[str, Any]:
        return {'index': self.index, 'value': self.value, 'raw': self.raw.hex()}


@dataclass
class Diag0x1D2E:
    """LOG_1D2E (0x1D2E) — cell-array record: ``n_counters`` LTE carriers
    of the TRM antenna-state freq list (F3-grounded). v0x01
    packed (49/37 B) or v0x02 aligned (80/40 B); see the module docstring.
    """
    log_time: int
    version: int
    subversion: int
    n_counters: int            # data[48] — the length prefix
    tag1: bytes
    tag2: bytes
    field_pre: int | None      # v0x01 only
    magic: int | None          # v0x01 only: 0x8737 RM520, 0x04B7 Sierra
    field_32: int | None       # v0x01 only, modem-specific
    counters: list[CounterCell]
    trailer_mask: int          # trailer [+1] == 2**n_counters - 1
    trailer_raw: bytes
    n_cells: int               # n_counters + 1
    payload_size: int
    layout: str = "v1_packed"  # "v1_packed" (49/37 B) or "v2_aligned" (80/40 B)
    hdr_byte18: int | None = None   # v0x02 [18] (0/1, raw)

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1D2E',
            'log_time': self.log_time,
            'version': self.version,
            'subversion': self.subversion,
            'n_counters': self.n_counters,
            'tag1': self.tag1.hex(),
            'tag2': self.tag2.hex(),
            'field_pre': self.field_pre,
            'magic': self.magic,
            'field_32': self.field_32,
            'counters': [c.to_dict() for c in self.counters],
            'trailer_mask': self.trailer_mask,
            'trailer_raw': self.trailer_raw.hex(),
            'n_cells': self.n_cells,
            'payload_size': self.payload_size,
            'layout': self.layout,
            'hdr_byte18': self.hdr_byte18,
        }


@register(
    0x1D2E,  # domain intentionally unset: not GNSS; the emitter is the RF
             # limits manager / TRM antenna state, with no clean
             # DOMAIN_VOCAB match.
    name="0x1D2E",
    description="LOG_1D2E (0x1D2E) — cell-array record: v0x01 49-B header + N×37-B cells, v0x02 80-B header + N×40-B cells, 37-B trailer; N = LTE carriers in the TRM antenna-state freq list (F3)",
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE from RM520N-GL SDX62 + a Sierra EM9291 SDX65 "
        "edge-case suite. Variable length 86+37*N; cell count at "
        "data[48], cross-checked by data[11] and the trailer presence bitmask. "
        "v0x02 (T99W640/SDX72) is the "
        "aligned-field variant (117+40*N, n_counters at [79], 257/257 corpus "
        "records); both versions F3-grounded to lmtsmgr TRM antenna-state "
        "updates (v0x02 36/86 vs 3/8000 control, v0x01 37/123 vs 0/2000) and "
        "n_counters to lmtsmgr freq-list NumEntries == 2*N (20/20 v0x02)."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    field_invariants={
        "version": {"enum": [0x01, 0x02]},
        "subversion": {"enum": [0x01]},
        # v0x01: 86 + 37*N; v0x02: 117 + 40*N (N = n_counters, 1..4 seen).
        "payload_size": {"enum": [123, 160, 197, 234, 271, 157, 237, 277]},
        "n_cells": {"min": 2},
    },
)
def parse_0x1d2e(log_time: int, data: bytes) -> Diag0x1D2E | None:
    if data[:1] == b"\x02":
        return _parse_v2(log_time, data)
    n = len(data)
    # Clean cell-array family only: 86 + 37*N, N >= 1 (i.e. n >= 123).
    if n < _MIN_LEN + _CELL_LEN or (n - _MIN_LEN) % _CELL_LEN != 0:
        return None
    if data[0] != 0x01 or data[1] != 0x01:
        return None
    # tag skeleton FF FF 00 ?? 00 — 4th byte is modem-specific (0x06 / 0x08).
    if data[18] != 0xFF or data[19] != 0xFF or data[22] != 0x00:
        return None
    if data[23] != 0xFF or data[24] != 0xFF or data[27] != 0x00:
        return None
    if data[38] != 0x0D or data[39] != 0x0F:
        return None

    n_counters = data[48]
    # Size must agree with the length prefix, and the redundant data[11]
    # field must equal n_counters - 1. Both are part of the structural
    # contract; a mismatch means this isn't a clean cell-array record.
    if (n - _MIN_LEN) // _CELL_LEN != n_counters:
        return None
    if data[11] != n_counters - 1:
        return None

    counters: list[CounterCell] = []
    for k in range(n_counters):
        off = _HEADER_LEN + k * _CELL_LEN
        cell = bytes(data[off:off + _CELL_LEN])
        counters.append(CounterCell(
            index=cell[0],
            value=unpack_from('<H', cell, 11)[0],
            raw=cell,
        ))

    trailer_off = _HEADER_LEN + n_counters * _CELL_LEN
    trailer = bytes(data[trailer_off:trailer_off + _CELL_LEN])

    return Diag0x1D2E(
        log_time=log_time,
        version=data[0],
        subversion=data[1],
        n_counters=n_counters,
        tag1=bytes(data[18:23]),
        tag2=bytes(data[23:28]),
        field_pre=unpack_from('<H', data, 28)[0],
        magic=unpack_from('<H', data, 30)[0],
        field_32=data[32],
        counters=counters,
        trailer_mask=trailer[1] if len(trailer) > 1 else 0,
        trailer_raw=trailer,
        n_cells=n_counters + 1,
        payload_size=n,
    )


def _parse_v2(log_time: int, data: bytes) -> Diag0x1D2E | None:
    """v0x02 (T99W640 / SDX72): 80 B header + N x 40 B cells + 37 B trailer.

    The v0x01 struct with naturally-aligned fields: the 0x0D / 0x0F markers and
    the four 0x8000 words widen to u32 ([55], [59], [63:79]), ``n_counters``
    moves to [79], cells grow to 40 B (``value`` u16 at +12, after the +10
    byte's pad). The 37 B trailer is unchanged. All of it holds on 257/257
    clean corpus records; 273 B is the +36 B extension also seen
    on v0x01 and is not decoded.
    """
    n = len(data)
    if n < _V2_BASE + _V2_CELL_LEN or (n - _V2_BASE) % _V2_CELL_LEN:
        return None
    n_counters = (n - _V2_BASE) // _V2_CELL_LEN
    if data[1] != 0x01 or data[79] != n_counters:
        return None
    if not (data[3:5] == data[19:21] == data[39:41] == b"\xff\xff"):
        return None
    if unpack_from('<II', data, 55) != (0x0D, 0x0F):
        return None

    counters: list[CounterCell] = []
    for k in range(n_counters):
        off = _V2_HEADER_LEN + k * _V2_CELL_LEN
        cell = bytes(data[off:off + _V2_CELL_LEN])
        counters.append(CounterCell(index=cell[0], value=unpack_from('<H', cell, 12)[0], raw=cell))
    trailer = bytes(data[n - _TRAILER_LEN:])

    return Diag0x1D2E(
        log_time=log_time,
        version=data[0],
        subversion=data[1],
        n_counters=n_counters,
        tag1=bytes(data[3:19]),
        tag2=bytes(data[19:39]),
        field_pre=None,
        magic=None,
        field_32=None,
        counters=counters,
        trailer_mask=trailer[1],
        trailer_raw=trailer,
        n_cells=n_counters + 1,
        payload_size=n,
        layout="v2_aligned",
        hdr_byte18=data[18],
    )
