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

*The trailer is ``u8 n_groups`` + n_groups x 36 B groups.*
The 37 B "trailer cell" was always the K == 1 case. Each group's [+0] is a
cell bitmask; the K masks are disjoint and OR to 2**N - 1 (group order is not
cell order: 01, 04, 02 is seen). So the former "+36 B anomaly" family
(196/233/269/270/307 B v0x01, 273 B v0x02) is K = 2 or 3:

    v0x01: payload_size = 49 + 37*N + 1 + 36*K
    v0x02: payload_size = 80 + 40*N + 1 + 36*K

This holds on 5,475/5,475 v0x01 + 7/7 v0x02 extension records from a
100-capture walk (Inseego M3100, Foxconn T99W373 + T99W640, RM520N-GL,
Orbic R562L5), plus every sampled clean record. The v3 parser rejected all
5,482 of them. What a group stands for is not F3-grounded (hypothesis:
carriers that share an RF path / band), so group bodies stay raw.

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

The sizes {196, 233, 269, 270, 307} that do not fit ``86 + 37*N`` are the
multi-group trailer above, not a distinct layout. Two 2026-06 readings were
wrong: ``data[11]`` is N - 1 only when ``data[12:18]`` is all-zero (true on
every such record; otherwise [11:18] is a different sub-block, surfaced as
``hdr_11_18``), and ``magic`` / the ``ff ff 00 xx 00`` tags are values, not
constants (56 records carry ``04 00 00 00 00`` / zeros as the tags). The v3
tag gate silently dropped those; v4 does not gate on tags.

Layout (little-endian):

  Header — 49 B, ``data[0:49]``
    [0]        u8      version          = 0x01
    [1]        u8      subversion       = 0x01
    [2..11]    10 B    reserved (zero)
    [11..18]   7 B     hdr_11_18        when [12..18] == 0: [11] = n_counters - 1;
                                        otherwise a sub-block (raw, not gated)
    [18..23]   5 B     tag1             usually FF FF 00 <0x06 | 0x08> 00 (a value)
    [23..28]   5 B     tag2             (same shape as tag1)
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

  Trailer — ``data[49 + 37*N :]``, 1 + 36*K B (always present, K >= 1)
    [+0]       u8      n_groups (K)     1 on the clean family
  Group g — 36 B at trailer [+1 + 36*g]
    [+0]       u8      mask             cell bitmask; masks partition 2**N - 1
    [+4]       u8      0x04 or 0x00
    [+11..13]          01 02 / 01 04 / 00 02 / 00 04 (raw)
    [+32]      u8      checksum-like    (varies: 0x83, 0xA8, 0xBF, ...)

Counter-cell internals beyond ``index`` and ``value`` vary by modem and
firmware, so they are exposed as raw bytes rather than decoded into named
fields — see ``CounterCell.raw`` and ``Diag0x1D2E.trailer_raw``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
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
_TRAILER_LEN = 37                     # K == 1 trailer: 1 + 36 (both versions)
_V2_BASE = _V2_HEADER_LEN + _TRAILER_LEN  # 117: payload_size = 117 + 40*N
_GROUP_LEN = 36                       # one trailer group (packed, both versions)


@dataclass
class TrailerGroup:
    """One 36-byte trailer group. ``mask`` ([+0]) is a bitmask over the
    counter cells; the groups' masks are disjoint and OR to 2**N - 1. What
    a group stands for is not F3-grounded (hypothesis: carriers sharing an
    RF path / band); the rest of the group stays raw."""
    mask: int
    raw: bytes

    def to_dict(self) -> dict[str, Any]:
        return {'mask': self.mask, 'raw': self.raw.hex()}


def _split_trailer(data: bytes, off: int, n_counters: int) -> list[TrailerGroup] | None:
    """Parse ``u8 n_groups`` + n_groups x 36 B at ``off``, which must end the
    record exactly; the masks must partition the N cells. None otherwise."""
    if off >= len(data):
        return None
    k = data[off]
    if k < 1 or len(data) != off + 1 + _GROUP_LEN * k:
        return None
    groups = [TrailerGroup(mask=data[o], raw=bytes(data[o:o + _GROUP_LEN]))
              for o in range(off + 1, len(data), _GROUP_LEN)]
    union = 0
    for g in groups:
        if g.mask == 0 or union & g.mask:
            return None
        union |= g.mask
    if union != (1 << n_counters) - 1:
        return None
    return groups


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
    trailer_mask: int          # OR of the group masks == 2**n_counters - 1
    trailer_raw: bytes         # u8 n_groups + n_groups x 36 B (37 B when K == 1)
    n_cells: int               # n_counters + 1
    payload_size: int
    layout: str = "v1_packed"  # "v1_packed" (49/37 B) or "v2_aligned" (80/40 B)
    hdr_byte18: int | None = None   # v0x02 [18] (0/1, raw)
    n_groups: int = 1          # trailer [+0]; the clean family is 1
    groups: list[TrailerGroup] = field(default_factory=list)
    hdr_11_18: bytes | None = None  # v0x01 [11:18] raw; [11] == N-1 iff [12:18] == 0

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
            'n_groups': self.n_groups,
            'groups': [g.to_dict() for g in self.groups],
            'hdr_11_18': self.hdr_11_18.hex() if self.hdr_11_18 is not None else None,
        }


@register(
    0x1D2E,  # domain intentionally unset: not GNSS; the emitter is the RF
             # limits manager / TRM antenna state, with no clean
             # DOMAIN_VOCAB match.
    name="0x1D2E",
    description="LOG_1D2E (0x1D2E) — cell-array record: v0x01 49-B header + N×37-B cells, v0x02 80-B header + N×40-B cells, then u8 K + K×36-B groups whose masks partition the cells; N = LTE carriers in the TRM antenna-state freq list (F3)",
    version=4,
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
        "n_counters to lmtsmgr freq-list NumEntries == 2*N (20/20 v0x02). "
        "v4: the trailer is u8 K + K x 36 B mask groups, decoding "
        "the former +36 B family (5,482 records the v3 gates dropped)."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    field_invariants={
        "version": {"enum": [0x01, 0x02]},
        "subversion": {"enum": [0x01]},
        # v0x01: 49 + 37*N + 1 + 36*K; v0x02: 80 + 40*N + 1 + 36*K.
        # Corpus-attested (version, N, K) forms only (whole-corpus walk).
        "payload_size": {"enum": [123, 160, 197, 234, 196, 233, 269, 270, 307,
                                  157, 197, 237, 277, 273]},
        "n_cells": {"min": 2},
        "n_groups": {"min": 1, "max": 3},
    },
)
def parse_0x1d2e(log_time: int, data: bytes) -> Diag0x1D2E | None:
    if data[:1] == b"\x02":
        return _parse_v2(log_time, data)
    # v0x01: 49 + 37*N + 1 + 36*K. Anything off this contract returns None, so
    # the registry WARNs + tallies it: never a silent drop.
    if len(data) < _HEADER_LEN or data[0] != 0x01 or data[1] != 0x01:
        return None
    if data[38] != 0x0D or data[39] != 0x0F:
        return None
    n_counters = data[48]
    if n_counters < 1:
        return None
    # data[11] == N-1 held on every corpus record whose [12:18] is all-zero;
    # with [12:18] non-zero, [11:18] is a different sub-block.
    if data[12:18] == bytes(6) and data[11] != n_counters - 1:
        return None

    counters: list[CounterCell] = []
    for k in range(n_counters):
        off = _HEADER_LEN + k * _CELL_LEN
        cell = bytes(data[off:off + _CELL_LEN])
        if len(cell) != _CELL_LEN or cell[0] != k:
            return None
        counters.append(CounterCell(
            index=cell[0],
            value=unpack_from('<H', cell, 11)[0],
            raw=cell,
        ))

    trailer_off = _HEADER_LEN + n_counters * _CELL_LEN
    groups = _split_trailer(data, trailer_off, n_counters)
    if groups is None:
        return None

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
        trailer_mask=(1 << n_counters) - 1,
        trailer_raw=bytes(data[trailer_off:]),
        n_cells=n_counters + 1,
        payload_size=len(data),
        n_groups=len(groups),
        groups=groups,
        hdr_11_18=bytes(data[11:18]),
    )


def _parse_v2(log_time: int, data: bytes) -> Diag0x1D2E | None:
    """v0x02 (T99W640 / SDX72): 80 B header + N x 40 B cells + 37 B trailer.

    The v0x01 struct with naturally-aligned fields: the 0x0D / 0x0F markers and
    the four 0x8000 words widen to u32 ([55], [59], [63:79]), ``n_counters``
    moves to [79], cells grow to 40 B (``value`` u16 at +12, after the +10
    byte's pad). The trailer is the same ``u8 n_groups`` + K x 36 B as v0x01
    (K == 1 on 257/257 clean records; 273 B is K == 2, 7/7).
    """
    n = len(data)
    if n < _V2_HEADER_LEN or data[1] != 0x01:
        return None
    n_counters = data[79]
    if n_counters < 1:
        return None
    if not (data[3:5] == data[19:21] == data[39:41] == b"\xff\xff"):
        return None
    if unpack_from('<II', data, 55) != (0x0D, 0x0F):
        return None

    counters: list[CounterCell] = []
    for k in range(n_counters):
        off = _V2_HEADER_LEN + k * _V2_CELL_LEN
        cell = bytes(data[off:off + _V2_CELL_LEN])
        if len(cell) != _V2_CELL_LEN or cell[0] != k:
            return None
        counters.append(CounterCell(index=cell[0], value=unpack_from('<H', cell, 12)[0], raw=cell))
    trailer_off = _V2_HEADER_LEN + n_counters * _V2_CELL_LEN
    groups = _split_trailer(data, trailer_off, n_counters)
    if groups is None:
        return None

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
        trailer_mask=(1 << n_counters) - 1,
        trailer_raw=bytes(data[trailer_off:]),
        n_cells=n_counters + 1,
        payload_size=n,
        layout="v2_aligned",
        hdr_byte18=data[18],
        n_groups=len(groups),
        groups=groups,
    )
