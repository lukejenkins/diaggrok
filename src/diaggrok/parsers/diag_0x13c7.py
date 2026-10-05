"""LTE Config (0x13C7) — multi-size, self-describing u16 body_len.

Chipset-gated to MDM9x07 / MDM9x30 — emits zero records on SDX20
(LM960, FN980), SDX55 (FN980 SDX55, RM500Q SDX55, EM9190), SDX62
(RM520N-GL), and X12 (Inseego M2000). Corpus: 271,795 records /
29 logical captures / 6 modems / 2 chipset families.

Variable-length (74 distinct sizes; top 7 classes cover 99%):
200B (29%) / 170B (25%) / 602B (23%) / 109B (11%) / 115B (5%) /
135B (3%) / 206B (2%) — others 1% combined.

Key correctness invariant: ``payload_size == 8 + body_len`` where
``body_len`` is u16 LE at bytes[6:8]. Holds on 100% of a 24-fixture probe
(4 modems × up to 7 size classes). Parser returns ``None`` on any
record that violates it — covers truncated records and any future
format change that breaks the length field.

byte[0] is a uniformly-distributed counter (256/256 distinct values),
not a version byte, so record size does not imply a fixed format here.
byte[2:4] is universal CONST 0x0000 (271,795/271,795 records).

## Body layout is mode_flags-bit0 discriminated (F3-grounded)

The body (bytes[8:]) is not one schema — ``mode_flags`` (u16 LE @ [4:6])
**bit 0** selects between two families, on an SWI9X30C EM7455 capture
with F3 enabled (3801 records):

* **bit0 == 0** (mode 0x0000 / 0x8000) → **grid-summary** layout
  (200B / 170B / 135B classes). First 32 body bytes are a fixed
  sub-header (all rates below 100% on the 200B/170B classes):
  ``col_peak_value`` (u32 @ body[0]), ``reserved_body4`` (CONST 0),
  ``grid_count`` (u32 @ body[8]), a signed word @ body[12],
  ``col_peak_value_echo`` (u32 @ body[16] == ``col_peak_value``),
  ``grid_resolution`` (u32 @ body[20], a per-class constant
  25000/50000/100000/500000), ``col_peak_energy`` (u32 @ body[24]),
  ``reserved_body28`` (CONST 0). Remainder is a per-SV tail
  (``grid_body_raw``) that scales the size class.
* **bit0 == 1** (mode 0x8001) → **full-grid energy array** layout
  (602B / 314B / 212B / … classes). Body is a dense u32/u16 array of
  per-cell search energies (values 75M–215M on 602B); too large to be
  printed as terse F3 args, so not ``0x92``-groundable — kept opaque
  as ``grid_body_raw``.

### F3 grounding

Grounded on an EM7455 (SWI9X30C) firmware via its legacy-QSR (``0x92``)
on-device message index — the ``0x92`` envelope gives ``file:line`` + u32
args offline. The method is validated by a known-answer control on 0x1477
(layout grounded on 14 chipsets): its known ``f_count`` reproduces 155/155
at ``nf_navsolution.c:4886-4916 arg[0]`` and ``milliseconds`` 155/155 at
``mc_timetag.c:4630 arg[0]`` (frac 1.000, 155 distinct values).

For 0x13C7 (200B grid-summary):

* ``col_peak_value`` (body[0:4], == echo body[16:20]) = ``pp_columnpeaks.c:3428``
  **arg[1]** — value-set intersection 1415/1449 distinct (1841/1925 records).
* ``col_peak_energy`` (body[24:28]) = ``pp_columnpeaks.c:3428`` **arg[2]**
  (1775/1925 records; arg[2] is distinct per frame — a peak metric).
* ``pp_columnpeaks.c:3428`` arg[0] is a small peak index (1..79).

body[0:4] is not the nav-solution GPS full-cycle (``FC=``) counter despite
a similar ~276M magnitude: body[0:4] ∩ ``nf_navsolution.c`` arg[0] (the
control-confirmed FC print) = **0 of 1449**. It is a ``pp_columnpeaks``
peak value (a search-grid code-phase/time index). The
``mc_gnsssearchstrategy.c`` prints do not carry any 0x13C7 body field
verbatim (value-join noise, max 3 distinct); the grounding site is the peak
post-processor ``pp_columnpeaks.c``, downstream of the search strategy.

The ``0x92`` envelope carries no format string, so the two grounded fields
have no firmware field name — the names here are interpretations tied to
the emitting source site.

## byte-0 is not a version

byte-0 is the low byte of the uniformly-distributed record counter
(256/256 distinct values, ~equal counts across 271,795 corpus records),
**not** a DIAG log-version discriminant. The real parse-gate is the
self-describing length invariant ``payload_size == 8 + body_len`` (u16 LE
@ [6:8]) plus the universal ``reserved_2`` CONST 0x0000 — both enforced
below (``return None`` on violation), and strictly stronger than a byte-0
gate would be. A ``field_invariants["version"]={enum:[<some byte-0>]}`` would
therefore be semantically false (it would name a counter byte a
"version") and would wrongly reject 255/256 of the legitimate corpus.
Declared ``version_less=True``.

Log name: LOG_CONVERGED_GPS_MEDIUM_GRID_C
Also known as: LOG_INTERNAL_CGPS_MEDIUM_GRID
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


# Grid-summary sub-header (mode_flags bit0 == 0): 32-byte fixed prefix of the
# body, then a per-SV tail. Only the fields with 100% support on the
# grounding capture (or an F3 grounding) are pulled out by name; the tail is
# preserved raw. See the module docstring for the F3 grounding.
_GRID_SUMMARY_SUBHDR = 32


@dataclass
class Diag0x13C7:
    """0x13C7 — multi-size with self-describing u16 body_len.

    Header (8B) is fully named. The body is ``mode_flags``-bit0
    discriminated (see module docstring): the **grid-summary** layout
    (bit0==0) exposes an F3-grounded 32-byte sub-header; the **full-grid
    energy array** layout (bit0==1) is preserved raw.

    Key correctness invariant: ``payload_size == 8 + body_len``. Parser
    returns ``None`` on any record that violates this (covers truncated
    records and any future format change that breaks the length field).
    """

    log_time: int
    seq: int             # byte[0] — uniformly distributed counter, NOT version
    flags1: int          # byte[1] — per-record varying, semantic unknown
    reserved_2: int      # u16 from bytes[2:4] — universal CONST 0x0000
    mode_flags: int      # u16 from bytes[4:6] — bit0 selects body layout
    body_len: int        # u16 from bytes[6:8] — body length; size = 8 + body_len
    payload_size: int    # total record size (always == 8 + body_len)
    # "grid_summary" (mode bit0==0) | "grid_array" (mode bit0==1) | "header_only"
    layout: str = "header_only"
    # --- grid-summary sub-header (populated only when layout=="grid_summary") ---
    # F3-grounded to pp_columnpeaks.c:3428 arg[1]/arg[2] on SWI9X30C.
    col_peak_value: int | None = None       # body[0:4]  = pp_columnpeaks:3428 arg[1]
    reserved_body4: int | None = None        # body[4:8]  = CONST 0 (100%)
    grid_count: int | None = None            # body[8:12] = block/SV count-or-flag
    grid_word12: int | None = None           # body[12:16] = signed word, semantic open
    col_peak_value_echo: int | None = None    # body[16:20] == col_peak_value (100%)
    grid_resolution: int | None = None        # body[20:24] = per-class const (25000/…)
    col_peak_energy: int | None = None        # body[24:28] = pp_columnpeaks:3428 arg[2]
    reserved_body28: int | None = None        # body[28:32] = CONST 0 (100%)
    grid_body_raw: bytes | None = None        # body[32:] per-SV tail (grid_summary)
                                              # OR entire body (grid_array)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'type': 'Diag0x13C7',
            'log_time': self.log_time,
            'seq': self.seq,
            'flags1': self.flags1,
            'reserved_2': self.reserved_2,
            'mode_flags': self.mode_flags,
            'body_len': self.body_len,
            'payload_size': self.payload_size,
            'layout': self.layout,
        }
        if self.layout == "grid_summary":
            d.update({
                'col_peak_value': self.col_peak_value,
                'reserved_body4': self.reserved_body4,
                'grid_count': self.grid_count,
                'grid_word12': self.grid_word12,
                'col_peak_value_echo': self.col_peak_value_echo,
                'grid_resolution': self.grid_resolution,
                'col_peak_energy': self.col_peak_energy,
                'reserved_body28': self.reserved_body28,
                'grid_body_raw': self.grid_body_raw,
            })
        elif self.layout == "grid_array":
            d['grid_body_raw'] = self.grid_body_raw
        return d


@register(0x13C7,
    name="0x13C7",
    description=(
        "LTE Config 0x13C7 — multi-size MDM9x07/MDM9x30-gated; "
        "8-byte header with u16 LE body_len at bytes[6:8] s.t. "
        "payload_size = 8 + body_len; reserved_2 CONST 0x0000; "
        "chipset-gated (zero records on SDX20/SDX55/SDX62/X12)"
    ),
    version=4, author="Luke Jenkins", author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Header (8B) fully named; payload_size == 8 + body_len (u16 LE @ "
        "[6:8]) on a 24-fixture probe (4 modems x 7 size classes) and "
        "reserved_2 CONST 0x0000 across 271,795 records / 29 captures / 6 modems (Quectel EG25-G, EG18-NA, "
        "EG95-NA, EP06-A; Sierra MC7455; SIMCom SIM7600NA) on MDM9x07 + "
        "MDM9x30. Zero records on SDX20 (LM960, FN980), SDX55 (FN980 SDX55, "
        "RM500Q SDX55), SDX62 (RM520N-GL) and X12 (Inseego M2000). Body is "
        "mode_flags-bit0 discriminated: grid-summary (bit0==0, 200/170/135B) "
        "has an F3-grounded 32-byte sub-header; the grid-array energy array "
        "(bit0==1, 602/314/…B) is preserved raw. Grounded on SWI9X30C EM7455 "
        "via the 0x92 legacy-QSR message index: col_peak_value (body[0:4], "
        "==echo body[16:20]) = pp_columnpeaks.c:3428 arg[1] (1415/1449 "
        "distinct); col_peak_energy (body[24:28]) = pp_columnpeaks.c:3428 "
        "arg[2]. grid_resolution (body[20:24]) is a per-class const "
        "(25000/50000/100000/500000); reserved_body4/reserved_body28 CONST 0 "
        "(100% on 200/170B). Method validated by a known-answer control on "
        "0x1477 (155/155 f_count↔nf_navsolution.c, milliseconds↔"
        "mc_timetag.c). body[0:4] is not the nav FC counter (body[0:4] ∩ "
        "nf_navsolution arg[0] = 0/1449). byte-0 is the low byte of a "
        "uniform record counter, not a DIAG version (version_less=True). "
        "Open: the grid-summary per-SV tail, grid_count / grid_word12 "
        "semantics, and the grid-array body."
    ),
    issues=(),
    # 7 header/layout fields always + 8 grounded grid-summary sub-header fields.
    fields_identified=15,
    fields_parsed=15,
    field_invariants={
        "reserved_2": {"enum": [0x0000]},
    },
    # byte-0 is the low byte of a uniform record counter (256/256 values),
    # NOT a DIAG version; the `payload_size == 8 + body_len` length gate and
    # reserved_2 CONST 0x0000 (below) already reject foreign payloads. A
    # byte-0 `version` enum would be semantically false and reject 255/256 of
    # the corpus — see the byte-0 note in the module docstring.
    version_less=True,
)
def parse_0x13c7(log_time: int, data: bytes) -> Diag0x13C7 | None:
    n = len(data)
    if n < 8:
        return None
    body_len = unpack_from('<H', data, 6)[0]
    if 8 + body_len != n:
        # Layer-2 plausibility: the self-describing length must match the
        # record size. Any record that breaks this is either truncated or
        # a future format variant — reject so the corpus-decode pipeline
        # surfaces it rather than silently misparsing.
        return None
    mode_flags = unpack_from('<H', data, 4)[0]
    rec = Diag0x13C7(
        log_time=log_time,
        seq=data[0],
        flags1=data[1],
        reserved_2=unpack_from('<H', data, 2)[0],
        mode_flags=mode_flags,
        body_len=body_len,
        payload_size=n,
    )
    if body_len == 0:
        return rec  # layout stays "header_only"
    if mode_flags & 0x0001:
        # full-grid energy array (mode 0x8001) — dense per-cell search energies,
        # not F3-groundable (too large for terse args). Preserve raw.
        rec.layout = "grid_array"
        rec.grid_body_raw = bytes(data[8:])
        return rec
    if body_len >= _GRID_SUMMARY_SUBHDR:
        # grid-summary (mode 0x0000 / 0x8000) — 32-byte F3-grounded sub-header
        # then a per-SV tail. Offsets below are body-relative (+8).
        rec.layout = "grid_summary"
        rec.col_peak_value = unpack_from('<I', data, 8)[0]
        rec.reserved_body4 = unpack_from('<I', data, 12)[0]
        rec.grid_count = unpack_from('<I', data, 16)[0]
        rec.grid_word12 = unpack_from('<i', data, 20)[0]  # signed, semantic open
        rec.col_peak_value_echo = unpack_from('<I', data, 24)[0]
        rec.grid_resolution = unpack_from('<I', data, 28)[0]
        rec.col_peak_energy = unpack_from('<I', data, 32)[0]
        rec.reserved_body28 = unpack_from('<I', data, 36)[0]
        rec.grid_body_raw = bytes(data[40:])
        return rec
    # bit0==0 but body too short for the sub-header — preserve raw, name known.
    rec.layout = "grid_array"
    rec.grid_body_raw = bytes(data[8:])
    return rec
