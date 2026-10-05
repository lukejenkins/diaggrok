"""GNSS QZSS/SBAS L1 measurement report — 47 B header + N x 118 B per-SV slots.

A **GNSS measurement** log code, not an NR5G ML1 code despite its position
in the code range.

F3 status (v0x01): this code has no MBlk print of its
own in the M3100 (SDX65) build, unlike its siblings 0x1CCC (``L1Gps_MBlk``)
and 0x1CE1 (``L5QzSbas_MBlk``). Its header is the same shared layout, and
FC-joined to those siblings' prints on two M3100 captures it carries the same
epoch: GPS week / ms / clock bias / time uncertainty match on 745/747 joined
records, and the preceding ``:6597`` print's F / FUnc == trunc(header
freq_bias / freq_unc) on 745/745. N SVs never equals either sibling print's
count, so this is a third per-SV block. Its slot SV ids are SBAS and QZSS
(the two WAAS GEOs 131 / 133 on 25,540 slots, plus QZSS 194..201), which
makes it the L1 counterpart of ``L5QzSbas``. N is never 0 because a WAAS GEO
is almost always tracked; its direction carries the -90 deg sentinel. The
shared header layout and the full verdict are in the
``_gnss_meas118_helpers.py`` module docstring.

Slots: value-joined to the legacy twin 0x18F5. 0x18F5 is
the 0x1477 GPS report's layout applied to QZSS / SBAS. By (FC, sv_id), every
named slot field equals the 0x18F5 block field on 1,677 / 1,677 M3100 (SDX65)
rows, apart from parity on not-tracking (observation_state 1) QZSS rows,
where 0x18F5 carries noise and 0x1CCB 0.

Size: header byte[46] is the SV count N. The corpus carries N=1 (165 B,
3,485 records on RM520N-GL SDX62, Inseego M3100 SDX65 and Foxconn
T99W640 SDX72), N=2 (283 B) and N=3 (401 B, 627 records, M3100). N is
never 0 in the
corpus. Accepted: N in {1, 2, 3}, coupled to ``len == 47 + 118 * N``. Any
other N or length returns None (fail loudly).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from diaggrok.parsers._gnss_meas118_helpers import (
    _TRIO_HEADER_LEN,
    GnssMeas118Slot,
    _parse_trio_header,
    parse_slots,
    trio_payload_sizes,
)
from diaggrok.registry import register

# Corpus-attested slot counts. Widen only against a real record.
_SLOT_COUNTS = frozenset({1, 2, 3})
_PAYLOAD_SIZES = trio_payload_sizes(_SLOT_COUNTS)  # [165, 283, 401]


@dataclass
class Diag0x1CCB:
    """GNSS QZSS/SBAS L1 measurement report — 47 B header + N slots."""

    log_time: int
    version: int
    code_discriminator: int
    capture_marker: int
    const_word: int
    tick_a: int
    fcount: int
    gps_week: int
    gps_ms: int
    clk_bias_ms: float
    clk_tunc_ms: float
    freq_bias_mps: float
    freq_unc_mps: float
    hdr_f32_42: float
    cell_context: bytes
    slot_count: int
    sv_ids: tuple[int, ...]
    slots: list[GnssMeas118Slot]
    body: bytes
    payload_size: int

    @property
    def tick_b(self) -> int:
        """Old name for ``fcount``."""
        return self.fcount

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x1CCB",
            "log_time": self.log_time,
            "version": self.version,
            "code_discriminator": self.code_discriminator,
            "capture_marker": self.capture_marker,
            "const_word": self.const_word,
            "tick_a": self.tick_a,
            "fcount": self.fcount,
            "gps_week": self.gps_week,
            "gps_ms": self.gps_ms,
            "clk_bias_ms": self.clk_bias_ms,
            "clk_tunc_ms": self.clk_tunc_ms,
            "freq_bias_mps": self.freq_bias_mps,
            "freq_unc_mps": self.freq_unc_mps,
            "hdr_f32_42": self.hdr_f32_42,
            "slot_count": self.slot_count,
            "sv_ids": list(self.sv_ids),
            "slots": [sl.to_dict() for sl in self.slots],
            # Old names, kept for JSON consumers.
            "tick_b": self.fcount,
            "cell_context_len": len(self.cell_context),
            "trailing_zero": self.slot_count,
            "body_len": len(self.body),
            "payload_size": self.payload_size,
        }


@register(
    0x1CCB,
    name="0x1CCB",
    description=(
        "GNSS QZSS/SBAS L1 measurement report — 47 B header + N x "
        "118 B per-SV slots, version=1, header byte[46] = N in {1, 2, 3} "
        "(165/283/401 B). Shares the F3-grounded header (FC / GPS week / ms "
        "/ clock bias / time uncertainty / freq bias) with 0x1CCC (GPS L1) "
        "and 0x1CE1 (QZSS/SBAS L5). Slot SV ids are SBAS / QZSS."
    ),
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "F3 v0x01: no MBlk print of its own in the M3100 (SDX65) build; FC-joined to the sibling "
        "L1Gps_MBlk / L5QzSbas_MBlk prints on two M3100 captures, the header "
        "clock fields match on 745/747 records and the :6597 print's F / "
        "FUnc == trunc(f32@34 / f32@38) on 745/745. Slot u16@0 is the SV id. "
        "Clean-room RE from RM520N-GL SDX62, 4,392 records across 8 "
        "captures; version=1 and code_discriminator=0 on every record. "
        "const_word (u32@4) is not invariant (13..35 observed). Sierra "
        "EM9291 (also SDX62) adds 2,349 records / 15 captures."
    ),
    source_url="",
    issues=(),
    fields_identified=40, fields_parsed=38,
    field_invariants={
        "version": {"enum": [1]},
        "code_discriminator": {"enum": [0]},
        "payload_size": {"enum": list(_PAYLOAD_SIZES)},
        "slot_count": {"enum": sorted(_SLOT_COUNTS)},
    },
)
def parse_0x1ccb(log_time: int, data: bytes) -> Diag0x1CCB | None:
    if len(data) not in _PAYLOAD_SIZES:
        return None
    if data[0] != 1:
        return None
    # Also enforces len == 47 + 118 * byte[46] with byte[46] in _SLOT_COUNTS.
    h = _parse_trio_header(data, _SLOT_COUNTS)
    if h is None:
        return None
    return Diag0x1CCB(
        log_time=log_time,
        version=h.version,
        code_discriminator=h.code_discriminator,
        capture_marker=h.capture_marker,
        const_word=h.const_word,
        tick_a=h.tick_a,
        fcount=h.fcount,
        gps_week=h.gps_week,
        gps_ms=h.gps_ms,
        clk_bias_ms=h.clk_bias_ms,
        clk_tunc_ms=h.clk_tunc_ms,
        freq_bias_mps=h.freq_bias_mps,
        freq_unc_mps=h.freq_unc_mps,
        hdr_f32_42=h.hdr_f32_42,
        cell_context=h.cell_context,
        slot_count=h.slot_count,
        sv_ids=h.sv_ids,
        slots=parse_slots(data, h.slot_count),
        body=bytes(data[_TRIO_HEADER_LEN:]),
        payload_size=len(data),
    )
