"""GNSS QZSS/SBAS L5 measurement report — 47 B header + N x 118 B per-SV slots.

A **GNSS measurement** log code, not an NR5G ML1 code despite its position
in the code range.

F3 grounding (v0x01): the firmware prints this block as
``L5QzSbas_MBlk - N SVs,FC ..,Wk ..,Ms ..,CB ..,TMs ..,Src .. Seq 6 C 7``
(``mc_gnssmeasreport.c:9868``, 0x79 plaintext). Joined by FC on two Inseego
M3100 (SDX65) captures, 736/736 records match: N SVs == header[46], Seq ==
header[1], and Wk / Ms / CB / TMs == the header clock fields. The only SV the
corpus carries is QZSS (sv_id 193..202). The shared header layout and the full
verdict are in the ``_gnss_meas118_helpers.py`` module docstring.

Slots: the shared 118 B layout. Against the legacy L1 QZSS/SBAS report 0x18F5,
only the frequency-independent fields can join: azimuth, elevation,
fine_speed and fine_speed_unc match on 543 / 543 QZSS 195 rows (M3100 SDX65),
speed on 536 / 543. The per-signal fields (C/N0, measurement block, latency,
status) are L5 values with no legacy L5 report to join. They use the layout by
transfer (same writer), so treat them as CANDIDATE.

Header byte[46] is the SV count N. Almost every record is N=0 (47 B, the
header only). Inseego M3100 SDX65 also emits N=1 (165 B, 634 records / 4
captures).
Accepted: N in {0, 1}, coupled to ``len == 47 + 118 * N``. Any other N or
length returns None (fail loudly).
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
_SLOT_COUNTS = frozenset({0, 1})
_PAYLOAD_SIZES = trio_payload_sizes(_SLOT_COUNTS)  # [47, 165]


@dataclass
class Diag0x1CE1:
    """GNSS QZSS/SBAS L5 measurement report — 47 B header + N slots."""

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
            "type": "Diag0x1CE1",
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
    0x1CE1,
    name="0x1CE1",
    description=(
        "GNSS QZSS/SBAS L5 measurement report — 47 B header + N x "
        "118 B per-SV slots, version=1, header byte[46] = N. F3-grounded: "
        "the firmware's L5QzSbas_MBlk print (mc_gnssmeasreport.c) matches "
        "N SVs, Seq, and the FC / GPS week / ms / clock bias / time "
        "uncertainty header fields on 736/736 joined M3100 records. N=0 "
        "(47 B) on every SDX62/SDX65 source; N=1 (165 B, QZSS) on Inseego "
        "M3100 SDX65. code_discriminator is per-session (0x03, 0x05, 0x06 "
        "on Quectel RM520N-GL; 0x07 on Sierra EM9291); do not enum-lock it."
    ),
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "F3-grounded v0x01: mc_gnssmeasreport.c:9868 "
        "'L5QzSbas_MBlk - N SVs,FC,Wk,Ms,CB,TMs,Src,Seq,C' joined by FC to "
        "189 + 547 records on two Inseego M3100 (SDX65) "
        "captures, 0 mismatches: N == byte[46], Seq == byte[1], "
        "FC == u32@16, Wk == u16@20, Ms == u32@22, CB == f32@26, TMs == "
        "f32@30; the preceding :6597 print's F / FUnc == trunc(f32@34 / "
        "f32@38). Slot u16@0 is the SV id (QZSS 193..202). "
        "Clean-room RE from RM520N-GL SDX62, 3,090 records across 6 "
        "captures. code_discriminator is per-session (0x06: 1,494 / 0x03: "
        "977 / 0x05: 619). const_word is not enum-locked (the siblings "
        "0x1CCB/0x1CCC show 13..35 on RM520N-GL). Sierra EM9291 (also "
        "SDX62) adds 2,330 records / 15 "
        "captures and a 4th code_discriminator value 0x07."
    ),
    source_url="",
    issues=(),
    fields_identified=40, fields_parsed=38,
    field_invariants={
        "version": {"enum": [1]},
        "payload_size": {"enum": list(_PAYLOAD_SIZES)},
        "slot_count": {"enum": sorted(_SLOT_COUNTS)},
    },
)
def parse_0x1ce1(log_time: int, data: bytes) -> Diag0x1CE1 | None:
    if len(data) not in _PAYLOAD_SIZES:
        return None
    if data[0] != 0x01:
        return None
    # Also enforces len == 47 + 118 * byte[46] with byte[46] in _SLOT_COUNTS.
    h = _parse_trio_header(data, _SLOT_COUNTS)
    if h is None:
        return None
    return Diag0x1CE1(
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
