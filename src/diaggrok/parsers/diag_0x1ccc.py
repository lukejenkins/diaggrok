"""GNSS GPS L1 measurement report — 47 B header + N x 118 B per-SV slots.

A **GNSS measurement** log code, not an NR5G ML1 code despite its position
in the code range.

F3 grounding (v0x01): the firmware names this code when
it allocates the packet, ``Log packet id|SvCnt 0x1ccc000b. Tot sz 1357 bytes.
118 bytes per SV`` (``mc_gnssmeasreport.c:923``; 0x1ccc << 16 | 11 SVs, and
1357 = 12 B log header + 47 + 11 * 118). It prints the block itself as
``L1Gps_MBlk(1Hz) - N SVs,FC ..,Wk ..,Ms ..,CB ..,TMs ..`` (``:6614``, 0x79
plaintext). Joined by FC on two Inseego M3100 (SDX65) captures, 745/745
records match: N SVs == header[46], and Wk / Ms / CB / TMs == the header
clock fields. The slot SV ids are GPS PRNs (1..32).

Slots: 18 per-SV fields (C/N0, latency, SV time integral and
fraction, time uncertainty, speed and its uncertainty, azimuth, elevation,
status, cycle slips, ...) are value-joined to the co-emitted legacy GPS report
0x1477 by (FC, sv_id): 7,597 / 7,597 joined SV rows match on every field, on
SDX62, SDX65 and SDX72. The shared header and slot layouts and the full
verdict are in the ``_gnss_meas118_helpers.py`` module docstring.

Size: header byte[46] is the SV count N, and ``len == 47 + 118 * N`` holds on
54,734 / 54,734 corpus records, N 0..16 (1935 B, CFW-3212 RG520N-NA, is the
max). The 47 B records carry the header only (no SV tracked, e.g. a drive
with poor sky view). Accepted: N in 0..16, coupled to the length. Any other
N or length returns None (fail loudly).
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
_SLOT_COUNTS = frozenset(range(0, 17))
_PAYLOAD_SIZES = trio_payload_sizes(_SLOT_COUNTS)  # 47 .. 1935


@dataclass
class Diag0x1CCC:
    """GNSS GPS L1 measurement report — 47 B header + N slots."""

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
            "type": "Diag0x1CCC",
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
    0x1CCC,
    name="0x1CCC",
    description=(
        "GNSS GPS L1 measurement report — 47 B header + N x 118 B "
        "per-SV slots, version=1, header byte[46] = N (0..16). F3-grounded: "
        "the firmware names the code in its packet-allocation print "
        "('Log packet id|SvCnt 0x1ccc000b ... 118 bytes per SV') and its "
        "L1Gps_MBlk(1Hz) print matches N SVs and the FC / GPS week / ms / "
        "clock bias / time uncertainty header fields on 745/745 joined M3100 "
        "records. Slot SV ids are GPS PRNs 1..32; 18 per-SV slot fields are "
        "value-joined to the co-emitted 0x1477 GPS report (7,597/7,597 SV "
        "rows, SDX62/65/72)."
    ),
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "F3-grounded v0x01: mc_gnssmeasreport.c:923 'Log "
        "packet id|SvCnt 0x1ccc000b. Tot sz 1357 bytes. 118 bytes per SV' "
        "(and 0x1ccc000a / 1239 B) names the code; mc_gnssmeasreport.c:6614 "
        "'L1Gps_MBlk(1Hz) - N SVs,FC,Wk,Ms,CB,TMs,...' joined by FC to 188 + "
        "557 records on two Inseego M3100 (SDX65) "
        "captures, 0 mismatches: N == byte[46], FC == u32@16, Wk == u16@20, "
        "Ms == u32@22, CB == f32@26, TMs == f32@30; the preceding :6597 "
        "print's F / FUnc == trunc(f32@34 / f32@38). Slot u16@0 is the GPS "
        "PRN. Slot fields value-joined to 0x1477 by (f_count, sv_id): "
        "7,597/7,597 SV rows on RM520N-GL SDX62 (2,804), M3100 SDX65 (4,551) "
        "and T99W640 SDX72 (242), 0 mismatches. Clean-room RE from RM520N-GL SDX62, 7,392 records "
        "across 11 captures; version=1 and code_discriminator=0 hold across "
        "every record. const_word (u32@4) is not invariant (13..35 "
        "observed). Sierra EM9291 (also SDX62) adds 2,349 records "
        "/ 15 captures and the 755/1109 B members of the 47 + 118N series."
    ),
    source_url="",
    issues=(),
    fields_identified=40, fields_parsed=38,
    field_invariants={
        "version": {"enum": [1]},
        "code_discriminator": {"enum": [0]},
        "payload_size": {"enum": list(_PAYLOAD_SIZES)},
        "slot_count": {"range": [min(_SLOT_COUNTS), max(_SLOT_COUNTS)]},
    },
)
def parse_0x1ccc(log_time: int, data: bytes) -> Diag0x1CCC | None:
    if len(data) not in _PAYLOAD_SIZES:
        return None
    if data[0] != 1:
        return None
    # Also enforces len == 47 + 118 * byte[46] with byte[46] in _SLOT_COUNTS.
    h = _parse_trio_header(data, _SLOT_COUNTS)
    if h is None:
        return None
    return Diag0x1CCC(
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
