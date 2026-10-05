"""GNSS BeiDou B1C measurement report — 47 B header + N x 118 B per-SV slots.

A **GNSS measurement** log code, not an NR5G ML1 code despite its position
in the code range. Canonical name ``LOG_GNSS_BDS_B1C_MEASUREMENT_REPORT``. The format is the
shared ``47 + 118 * N`` per-SV report of 0x1CCC / 0x1CCB / 0x1CE1; header and
slot layouts are in ``_gnss_meas118_helpers.py``. Only the Sierra EM9291
(SDX62) emits it in the corpus: 9,246 records / 36
captures, all v0x01.

F3 grounding (v0x01)
--------------------
Every 0x1CC6 record has a co-emitted 0x1CCC (GPS L1) and 0x1756 (BDS B1I)
record at the same FC (u32@16): 9,246 / 9,246 join on both.

* **F3, own records.** This build prints only ``L1Gps_MBlk(1Hz)``
  (``mc_gnssmeasreport.c:6905``, 0x79 plaintext) per epoch, no BDS block
  print (like 0x1CCB on the M3100). In an F3-bearing EM9291 capture,
  all 155 prints
  join to a 0x1CC6 record by FC, and 0x1CC6's own header matches the print
  on 155 / 155: N SVs 0 == byte[46], Wk == u16@20, Ms == u32@22,
  CB == f32@26, TMs == f32@30. Those epochs have no time (Wk 65535, TMs the
  3.15e12 sentinel), so this pins the fields, not the time base.
* **Time base is BDS time.** With time known (3,228 records), u16@20 /
  u32@22 are the **BDS** week and ms of week: exactly GPS week − 1356 and GPS
  ms − 14,000 against the F3-grounded 0x1CCC header, and equal to the 0x1756
  B1I header, on 3,228 / 3,228. With no time (week 0xFFFF, 6,018 records)
  they equal 0x1CCC's raw value. CB, freq bias / unc, FC and the raw words
  equal 0x1CCC on 9,246 / 9,246; TMs differs once time is known (BDS time
  uncertainty).
* **Identity.** Slot SV ids are 220..242 (BDS PRN C20..C42, Sierra 200+PRN
  numbering). B1C is broadcast only by BDS-3 satellites (C19+): the BDS-2
  C08 / C11..C14 slots (~7,200) appear on 0x1756 B1I and never here.
* **Slots, cross-signal.** Joined to the co-emitted 0x1756 B1I slots by
  (FC, sv_id): 23,492 SV rows, 0 unmatched. Azimuth / elevation identical on
  23,492 / 23,492; SV-time integral equal on 23,179 and fraction, time unc
  and speed within 1 % on ~96 % (same satellite, independent signal
  tracking). C/N0 differs, as it should for a different signal.
* **Slots, external.** ``AT!GPSSATINFO?`` (a GNSS comparison capture,
  epochs 0.4 s from the poll): 1,434 SV rows, elevation within −1..+1.5 deg
  and azimuth within −1..+2 deg on all (AT prints whole degrees). The SVs
  with live C/N0 here are exactly the BDS-3-only set of AT's 2nd / 3rd BDS
  band listings. AT's SNR does not track the slot C/N0 closely (medians
  0.5..6.5 dB off, sampled at a different instant), so C/N0 stays a transfer
  from the 0x1477-joined 0x1CCC slot (CANDIDATE), as do the other slot
  fields not checked above.

``code_discriminator`` (byte[1]) is 5 on the no-time records (6,018), 6 on
time-known empty or early records (98) and 10 on populated records (3,130).
It looks like a receiver state, not a sequence. Kept raw. On this silicon
``capture_marker`` (u16@2) equals byte[1] on 9,246 / 9,246 (the M3100 trio
carries a per-session constant 7 there), so no real record separates them.

In-capture oracle verdicts: F3 labelled (above). ``0x60``: not consulted for
a per-SV quantity (only GNSS session events fire, as on 0x1C60).
Black-box (qcsuper / SCAT): no output for this code (neither decodes GNSS
measurement reports).

Size (fail loudly): the parser enforces ``len == 47 + 118 * byte[46]``
with byte[46] bounded and a ``payload_size`` enum. The corpus N set is {0, 1, 3..9} (47..1109 B, 0 records
off-stride); N = 2 is interior and unobserved. Accepted: N in 0..9, coupled
to the length. Any other N or length returns None.

Older field names stay available as aliases: ``block_count`` (byte[46],
now ``slot_count``), ``report_id`` (u32@4, now ``const_word``) and
``blocks_raw`` (now ``body``).

Log name: LOG_GNSS_BDS_B1C_MEASUREMENT_REPORT
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

# Corpus-attested slot counts (0..9, N = 2 interior). Widen only against a
# real record.
_SLOT_COUNTS = frozenset(range(0, 10))
_PAYLOAD_SIZES = trio_payload_sizes(_SLOT_COUNTS)  # 47 .. 1109


@dataclass
class Diag0x1CC6:
    """GNSS BeiDou B1C measurement report — 47 B header + N slots."""

    log_time: int
    version: int
    code_discriminator: int
    capture_marker: int
    const_word: int
    tick_a: int
    fcount: int
    bds_week: int
    bds_ms: int
    clk_bias_ms: float
    clk_tunc_ms: float
    freq_bias_mps: float
    freq_unc_mps: float
    hdr_f32_42: float
    slot_count: int
    sv_ids: tuple[int, ...]
    slots: list[GnssMeas118Slot]
    body: bytes
    payload_size: int

    @property
    def report_id(self) -> int:
        """Old name for ``const_word``."""
        return self.const_word

    @property
    def block_count(self) -> int:
        """Old name for ``slot_count``."""
        return self.slot_count

    @property
    def blocks_raw(self) -> bytes:
        """Old name for ``body``."""
        return self.body

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x1CC6",
            "log_time": self.log_time,
            "version": self.version,
            "code_discriminator": self.code_discriminator,
            "capture_marker": self.capture_marker,
            "const_word": self.const_word,
            "tick_a": self.tick_a,
            "fcount": self.fcount,
            "bds_week": self.bds_week,
            "bds_ms": self.bds_ms,
            "clk_bias_ms": self.clk_bias_ms,
            "clk_tunc_ms": self.clk_tunc_ms,
            "freq_bias_mps": self.freq_bias_mps,
            "freq_unc_mps": self.freq_unc_mps,
            "hdr_f32_42": self.hdr_f32_42,
            "slot_count": self.slot_count,
            "sv_ids": list(self.sv_ids),
            "slots": [sl.to_dict() for sl in self.slots],
            # Old names, kept for JSON consumers.
            "report_id": self.const_word,
            "block_count": self.slot_count,
            "body_len": len(self.body),
            "payload_size": self.payload_size,
        }


@register(
    0x1CC6,
    name="0x1CC6",
    description=(
        "GNSS BeiDou B1C measurement report — 47 B header + N x 118 B "
        "per-SV slots, version=1, header byte[46] = N (0..9, 47..1109 B). "
        "Header F3-grounded against the L1Gps_MBlk epoch print (155/155); "
        "u16@20 / u32@22 are BDS week / ms (GPS - 1356 wk, - 14,000 ms, "
        "3,228/3,228). Slot SV ids are BDS-3 PRNs (220..242); az/el equal "
        "the co-emitted 0x1756 B1I slots (23,492/23,492) and AT!GPSSATINFO."
    ),
    version=5,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "F3-grounded v0x01 on the EM9291 (SDX62), the only emitter (9,246 "
        "records / 36 captures). mc_gnssmeasreport.c:6905 'L1Gps_MBlk(1Hz) - "
        "N SVs,FC,Wk,Ms,CB,TMs' joined by FC to 155/155 0x1CC6 records in an "
        "F3-bearing capture: N == byte[46], Wk == "
        "u16@20, Ms == u32@22, CB == f32@26, TMs == f32@30. Time base: BDS "
        "week/ms (0x1CCC GPS week - 1356, ms - 14,000; == 0x1756 B1I "
        "header) on 3,228/3,228 time-known records. Slots: (FC, sv_id) join "
        "to 0x1756 B1I, 23,492 SV rows, az/el identical, SV-time integral "
        "equal on 23,179; AT!GPSSATINFO az/el within AT's whole-degree "
        "rounding on 1,434/1,434. SV ids 220..242 only (BDS-3; BDS-2 "
        "C08/C11..C14 appear on B1I only). Slot C/N0 and the fields not "
        "checked above remain CANDIDATE (transfer from 0x1CCC)."
    ),
    source_url="",
    issues=(),
    fields_identified=40, fields_parsed=38,
    field_invariants={
        "version": {"enum": [1]},
        "payload_size": {"enum": list(_PAYLOAD_SIZES)},
        "slot_count": {"range": [min(_SLOT_COUNTS), max(_SLOT_COUNTS)]},
    },
)
def parse_0x1cc6(log_time: int, data: bytes) -> Diag0x1CC6 | None:
    if len(data) not in _PAYLOAD_SIZES:
        return None
    if data[0] != 1:
        return None
    # Also enforces len == 47 + 118 * byte[46] with byte[46] in _SLOT_COUNTS.
    h = _parse_trio_header(data, _SLOT_COUNTS)
    if h is None:
        return None
    return Diag0x1CC6(
        log_time=log_time,
        version=h.version,
        code_discriminator=h.code_discriminator,
        capture_marker=h.capture_marker,
        const_word=h.const_word,
        tick_a=h.tick_a,
        fcount=h.fcount,
        bds_week=h.gps_week,
        bds_ms=h.gps_ms,
        clk_bias_ms=h.clk_bias_ms,
        clk_tunc_ms=h.clk_tunc_ms,
        freq_bias_mps=h.freq_bias_mps,
        freq_unc_mps=h.freq_unc_mps,
        hdr_f32_42=h.hdr_f32_42,
        slot_count=h.slot_count,
        sv_ids=h.sv_ids,
        slots=parse_slots(data, h.slot_count),
        body=bytes(data[_TRIO_HEADER_LEN:]),
        payload_size=len(data),
    )
