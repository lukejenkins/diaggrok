"""0xB141 — LTE per-subframe Rx-chain count + 4-lane filter-coefficient batch (v0x79).

Legacy registry label `LteMacB141` (a family heuristic from an early bulk
stub parser, not a canonical name — the only name table lists the code as
``RESERVED``). The body is not MAC: it is a batch
of LTE LL1/ML1 per-subframe records keyed by (SFN, subframe) whose one
F3-grounded quantity is the **ARD (Adaptive Rx Diversity) active Rx-chain
count**. The layout below comes from the full corpus:
21,148 records / 211,480 sub-records / 5 captures, all Telit LM960 (SDX20,
two firmware builds), every record 524 B, byte 0 0x79.

Layout (v0x79, little-endian)::

  [0]      version       u8   = 0x79 (121) — see "Version" below
  [1]      hdr_b1        u8   : bits 3..7 = num_records, bits 0..2 = 0
  [2:4]    hdr_reserved  u16  = 0 (corpus-invariant)
  [4:]     records[num_records], 52 B each:
     +0    sfn           u16  0..1023 (bits 10..15 = 0, corpus-invariant)
     +2    subframe      u8   0..9
     +3    reserved_3    u8   = 0
     +4    num_rx        u32  ∈ {2, 4} — active Rx chains (F3-GROUNDED)
     +8    reserved_8    u32  = 0
     +12   reserved_12   u32  = 0
     +16   coef_a_q14    4 × u16  per-lane weight, Q14 (0x4000 = 1.0)
     +24   coef_b_q14    4 × u16  per-lane weight, Q14
     +32   word_32 .. word_48  5 × u32  raw (see below)

  len == 4 + 52 * num_records.  Every corpus record: num_records = 10, 524 B.

Grounding (F3 = the firmware's own debug prints, same captures):

* ``num_rx`` — **GROUNDED** against ARD F3 on three captures.
  - LM960 idle capture (all-2Rx): ``lte_ml1_dlm_ard_new.c``
    "ARD meas result, cc0 valid numRx = %d" fires **25,183** times; the capture
    holds exactly **25,183** sf-0 sub-records — 1:1 co-emission, per-second
    bins equal apart from the 25 ms batch-flush jitter. F3 numRx = 2 and
    ``num_rx`` = 2 on all 100,720 sub-records.
  - LM960 SIM-attach capture (connected, B12 EARFCN 5035 + B66 EARFCN 66786):
    ``num_rx`` equals the last ARD-applied rxmap ("[cnf] new rxmap:%d", both
    confirm sites) on **13,600 / 13,660 (99.56%)** sub-records timed per
    sub-frame; all 60 misses lie ≤ 26 ms from an rxmap-change print (one
    record's batch window). ``num_rx`` = 4 only on B66 (4Rx-capable band),
    2 on B12; SCAT's MIB decode gives TX antennas = 4 on every cell, so the
    field is not the eNB Tx-port count.
  - LM960A18 drive capture: **11,198 / 11,540 (97.0%)**, every miss
    ≤ 119 ms from an rxmap-change print (HDLC stream, looser ts alignment).
* ``sfn`` / ``subframe`` — **GROUNDED**: ARD F3 ``sf_now`` (SFN*10+sf mod
  10240) minus the sub-record's SFN*10+sf, extrapolated to the F3 ts, is
  0 ± 1 ms on 88% (SIM attach, n = 3,995) and 86% (drive, n = 2,758) of
  prints; the tail is DRX gaps where linear extrapolation breaks.
  Two emission regimes: idle/camped — sub-frames {0,1,5,6} only (Δ 1 ms / 4 ms;
  the PCC is TDD there, F3 ``[RM] tdd_mask:0x1``, and ARD F3 names sf 1/6
  "First non-DMS after DMS"); connected — every sub-frame, Δ 1 ms.
* ``coef_a_q14`` / ``coef_b_q14`` — **CANDIDATE** recursive-filter weights,
  F3-SILENT (no print carries these values; the ``ant_corr_rpt`` "iir_a:1638"
  is a different filter and 0x0666 never appears here). Structural evidence:
  a + b == 0x4000 (1.0 Q14) on 90.8% of 845,920 lane slots; after a reset
  (a = 1.0, b = 0) the lane walks a = 1/2, 1/3, … 1/9 with b = 1 − a — a
  running-mean warm-up — then clamps to a floor (0x00a4 ≈ 0.01, 0x028c ≈
  0.04, 0x00dc). 8.0% of slots are 0x7fff / 0x5555 with b = 0 (meaning
  unknown); 1.2% are other transitionals. Lanes 0 == 1 and 2 == 3 on 100% of
  sub-records. The "lanes 2/3 held" state (a = 0, b = 1.0) occurs only when
  num_rx == 2 (3,304 sub-records, never at 4). At the 182 in-record num_rx
  switches, lanes 2/3 in the switching sub-frame are: 4→2 (94) — zeroed
  a = b = 0 (68) or held (26), never active weights; 2→4 (88) — re-seeded
  a = 1.0 / b = 0 (59), 0x5555 / 0 (28), unchanged floor (1). Consistent with
  lanes 2/3 tracking Rx chains 2/3 — not proven: they also stay active at
  num_rx == 2 on most sub-records.
* ``word_32`` .. ``word_48`` — raw, F3-silent. word_32/word_36 alternate
  between two values on successive sub-frames (0x221000/0x2210d0,
  0x2218f0/0x221a90, …) — ping-pong buffer-address-like; word_48 is a
  flag-like word (0x22820c idle; 0x3820c / 0x23820c / 0x3823c connected).
  Exposed, not named.
* ``0x60`` events: SILENT — 125 distinct event ids across the 3 captures that
  carry events, none an Rx-diversity / ARD /
  antenna / Doppler event; ABSENT on the other 2 (no 0x60 frames).

Version: byte 0 is 0x79 on all 21,148 records. Sibling LTE-PHY codes carry the
same 0x79 on this firmware and 0xA1 on others (0xB140, 0xB143, 0xB144), so
it reads as a per-firmware LL1 interface version. Only v0x79 is
implemented; any other byte 0, or a size that disagrees with num_records,
returns None so the registry's dispatch warning fires instead of
mis-slicing an unseen layout.

No PII: the log carries no identifiers.
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

B141_VERSION = 0x79
_HDR_SIZE = 4
_REC_SIZE = 52


@dataclass
class B141Record:
    """One 52-byte per-subframe record."""
    sfn: int
    subframe: int
    reserved_3: int
    num_rx: int
    reserved_8: int
    reserved_12: int
    coef_a_q14: tuple[int, int, int, int]
    coef_b_q14: tuple[int, int, int, int]
    word_32: int
    word_36: int
    word_40: int
    word_44: int
    word_48: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "sfn": self.sfn,
            "subframe": self.subframe,
            "reserved_3": self.reserved_3,
            "num_rx": self.num_rx,
            "reserved_8": self.reserved_8,
            "reserved_12": self.reserved_12,
            "coef_a_q14": list(self.coef_a_q14),
            "coef_b_q14": list(self.coef_b_q14),
            "word_32": self.word_32,
            "word_36": self.word_36,
            "word_40": self.word_40,
            "word_44": self.word_44,
            "word_48": self.word_48,
        }


@dataclass
class Diag0xB141:
    """0xB141 v0x79 — header + num_records × 52 B per-subframe records."""
    log_time: int
    version: int
    num_records: int
    hdr_b1_low: int
    hdr_reserved: int
    payload_size: int
    records: list[B141Record]

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB141",
            "log_time": self.log_time,
            "version": self.version,
            "num_records": self.num_records,
            "hdr_b1_low": self.hdr_b1_low,
            "hdr_reserved": self.hdr_reserved,
            "payload_size": self.payload_size,
            "records": [r.to_dict() for r in self.records],
        }


def _parse_record(data: bytes, off: int) -> B141Record:
    (sfn, subframe, reserved_3, num_rx, reserved_8, reserved_12) = unpack_from(
        "<HBBIII", data, off)
    coef_a = unpack_from("<4H", data, off + 16)
    coef_b = unpack_from("<4H", data, off + 24)
    words = unpack_from("<5I", data, off + 32)
    return B141Record(
        sfn=sfn,
        subframe=subframe,
        reserved_3=reserved_3,
        num_rx=num_rx,
        reserved_8=reserved_8,
        reserved_12=reserved_12,
        coef_a_q14=coef_a,
        coef_b_q14=coef_b,
        word_32=words[0],
        word_36=words[1],
        word_40=words[2],
        word_44=words[3],
        word_48=words[4],
    )


@register(
    0xB141,
    name="0xB141",
    description=(
        "LTE per-subframe Rx-chain count (ARD, F3-grounded) + 4-lane Q14 "
        "filter coefficients — v0x79, 4 B header + N x 52 B records"
    ),
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Body decoded over the full corpus "
        "(21,148 records, 5 LM960 captures, 2 firmware builds) - 4 B header "
        "(num_records = byte1>>3) + 10 x 52 B per-subframe records. num_rx "
        "F3-GROUNDED vs lte_ml1_dlm_ard_new.c ARD numRx / rxmap prints: 25,183 "
        "= 25,183 1:1 co-emission (idle), 99.56% (sim_attach) and 97.0% "
        "(wardrive) per-subframe agreement with every miss at an rxmap edge; "
        "SCAT MIB TX-antennas = 4 on every cell rules out an eNB-Tx-port reading. "
        "sfn/subframe GROUNDED vs ARD F3 sf_now (0 +/- 1 ms on 86-88%). "
        "coef_a/b_q14 CANDIDATE (a+b = 1.0 Q14, 1/n warm-up ramp; lanes 2/3 "
        "zeroed/held on every num_rx 4->2 switch; F3-silent). word_32..48 raw. "
        "Only byte 0 == 0x79 (the corpus-attested version) is decoded."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    domain="lte-ml1",
    # identified: version, num_records, hdr_b1_low, hdr_reserved, sfn,
    # subframe, reserved_3, num_rx, reserved_8, reserved_12, coef_a_q14,
    # coef_b_q14, word_32, word_36, word_40, word_44, word_48 — all exposed.
    fields_identified=17,
    fields_parsed=17,
    field_invariants={
        "version": {"enum": [B141_VERSION]},
        "hdr_b1_low": {"enum": [0]},
        "hdr_reserved": {"enum": [0]},
    },
)
def parse_0xb141(log_time: int, data: bytes) -> Diag0xB141 | None:
    # Only v0x79 is implemented; the size must equal the header's own
    # record count, or the layout is an unseen one.
    if len(data) < _HDR_SIZE or data[0] != B141_VERSION:
        return None
    num_records = data[1] >> 3
    if num_records == 0 or len(data) != _HDR_SIZE + _REC_SIZE * num_records:
        return None
    records = [
        _parse_record(data, _HDR_SIZE + _REC_SIZE * i)
        for i in range(num_records)
    ]
    return Diag0xB141(
        log_time=log_time,
        version=data[0],
        num_records=num_records,
        hdr_b1_low=data[1] & 0x07,
        hdr_reserved=unpack_from("<H", data, 2)[0],
        payload_size=len(data),
        records=records,
    )
