"""0xB169 — LTE ML1 UE Identification Message (MSG3) Report: RAR UL grant, MSG3 PUSCH allocation, MSG3 SFN/subframe.

One record per MSG3 the UE transmits (the step after a 0xB168 RAR, before a
0xB16A MSG4). The record holds the RAR UL grant (TS 36.213 6.2) as received,
the PUSCH allocation ML1 derived from it, and the MSG3 transmit time. It does
not carry the MSG3 payload or the UE identity (those are in 0xB064 / 0xB0C0).

### Layout

All three wire versions are 12 B. Bit numbers are little-endian over the whole
payload (bit 32 = byte 4 bit 0). v0x18 / v0x28 are v0x01 shifted: the grant
field moves up 3 bits, the SFN up 2, the allocation word up 1.

| field             | v0x01  | v0x18  | v0x28  |
|-------------------|--------|--------|--------|
| version           | @0     | @0     | @0     |
| hdr_raw           | @1-3   | @1-3   | @1-3   |
| tpc               | 32-34  | 35-37  | 35-37  |
| mcs               | 35-38  | 38-41  | 38-41  |
| riv               | 39-48  | 42-51  | 42-51  |
| grant_flags_raw   | 49-51  | 52-53  | 52-53  |
| msg3_sfn          | 52-61  | 54-63  | 54-63  |
| msg3_subframe     | 64-67  | 64-67  | 64-67  |
| start_rb          | 68-74  | 69-75  | 69-75  |
| num_rb            | 75-81  | 76-82  | 76-82  |
| tbs_index         | 82-86  | 83-87  | 83-87  |
| modulation_raw    | 87-89  | 88-90  | 88-90  |
| harq_id           | 91-93  | 92-94  | 91-93  |

`spare_raw` keeps every other bit of 32-95 in place (all other bits masked to 0).

v0x01 = MDM9x07 / MDM9x30 (EG25-G, EG95, MC7455, SIM7600NA, T9, RC400L, T77W595);
v0x18 = SDX20 / SDX24 (LM960, EM7511, MC7411, EM060K, EP06); v0x28 = SDX55 onward
(RM520N, LV55, R500L5, EM9291, FX2000, T99W640, EM120R).

### Grounding (1,034 records, 192 captures — the whole bearing corpus)

* **RAR UL grant, v0x01.** 87/88 records join to the 0xB063 v0x01 RA-RNTI
  transport block of the preceding 0xB168 RAR (same SFN/subframe, TC-RNTI equal
  to 0xB168 `tc_rnti`, and the TB's TA equal to 0xB168 `timing_advance` 87/87).
  The 20-bit UL grant in that MAC RAR gives `tpc` 87/87, `mcs` 87/87 and `riv`
  87/87. Its hopping / UL-delay / CSI-request bits are 0 on all 87, so
  `grant_flags_raw` (also 0 corpus-wide) is not split.
* **MSG3 timing (all versions).** `msg3_sfn`/`msg3_subframe` equal the 0xB168
  RAR time + 6 subframes (TS 36.213 6.1.1) on v0x01 88/88, v0x18 118/123,
  v0x28 805/822; every other record is + 8 (no +7, so UL-delay is never set).
  F3 `lte_ml1_dlm_schd.c:375 "PDCCH RNTI CHANGE REQ"` (T-RNTI enable after MSG3)
  carries the same SFN/subframe as its last two args 4/4 on two EG25-G captures.
* **Allocation (all versions).** `riv`, `start_rb` and `num_rb` satisfy the
  TS 36.213 8.1.1 RIV equation for some UL bandwidth on 1,034/1,034 records, and
  only real bandwidths occur (25 / 50 / 100 PRB).
* **TBS, v0x18 / v0x28.** TS 36.213 Table 7.1.7.2.1-1 TBS(`tbs_index`, `num_rb`)
  equals F3 `lte_mac_rach.c:1060 "trblk_size=%d,...;msg3_len=%d"` (bytes) 6/6 on
  the LM960 attach capture (9 B), 1/1 on a second LM960 capture (32 B, 6 PRB)
  and 1/1 on the EM120R-GL (`lte_mac_rach.c:1036`, 9 B). It also equals the
  0xB064 MSG3 TB `tbs` 5/5 (v0x01 3, v0x18 2).
* **mcs vs tbs_index.** Equal on 1,029/1,034. The 5 exceptions are v0x28 records
  with grant MCS 0 and tbs_index 2; the EM120R F3 TBS sides with tbs_index.
* **harq_id.** Equals the 0xB064 MSG3 TB `harq_id` 5/5 (v0x01 3, v0x18 2). On
  v0x28 it equals the synchronous FDD UL HARQ process (10*sfn + sf) mod 8 on
  801/823; no MAC oracle was available for v0x28.
* **Raw, no oracle:** `modulation_raw` (1 on v0x01 / v0x18, 0 on v0x28; MSG3 is
  QPSK), `grant_flags_raw`, `spare_raw`, `hdr_raw` (firmware scratch).
* **Black-box.** Not run for these fields: qcsuper and SCAT emit no MAC-LTE RAR
  PDU for these captures (see 0xB168), so the 0xB063 byte-join stands in.

Log name: LTE UE Identification Message (MSG3) Report
Also known as: LOG_LTE_ML1_RACH_UE_ID_LOG_C, LOG_LTE_ML1_UE_IDENTIFICATION_MESSAGE_MSG3_REPORT, LOG_LTE_ML1_UL_GRANT_INFORMATION_REPORT, LOG_UL_GRANT_INFORMATION_REPORT, LOG_LTE_UE_IDENTIFICATION_MESSAGE_MSG3_REPORT, LTE ML1
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from diaggrok.registry import register

# byte 0 is the version; all are 12 B. v0x01 = MDM9x07/9x30, v0x18 = SDX20/24, v0x28 = SDX55+.
_B169_VERSIONS_OBSERVED = (0x01, 0x18, 0x28)
_SIZE = 12

# (start bit, width) per field, over the payload as one little-endian integer.
_LAYOUT_V01 = {
    "tpc": (32, 3), "mcs": (35, 4), "riv": (39, 10), "grant_flags_raw": (49, 3),
    "msg3_sfn": (52, 10), "msg3_subframe": (64, 4), "start_rb": (68, 7),
    "num_rb": (75, 7), "tbs_index": (82, 5), "modulation_raw": (87, 3), "harq_id": (91, 3),
}
_LAYOUT_V18 = {
    "tpc": (35, 3), "mcs": (38, 4), "riv": (42, 10), "grant_flags_raw": (52, 2),
    "msg3_sfn": (54, 10), "msg3_subframe": (64, 4), "start_rb": (69, 7),
    "num_rb": (76, 7), "tbs_index": (83, 5), "modulation_raw": (88, 3), "harq_id": (92, 3),
}
_LAYOUT_V28 = {**_LAYOUT_V18, "harq_id": (91, 3)}
_LAYOUTS = {0x01: _LAYOUT_V01, 0x18: _LAYOUT_V18, 0x28: _LAYOUT_V28}


def _mask(layout: dict[str, tuple[int, int]]) -> int:
    m = 0
    for start, width in layout.values():
        m |= ((1 << width) - 1) << start
    return m


_SPARE_MASKS = {v: ((1 << 96) - 1) & ~((1 << 32) - 1) & ~_mask(lay) for v, lay in _LAYOUTS.items()}


@dataclass
class Diag0xB169:
    """0xB169 — LTE ML1 RACH MSG3 report."""
    log_time: int
    version: int
    tpc: int
    mcs: int
    riv: int
    grant_flags_raw: int
    msg3_sfn: int
    msg3_subframe: int
    start_rb: int
    num_rb: int
    tbs_index: int
    modulation_raw: int
    harq_id: int
    spare_raw: int
    hdr_raw: bytes
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB169",
            "log_time": self.log_time,
            "version": self.version,
            "tpc": self.tpc,
            "mcs": self.mcs,
            "riv": self.riv,
            "grant_flags_raw": self.grant_flags_raw,
            "msg3_sfn": self.msg3_sfn,
            "msg3_subframe": self.msg3_subframe,
            "start_rb": self.start_rb,
            "num_rb": self.num_rb,
            "tbs_index": self.tbs_index,
            "modulation_raw": self.modulation_raw,
            "harq_id": self.harq_id,
            "spare_raw": self.spare_raw,
            "hdr_raw": self.hdr_raw,
            "payload_size": self.payload_size,
        }


@register(
    0xB169,
    name="0xB169",
    description="0xB169 — LTE ML1 RACH MSG3 report: RAR UL grant (TPC, MCS, RIV), MSG3 PUSCH allocation (start RB, num RB, TBS index, HARQ id), MSG3 SFN/subframe",
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Body decoded on v0x01/v0x18/v0x28 (12 B). Fields are LE bit ranges over the payload: "
        "RAR UL grant tpc/mcs/riv, msg3_sfn/msg3_subframe, start_rb/num_rb/tbs_index/harq_id; "
        "v0x18/v0x28 shift the grant +3, SFN +2, allocation +1. v0x01 grant == 0xB063 RA-RNTI "
        "TB MAC RAR UL grant 87/87. MSG3 time == 0xB168 RAR + 6 sf (rest +8). RIV equation "
        "holds 1,034/1,034 (N_UL_RB 25/50/100). F3 lte_mac_rach.c trblk_size == TBS(tbs_index, "
        "num_rb) LM960 v0x18 7/7, EM120R v0x28 1/1; 0xB064 MSG3 TB tbs + harq_id 5/5. "
        "Byte-0 version gate {0x01, 0x18, 0x28}."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=14,
    fields_parsed=14,
    field_invariants={
        "version": {"enum": [0x01, 0x18, 0x28]},
        "payload_size": {"enum": [_SIZE]},
        "msg3_subframe": {"range": (0, 9)},
        "num_rb": {"range": (1, 100)},
        "start_rb": {"range": (0, 99)},
    },
)
def parse_0xb169(log_time: int, data: bytes) -> Diag0xB169 | None:
    if len(data) < 1:
        return None
    version = data[0]
    if version not in _B169_VERSIONS_OBSERVED or len(data) != _SIZE:
        return None
    word = int.from_bytes(data, "little")
    f = {k: (word >> s) & ((1 << w) - 1) for k, (s, w) in _LAYOUTS[version].items()}
    return Diag0xB169(
        log_time=log_time,
        version=version,
        spare_raw=word & _SPARE_MASKS[version],
        hdr_raw=bytes(data[1:4]),
        payload_size=len(data),
        **f,
    )
