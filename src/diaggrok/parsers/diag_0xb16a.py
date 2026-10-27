"""0xB16A — LTE ML1 Contention Resolution Message (MSG4) Report: MSG4 SFN/subframe, contention result, UL ACK timing.

One record per RACH contention resolution (the step after a 0xB169 MSG3). The
legacy registry label `LtePdcpB16A` was a misnomer (this is ML1 RACH, not PDCP).

### Layout (v0x01, 8 B — the only version, emitted by every chipset from MDM9x07 to SDX6x)

    @0   u8   version                 0x01
    @1   3B   hdr_raw                 raw (firmware scratch)
    @4   u32  msg4 word
                bits 0-9    msg4_sfn           SFN of the MSG4 (DL-SCH TB with the CRI MAC CE)
                bits 10-13  msg4_subframe      subframe; 15 = no MSG4 TB was logged
                bit  14     contention_result  1 = contention resolved, 0 = failed
                bits 15-24  ul_ack_sfn         SFN of the HARQ ACK for the MSG4
                bits 25-28  ul_ack_subframe    subframe; 15 = no ACK
                bits 29-31  tail_raw           raw (0 on 722/836 valid records; not the MSG4 HARQ id)

`msg4_received` is False when msg4_subframe is 15. On those records both SFNs
are 0 and both subframes 15, whatever `contention_result` says.

### Grounding (949 records, 192 captures — the whole bearing corpus)

* **msg4_sfn / msg4_subframe / contention_result.** F3 `lte_mac_rach.c:1162
  "In RACH ConRes,got MSG4_RESULT_INDI mat=%d,suf=%d,syf=%d"` gives
  (contention_result, msg4_subframe, msg4_sfn) 6/6 on the LM960 attach capture,
  and `lte_mac_rach.c:1130` 1/1 on the EM120R-GL. On MDM9x07 the same site is
  legacy hash `0x92:5825b063 [mat, suf, syf]`, equal 3/3 on two EG25-G captures
  with distinct values (243/4, 310/5, 381/1); `0x92:0d00a2a3 [1, 1, sfn, sf]`
  repeats it 3/3. `lte_mac_dl.c "Got Cont Res Ind status=%d"` equals
  contention_result on every record it brackets (LM960 6/6, EM120R 1/1, EG25-G 4/4,
  including one no-MSG4 record).
* **MSG4 time vs MSG3.** msg4_sfn is the 0xB169 msg3_sfn + 0..1 on 813 paired records.
* **UL ACK timing.** ul_ack time - msg4 time = 4 subframes (FDD HARQ timing,
  TS 36.213 10.1) on 807/813 paired records with a logged MSG4; 7 on 5 (TDD).
  The 2 result-0 records with a logged MSG4 also read +4, so the ACK fields are
  the scheduled ACK time, not proof an ACK was sent.
* **contention_result vs what follows.** A new 0xB167 MSG1 follows within 300 ms
  after 52/54 records with result 0, and after 12/835 records with result 1 and a
  logged MSG4. Records with no MSG4 TB split 52 (result 0, 50 re-RACH) / 60
  (result 1). Result 1 with no MSG4 TB is consistent with contention resolved by a
  PDCCH to the C-RNTI (MSG3 with a C-RNTI MAC CE, TS 36.321 5.1.5), but no MAC
  oracle confirmed that here.
* **tail_raw is not the MSG4 HARQ id.** 0xB063 TC-RNTI TBs at the MSG4 time have
  harq_id 1 on 68/69 joins while tail_raw takes 0..7.
* **Black-box.** Not run: qcsuper and SCAT emit no MAC-LTE MSG4 PDU for these captures.

Log name: LOG_LTE_ML1_RACH_CONTENTION_LOG_C
Also known as: LOG_LTE_ML1_CONTENTION_RESOLUTION_MESSAGE_MSG4_REPORT, LOG_LTE_ML1_PUSCH_TX_REPORT, LOG_PUSCH_TX_REPORT, LOG_LTE_CONTENTION_RESOLUTION_MESSAGE_MSG4_REPORT, LTE ML1
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

# One version and one size on every chipset in the corpus (949 records).
_B16A_VERSION_OBSERVED = 0x01
_B16A_PAYLOAD_SIZE_OBSERVED = 8
_SUBFRAME_NONE = 15


@dataclass
class Diag0xB16A:
    """0xB16A — LTE ML1 RACH MSG4 (contention resolution) report."""
    log_time: int
    version: int
    msg4_sfn: int
    msg4_subframe: int
    msg4_received: bool
    contention_result: int
    ul_ack_sfn: int
    ul_ack_subframe: int
    tail_raw: int
    msg4_word_raw: int
    hdr_raw: bytes
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB16A",
            "log_time": self.log_time,
            "version": self.version,
            "msg4_sfn": self.msg4_sfn,
            "msg4_subframe": self.msg4_subframe,
            "msg4_received": self.msg4_received,
            "contention_result": self.contention_result,
            "ul_ack_sfn": self.ul_ack_sfn,
            "ul_ack_subframe": self.ul_ack_subframe,
            "tail_raw": self.tail_raw,
            "msg4_word_raw": self.msg4_word_raw,
            "hdr_raw": self.hdr_raw,
            "payload_size": self.payload_size,
        }


@register(
    0xB16A,
    name="0xB16A",
    description="0xB16A — LTE ML1 RACH MSG4 (contention resolution) report: MSG4 SFN/subframe, contention result, UL HARQ-ACK SFN/subframe",
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Body decoded (v0x01, 8 B). u32@4: bits 0-9 msg4_sfn, 10-13 msg4_subframe "
        "(15 = no MSG4 TB), bit 14 contention_result, 15-24 ul_ack_sfn, 25-28 "
        "ul_ack_subframe, 29-31 raw. F3 lte_mac_rach.c MSG4_RESULT_INDI "
        "mat/suf/syf == result/subframe/sfn LM960 6/6, EM120R-GL 1/1; MDM9x07 legacy "
        "hash 0x92:5825b063 3/3 (EG25-G x2); lte_mac_dl.c Cont Res Ind status == "
        "result 11/11. ACK - MSG4 == 4 sf on 807/813. Result 0 -> re-RACH 52/54. "
        "Strict version+size gate {0x01} / 8 B."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=8,
    fields_parsed=8,
    field_invariants={
        "version": {"enum": [_B16A_VERSION_OBSERVED]},
        "payload_size": {"enum": [_B16A_PAYLOAD_SIZE_OBSERVED]},
        "msg4_subframe": {"enum": [*range(10), _SUBFRAME_NONE]},
        "ul_ack_subframe": {"enum": [*range(10), _SUBFRAME_NONE]},
    },
)
def parse_0xb16a(log_time: int, data: bytes) -> Diag0xB16A | None:
    if len(data) != _B16A_PAYLOAD_SIZE_OBSERVED or data[0] != _B16A_VERSION_OBSERVED:
        return None
    word = unpack_from("<I", data, 4)[0]
    sf = (word >> 10) & 0xF
    return Diag0xB16A(
        log_time=log_time,
        version=data[0],
        msg4_sfn=word & 0x3FF,
        msg4_subframe=sf,
        msg4_received=sf != _SUBFRAME_NONE,
        contention_result=(word >> 14) & 1,
        ul_ack_sfn=(word >> 15) & 0x3FF,
        ul_ack_subframe=(word >> 25) & 0xF,
        tail_raw=word >> 29,
        msg4_word_raw=word,
        hdr_raw=bytes(data[1:4]),
        payload_size=len(data),
    )
