"""0xB168 — LTE ML1 Random Access Response (MSG2) Report: TC-RNTI, timing advance, RAR timing.

The legacy registry label
`LtePdcpB168` was a misnomer (this is ML1 RACH, not PDCP). One record per RAR
the UE accepts (MSG2 of the RACH, after a 0xB167 MSG1). Sibling of 0xB167.

### Layout

Both wire versions are 12 B and carry the same three RAR quantities at different
offsets. The timing word packs like 0xB167's: sfn bits 0-9, subframe bits 12-15.

v0x18 (SDX20 LM960, SDX24 EM120R, SDX55/SDX6x RM500Q / RM520N / LV55 / EM9291 …):

    @0   u8   version                 0x18
    @1   3B   hdr_raw                 raw (firmware scratch: 0xDEAD, "pre", …)
    @4   u32  rar word
                bits 0-9    word_flags_raw   {0x108: 405, 0x118: 7, 0x000: 41}. NOT the RA-RNTI
                                             (8 against MSG1 RA-RNTI 2/4/5/8)
                  bit 3     contention_based 1 = contention-based RAR (TC-RNTI granted);
                                             0 = contention-free (dedicated preamble), tc_rnti 0
                bits 10-25  tc_rnti          Temporary C-RNTI granted by the RAR
                bits 26-31  word_hi_raw      raw (1 on 372/453; no oracle)
    @8   u16  rar timing                 rar_sfn / rar_subframe
    @10  u16  timing_advance             RAR absolute TA command (TS 36.321 6.1.3.3), 0..1282

v0x01 (MDM9x07 EG25-G / EG95, MDM9x30 MC7455, SIM7600NA):

    @0   u8   version                 0x01
    @1   3B   hdr_raw                 raw (firmware scratch)
    @4   u16  rar timing                 rar_sfn / rar_subframe
    @6   u16  timing_advance             RAR absolute TA command, 0..1282
    @8   u8   byte8_raw                  raw (0x43 on 42/42; no oracle)
    @9   u16  tc_rnti                    Temporary C-RNTI (unaligned)
    @11  u8   tail_raw                   raw

### Grounding (495 records, 102 captures — the whole bearing corpus)

* **RAR timing (both versions).** Every record whose MSG1 is in the same capture
  lands inside that 0xB167 record's RAR window: v0x18 439/439, v0x01 42/42. One
  more v0x18 record sits 442 ms after the last logged MSG1; its own MSG1 was not
  logged (0xB167 does not fire on every RACH). Subframe 0..9 and timing bits
  10-11 == 0 on 495/495.
* **tc_rnti, v0x18.** F3 `lte_mac_rach.c:926 "rach_preamble_resp_state_handler
  reset backoff,Result=1,tmp_rnti=%d"` equals the field 6/6 on the LM960
  (27411, 4169, 27657, 4253, 28917, 4545), and `lte_mac_rach.c:936` 1/1 on the
  EM120R-GL (5913), each ~10 us before the record.
* **timing_advance, v0x18.** F3 `lte_ml1_ulm_cfg.c:7005 "ULM apply ta: adj %d,
  is_adj_abs 1"` equals the field 6/6 on the LM960 (10, 8, 10, 10, 10, 8). It is
  the absolute RAR TA (is_adj_abs 1), and `lte_ml1_pos_mrl.c:418 "LTE GPS TA has
  been updated (%d), abs:1"` repeats it.
* **tc_rnti, v0x01.** F3 `lte_ml1_dlm_schd.c:375 "[RA(16bit),Temp(16bit)]"`
  equals the field 2/2 on two EG25-G captures (0x6ACD, 0x76C7). The RNTI-change
  request 1 ms later swaps the PDCCH Temp RNTI to it. Legacy hash `0x92:e8cad705
  [1, tc]` repeats it 2/2.
* **timing_advance, v0x01.** Legacy hash `0x92:9c7a2e52 [ta, 1, ta]` tracks the
  field 2/2 with distinct values (9, 4). The middle 1 mirrors `is_adj_abs`. The
  decoy `0x92:51f6a9dd [9,3,0,6,64]` reads 9 on both, so it is not the TA.
* **contention_based, v0x18.** The flag splits the corpus 412 / 41, and
  tc_rnti == 0 exactly when it is clear (41/41). On the RM520N-GL drive
  captures, all 35 clear-flag records follow a MSG1 with a dedicated preamble
  (52/53, above numberOfRA-Preambles), and all set-flag records follow a random
  preamble (0..50). In contention-free RACH the RAR TC-RNTI is unused (TS 36.321
  5.1.4), so the firmware logs 0.
* **Structural.** On a stationary RM520N-GL, tc_rnti climbs monotonically across
  46 RACHs (4659 → 9963) while TA holds at 9. The MC7455 shows the same pattern
  (65, 66, 67, 68) with a slowly drifting TA (542, 543, 545, 547).
* **Black-box.** qcsuper and SCAT produce no MAC-LTE RAR PDUs for these captures,
  and 0xB063 does not log the RA-RNTI transport block, so no byte-join was available.

Log name: LOG_LTE_ML1_PDCCH_PHICH_INDICATION_REPORT
Also known as: LOG_LTE_ML1_RANDOM_ACCESS_RESPONSE_MSG2_REPORT, LOG_PDCCH_PHICH_INDICATION_REPORT, LOG_LTE_RANDOM_ACCESS_RESPONSE_MSG2_REPORT, LTE ML1
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

# byte 0 is the version; both are 12 B. v0x01 = MDM9x07/9x30, v0x18 = SDX20 onward.
_B168_VERSIONS_OBSERVED = (0x01, 0x18)
_SIZE = 12


def _sfn_sf(word: int) -> tuple[int, int]:
    """(sfn, subframe) from the packed timing u16: sfn bits 0-9, subframe 12-15."""
    return word & 0x3FF, (word >> 12) & 0xF


@dataclass
class Diag0xB168:
    """0xB168 — LTE ML1 RACH MSG2 (Random Access Response) report."""
    log_time: int
    version: int
    tc_rnti: int
    timing_advance: int
    rar_sfn: int
    rar_subframe: int
    contention_based: bool | None
    rar_word_raw: int | None
    word_flags_raw: int | None
    word_hi_raw: int | None
    byte8_raw: int | None
    hdr_raw: bytes
    tail_raw: bytes
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB168",
            "log_time": self.log_time,
            "version": self.version,
            "tc_rnti": self.tc_rnti,
            "timing_advance": self.timing_advance,
            "rar_sfn": self.rar_sfn,
            "rar_subframe": self.rar_subframe,
            "contention_based": self.contention_based,
            "rar_word_raw": self.rar_word_raw,
            "word_flags_raw": self.word_flags_raw,
            "word_hi_raw": self.word_hi_raw,
            "byte8_raw": self.byte8_raw,
            "hdr_raw": self.hdr_raw,
            "tail_raw": self.tail_raw,
            "payload_size": self.payload_size,
        }


@register(
    0xB168,
    name="0xB168",
    description="0xB168 — LTE ML1 RACH MSG2 (Random Access Response) report: TC-RNTI, absolute timing advance, RAR SFN/subframe, contention-based flag",
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Body decoded on both versions. v0x18: u32@4 rar word "
        "(bits 10-25 tc_rnti, bit 3 contention_based: clear <=> tc_rnti 0 <=> dedicated preamble 41/41; bits 0-9 / 26-31 raw), u16@8 RAR timing (sfn bits 0-9, "
        "subframe 12-15), u16@10 timing_advance. v0x01: u16@4 RAR timing, u16@6 "
        "timing_advance, u8@8 raw, u16@9 tc_rnti, u8@11 raw. RAR timing inside the "
        "preceding 0xB167 RAR window on 481/481 paired records (102 captures). F3: "
        "LM960 v0x18 `lte_mac_rach.c tmp_rnti` 6/6 + `lte_ml1_ulm_cfg.c ULM apply ta` "
        "6/6; EM120R-GL v0x18 `tmp_rnti` 1/1; EG25-G v0x01 `lte_ml1_dlm_schd.c "
        "Temp(16bit)` 2/2 + legacy hash 0x92:9c7a2e52 TA 2/2. Byte-0 version "
        "gate {0x01, 0x18}."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=11,
    fields_parsed=11,
    field_invariants={
        "version": {"enum": [0x01, 0x18]},
        "rar_subframe": {"range": (0, 9)},
        "timing_advance": {"range": (0, 1282)},
        "tc_rnti": {"range": (0, 0xFFF3)},  # 0 on contention-free RARs
    },
)
def parse_0xb168(log_time: int, data: bytes) -> Diag0xB168 | None:
    if len(data) < 1:
        return None
    version = data[0]
    if version not in _B168_VERSIONS_OBSERVED or len(data) < _SIZE:
        return None
    if version == 0x18:
        word = unpack_from("<I", data, 4)[0]
        timing, ta = unpack_from("<HH", data, 8)
        tc_rnti = (word >> 10) & 0xFFFF
        rar_word_raw, word_flags_raw, word_hi_raw = word, word & 0x3FF, word >> 26
        contention_based: bool | None = bool(word & 0x8)
        byte8_raw = None
        tail_raw = b""
    else:
        timing, ta = unpack_from("<HH", data, 4)
        tc_rnti = unpack_from("<H", data, 9)[0]
        rar_word_raw = word_flags_raw = word_hi_raw = None
        contention_based = None
        byte8_raw = data[8]
        tail_raw = bytes(data[11:12])
    sfn, sf = _sfn_sf(timing)
    return Diag0xB168(
        log_time=log_time,
        version=version,
        tc_rnti=tc_rnti,
        timing_advance=ta,
        rar_sfn=sfn,
        rar_subframe=sf,
        contention_based=contention_based,
        rar_word_raw=rar_word_raw,
        word_flags_raw=word_flags_raw,
        word_hi_raw=word_hi_raw,
        byte8_raw=byte8_raw,
        hdr_raw=bytes(data[1:4]),
        tail_raw=tail_raw,
        payload_size=len(data),
    )
