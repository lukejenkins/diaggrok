"""0xB064 — LTE MAC UL Transport Block (LOG_LTE_MAC_UL_TRANSPORT_BLOCK): per-TB HARQ id, RNTI type, SFN/subframe, grant size, RLC PDU count, padding, BSR trigger, MAC header + CEs.

The body is the MAC uplink transport block log, one sample per transmitted TB.
It is the UL twin of 0xB063 and shares its v0x01 subpacket container.

### Layout

One wire version, **v0x01**, on every observed chipset (MDM9x07 EG25-G
through SDX62 RM520N-GL / SDX65 EM9291). The modern DL entry-list versions
(0xB063 v0x31/v0x32) have no UL counterpart.

    @0   u8   version            0x01
    @1   u8   num_subpackets     0 or 1
    @2   2B   hdr_raw            raw
    per subpacket:
    +0   u8   subpacket_id       0x08 (UL transport block)
    +1   u8   subpacket_version  1 (MDM9x07/MDM9x30/MDM9x50), 2 (SDX20/SDX24/SDX50M/SDX55), 3 (SDX62/SDX65)
    +2   u16  subpacket_size     includes this 4-byte header
    +4   u8   num_samples
    then num_samples packed samples, then 0..3 alignment bytes to the subpacket end.
    A subpacket overrunning the record, or a sample overrunning its subpacket,
    returns None (registry WARN) instead of a short list.

    sample (12 B + mac_hdr; subpacket_version >= 2 prefixes u8 sub_id_raw, u8 cell_id_raw):
      u8  harq_id
      u8  rnti_type           0 C-RNTI, 3 RA-RNTI (the RAR-granted Msg3)
      u16 timing              sfn bits 4-15, subframe bits 0-3
      u16 tbs                 grant size, bytes
      u8  rlc_pdus            number of LCH 1-10 SDU subheaders in the TB
      u16 padding_bytes
      u8  bsr_event_raw       raw (0 on every TB without a BSR CE)
      u8  bsr_trig            0 no BSR, 3 Short BSR, 4 Long BSR (1/2/5 raw)
      u8  mac_hdr_len
      mac_hdr_len bytes       the UL-SCH MAC subheaders + MAC CEs (SDU bytes are never logged)

mac_hdr is the head of the TB as TS 36.321 6.1.2 lays it out, so it is also
decoded into `mac_subheaders` (lcid, L) and the CE payloads. LCIDs 22-25
(sidelink BSRs, Dual Connectivity PHR, Extended PHR) are variable-size CEs with
an L field, or with no L as the last subheader (the CE fills the rest). Then

    tbs == mac_hdr_len + sum(SDU L) + padding_bytes        (padding/CE last)
    tbs == mac_hdr_len + sum(SDU L) + last SDU, padding 0  (SDU last)

The initial-access Msg3 (a CCCH SDU) is never logged here: 0 LCID-0 subheaders
in any capture. That Msg3 is in 0xB062, which SCAT reads it from.

### Grounding

* **F3, sver 2, LM960A18 SDX20 drive capture (5 connected-mode RACHs):** each Msg3
  sample pairs with the firmware's own MAC RACH prints.
  `lte_mac_rach.c:1060 trblk_size=%d,rnti_typ=%d,...,msg3_len=%d` gives
  rnti_typ 3 == rnti_type 5/5 and trblk_size == tbs 5/5;
  `lte_mac_rach.c:1255 PKT_BUILD_IND reason,rnti,tx,grnt` (one per built TB)
  gives (rnti, grnt) == the Msg3 sample 5/5 and == the next logged TB 4/5;
  the C-RNTI CE in mac_hdr == `lte_mac_ctrl.c:2776 New C-RNTI CFG new_rnti`
  5/5 (a post-handover RACH).
* **F3, sver 1, EG25-G MDM9207:** the Msg3 C-RNTI CE ==
  `lte_ml1_dlm_schd.c:375 DLM->LL: PDCCH RNTI CHANGE REQ ... C# %d`, before and
  after (1/1).
* **F3, sver 3, RM520N-GL SDX62:** silent. The QSR4 builds checked carry no
  MAC-UL / RACH-internal print, and the RRC-side `LTE_MAC_RRC_MSG3_SENT_IND`
  marks the initial-access Msg3, which this log does not carry.
* **Black-box, SCAT MAC-LTE UL (all three subpacket versions):** at every
  SCAT frame whose sfn/subframe has a 0xB064 sample, the PDU == mac_hdr
  138/138 (EG25-G 26, M2000 92, RM520N-GL 20). SCAT maps rnti_type 0 ->
  C-RNTI 128/128 and 3 -> RA-RNTI 10/10, the 0xB063 enum.
* **RACH, in-capture:** every rnti_type-3 sample (45) carries a C-RNTI CE, and
  the C-RNTI CE occurs on no other TB (45/45). Each follows a 0xB061 trigger,
  0xB168 RAR, 0xB062 attempt; Msg3 sfn/subframe == the 0xB168 RAR + 6
  subframes (TS 36.213 k1 = 6) 40/45 (the rest pair to the wrong RAR in
  back-to-back RACHs). tbs == the RAR grant (9) on all of them.
* **All bearing captures (115 captures, 8,479 records, 54,920 samples):**
  every subpacket walks with 0..3 alignment bytes; the tbs arithmetic above
  holds 54,920/54,920; rlc_pdus == the SDU subheader count 54,920/54,920;
  bsr_trig 0 -> no BSR CE 8,066/8,066, 3 -> Short BSR 35,608/35,608, 4 -> Long
  BSR 10,651/10,651.
* **harq_id:** FDD UL HARQ is synchronous, process = (10*sfn + subframe) mod 8.
  sver 3 holds it on 43,769/43,775 samples. sver 2 holds it with offset 0 on
  most captures (SDX55 M2000/LV55/RM500Q/FN980/T99W175: all), mixed on some
  SDX20/SDX50M/X16 captures (TDD or carrier-aggregation, not resolved).
  sver 1 holds it at a constant offset of 4 on most captures: there the
  timing is the PDCCH grant subframe, n, of a TB sent at n+4.
* **Raw:** sub_id_raw (1; 0 on SWI9X50 Sierra builds), cell_id_raw (0),
  bsr_event_raw (0-3), bsr_trig 1/2/5 (~570 samples), hdr_raw.

Log name: LOG_LTE_MAC_UL_TRANSPORT_BLOCK
Also known as: LOG_UL_TRANSPORT_BLOCK, LTE MAC UL Transport Block
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

_B064_VERSION_OBSERVED = 0x01

#: Sample rnti_type, the 0xB063 enum (grounded: see module docstring).
RNTI_TYPES = {0: "C-RNTI", 3: "RA-RNTI"}

#: bsr_trig values that pin to the BSR CE in mac_hdr (the rest stay raw).
BSR_TRIG_NAMES = {0: "none", 3: "Short BSR", 4: "Long BSR"}

#: TS 36.321 Table 6.2.1-2 UL-SCH LCIDs (1-10 are logical channels).
UL_LCID_NAMES = {
    0: "CCCH",
    20: "Recommended bit rate query",
    21: "SPS confirmation",
    22: "Truncated Sidelink BSR",
    23: "Sidelink BSR",
    24: "Dual Connectivity PHR",
    25: "Extended PHR",
    26: "PHR",
    27: "C-RNTI",
    28: "Truncated BSR",
    29: "Short BSR",
    30: "Long BSR",
    31: "Padding",
}
#: Fixed-size UL MAC CEs (bytes).
_FIXED_CE = {20: 1, 21: 0, 26: 1, 27: 2, 28: 1, 29: 1, 30: 3, 31: 0}
#: Variable-size UL MAC CEs (L field, or the rest of the header when last).
_VAR_CE = (22, 23, 24, 25)


def _lcid_name(lcid: int) -> str | None:
    if 1 <= lcid <= 10:
        return f"LCH{lcid}"
    return UL_LCID_NAMES.get(lcid)


def _subheaders(h: bytes) -> list[dict[str, Any]] | None:
    """Decode the UL-SCH subheaders + CE payloads in `h`, or None if it doesn't frame."""
    subs: list[dict[str, Any]] = []
    o = 0
    while True:
        if o >= len(h) or h[o] & 0xC0:
            return None
        b = h[o]
        more, lcid = (b >> 5) & 1, b & 0x1F
        o += 1
        length = None
        if more and lcid not in _FIXED_CE:
            if o >= len(h):
                return None
            if h[o] & 0x80:
                if o + 1 >= len(h):
                    return None
                length = ((h[o] & 0x7F) << 8) | h[o + 1]
                o += 2
            else:
                length = h[o]
                o += 1
        subs.append({"lcid": lcid, "lcid_name": _lcid_name(lcid), "length": length})
        if not more:
            break
    for i, s in enumerate(subs):
        lcid = s["lcid"]
        if lcid in _FIXED_CE:
            n = _FIXED_CE[lcid]
        elif lcid in _VAR_CE:
            n = s["length"] if s["length"] is not None else len(h) - o
        else:
            continue
        if n and lcid != 31:
            if o + n > len(h):
                return None
            s["ce_payload"] = bytes(h[o:o + n])
        o += n if lcid != 31 else 0
    if o != len(h):
        return None
    return subs


@dataclass
class Diag0xB064:
    """0xB064 — LTE MAC UL transport block log."""
    log_time: int
    version: int
    num_subpackets: int
    hdr_raw: bytes
    subpackets: list[dict[str, Any]] = field(default_factory=list)
    unparsed_raw: bytes = b""
    payload_size: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB064",
            "log_time": self.log_time,
            "version": self.version,
            "num_subpackets": self.num_subpackets,
            "hdr_raw": self.hdr_raw,
            "subpackets": self.subpackets,
            "unparsed_raw": self.unparsed_raw,
            "payload_size": self.payload_size,
        }


def _sample(body: bytes, o: int, sver: int) -> tuple[dict[str, Any], int] | None:
    s: dict[str, Any] = {}
    if sver >= 2:
        if o + 2 > len(body):
            return None
        s["sub_id_raw"], s["cell_id_raw"] = body[o], body[o + 1]
        o += 2
    if o + 12 > len(body):
        return None
    harq_id, rnti_type = body[o], body[o + 1]
    timing, tbs = unpack_from("<HH", body, o + 2)
    hl = body[o + 11]
    if o + 12 + hl > len(body):
        return None
    hdr = bytes(body[o + 12:o + 12 + hl])
    s.update(
        harq_id=harq_id,
        rnti_type=rnti_type,
        rnti_type_name=RNTI_TYPES.get(rnti_type),
        sfn=timing >> 4,
        subframe=timing & 0xF,
        tbs=tbs,
        rlc_pdus=body[o + 6],
        padding_bytes=unpack_from("<H", body, o + 7)[0],
        bsr_event_raw=body[o + 9],
        bsr_trig=body[o + 10],
        bsr_trig_name=BSR_TRIG_NAMES.get(body[o + 10]),
        mac_hdr_len=hl,
        mac_hdr=hdr,
        mac_subheaders=_subheaders(hdr),
    )
    return s, o + 12 + hl


def _parse_subpackets(data: bytes) -> tuple[list[dict[str, Any]], int] | None:
    """Walk the declared subpackets; None when any declared subpacket or sample
    does not fit (truncated -> loud None, never a silently short list)."""
    subs: list[dict[str, Any]] = []
    off = 4
    for _ in range(data[1]):
        if off + 4 > len(data):
            return None
        sid, sver = data[off], data[off + 1]
        ssz = unpack_from("<H", data, off + 2)[0]
        if ssz < 5 or off + ssz > len(data):
            return None
        body = data[off + 4:off + ssz]
        sp: dict[str, Any] = {
            "subpacket_id": sid,
            "subpacket_version": sver,
            "subpacket_size": ssz,
            "num_samples": body[0],
            "samples": [],
            "align_raw": b"",
        }
        o = 1
        if sid == 0x08 and sver in (1, 2, 3):
            for _ in range(body[0]):
                r = _sample(body, o, sver)
                if r is None:
                    return None
                sp["samples"].append(r[0])
                o = r[1]
        sp["align_raw"] = bytes(body[o:])
        subs.append(sp)
        off += ssz
    return subs, off


@register(
    0xB064,
    name="0xB064",
    description="0xB064 — LTE MAC UL Transport Block: per-TB HARQ id, RNTI type (C-RNTI / RA-RNTI Msg3), SFN/subframe, grant size, RLC PDU count, padding, BSR trigger, UL-SCH MAC subheaders + CEs (BSR, PHR, C-RNTI, DC-PHR)",
    version=4,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE. v0x01 = LTE-MAC subpacket "
        "container (subpacket 0x08 v1/v2/v3; samples: harq_id, rnti_type 0 C/3 RA, "
        "timing sfn<<4|sf, tbs, rlc_pdus, padding_bytes, bsr_event_raw, bsr_trig "
        "0 none/3 short/4 long, UL-SCH MAC header + CEs). Grounding: LM960 SDX20 F3 "
        "lte_mac_rach.c:1060 rnti_typ/trblk_size 5/5, :1255 PKT_BUILD_IND (rnti, "
        "grnt) 5/5 + next TB 4/5, C-RNTI CE == lte_mac_ctrl.c:2776 new_rnti 5/5; "
        "EG25-G C-RNTI CE == lte_ml1_dlm_schd.c:375 C# 1/1; SCAT MAC-LTE UL PDU == "
        "mac_hdr 138/138; Msg3 == 0xB168 RAR + 6 subframes 40/45; across 54,920 "
        "samples: tbs arithmetic, rlc_pdus == SDU subheaders, bsr_trig <-> BSR CE "
        "all exact. Truncated payloads return None (registry WARN): a subpacket "
        "whose subpacket_size overruns the record, or a sample overrunning its "
        "subpacket, never yields a silently short subpacket/sample list."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=14,
    fields_parsed=14,
    field_invariants={
        "version": {"enum": [_B064_VERSION_OBSERVED]},
    },
)
def parse_0xb064(log_time: int, data: bytes) -> Diag0xB064 | None:
    if len(data) < 4:
        return None
    if data[0] != _B064_VERSION_OBSERVED:
        return None
    rec = Diag0xB064(
        log_time=log_time,
        version=data[0],
        num_subpackets=data[1],
        hdr_raw=bytes(data[2:4]),
        payload_size=len(data),
    )
    walked = _parse_subpackets(data)
    if walked is None:
        return None
    rec.subpackets, used = walked
    rec.unparsed_raw = bytes(data[used:])
    return rec
