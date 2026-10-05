"""LTE RRC OTA message parser (0xB0C0).

Standard LTE RRC Over-The-Air message log, present on all supported chipsets.
Contains ASN.1 PER-encoded RRC messages (SIBs, RRC Connection Setup/Reconfig,
measurement reports, handover commands, etc.).

Version 20 layout (SDX20/SDX55/MDM9607):
    [0]     u8   version (20)
    [1]     u8   rrc_release (14 = Rel-14)
    [2]     u8   constant 0x30 (not the channel; see [12])
    [3]     u8   reserved
    [4:6]   u16  physical_cell_id
    [6:10]  u32  earfcn (u32 - carries >65535 EARFCNs, e.g. B66)
    [10:12] u16  sfn_subfn: subfn(4b) | sfn(10b) | reserved(2b)
                 (sfn masked to 10 bits; top 2 bits are a separate field)
    [12]    u8   channel_type (the channel selector)
    [13:17] u32  sib_mask (SIB-presence bitmap, LE - see the sib_mask field)
    [17:19] u16  msg_length (bytes of ASN.1 PER-encoded RRC message)
    [19:]   bytes msg_data

Version 27 layout (SDX62/SDX55, the NR-capable header - RM520N-GL, RM500Q):
    [0]     u8   version (27)
    [1]     u8   rrc_release
    [2]     u8   rrc_ver_major
    [3]     u8   rrc_ver_minor
    [4]     u8   log-encoding constant (0x60 SDX62 / 0x90 SDX55; NOT the bearer)
    [5]     u8   radio_bearer_id (0=common/SRB0, 1=SRB1, 2=SRB2)
    [6:8]   u16  physical_cell_id
    [8:12]  u32  earfcn (u32 - carries >65535 EARFCNs, e.g. B66)
    [12:14] u16  sfn_subfn
    [14]    u8   channel_type
    [15:19] u32  sib_mask (SIB-presence bitmap, LE)
    [19:21] u16  msg_length
    [21:]   bytes msg_data
Version 30 layout (0x1E, Foxconn T99W640 / SDX72): the v27 header
plus a 3-byte pad, so the header is 24 bytes, not 21:
    [0:19]  as v27 (rrc_release 17, rrc_ver 32/17, byte[4] const 0x40)
    [19:21] u16  msg_length (the EXACT PDU length: len - u16 == 24, 723/723)
    [21:24] 3 zero bytes (723/723)
    [24:]   bytes msg_data
The sib_mask sits in the 4 bytes immediately after channel_type on every
version, always followed by msg_length (u16). See the sib_mask field docstring
for the bit=SIB mapping and the "mask=0 means unpopulated" caveat.

The v20 channel selector is raw byte[12], not byte[2]. byte[2] is a constant
0x30 on every observed v20 record (290/290 across EG18-NA + EG25-G, both wire
version 20), so reading the channel from byte[2] would label every record
BCCH-DL-SCH (0x30). The byte[12] field uses a different, contiguous
small-integer enum from the legacy byte[2]-era _CHANNEL_NAMES (see
_V20_CHANNEL_NAMES below).

v20 channel_type enum at byte[12]. The observed enum {2,5,6,7,8,9} is both
content-verified across the capture corpus and confirmed by a QCSuper
byte-join; only the never-observed values 1/3/4 (incl. BCCH-BCH) are unmapped.
The byte-join (an EG25-G connected-mode capture) matched 56/56 v20 PDUs to
QCSuper's GSMTAP frames by raw RRC-PDU bytes, with 0 disagreements; the enum
mapping is cross-checked against tshark's independent GSMTAP dissection:
    2  BCCH-DL-SCH  - System Information / SIB1 (content-verified: only ch==2
                      records decode as SIB1 cell-access info; byte-join 18/18)
    5  PCCH         - Paging (QCSuper byte-join 19/19 + idle-camp frequency)
    6  DL-CCCH      - RRCConnectionSetup (content-verified: 30/30 ch==6 PDUs
                      decode as rrcConnectionSetup, a DL-CCCH-exclusive message;
                      QCSuper byte-join 2/2)
    7  DL-DCCH      - Reconfig/Release/SMC/dlInfoXfer (content-verified: all 68
                      ch==7 PDUs decode as DL-DCCH-exclusive messages; byte-join 6/6)
    8  UL-CCCH      - RRC Connection Request (QCSuper byte-join 2/2)
    9  UL-DCCH      - SetupComplete/measReport/ulInfoXfer (content-verified: all
                      54 ch==9 PDUs decode as UL-DCCH-exclusive messages; byte-join 9/9)

Legacy byte[2]-era channel constants (LTE_RRC_CHANNEL_*) are retained. The
non-v20 multi-version path reads its channel from byte[12]/[14] and names it
through the per-version _NONV20_CHANNEL_NAMES_BY_VERSION table.

Layout derived from SDX20 (LM960) and MDM9607 (EG25-G) captures and
cross-referenced with the QCSuper and SCAT open-source DIAG parsers.

Field names follow the public Techplayon log-packet field reference:
    0xB0C0 - LTE RRC OTA Packet
        pkt_version, rrc_release_num, radio_bearer_id, phys_cell_id (a.k.a. pci),
        earfcn, sfn, subframe_number, pdu_bytes, pdu_length, sib_mask

Log name: LOG_LTE_RRC_OTA_MSG_LOG_C
Also known as: LTE RRC OTA Packet, LOG_LTE_RRC_OTA_MESSAGE, LOG_OTA_MESSAGE, LOG_LTE_RRC_OTA_PACKET
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_LTE_RRC_OTA_MSG
from diaggrok.parsers.uper import UperReader
from diaggrok.parsers.asn1_helpers import read_open_type_length
from diaggrok.registry import register

# Channel type constants (3GPP TS 36.331)
LTE_RRC_CHANNEL_BCCH_BCH   = 0x01
LTE_RRC_CHANNEL_BCCH_DL_SCH = 0x30
LTE_RRC_CHANNEL_PCCH        = 0x0C
LTE_RRC_CHANNEL_DL_CCCH     = 0x08
LTE_RRC_CHANNEL_DL_DCCH     = 0x09
LTE_RRC_CHANNEL_UL_CCCH     = 0x0A
LTE_RRC_CHANNEL_UL_DCCH     = 0x0B

_CHANNEL_NAMES = {
    0x01: "BCCH-BCH",
    0x08: "DL-CCCH",
    0x09: "DL-DCCH",
    0x0A: "UL-CCCH",
    0x0B: "UL-DCCH",
    0x0C: "PCCH",
    0x30: "BCCH-DL-SCH",
}

# v20 channel selector. The v20 wire format carries the RRC logical channel at
# raw byte[12] using a contiguous small-integer enum that is distinct from the
# legacy byte[2]-era LTE_RRC_CHANNEL_* constants above. Only values witnessed in
# captures are mapped; an unobserved value falls back to a hex string ("0x03"
# etc.) so, for example, a BCCH-BCH record surfaces as an unknown rather than a
# guessed name.
#
# The observed enum {2,5,6,7,8,9} is content-verified across 5.4K v20 records
# from 720 captures. 2/5/8 are also pinned by SIB1 content and QCSuper output;
# 6/7/9 come from 152 dedicated-channel records in connected-mode captures (LTE
# attach, per-channel sweeps, SIM power-cycle/reboot). Every record's RRC PDU
# decodes (UperReader, TS 36.331 Rel-8 c1 CHOICE order) as a message exclusive
# to its channel, with zero cross-channel contamination:
#   6 -> DL-CCCH : 30/30 rrcConnectionSetup
#   7 -> DL-DCCH : dlInformationTransfer 33 / rrcConnRelease 26 / Reconfig 4 /
#                  ueCapabilityEnquiry 3 / securityModeCommand 2 (all DL-DCCH-only)
#   9 -> UL-DCCH : rrcConnSetupComplete 30 / ulInformationTransfer 12 /
#                  ReconfigComplete 4 / securityModeComplete 3 / measReport 3 /
#                  ueCapabilityInformation 2 (all UL-DCCH-only)
# Internal consistency: ch6 rrcConnSetup (30) == ch9 rrcConnSetupComplete (30) -
# each DL setup answered by one UL complete during attach. This matches the
# v15 byte[12] enum below, so v20 and v15 share the contiguous enum. Values 1/3/4
# (incl. BCCH-BCH) remain unobserved and fall back to hex.
#
# QCSuper cross-check: a byte-join on an EG25-G connected-mode capture matched
# 56/56 v20 PDUs to QCSuper's GSMTAP frames by raw RRC-PDU bytes, with 0
# disagreements and full enum coverage, including 6->DL-CCCH (2/2), 7->DL-DCCH
# (6/6), 9->UL-DCCH (9/9) and 8->UL-CCCH (2/2). The GSMTAP sub-type->channel
# mapping is the osmocom enum, cross-checked against tshark's independent
# dissection of the same pcap.
LTE_RRC_V20_CHANNEL_OFFSET = 12
LTE_RRC_V20_CHANNEL_BCCH_DL_SCH = 2
LTE_RRC_V20_CHANNEL_PCCH = 5
LTE_RRC_V20_CHANNEL_DL_CCCH = 6
LTE_RRC_V20_CHANNEL_DL_DCCH = 7
LTE_RRC_V20_CHANNEL_UL_CCCH = 8
LTE_RRC_V20_CHANNEL_UL_DCCH = 9

_V20_CHANNEL_NAMES = {
    LTE_RRC_V20_CHANNEL_BCCH_DL_SCH: "BCCH-DL-SCH",  # SystemInformation / SIB1
    LTE_RRC_V20_CHANNEL_PCCH: "PCCH",                # Paging
    LTE_RRC_V20_CHANNEL_DL_CCCH: "DL-CCCH",          # RRCConnectionSetup/Reject
    LTE_RRC_V20_CHANNEL_DL_DCCH: "DL-DCCH",          # Reconfig/Release/SMC/dlInfoXfer
    LTE_RRC_V20_CHANNEL_UL_CCCH: "UL-CCCH",          # RRCConnectionRequest
    LTE_RRC_V20_CHANNEL_UL_DCCH: "UL-DCCH",          # SetupComplete/measReport/ulInfoXfer
}

# Per-wire-version channel enums for the non-v20 parse path, each pinned by a
# byte-identical join of the parsed RRC PDUs against QCSuper's GSMTAP output.
# The channel enum is per-version; there is no single non-v20 map:
#   * v15 (MDM9x50) uses the SAME small-int enum as v20's byte[12] enum.
#   * v26/v27 (SDX55/SDX62) use a DIFFERENT enum (DL-CCCH..UL-DCCH at 8..11).
#   * v9 (MDM9230) and v2 (MDM9600) are distinct again.
# Only channel_type values observed and byte-joined are mapped; an unobserved
# value falls back to a hex string. The legacy byte[2]-era _CHANNEL_NAMES is not
# used as a fallback because it is wrong for these versions (it would label v9
# ct=11 as UL-DCCH, which is PCCH, and v15 ct=8/9 as DL-CCCH/DL-DCCH, which are
# UL-CCCH/UL-DCCH). Extend a version's map only from a fresh byte-join.
_NONV20_CHANNEL_NAMES_BY_VERSION: dict[int, dict[int, str]] = {
    # MC7700 / MDM9600 (SWI9200X). Captures that drive CFUN cycles (forcing SIB
    # re-acquisition) carry ct=2 BCCH-DL-SCH records alongside idle-camp paging.
    # tshark lte_rrc decodes those PDUs 13/13 clean as
    # SystemInformationBlockType1 / SystemInformation[SIB2/3/4/5/7], 0 malformed;
    # a misaligned v2 (version<8) header offset would desync the PER, so this
    # pins both ct=2 = BCCH-DL-SCH and the v2 u16-EARFCN header framing. The SIB1
    # ECGI (MCC 310 / MNC 260 / TAC 11544) matches the UperReader decode and the
    # same serving location seen in an EG95-NA v12 capture.
    # PCCH stays ct=4 (unique to the MDM9200-era enum; not the v9/v15 numbering).
    2: {2: "BCCH-DL-SCH", 4: "PCCH"},
    # EM7455 / MDM9230. Idle camp - SIB broadcast + paging.
    9: {9: "BCCH-DL-SCH", 11: "PCCH"},
    # Quectel EG95-NA (MDM9207), 490 records / 20 captures. Shares v9's
    # contiguous small-int enum at byte[12]. A QCSuper byte-join on an EG95-NA
    # idle capture matched 38/38 PDUs by raw RRC bytes: ct=9->BCCH-DL-SCH (17/17,
    # also content-verified: 59 SIB1 + 72 SI decode via UperReader) and
    # ct=11->PCCH (21/21). Rare byte[12] values 12/13/14/15 (2..4 records each,
    # never oracle-decoded) stay unmapped and render as hex.
    12: {9: "BCCH-DL-SCH", 11: "PCCH"},
    # Quectel EP06-A (MDM9x40), 142 records / 5 captures. A QCSuper byte-join on
    # an EP06-A idle capture matched 65/65 PDUs: ct=4->PCCH (65/65). Only PCCH is
    # observed in idle windows; other channels await a connected-mode v13
    # capture and render as hex.
    13: {4: "PCCH"},
    # MikroTik R11e-LTE-US (MDM9207-class LTE Cat-4): 18 records, all ct=5, from
    # a single serving-cell capture on one unit. A QCSuper byte-join on that
    # capture emits 18 GSMTAP LTE-RRC frames, all sub_type=6 (PCCH), each RRC PDU
    # matching msg_data byte-for-byte (18/18 positional), so ct=5 = PCCH. v14
    # puts PCCH at ct=5 (like v15), not ct=4 like v13 (EP06-A): the small-int
    # enum is renumbered per firmware generation, so this value is pinned from
    # the oracle, not inferred. The firmware's own 0x60 EVENT_LTE_RRC_DL_MSG
    # (payload 02 40 = PCCH) fires tick-identical to all 18 records, and stock
    # tshark lte_rrc.pcch decodes 18/18 clean. Only PCCH is observed in the idle
    # window; other v14 channels await a connected-mode capture and render as hex.
    14: {5: "PCCH"},
    # MDM9x50 (EM7565, MC7411). Same enum as v20 byte[12].
    15: {2: "BCCH-DL-SCH", 5: "PCCH", 6: "DL-CCCH", 7: "DL-DCCH",
         8: "UL-CCCH", 9: "UL-DCCH"},
    # v24 (0x18, Quectel EM120R-GL / EM160R-GL, SDX24), 189 records / 8
    # captures. Same enum as v15. A QCSuper byte-join on an EM120R-GL capture
    # (PLMN scan + attach) matched 118/118 PDUs, each ct to exactly one sub_type;
    # SCAT agrees on every PDU it emits; stock tshark decodes 189/189 clean.
    # Independently re-derived from the firmware's own 0x60 EVENT_LTE_RRC_DL_MSG /
    # UL_MSG channel byte (1=BCCH 2=PCCH 3=DL-CCCH 4=DL-DCCH 5=UL-CCCH 6=UL-DCCH),
    # same tick: BCCH 9/9 (msg byte == the SIB tshark decodes), PCCH 68/68, DL-CCCH
    # 1/1, DL-DCCH 11/12 (the 12th, a Release, landed on a same-tick page), UL-CCCH
    # 1/1, UL-DCCH 16/16.
    24: {2: "BCCH-DL-SCH", 5: "PCCH", 6: "DL-CCCH", 7: "DL-DCCH",
         8: "UL-CCCH", 9: "UL-DCCH"},
    # SDX55 (Wistron LV55). Distinct enum: dedicated/CCCH at 8..11.
    26: {3: "BCCH-DL-SCH", 7: "PCCH", 8: "DL-CCCH", 9: "DL-DCCH",
         10: "UL-CCCH", 11: "UL-DCCH"},
    # SDX62 (RM520N-GL, CFW-3212). Identical enum to v26.
    27: {3: "BCCH-DL-SCH", 7: "PCCH", 8: "DL-CCCH", 9: "DL-DCCH",
         10: "UL-CCCH", 11: "UL-DCCH"},
    # v30 (0x1E, Foxconn T99W640 / SDX72). {3,7} like v26/v27, with the PDU at
    # [24] (24-byte header, see the parse path): stock tshark 34/34 BCCH SIB set
    # == sib_mask and 689/689 PCCH with their paging records; SCAT 23/23 byte-identical; F3
    # lte_rrc_stm.c LTE_MAC_RRC_PCCH_DL_DATA_IND 30/30 on ct=7; 0x60
    # EVENT_LTE_RRC_DL_MSG (ch 1=BCCH with the SIB number / ch 2=PCCH) on
    # ct=3 / ct=7. Idle only: no DL/UL CCCH/DCCH event appears in any T99W640
    # capture, so connected-mode channels remain unobserved.
    30: {3: "BCCH-DL-SCH", 7: "PCCH"},
}

_V20_HEADER_SIZE = 19  # bytes before msg_data


@dataclass
class Diag0xB0C0:
    """Parsed LTE RRC OTA message."""
    log_time: int
    version: int
    rrc_release: int
    channel_type: int
    channel_name: str
    pci: int
    earfcn: int
    sfn: int
    subfn: int
    pdu_number: int
    msg_length: int
    msg_data: bytes    # raw ASN.1 PER-encoded RRC message
    # Radio bearer id - Techplayon-documented `radio_bearer_id` (TS 36.331
    # rb-Identity). On the version>=25 header this is the HIGH byte of the 2-byte
    # field at [4:6] (byte[5]), just before pci@6. Values seen: 0 = common / broadcast (SRB0 - every
    # BCCH-DL-SCH/PCCH/DL-CCCH/UL-CCCH record), 1 = SRB1, 2 = SRB2 (dedicated
    # DL/UL-DCCH). The partition is byte-clean across BOTH SDX62 (RM520N-GL) and
    # SDX55 (Inseego M2000): a common channel never carries 1/2, a DCCH never
    # carries 0. The LOW byte [4] is a per-chipset log-encoding CONSTANT (0x60 on
    # SDX62, 0x90 on SDX55 - invariant within a capture, orthogonal to the bearer)
    # so it is deliberately NOT folded into this value. None on versions whose
    # header places pci at byte[4] (no separate bearer field on the wire there).
    # The exception is v24: there byte[3] carries the same 0/1/2 bearer
    # partition (189/189 records), so v24 reports it from byte[3].
    radio_bearer_id: int | None = None
    # SIB mask - Techplayon-documented `sib_mask` ("bitmap of decoded SIB
    # IDs"). A u32-LE bitmap in the 4 bytes immediately
    # AFTER channel_type on every version (v20: byte[13:17]; v>=8 non-v20: the 4
    # bytes the length-probe skips), immediately followed by msg_length (u16-LE).
    # bit N (1..31) set => SystemInformationBlockTypeN is present in this SI
    # message (one-way: the mask is a lower bound, see below); bit0 is unused.
    # Established by correlating the field against the SIBs the PDU decodes to
    # across 791 BCCH-DL-SCH records (SIB1->0x02, SIB2+SIB3->0x0c, SIB4->0x10,
    # SIB5->0x20; zero wrong-bit counterexamples). The mask also flags bit8=SIB8
    # (CDMA2000, rides with SIB5 as 0x120; body decoded into sib8_cdma_time)
    # and bit24=SIB24 (NR cell reselection, broadcast by the 5G-capable SDX62 as
    # the lone 0x1000000 records; body decoded into sib24_nr_resel). Non-SI channels
    # (DCCH/CCCH/PCCH) carry 0. FAITHFUL to the wire: ~8.5% of BCCH-DL-SCH records
    # (mostly v20) carry a real SIB with mask=0 on the wire - so sib_mask==0 means
    # "field unpopulated", NOT "no SIBs present". The authoritative SIB-presence
    # signal is the decoded sibN_* fields; sib_mask is the firmware's own hint.
    # None when the record carries no mask field.
    #
    # Lower bound, not an exact set. A non-zero mask can also omit a SIB the
    # message carries. Across 660 captures, every BCCH SystemInformation record
    # whose decoded SIB set differed from the mask set (93 records / 45
    # distinct PDUs, v0x09/0c/14/1b)
    # was run through stock tshark lte_rrc.bcch_dl_sch, and tshark agreed with
    # the decode on 45/45, with the mask on 0/45. There were no walker false
    # positives, and in every case the decode was a SUPERSET of the mask. 77 of
    # the 93 are the mask==0 case above. The other 16 are v0x1b [SIB5, SIB8]
    # messages flagged 0x100 (15) or 0x20 (1) instead of 0x120 (RM520N-GL,
    # EM9291, FN980; 9 captures). So bit N set => SIB N present, but bit N clear
    # proves nothing. Take SIB presence from the decoded sibN_* fields.
    #
    # Where the partial masks come from: v0x1b logs BCCH SI on two paths. OTA: sfn>0, one record per over-the-air reception. REPLAY:
    # sfn==0, the cell's whole cached SI set re-logged within 2 ms of a SIB1
    # record (re-camp on a known cell). Over the 9 bearing captures (388 SI
    # records): OTA mask == decoded set 86/88 (the other 2 are mask==0, and
    # both are a second log of the same PDU at the same SFN, 4-11 ms after a
    # flagged copy). REPLAY mask == decoded set 284/300. All 16 partial masks
    # are REPLAY [SIB5, SIB8]. When the capture holds the OTA read, the first
    # replay after it keeps 0x120 (3/3) and later replays drop SIB5 to 0x100
    # (5/5). Byte-identical PDUs carry both masks, so the mask is state-driven,
    # not a function of the message. It is NOT "SIBs newly added to the SI DB":
    # the replay re-delivers nothing new over the air, yet 280/280 other replay
    # records (SIB5 alone 55/55) carry their full mask. Nor is it the F3
    # `SIB_DBG:sibs_added_bitmask`, which is REQUEST-side: it prints just before
    # `Sent cphy_sib_sched_req` (0x3 = MIB+SIB1 on get_sibs_req, 0x0 on abort).
    # On EM7565/MC7411 v0x0f and LM960 v0x14, sib_mask equals the firmware's
    # per-reception `Received ind has SIBs 0x%x` on 68/68 same-tick joins, while
    # sibs_added_bitmask reads 0x0 beside 45 of them. No partial-mask build
    # emits lte_rrc_sib.c F3, so why SIB5 drops on later replays is not known.
    #
    # F3 corroboration: the firmware's own F3 debug messages print SIB masks in
    # the same bit space. `lte_rrc_sib.c` carries a family of masks -
    # `SIB_DBG:sibs_added_bitmask: 0x%x`, `in-consistent sibs to be rmvd 0x%x;
    # all_si's sibs_bitmask 0x%x`, `In post-processing, curr_mask = 0x%x
    # next_mask = 0x%x rcvd_curr_bitmask = 0x%x` (line numbers move per build; the
    # FORMAT STRING is the stable key). Measured over 10 F3 streams / 4 modules /
    # 2 vendors / 2 chipset generations (Sierra EM7565 + MC7411 MDM9x50, Telit
    # LM960 + LM960A18 SDX20): on 7/7 windows where the co-temporal same-cell
    # 0xB0C0 union is rich enough to discriminate, `all_si's sibs_bitmask` equals
    # that union with bits 0-1 cleared - e.g. 0x21c == {SIB2,SIB3,SIB4,SIB9} and
    # 0x13c == {SIB2,SIB3,SIB4,SIB5,SIB8}. `bit N = SIB N+1` and `bit N = SIB N+2`
    # score 0/7. bit9 is value-grounded, not just bitmap-grounded: the same cell's
    # SIB9 records decode the Home eNB name 'et-124-cbs1'. And the F3
    # family shows the same SIB5+SIB8 = 0x120 pairing documented above.
    # bit0 is set in the F3 masks but NEVER in this field (0/800 records measured),
    # consistent with "bit0 is unused" here: the F3 DB also tracks the MIB, which
    # is not a SIB and never rides BCCH-DL-SCH. The bit0 evidence is structural;
    # event-level tests so far are two negatives.
    sib_mask: int | None = None
    # SIB numbers whose bit is set in sib_mask (derived; empty list when
    # sib_mask is 0 or None). See the sib_mask caveat above: an empty list does
    # not prove the SI carries no SIBs, and a non-empty list is a lower bound.
    sibs_present: list[int] = field(default_factory=list)
    # RRC release minor/patch - populated on non-v20 versions where the wire
    # carries them at byte[2]/byte[3] (the vendor log viewer labels them "RRC
    # Release Number.Major.minor"). v20 puts channel_type/reserved at those
    # offsets, so they remain None on v20. Matches the lte_nas_ota.py naming
    # convention. A vendor decoder's rendered output for a v15 record shows
    # "RRC Release Number.Major.minor = 13.2.1" → rrc_rel=13, rrc_ver_major=2,
    # rrc_ver_minor=1.
    rrc_ver_major: int | None = None
    rrc_ver_minor: int | None = None
    # SIB1 decoded fields (populated when message is SIB1)
    sib1_mcc: str | None = None
    sib1_mnc: str | None = None
    sib1_tac: int | None = None
    sib1_cell_id: int | None = None
    # SIB1 cellAccessRelatedInfo flags + the full PLMN list, as decoded by
    # decode_sib1_cell_access (sib1_mcc/mnc above come from plmn_list[0]).
    # Present-only, like the sib1_* identity block above.
    #   sib1_cell_barred    -- ENUMERATED {barred, notBarred}; True == barred.
    #   sib1_csg_indication -- BOOLEAN; True == closed subscriber group cell.
    #   sib1_plmn_list      -- [{'mcc','mnc'}]; >1 entry is an MOCN/RAN-shared
    #                          cell broadcasting multiple operators.
    sib1_cell_barred: bool | None = None
    sib1_csg_indication: bool | None = None
    sib1_plmn_list: list | None = None
    # NAS-tunneling decode (populated for DCCH InformationTransfer carrying
    # dedicatedInfoNAS - see _try_decode_nas_tunneled). nas_tunneled is True
    # iff the dedicatedInfoNAS path was matched and dedicated_info_nas holds
    # the extracted NAS PDU bytes.
    nas_tunneled: bool = False
    dedicated_info_nas: bytes | None = None
    # measConfig auto-decode - populated when a DL-DCCH record carries
    # an RRCConnectionReconfiguration whose measConfig is present. Decoded by
    # lte_rrc_reconfig.decode_rrc_reconfig_meas_config. meas_objects is the list
    # of MeasObjectEUTRA (each: earfcn/bandwidth/offset + CellToAddMod list);
    # has_meas_gap / s_measure are the measConfig scalars. Empty/None when the
    # record is not a reconfiguration, carries no measConfig, or fails to decode.
    meas_objects: list[Any] = field(default_factory=list)
    meas_has_gap_config: bool = False
    meas_s_measure: int | None = None
    # MeasurementReport auto-decode - populated when a UL-DCCH record
    # carries a MeasurementReport. Decoded by
    # lte_rrc_meas_report.decode_measurement_report. meas_report_id is the
    # measId (1..maxMeasId); pcell_rsrp/rsrq are the serving-cell measurements
    # in dBm/dB; meas_report_neighbors is the list of MeasResultCell. None when
    # the record is not a MeasurementReport or fails to decode.
    meas_report_id: int | None = None
    meas_report_pcell_rsrp: float | None = None
    meas_report_pcell_rsrq: float | None = None
    meas_report_neighbors: list[Any] = field(default_factory=list)
    # The whole decoded RRCConnectionReconfiguration measConfig delta:
    # measObjectIds, measId links, remove lists and the mobilityControlInfo
    # (handover) flag -- the state observation.py needs to map a
    # MeasurementReport's measId to a carrier. Set for EVERY decoded
    # reconfiguration, including one with no measConfig (a bare handover still
    # invalidates the measId links). None otherwise. Not serialized by to_dict;
    # meas_objects above remains the flattened view.
    meas_config: Any = None
    # SIB2/SIB3/SIB4 auto-decode - populated when a
    # BCCH-DL-SCH record carries a SystemInformation container with the
    # respective SIB. Decoded in ONE container walk by
    # lte_rrc_sib_time.decode_si_sibs: sib2_access = access barring / RACH /
    # common radio config; sib3_resel = intra-freq cell-reselection params
    # (q-Hyst, threshServingLow, priority, s-IntraSearch…); sib4_neighbors =
    # intra-freq neighbor cells (PCI + q-offset), excluded PCI ranges, CSG
    # range. Each is None when the record is a SIB1 or carries no such SIB.
    sib2_access: Any | None = None
    sib3_resel: Any | None = None
    sib4_neighbors: Any | None = None
    # SIB5 auto-decode - populated when a BCCH-DL-SCH record
    # carries a SystemInformation container with SIB5, via the same fused
    # decode_si_sibs walk (per-carrier inter-freq reselection info +
    # neighbor/excluded lists + v8h0/v9e0 multi-band overlays + Ext-r12
    # additional carriers). None when the record is a SIB1 or carries no SIB5.
    sib5_inter_freq: Any | None = None
    # SIB6 auto-decode - populated when a BCCH-DL-SCH record carries a
    # SystemInformation container with SIB6 (UTRAN/3G neighbor freqs). Decoded
    # by lte_rrc_sib_time.decode_si_sib6. None when the record is a SIB1 or
    # carries no SIB6. SIB6 is absent from the capture corpus (US 3G sunset);
    # wired for future 3G-neighbor captures, validated via pycrate vectors.
    sib6_neighbors: Any | None = None
    # SIB7 auto-decode - populated when a BCCH-DL-SCH record carries a
    # SystemInformation container with SIB7 (GERAN/2G neighbor freqs). Decoded
    # by lte_rrc_sib_time.decode_si_sib7. None when the record is a SIB1 or
    # carries no SIB7. SIB7 is absent from RM520N-GL captures (0/2886 0xB0C0
    # records; US 2G sunset - SIB5 is present in the same records, so the walk
    # is live); wired for future 2G-neighbor captures, validated via pycrate.
    sib7_neighbors: Any | None = None
    # SIB8 CDMA system-time anchor - a SibTimeInfo (source="sib8")
    # populated when a BCCH-DL-SCH record carries a SystemInformation container
    # with SIB8 (CDMA2000 synchronousSystemTime), via the same fused
    # decode_si_sibs walk. None when the record is a SIB1 or carries no SIB8.
    # Present in the RM520N-GL corpus on band-12 cells still broadcasting a
    # CDMA2000 neighbour config (EARFCN 5230); the decoded UTC is a wall-clock
    # time anchor for DIAG ts64 calibration (10ms tick, TS 36.331 §6.3.1).
    sib8_cdma_time: Any | None = None
    # SIB9 auto-decode - populated when a BCCH-DL-SCH record carries a
    # SystemInformation container with SIB9 (Home eNB / femtocell name). Decoded
    # by lte_rrc_sib_time.decode_si_sib9 in the same fused container walk.
    # hnb-Name is an operator/owner-chosen UTF-8 identity string, the LTE analogue
    # of a Wi-Fi SSID, and is itself OPTIONAL inside SIB9 - so an LteSIB9 with
    # hnb_name=None is a legal record (an HNB that declines to name itself), NOT a
    # decode failure. None when the record is a SIB1 or carries no SIB9.
    # A census of 597 0xB0C0-bearing captures (48,549 records) finds 29 SIB9
    # records on three vendors x chipsets x wire versions - Sierra EM7565 (MDM9x50 v15) + Telit LM960 (SDX20 v20) both decode
    # 'et-124-cbs1' byte-identically, SimCom SIM8202G-M2 (SDX55 v27) broadcasts
    # 'ty-outdoor-cbs1-p'/'mf-outdoor-cbs3-p' with a non-UTF-8 tail (length
    # determinant verified correct by byte-accounting; the operator's name is not
    # valid UTF-8 - see lte_rrc_sib9). sib_mask bit 9 is set on 29/29 of exactly
    # those records and no others, independently confirming bit N = SIB N.
    # SIB9 is a base-CHOICE alternative with no open-type length prefix, so it
    # must be decoded in place: the container walk has no way to skip an
    # undecoded SIB9 and reach the SIBs after it.
    sib9_hnb: Any | None = None
    # SIB16 auto-decode - populated when a BCCH-DL-SCH record carries a
    # SystemInformation container with SIB16 (UTC/GPS network time). Decoded by
    # lte_rrc_sib_time.decode_si_sib16 in the same fused container walk. Full
    # fields (time_info_utc / utc_datetime / leap_seconds / dst /
    # local_time_offset), not just the time anchor. None when the record is a
    # SIB1 or carries no SIB16. SIB16 is absent from the capture corpus (US
    # operators anchor time via SIB8/GNSS); wired for future SIB16-bearing
    # captures, validated via pycrate vectors.
    sib16_time: Any | None = None
    # SIB24 auto-decode - populated when a BCCH-DL-SCH record carries a
    # SystemInformation container with SIB24 (NR/5G inter-RAT cell reselection).
    # Decoded by lte_rrc_sib_time.decode_si_sib24 in the same fused container
    # walk. Per-carrier NR ARFCN / band / reselection priority + sub-priority /
    # threshX / q-RxLevMin / p-MaxNR / q-QualMin / SSB spacing + duration, plus
    # t-ReselectionNR. Presence is flagged by the sib_mask bit24; the
    # SDX62 RM520N-GL broadcasts it in the corpus. None when the record is a
    # SIB1 or carries no SIB24.
    sib24_nr_resel: Any | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'type': 'Diag0xB0C0',
            'log_time': self.log_time,
            'version': self.version,
            'rrc_release': self.rrc_release,
            'channel_type': self.channel_type,
            'channel_name': self.channel_name,
            'pci': self.pci,
            'earfcn': self.earfcn,
            'sfn': self.sfn,
            'subfn': self.subfn,
            'pdu_number': self.pdu_number,
            'msg_length': self.msg_length,
            # The raw ASN.1 PER-encoded RRC message - the main content of an RRC
            # OTA log: downstream ASN.1 decode / pcap export (QCSuper-style)
            # needs the PDU bytes, not just its length. Hex like dedicated_info_nas.
            'msg_data': self.msg_data.hex() if self.msg_data else '',
        }
        # radio_bearer_id - present-only, header-level field.
        if self.radio_bearer_id is not None:
            d['radio_bearer_id'] = self.radio_bearer_id
        # sib_mask - present-only. Emit the raw bitmap AND the derived
        # SIB-number list so downstream (WiGLE / pcap / SI analysis) sees which
        # SIBs the firmware flagged.
        if self.sib_mask is not None:
            d['sib_mask'] = self.sib_mask
            d['sibs_present'] = self.sibs_present
        if self.rrc_ver_major is not None:
            d['rrc_ver_major'] = self.rrc_ver_major
            d['rrc_ver_minor'] = self.rrc_ver_minor
        if self.sib1_tac is not None:
            d['sib1_mcc'] = self.sib1_mcc
            d['sib1_mnc'] = self.sib1_mnc
            d['sib1_tac'] = self.sib1_tac
            d['sib1_cell_id'] = self.sib1_cell_id
            # SIB1 flags + full PLMN list - present-only, gated on the
            # same sib1_tac as the identity block they decode alongside.
            if self.sib1_cell_barred is not None:
                d['sib1_cell_barred'] = self.sib1_cell_barred
            if self.sib1_csg_indication is not None:
                d['sib1_csg_indication'] = self.sib1_csg_indication
            if self.sib1_plmn_list is not None:
                d['sib1_plmn_list'] = self.sib1_plmn_list
        if self.nas_tunneled:
            d['nas_tunneled'] = True
            d['dedicated_info_nas'] = (
                self.dedicated_info_nas.hex()
                if self.dedicated_info_nas is not None
                else None
            )
        # measConfig - only emit when a reconfiguration actually
        # carried meas objects, mirroring the SIB1/NAS "present-only" pattern.
        if self.meas_objects:
            d['meas_objects'] = [m.to_dict() for m in self.meas_objects]
            d['meas_has_gap_config'] = self.meas_has_gap_config
            if self.meas_s_measure is not None:
                d['meas_s_measure'] = self.meas_s_measure
        # MeasurementReport - keyed on meas_report_id being set.
        if self.meas_report_id is not None:
            d['meas_report_id'] = self.meas_report_id
            d['meas_report_pcell_rsrp'] = self.meas_report_pcell_rsrp
            d['meas_report_pcell_rsrq'] = self.meas_report_pcell_rsrq
            d['meas_report_neighbors'] = [
                c.to_dict() for c in self.meas_report_neighbors
            ]
        # SIB2/SIB3/SIB4 - present-only, mirroring
        # the SIB1/NAS pattern.
        if self.sib2_access is not None:
            d['sib2_access'] = self.sib2_access.to_dict()
        if self.sib3_resel is not None:
            d['sib3_resel'] = self.sib3_resel.to_dict()
        if self.sib4_neighbors is not None:
            d['sib4_neighbors'] = self.sib4_neighbors.to_dict()
        # SIB5 - present-only, mirroring the SIB2 pattern.
        if self.sib5_inter_freq is not None:
            d['sib5_inter_freq'] = self.sib5_inter_freq.to_dict()
        # SIB6 - present-only, mirroring the SIB2 pattern.
        if self.sib6_neighbors is not None:
            d['sib6_neighbors'] = self.sib6_neighbors.to_dict()
        # SIB7 - present-only, mirroring the SIB2 pattern.
        if self.sib7_neighbors is not None:
            d['sib7_neighbors'] = self.sib7_neighbors.to_dict()
        # SIB8 CDMA system time - present-only, mirroring the pattern.
        if self.sib8_cdma_time is not None:
            d['sib8_cdma_time'] = self.sib8_cdma_time.to_dict()
        # SIB9 / SIB16 - present-only, mirroring the SIB2 pattern.
        if self.sib9_hnb is not None:
            d['sib9_hnb'] = self.sib9_hnb.to_dict()
        if self.sib16_time is not None:
            d['sib16_time'] = self.sib16_time.to_dict()
        # SIB24 NR cell reselection - present-only, mirroring the pattern.
        if self.sib24_nr_resel is not None:
            d['sib24_nr_resel'] = self.sib24_nr_resel.to_dict()
        return d


# Field values are hardware-validated on an EG25-G.

# The wire versions this parser implements: the byte-0 values attested in
# captures (records per version byte, payloads >4 bytes: {'0x02': 455,
# '0x09': 2472, '0x0C': 531, '0x0D': 277, '0x0E': 90, '0x0F': 4563,
# '0x14': 19052, '0x1A': 4336, '0x1B': 53476, '0x1E': 815}) plus 0x18 (v24,
# EM120R-GL/EM160R-GL SDX24; 206 records / 10 captures, see the v24 channel
# map). Any other version returns None so the registry dispatch warning fires
# instead of a silent record.
_VERSIONS_B0C0_4918: tuple[int, ...] = (0x02, 0x09, 0x0C, 0x0D, 0x0E, 0x0F, 0x14, 0x18, 0x1A, 0x1B, 0x1E)


@register(LOG_LTE_RRC_OTA_MSG, domain="rrc",
    name="0xB0C0",
    description="Standard LTE RRC Over-The-Air message with ASN.1 PER-encoded content",
    version=32,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Reverse-engineered from captures across eleven wire versions (0x02, "
        "0x09, 0x0C, 0x0D, 0x0E, 0x0F, 0x14, 0x18, 0x1A, 0x1B, 0x1E) on MDM9600, "
        "MDM9230, MDM9207, MDM9x40, MDM9x50, MDM9607, SDX20, SDX24, SDX55, SDX62 "
        "and SDX72 modules, cross-referenced with the QCSuper and SCAT parsers. "
        "Every header byte is accounted for: version, rrc_release, "
        "rrc_ver_major/minor (non-v20), radio_bearer_id (byte[5] on v>=25, "
        "byte[3] on v24; 0=common/SRB0, 1=SRB1, 2=SRB2), pci, earfcn (u32 on "
        "v>=8, so >65535 band-66 EARFCNs are not truncated), sfn/subfn (10-bit "
        "SFN mask on all versions), channel_type, the u32-LE sib_mask and "
        "msg_length; v30 (0x1E, T99W640) has a 24-byte header with a 3-byte "
        "zero pad before the PDU (723/723 records). Truncated payloads return "
        "None. The channel_type enum is per wire version and each mapping is "
        "pinned by a byte-identical join of the RRC PDUs against QCSuper's "
        "GSMTAP output, cross-checked with stock tshark lte_rrc dissection, "
        "SCAT, decoded-message content (each channel carries only messages "
        "exclusive to it) and, where present, the firmware's 0x60 "
        "EVENT_LTE_RRC_DL_MSG/UL_MSG channel byte and F3 PCCH_DL_DATA_IND "
        "messages. pci and earfcn are verified by identity against serving-cell "
        "readback (AT+QENG, AT!GSTATUS, AT#MONI, QMI GetCellLocationInfo, "
        "JSONRPC) and against co-captured 0xB116/0xB193 on EG25-G, MC7700, "
        "LV55, RM500Q-AE, MC7411, EM7455, LM960A18, RM520N-GL and EM7565, and "
        "by the firmware's own F3 serving-cell prints (lte_rrc_sib.c "
        "phy_cell_id/freq, lte_ml1_common_rssi_ind.c serving earfcn) on "
        "several builds. SIB1 TAC and cell identity match AT#MONI broadcast "
        "values on three serving cells. sib_mask bit N = SIB N was established "
        "by correlation over 791 BCCH-DL-SCH records with zero wrong-bit "
        "counterexamples and matches the firmware's F3 SIB bitmasks; it is a "
        "lower bound (~8.5% of BCCH records carry mask 0, and some v0x1B "
        "replayed SI records omit SIB5), so the decoded sibN_* fields are the "
        "authoritative SIB-presence signal. The msg_data PDU is surfaced as hex "
        "and deep-decoded in-band (SIB1-9/16/24, NAS tunnel, measConfig, "
        "MeasurementReport). Known gaps: v20 channel values 1/3/4 (incl. "
        "BCCH-BCH) and rare v12 byte[12] values 12-15 are unobserved or "
        "unconfirmed and render as hex; v13, v14 and v30 have only idle-mode "
        "channels pinned; on v15 byte[3] shows the radio-bearer partition but "
        "is still reported as rrc_ver_minor."
    ),
    source_url="https://github.com/lukejenkins",
    issues=(),
    primary_issue=None,
    wigle_direct=True,
    wigle_roles=("identity", "timing-anchor:periodic", "rat-context"),
    # Header binary fields, all decoded into named to_dict fields (100% byte
    # accounting): version, rrc_release, radio_bearer_id, channel_type,
    # pci, earfcn, sfn, subfn, pdu_number, sib_mask, msg_length, msg_data (12).
    # Non-v20 adds rrc_ver_major/minor (2). Deep-decoded SIB1 contributes 4
    # (mcc, mnc, tac, cell_id) from the msg_data ASN.1 PER decode. NAS tunnel
    # detection adds 2 (nas_tunneled flag, dedicated_info_nas bytes). = 20
    # counted quantities, ALL parsed. channel_name (derived from channel_type)
    # and sibs_present (derived from sib_mask) are presentations, not counted.
    # The sib_mask region is the decoded u32 SIB bitmap, and msg_data is
    # surfaced as hex for downstream ASN.1 / pcap consumers (the main content of
    # an RRC-OTA log) and deep-decoded in-band (SIB1-9/16/24, NAS tunnel,
    # measConfig, MeasurementReport).
    fields_identified=20,
    fields_parsed=20,
    field_invariants={"version": {"enum": [0x02, 0x09, 0x0C, 0x0D, 0x0E, 0x0F, 0x14, 0x18, 0x1A, 0x1B, 0x1E]}},
)
def parse_0xb0c0(log_time: int, data: bytes) -> Diag0xB0C0 | None:
    """Parse 0xB0C0 - LTE RRC OTA Message.

    Version 20 (primary, SDX20/MDM9607/SDX55):
        Fixed 19-byte header with u32 EARFCN at offset 6.

    Other versions (2, 9, 12, 13, 14, 15, 24, 26, 27, 30):
        Variable header with version-dependent EARFCN width and SIB mask.
        Based on QCSuper's multi-version approach.
    """
    if not data or data[0] not in _VERSIONS_B0C0_4918:  # unknown version -> None (warned)
        return None
    if len(data) < 6:
        return None

    version = data[0]
    rrc_release = data[1]

    # Version 20: use the known fixed layout
    if version == 20:
        if len(data) < _V20_HEADER_SIZE:
            return None
        # The channel selector is byte[12], NOT byte[2] (byte[2] is a
        # constant 0x30 on every observed v20 record). v20 uses its own
        # small-integer channel enum (_V20_CHANNEL_NAMES), not _CHANNEL_NAMES.
        channel_type = data[LTE_RRC_V20_CHANNEL_OFFSET]
        pci = unpack_from('<H', data, 4)[0]
        # earfcn is a u32 at [6:10], NOT a u16 at [6:8]. A u16 read truncates
        # any EARFCN > 65535 (band-66 66786 decodes as 1250) and misplaces
        # sfn_subfn. Confirmed on an LM960A18 camped on T-Mobile B66: SCAT's independent 0xB193 ML1 stream
        # reports EARFCN 66786 / PCI 236 for the same cell, matching u32@[6:10].
        earfcn = unpack_from('<I', data, 6)[0]
        # sfn_subfn is the u16 at [10:12], NOT [8:10]; [8:10] is the earfcn high
        # half. On the same B66 capture every 0xB0C0 v20 SFN computed from
        # [10:12] (812, 1004, 364, 236, 300) appears in SCAT's independent 0xB193
        # ML1 SFN set, and subfn is a constant 9 in both (the paging occasion).
        # For any EARFCN <= 65535, [8:10] is 00 00, so a misaligned read yields
        # sfn=0/subfn=0 rather than an obvious error.
        sfn_subfn = unpack_from('<H', data, 10)[0]
        # The field is subfn(4b) | sfn(10b) | reserved(2b). The SFN is
        # 10-bit by definition (TS 36.211: 0..1023), so mask off the top 2 bits.
        # Confirmed on TWO carriers: T-Mobile B66 (top bits 0, sfn 812) AND
        # Verizon B66 (top bits 0b11 - masking maps [10:12]>>4 {3871,3103,...} to
        # SCAT ML1's {799,31,...}, an exact match on all 8 distinct SFNs). Without
        # the mask a Verizon paging SFN decodes as 3871, impossible for a 10-bit field.
        sfn = (sfn_subfn >> 4) & 0x3FF
        subfn = sfn_subfn & 0xF
        # pdu_number is not a distinct v20 field ([10] is sfn_subfn's low byte);
        # it is reported as 0, like the non-v20 path.
        pdu_number = 0
        # sib_mask: the u32-LE SIB-presence bitmap in the 4 bytes right
        # after channel_type (byte[12]) → byte[13:17]. In-bounds by len>=19 gate.
        sib_mask = unpack_from('<I', data, LTE_RRC_V20_CHANNEL_OFFSET + 1)[0]
        msg_length = unpack_from('<H', data, 17)[0]
        header_size = _V20_HEADER_SIZE

        # A msg_length overrunning the record is a truncated payload -> None
        # (registry WARN), never a record with a silently empty PDU.
        if header_size + msg_length > len(data):
            return None
        msg_data = data[header_size:header_size + msg_length]

        channel_name = _V20_CHANNEL_NAMES.get(channel_type, f"0x{channel_type:02X}")
        return _build_result(log_time, version, rrc_release, channel_type,
                             channel_name, pci, earfcn, sfn, subfn,
                             pdu_number, msg_length, msg_data, data,
                             sib_mask=sib_mask)

    # Other versions: QCSuper-style multi-version parsing.
    # The non-v20 wire layout carries rrc_ver_major/minor at bytes 2/3 (as a
    # vendor decoder renders them) - name parity with lte_nas_ota.py.
    rrc_ver_major = data[2]
    rrc_ver_minor = data[3]

    radio_bearer_id: int | None = None
    if version >= 25:
        if len(data) < 8:
            return None
        # radio_bearer_id is the HIGH byte of the [4:6] field (byte[5]):
        # 0=common/SRB0 (broadcast), 1=SRB1, 2=SRB2. byte[4] is a per-chipset
        # log-encoding constant (0x60 SDX62 / 0x90 SDX55) - not part of the id.
        radio_bearer_id = data[5]
        pci = unpack_from('<H', data, 6)[0]
        ext_offset = 8
    else:
        pci = unpack_from('<H', data, 4)[0]
        ext_offset = 6
        # On v24 byte[3] is the radio bearer, not an RRC
        # version minor. 189/189 v0x18 records: 0 on every BCCH/PCCH/CCCH record,
        # 1 on every SRB1-only RRC message (SecurityModeCommand/Complete,
        # UECapabilityEnquiry/Information, MeasurementReport, Reconfiguration/
        # Complete, SetupComplete, Release - TS 36.331 sends these on SRB1 only),
        # 2 only on a ciphered DL/ULInformationTransfer (NAS on SRB2). v15 shows
        # the same partition, but there rrc_ver_minor is still reported as-is.
        if version == 24:
            radio_bearer_id = data[3]

    if ext_offset + 5 > len(data):
        return None

    # EARFCN width depends on version
    if version < 8:
        earfcn = unpack_from('<H', data, ext_offset)[0]
        sfn_subfn = unpack_from('<H', data, ext_offset + 2)[0]
        channel_type = data[ext_offset + 4]
        len_offset = ext_offset + 5
    else:
        if ext_offset + 7 > len(data):
            return None
        earfcn = unpack_from('<I', data, ext_offset)[0]
        sfn_subfn = unpack_from('<H', data, ext_offset + 4)[0]
        channel_type = data[ext_offset + 6]
        len_offset = ext_offset + 7

    # SIB mask detection. The 4 bytes at len_offset are the u32-LE sib_mask;
    # msg_length follows it. When the low u16 of the mask != the remaining
    # byte count, that region is the mask (not the length) → capture it and skip
    # past it to the real msg_length.
    sib_mask: int | None = None
    if len_offset + 2 <= len(data):
        test_len = unpack_from('<H', data, len_offset)[0]
        remaining = len(data) - len_offset - 2
        if test_len != remaining and len_offset + 6 <= len(data):
            sib_mask = unpack_from('<I', data, len_offset)[0]
            len_offset += 4

    msg_length = unpack_from('<H', data, len_offset)[0] if len_offset + 2 <= len(data) else 0
    header_size = len_offset + 2

    # v30 (0x1E, Foxconn T99W640 / SDX72) header is 24 bytes: the u16 at
    # [19:21] is the exact RRC PDU length, [21:24] are three zero bytes, and the
    # PDU starts at [24]. Measured on 723/723 v0x1E records across 22 captures
    # (len - u16 == 24; pad == 00 00 00). Reading the PDU from [21] prepends the
    # pad: PCCH then dissects as an empty Paging (689/689 lose their records)
    # and BCCH decodes fail (0/12 SIB1 ECGI). Oracles for [24:]: stock tshark
    # 723/723 clean,
    # SIB set == sib_mask 34/34; SCAT 23/23 byte-identical; F3
    # LTE_MAC_RRC_PCCH_DL_DATA_IND 30/30; 0x60 EVENT_LTE_RRC_DL_MSG labels.
    if version == 30:
        header_size += 3

    # The non-v20 (v>=8) paths read the same bit-packed sfn_subfn field as v20
    # (subfn(4b) | sfn(10b) | reserved(2b)). SFN is 10-bit on every LTE RRC OTA
    # version (TS 36.211), so the top 2 bits are masked here too. The mask
    # matters: on an RM520N-GL (SDX6x, wire v27, T-Mobile B66 EARFCN 66786) 111
    # of 196 records have the reserved top 2 bits set, and unmasked they give
    # impossible SFNs (1257/3771/3773/...); masked, they agree with AT readback.
    sfn = (sfn_subfn >> 4) & 0x3FF
    subfn = sfn_subfn & 0xF
    pdu_number = 0

    # The header (incl. msg_length itself) and the declared PDU must fit;
    # otherwise the payload is truncated -> loud None (registry WARN), never a
    # record with a silently empty PDU. This also catches a truncated no-mask
    # (v<8) record whose length probe then mis-takes the length for a sib_mask:
    # the u16 read after the "mask" overruns the record.
    if header_size + msg_length > len(data):
        return None
    msg_data = data[header_size:header_size + msg_length]

    # Name the channel via the per-version oracle-pinned enum, NOT the legacy
    # byte[2]-era _CHANNEL_NAMES (wrong for non-v20: it lacks the small-int
    # values and would mislabel the ones that collide with a legacy key, e.g.
    # v15 ct=8/9 as DL-CCCH/DL-DCCH when they are UL-CCCH/UL-DCCH).
    # Unmapped (version, channel_type) → hex string, never a legacy guess.
    chan_map = _NONV20_CHANNEL_NAMES_BY_VERSION.get(version, {})
    channel_name = chan_map.get(channel_type, f"0x{channel_type:02X}")

    return _build_result(log_time, version, rrc_release, channel_type,
                         channel_name, pci, earfcn, sfn, subfn,
                         pdu_number, msg_length, msg_data, data,
                         rrc_ver_major=rrc_ver_major,
                         rrc_ver_minor=rrc_ver_minor,
                         radio_bearer_id=radio_bearer_id,
                         sib_mask=sib_mask)


def _try_decode_nas_tunneled(channel_name: str, msg_data: bytes) -> bytes | None:
    """Detect DCCH InformationTransfer + extract dedicatedInfoNAS bytes.

    Implements a minimal bit-pattern match:
    walk just enough UPER prefix to confirm the CHOICE path is
    DLInformationTransfer / ULInformationTransfer → dlInformationTransfer-r8
    / ulInformationTransfer-r8 → dedicatedInfoType=NAS, then read the
    DedicatedInfoNAS OCTET STRING length determinant and the payload bytes.

    Returns the dedicatedInfoNAS bytes on a successful match, or None for
    any other channel/message - including DCCH messages that aren't
    InformationTransfer (reconfig, security mode, capability info, etc.)
    and InformationTransfer records whose dedicatedInfoType is CDMA2000
    rather than NAS.

    Bit layout (per 3GPP TS 36.331 §6.2.2 + ITU-T X.691 UPER):

      DL-DCCH path (channel_type = 0x09):
        0    : DL-DCCH-MessageType outer CHOICE (0 = c1)
        1-4  : c1 inner CHOICE index (1 = dlInformationTransfer)
        5-6  : RRC-TransactionIdentifier (INTEGER(0..3))
        7    : DLInformationTransfer criticalExtensions CHOICE (0 = c1)
        8-10 : c1 inner CHOICE (0 = dlInformationTransfer-r8)
        11   : DLInformationTransfer-r8-IEs optional bitmap
               (1 bit, nonCriticalExtension presence - value is irrelevant
               because the optional field comes AFTER dedicatedInfoType in
               UPER encoding order)
        12-13: dedicatedInfoType CHOICE (3 alternatives, 2 bits;
               0 = dedicatedInfoNAS, 1/2 = CDMA2000 variants)
        14+  : DedicatedInfoNAS OCTET STRING (length determinant + bytes)

      UL-DCCH path (channel_type = 0x0B): same shape, but
        - no RRC-TransactionIdentifier (saves 2 bits)
        - ULInformationTransfer-r8-IEs has NO optional fields (saves 1 bit)
        - effective offset to dedicatedInfoType is bit 9 vs. bit 12 on DL

    The length determinant of an unconstrained OCTET STRING is the
    standard UPER length form (X.691 §10.9.3.6):
        0xxxxxxx                - 7-bit length (0..127)
        10xxxxxx xxxxxxxx       - 14-bit length (128..16383)
        11xxxxxx                - fragmented (16384+; not currently observed)
    Decoded via ``asn1_helpers.read_open_type_length``, which handles
    all three forms; the fragmented branch is summed per X.691 §11.9.
    """
    if not msg_data:
        return None
    # Gate on the canonical channel NAME, not the raw integer: the DCCH
    # channel_type value differs per wire version (v15 DL-DCCH=7/UL-DCCH=9 vs
    # v26/v27 DL-DCCH=9/UL-DCCH=11 vs the legacy 0x09/0x0B).
    if channel_name not in ("DL-DCCH", "UL-DCCH"):
        return None

    r = UperReader(msg_data)
    try:
        if channel_name == "DL-DCCH":
            if r.read_bits(1) != 0:
                return None  # messageClassExtension, not c1
            if r.read_bits(4) != 1:
                return None  # not dlInformationTransfer
            r.read_bits(2)  # rrc-TransactionIdentifier (don't care, 0..3)
            if r.read_bits(1) != 0:
                return None  # criticalExtensionsFuture
            if r.read_bits(3) != 0:
                return None  # spare1..7 instead of dlInformationTransfer-r8
            r.read_bits(1)  # nonCriticalExtension OPTIONAL flag - see docstring
            if r.read_bits(2) != 0:
                return None  # CDMA2000 variant, not NAS
        else:
            if r.read_bits(1) != 0:
                return None
            if r.read_bits(4) != 9:
                return None  # not ulInformationTransfer
            if r.read_bits(1) != 0:
                return None
            if r.read_bits(3) != 0:
                return None
            if r.read_bits(2) != 0:
                return None

        # Open-type length determinant via toolkit - handles the
        # 7-bit / 14-bit / fragmented forms per X.691 §11.9.
        nas_len = read_open_type_length(r)

        if nas_len == 0:
            return b""

        nas_bytes = bytearray(nas_len)
        for i in range(nas_len):
            nas_bytes[i] = r.read_bits(8)
        return bytes(nas_bytes)
    except (IndexError, ValueError):
        return None


def _build_result(
    log_time: int, version: int, rrc_release: int, channel_type: int,
    channel_name: str, pci: int, earfcn: int, sfn: int, subfn: int,
    pdu_number: int, msg_length: int, msg_data: bytes, raw_data: bytes,
    rrc_ver_major: int | None = None,
    rrc_ver_minor: int | None = None,
    radio_bearer_id: int | None = None,
    sib_mask: int | None = None,
) -> Diag0xB0C0:
    """Build Diag0xB0C0 with optional SIB1 auto-decode."""
    # Derive the SIB-number list from the sib_mask bits (bit N = SIBN;
    # bit0 unused). Empty when sib_mask is 0 or None (see the sib_mask field
    # docstring: an empty list does not prove the SI carries no SIBs).
    sibs_present: list[int] = (
        [n for n in range(1, 32) if sib_mask & (1 << n)]
        if sib_mask else []
    )
    sib1_mcc = sib1_mnc = None
    sib1_tac = sib1_cell_id = None
    sib1_cell_barred = sib1_csg_indication = sib1_plmn_list = None
    # Trigger on the canonical channel NAME, not the raw integer: v20 encodes
    # BCCH-DL-SCH as byte[12]==2 (_V20_CHANNEL_NAMES) while the legacy/non-v20
    # path encodes it as 0x30 (_CHANNEL_NAMES). Keying on channel_name keeps SIB1
    # auto-decode correct across both enums.
    sib2_access = sib3_resel = sib4_neighbors = None
    sib5_inter_freq = sib6_neighbors = sib7_neighbors = sib16_time = None
    sib8_cdma_time = sib24_nr_resel = sib9_hnb = None
    if channel_name == "BCCH-DL-SCH" and msg_data:
        from diaggrok.parsers.lte_rrc_sib import decode_sib1_cell_access
        sib1 = decode_sib1_cell_access(msg_data)
        if sib1 and sib1.plmn_list:
            sib1_mcc = sib1.plmn_list[0].mcc
            sib1_mnc = sib1.plmn_list[0].mnc
            sib1_tac = sib1.tracking_area_code
            sib1_cell_id = sib1.cell_identity
            # SIB1 flags + the full PLMN list. cellBarred
            # and csg-Indication are booleans decode_sib1_cell_access already read;
            # the PLMN list beyond [0] identifies MOCN/RAN-shared operators.
            sib1_cell_barred = sib1.cell_barred
            sib1_csg_indication = sib1.csg_indication
            sib1_plmn_list = [{"mcc": p.mcc, "mnc": p.mnc} for p in sib1.plmn_list]
        else:
            # Not a SIB1 → walk the SystemInformation container ONCE for
            # SIB2 + SIB3 + SIB4 + SIB5 + SIB6 + SIB7 + SIB8 + SIB9 + SIB16 +
            # SIB24. decode_si_sibs self-gates
            # (returns None unless it's an SI message carrying a target SIB),
            # so this never mis-fires on SIB1 / other SIBs.
            from diaggrok.parsers.lte_rrc_sib_time import decode_si_sibs
            sibs = decode_si_sibs(msg_data)
            if sibs is not None:
                sib2_access = sibs.sib2
                sib3_resel = sibs.sib3
                sib4_neighbors = sibs.sib4
                sib5_inter_freq = sibs.sib5
                sib6_neighbors = sibs.sib6
                sib7_neighbors = sibs.sib7
                sib8_cdma_time = sibs.sib8
                sib9_hnb = sibs.sib9
                sib16_time = sibs.sib16
                sib24_nr_resel = sibs.sib24

    nas_bytes = _try_decode_nas_tunneled(channel_name, msg_data)
    nas_tunneled = nas_bytes is not None

    # measConfig / MeasurementReport auto-decode. Both decoders re-walk
    # the ASN.1 CHOICE bits themselves and self-gate (return None if the message
    # is not their target type), so dispatch keys on the SRB channel name alone -
    # RRCConnectionReconfiguration rides DL-DCCH, MeasurementReport rides UL-DCCH.
    # Mirrors the SIB1/NAS "decode-and-flatten" pattern above. Lazy import keeps
    # the hot path (PCCH/BCCH records, which never hit these branches) free of
    # the reconfig/meas-report module import cost.
    meas_objects: list[Any] = []
    meas_has_gap_config = False
    meas_s_measure: int | None = None
    meas_report_id: int | None = None
    meas_report_pcell_rsrp: float | None = None
    meas_report_pcell_rsrq: float | None = None
    meas_report_neighbors: list[Any] = []
    meas_config: Any = None
    if channel_name == "DL-DCCH" and msg_data:
        from diaggrok.parsers.lte_rrc_reconfig import (
            decode_rrc_reconfig_meas_config,
        )
        mc = decode_rrc_reconfig_meas_config(log_time, msg_data)
        meas_config = mc
        if mc is not None and mc.meas_objects:
            meas_objects = mc.meas_objects
            meas_has_gap_config = mc.has_gap_config
            meas_s_measure = mc.s_measure
    elif channel_name == "UL-DCCH" and msg_data:
        from diaggrok.parsers.lte_rrc_meas_report import (
            decode_measurement_report,
        )
        mr = decode_measurement_report(log_time, msg_data)
        if mr is not None:
            meas_report_id = mr.meas_id
            meas_report_pcell_rsrp = mr.pcell_rsrp
            meas_report_pcell_rsrq = mr.pcell_rsrq
            meas_report_neighbors = mr.neighbor_cells

    return Diag0xB0C0(
        log_time=log_time,
        version=version,
        rrc_release=rrc_release,
        channel_type=channel_type,
        channel_name=channel_name,
        pci=pci,
        earfcn=earfcn,
        sfn=sfn,
        subfn=subfn,
        pdu_number=pdu_number,
        msg_length=msg_length,
        msg_data=msg_data,
        radio_bearer_id=radio_bearer_id,
        sib_mask=sib_mask,
        sibs_present=sibs_present,
        rrc_ver_major=rrc_ver_major,
        rrc_ver_minor=rrc_ver_minor,
        sib1_mcc=sib1_mcc,
        sib1_mnc=sib1_mnc,
        sib1_tac=sib1_tac,
        sib1_cell_id=sib1_cell_id,
        sib1_cell_barred=sib1_cell_barred,
        sib1_csg_indication=sib1_csg_indication,
        sib1_plmn_list=sib1_plmn_list,
        nas_tunneled=nas_tunneled,
        dedicated_info_nas=nas_bytes,
        meas_objects=meas_objects,
        meas_has_gap_config=meas_has_gap_config,
        meas_s_measure=meas_s_measure,
        meas_report_id=meas_report_id,
        meas_report_pcell_rsrp=meas_report_pcell_rsrp,
        meas_report_pcell_rsrq=meas_report_pcell_rsrq,
        meas_report_neighbors=meas_report_neighbors,
        meas_config=meas_config,
        sib2_access=sib2_access,
        sib3_resel=sib3_resel,
        sib4_neighbors=sib4_neighbors,
        sib5_inter_freq=sib5_inter_freq,
        sib6_neighbors=sib6_neighbors,
        sib9_hnb=sib9_hnb,
        sib7_neighbors=sib7_neighbors,
        sib8_cdma_time=sib8_cdma_time,
        sib16_time=sib16_time,
        sib24_nr_resel=sib24_nr_resel,
    )
