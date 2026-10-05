"""NR5G RRC OTA message parser (0xB821).

NR RRC Over-The-Air message log — the NR equivalent of LTE's 0xB0C0.
Contains ASN.1 PER-encoded NR RRC messages (SIB1, RRC Setup/Reconfiguration,
measurement reports, etc.).

Header layout follows SCAT's ``diagnrlogparser.parse_nr_rrc`` (used as a
validation reference only). byte[5] is ``rrc_rel_min`` (release minor), not a
channel type; the channel discriminator is ``pdu_id`` at a version-keyed
offset (byte[17] on v9, byte[16] on v12/v14, byte[24] on v17+).

Version 9 layout (SDX55 / RM500Q, Rel-15):
    [0:4]   u32  version (9)
    [4]     u8   rrc_release (15)         (SCAT: rrc_rel_maj)
    [5]     u8   rrc_rel_min              (not a channel type)
    [6]     u8   bearer_id                (SCAT: rbid)
    [7:9]   u16  physical_cell_id
    [9:13]  u32  nr_arfcn
    [13:17] u32  sfn_subfn (LE u32; low 16 bits encode sfn<<4|slot)
    [17]    u8   pdu_id                   (channel discriminator)
    [18:22] u32  sib_mask
    [22:24] u16  msg_length
    [24:]   bytes msg_data

Version 12 / 14 layout (SDX55 EM9190, SDX62 RM520N v14):
    Same as v9 but sfn_subfn is 3 bytes ([13:16]) and pdu_id shifts to
    byte[16]. sib_mask at [17:21] (4 bytes), msg_length at [21:23],
    msg_data starts at offset 23.

Version 17 layout (SDX62 RM520N, Rel-16):
    [0:4]   u32  version (17)
    [4]     u8   rrc_release (16)
    [5]     u8   rrc_rel_min
    [6]     u8   bearer_id
    [7:9]   u16  physical_cell_id
    [9:17]  u64  cell_global_id (60-bit NCGI of the camped serving cell:
                  PLMN-Identity in the high 24 bits, 36-bit NCI in the low
                  bits — see decode_ncgi; SCAT decodes it as a bitstring)
    [17:21] u32  nr_arfcn
    [21:24] u24  sfn_subfn (3 bytes)
    [24]    u8   pdu_id                   (channel discriminator)
    [25:29] u32  sib_mask
    [29:31] u16  msg_length
    [31:]   bytes msg_data

Version 26 layout (SDX72 RG650V, Rel-17):
    Same as v17 through msg_length, plus 4 reserved bytes inserted between
    msg_length and msg_data — header grows 31→35. Observed at zero across
    the v26 corpus; SCAT's v23/v24/v26 struct exposes them as
    ``unk1/unk2/unk3/segment_id`` (RRC segmentation — segment_id values 1-7
    indicate a chunked PDU). Treated as opaque here.

Version 7 (early Rel-15) is not declared: no capture in the corpus carries
pkt_ver 7, so it has no ground truth, and a v7 record returns None (registry
WARN + tally). For re-admission against a real capture: four records rendered
by a vendor decoder put v7 at the v9 byte positions (24-byte header,
msg_length at offset 22, pdu_id at byte[17]) with byte[5] (``rrc_rel_min``)
constant 0x41; their pdu_id matches the v9 map for BCCH-BCH (1) and
RRC-RECONF-COMPLETE (10) but a RADIO_BEARER_CONFIG record carries the
unmapped 24, so the v7 channel discriminator appears to sit in the DLF outer
header rather than the payload. SCAT does not handle pkt_ver 7. Re-admitting
it means adding 7 back to the _HEADER_SIZE / offset tables (24 / 22 / 17 /
13 / 18), the rrc_type_map table (the v9 map) and the version enum.

Layout verified at 100% across 1,544+ DLF records spanning EM9190 (SDX55),
RM500Q (SDX55), RM520N-GL (SDX62), and RG650V (SDX72): ``header_size +
msg_length == record_size`` for every record. The byte[24] pdu_id reading is
asserted by tests against three independent v17 fixtures.

Log name: LOG_NR5G_RRC_OTA_MSG
Also known as: LOG_NR5G_RRC_OTA_PACKET, NR5G RRC OTA Packet
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any, Optional

from diaggrok.codes import LOG_NR5G_RRC_OTA_MSG
from diaggrok.registry import register
from diaggrok.parsers.nr5g_rrc_sib1_uper import decode_nr_sib1_uper
from diaggrok.parsers.nr5g_rrc_si import decode_nr_si
from diaggrok.parsers.nr5g_rrc_sib_decode import decode_sib2, decode_sib4, decode_sib5
from diaggrok.parsers.uper import UperReader
from diaggrok.parsers.nr5g_rrc_mib import decode_nr_mib
from diaggrok.parsers.nr5g_rrc_smc import decode_nr_security_mode_command
from diaggrok.parsers.nr5g_rrc_dlccch import decode_nr_dl_ccch
from diaggrok.parsers.nr5g_rrc_release import decode_nr_rrc_release
from diaggrok.parsers.nr5g_rrc_reconfig_complete import (
    decode_nr_rrc_reconfig_complete,
    decode_nr_rrc_reconfig_complete_direct,
)
from diaggrok.parsers.nr5g_rrc_paging import decode_nr_paging
from diaggrok.parsers.nr5g_rrc_ulccch import decode_nr_ul_ccch, decode_nr_ul_ccch1
from diaggrok.parsers.nr5g_rrc_meas_report import decode_nr_measurement_report
from diaggrok.parsers.nr5g_rrc_reconfig import (
    decode_nr_meas_config,
    decode_nr_meas_config_direct,
)

# Per-version header sizes (bytes from start of payload to start of msg_data).
# v23 (0x17, SDX72 T99W640) shares the v26 layout exactly (NCGI-inserted, 35B
# header) — confirmed 86/86 corpus records by header_size + msg_length == len.
# It differs from v26 only in the channel map (no RRC-RECONF shift).
_HEADER_SIZE = {9: 24, 12: 23, 14: 23, 17: 31, 23: 35, 26: 35}
# Per-version offset of msg_length u16 LE.
_MSG_LEN_OFFSET = {9: 22, 12: 21, 14: 21, 17: 29, 23: 29, 26: 29}
# Per-version offset of pdu_id u8 (the channel discriminator). v9-shape
# layouts put pdu_id directly after the 4-byte sfn_subfn; v12/v14 trim
# sfn_subfn to 3 bytes; v17+ insert NCGI before nr_arfcn and use a 3-byte
# sfn_subfn.
_PDU_ID_OFFSET = {9: 17, 12: 16, 14: 16, 17: 24, 23: 24, 26: 24}
# Per-version offset of sfn_subfn (u16-LE for the low 16 bits → sfn<<4|slot).
_SFN_SUBFN_OFFSET = {9: 13, 12: 13, 14: 13, 17: 21, 23: 21, 26: 21}
# Per-version offset of sib_mask u32 LE.
_SIB_MASK_OFFSET = {9: 18, 12: 17, 14: 17, 17: 25, 23: 25, 26: 25}

# SCAT's pdu_id → channel name maps, keyed by parser version. Five distinct
# tables in SCAT (rrc_type_map for pkt_ver in 0x09/0x0c, 0x0e, 0x11/0x13,
# 0x14/0x17/0x18, 0x1a). The maps differ: pdu_id=5 is PCCH on
# 0x09/0x0c/0x0e/0x11/0x13 but MCCH on 0x14/0x17/0x18/0x1a; PCCH shifts to 6
# in the latter group. v26 (0x1a) also shifts RRC-RECONF/RRC-RECONF-COMPLETE
# from 9/10 to 11/12.
_RRC_TYPE_MAP_PRE_MCCH = {
    1: 'BCCH-BCH', 2: 'BCCH-DL-SCH', 3: 'DL-CCCH', 4: 'DL-DCCH',
    5: 'PCCH', 6: 'UL-CCCH', 7: 'UL-CCCH1', 8: 'UL-DCCH',
    9: 'RRC-RECONF', 10: 'RRC-RECONF-COMPLETE',
}
_RRC_TYPE_MAP_V26 = {
    1: 'BCCH-BCH', 2: 'BCCH-DL-SCH', 3: 'DL-CCCH', 4: 'DL-DCCH',
    5: 'MCCH', 6: 'PCCH', 7: 'UL-CCCH', 8: 'UL-CCCH1', 9: 'UL-DCCH',
    11: 'RRC-RECONF', 12: 'RRC-RECONF-COMPLETE',
}
# 0x14/0x17/0x18 group (v23 = 0x17, SDX72): same MCCH insertion as v26
# (MCCH@5, PCCH@6, shifting the DL/UL channels by +1 vs the pre-MCCH group),
# but WITHOUT the v26 RRC-RECONF/COMPLETE shift to 11/12 (existing behavioral
# note above). The corpus exercises pdu_id {1,2,6} here → BCCH-BCH /
# BCCH-DL-SCH / PCCH; pdu_id 7-9 follow the same MCCH-shifted order as v26.
# RRC-RECONF/COMPLETE position is not yet corpus-grounded for this group (no
# pdu_id>=10 records observed) — deliberately omitted so an unmapped pdu_id
# renders the empty unmapped signal rather than a guessed label.
_RRC_TYPE_MAP_MCCH_NOSHIFT = {
    1: 'BCCH-BCH', 2: 'BCCH-DL-SCH', 3: 'DL-CCCH', 4: 'DL-DCCH',
    5: 'MCCH', 6: 'PCCH', 7: 'UL-CCCH', 8: 'UL-CCCH1', 9: 'UL-DCCH',
}
# Parser-version → rrc_type_map. v7 piggybacks on v9 (SCAT does not parse
# pkt_ver=7). v7 is not declared — _HEADER_SIZE rejects it before this map is
# consulted — but its key stays here because the map is mirrored in a shared
# enrichment table that is checked for parity with this one.
_RRC_TYPE_MAPS = {
    7: _RRC_TYPE_MAP_PRE_MCCH,
    9: _RRC_TYPE_MAP_PRE_MCCH,
    12: _RRC_TYPE_MAP_PRE_MCCH,
    14: _RRC_TYPE_MAP_PRE_MCCH,
    17: _RRC_TYPE_MAP_PRE_MCCH,
    23: _RRC_TYPE_MAP_MCCH_NOSHIFT,
    26: _RRC_TYPE_MAP_V26,
}


# Standalone SIB records. Some firmware logs each SIB it
# acquires as its own 0xB821 record — the bare SIB SEQUENCE, with no
# BCCH-DL-SCH / systemInformation wrapper — on a pdu_id outside SCAT's channel
# map. Proven per version from the wire: each standalone payload is a
# bit-substring of a same-capture systemInformation message, and the 4 bits
# before it are the sib-TypeAndInfo CHOICE tag naming the SIB (sib2=000,
# sib4=010, sib5=011); the standalone decode equals the SI-container decode of
# the same cell object-for-object. The numbering DIFFERS between v12 and v17
# although they share a channel map (SIB2 is 14 on v12, 15 on v17), so these
# are per-version. Only tag-proven ids are listed; the interpolated SIB3 slots
# were never observed and stay unmapped (the empty unmapped signal rather than
# a guessed label, as for the v23 RRC-RECONF position above).
# v23 19/21 are proven on T99W640 captures with same-cell SI: each 19 payload
# sits behind the sib2 tag and each 21
# payload behind the sib4 tag (a same-capture match on PCI 260 / 501390, and
# PCI 596 on both 501390 and 521310), and all 4+4 with a matching SI decode
# equal it object-for-object. v23 numbering is v17's plus 4.
_STANDALONE_SIB_PDU_IDS: dict[int, dict[int, str]] = {
    12: {14: 'SIB2', 16: 'SIB4', 17: 'SIB5'},
    17: {15: 'SIB2', 17: 'SIB4', 18: 'SIB5'},
    23: {19: 'SIB2', 21: 'SIB4', 22: 'SIB5'},
}


def pkt_ver_to_channel_name(pkt_ver: int, pdu_id: int) -> str:
    """Resolve (pkt_ver, pdu_id) → 3GPP TS 38.331 channel name.

    Returns the channel-class name (``BCCH-BCH`` / ``BCCH-DL-SCH`` / ``DL-CCCH``
    / ``DL-DCCH`` / ``PCCH`` / etc.) per SCAT's pkt_ver-keyed rrc_type_map
    tables. Returns an empty string when pkt_ver is unsupported or pdu_id is
    outside the map for that version — callers must treat empty as the
    unmapped signal (the parser does this in ``channel_name``).
    """
    rrc_map = _RRC_TYPE_MAPS.get(pkt_ver)
    if rrc_map is None:
        return ""
    return (rrc_map.get(pdu_id, "")
            or _STANDALONE_SIB_PDU_IDS.get(pkt_ver, {}).get(pdu_id, ""))


# Per-channel inner-c1 CHOICE width in bits, as defined by 3GPP TS 38.331.
# The outer ``<Channel>-MessageType`` CHOICE is always 1 bit (c1 vs
# messageClassExtension). The c1 alternative-count differs per channel:
#   BCCH-BCH     → outer CHOICE has just (mib, messageClassExtension),
#                  no inner c1 wrapper; treat as a special case.
#   BCCH-DL-SCH.c1   → 2 alternatives → 1 bit
#   DL-CCCH.c1       → 4 alternatives → 2 bits
#   DL-DCCH.c1       → 16 alternatives → 4 bits
#   PCCH.c1          → 2 alternatives (paging, spare1) → 1 bit
#   UL-CCCH.c1       → 4 alternatives → 2 bits
#   UL-CCCH1.c1      → 4 alternatives (rrcResumeRequest1, spare3..spare1) → 2 bits
#                      (confirmed against 38.331 v17.17.0 + stock tshark
#                      nr-rrc.ul.ccch1)
#   UL-DCCH.c1       → 16 alternatives → 4 bits
_C1_CHOICE_BITS = {
    'BCCH-DL-SCH': 1,
    'DL-CCCH': 2,
    'DL-DCCH': 4,
    'PCCH': 1,
    'UL-CCCH': 2,
    'UL-CCCH1': 2,
    'UL-DCCH': 4,
}

# NrUlCcch attribute names copied onto Diag0xB821 as ``ul_ccch_<name>`` by the
# UL-CCCH / UL-CCCH1 dispatch (message_type is handled separately: it is the
# presence key). One list for both the copy and to_dict so they cannot drift.
_UL_CCCH_FIELDS = (
    'ue_identity_type', 'ue_identity_value', 'establishment_cause',
    'resume_identity_type', 'resume_identity', 'resume_mac_i', 'resume_cause',
    'reestab_c_rnti', 'reestab_phys_cell_id', 'reestab_short_mac_i',
    'reestablishment_cause', 'si_request_kind', 'requested_si_list',
)

# (channel_name, c1_index) → 3GPP TS 38.331 message class name. DL-DCCH /
# DL-CCCH / BCCH-DL-SCH validated against pycrate's NR_RRC_Definitions
# (pycrate is validation-only, never runtime). There is no separate
# "DL-DCCH-r17" family: byte[5] is not a channel discriminator, so all
# DL-DCCH messages share this table.
_MSG_CLASS_NAMES: dict[tuple[str, int], str] = {
    # BCCH-DL-SCH (1-bit c1)
    ('BCCH-DL-SCH', 0): 'systemInformation',
    ('BCCH-DL-SCH', 1): 'systemInformationBlockType1',
    # PCCH (1-bit c1)
    ('PCCH', 0): 'paging',
    ('PCCH', 1): 'spare1',
    # DL-CCCH (2-bit c1)
    ('DL-CCCH', 0): 'rrcReject',
    ('DL-CCCH', 1): 'rrcSetup',
    ('DL-CCCH', 2): 'spare2',
    ('DL-CCCH', 3): 'spare1',
    # DL-DCCH (4-bit c1)
    ('DL-DCCH', 0): 'rrcReconfiguration',
    ('DL-DCCH', 1): 'rrcResume',
    ('DL-DCCH', 2): 'rrcRelease',
    ('DL-DCCH', 3): 'rrcReestablishment',
    ('DL-DCCH', 4): 'securityModeCommand',
    ('DL-DCCH', 5): 'dlInformationTransfer',
    ('DL-DCCH', 6): 'ueCapabilityEnquiry',
    ('DL-DCCH', 7): 'counterCheck',
    ('DL-DCCH', 8): 'mobilityFromNRCommand',
    ('DL-DCCH', 9): 'dlDedicatedMessageSegment-r16',
    ('DL-DCCH', 10): 'ueInformationRequest-r16',
    ('DL-DCCH', 11): 'dlInformationTransferMRDC-r16',
    ('DL-DCCH', 12): 'loggedMeasurementConfiguration-r16',
    ('DL-DCCH', 13): 'spare3',
    ('DL-DCCH', 14): 'spare2',
    ('DL-DCCH', 15): 'spare1',
    # UL-CCCH (2-bit c1) per 38.331 v16
    ('UL-CCCH', 0): 'rrcSetupRequest',
    ('UL-CCCH', 1): 'rrcResumeRequest',
    ('UL-CCCH', 2): 'rrcReestablishmentRequest',
    ('UL-CCCH', 3): 'rrcSystemInfoRequest',
    # UL-CCCH1 (2-bit c1)
    ('UL-CCCH1', 0): 'rrcResumeRequest1',
    ('UL-CCCH1', 1): 'spare3',
    ('UL-CCCH1', 2): 'spare2',
    ('UL-CCCH1', 3): 'spare1',
    # UL-DCCH (4-bit c1)
    ('UL-DCCH', 0): 'measurementReport',
    ('UL-DCCH', 1): 'rrcReconfigurationComplete',
    ('UL-DCCH', 2): 'rrcSetupComplete',
    ('UL-DCCH', 3): 'rrcReestablishmentComplete',
    ('UL-DCCH', 4): 'rrcResumeComplete',
    ('UL-DCCH', 5): 'securityModeComplete',
    ('UL-DCCH', 6): 'securityModeFailure',
    ('UL-DCCH', 7): 'ulInformationTransfer',
    ('UL-DCCH', 8): 'locationMeasurementIndication',
    ('UL-DCCH', 9): 'ueCapabilityInformation',
    ('UL-DCCH', 10): 'counterCheckResponse',
    ('UL-DCCH', 11): 'ueAssistanceInformation',
    ('UL-DCCH', 12): 'failureInformation',
    ('UL-DCCH', 13): 'ulInformationTransferMRDC',
    ('UL-DCCH', 14): 'scgFailureInformation',
    ('UL-DCCH', 15): 'scgFailureInformationEUTRA',
}


def decode_ncgi(cell_global_id: Optional[int]) -> Optional[tuple[str, str, int]]:
    """Decode a v17+ ``cell_global_id`` into (mcc, mnc, nci).

    The 60-bit NR Cell Global Identity (NCGI, 3GPP TS 38.413) packs a
    24-bit PLMN-Identity in the high bits and the 36-bit NR Cell Identity
    (NCI) in the low bits::

        bits [59:36]  PLMN-Identity (3 octets, TS 24.008 §10.5.1.3 BCD)
        bits [35: 0]  NR Cell Identity (36-bit NCI)

    The PLMN octets are nibble-swapped BCD: octet1 = MCC2<<4|MCC1,
    octet2 = MNC3<<4|MCC3, octet3 = MNC2<<4|MNC1 (MNC3 == 0xF ⇒ 2-digit MNC).

    Returns ``None`` for a zero/absent id or when the PLMN nibbles are not
    valid BCD digits (so an unexpected layout yields no fabricated PLMN
    rather than garbage). Verified against SCAT and an AT network scan on
    RM520N-GL SDX62: cgi 0x130184087eac028 →
    MCC 311 / MNC 480 / NCI 0x087EAC028 (Verizon n5).
    """
    if not cell_global_id:
        return None
    nci = cell_global_id & 0xFFFFFFFFF
    plmn = (cell_global_id >> 36) & 0xFFFFFF
    o1 = (plmn >> 16) & 0xFF
    o2 = (plmn >> 8) & 0xFF
    o3 = plmn & 0xFF
    mcc1, mcc2 = o1 & 0xF, o1 >> 4
    mcc3, mnc3 = o2 & 0xF, o2 >> 4
    mnc1, mnc2 = o3 & 0xF, o3 >> 4
    if any(d > 9 for d in (mcc1, mcc2, mcc3, mnc1, mnc2)):
        return None
    if mnc3 != 0xF and mnc3 > 9:
        return None
    mcc = f"{mcc1}{mcc2}{mcc3}"
    mnc = f"{mnc1}{mnc2}" if mnc3 == 0xF else f"{mnc1}{mnc2}{mnc3}"
    return mcc, mnc, nci


@dataclass
class Diag0xB821:
    """Parsed NR5G RRC OTA message."""
    log_time: int
    version: int
    rrc_release: int                # byte[4], SCAT rrc_rel_maj
    rrc_rel_min: int                # byte[5], release minor (not a channel type)
    bearer_id: int                  # SCAT rbid
    pci: int
    arfcn: int
    sfn: int
    slot: int
    # Full-width sfn_subfn field (4 bytes on v7/v9, 3 bytes on v12/v14/v17+).
    # sfn/slot are the low 16 bits (sfn<<4|slot); the upper byte(s) are LIVE,
    # not reserved (non-zero in 6/12 fixtures; SCAT derives subframe/slot
    # from them). Exposed raw so no on-wire byte is discarded.
    sfn_subfn_raw: int
    pdu_id: int                     # actual channel discriminator
    sib_mask: int                   # 4-byte u32 sib_mask
    msg_length: int
    msg_data: bytes                 # raw ASN.1 PER-encoded NR RRC message
    # v17+ only: 60-bit NR Cell Global Identity (NCGI) inserted between
    # bearer_id and arfcn — the CAMPED serving cell's identity, stamped onto
    # every record (constant across a camp, NOT per-record/per-neighbour).
    # Decomposes as PLMN-Identity (high 24 bits, BCD) + NR Cell Identity
    # (low 36 bits); see decode_ncgi(). None on v7/v9/v12/v14. A value that
    # repeats across records (e.g. 0x01300621 in the upper word) is one
    # operator's PLMN + NCI prefix, not a format constant.
    cell_global_id: Optional[int] = None
    # NCGI decode: camped serving PLMN + NCI from cell_global_id.
    ncgi_mcc: str = ""
    ncgi_mnc: str = ""
    ncgi_nci: Optional[int] = None
    # Channel-class label resolved from (version, pdu_id) via SCAT's
    # pkt_ver-keyed rrc_type_map. Empty when pdu_id is unmapped — downstream
    # tooling treats empty as the unmapped signal.
    channel_name: str = ""
    # ASN.1 c1 CHOICE index decoded from the leading bits of msg_data. None
    # when channel has no c1 (BCCH-BCH), msg_data is empty, or the outer
    # CHOICE selects messageClassExtension.
    msg_class_index: Optional[int] = None
    # 3GPP TS 38.331 message-class name resolved from (channel_name,
    # msg_class_index) via _MSG_CLASS_NAMES, or the special "mib" string on
    # BCCH-BCH outer=0 (no inner c1).
    msg_class_name: str = ""
    # SIB1 cell identity (auto-decoded when channel_name == 'BCCH-DL-SCH')
    sib1_mcc: str = ""
    sib1_mnc: str = ""
    sib1_tac: Optional[int] = None
    sib1_cell_id: Optional[int] = None
    # False when SIB1's OPTIONAL trackingAreaCode is absent (an NSA-only,
    # PSCell/SCell-only cell): sib1_tac is then 0 by convention, not a TAC.
    sib1_tac_present: Optional[bool] = None
    # SIB1 servingCellConfigCommon headline fields: first DL
    # freqBandIndicatorNR, first DL scs-SpecificCarrier SCS + carrierBandwidth,
    # and the TS 38.101 channel bandwidth they imply. Pinned to stock tshark.
    sib1_band: Optional[int] = None
    sib1_scs_khz: Optional[int] = None
    sib1_carrier_bandwidth_prb: Optional[int] = None
    sib1_channel_bandwidth_mhz: Optional[int] = None
    # SI-container walk of a BCCH-DL-SCH systemInformation message
    # (via nr5g_rrc_si.decode_nr_si): declared sib-TypeAndInfo size + the
    # tag sequence walked ('sib2'..'sib9'), in order. Empty/None on non-SI
    # records and on SI records whose criticalExtensions selects the r16
    # future branch. The observed corpus carries exactly two layouts —
    # [sib2,sib4,sib5] and [sib2,sib4,sib5,sib9] — tshark-verified 225/225.
    si_sib_count: Optional[int] = None
    si_sib_tags: list[str] = field(default_factory=list)
    # NR SIB2 serving-cell reselection parameters —
    # NrSib2 from nr5g_rrc_sib_decode.decode_sib2. None when no sib2 decoded.
    sib2_params: Optional[Any] = None
    # NR SIB4 inter-frequency neighbour carriers — NrSib4
    # from decode_sib4; carriers each carry dl_carrier_freq (NR ARFCN),
    # freq_band_list, reselection thresholds and any interFreqNeighCellList
    # PCIs. None when no sib4 decoded.
    sib4_params: Optional[Any] = None
    # NR SIB5 inter-RAT EUTRA neighbour carriers — NrSib5
    # from decode_sib5; carriers each carry carrier_freq (EUTRA EARFCN),
    # reselection thresholds and any eutra-FreqNeighCellList PCIs. None when
    # no sib5 decoded.
    sib5_params: Optional[Any] = None
    # NR SIB9 network time — decoded by the walker when the
    # SI message carries sib9 (rides LAST behind sib2/sib4/sib5 in the
    # observed corpus). timeInfoUTC raw value is 10 ms units since
    # 1900-01-01 00:00:00 UTC (TS 38.331 semantics, wall-clock-validated).
    sib9_time_info_utc: Optional[int] = None
    sib9_utc_iso: str = ""
    sib9_leap_seconds: Optional[int] = None
    sib9_dst: Optional[int] = None
    sib9_local_time_offset: Optional[int] = None
    # MIB PHY/access config (auto-decoded when channel_name == 'BCCH-BCH' and
    # the outer CHOICE selects mib). 3GPP TS 38.331 MasterInformationBlock.
    mib_scs_common: str = ""           # 'scs15or60' | 'scs30or120'
    mib_ssb_subcarrier_offset: Optional[int] = None
    mib_dmrs_typeA_position: str = ""  # 'pos2' | 'pos3'
    mib_coreset0: Optional[int] = None
    mib_searchspace0: Optional[int] = None
    mib_cell_barred: str = ""          # 'barred' | 'notBarred'
    mib_intra_freq_reselection: str = ""  # 'allowed' | 'notAllowed'
    mib_sfn_msb: Optional[int] = None  # 6 MSBs of the 10-bit SFN
    # SecurityModeCommand AS-security algorithms (auto-decoded when
    # channel_name == 'DL-DCCH' and the c1 index resolves to
    # securityModeCommand). 3GPP TS 38.331 §6.3.2 SecurityAlgorithmConfig.
    smc_rrc_transaction_id: Optional[int] = None
    smc_ciphering_algorithm: Optional[int] = None
    smc_ciphering_algorithm_name: str = ""       # 'nea0'..'nea3' | spare
    smc_integrity_prot_algorithm: Optional[int] = None
    smc_integrity_prot_algorithm_name: str = ""  # 'nia0'..'nia3' | spare
    # NR DL-CCCH message: auto-decoded when channel_name == 'DL-CCCH'
    # and the c1 index resolves to rrcSetup / rrcReject. Decoded by
    # nr5g_rrc_dlccch.decode_nr_dl_ccch (3GPP TS 38.331 6.2.2). These are the
    # RRC connection-establishment messages a gNB sends before an SRB1/DCCH
    # exists. dl_ccch_message_type is 'rrcSetup' | 'rrcReject';
    # dl_ccch_rrc_transaction_identifier is the rrcSetup leading scalar (the
    # RadioBearerConfig + masterCellGroup CellGroupConfig bodies are heavy and
    # intentionally left structural); dl_ccch_wait_time is the rrcReject
    # RejectWaitTime seconds (INTEGER 1..16). All None/"" on non-DL-CCCH records.
    dl_ccch_message_type: str = ""
    dl_ccch_rrc_transaction_identifier: Optional[int] = None
    dl_ccch_wait_time: Optional[int] = None
    # NR MeasurementReport — auto-decoded when channel_name == 'UL-DCCH'
    # and the c1 index resolves to measurementReport. Decoded by
    # nr5g_rrc_meas_report.decode_nr_measurement_report (3GPP TS 38.331 §6.2.2).
    # meas_report_id is the measId; serving_* are the serving-cell results
    # (any of RSRP dBm / RSRQ dB / SINR dB may be absent → None);
    # meas_report_neighbors is the list of NrMeasResultCell. None/empty when the
    # record is not a MeasurementReport or fails to decode.
    meas_report_id: Optional[int] = None
    meas_report_serving_rsrp: Optional[float] = None
    meas_report_serving_rsrq: Optional[float] = None
    meas_report_serving_sinr: Optional[float] = None
    meas_report_neighbors: list[Any] = field(default_factory=list)
    # NR measConfig. Auto-decoded when the c1 index
    # resolves to rrcReconfiguration on the DL-DCCH channel (via
    # nr5g_rrc_reconfig.decode_nr_meas_config) or on the firmware-direct
    # RRC-RECONF channel (via decode_nr_meas_config_direct). 3GPP TS 38.331
    # §6.2.2. The radioBearerConfig is skipped structurally and the
    # RRC-RECONF bare-SEQUENCE framing is handled, so this populates on the
    # real corpus (validated field-for-field against pycrate: DL-DCCH 124/124,
    # RRC-RECONF 23/23). meas_objects holds MeasObjectNR entries; meas_eutra_objects holds
    # inter-RAT MeasObjectEUTRA; meas_s_measure_ssb / _csi are the SSB/CSI-RSRP
    # thresholds.
    meas_objects: list[Any] = field(default_factory=list)
    meas_eutra_objects: list[Any] = field(default_factory=list)
    meas_s_measure_ssb: Optional[int] = None
    meas_s_measure_csi: Optional[int] = None
    # NR PCCH Paging — auto-decoded when channel_name == 'PCCH' and the
    # c1 index resolves to paging. Decoded by nr5g_rrc_paging.decode_nr_paging
    # (3GPP TS 38.331 6.2.2). paging_record_count is the PagingRecordList length
    # (INTEGER 1..32); paging_records is the list of NrPagingRecord, each
    # carrying a ng-5G-S-TMSI (with its TS 23.003 amf_set_id / amf_pointer /
    # five_g_tmsi decomposition) or a fullI-RNTI. None/empty on non-paging
    # records. These are the temporary UE identities a gNB pages in idle mode.
    paging_record_count: Optional[int] = None
    paging_records: list[Any] = field(default_factory=list)

    # NR DL-DCCH RRCRelease redirect — auto-decoded when channel_name
    # == 'DL-DCCH' and the c1 index resolves to rrcRelease. Decoded by
    # nr5g_rrc_release.decode_nr_rrc_release (3GPP TS 38.331 6.2.2). The
    # redirect_* fields describe redirectedCarrierInfo — the carrier the gNB
    # is pushing the UE onto at connection teardown: redirect_rat is 'nr' or
    # 'eutra'; redirect_arfcn is the target NR ARFCN or E-UTRA EARFCN;
    # redirect_scs_khz is the SSB subcarrier spacing (NR redirect only);
    # redirect_cn_type is 'epc'/'fiveGC' (EUTRA redirect only). The release_
    # suspend_* fields carry the suspendConfig (RRC-Inactive) resume config:
    # full_i_rnti / short_i_rnti are the 40-bit / 24-bit resume identities,
    # ran_paging_cycle the RAN paging cycle, next_hop_chaining_count the security
    # counter (decoded when both preceding OPTIONALs are absent). All None when
    # the record is not an rrcRelease or the field is absent.
    release_rrc_transaction_identifier: Optional[int] = None
    release_redirect_rat: Optional[str] = None
    release_redirect_arfcn: Optional[int] = None
    release_redirect_scs_khz: Optional[int] = None
    release_redirect_cn_type: Optional[str] = None
    release_suspend_config: Optional[bool] = None
    release_suspend_full_i_rnti: Optional[int] = None
    release_suspend_short_i_rnti: Optional[int] = None
    release_suspend_ran_paging_cycle: Optional[str] = None
    release_suspend_next_hop_chaining_count: Optional[int] = None

    # NR UL-DCCH RRCReconfigurationComplete — auto-decoded when
    # channel_name == 'UL-DCCH' and the c1 index resolves to
    # rrcReconfigurationComplete. Decoded by
    # nr5g_rrc_reconfig_complete.decode_nr_rrc_reconfig_complete (3GPP TS 38.331
    # 6.2.2). reconfig_complete_transaction_id is the RRC-TransactionIdentifier
    # (INTEGER 0..3) — the handle that pairs this UE acknowledgement with the
    # gNB RRCReconfiguration carrying the same id, so a one-sided OTA capture can
    # be reassembled into a reconfiguration round-trip. None on non-Complete
    # records. Always present on a Complete (it precedes criticalExtensions and
    # is decoded on both the -IEs and criticalExtensionsFuture branches).
    reconfig_complete_transaction_id: Optional[int] = None

    # NR UL-CCCH / UL-CCCH1 — the UE's first RRC words on a cell
    # (SRB0), auto-decoded on those channels by nr5g_rrc_ulccch (3GPP TS 38.331
    # 6.2.1). ul_ccch_message_type names the c1 alternative and only that
    # alternative's fields are set: rrcSetupRequest → ue identity (39-bit
    # ng-5G-S-TMSI-Part1 or randomValue) + establishment cause (why the UE
    # connected: mt-Access after a page, mo-Data, emergency …); rrcResumeRequest
    # (shortI-RNTI) / rrcResumeRequest1 (UL-CCCH1, fullI-RNTI) → resume identity,
    # resumeMAC-I and resume cause (incl. rna-Update); rrcReestablishmentRequest →
    # C-RNTI + physCellId of the PCell the UE lost + shortMAC-I + cause
    # (handoverFailure / reconfigurationFailure / otherFailure);
    # rrcSystemInfoRequest → the on-demand SI messages requested (1-based).
    ul_ccch_message_type: str = ""
    ul_ccch_ue_identity_type: Optional[str] = None
    ul_ccch_ue_identity_value: Optional[int] = None
    ul_ccch_establishment_cause: Optional[str] = None
    ul_ccch_resume_identity_type: Optional[str] = None
    ul_ccch_resume_identity: Optional[int] = None
    ul_ccch_resume_mac_i: Optional[int] = None
    ul_ccch_resume_cause: Optional[str] = None
    ul_ccch_reestab_c_rnti: Optional[int] = None
    ul_ccch_reestab_phys_cell_id: Optional[int] = None
    ul_ccch_reestab_short_mac_i: Optional[int] = None
    ul_ccch_reestablishment_cause: Optional[str] = None
    ul_ccch_si_request_kind: Optional[str] = None
    ul_ccch_requested_si_list: Optional[list[int]] = None

    @property
    def channel_type(self) -> int:
        """Deprecated alias for ``rrc_rel_min`` (byte[5]).

        byte[5] was once exposed as ``channel_type`` and read as the channel
        discriminator; it is ``rrc_rel_min`` per SCAT's NR RRC OTA parser. New consumers should
        read ``rrc_rel_min`` (raw byte) or ``channel_name`` (resolved
        channel-class label) instead. Scheduled for removal once downstream
        callers have migrated.
        """
        return self.rrc_rel_min

    def to_dict(self) -> dict[str, Any]:
        d = {
            'type': 'Diag0xB821',
            'log_time': self.log_time,
            'version': self.version,
            'rrc_release': self.rrc_release,
            'rrc_rel_min': self.rrc_rel_min,
            # Deprecated alias for one release. Same value as
            # rrc_rel_min; will be removed once downstream consumers migrate.
            'channel_type': self.rrc_rel_min,
            'bearer_id': self.bearer_id,
            'pci': self.pci,
            'earfcn': self.arfcn,
            'arfcn': self.arfcn,
            'sfn': self.sfn,
            'slot': self.slot,
            'sfn_subfn_raw': self.sfn_subfn_raw,
            'pdu_id': self.pdu_id,
            'sib_mask': self.sib_mask,
            'msg_length': self.msg_length,
            'msg_bytes': self.msg_data.hex(),
        }
        if self.cell_global_id is not None:
            d['cell_global_id'] = self.cell_global_id
        if self.ncgi_nci is not None:
            d['ncgi_mcc'] = self.ncgi_mcc
            d['ncgi_mnc'] = self.ncgi_mnc
            d['ncgi_nci'] = self.ncgi_nci
            d['ncgi_nci_hex'] = f"{self.ncgi_nci:09X}"
        if self.channel_name:
            d['channel_name'] = self.channel_name
        if self.msg_class_index is not None:
            d['msg_class_index'] = self.msg_class_index
        if self.msg_class_name:
            d['msg_class_name'] = self.msg_class_name
        if self.sib1_tac is not None:
            d['sib1_mcc'] = self.sib1_mcc
            d['sib1_mnc'] = self.sib1_mnc
            d['sib1_tac'] = self.sib1_tac
            d['sib1_cell_id'] = self.sib1_cell_id
            if self.sib1_tac_present is False:
                d['sib1_tac_present'] = False
            for k in ('sib1_band', 'sib1_scs_khz', 'sib1_carrier_bandwidth_prb',
                      'sib1_channel_bandwidth_mhz'):
                v = getattr(self, k)
                if v is not None:
                    d[k] = v
        # SI-container walk + SIB2 params + SIB9 network time.
        if self.si_sib_count is not None:
            d['si_sib_count'] = self.si_sib_count
            d['si_sib_tags'] = self.si_sib_tags
        if self.sib2_params is not None:
            d['sib2_params'] = self.sib2_params.to_dict()
        if self.sib4_params is not None:
            d['sib4_params'] = self.sib4_params.to_dict()
        if self.sib5_params is not None:
            d['sib5_params'] = self.sib5_params.to_dict()
        if self.sib9_time_info_utc is not None:
            d['sib9_time_info_utc'] = self.sib9_time_info_utc
            if self.sib9_utc_iso:
                d['sib9_utc_iso'] = self.sib9_utc_iso
            if self.sib9_leap_seconds is not None:
                d['sib9_leap_seconds'] = self.sib9_leap_seconds
            if self.sib9_dst is not None:
                d['sib9_dst'] = self.sib9_dst
            if self.sib9_local_time_offset is not None:
                d['sib9_local_time_offset'] = self.sib9_local_time_offset
        if self.mib_scs_common:
            d['mib_scs_common'] = self.mib_scs_common
            d['mib_ssb_subcarrier_offset'] = self.mib_ssb_subcarrier_offset
            d['mib_dmrs_typeA_position'] = self.mib_dmrs_typeA_position
            d['mib_coreset0'] = self.mib_coreset0
            d['mib_searchspace0'] = self.mib_searchspace0
            d['mib_cell_barred'] = self.mib_cell_barred
            d['mib_intra_freq_reselection'] = self.mib_intra_freq_reselection
            d['mib_sfn_msb'] = self.mib_sfn_msb
        if self.smc_ciphering_algorithm is not None:
            d['smc_rrc_transaction_id'] = self.smc_rrc_transaction_id
            d['smc_ciphering_algorithm'] = self.smc_ciphering_algorithm
            d['smc_ciphering_algorithm_name'] = self.smc_ciphering_algorithm_name
            d['smc_integrity_prot_algorithm'] = self.smc_integrity_prot_algorithm
            d['smc_integrity_prot_algorithm_name'] = (
                self.smc_integrity_prot_algorithm_name)
        # NR DL-CCCH message: keyed on dl_ccch_message_type being set.
        if self.dl_ccch_message_type:
            d['dl_ccch_message_type'] = self.dl_ccch_message_type
            if self.dl_ccch_rrc_transaction_identifier is not None:
                d['dl_ccch_rrc_transaction_identifier'] = (
                    self.dl_ccch_rrc_transaction_identifier)
            if self.dl_ccch_wait_time is not None:
                d['dl_ccch_wait_time'] = self.dl_ccch_wait_time
        # NR DL-DCCH RRCRelease redirect — keyed on the redirect RAT or
        # the transaction id being set (an rrcRelease with no redirect still
        # surfaces its transaction id).
        if self.release_redirect_rat is not None:
            d['release_redirect_rat'] = self.release_redirect_rat
            if self.release_redirect_arfcn is not None:
                d['release_redirect_arfcn'] = self.release_redirect_arfcn
            if self.release_redirect_scs_khz is not None:
                d['release_redirect_scs_khz'] = self.release_redirect_scs_khz
            if self.release_redirect_cn_type is not None:
                d['release_redirect_cn_type'] = self.release_redirect_cn_type
        if self.release_suspend_config:
            d['release_suspend_config'] = self.release_suspend_config
            for k in ('release_suspend_full_i_rnti',
                      'release_suspend_short_i_rnti',
                      'release_suspend_ran_paging_cycle',
                      'release_suspend_next_hop_chaining_count'):
                v = getattr(self, k)
                if v is not None:
                    d[k] = v
        if self.release_rrc_transaction_identifier is not None:
            d['release_rrc_transaction_identifier'] = (
                self.release_rrc_transaction_identifier)
        # NR MeasurementReport — keyed on meas_report_id being set.
        if self.meas_report_id is not None:
            d['meas_report_id'] = self.meas_report_id
            if self.meas_report_serving_rsrp is not None:
                d['meas_report_serving_rsrp'] = self.meas_report_serving_rsrp
            if self.meas_report_serving_rsrq is not None:
                d['meas_report_serving_rsrq'] = self.meas_report_serving_rsrq
            if self.meas_report_serving_sinr is not None:
                d['meas_report_serving_sinr'] = self.meas_report_serving_sinr
            d['meas_report_neighbors'] = [
                c.to_dict() for c in self.meas_report_neighbors
            ]
        # NR measConfig — emit only when meas objects were extracted.
        if self.meas_objects:
            d['meas_objects'] = [m.to_dict() for m in self.meas_objects]
            if self.meas_eutra_objects:
                d['meas_eutra_objects'] = [
                    m.to_dict() for m in self.meas_eutra_objects
                ]
            if self.meas_s_measure_ssb is not None:
                d['meas_s_measure_ssb'] = self.meas_s_measure_ssb
            if self.meas_s_measure_csi is not None:
                d['meas_s_measure_csi'] = self.meas_s_measure_csi
        # NR PCCH Paging — keyed on paging_record_count being set.
        if self.paging_record_count is not None:
            d['paging_record_count'] = self.paging_record_count
            d['paging_records'] = [r.to_dict() for r in self.paging_records]
        # NR UL-DCCH RRCReconfigurationComplete — keyed on the
        # transaction id being set (always present on a Complete).
        if self.reconfig_complete_transaction_id is not None:
            d['reconfig_complete_transaction_id'] = (
                self.reconfig_complete_transaction_id)
        # NR UL-CCCH / UL-CCCH1 — keyed on ul_ccch_message_type.
        if self.ul_ccch_message_type:
            d['ul_ccch_message_type'] = self.ul_ccch_message_type
            for k in _UL_CCCH_FIELDS:
                v = getattr(self, 'ul_ccch_' + k)
                if v is not None:
                    d['ul_ccch_' + k] = v
        return d


def _decode_outer_choice(
    channel_name: str, msg_data: bytes,
) -> tuple[Optional[int], str]:
    """Decode the outer ASN.1 CHOICE + c1 index from msg_data.

    The outer envelope on every RRC channel is::

        <Channel>-Message ::= SEQUENCE { message <Channel>-MessageType }
        <Channel>-MessageType ::= CHOICE { c1 CHOICE { ... }, messageClassExtension }

    UPER encodes the outer CHOICE as 1 bit (c1 vs extension). When that bit
    is 0 (c1 path), the next ``width`` bits encode the c1 alternative — width
    is channel-specific per TS 38.331. BCCH-BCH is the special case: the
    outer CHOICE has only ``mib`` and ``messageClassExtension``, with no
    inner c1 wrapper.

    Returns ``(msg_class_index, msg_class_name)``. ``msg_class_index`` is
    None when the channel has no c1 (BCCH-BCH), msg_data is empty, or the
    outer CHOICE selects messageClassExtension. ``msg_class_name`` is empty
    in those cases except BCCH-BCH outer=0 which returns ("", "mib").
    """
    if not msg_data:
        return None, ""

    if channel_name == "BCCH-BCH":
        # Outer CHOICE only — no inner c1.
        outer = (msg_data[0] >> 7) & 1
        if outer == 0:
            return None, "mib"
        return None, ""

    width = _C1_CHOICE_BITS.get(channel_name)
    if width is None:
        return None, ""

    b = msg_data[0]
    outer = (b >> 7) & 1
    if outer != 0:
        # messageClassExtension path — alternative is not a c1 index.
        return None, ""
    c1_index = (b >> (7 - width)) & ((1 << width) - 1)
    name = _MSG_CLASS_NAMES.get((channel_name, c1_index), "")
    return c1_index, name


# ── Ground-truth recipe — WiGLE-direct (identity) ────────────────────────────
# 0xB821 is the NR5G RRC OTA message log — wigle:direct because its decoded
# header (and SIB1, when the OTA message IS a SIB1 broadcast) carries the full
# WiGLE cell-identity set: PCI, NR-ARFCN, NCGI (cell_global_id), and PLMN+TAC+
# cellID from the SIB1 ASN.1. Target = RM520N-GL (SDX62), which emits version
# 0x11 (=17, Rel-16) in the corpus (1582 v0x11 records in an offset-0 walk;
# v17 is the only RM520N-GL version with the NCGI cell_global_id field).
# cond:nr5g — drive an NR5G-SA attach so RRC OTA fires; SIB1-bearing records
# appear during cell (re)selection / connection setup.

@register(LOG_NR5G_RRC_OTA_MSG, domain="rrc",
    name="0xB821",
    description="NR5G RRC Over-The-Air message with ASN.1 PER-encoded content",
    version=28,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Header layouts for v9 (SDX55 RM500Q, cross-checked against AT+QENG "
        "serving cell), v12/v14/v17 (1,544-record corpus walk across EM9190 / "
        "RM500Q / RM520N-GL), v23 (T99W640) and v26 (RG650V SDX72; v17 plus 4 "
        "zero bytes before msg_data, header 31->35), verified at 100% by "
        "header_size + msg_length == payload_len. Dispatch follows SCAT's "
        "pkt_ver-keyed rrc_type_map and pdu_id at a version-keyed offset "
        "(byte[17] v9, byte[16] v12/v14, byte[24] v17+); byte[5] is rrc_rel_min "
        "(kept as a deprecated channel_type alias). v23 uses the MCCH-shifted "
        "map without v26's RRC-RECONF shift. A record shorter than header_size "
        "+ msg_length returns None (registry WARN). The v17+ cell_global_id "
        "decodes to ncgi_mcc / ncgi_mnc / ncgi_nci (PLMN BCD high 24 bits + "
        "36-bit NCI), validated against SCAT on RM520N-GL (Verizon n5 311/480 "
        "NCI 0x087EAC028). "
        "Version-bound grounding: every extracted PDU dissects in stock tshark "
        "nr-rrc.<channel> with 0 malformed — v9 772/772 (3 SDX55 modules, 7 "
        "channels; PCCH 5G-S-TMSI and MIB fields A/B-equal), v12 1239/1239 (19 "
        "captures, EM9190 + FT980M; 142 SIB1 cellIdentity values identical "
        "across 43 NR cells and 3 US carriers), v23 157/157 (T99W640; QCSuper "
        "and SCAT yield no packets here), v26 7/7 (RG650V-NA). SIB1 "
        "cellIdentity == tshark cellIdentity >> 4 (the 4 UPER pad bits). "
        "Body decoders dispatched in-band on the payload's own outer CHOICE, "
        "each validated field-for-field against stock tshark nr-rrc unless "
        "noted: SIB1 identity (MCC/MNC/TAC/cell id; sib1_tac_present=False for "
        "an NSA-only cell without trackingAreaCode) and SIB1 band/SCS/carrier "
        "bandwidth; the systemInformation container (SIB2 reselection, SIB4 "
        "inter-frequency and SIB5 inter-RAT EUTRA neighbour carriers, SIB9 "
        "network time) on all 225 distinct corpus SI messages (416 records / "
        "78 captures / 6 chipsets); standalone SIB2/SIB4/SIB5 records on "
        "per-version pdu_ids, tag-proven against same-capture SI and identical "
        "to tshark on 54/54 distinct payloads; MIB (same-cell invariance on a "
        "T-Mobile n41 cell, 30 kHz SSB SCS); securityModeCommand algorithms "
        "(nea2/nia2 on a T-Mobile NR5G-SA capture); DL-CCCH rrcSetup / "
        "rrcReject (24 real rrcSetup records over 3 chipsets + synthetic "
        "rrcReject vectors); PCCH paging records (5G-S-TMSI with TS 23.003 "
        "AMF set / pointer / 5G-TMSI split, byte-for-byte on real records; AMF "
        "Set ID 256 corpus-wide); RRCRelease redirectedCarrierInfo + "
        "suspendConfig (synthetic vectors + 3 real suspendConfig records; "
        "cellReselectionPriorities and ran-NotificationAreaInfo not walked); "
        "rrcReconfiguration measConfig on DL-DCCH and the firmware-direct "
        "RRC-RECONF framing (pycrate 124/124 and 23/23); RRCReconfigurationComplete "
        "transaction id (wrapped and firmware-direct); UL-CCCH / UL-CCCH1 "
        "requests (10 synthetic vectors + 50/50 distinct real payloads, framing "
        "proven by fixed SDU size, zero spare bits and the AMF pointer range); "
        "MeasurementReport (serving and neighbour SSB RSRP/RSRQ/SINR, 459/459 "
        "distinct). A whole-corpus A/B against stock tshark (20,623 records, "
        "every version) shows 0 mismatches on every decoded field. SIB9 "
        "timeInfoUTC is 10 ms units since 1900-01-01 UTC, confirmed against "
        "tshark and wardrive host-clock session starts. Still unmapped: v9 "
        "pdu_id 24/25, v12 25 and v17 29. Committed fixtures use synthetic "
        "identities."
    ),
    source_url="https://github.com/lukejenkins",
    issues=(),
    primary_issue=None,
    fields_identified=66,
    fields_parsed=66,
    field_invariants={
        # Validated against 1,544 DLF records / 23 captures / 4 chipsets plus
        # 7 RG650V SDX72 v26 records.
        # version is the u32-LE discriminator used to pick header layout.
        # rrc_release is 15 (Rel-15) on v7/v9/v12, 16 (Rel-16) on v14/v17,
        # 17 (Rel-17) on v26. rrc_rel_min varies with firmware and is not
        # an enum — no invariant. pdu_id is not an enum either (the map
        # itself is the validation surface; an unmapped pdu_id surfaces as
        # an empty channel_name).
        "version": {"enum": [9, 12, 14, 17, 23, 26]},
        "rrc_release": {"enum": [15, 16, 17]},
    },
    wigle_direct=True,
    wigle_roles=("identity", "rat-context"),
    # Ground-truth recipe: WiGLE-direct identity validation for v0x11
    # (RM520N-GL SDX62), hardware-run. Identity fields (pci/arfcn/
    # cell_global_id/sib1_*) verified on hardware against AT/QMI; SIB9
    # network-time fields verified via tshark equality + host clock.
)
def parse_0xb821(log_time: int, data: bytes) -> Diag0xB821 | None:
    """Parse 0xB821 — NR5G RRC OTA Message.

    Extracts the RRC message header (PCI, NR-ARFCN, SFN/slot, pdu_id) and
    the raw ASN.1 PER-encoded message body. Bodies are decoded inline per
    channel via from-scratch UPER sibling decoders (3GPP TS 38.331): SIB1 +
    the systemInformation SI container (SIB2/4/5/9) on BCCH-DL-SCH, MIB on
    BCCH-BCH, securityModeCommand + rrcReconfiguration measConfig on DL-DCCH,
    rrcSetup / rrcReject on DL-CCCH, MeasurementReport on UL-DCCH, and every
    UL-CCCH / UL-CCCH1 request (setup / resume / reestablishment / SI). Channels
    / message classes without a body decoder still resolve their
    channel_name + msg_class_name and hand msg_data back raw.

    Supports versions 9, 12, 14, 17, 23, 26. Other versions (v7 included)
    return None.
    Header dispatch is keyed on SCAT's pkt_ver-aware rrc_type_map and the
    pdu_id at a version-keyed offset. byte[5] is ``rrc_rel_min`` (release
    minor); the ``channel_type`` name for it survives only as a deprecated
    alias on the dataclass.
    """
    if len(data) < 4:
        return None

    version = unpack_from('<I', data, 0)[0]
    header_size = _HEADER_SIZE.get(version)
    if header_size is None or len(data) < header_size:
        return None

    rrc_release = data[4]
    rrc_rel_min = data[5]
    bearer_id = data[6]
    pci = unpack_from('<H', data, 7)[0]

    # v17+ insert an 8-byte cell_global_id (NCGI) between bearer_id and arfcn:
    # PLMN-Identity in the high 24 bits, the 36-bit NCI below (decode_ncgi).
    if version in (17, 23, 26):
        cell_global_id = unpack_from('<Q', data, 9)[0]
        arfcn_offset = 17
    else:
        cell_global_id = None
        arfcn_offset = 9

    ncgi = decode_ncgi(cell_global_id)

    arfcn = unpack_from('<I', data, arfcn_offset)[0]

    # sfn_subfn: the field is 4 bytes on v7/v9 (u32) and 3 bytes on v12/v14/v17+
    # (u24). The low 16 bits give sfn<<4|slot (validated vs 1,544 corpus records).
    # The upper byte(s) are not reserved — they
    # carry live, varying data (non-zero in 6/12 fixtures; SCAT derives
    # subframe/slot from them), so the full-width value is read and exposed as
    # sfn_subfn_raw rather than discarded. Width = pdu_id_offset - sfn_offset.
    sfn_off = _SFN_SUBFN_OFFSET[version]
    sfn_width = _PDU_ID_OFFSET[version] - sfn_off      # 4 on v7/v9, 3 elsewhere
    sfn_subfn_raw = int.from_bytes(data[sfn_off:sfn_off + sfn_width], 'little')
    sfn_slot = sfn_subfn_raw & 0xFFFF
    sfn = sfn_slot >> 4
    slot = sfn_slot & 0xF

    pdu_id = data[_PDU_ID_OFFSET[version]]
    sib_mask = unpack_from('<I', data, _SIB_MASK_OFFSET[version])[0]
    msg_length = unpack_from('<H', data, _MSG_LEN_OFFSET[version])[0]

    # Truncation gate: the header declares msg_length bytes of RRC PDU.
    # A record shorter than that lost its tail — decline it (registry WARN)
    # instead of returning the header with an empty msg_data.
    if len(data) < header_size + msg_length:
        return None
    msg_data = data[header_size:header_size + msg_length]

    channel_name = pkt_ver_to_channel_name(version, pdu_id)
    msg_class_index, msg_class_name = _decode_outer_choice(channel_name, msg_data)

    result = Diag0xB821(
        log_time=log_time,
        version=version,
        rrc_release=rrc_release,
        rrc_rel_min=rrc_rel_min,
        bearer_id=bearer_id,
        pci=pci,
        arfcn=arfcn,
        sfn=sfn,
        slot=slot,
        sfn_subfn_raw=sfn_subfn_raw,
        pdu_id=pdu_id,
        sib_mask=sib_mask,
        msg_length=msg_length,
        msg_data=msg_data,
        cell_global_id=cell_global_id,
        ncgi_mcc=ncgi[0] if ncgi else "",
        ncgi_mnc=ncgi[1] if ncgi else "",
        ncgi_nci=ncgi[2] if ncgi else None,
        channel_name=channel_name,
        msg_class_index=msg_class_index,
        msg_class_name=msg_class_name,
    )

    # Auto-decode NR SIB1 from BCCH-DL-SCH frames using the from-scratch
    # UPER decoder (3GPP TS 38.331); no pycrate at runtime, keeping diaggrok
    # Apache-2.0-clean. SIB1 dispatch keys on the resolved channel_name, not on
    # byte[5] (a byte[5] key would also fire on PCCH records that share the
    # same rrc_rel_min value).
    if channel_name == "BCCH-DL-SCH" and msg_data:
        sib1 = decode_nr_sib1_uper(msg_data)
        if sib1 is not None:
            result.sib1_mcc = sib1.mcc
            result.sib1_mnc = sib1.mnc
            result.sib1_tac = sib1.tac
            result.sib1_cell_id = sib1.cell_id
            result.sib1_tac_present = sib1.tac_present
            result.sib1_band = sib1.band
            result.sib1_scs_khz = sib1.scs_khz
            result.sib1_carrier_bandwidth_prb = sib1.carrier_bandwidth_prb
            result.sib1_channel_bandwidth_mhz = sib1.channel_bandwidth_mhz

    # Auto-decode the systemInformation (c1=0) SI container: walk the
    # sib-TypeAndInfo list — extracting SIB2 serving-cell reselection
    # parameters, the SIB4/SIB5 neighbour carriers (nr5g_rrc_sib_decode) and
    # the SIB9 timeInfo (NR network time). Same in-band dispatch signal as the
    # MIB/SMC paths — msg_class_name comes from the payload's own outer
    # CHOICE. Validated field-for-field against the stock tshark nr-rrc
    # dissector on all 225 distinct corpus SI messages.
    if (channel_name == "BCCH-DL-SCH"
            and msg_class_name == "systemInformation" and msg_data):
        si = decode_nr_si(log_time, msg_data)
        if si is not None:
            result.si_sib_count = si.sib_count
            result.si_sib_tags = si.sib_tags
            result.sib2_params = si.sib2
            result.sib4_params = si.sib4
            result.sib5_params = si.sib5
            if si.sib9 is not None:
                result.sib9_time_info_utc = si.sib9.time_info_utc
                result.sib9_utc_iso = (
                    si.sib9.utc_datetime.isoformat()
                    if si.sib9.utc_datetime is not None else "")
                result.sib9_leap_seconds = si.sib9.leap_seconds
                result.sib9_dst = si.sib9.dst
                result.sib9_local_time_offset = si.sib9.local_time_offset

    # Auto-decode the NR MIB from BCCH-BCH frames whose outer CHOICE selects
    # mib. The canonical decoder lives in nr5g_rrc_mib. v7's MIB-vs-RRC_RECONFIG
    # discriminator sits in the DLF outer header, invisible inside the payload;
    # on the declared versions the payload's own outer CHOICE is decodable, so
    # _decode_outer_choice resolving msg_class_name=='mib' is an in-band,
    # self-consistent dispatch signal and auto-decode is safe.
    if channel_name == "BCCH-BCH" and msg_class_name == "mib" and msg_data:
        mib = decode_nr_mib(log_time, msg_data)
        if mib is not None:
            result.mib_scs_common = mib.sub_carrier_spacing_common_name
            result.mib_ssb_subcarrier_offset = mib.ssb_subcarrier_offset
            result.mib_dmrs_typeA_position = mib.dmrs_type_a_position_name
            result.mib_coreset0 = mib.control_resource_set_zero
            result.mib_searchspace0 = mib.search_space_zero
            result.mib_cell_barred = (
                "notBarred" if mib.cell_not_barred else "barred"
            )
            result.mib_intra_freq_reselection = (
                "allowed" if mib.intra_freq_reselection_allowed else "notAllowed"
            )
            result.mib_sfn_msb = mib.system_frame_number

    # Auto-decode the DL-DCCH SecurityModeCommand body (AS-security algorithm
    # pair) when the c1 index resolves to securityModeCommand. Same in-band,
    # self-consistent dispatch signal as the MIB: msg_class_name comes from
    # the payload's own outer CHOICE, so there is no out-of-band ambiguity.
    # securityModeCommand is offset-stable across wire versions (smallest-
    # fully-defined message, no per-version drift) — see nr5g_rrc_smc.
    if (channel_name == "DL-DCCH" and msg_class_name == "securityModeCommand"
            and msg_data):
        smc = decode_nr_security_mode_command(log_time, msg_data)
        if smc is not None:
            result.smc_rrc_transaction_id = smc.rrc_transaction_identifier
            result.smc_ciphering_algorithm = smc.ciphering_algorithm
            result.smc_ciphering_algorithm_name = smc.ciphering_algorithm_name
            result.smc_integrity_prot_algorithm = smc.integrity_prot_algorithm
            result.smc_integrity_prot_algorithm_name = (
                smc.integrity_prot_algorithm_name or "")

    # Auto-decode the DL-CCCH message (rrcSetup / rrcReject): the RRC
    # connection-establishment messages sent before an SRB1/DCCH exists.
    # Same in-band dispatch signal as the MIB/SMC paths: the c1 index that
    # _decode_outer_choice resolved from the payload's own outer CHOICE names
    # the message class, so there is no out-of-band ambiguity. The decoder
    # extracts the clean leading scalars (rrcSetup.rrc-TransactionIdentifier,
    # rrcReject.waitTime); the heavy RadioBearerConfig / masterCellGroup
    # CellGroupConfig in rrcSetup is intentionally left structural. Validated
    # field-for-field against the stock tshark nr-rrc dissector on 24 real
    # rrcSetup records (RM520N-GL SDX62 v17, RXM-G1 v9, T99W640 SDX72 v23) and
    # on synthetic rrcReject vectors (rrcReject has zero corpus records).
    if channel_name == "DL-CCCH" and msg_data:
        dl_ccch = decode_nr_dl_ccch(log_time, msg_data)
        if dl_ccch is not None:
            result.dl_ccch_message_type = dl_ccch.message_type
            result.dl_ccch_rrc_transaction_identifier = (
                dl_ccch.rrc_transaction_identifier)
            result.dl_ccch_wait_time = dl_ccch.wait_time

    # Auto-decode the DL-DCCH RRCRelease redirect: the carrier the gNB
    # redirects the UE onto at connection teardown — an NR ARFCN or an inter-RAT
    # E-UTRA EARFCN, serving-infrastructure data of the same class the 0xB821
    # WiGLE program lifts from SIB1/paging. Same in-band dispatch signal as the
    # MIB/SMC/DL-CCCH paths: msg_class_name comes from the payload's own outer
    # CHOICE, so there is no out-of-band ambiguity. The decoder consumes the
    # full DL-DCCH-Message prefix and extracts the redirect head; the heavier
    # redirectedCarrierInfo (redirect carrier) and suspendConfig (RRC-Inactive
    # resume identities fullI-RNTI / shortI-RNTI + paging config) are both
    # decoded. Validated field-for-field against the stock tshark nr-rrc.dl.dcch
    # dissector on synthetic redirect + suspendConfig vectors and on real
    # corpus rrcRelease records (the suspendConfig resume identities match
    # tshark byte-for-byte on real captures). cellReselectionPriorities /
    # deprioritisationReq are not yet walked (0 corpus records exercise them).
    if (channel_name == "DL-DCCH" and msg_class_name == "rrcRelease"
            and msg_data):
        rel = decode_nr_rrc_release(log_time, msg_data)
        if rel is not None:
            result.release_rrc_transaction_identifier = (
                rel.rrc_transaction_identifier)
            result.release_redirect_rat = rel.redirect_rat
            result.release_redirect_arfcn = rel.redirect_arfcn
            result.release_redirect_scs_khz = rel.redirect_scs_khz
            result.release_redirect_cn_type = rel.redirect_cn_type
            result.release_suspend_config = rel.suspend_config
            result.release_suspend_full_i_rnti = rel.suspend_full_i_rnti
            result.release_suspend_short_i_rnti = rel.suspend_short_i_rnti
            result.release_suspend_ran_paging_cycle = rel.suspend_ran_paging_cycle
            result.release_suspend_next_hop_chaining_count = (
                rel.suspend_next_hop_chaining_count)

    # Auto-decode the UL-DCCH MeasurementReport (serving + neighbor NR cell
    # measurements) when the c1 index resolves to measurementReport. Same
    # in-band dispatch signal as the MIB/SMC paths: msg_class_name comes from
    # the payload's own outer CHOICE, so there is no out-of-band ambiguity. The
    # decoder self-gates on the full UL-DCCH-Message outer. 63/188
    # UL-DCCH records across the sampled corpus carry a MeasurementReport.
    if (channel_name == "UL-DCCH" and msg_class_name == "measurementReport"
            and msg_data):
        mr = decode_nr_measurement_report(log_time, msg_data)
        if mr is not None:
            result.meas_report_id = mr.meas_id
            result.meas_report_serving_rsrp = mr.serving_rsrp
            result.meas_report_serving_rsrq = mr.serving_rsrq
            result.meas_report_serving_sinr = mr.serving_sinr
            result.meas_report_neighbors = mr.neighbor_cells

    # Auto-decode the RRCReconfiguration measConfig (NR measurement objects:
    # SSB NR-ARFCNs, subcarrier spacing, neighbor PCIs; inter-RAT EUTRA EARFCNs)
    # from two framings:
    #   * DL-DCCH channel, c1 == rrcReconfiguration — payload begins with the
    #     DL-DCCH-Message outer CHOICE → decode_nr_meas_config.
    #   * RRC-RECONF firmware-direct channel — the DLF outer header already named
    #     the message, so msg_data starts at the bare RRCReconfiguration SEQUENCE
    #     (no DL-DCCH-Message wrapper) → decode_nr_meas_config_direct.
    # Both paths handle the radioBearerConfig structural skip and are validated
    # field-for-field against pycrate on the real 0xB821 corpus (DL-DCCH
    # 124/124, RRC-RECONF 23/23).
    if msg_data and (
        (channel_name == "DL-DCCH" and msg_class_name == "rrcReconfiguration")
        or channel_name == "RRC-RECONF"
    ):
        if channel_name == "RRC-RECONF":
            mc = decode_nr_meas_config_direct(log_time, msg_data)
        else:
            mc = decode_nr_meas_config(log_time, msg_data)
        if mc is not None and (mc.nr_objects or mc.eutra_objects):
            result.meas_objects = mc.nr_objects
            result.meas_eutra_objects = mc.eutra_objects
            result.meas_s_measure_ssb = mc.s_measure_ssb
            result.meas_s_measure_csi = mc.s_measure_csi

    # Auto-decode the PCCH Paging record list (idle-mode UE identities) when the
    # c1 index resolves to paging. Same in-band, self-consistent dispatch signal
    # as the MIB/SMC/DL-CCCH paths: msg_class_name comes from the payload's own
    # outer CHOICE, so there is no out-of-band ambiguity. Paging is the highest-
    # volume PCCH message and, like the MIB, a smallest-fully-bounded message —
    # one offset-stable decoder covers every wire version. Validated
    # byte-for-byte against the stock tshark nr-rrc.pcch dissector on real v14 +
    # v17 RM520N-GL records (single- and multi-record PagingRecordList).
    if (channel_name == "PCCH" and msg_class_name == "paging" and msg_data):
        paging = decode_nr_paging(log_time, msg_data)
        if paging is not None:
            result.paging_record_count = paging.record_count
            result.paging_records = paging.records

    # Auto-decode the UL-DCCH RRCReconfigurationComplete: the UE's
    # uplink acknowledgement of a gNB RRCReconfiguration. Same in-band,
    # self-consistent dispatch signal as the MIB/SMC/paging paths: msg_class_name
    # comes from the payload's own outer CHOICE, so there is no out-of-band
    # ambiguity. Its rrc-TransactionIdentifier pairs this Complete with the
    # RRCReconfiguration carrying the same id — the DL side already decoded on the
    # rrcReconfiguration path — so a one-sided OTA capture can be reassembled into
    # a reconfiguration round-trip. Like paging/SMC it is a smallest-fully-bounded
    # message: one offset-stable decoder covers every wire version. Validated
    # against the stock tshark nr-rrc.ul.dcch dissector on the transaction-id
    # sweep vectors.
    if (channel_name == "UL-DCCH"
            and msg_class_name == "rrcReconfigurationComplete" and msg_data):
        rcc = decode_nr_rrc_reconfig_complete(log_time, msg_data)
        if rcc is not None:
            result.reconfig_complete_transaction_id = (
                rcc.rrc_transaction_identifier)
    # The firmware-direct RRC-RECONF-COMPLETE pdu_id carries the bare message,
    # without the UL-DCCH wrapper (same split as RRC-RECONF, above).
    elif channel_name == "RRC-RECONF-COMPLETE" and msg_data:
        rcc = decode_nr_rrc_reconfig_complete_direct(log_time, msg_data)
        if rcc is not None:
            result.reconfig_complete_transaction_id = (
                rcc.rrc_transaction_identifier)

    # Auto-decode the UL-CCCH / UL-CCCH1 message: the UE's first
    # RRC words on a cell — setup / resume / reestablishment / on-demand-SI
    # requests. Keyed on the channel alone (every c1 alternative is decoded,
    # like DL-CCCH); the decoder re-reads the outer CHOICE itself and refuses a
    # payload shorter than the fixed CCCH48 / CCCH64 SDU. One offset-stable
    # decoder covers every wire version (fixed-size, non-extensible messages).
    if channel_name in ("UL-CCCH", "UL-CCCH1") and msg_data:
        ul = (decode_nr_ul_ccch if channel_name == "UL-CCCH"
              else decode_nr_ul_ccch1)(log_time, msg_data)
        if ul is not None:
            result.ul_ccch_message_type = ul.message_type
            for k in _UL_CCCH_FIELDS:
                setattr(result, 'ul_ccch_' + k, getattr(ul, k))

    # Standalone SIB2/SIB4/SIB5 records: the bare SIB SEQUENCE on the
    # per-version pdu_ids in _STANDALONE_SIB_PDU_IDS. The payload is exactly the
    # bit span the systemInformation container carries after its sib-TypeAndInfo
    # tag, so the same SIB decoders run from bit 0 and fill the same *_params
    # fields the SI path fills (proven equal object-for-object on real records).
    if channel_name in ("SIB2", "SIB4", "SIB5") and msg_data:
        try:
            r = UperReader(msg_data)
            if channel_name == "SIB2":
                result.sib2_params = decode_sib2(r)
            elif channel_name == "SIB4":
                result.sib4_params = decode_sib4(r)
            else:
                result.sib5_params = decode_sib5(r)
        except (IndexError, ValueError, KeyError):   # same guard as decode_nr_si
            pass

    return result
