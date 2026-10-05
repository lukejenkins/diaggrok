"""0xB822 — LOG_NR5G_RRC_MIB_INFO (NR5G RRC MIB info), 14/15 B fixed record.

One record per decoded PBCH/MIB: the cell it came from (PCI, NR-ARFCN),
the SFN, and the 3GPP TS 38.331 MIB fields unpacked into one 16-bit word.
Two layouts, one per on-wire version tuple (the header is ``u16 minor,
u16 major``; the registry's u8 "version" is the minor):

======  ==========  ======  =============================================
minor   major       size    silicon (corpus)
======  ==========  ======  =============================================
0x03    0           14 B    SDX55 (RM500Q, LV55, EM9190, SIM8202G, RXM-G1)
0x00    2           15 B    SDX62/SDX65/SDX72 (RM520N, RG520N/CFW-3212,
                            EM9291, T99W640)
======  ==========  ======  =============================================

Common layout::

    [0:2]   u16  version_minor     0x03 | 0x00
    [2:4]   u16  version_major     0    | 2
    [4:6]   u16  pci               0..1007
    [6:10]  u32  nr_arfcn          global-raster NR-ARFCN
    [10:12] u16  sfn_word          bits 0-9  sfn (10-bit system frame number)
                                   bits 10-14 reserved (0 on every record)
                                   bit  15   not_barred (1 = cellBarred notBarred)
    [12:14] u16  mib_word          bits 0-3  searchSpaceZero
                                   bits 4-7  controlResourceSetZero
                                   bit  8    dmrs-TypeA-Position (1 = pos3)
                                   bit  9    flag_b9 (raw; 1 on every record)
                                   v0x03: bits 10-13 ssb-SubcarrierOffset,
                                          bit 14 subCarrierSpacingCommon,
                                          bit 15 reserved (0 on every record)
                                   v0x00: bits 10-14 k_SSB (5 bits),
                                          bit 15 subCarrierSpacingCommon
    [14]    u8   unknown_14        v0x00 only; raw (always even, varies
                                   record to record on one cell)

So v0x00 widens the subcarrier offset to the full 5-bit FR1 k_SSB
(38.213 §4.1: the MIB's 4-bit ssb-SubcarrierOffset plus the PBCH payload
bit a_{A+5}), and SCS moves up one bit to make room.

GROUNDING (all measured on the capture corpus; real, PII-free cell parameters):

1. In-capture 0xB821 BCCH-BCH MIB OTA (decoded by ``nr5g_rrc_mib``), joined
   on (capture, PCI, NR-ARFCN, nearest timestamp, |dt| <= 2 ms), whole
   corpus (3,939 records / 183 captures): v0x00 2,689/2,689 and v0x03
   275/275 on searchSpaceZero, controlResourceSetZero, dmrs-TypeA-Position,
   ssb-SubcarrierOffset (low 4 bits) and subCarrierSpacingCommon (bit 15 on
   v0x00, bit 14 on v0x03; the other placement scores 1,900/2,689 and
   47/275). v0x03 sfn >> 4 equals the OTA 6-bit SFN MSBs 275/275.
2. SCAT output, whose NR MIB line
   reports NR-ARFCN, PCI, SFN and SCS: v0x03 33/33 exact multiset match
   (RM500Q-AE survey); v0x00 21/21 with scat-only = 0 (RM520N network
   scan; SCAT drops 14 records to a framing difference).
3. F3 (v0x03): ``tm_cm_iface_nonship.c:284`` "5G-NR CID Update: TAC=%d
   Freq=%d PSC=%d" — the serving cell's Freq/PSC equals a 0xB822
   (nr_arfcn, pci) within 1 s in 5/5 prints, 5 distinct PCIs, 0 disagreeing
   (Compal RXM-G1 drive capture). Neighbour/scan MIBs have no CID print. On
   SDX62 (v0x00) F3 is silent on these fields in 3 captures, and 0x60
   carries no NR5G event.
4. k_SSB is 5 bits on v0x00: all 735 records with bit 14 set have a low
   nibble <= 7, so every k_SSB is <= 23 (FR1 range with CORESET#0). Values
   observed: 0..22.
5. not_barred: on v0x00, sfn_word bit 15 against the OTA cellBarred is a
   clean diagonal — (1, notBarred) 2,677, (0, barred) 12, off-diagonal 0;
   the 12 barred come from 6 captures (EM9291 band scans, RM520N COPS-dereg
   / RAT-lock / PSM cycles). On v0x03 every joined MIB is notBarred (275),
   so there it is CANDIDATE by structural transfer. flag_b9 is 1 on all 12
   barred records, so it is not cellBarred; it stays raw.

intraFreqReselection is not located: every OTA MIB in the corpus reads
``allowed``, so no bit can be tested. sfn is 0 on most SDX62 records (SCAT
agrees); SDX55 fills it.

Size or (minor, major) outside the two layouts returns ``None`` — a misframe
or a new firmware layout, never a guess. Whole corpus: 3,939/3,939 parse,
0 rejected, 0 invariant violations.

Log name: LOG_NR5G_RRC_MIB_INFO
Also known as: NR5G RRC MIB Info
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

# minor -> (major, size)
_LAYOUTS = {
    0x03: (0, 14),  # SDX55
    0x00: (2, 15),  # SDX62 / SDX65 / SDX72
}
_FR2_MIN_ARFCN = 2016667  # 24250 MHz, the FR1/FR2 boundary on the global raster


@dataclass
class Diag0xB822:
    """0xB822 — NR5G RRC MIB info (one decoded PBCH/MIB)."""
    log_time: int
    version: int          # u16@0, the release minor (registry version byte)
    version_major: int    # u16@2
    payload_size: int
    pci: int
    nr_arfcn: int
    sfn: int
    sfn_word: int
    not_barred: bool      # v0x00 grounded; v0x03 CANDIDATE
    mib_word: int
    search_space_zero: int
    coreset_zero: int
    dmrs_type_a_pos3: bool
    flag_b9: int
    ssb_subcarrier_offset: int
    k_ssb: int | None     # v0x00 only (5-bit)
    scs_common_hi: bool   # True = scs30or120
    unknown_14: int | None  # v0x00 only

    @property
    def scs_common(self) -> str:
        return "scs30or120" if self.scs_common_hi else "scs15or60"

    @property
    def scs_common_khz(self) -> int:
        fr2 = self.nr_arfcn >= _FR2_MIN_ARFCN
        return (120 if fr2 else 30) if self.scs_common_hi else (60 if fr2 else 15)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB822",
            "log_time": self.log_time,
            "version": self.version,
            "version_major": self.version_major,
            "payload_size": self.payload_size,
            "pci": self.pci,
            "nr_arfcn": self.nr_arfcn,
            "sfn": self.sfn,
            "sfn_word": self.sfn_word,
            "not_barred": self.not_barred,
            "mib_word": self.mib_word,
            "search_space_zero": self.search_space_zero,
            "coreset_zero": self.coreset_zero,
            "dmrs_type_a_position": "pos3" if self.dmrs_type_a_pos3 else "pos2",
            "flag_b9": self.flag_b9,
            "ssb_subcarrier_offset": self.ssb_subcarrier_offset,
            "k_ssb": self.k_ssb,
            "scs_common": self.scs_common,
            "scs_common_khz": self.scs_common_khz,
            "unknown_14": self.unknown_14,
        }


@register(
    0xB822,
    name="0xB822",
    description=(
        "0xB822 — LOG_NR5G_RRC_MIB_INFO, 14/15B: PCI, NR-ARFCN, SFN and the "
        "unpacked MIB (SS#0, CORESET#0, DMRS pos, ssb-SubcarrierOffset/k_SSB, SCS)"
    ),
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Body decode, two layouts keyed by (minor, major, size) = (3, 0, 14) "
        "SDX55 / (0, 2, 15) SDX62+. Fields joined 1:1 to the co-emitted "
        "0xB821 BCCH-BCH MIB (2689/2689, 275/275), checked against SCAT "
        "(33/33; 21/21), F3 tm_cm_iface_nonship.c:284 Freq/PSC 5/5 on SDX55. "
        "not_barred = sfn_word bit 15 (12/12 barred, 2677/2677 notBarred on "
        "v0x00; CANDIDATE on v0x03). intraFreqReselection is not located."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=15,
    fields_parsed=15,
    field_invariants={
        "version": {"enum": [0x00, 0x03]},
    },
    domain="rrc",
    wigle_direct=False,
    wigle_roles=("pci-earfcn-bridge", "rat-context"),
)
def parse_0xb822(log_time: int, data: bytes) -> Diag0xB822 | None:
    if len(data) < 14 or data[0] not in _LAYOUTS:  # Layer-1 version gate
        return None
    minor, major = unpack_from("<HH", data, 0)
    layout = _LAYOUTS.get(minor)
    if layout is None or layout != (major, len(data)):
        return None
    pci, nr_arfcn, sfn_word, mib_word = unpack_from("<HIHH", data, 4)
    if minor == 0x00:
        k_ssb: int | None = (mib_word >> 10) & 0x1F
        scs_hi = bool((mib_word >> 15) & 1)
        unknown_14: int | None = data[14]
    else:
        k_ssb = None
        scs_hi = bool((mib_word >> 14) & 1)
        unknown_14 = None
    return Diag0xB822(
        log_time=log_time,
        version=minor,
        version_major=major,
        payload_size=len(data),
        pci=pci,
        nr_arfcn=nr_arfcn,
        sfn=sfn_word & 0x3FF,
        sfn_word=sfn_word,
        not_barred=bool(sfn_word >> 15),
        mib_word=mib_word,
        search_space_zero=mib_word & 0xF,
        coreset_zero=(mib_word >> 4) & 0xF,
        dmrs_type_a_pos3=bool((mib_word >> 8) & 1),
        flag_b9=(mib_word >> 9) & 1,
        ssb_subcarrier_offset=(mib_word >> 10) & 0xF,
        k_ssb=k_ssb,
        scs_common_hi=scs_hi,
        unknown_14=unknown_14,
    )
