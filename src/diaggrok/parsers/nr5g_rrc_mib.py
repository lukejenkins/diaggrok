# diaggrok-provenance: re
"""NR MIB (Master Information Block) decoder — from-scratch UPER.

Decodes BCCH-BCH-Message carrying NR MIB per 3GPP TS 38.331 §6.2.2. MIB is
the smallest fully-defined RRC message in NR — 24 actual bits packed into
4 bytes (with 8 trailing padding bits). It carries the bare minimum a UE
needs to begin acquiring SIB1: the SFN MSBs, common subcarrier spacing,
the SSB-to-CORESET#0 frequency offset, the DMRS Type-A position, the
CORESET#0 and Search-Space#0 config-indices that point into the PDCCH
config tables (38.213 §13), the cellBarred / intraFreqReselection flags,
and a spare bit.

ASN.1 path (3GPP TS 38.331):

    BCCH-BCH-Message ::= SEQUENCE {
        message     BCCH-BCH-MessageType
    }
    BCCH-BCH-MessageType ::= CHOICE {
        mib                    MIB,
        messageClassExtension  SEQUENCE {}
    }
    MIB ::= SEQUENCE {
        systemFrameNumber             BIT STRING (SIZE (6)),
        subCarrierSpacingCommon       ENUMERATED { scs15or60, scs30or120 },
        ssb-SubcarrierOffset          INTEGER (0..15),
        dmrs-TypeA-Position           ENUMERATED { pos2, pos3 },
        pdcch-ConfigSIB1              PDCCH-ConfigSIB1,
        cellBarred                    ENUMERATED { barred, notBarred },
        intraFreqReselection          ENUMERATED { allowed, notAllowed },
        spare                         BIT STRING (SIZE (1))
    }
    PDCCH-ConfigSIB1 ::= SEQUENCE {
        controlResourceSetZero        ControlResourceSetZero,  -- INTEGER (0..15)
        searchSpaceZero               SearchSpaceZero          -- INTEGER (0..15)
    }

UPER bit layout (none of the SEQUENCEs are extensible, no OPTIONAL fields):

    bit  0     : BCCH-BCH-MessageType CHOICE (0=mib, 1=messageClassExtension)
    bits 1-6   : systemFrameNumber  (BIT STRING SIZE 6, MSB-first)
    bit  7     : subCarrierSpacingCommon  (0=scs15or60, 1=scs30or120)
    bits 8-11  : ssb-SubcarrierOffset     (INTEGER 0..15 → 4 bits)
    bit  12    : dmrs-TypeA-Position      (0=pos2, 1=pos3)
    bits 13-16 : controlResourceSetZero   (INTEGER 0..15 → 4 bits)
    bits 17-20 : searchSpaceZero          (INTEGER 0..15 → 4 bits)
    bit  21    : cellBarred               (0=barred, 1=notBarred)
    bit  22    : intraFreqReselection     (0=allowed, 1=notAllowed)
    bit  23    : spare                    (BIT STRING SIZE 1)
    bits 24-31 : zero-pad to byte boundary

Total payload size: 4 bytes (3 content + 1 padding).

Validated against the QCAT-decoded BCCH-BCH MIB record in
``sources/qualcomm/community/tool_analysis_qcat/UlDl-90-9-1_signaling.txt.layers.yaml``
(LG U+ EN-DC trace, RRC 15.4.1, 2020-07-15):

    msg_data (hex)         '43 0D 04 A4'
    systemFrameNumber      '100001'B   (= 33)
    subCarrierSpacingCommon scs30or120  (= 1)
    ssb-SubcarrierOffset   0
    dmrs-TypeA-Position    pos3        (= 1)
    controlResourceSetZero 10
    searchSpaceZero        0
    cellBarred             notBarred   (= 1)
    intraFreqReselection   allowed     (= 0)
    spare                  '0'B

This decoder is the canonical NR MIB unpacker for diaggrok. It is exposed
for any caller that has a 4-byte BCCH-BCH PDU — currently only reached via
the v7 0xB821 layout where the DLF outer-header byte (not the payload's
channel_type byte) discriminates MIB from RRC_RECONFIG / RADIO_BEARER_CONFIG
/ RRC_RECONFIG_COMPLETE. The 0xB821 parser does not auto-dispatch MIB
because that outer header is not visible inside the payload; callers that
process raw DLF records can invoke ``decode_nr_mib`` directly when the
outer dispatch resolves to MIB.

Reference: 3GPP TS 38.331 v16.x (NR RRC Protocol specification), §6.2.2.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from diaggrok.parsers.uper import UperReader


# SubcarrierSpacingCommon ENUMERATED values from MIB. Distinct from the
# 8-value SubcarrierSpacing used elsewhere — MIB only encodes the two
# common-channel options. The displayed kHz pair depends on the frequency
# band (FR1 uses the first of each pair, FR2 the second).
_SCS_COMMON_NAMES = ("scs15or60", "scs30or120")

# DMRS-TypeA-Position ENUMERATED values — position of the front-loaded DMRS
# symbol for PDSCH/PUSCH mapping type A (38.211 §7.4.1.1.2).
_DMRS_TYPE_A_NAMES = ("pos2", "pos3")


@dataclass
class NrMIB:
    """Decoded NR Master Information Block (3GPP TS 38.331 §6.2.2).

    Fields preserve the on-wire encoding values (integers / booleans) and
    expose the ENUMERATED labels alongside, so callers can round-trip back
    to the spec text without re-decoding.
    """

    log_time: int
    # 6-bit field — represents bits 4..9 of the 10-bit SFN. The two LSBs
    # of the full SFN are signalled outside the MIB (via the PBCH payload
    # scrambling sequence per 38.212). 0..63.
    system_frame_number: int
    # ENUM value: 0=scs15or60, 1=scs30or120
    sub_carrier_spacing_common: int
    sub_carrier_spacing_common_name: str
    # 0..15 — kSSB; subcarrier offset from SSB to CORESET#0 grid
    ssb_subcarrier_offset: int
    # ENUM value: 0=pos2, 1=pos3
    dmrs_type_a_position: int
    dmrs_type_a_position_name: str
    # 0..15 — selects CORESET#0 config row (38.213 §13 Table 13-1..6)
    control_resource_set_zero: int
    # 0..15 — selects SearchSpace#0 config row (38.213 §13 Table 13-11..15)
    search_space_zero: int
    # True when cellBarred=notBarred (UE may camp). When False the cell
    # is barred and the UE must reselect.
    cell_not_barred: bool
    # True when intraFreqReselection=allowed (UE may reselect to other
    # cells on the same frequency even when barred elsewhere).
    intra_freq_reselection_allowed: bool
    # 1-bit BIT STRING reserved for future RRC additions — always '0'B
    # in spec-compliant decoders today, but preserved so non-conformance
    # is visible to corpus walks.
    spare: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "NrMIB",
            "log_time": self.log_time,
            "system_frame_number": self.system_frame_number,
            "sub_carrier_spacing_common": self.sub_carrier_spacing_common,
            "sub_carrier_spacing_common_name": self.sub_carrier_spacing_common_name,
            "ssb_subcarrier_offset": self.ssb_subcarrier_offset,
            "dmrs_type_a_position": self.dmrs_type_a_position,
            "dmrs_type_a_position_name": self.dmrs_type_a_position_name,
            "control_resource_set_zero": self.control_resource_set_zero,
            "search_space_zero": self.search_space_zero,
            "cell_barred": not self.cell_not_barred,
            "intra_freq_reselection_allowed": self.intra_freq_reselection_allowed,
            "spare": self.spare,
        }


def decode_nr_mib(log_time: int, msg_data: bytes) -> Optional[NrMIB]:
    """Decode an NR BCCH-BCH-Message into an NrMIB dataclass.

    Returns ``None`` if:
      * ``msg_data`` is shorter than 3 bytes (24 bits of MIB content),
      * the BCCH-BCH-MessageType outer CHOICE is messageClassExtension
        (no MIB content available — encountered on extension records).

    A spare-bit value of 1 is decoded faithfully (not rejected) so corpus
    walks can flag potentially non-conformant encoders.
    """
    if not msg_data or len(msg_data) < 3:
        return None

    r = UperReader(msg_data)

    outer = r.read_choice(2)
    if outer != 0:
        # messageClassExtension — no MIB content.
        return None

    sfn = r.read_bits(6)
    scs_common = r.read_bits(1)
    ssb_subcarrier_offset = r.read_constrained_int(0, 15)
    dmrs_type_a_position = r.read_bits(1)
    coreset_zero = r.read_constrained_int(0, 15)
    search_space_zero = r.read_constrained_int(0, 15)
    cell_not_barred = r.read_bool()
    intra_freq_reselection_allowed = (
        r.read_bits(1) == 0
    )  # ENUM 0=allowed, 1=notAllowed
    spare = r.read_bits(1)

    return NrMIB(
        log_time=log_time,
        system_frame_number=sfn,
        sub_carrier_spacing_common=scs_common,
        sub_carrier_spacing_common_name=_SCS_COMMON_NAMES[scs_common],
        ssb_subcarrier_offset=ssb_subcarrier_offset,
        dmrs_type_a_position=dmrs_type_a_position,
        dmrs_type_a_position_name=_DMRS_TYPE_A_NAMES[dmrs_type_a_position],
        control_resource_set_zero=coreset_zero,
        search_space_zero=search_space_zero,
        cell_not_barred=cell_not_barred,
        intra_freq_reselection_allowed=intra_freq_reselection_allowed,
        spare=spare,
    )
