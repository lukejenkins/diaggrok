# diaggrok-provenance: re
"""LTE RRC SIB1 decoder for 0xB0C0 message payloads.

Decodes SystemInformationBlockType1 from UPER-encoded BCCH-DL-SCH messages
to extract cell identity (MCC, MNC, TAC, CellID).

Implements a minimal UPER (Unaligned Packed Encoding Rules) reader for the
specific ASN.1 structures defined in 3GPP TS 36.331 that we need:

    BCCH-DL-SCH-Message ::= SEQUENCE {
        message     BCCH-DL-SCH-MessageType
    }
    BCCH-DL-SCH-MessageType ::= CHOICE {
        c1              CHOICE {
            systemInformation           SystemInformation,
            systemInformationBlockType1 SystemInformationBlockType1
        },
        messageClassExtension   SEQUENCE {}
    }
    SystemInformationBlockType1 ::= SEQUENCE {
        cellAccessRelatedInfo   SEQUENCE {
            plmn-IdentityList       PLMN-IdentityList,  -- 1..6
            trackingAreaCode        TrackingAreaCode,    -- BIT STRING (SIZE (16))
            cellIdentity            CellIdentity,        -- BIT STRING (SIZE (28))
            cellBarred              ENUMERATED {barred, notBarred},
            intraFreqReselection    ENUMERATED {allowed, notAllowed},
            csg-Indication          BOOLEAN
        },
        ...  -- remaining fields not decoded
    }

Reference: 3GPP TS 36.331 v16.x (E-UTRA RRC Protocol specification)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# UperReader is the canonical shared UPER bit reader.
# Defined in uper.py, re-exported here for backward compatibility.
from diaggrok.parsers.uper import UperReader  # noqa: F401
from diaggrok.parsers.asn1_helpers import PlmnIdentity, decode_plmn_identity


@dataclass
class Sib1CellIdentity:
    """Decoded SIB1 cell identity fields."""
    plmn_list: list[PlmnIdentity]
    tracking_area_code: int   # 16-bit TAC
    cell_identity: int        # 28-bit Cell ID
    cell_barred: bool
    csg_indication: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Sib1CellIdentity',
            'plmn_list': [p.to_dict() for p in self.plmn_list],
            'tracking_area_code': self.tracking_area_code,
            'cell_identity': self.cell_identity,
            'cell_barred': self.cell_barred,
            'csg_indication': self.csg_indication,
        }


def decode_sib1_cell_access(msg_data: bytes) -> Sib1CellIdentity | None:
    """Decode SIB1 cellAccessRelatedInfo from a BCCH-DL-SCH UPER bitstream.

    Navigates the ASN.1 structure:
        BCCH-DL-SCH-Message → message → c1 → systemInformationBlockType1
        → cellAccessRelatedInfo → plmn-IdentityList, TAC, cellIdentity, ...

    Returns None if the message is not SIB1 or decoding fails.

    Reference: 3GPP TS 36.331 §6.2.2
    """
    # SIB1 needs at least ~30 bytes (2 bits BCCH choice + 1 bit extension +
    # 3 bits optionals + 3 bits PLMN count + PLMN + 16 bits TAC + 28 bits CID + ...)
    if not msg_data or len(msg_data) < 10:
        return None

    try:
        r = UperReader(msg_data)

        # BCCH-DL-SCH-MessageType: CHOICE { c1, messageClassExtension }
        msg_choice = r.read_choice(2)
        if msg_choice != 0:  # not c1
            return None

        # c1: CHOICE { systemInformation(0), systemInformationBlockType1(1) }
        c1_choice = r.read_choice(2)
        if c1_choice != 1:  # not SIB1
            return None

        # SystemInformationBlockType1 is a SEQUENCE with extension marker
        has_extension = r.read_bool()

        # SIB1 base SEQUENCE has 3 OPTIONAL fields (3GPP TS 36.331 §6.2.2):
        #   p-Max, tdd-Config, nonCriticalExtension
        # UPER encodes a presence bitmap for all optionals
        r.read_bits(3)  # skip optional presence flags

        # cellAccessRelatedInfo: SEQUENCE (no extension marker, no optionals)
        # plmn-IdentityList: SEQUENCE (SIZE (1..6)) OF PLMN-IdentityInfo
        num_plmns = r.read_length_determinant(1, 6)

        plmn_list: list[PlmnIdentity] = []
        for _ in range(num_plmns):
            # PLMN-IdentityInfo ::= SEQUENCE {
            #     plmn-Identity   PLMN-Identity,
            #     cellReservedForOperatorUse  ENUMERATED {reserved, notReserved}
            # }
            plmn = decode_plmn_identity(r)
            plmn_list.append(plmn)
            # cellReservedForOperatorUse: ENUMERATED {reserved(0), notReserved(1)}
            r.read_enum(2)  # 1 bit

        # trackingAreaCode: BIT STRING (SIZE (16))
        tac = r.read_bits(16)

        # cellIdentity: BIT STRING (SIZE (28))
        cell_id = r.read_bits(28)

        # cellBarred: ENUMERATED {barred(0), notBarred(1)}
        cell_barred = r.read_enum(2) == 0

        # intraFreqReselection: ENUMERATED {allowed(0), notAllowed(1)}
        r.read_enum(2)  # skip

        # csg-Indication: BOOLEAN
        csg = r.read_bool()

        # Sanity check: first PLMN should have a 3-digit MCC
        if not plmn_list or len(plmn_list[0].mcc) != 3:
            return None
        # TAC and CellID should be non-zero
        if tac == 0 or cell_id == 0:
            return None

        return Sib1CellIdentity(
            plmn_list=plmn_list,
            tracking_area_code=tac,
            cell_identity=cell_id,
            cell_barred=cell_barred,
            csg_indication=csg,
        )

    except (IndexError, ValueError):
        return None
