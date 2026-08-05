# diaggrok-provenance: re
"""NR SIB1 cell identity decoder — from-scratch UPER (no pycrate).

Decodes NR BCCH-DL-SCH-Message containing systemInformationBlockType1
to extract cell identity (MCC/MNC/TAC/NCI) from cellAccessRelatedInfo.

From-scratch UPER decoder using the shared UperReader, following the same
pattern as lte_rrc_sib.py. Replaces the pycrate-based nr5g_rrc_sib1.py
for production use (#N).

ASN.1 path (3GPP TS 38.331):

    BCCH-DL-SCH-Message ::= SEQUENCE {
        message     BCCH-DL-SCH-MessageType
    }
    BCCH-DL-SCH-MessageType ::= CHOICE {
        c1    CHOICE {
            systemInformation           SystemInformation,
            systemInformationBlockType1 SIB1,
            ...  (4 base alternatives total: SI, SIB1, spare2, spare1)
        },
        messageClassExtension  SEQUENCE {}
    }
    SIB1 ::= SEQUENCE {
        cellSelectionInfo           SEQUENCE { ... } OPTIONAL,
        cellAccessRelatedInfo       CellAccessRelatedInfo,
        connEstFailureControl       SEQUENCE { ... } OPTIONAL,
        si-SchedulingInfo           SEQUENCE { ... } OPTIONAL,
        servingCellConfigCommon     SEQUENCE { ... } OPTIONAL,
        ims-EmergencySupport        ENUMERATED { true } OPTIONAL,
        eCallOverIMS-Support        ENUMERATED { true } OPTIONAL,
        ue-TimersAndConstants       SEQUENCE { ... } OPTIONAL,
        uac-BarringInfo             SEQUENCE { ... } OPTIONAL,
        useFullResumeID             ENUMERATED { true } OPTIONAL,
        ...
    }
    CellAccessRelatedInfo ::= SEQUENCE {
        plmn-IdentityInfoList   PLMN-IdentityInfoList,  -- SIZE (1..maxPLMN-Identities=12)
        cellReservedForOtherUse ENUMERATED { true } OPTIONAL,
        ...  -- extension marker, no known extensions
    }
    PLMN-IdentityInfoList ::= SEQUENCE (SIZE (1..maxPLMN-Identities)) OF PLMN-IdentityInfo
    PLMN-IdentityInfo ::= SEQUENCE {
        plmn-IdentityList     SEQUENCE (SIZE (1..maxPLMN)) OF PLMN-Identity,
        trackingAreaCode      TrackingAreaCode OPTIONAL,  -- BIT STRING (SIZE (24))
        ranac                 RAN-AreaCode OPTIONAL,      -- INTEGER (0..255)
        cellIdentity          CellIdentity,               -- BIT STRING (SIZE (36))
        cellReservedForOperatorUse  ENUMERATED { reserved, notReserved },
        ...
    }

Reference: 3GPP TS 38.331 v16.x (NR RRC Protocol specification)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from diaggrok.parsers.uper import UperReader
from diaggrok.parsers.asn1_helpers import (
    PlmnIdentity,
    decode_plmn_identity,
    skip_extension_additions,
)


@dataclass
class NrSib1CellId:
    """Cell identity extracted from NR SIB1 via from-scratch UPER."""
    mcc: str
    mnc: str
    tac: int              # 24-bit tracking area code
    cell_id: int          # 36-bit NR Cell Identity (NCI)
    band: Optional[int] = None
    additional_plmns: list[PlmnIdentity] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'type': 'NrSib1CellId',
            'mcc': self.mcc,
            'mnc': self.mnc,
            'tac': self.tac,
            'cell_id': self.cell_id,
        }
        if self.band is not None:
            d['band'] = self.band
        if self.additional_plmns:
            d['additional_plmns'] = [p.to_dict() for p in self.additional_plmns]
        return d


def decode_nr_sib1_uper(msg_data: bytes) -> NrSib1CellId | None:
    """Decode NR SIB1 cell identity from BCCH-DL-SCH UPER bitstream.

    Navigates:
        BCCH-DL-SCH-Message → message → c1 → systemInformationBlockType1
        → cellAccessRelatedInfo → plmn-IdentityInfoList[0]
        → plmn-IdentityList, trackingAreaCode, cellIdentity

    Returns None if the message is not SIB1 or decoding fails.
    """
    if not msg_data or len(msg_data) < 10:
        return None

    try:
        r = UperReader(msg_data)

        # BCCH-DL-SCH-MessageType: CHOICE { c1, messageClassExtension }
        msg_choice = r.read_choice(2)
        if msg_choice != 0:
            return None

        # c1: CHOICE of 2 alternatives per TS 38.331 §6.2.2:
        #   0 = systemInformation
        #   1 = systemInformationBlockType1
        # Encoded in 1 bit. (Earlier drafts of this decoder mistakenly read
        # 2 bits assuming LTE-style spare1/spare2 — but NR has never had
        # those, and LTE removed them by Rel-15.)
        c1_choice = r.read_choice(2)
        if c1_choice != 1:
            return None

        # SIB1 is NOT extensible per the published 38.331 ASN.1 (the spec
        # uses an explicit nonCriticalExtension chain rather than the `...`
        # marker). So there is no extension-presence bit at this position
        # — the optional bitmap starts immediately. Verified against pycrate's
        # compiled grammar (_ext is None on SIB1) — see #N.
        #
        # SIB1 has 11 OPTIONAL fields in the root section, MSB-first:
        #   bit 10: cellSelectionInfo
        #   bit  9: connEstFailureControl
        #   bit  8: si-SchedulingInfo
        #   bit  7: servingCellConfigCommon
        #   bit  6: ims-EmergencySupport
        #   bit  5: eCallOverIMS-Support
        #   bit  4: ue-TimersAndConstants
        #   bit  3: uac-BarringInfo
        #   bit  2: useFullResumeID
        #   bit  1: lateNonCriticalExtension
        #   bit  0: nonCriticalExtension
        # (cellAccessRelatedInfo is MANDATORY, not in the bitmap.)
        num_optionals = 11
        opt_bitmap = r.read_bits(num_optionals)

        has_cell_sel = (opt_bitmap >> 10) & 1

        # Skip cellSelectionInfo if present
        if has_cell_sel:
            _skip_nr_cell_selection_info(r)

        # cellAccessRelatedInfo: MANDATORY, next in sequence
        # CellAccessRelatedInfo ::= SEQUENCE {
        #     plmn-IdentityInfoList   PLMN-IdentityInfoList,
        #     cellReservedForOtherUse ENUMERATED { true } OPTIONAL,
        #     ...
        # }
        cari_has_ext = r.read_bool()
        cari_opt = r.read_bits(1)  # 1 optional: cellReservedForOtherUse

        # plmn-IdentityInfoList: SEQUENCE (SIZE (1..12))
        num_plmn_entries = r.read_constrained_int(1, 12)

        primary_mcc = ''
        primary_mnc = ''
        primary_tac = 0
        primary_cell_id = 0
        additional_plmns: list[PlmnIdentity] = []

        for entry_idx in range(num_plmn_entries):
            # PLMN-IdentityInfo ::= SEQUENCE { ... } — extensible
            pii_has_ext = r.read_bool()

            # Optional fields: trackingAreaCode(0), ranac(1)
            pii_opt = r.read_bits(2)
            has_tac = (pii_opt >> 1) & 1
            has_ranac = pii_opt & 1

            # plmn-IdentityList: SEQUENCE (SIZE (1..maxPLMN=12))
            num_plmns = r.read_constrained_int(1, 12)
            plmns: list[PlmnIdentity] = []
            for _ in range(num_plmns):
                plmn = decode_plmn_identity(r)
                plmns.append(plmn)

            # trackingAreaCode: BIT STRING (SIZE (24)) — OPTIONAL
            tac = 0
            if has_tac:
                tac = r.read_bits(24)

            # ranac: INTEGER (0..255) — OPTIONAL
            if has_ranac:
                r.read_constrained_int(0, 255)

            # cellIdentity: BIT STRING (SIZE (36))
            cell_id = r.read_bits(36)

            # cellReservedForOperatorUse: ENUMERATED { reserved, notReserved }
            r.read_enum(2)

            # Skip PLMN-IdentityInfo extensions
            if pii_has_ext:
                skip_extension_additions(r)

            if entry_idx == 0:
                # Primary PLMN entry
                if plmns:
                    primary_mcc = plmns[0].mcc
                    primary_mnc = plmns[0].mnc
                    # Additional PLMNs in same entry
                    additional_plmns.extend(plmns[1:])
                primary_tac = tac
                primary_cell_id = cell_id
            else:
                # Additional PLMN entries
                additional_plmns.extend(plmns)

        # Sanity checks
        if len(primary_mcc) != 3 or primary_cell_id == 0:
            return None

        return NrSib1CellId(
            mcc=primary_mcc,
            mnc=primary_mnc,
            tac=primary_tac,
            cell_id=primary_cell_id,
            additional_plmns=additional_plmns if additional_plmns else [],
        )

    except (IndexError, ValueError):
        return None


def _skip_nr_cell_selection_info(r: UperReader) -> None:
    """Skip cellSelectionInfo SEQUENCE.

    CellSelectionInfo ::= SEQUENCE {
        q-RxLevMin              Q-RxLevMin,           -- INTEGER (-70..-22)
        q-RxLevMinOffset        INTEGER (1..8) OPTIONAL,
        q-RxLevMinSUL           Q-RxLevMin OPTIONAL,  -- INTEGER (-70..-22)
        q-QualMin               Q-QualMin OPTIONAL,    -- INTEGER (-43..-12)
        q-QualMinOffset         INTEGER (1..8) OPTIONAL,
    }
    """
    # Not extensible in base spec
    opt = r.read_bits(4)  # 4 optional fields
    r.read_constrained_int(-70, -22)  # q-RxLevMin
    if (opt >> 3) & 1:
        r.read_constrained_int(1, 8)    # q-RxLevMinOffset
    if (opt >> 2) & 1:
        r.read_constrained_int(-70, -22)  # q-RxLevMinSUL
    if (opt >> 1) & 1:
        r.read_constrained_int(-43, -12)  # q-QualMin
    if opt & 1:
        r.read_constrained_int(1, 8)    # q-QualMinOffset
