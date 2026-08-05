# diaggrok-provenance: re
"""LTE RRC MeasurementReport decoder for UL-DCCH messages.

Decodes MeasurementReport from UPER-encoded UL-DCCH messages to extract
primary cell and neighbor cell measurements. When CGI reporting is enabled
by the network, neighbor cells include full cell identity (MCC/MNC/CID/TAC).

Implements a minimal UPER decoder for the specific ASN.1 structures defined
in 3GPP TS 36.331:

    UL-DCCH-Message ::= SEQUENCE {
        message     UL-DCCH-MessageType
    }
    UL-DCCH-MessageType ::= CHOICE {
        c1              CHOICE {
            ... (16 alternatives, measurementReport is index 1)
        },
        messageClassExtension   SEQUENCE {}
    }
    MeasurementReport ::= SEQUENCE {
        criticalExtensions CHOICE {
            c1 CHOICE {
                measurementReport-r8 MeasurementReport-r8-IEs,
                spare7, spare6, ... spare1  (8 alternatives total)
            },
            criticalExtensionsFuture SEQUENCE {}
        }
    }
    MeasurementReport-r8-IEs ::= SEQUENCE {
        measResults MeasResults,
        ...
    }

Reference: 3GPP TS 36.331 v16.x (E-UTRA RRC Protocol specification)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from diaggrok.parsers.uper import UperReader
from diaggrok.parsers.asn1_helpers import decode_plmn_identity, skip_extension_additions
from diaggrok.parsers.lte_signal_levels import (
    MAX_RSRP_RANGE,
    MAX_RSRQ_RANGE,
    rsrp_to_dbm,
    rsrq_to_db,
)

# ASN.1 constants from 3GPP TS 36.331
_MAX_MEAS_ID = 32        # INTEGER (1..maxMeasId)
_MAX_PHYS_CELL_ID = 503  # PhysCellId ::= INTEGER (0..503)
_MAX_CELL_REPORT = 8     # maxCellReport — max neighbor cells in one report


@dataclass
class MeasResultCell:
    """A single neighbor cell measurement result."""
    pci: int
    rsrp: Optional[float] = None   # dBm (-140 to -44)
    rsrq: Optional[float] = None   # dB (-19.5 to -3)
    # CGI info (when present -- this is neighbor cell identity!)
    mcc: Optional[str] = None
    mnc: Optional[str] = None
    cid: Optional[int] = None
    tac: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'pci': self.pci,
        }
        if self.rsrp is not None:
            d['rsrp'] = self.rsrp
        if self.rsrq is not None:
            d['rsrq'] = self.rsrq
        if self.mcc is not None:
            d['mcc'] = self.mcc
            d['mnc'] = self.mnc
            d['cid'] = self.cid
            d['tac'] = self.tac
        return d


@dataclass
class LteMeasurementReport:
    """Decoded MeasurementReport."""
    log_time: int
    meas_id: int
    pcell_rsrp: float              # dBm
    pcell_rsrq: float              # dB
    neighbor_cells: list[MeasResultCell] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'LteMeasurementReport',
            'log_time': self.log_time,
            'meas_id': self.meas_id,
            'pcell_rsrp': self.pcell_rsrp,
            'pcell_rsrq': self.pcell_rsrq,
            'neighbor_cells': [c.to_dict() for c in self.neighbor_cells],
        }


def _decode_cgi_info_eutra(r: UperReader) -> tuple[
    Optional[str], Optional[str], Optional[int], Optional[int]
]:
    """Decode cgi-Info for E-UTRA neighbor cell.

    cgi-Info ::= SEQUENCE {
        cellGlobalId        CellGlobalIdEUTRA,
        trackingAreaCode    TrackingAreaCode,        -- BIT STRING (SIZE 16)
        plmn-IdentityList   PLMN-IdentityList2       OPTIONAL
    }

    CellGlobalIdEUTRA ::= SEQUENCE {
        plmn-Identity       PLMN-Identity,
        cellIdentity        CellIdentity             -- BIT STRING (SIZE 28)
    }

    Returns (mcc, mnc, cid, tac).
    """
    # cgi-Info SEQUENCE has 1 OPTIONAL field (plmn-IdentityList)
    has_plmn_list = r.read_bool()

    # CellGlobalIdEUTRA: PLMN-Identity + cellIdentity
    plmn = decode_plmn_identity(r)
    cell_identity = r.read_bits(28)

    # trackingAreaCode: BIT STRING (SIZE (16))
    tac = r.read_bits(16)

    # plmn-IdentityList: SEQUENCE (SIZE (1..5)) OF PLMN-Identity (OPTIONAL)
    if has_plmn_list:
        num_plmns = r.read_constrained_int(1, 5)
        for _ in range(num_plmns):
            decode_plmn_identity(r)  # consume but discard additional PLMNs

    return plmn.mcc or None, plmn.mnc or None, cell_identity, tac


def _decode_meas_result_eutra(r: UperReader) -> MeasResultCell:
    """Decode a single MeasResultEUTRA entry.

    MeasResultEUTRA ::= SEQUENCE {
        physCellId      PhysCellId,                 -- INTEGER (0..503)
        cgi-Info        SEQUENCE { ... }            OPTIONAL,
        measResult      SEQUENCE {
            rsrpResult      RSRP-Range              OPTIONAL,
            rsrqResult      RSRQ-Range              OPTIONAL,
            ...
        }
    }
    """
    # MeasResultEUTRA is an extensible SEQUENCE (has extension marker)
    # But the base part has 1 OPTIONAL: cgi-Info
    # Read the extension bit first
    has_ext = r.read_bool()

    # OPTIONAL presence bitmap: cgi-Info
    has_cgi = r.read_bool()

    # physCellId: INTEGER (0..503)
    pci = r.read_constrained_int(0, _MAX_PHYS_CELL_ID)

    # cgi-Info (OPTIONAL)
    mcc = mnc = None
    cid = tac = None
    if has_cgi:
        mcc, mnc, cid, tac = _decode_cgi_info_eutra(r)

    # measResult: SEQUENCE with extension marker
    meas_ext = r.read_bool()

    # measResult has 2 OPTIONAL fields: rsrpResult, rsrqResult
    has_rsrp = r.read_bool()
    has_rsrq = r.read_bool()

    rsrp = None
    rsrq = None
    if has_rsrp:
        rsrp = rsrp_to_dbm(r.read_constrained_int(0, MAX_RSRP_RANGE))
    if has_rsrq:
        rsrq = rsrq_to_db(r.read_constrained_int(0, MAX_RSRQ_RANGE))

    # If measResult has extensions, skip them so the bit reader advances
    # past the extension data before parsing the next neighbor cell
    if meas_ext:
        skip_extension_additions(r)

    cell = MeasResultCell(pci=pci, rsrp=rsrp, rsrq=rsrq)
    if mcc is not None:
        cell.mcc = mcc
        cell.mnc = mnc
        cell.cid = cid
        cell.tac = tac

    # Skip MeasResultEUTRA extensions (e.g., additionalSI-Info-r9)
    if has_ext:
        skip_extension_additions(r)

    return cell


def _decode_meas_result_list_eutra(r: UperReader) -> list[MeasResultCell]:
    """Decode MeasResultListEUTRA.

    MeasResultListEUTRA ::= SEQUENCE (SIZE (1..maxCellReport)) OF MeasResultEUTRA
    """
    count = r.read_constrained_int(1, _MAX_CELL_REPORT)
    cells: list[MeasResultCell] = []
    for _ in range(count):
        cells.append(_decode_meas_result_eutra(r))
    return cells


def decode_measurement_report(
    log_time: int, msg_data: bytes
) -> LteMeasurementReport | None:
    """Decode MeasurementReport from a UL-DCCH UPER bitstream.

    Navigates the ASN.1 structure:
        UL-DCCH-Message -> message -> c1 -> measurementReport
        -> criticalExtensions -> c1 -> measurementReport-r8
        -> measResults

    Returns None if the message is not a MeasurementReport or decoding fails.

    Reference: 3GPP TS 36.331 section 6.2.2
    """
    if not msg_data or len(msg_data) < 4:
        return None

    try:
        r = UperReader(msg_data)

        # UL-DCCH-MessageType: CHOICE { c1, messageClassExtension }
        msg_choice = r.read_choice(2)
        if msg_choice != 0:  # not c1
            return None

        # c1: CHOICE of 16 alternatives
        # measurementReport is index 1 (0-based):
        #   0 = csfbParametersRequestCDMA2000
        #   1 = measurementReport
        #   2 = rrcConnectionReconfigurationComplete
        #   ...
        c1_choice = r.read_choice(16)
        if c1_choice != 1:  # not measurementReport
            return None

        # MeasurementReport ::= SEQUENCE {
        #     criticalExtensions CHOICE {
        #         c1 CHOICE { measurementReport-r8, spare7..spare1 } (8 alts),
        #         criticalExtensionsFuture SEQUENCE {}
        #     }
        # }
        crit_choice = r.read_choice(2)
        if crit_choice != 0:  # not c1
            return None

        c1_meas_choice = r.read_choice(8)
        if c1_meas_choice != 0:  # not measurementReport-r8
            return None

        # MeasurementReport-r8-IEs ::= SEQUENCE {
        #     measResults     MeasResults,
        #     ...
        # }
        # Extension marker
        r8_has_ext = r.read_bool()

        # MeasResults ::= SEQUENCE {
        #     measId                  INTEGER (1..maxMeasId),
        #     measResultPCell         SEQUENCE { rsrpResult, rsrqResult },
        #     measResultNeighCells    CHOICE { ... } OPTIONAL,
        #     ...
        # }
        # Extension marker for MeasResults
        meas_has_ext = r.read_bool()

        # OPTIONAL bitmap: measResultNeighCells (1 optional field)
        has_neigh = r.read_bool()

        # measId: INTEGER (1..maxMeasId)
        meas_id = r.read_constrained_int(1, _MAX_MEAS_ID)

        # measResultPCell (a.k.a. measResultServCell in older specs)
        # SEQUENCE { rsrpResult RSRP-Range, rsrqResult RSRQ-Range }
        # No extension marker, no optionals — both fields are mandatory
        pcell_rsrp_raw = r.read_constrained_int(0, MAX_RSRP_RANGE)
        pcell_rsrq_raw = r.read_constrained_int(0, MAX_RSRQ_RANGE)

        pcell_rsrp = rsrp_to_dbm(pcell_rsrp_raw)
        pcell_rsrq = rsrq_to_db(pcell_rsrq_raw)

        # measResultNeighCells (OPTIONAL)
        neighbor_cells: list[MeasResultCell] = []
        if has_neigh:
            # CHOICE with extension marker:
            #   0 = measResultListEUTRA
            #   1 = measResultListUTRA
            #   2 = measResultListGERAN
            #   3 = measResultsCDMA2000
            neigh_ext = r.read_bool()  # extension bit for the CHOICE
            if not neigh_ext:
                neigh_choice = r.read_choice(4)
                if neigh_choice == 0:
                    # measResultListEUTRA — the most common case
                    neighbor_cells = _decode_meas_result_list_eutra(r)
                # UTRA/GERAN/CDMA2000 not decoded yet — skip gracefully

        return LteMeasurementReport(
            log_time=log_time,
            meas_id=meas_id,
            pcell_rsrp=pcell_rsrp,
            pcell_rsrq=pcell_rsrq,
            neighbor_cells=neighbor_cells,
        )

    except (IndexError, ValueError):
        return None
