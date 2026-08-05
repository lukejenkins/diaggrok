# diaggrok-provenance: re
"""NR RRC MeasurementReport decoder for UL-DCCH messages.

Decodes NR MeasurementReport from UPER-encoded UL-DCCH messages to extract
serving cell and neighbor cell measurements (RSRP, RSRQ, SINR).

Implements a minimal UPER decoder for the specific ASN.1 structures defined
in 3GPP TS 38.331:

    UL-DCCH-Message ::= SEQUENCE {
        message     UL-DCCH-MessageType
    }
    UL-DCCH-MessageType ::= CHOICE {
        c1              CHOICE {
            ... (16 alternatives, measurementReport is index 5)
        },
        messageClassExtension   SEQUENCE {}
    }
    MeasurementReport ::= SEQUENCE {
        criticalExtensions CHOICE {
            measurementReport  MeasurementReport-IEs,
            criticalExtensionsFuture SEQUENCE {}
        }
    }
    MeasurementReport-IEs ::= SEQUENCE {
        measResults     MeasResults,
        ...
    }

Reference: 3GPP TS 38.331 v16.x (NR RRC Protocol specification)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from diaggrok.parsers.uper import UperReader
from diaggrok.parsers.asn1_helpers import skip_extension_additions
from diaggrok.parsers.nr5g_signal_levels import (
    MAX_RSRP_RANGE,
    MAX_RSRQ_RANGE,
    MAX_SINR_RANGE,
    rsrp_to_dbm,
    rsrq_to_db,
    sinr_to_db,
)

# ASN.1 constants from 3GPP TS 38.331
_MAX_MEAS_ID = 64         # MeasId ::= INTEGER (1..maxMeasId) where maxMeasId=64
_MAX_NR_PHYS_CELL_ID = 1007  # PhysCellId ::= INTEGER (0..1007)
_MAX_CELL_REPORT = 8      # maxCellReport
_MAX_NR_ARFCN = 3279165   # ARFCN-ValueNR ::= INTEGER (0..3279165)


@dataclass
class NrMeasResultCell:
    """A single NR neighbor cell measurement result."""

    pci: int
    rsrp: Optional[float] = None  # dBm (-156 to -31)
    rsrq: Optional[float] = None  # dB (-43.5 to 20)
    sinr: Optional[float] = None  # dB (-23 to 40)
    # Optional CGI info
    mcc: Optional[str] = None
    mnc: Optional[str] = None
    nci: Optional[int] = None  # NR Cell Identity (36 bits)
    tac: Optional[int] = None  # Tracking Area Code (24 bits)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"pci": self.pci}
        if self.rsrp is not None:
            d["rsrp"] = self.rsrp
        if self.rsrq is not None:
            d["rsrq"] = self.rsrq
        if self.sinr is not None:
            d["sinr"] = self.sinr
        if self.mcc is not None:
            d["mcc"] = self.mcc
            d["mnc"] = self.mnc
            d["nci"] = self.nci
            d["tac"] = self.tac
        return d


@dataclass
class NrMeasurementReport:
    """Decoded NR MeasurementReport."""

    log_time: int
    meas_id: int
    serving_rsrp: Optional[float] = None  # dBm
    serving_rsrq: Optional[float] = None  # dB
    serving_sinr: Optional[float] = None  # dB
    neighbor_cells: list[NrMeasResultCell] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": "NrMeasurementReport",
            "log_time": self.log_time,
            "meas_id": self.meas_id,
        }
        if self.serving_rsrp is not None:
            d["serving_rsrp"] = self.serving_rsrp
        if self.serving_rsrq is not None:
            d["serving_rsrq"] = self.serving_rsrq
        if self.serving_sinr is not None:
            d["serving_sinr"] = self.serving_sinr
        d["neighbor_cells"] = [c.to_dict() for c in self.neighbor_cells]
        return d


def _decode_nr_meas_result(r: UperReader) -> tuple[
    Optional[float], Optional[float], Optional[float]
]:
    """Decode MeasResultNR measurement quantities.

    MeasQuantityResults ::= SEQUENCE {
        rsrp    RSRP-Range  OPTIONAL,  -- INTEGER (0..127)
        rsrq    RSRQ-Range  OPTIONAL,  -- INTEGER (0..127)
        sinr    SINR-Range  OPTIONAL,  -- INTEGER (0..127)
    }

    Returns (rsrp_dbm, rsrq_db, sinr_db).
    """
    # MeasQuantityResults: 3 optionals (rsrp, rsrq, sinr)
    opt = r.read_bits(3)

    rsrp = rsrq = sinr = None
    if (opt >> 2) & 1:  # rsrp
        rsrp = rsrp_to_dbm(r.read_constrained_int(0, MAX_RSRP_RANGE))
    if (opt >> 1) & 1:  # rsrq
        rsrq = rsrq_to_db(r.read_constrained_int(0, MAX_RSRQ_RANGE))
    if opt & 1:  # sinr
        sinr = sinr_to_db(r.read_constrained_int(0, MAX_SINR_RANGE))

    return rsrp, rsrq, sinr


def _decode_meas_result_nr(r: UperReader) -> NrMeasResultCell:
    """Decode a single MeasResultNR entry (neighbor cell).

    MeasResultNR ::= SEQUENCE {
        physCellId          PhysCellId OPTIONAL,      -- INTEGER (0..1007)
        measResult          SEQUENCE {
            cellResults         MeasQuantityResults,
            rsIndexResults      SEQUENCE { ... } OPTIONAL,
            ...
        },
        ...
    }
    """
    has_ext = r.read_bool()

    # MeasResultNR: 1 optional in root (physCellId)
    has_pci = r.read_bool()

    pci = 0
    if has_pci:
        pci = r.read_constrained_int(0, _MAX_NR_PHYS_CELL_ID)

    # measResult SEQUENCE (extensible)
    meas_ext = r.read_bool()

    # measResult has 1 optional: rsIndexResults
    has_rs_index = r.read_bool()

    # cellResults: MeasQuantityResults
    rsrp, rsrq, sinr = _decode_nr_meas_result(r)

    # rsIndexResults (optional): SEQUENCE { ... }
    if has_rs_index:
        _skip_rs_index_results(r)

    if meas_ext:
        skip_extension_additions(r)

    cell = NrMeasResultCell(pci=pci, rsrp=rsrp, rsrq=rsrq, sinr=sinr)

    if has_ext:
        skip_extension_additions(r)

    return cell


def _skip_rs_index_results(r: UperReader) -> None:
    """Skip ResultsPerSSB-IndexList and ResultsPerCSI-RS-IndexList.

    rsIndexResults ::= SEQUENCE {
        resultsSSB-Indexes      ResultsPerSSB-IndexList OPTIONAL,
        resultsCSI-RS-Indexes   ResultsPerCSI-RS-IndexList OPTIONAL,
    }
    ResultsPerSSB-IndexList  ::= SEQUENCE (SIZE (1..maxNrofSSBs=64)) OF ResultsPerSSB-Index
    ResultsPerSSB-Index ::= SEQUENCE {
        ssb-Index       SSB-Index,          -- INTEGER (0..63)
        ssb-Results     MeasQuantityResults OPTIONAL,
        ...
    }
    ResultsPerCSI-RS-IndexList ::= SEQUENCE (SIZE (1..maxNrofCSI-RS=64)) OF ResultsPerCSI-RS-Index
    ResultsPerCSI-RS-Index ::= SEQUENCE {
        csi-RS-Index    CSI-RS-Index,       -- INTEGER (0..95)
        csi-RS-Results  MeasQuantityResults OPTIONAL,
        ...
    }
    """
    opt = r.read_bits(2)  # resultsSSB-Indexes, resultsCSI-RS-Indexes

    if (opt >> 1) & 1:  # resultsSSB-Indexes
        num_ssb = r.read_constrained_int(1, 64)
        for _ in range(num_ssb):
            ssb_ext = r.read_bool()
            has_results = r.read_bool()
            r.read_constrained_int(0, 63)  # ssb-Index
            if has_results:
                _decode_nr_meas_result(r)  # consume MeasQuantityResults
            if ssb_ext:
                skip_extension_additions(r)

    if opt & 1:  # resultsCSI-RS-Indexes
        num_csi = r.read_constrained_int(1, 64)
        for _ in range(num_csi):
            csi_ext = r.read_bool()
            has_results = r.read_bool()
            r.read_constrained_int(0, 95)  # csi-RS-Index
            if has_results:
                _decode_nr_meas_result(r)
            if csi_ext:
                skip_extension_additions(r)


def _decode_meas_result_list_nr(r: UperReader) -> list[NrMeasResultCell]:
    """Decode MeasResultListNR.

    MeasResultListNR ::= SEQUENCE (SIZE (1..maxCellReport)) OF MeasResultNR
    """
    count = r.read_constrained_int(1, _MAX_CELL_REPORT)
    cells: list[NrMeasResultCell] = []
    for _ in range(count):
        cells.append(_decode_meas_result_nr(r))
    return cells


def decode_nr_measurement_report(
    log_time: int, msg_data: bytes
) -> NrMeasurementReport | None:
    """Decode NR MeasurementReport from a UL-DCCH UPER bitstream.

    Navigates the ASN.1 structure:
        UL-DCCH-Message → message → c1 → measurementReport
        → criticalExtensions → measurementReport
        → measResults

    Returns None if the message is not a MeasurementReport or decoding fails.

    Reference: 3GPP TS 38.331 section 6.2.2
    """
    if not msg_data or len(msg_data) < 4:
        return None

    try:
        r = UperReader(msg_data)

        # UL-DCCH-MessageType: CHOICE { c1, messageClassExtension }
        msg_choice = r.read_choice(2)
        if msg_choice != 0:  # not c1
            return None

        # UL-DCCH-MessageType.c1 CHOICE indices per 3GPP TS 38.331 v16
        # (validated against pycrate NR_RRC_Definitions.UL_DCCH_MessageType):
        #   0 = measurementReport
        #   1 = rrcReconfigurationComplete
        #   2 = rrcSetupComplete
        #   3 = rrcReestablishmentComplete
        #   4 = rrcResumeComplete
        #   5 = securityModeComplete
        #   6 = securityModeFailure
        #   7 = ueCapabilityInformation
        #   8 = ulInformationTransfer
        #   9 = counterCheckResponse
        #  10 = ueAssistanceInformation
        #  11 = failureInformation
        #  12 = ulInformationTransferMRDC
        #  13 = scgFailureInformation
        #  14 = scgFailureInformationEUTRA
        #  15 = spare1
        c1_choice = r.read_choice(16)
        if c1_choice != 0:  # not measurementReport
            return None

        # MeasurementReport ::= SEQUENCE {
        #     criticalExtensions CHOICE {
        #         measurementReport  MeasurementReport-IEs,
        #         criticalExtensionsFuture SEQUENCE {}
        #     }
        # }
        crit_choice = r.read_choice(2)
        if crit_choice != 0:  # not measurementReport
            return None

        # MeasurementReport-IEs ::= SEQUENCE {
        #     measResults     MeasResults,
        #     ...
        # }
        mr_has_ext = r.read_bool()

        # No optionals in MeasurementReport-IEs root

        # MeasResults ::= SEQUENCE {
        #     measId                      MeasId,             -- INTEGER (1..maxMeasId)
        #     measResultServingMOList     MeasResultServMOList, -- SIZE (1..maxNrofServingCells=32)
        #     measResultNeighCells        CHOICE { ... }      OPTIONAL,
        #     ...
        # }
        meas_has_ext = r.read_bool()

        # MeasResults optionals: measResultNeighCells = 1
        has_neigh = r.read_bool()

        # measId: INTEGER (1..maxMeasId)
        meas_id = r.read_constrained_int(1, _MAX_MEAS_ID)

        # measResultServingMOList: SEQUENCE (SIZE (1..maxNrofServingCells=32))
        # OF MeasResultServMO
        num_serving = r.read_constrained_int(1, 32)

        serving_rsrp = serving_rsrq = serving_sinr = None
        for i in range(num_serving):
            # MeasResultServMO ::= SEQUENCE {
            #     servCellId              ServCellIndex,       -- INTEGER (0..31)
            #     measResultServingCell   MeasResultNR,
            #     measResultBestNeighCell MeasResultNR OPTIONAL,
            #     ...
            # }
            smo_ext = r.read_bool()
            smo_opt = r.read_bits(1)  # measResultBestNeighCell optional

            r.read_constrained_int(0, 31)  # servCellId

            # measResultServingCell: MeasResultNR (decode for PCell)
            serv_cell = _decode_meas_result_nr(r)

            # Keep the first serving cell (PCell) measurements
            if i == 0:
                serving_rsrp = serv_cell.rsrp
                serving_rsrq = serv_cell.rsrq
                serving_sinr = serv_cell.sinr

            # measResultBestNeighCell (optional)
            if smo_opt & 1:
                _decode_meas_result_nr(r)  # consume but discard

            if smo_ext:
                skip_extension_additions(r)

        # measResultNeighCells (OPTIONAL)
        neighbor_cells: list[NrMeasResultCell] = []
        if has_neigh:
            # CHOICE (extensible):
            #   0 = measResultListNR
            #   1 = (reserved/future)
            neigh_ext = r.read_bool()
            if not neigh_ext:
                neigh_choice = r.read_choice(2)
                if neigh_choice == 0:
                    # measResultListNR — the primary case
                    neighbor_cells = _decode_meas_result_list_nr(r)
            # Extension alternatives (inter-RAT) not decoded

        return NrMeasurementReport(
            log_time=log_time,
            meas_id=meas_id,
            serving_rsrp=serving_rsrp,
            serving_rsrq=serving_rsrq,
            serving_sinr=serving_sinr,
            neighbor_cells=neighbor_cells,
        )

    except (IndexError, ValueError):
        return None
