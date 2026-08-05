# diaggrok-provenance: re
"""NR RRC RRCReconfiguration measConfig decoder.

Decodes measConfig from DL-DCCH RRCReconfiguration messages to extract
NR measurement objects (NR-ARFCNs, SSB subcarrier spacing, neighbor PCIs).

From-scratch UPER decoder -- no pycrate or other ASN.1 library dependency.
Receives the RRC message payload from within a 0xB821 frame (DL-DCCH channel).

ASN.1 path (3GPP TS 38.331):
    DL-DCCH-Message
      -> message (DL-DCCH-MessageType)
        -> c1 (CHOICE, 16 alternatives)
          -> rrcReconfiguration (index 0)
            -> rrc-TransactionIdentifier
            -> criticalExtensions
              -> rrcReconfiguration
                -> RRCReconfiguration-IEs
                  -> measConfig (OPTIONAL)
                    -> measObjectToAddModList (OPTIONAL)
                      -> MeasObjectToAddMod
                        -> measObject (CHOICE)
                          -> measObjectNR
                            -> ssbFrequency, ssbSubcarrierSpacing, ...

Reference: 3GPP TS 38.331 v16.x (NR RRC Protocol specification)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from diaggrok.parsers.uper import UperReader
from diaggrok.parsers.asn1_helpers import (
    SCS_KHZ,
    read_open_type_length,
    skip_extension_additions,
)

# ASN.1 constants from 3GPP TS 38.331
_MAX_MEAS_ID = 64          # MeasId ::= INTEGER (1..maxMeasId)
_MAX_MEAS_OBJ_ID = 64      # MeasObjectId ::= INTEGER (1..maxNrofObjectId)
_MAX_NR_ARFCN = 3279165    # ARFCN-ValueNR ::= INTEGER (0..3279165)
_MAX_NR_PCI = 1007          # PhysCellId ::= INTEGER (0..1007)
_MAX_CELL_IDX = 32          # maxNrofCellMeas = 32
_MAX_PCI_RANGE = 8          # maxNrofPCIsPerSMTC / PCI-RangeIndex = 8
_MAX_MEAS_OBJ_LIST = 64    # maxNrofObjectId = 64
_MAX_REPORT_CONFIG_ID = 64  # ReportConfigId ::= INTEGER (1..maxReportConfigId)

@dataclass
class NrCellToAddMod:
    """A single neighbor cell from cellsToAddModList in MeasObjectNR.

    NR's CellsToAddMod (TS 38.331) is ``{ physCellId, cellIndividualOffset }`` —
    note there is NO ``cellIndex`` field (that is the LTE TS 36.331 shape). The
    cellIndividualOffset (a Q-OffsetRangeList of DEFAULT-dB0 enums) is walked but
    not surfaced; only the PCI is retained for neighbor-cell reporting.
    """

    pci: int  # PhysCellId (0..1007)

    def to_dict(self) -> dict[str, Any]:
        return {"pci": self.pci}


@dataclass
class MeasObjectNR:
    """A single NR measurement object — a frequency the UE must measure."""

    ssb_frequency: Optional[int] = None  # ARFCN-ValueNR (0..3279165)
    ssb_subcarrier_spacing: Optional[int] = None  # kHz (15, 30, 60, 120, 240)
    cells: list[NrCellToAddMod] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        if self.ssb_frequency is not None:
            d["ssb_frequency"] = self.ssb_frequency
        if self.ssb_subcarrier_spacing is not None:
            d["ssb_subcarrier_spacing"] = self.ssb_subcarrier_spacing
        if self.cells:
            d["cells"] = [c.to_dict() for c in self.cells]
        return d


@dataclass
class MeasObjectEUTRA:
    """An inter-RAT EUTRA measurement object from NR measConfig."""

    earfcn: int  # ARFCN-ValueEUTRA (0..262143 in NR spec)

    def to_dict(self) -> dict[str, Any]:
        return {"earfcn": self.earfcn}


@dataclass
class NrRRCMeasConfig:
    """Decoded NR measurement configuration from RRCReconfiguration."""

    log_time: int
    nr_objects: list[MeasObjectNR] = field(default_factory=list)
    eutra_objects: list[MeasObjectEUTRA] = field(default_factory=list)
    s_measure_ssb: Optional[int] = None  # SSB-RSRP threshold (0..127)
    s_measure_csi: Optional[int] = None  # CSI-RSRP threshold (0..127)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": "NrRRCMeasConfig",
            "log_time": self.log_time,
            "nr_objects": [m.to_dict() for m in self.nr_objects],
        }
        if self.eutra_objects:
            d["eutra_objects"] = [m.to_dict() for m in self.eutra_objects]
        if self.s_measure_ssb is not None:
            d["s_measure_ssb"] = self.s_measure_ssb
        if self.s_measure_csi is not None:
            d["s_measure_csi"] = self.s_measure_csi
        return d


# -----------------------------------------------------------------------
# MeasObjectNR decoder
# -----------------------------------------------------------------------


def _decode_cells_to_add_mod_list_nr(r: UperReader) -> list[NrCellToAddMod]:
    """Decode CellsToAddModList for NR (TS 38.331).

    CellsToAddModList ::= SEQUENCE (SIZE (1..maxNrofCellMeas=32)) OF CellsToAddMod
    CellsToAddMod ::= SEQUENCE {          -- NOT extensible, no preamble
        physCellId            PhysCellId,           -- INTEGER (0..1007)
        cellIndividualOffset  Q-OffsetRangeList     -- mandatory SEQUENCE
    }

    NR has no ``cellIndex`` field (unlike LTE). ``cellIndividualOffset`` is a
    Q-OffsetRangeList (six DEFAULT-dB0 enums, a 6-bit presence preamble) that is
    walked to stay byte-aligned but not surfaced.
    """
    num = r.read_constrained_int(1, _MAX_CELL_IDX)
    cells = []
    for _ in range(num):
        pci = r.read_constrained_int(0, _MAX_NR_PCI)
        _skip_q_offset_range_list(r)  # cellIndividualOffset (mandatory)
        cells.append(NrCellToAddMod(pci=pci))
    return cells


def _skip_pci_range_list(r: UperReader) -> None:
    """Skip PCI-RangeElementList.

    PCI-RangeElementList ::= SEQUENCE (SIZE (1..8)) OF PCI-RangeElement
    PCI-RangeElement ::= SEQUENCE {
        pci-RangeIndex  PCI-RangeIndex,   -- INTEGER (1..maxNrofPCI-Range=8)
        pci-Range       PCI-Range
    }
    PCI-Range ::= SEQUENCE {
        start   PhysCellId,               -- INTEGER (0..1007)
        range   ENUMERATED {n4..n504} OPTIONAL  -- 16 values
    }
    """
    num = r.read_constrained_int(1, _MAX_PCI_RANGE)
    for _ in range(num):
        r.read_constrained_int(1, _MAX_PCI_RANGE)  # pci-RangeIndex
        # PCI-Range
        r.read_constrained_int(0, _MAX_NR_PCI)  # start
        has_range = r.read_bool()
        if has_range:
            r.read_enum(16)  # range: 16 values


def _skip_ssb_config_mobility(r: UperReader) -> None:
    """Skip SSB-ConfigMobility (extensible SEQUENCE).

    SSB-ConfigMobility ::= SEQUENCE {
        ssb-ToMeasure               SSB-ToMeasure OPTIONAL,
        deriveSSB-IndexFromCell     BOOLEAN,
        ss-RSSI-Measurement         SS-RSSI-Measurement OPTIONAL,
        ...
    }
    """
    ext = r.read_bool()
    opt = r.read_bits(2)  # ssb-ToMeasure, ss-RSSI-Measurement

    if (opt >> 1) & 1:  # ssb-ToMeasure (CHOICE)
        _skip_ssb_to_measure(r)

    r.read_bool()  # deriveSSB-IndexFromCell

    if opt & 1:  # ss-RSSI-Measurement
        _skip_ss_rssi_measurement(r)

    if ext:
        skip_extension_additions(r)


def _skip_ssb_to_measure(r: UperReader) -> None:
    """Skip SSB-ToMeasure (CHOICE).

    SSB-ToMeasure ::= CHOICE {
        shortBitmap     BIT STRING (SIZE (4)),
        mediumBitmap    BIT STRING (SIZE (8)),
        longBitmap      BIT STRING (SIZE (64))
    }
    """
    choice = r.read_choice(3)
    if choice == 0:
        r.read_bits(4)
    elif choice == 1:
        r.read_bits(8)
    else:
        r.read_bits(64)


def _skip_ss_rssi_measurement(r: UperReader) -> None:
    """Skip SS-RSSI-Measurement.

    SS-RSSI-Measurement ::= SEQUENCE {
        measurementSlots    BIT STRING (SIZE (1..80)),
        endSymbol           INTEGER (0..3)
    }
    """
    # BIT STRING with constrained SIZE (1..80)
    bitmask_len = r.read_constrained_int(1, 80)
    r.skip_bits(bitmask_len)
    r.read_constrained_int(0, 3)  # endSymbol


def _decode_meas_object_nr(r: UperReader) -> MeasObjectNR:
    """Decode MeasObjectNR from UPER.

    MeasObjectNR ::= SEQUENCE {
        ssbFrequency                ARFCN-ValueNR OPTIONAL,
        ssbSubcarrierSpacing        SubcarrierSpacing OPTIONAL,
        smtc1                       SSB-MTC OPTIONAL,
        smtc2                       SSB-MTC2 OPTIONAL,
        refFreqCSI-RS               ARFCN-ValueNR OPTIONAL,
        referenceSignalConfig       ReferenceSignalConfig,
        absThreshSS-BlocksConsolidation ThresholdNR OPTIONAL,
        absThreshCSI-RS-Consolidation   ThresholdNR OPTIONAL,
        nrofSS-BlocksToAverage      INTEGER (2..maxNrofSS-BlocksToAverage=16) OPTIONAL,
        nrofCSI-RS-ResourcesToAverage INTEGER (2..maxNrofCSI-RS-ResourcesToAverage=16) OPTIONAL,
        quantityConfigIndex         INTEGER (1..maxNrofQuantityConfig=2),
        offsetMO                    Q-OffsetRangeList OPTIONAL,
        cellsToRemoveList           PCI-List OPTIONAL,
        cellsToAddModList           CellsToAddModList OPTIONAL,
        excludedCellsToRemoveList   PCI-RangeIndexList OPTIONAL,
        excludedCellsToAddModList   PCI-RangeElementList OPTIONAL,
        allowedCellsToRemoveList    PCI-RangeIndexList OPTIONAL,
        allowedCellsToAddModList    PCI-RangeElementList OPTIONAL,
        ...
    }
    """
    obj = MeasObjectNR()

    ext = r.read_bool()

    # MeasObjectNR carries exactly 15 root OPTIONAL fields (validated against
    # pycrate's compiled TS 38.331 v17 grammar, #N). referenceSignalConfig,
    # quantityConfigIndex, AND offsetMO are MANDATORY — a prior 16-bit read that
    # treated offsetMO as optional consumed one phantom bit and desynced every
    # object. Optional bitmap (MSB=bit14 → LSB=bit0), in declaration order:
    #   14 ssbFrequency         13 ssbSubcarrierSpacing  12 smtc1
    #   11 smtc2                 10 refFreqCSI-RS          9 absThreshSS
    #    8 absThreshCSI          7 nrofSS-BlocksToAvg      6 nrofCSI-RS-ToAvg
    #    5 cellsToRemoveList     4 cellsToAddModList       3 excludedCellsToRemove
    #    2 excludedCellsToAddMod 1 allowedCellsToRemove    0 allowedCellsToAddMod
    opt = r.read_bits(15)

    # ssbFrequency (optional)
    if (opt >> 14) & 1:
        obj.ssb_frequency = r.read_constrained_int(0, _MAX_NR_ARFCN)

    # ssbSubcarrierSpacing (optional)
    if (opt >> 13) & 1:
        scs_idx = r.read_enum(8)  # SubcarrierSpacing: 8 values (kHz15..spare1)
        if scs_idx < len(SCS_KHZ):
            obj.ssb_subcarrier_spacing = SCS_KHZ[scs_idx]

    # smtc1 (optional): SSB-MTC
    if (opt >> 12) & 1:
        _skip_ssb_mtc(r)

    # smtc2 (optional): SSB-MTC2
    if (opt >> 11) & 1:
        _skip_ssb_mtc2(r)

    # refFreqCSI-RS (optional)
    if (opt >> 10) & 1:
        r.read_constrained_int(0, _MAX_NR_ARFCN)  # refFreqCSI-RS

    # referenceSignalConfig (mandatory): ReferenceSignalConfig
    _skip_reference_signal_config(r)

    # absThreshSS-BlocksConsolidation (optional): ThresholdNR
    if (opt >> 9) & 1:
        _skip_threshold_nr(r)

    # absThreshCSI-RS-Consolidation (optional): ThresholdNR
    if (opt >> 8) & 1:
        _skip_threshold_nr(r)

    # nrofSS-BlocksToAverage (optional)
    if (opt >> 7) & 1:
        r.read_constrained_int(2, 16)

    # nrofCSI-RS-ResourcesToAverage (optional)
    if (opt >> 6) & 1:
        r.read_constrained_int(2, 16)

    # quantityConfigIndex (mandatory): INTEGER (1..maxNrofQuantityConfig=2)
    r.read_constrained_int(1, 2)

    # offsetMO (mandatory): Q-OffsetRangeList
    _skip_q_offset_range_list(r)

    # cellsToRemoveList (optional): PCI-List SIZE (1..32) OF PhysCellId
    if (opt >> 5) & 1:
        num = r.read_constrained_int(1, _MAX_CELL_IDX)
        for _ in range(num):
            r.read_constrained_int(0, _MAX_NR_PCI)

    # cellsToAddModList (optional)
    if (opt >> 4) & 1:
        obj.cells = _decode_cells_to_add_mod_list_nr(r)

    # excludedCellsToRemoveList (optional): PCI-RangeIndexList SIZE (1..8)
    #   OF PCI-RangeIndex INTEGER (1..8)
    if (opt >> 3) & 1:
        num = r.read_constrained_int(1, _MAX_PCI_RANGE)
        for _ in range(num):
            r.read_constrained_int(1, _MAX_PCI_RANGE)

    # excludedCellsToAddModList (optional): PCI-RangeElementList
    if (opt >> 2) & 1:
        _skip_pci_range_list(r)

    # allowedCellsToRemoveList (optional): PCI-RangeIndexList SIZE (1..8)
    if (opt >> 1) & 1:
        num = r.read_constrained_int(1, _MAX_PCI_RANGE)
        for _ in range(num):
            r.read_constrained_int(1, _MAX_PCI_RANGE)

    # allowedCellsToAddModList (optional): PCI-RangeElementList
    if opt & 1:
        _skip_pci_range_list(r)

    if ext:
        skip_extension_additions(r)

    return obj


def _skip_ssb_mtc(r: UperReader) -> None:
    """Skip SSB-MTC (not extensible).

    SSB-MTC ::= SEQUENCE {
        periodicityAndOffset  CHOICE { ... },  -- 6 alternatives
        duration              ENUMERATED {sf1..sf5} -- 5 values
    }
    """
    # periodicityAndOffset CHOICE (6 alternatives)
    choice = r.read_choice(6)
    if choice == 0:
        pass  # sf5: NULL (periodicity only)
    elif choice == 1:
        r.read_constrained_int(0, 9)  # sf10: INTEGER (0..9)
    elif choice == 2:
        r.read_constrained_int(0, 19)  # sf20
    elif choice == 3:
        r.read_constrained_int(0, 39)  # sf40
    elif choice == 4:
        r.read_constrained_int(0, 79)  # sf80
    elif choice == 5:
        r.read_constrained_int(0, 159)  # sf160
    r.read_enum(5)  # duration: sf1..sf5


def _skip_ssb_mtc2(r: UperReader) -> None:
    """Skip SSB-MTC2 (not extensible).

    SSB-MTC2 ::= SEQUENCE {
        pci-List    SEQUENCE (SIZE (1..maxNrofCellMeas=32)) OF PhysCellId OPTIONAL,
        periodicity ENUMERATED {sf5, sf10, sf20, sf40, sf80, sf160, spare2, spare1}
    }
    """
    has_pci_list = r.read_bool()
    if has_pci_list:
        num = r.read_constrained_int(1, _MAX_CELL_IDX)
        for _ in range(num):
            r.read_constrained_int(0, _MAX_NR_PCI)
    r.read_enum(8)  # periodicity: 8 values


def _skip_reference_signal_config(r: UperReader) -> None:
    """Skip ReferenceSignalConfig (not extensible).

    ReferenceSignalConfig ::= SEQUENCE {
        ssb-ConfigMobility      SSB-ConfigMobility OPTIONAL,
        csi-rs-ResourceConfigMobility  CSI-RS-ResourceConfigMobility OPTIONAL,
    }
    """
    opt = r.read_bits(2)
    if (opt >> 1) & 1:
        _skip_ssb_config_mobility(r)
    if opt & 1:
        _skip_csi_rs_resource_config_mobility(r)


def _skip_csi_rs_resource_config_mobility(r: UperReader) -> None:
    """Skip CSI-RS-ResourceConfigMobility (extensible).

    CSI-RS-ResourceConfigMobility ::= SEQUENCE {
        subcarrierSpacing    SubcarrierSpacing,
        csi-RS-CellList-Mobility  SEQUENCE (SIZE (1..maxNrofCSI-RS-CellsRRM=96)) OF CSI-RS-CellMobility,
        ...
    }
    """
    ext = r.read_bool()
    r.read_enum(8)  # subcarrierSpacing
    num = r.read_constrained_int(1, 96)
    for _ in range(num):
        _skip_csi_rs_cell_mobility(r)
    if ext:
        skip_extension_additions(r)


def _skip_csi_rs_cell_mobility(r: UperReader) -> None:
    """Skip CSI-RS-CellMobility (not extensible).

    CSI-RS-CellMobility ::= SEQUENCE {
        cellId                  PhysCellId,
        csi-rs-MeasurementBW    SEQUENCE { ... },
        density                 ENUMERATED OPTIONAL,
        csi-rs-ResourceList-Mobility  SEQUENCE (SIZE 1..maxNrofCSI-RS-ResourcesRRM=96) OF ...
    }
    """
    opt = r.read_bits(1)  # density optional
    r.read_constrained_int(0, _MAX_NR_PCI)  # cellId

    # csi-rs-MeasurementBW (not extensible)
    r.read_enum(4)  # nrofPRBs: ENUMERATED {size24, size48, size96, size192} = 4
    r.read_constrained_int(0, 2169)  # startPRB: INTEGER (0..2169)

    if opt & 1:
        r.read_enum(3)  # density: ENUMERATED {d1, d3, spare2, spare1} in context

    # csi-rs-ResourceList-Mobility
    num_res = r.read_constrained_int(1, 96)
    for _ in range(num_res):
        _skip_csi_rs_resource(r)


def _skip_csi_rs_resource(r: UperReader) -> None:
    """Skip CSI-RS-Resource-Mobility (extensible).

    CSI-RS-Resource-Mobility ::= SEQUENCE {
        csi-RS-Index              CSI-RS-Index,  -- INTEGER (0..95)
        slotConfig                CHOICE { ... },
        associatedSSB             SEQUENCE { ... } OPTIONAL,
        frequencyDomainAllocation CHOICE { ... },
        firstOFDMSymbolInTimeDomain INTEGER (0..13),
        sequenceGenerationConfig  INTEGER (0..1023),
        ...
    }
    """
    ext = r.read_bool()
    opt = r.read_bits(1)  # associatedSSB optional
    r.read_constrained_int(0, 95)  # csi-RS-Index

    # slotConfig: CHOICE (3 alternatives)
    slot_choice = r.read_choice(3)
    if slot_choice == 0:
        r.read_constrained_int(0, 319)  # ms4
    elif slot_choice == 1:
        r.read_constrained_int(0, 639)  # ms5
    elif slot_choice == 2:
        r.read_constrained_int(0, 2559)  # ms10..ms40

    if opt & 1:  # associatedSSB
        r.read_constrained_int(0, 63)  # ssb-Index
        r.read_bool()  # isQuasiColocated

    # frequencyDomainAllocation: CHOICE
    fda_choice = r.read_choice(2)
    if fda_choice == 0:
        r.read_bits(4)  # row1: BIT STRING (SIZE (4))
    else:
        r.read_bits(12)  # row2: BIT STRING (SIZE (12))

    r.read_constrained_int(0, 13)  # firstOFDMSymbolInTimeDomain
    r.read_constrained_int(0, 1023)  # sequenceGenerationConfig

    if ext:
        skip_extension_additions(r)


def _skip_threshold_nr(r: UperReader) -> None:
    """Skip ThresholdNR.

    ThresholdNR ::= SEQUENCE {
        thresholdRSRP   RSRP-Range OPTIONAL,   -- INTEGER (0..127)
        thresholdRSRQ   RSRQ-Range OPTIONAL,   -- INTEGER (0..127)
        thresholdSINR   SINR-Range OPTIONAL,   -- INTEGER (0..127)
    }
    """
    opt = r.read_bits(3)
    if (opt >> 2) & 1:
        r.read_constrained_int(0, 127)  # RSRP
    if (opt >> 1) & 1:
        r.read_constrained_int(0, 127)  # RSRQ
    if opt & 1:
        r.read_constrained_int(0, 127)  # SINR


def _skip_q_offset_range_list(r: UperReader) -> None:
    """Skip Q-OffsetRangeList.

    Q-OffsetRangeList ::= SEQUENCE {
        rsrpOffsetSSB       Q-OffsetRange OPTIONAL,   -- ENUMERATED (31 values)
        rsrqOffsetSSB       Q-OffsetRange OPTIONAL,
        sinrOffsetSSB       Q-OffsetRange OPTIONAL,
        rsrpOffsetCSI-RS    Q-OffsetRange OPTIONAL,
        rsrqOffsetCSI-RS    Q-OffsetRange OPTIONAL,
        sinrOffsetCSI-RS    Q-OffsetRange OPTIONAL,
    }
    """
    opt = r.read_bits(6)
    for i in range(6):
        if (opt >> (5 - i)) & 1:
            r.read_enum(31)


# -----------------------------------------------------------------------
# MeasObjectEUTRA decoder (inter-RAT from NR)
# -----------------------------------------------------------------------


def _decode_meas_object_eutra(r: UperReader) -> MeasObjectEUTRA:
    """Decode MeasObjectEUTRA from NR measConfig (simplified — extract EARFCN only).

    MeasObjectEUTRA ::= SEQUENCE {
        carrierFreq             ARFCN-ValueEUTRA,   -- INTEGER (0..262143 in NR)
        allowedMeasBandwidth    EUTRA-AllowedMeasBandwidth,  -- ENUMERATED (6)
        cellsToRemoveListEUTRA  EUTRA-CellIndexList OPTIONAL,
        cellsToAddModListEUTRA  SEQUENCE (...) OPTIONAL,
        excludedCellsToRemoveListEUTRA  EUTRA-CellIndexList OPTIONAL,
        excludedCellsToAddModListEUTRA  SEQUENCE (...) OPTIONAL,
        eutra-PresenceAntennaPort1 EUTRA-PresenceAntennaPort1,
        eutra-Q-OffsetRange     EUTRA-Q-OffsetRange OPTIONAL,
        widebandRSRQ-Meas       BOOLEAN,
        ...
    }
    """
    ext = r.read_bool()
    opt = r.read_bits(5)  # 5 optionals

    earfcn = r.read_constrained_int(0, 262143)  # carrierFreq
    r.read_enum(6)  # allowedMeasBandwidth

    # cellsToRemoveListEUTRA (optional)
    if (opt >> 4) & 1:
        num = r.read_constrained_int(1, 32)
        for _ in range(num):
            r.read_constrained_int(1, 32)

    # cellsToAddModListEUTRA (optional) — skip
    if (opt >> 3) & 1:
        num = r.read_constrained_int(1, 32)
        for _ in range(num):
            r.read_constrained_int(1, 32)  # cellIndex
            r.read_constrained_int(0, 503)  # physCellId (EUTRA: 0..503)
            # CellIndividualOffset: ENUMERATED (31 values)
            r.read_enum(31)

    # excludedCellsToRemoveListEUTRA (optional)
    if (opt >> 2) & 1:
        num = r.read_constrained_int(1, 32)
        for _ in range(num):
            r.read_constrained_int(1, 32)

    # excludedCellsToAddModListEUTRA (optional) — skip PCI ranges
    if (opt >> 1) & 1:
        num = r.read_constrained_int(1, 32)
        for _ in range(num):
            r.read_constrained_int(1, 32)  # pci-RangeIndex
            r.read_constrained_int(0, 503)  # start
            has_range = r.read_bool()
            if has_range:
                r.read_enum(16)

    r.read_bool()  # eutra-PresenceAntennaPort1

    if opt & 1:
        r.read_enum(31)  # eutra-Q-OffsetRange

    r.read_bool()  # widebandRSRQ-Meas

    if ext:
        skip_extension_additions(r)

    return MeasObjectEUTRA(earfcn=earfcn)


# -----------------------------------------------------------------------
# RadioBearerConfig structural skip (#N)
# -----------------------------------------------------------------------
#
# RRCReconfiguration-IEs inlines RadioBearerConfig directly (it is NOT an open
# type / OCTET STRING at that nesting level), so to reach the following
# measConfig field the reader must structurally walk it bit-exactly. Every
# field width / optional bitmap / SEQUENCE-OF bound below is taken verbatim
# from 3GPP TS 38.331 v17 and cross-checked against pycrate's compiled grammar
# (validation-only; the shipped decoder stays pycrate-free per the toolkit
# policy). Extension-addition blocks are skipped opaquely via the shared
# ``skip_extension_additions`` helper — every extensible SEQUENCE below sets an
# ext bit that gates it.


def _skip_header_compression(r: UperReader) -> None:
    """Skip PDCP-Config.drb.headerCompression (extensible CHOICE, 3 root alts).

    headerCompression ::= CHOICE {
        notUsed         NULL,
        rohc            SEQUENCE { maxCID INTEGER(1..16383) DEFAULT 15,
                                   profiles SEQUENCE { 9 BOOLEANs },
                                   drb-ContinueROHC ENUMERATED{true} OPTIONAL },
        uplinkOnlyROHC  SEQUENCE { maxCID INTEGER(1..16383) DEFAULT 15,
                                   profiles SEQUENCE { 1 BOOLEAN },
                                   drb-ContinueROHC ENUMERATED{true} OPTIONAL },
        ...
    }
    """
    if r.read_bool():  # extension marker set → alternative is an ext addition
        # normally-small non-negative index + open-type-wrapped value
        r.read_bits(7)  # simplified small index (root has 3 alts; ext unseen)
        length = read_open_type_length(r)
        r.skip_bits(length * 8)
        return
    choice = r.read_choice(3)
    if choice == 0:
        return  # notUsed: NULL
    # rohc (1) / uplinkOnlyROHC (2): identical shape, differ only in profile count
    n_profiles = 9 if choice == 1 else 1
    opt = r.read_bits(2)  # maxCID(DEFAULT), drb-ContinueROHC(OPTIONAL)
    if (opt >> 1) & 1:  # maxCID present (non-default)
        r.read_constrained_int(1, 16383)
    r.read_bits(n_profiles)  # profiles: fixed BOOLEAN bitmap
    # drb-ContinueROHC is ENUMERATED{true} → 0 value bits when present


def _skip_pdcp_drb(r: UperReader) -> None:
    """Skip PDCP-Config.drb (non-extensible SEQUENCE)."""
    opt = r.read_bits(6)  # discardTimer, SN-SizeUL, SN-SizeDL, integrityProt,
    #                       statusReportRequired, outOfOrderDelivery
    if (opt >> 5) & 1:
        r.read_enum(16)  # discardTimer
    if (opt >> 4) & 1:
        r.read_enum(2)  # pdcp-SN-SizeUL
    if (opt >> 3) & 1:
        r.read_enum(2)  # pdcp-SN-SizeDL
    _skip_header_compression(r)  # headerCompression (mandatory)
    # integrityProtection / statusReportRequired / outOfOrderDelivery are all
    # ENUMERATED{...} whose presence is signalled by the optional bit; each
    # carries 0 (integrityProtection: {enabled} → 0 bits) value bits.


def _skip_pdcp_more_than_one_rlc(r: UperReader) -> None:
    """Skip PDCP-Config.moreThanOneRLC (non-extensible SEQUENCE)."""
    opt = r.read_bits(2)  # ul-DataSplitThreshold, pdcp-Duplication
    # primaryPath (mandatory, non-extensible SEQUENCE)
    pp = r.read_bits(2)  # cellGroup, logicalChannel
    if (pp >> 1) & 1:
        r.read_constrained_int(0, 3)  # cellGroup
    if pp & 1:
        r.read_constrained_int(1, 32)  # logicalChannel
    if (opt >> 1) & 1:
        r.read_enum(32)  # ul-DataSplitThreshold
    if opt & 1:
        r.read_bool()  # pdcp-Duplication


def _skip_pdcp_config(r: UperReader) -> None:
    """Skip PDCP-Config (extensible SEQUENCE)."""
    ext = r.read_bool()
    opt = r.read_bits(3)  # drb, moreThanOneRLC, t-Reordering
    if (opt >> 2) & 1:
        _skip_pdcp_drb(r)
    if (opt >> 1) & 1:
        _skip_pdcp_more_than_one_rlc(r)
    if opt & 1:
        r.read_enum(64)  # t-Reordering
    if ext:
        skip_extension_additions(r)


def _skip_sdap_config(r: UperReader) -> None:
    """Skip SDAP-Config (extensible SEQUENCE)."""
    ext = r.read_bool()
    opt = r.read_bits(2)  # mappedQoS-FlowsToAdd, mappedQoS-FlowsToRelease
    r.read_constrained_int(0, 255)  # pdu-Session (PDU-SessionID)
    r.read_enum(2)  # sdap-HeaderDL
    r.read_enum(2)  # sdap-HeaderUL
    r.read_bool()  # defaultDRB
    if (opt >> 1) & 1:
        num = r.read_constrained_int(1, 64)  # mappedQoS-FlowsToAdd SIZE(1..64)
        for _ in range(num):
            r.read_constrained_int(0, 63)  # QFI
    if opt & 1:
        num = r.read_constrained_int(1, 64)  # mappedQoS-FlowsToRelease
        for _ in range(num):
            r.read_constrained_int(0, 63)  # QFI
    if ext:
        skip_extension_additions(r)


def _skip_srb_to_add_mod(r: UperReader) -> None:
    """Skip one SRB-ToAddMod (extensible SEQUENCE)."""
    ext = r.read_bool()
    opt = r.read_bits(3)  # reestablishPDCP, discardOnPDCP, pdcp-Config
    r.read_constrained_int(1, 3)  # srb-Identity
    # reestablishPDCP / discardOnPDCP: ENUMERATED{true} → 0 value bits
    if opt & 1:  # pdcp-Config
        _skip_pdcp_config(r)
    if ext:
        skip_extension_additions(r)


def _skip_drb_to_add_mod(r: UperReader) -> None:
    """Skip one DRB-ToAddMod (extensible SEQUENCE)."""
    ext = r.read_bool()
    opt = r.read_bits(4)  # cnAssociation, reestablishPDCP, recoverPDCP, pdcp-Config
    if (opt >> 3) & 1:  # cnAssociation CHOICE (2 alts, non-extensible)
        if r.read_choice(2) == 0:
            r.read_constrained_int(0, 15)  # eps-BearerIdentity
        else:
            _skip_sdap_config(r)  # sdap-Config
    r.read_constrained_int(1, 32)  # drb-Identity
    # reestablishPDCP / recoverPDCP: ENUMERATED{true} → 0 value bits
    if opt & 1:  # pdcp-Config
        _skip_pdcp_config(r)
    if ext:
        skip_extension_additions(r)


def _skip_security_config(r: UperReader) -> None:
    """Skip SecurityConfig (extensible SEQUENCE)."""
    ext = r.read_bool()
    opt = r.read_bits(2)  # securityAlgorithmConfig, keyToUse
    if (opt >> 1) & 1:  # securityAlgorithmConfig (extensible SEQUENCE)
        sac_ext = r.read_bool()
        sac_opt = r.read_bits(1)  # integrityProtAlgorithm
        # cipheringAlgorithm: extensible ENUMERATED (8 root values)
        if not r.read_bool():
            r.read_bits(3)
        if sac_opt & 1:  # integrityProtAlgorithm: extensible ENUMERATED (8 root)
            if not r.read_bool():
                r.read_bits(3)
        if sac_ext:
            skip_extension_additions(r)
    if opt & 1:
        r.read_enum(2)  # keyToUse
    if ext:
        skip_extension_additions(r)


def _skip_radio_bearer_config(r: UperReader) -> None:
    """Skip RadioBearerConfig (extensible SEQUENCE) to reach the next IE.

    RadioBearerConfig ::= SEQUENCE {
        srb-ToAddModList   SEQUENCE (SIZE (1..2))  OF SRB-ToAddMod  OPTIONAL,
        srb3-ToRelease     ENUMERATED {true}                       OPTIONAL,
        drb-ToAddModList   SEQUENCE (SIZE (1..29)) OF DRB-ToAddMod  OPTIONAL,
        drb-ToReleaseList  SEQUENCE (SIZE (1..29)) OF DRB-Identity  OPTIONAL,
        securityConfig     SecurityConfig                          OPTIONAL,
        ...
    }
    """
    ext = r.read_bool()
    opt = r.read_bits(5)
    if (opt >> 4) & 1:  # srb-ToAddModList
        num = r.read_constrained_int(1, 2)
        for _ in range(num):
            _skip_srb_to_add_mod(r)
    # srb3-ToRelease (opt bit 3): ENUMERATED{true} → 0 value bits
    if (opt >> 2) & 1:  # drb-ToAddModList
        num = r.read_constrained_int(1, 29)
        for _ in range(num):
            _skip_drb_to_add_mod(r)
    if (opt >> 1) & 1:  # drb-ToReleaseList
        num = r.read_constrained_int(1, 29)
        for _ in range(num):
            r.read_constrained_int(1, 32)  # DRB-Identity
    if opt & 1:  # securityConfig
        _skip_security_config(r)
    if ext:
        skip_extension_additions(r)


# -----------------------------------------------------------------------
# measConfig top-level decoder
# -----------------------------------------------------------------------


def _decode_meas_object_to_add_mod(
    r: UperReader,
) -> tuple[list[MeasObjectNR], list[MeasObjectEUTRA]]:
    """Decode measObjectToAddModList.

    MeasObjectToAddModList ::= SEQUENCE (SIZE (1..maxNrofObjectId=64)) OF MeasObjectToAddMod
    MeasObjectToAddMod ::= SEQUENCE {
        measObjectId    MeasObjectId,    -- INTEGER (1..maxNrofObjectId)
        measObject      CHOICE {
            measObjectNR        MeasObjectNR,
            ...  -- measObjectEUTRA added in extensions
        }
    }
    """
    nr_objects: list[MeasObjectNR] = []
    eutra_objects: list[MeasObjectEUTRA] = []

    num = r.read_constrained_int(1, _MAX_MEAS_OBJ_LIST)
    for _ in range(num):
        r.read_constrained_int(1, _MAX_MEAS_OBJ_ID)  # measObjectId

        # measObject: CHOICE (extensible)
        meas_ext = r.read_bool()
        if not meas_ext:
            # Base: 1 alternative (measObjectNR)
            # Since there's only 1 base alternative, no choice bits needed
            nr_obj = _decode_meas_object_nr(r)
            nr_objects.append(nr_obj)
        else:
            # Extension: measObjectEUTRA is extension addition index 0
            # Normally-small-length for extension choice
            ext_marker = r.read_bits(1)
            if ext_marker == 0:
                ext_choice = r.read_bits(6)
            else:
                ext_choice = r.read_bits(8)

            # Open-type length determinant via toolkit (#N).
            ot_len = read_open_type_length(r)

            # The extension value is an OPEN TYPE: its content is padded to a
            # whole number of octets (ot_len). Decode what we can, then ALWAYS
            # realign to the open-type end — a successful inner decode stops at
            # the last meaningful bit, several padding bits short of the octet
            # boundary, so trusting it to land exactly desyncs the next entry
            # (the phantom-trailing-object bug).
            saved_pos = r.bit_pos
            if ext_choice == 0:
                # measObjectEUTRA (extension addition index 0)
                try:
                    eutra_objects.append(_decode_meas_object_eutra(r))
                except (IndexError, ValueError):
                    pass
            r.bit_pos = saved_pos + ot_len * 8  # realign past open-type padding

    return nr_objects, eutra_objects


def decode_nr_meas_config(
    log_time: int, msg_data: bytes
) -> NrRRCMeasConfig | None:
    """Decode NR measConfig from a DL-DCCH RRCReconfiguration UPER bitstream.

    Navigates the ASN.1 structure:
        DL-DCCH-Message → message → c1 → rrcReconfiguration
        → criticalExtensions → rrcReconfiguration
        → RRCReconfiguration-IEs → measConfig
        → measObjectToAddModList

    Returns None if the message is not an RRCReconfiguration with measConfig.

    Reference: 3GPP TS 38.331 section 6.2.2
    """
    if not msg_data or len(msg_data) < 4:
        return None

    try:
        r = UperReader(msg_data)

        # DL-DCCH-MessageType: CHOICE { c1, messageClassExtension }
        msg_choice = r.read_choice(2)
        if msg_choice != 0:
            return None

        # c1: CHOICE of 16 alternatives — per 3GPP TS 38.331 v16/v17
        # (validated against pycrate ground truth on 545 v17 ct=0x60
        # records, 2026-05-25, #N), rrcReconfiguration is index 0.
        # The previous "index 4" value here was a transcription bug;
        # c1=4 is securityModeCommand, which dominated the wardriving
        # corpus (90.6%) and explains the prior 0/100 decode rate on
        # what looked like RRCReconfiguration bytes.
        c1_choice = r.read_choice(16)
        if c1_choice != 0:
            return None

        # RRCReconfiguration ::= SEQUENCE {
        #     rrc-TransactionIdentifier  RRC-TransactionIdentifier,  -- INTEGER (0..3)
        #     criticalExtensions  CHOICE {
        #         rrcReconfiguration  RRCReconfiguration-IEs,
        #         criticalExtensionsFuture SEQUENCE {}
        #     }
        # }
        r.read_constrained_int(0, 3)  # rrc-TransactionIdentifier

        crit_choice = r.read_choice(2)
        if crit_choice != 0:
            return None

        return _decode_reconfig_ies(r, log_time)

    except (IndexError, ValueError):
        return None


def decode_nr_meas_config_direct(
    log_time: int, msg_data: bytes
) -> NrRRCMeasConfig | None:
    """Decode NR measConfig from a firmware-direct ``RRC-RECONF`` channel (#N).

    On the ``RRC-RECONF`` channel the DLF outer header already identified the
    message, so ``msg_data`` does NOT begin with the ``DL-DCCH-Message`` outer
    CHOICE — it starts at the bare ``RRCReconfiguration`` SEQUENCE:

        RRCReconfiguration ::= SEQUENCE {
            rrc-TransactionIdentifier  INTEGER (0..3),
            criticalExtensions  CHOICE { rrcReconfiguration RRCReconfiguration-IEs,
                                         criticalExtensionsFuture SEQUENCE {} }
        }

    Returns None if the bytes are not a decodable rrcReconfiguration with a
    measConfig carrying at least one measObject.

    Reference: 3GPP TS 38.331 section 6.2.2
    """
    if not msg_data or len(msg_data) < 2:
        return None
    try:
        r = UperReader(msg_data)
        r.read_constrained_int(0, 3)  # rrc-TransactionIdentifier
        if r.read_choice(2) != 0:  # criticalExtensions CHOICE
            return None
        return _decode_reconfig_ies(r, log_time)
    except (IndexError, ValueError):
        return None


def _decode_reconfig_ies(r: UperReader, log_time: int) -> NrRRCMeasConfig | None:
    """Decode RRCReconfiguration-IEs from the reader positioned at its start.

    RRCReconfiguration-IEs ::= SEQUENCE {
        radioBearerConfig           RadioBearerConfig OPTIONAL,
        secondaryCellGroup          OCTET STRING (CONTAINING CellGroupConfig) OPTIONAL,
        measConfig                  MeasConfig OPTIONAL,
        lateNonCriticalExtension    OCTET STRING OPTIONAL,
        nonCriticalExtension        RRCReconfiguration-v1530-IEs OPTIONAL,
        ...
    }

    Shared by the DL-DCCH-Message entry (:func:`decode_nr_meas_config`) and the
    firmware-direct RRC-RECONF entry (:func:`decode_nr_meas_config_direct`).
    Returns None when no measConfig is present.

    NOTE: RRCReconfiguration-IEs is NOT extensible (its forward-compatibility is
    carried by the ``nonCriticalExtension`` chain, not an ``...`` ellipsis), so
    there is NO preamble extension bit — the optional bitmap starts immediately.
    Reading a phantom ext bit here desyncs the whole stream (was the latent bug
    behind the pre-#N 0-decode rate).
    """
    ies_opt = r.read_bits(5)  # 5 root optionals, no preceding ext bit

    # radioBearerConfig (optional) — inlined SEQUENCE (not an open type here),
    # so it must be structurally walked to advance to measConfig (#N).
    if (ies_opt >> 4) & 1:
        _skip_radio_bearer_config(r)

    # secondaryCellGroup (optional) — OCTET STRING (open-type length + bytes)
    if (ies_opt >> 3) & 1:
        scg_len = read_open_type_length(r)
        r.skip_bits(scg_len * 8)

    # measConfig (optional) — the target
    if not ((ies_opt >> 2) & 1):
        return None  # No measConfig present

    return _decode_meas_config(r, log_time)


def _decode_meas_config(r: UperReader, log_time: int) -> NrRRCMeasConfig:
    """Decode MeasConfig from its starting position.

    MeasConfig ::= SEQUENCE {
        measObjectToRemoveList      MeasObjectToRemoveList OPTIONAL,
        measObjectToAddModList      MeasObjectToAddModList OPTIONAL,
        reportConfigToRemoveList    ReportConfigToRemoveList OPTIONAL,
        reportConfigToAddModList    ReportConfigToAddModList OPTIONAL,
        measIdToRemoveList          MeasIdToRemoveList OPTIONAL,
        measIdToAddModList          MeasIdToAddModList OPTIONAL,
        s-MeasureConfig             CHOICE { ... } OPTIONAL,
        quantityConfig              QuantityConfig OPTIONAL,
        measGapConfig               MeasGapConfig OPTIONAL,
        measGapSharingConfig        MeasGapSharingConfig OPTIONAL,
        ...
    }
    """
    result = NrRRCMeasConfig(log_time=log_time)

    mc_ext = r.read_bool()
    mc_opt = r.read_bits(10)  # 10 optionals

    # measObjectToRemoveList (optional)
    if (mc_opt >> 9) & 1:
        num = r.read_constrained_int(1, _MAX_MEAS_OBJ_LIST)
        for _ in range(num):
            r.read_constrained_int(1, _MAX_MEAS_OBJ_ID)

    # measObjectToAddModList (optional) — THE MAIN TARGET
    if (mc_opt >> 8) & 1:
        result.nr_objects, result.eutra_objects = _decode_meas_object_to_add_mod(r)

    # reportConfigToRemoveList (optional)
    if (mc_opt >> 7) & 1:
        num = r.read_constrained_int(1, _MAX_REPORT_CONFIG_ID)
        for _ in range(num):
            r.read_constrained_int(1, _MAX_REPORT_CONFIG_ID)

    # reportConfigToAddModList (optional) — complex, skip for now
    if (mc_opt >> 6) & 1:
        # Too complex to skip structurally — bail out with what we have
        return result

    # measIdToRemoveList (optional)
    if (mc_opt >> 5) & 1:
        num = r.read_constrained_int(1, _MAX_MEAS_ID)
        for _ in range(num):
            r.read_constrained_int(1, _MAX_MEAS_ID)

    # measIdToAddModList (optional) — skip
    if (mc_opt >> 4) & 1:
        num = r.read_constrained_int(1, _MAX_MEAS_ID)
        for _ in range(num):
            r.read_constrained_int(1, _MAX_MEAS_ID)  # measId
            r.read_constrained_int(1, _MAX_MEAS_OBJ_ID)  # measObjectId
            r.read_constrained_int(1, _MAX_REPORT_CONFIG_ID)  # reportConfigId

    # s-MeasureConfig (optional)
    if (mc_opt >> 3) & 1:
        smc_choice = r.read_choice(2)
        if smc_choice == 0:
            result.s_measure_ssb = r.read_constrained_int(0, 127)
        else:
            result.s_measure_csi = r.read_constrained_int(0, 127)

    # Remaining fields (quantityConfig, measGapConfig, measGapSharingConfig)
    # are complex and rarely needed — stop here with extracted data

    return result
