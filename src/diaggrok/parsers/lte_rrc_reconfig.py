# diaggrok-provenance: re
"""LTE RRC RRCConnectionReconfiguration measConfig decoder.

Decodes measConfig from DL-DCCH RRCConnectionReconfiguration messages
to extract EUTRA measurement objects (EARFCNs the network tells the modem
to measure).

From-scratch UPER decoder -- no pycrate or other ASN.1 library dependency.
Receives the RRC message payload from within a 0xB0C0 frame (DL-DCCH channel).

ASN.1 path (3GPP TS 36.331):
    DL-DCCH-Message
      -> message (DL-DCCH-MessageType)
        -> c1 (CHOICE, 16 alternatives)
          -> rrcConnectionReconfiguration (index 4)
            -> rrc-TransactionIdentifier
            -> criticalExtensions -> c1
              -> rrcConnectionReconfiguration-r8
                -> measConfig (OPTIONAL)
                  -> measObjectToAddModList (OPTIONAL)
                    -> MeasObjectToAddMod
                      -> measObject (CHOICE)
                        -> measObjectEUTRA
                          -> carrierFreq, allowedMeasBandwidth, ...

Reference: 3GPP TS 36.331 v16.x (E-UTRA RRC Protocol specification)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from diaggrok.parsers.uper import UperReader
from diaggrok.parsers.asn1_helpers import (
    ALLOWED_MEAS_BW_RBS,
    Q_OFFSET_DB,
    read_open_type_length,
    skip_extension_additions,
)


# -----------------------------------------------------------------------
# Data structures
# -----------------------------------------------------------------------

@dataclass
class CellToAddMod:
    """A single neighbor cell from cellsToAddModList in measObjectEUTRA."""
    cell_index: int         # INTEGER (1..32)
    pci: int                # PhysCellId (0..503)
    cell_offset: int        # dB offset from Q-OffsetRange

    def to_dict(self) -> dict[str, Any]:
        return {
            'cell_index': self.cell_index,
            'pci': self.pci,
            'cell_offset': self.cell_offset,
        }


@dataclass
class MeasObjectEUTRA:
    """A single EUTRA measurement object -- a frequency the UE must measure."""
    earfcn: int             # ARFCN-ValueEUTRA (0..65535)
    bandwidth: int          # RBs: 6, 15, 25, 50, 75, 100
    offset: int             # dB offset from Q-OffsetRange
    cells: list[CellToAddMod] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'earfcn': self.earfcn,
            'bandwidth': self.bandwidth,
            'offset': self.offset,
        }
        if self.cells:
            d['cells'] = [c.to_dict() for c in self.cells]
        return d


@dataclass
class LteRRCMeasConfig:
    """Decoded measurement configuration from RRCConnectionReconfiguration."""
    log_time: int
    meas_objects: list[MeasObjectEUTRA] = field(default_factory=list)
    has_gap_config: bool = False
    s_measure: Optional[int] = None  # RSRP threshold (0..97), None if absent

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'type': 'LteRRCMeasConfig',
            'log_time': self.log_time,
            'meas_objects': [m.to_dict() for m in self.meas_objects],
            'has_gap_config': self.has_gap_config,
        }
        if self.s_measure is not None:
            d['s_measure'] = self.s_measure
        return d


# -----------------------------------------------------------------------
# MeasObjectEUTRA decoder
# -----------------------------------------------------------------------

def _decode_meas_object_eutra(r: UperReader) -> MeasObjectEUTRA:
    """Decode MeasObjectEUTRA from UPER.

    MeasObjectEUTRA ::= SEQUENCE {
        carrierFreq              ARFCN-ValueEUTRA,          -- INTEGER (0..65535)
        allowedMeasBandwidth     AllowedMeasBandwidth,      -- ENUMERATED {6 values}
        presenceAntennaPort1     PresenceAntennaPort1,      -- BOOLEAN
        neighCellConfig          NeighCellConfig,           -- BIT STRING (SIZE (2))
        offsetFreq               Q-OffsetRange DEFAULT dB0, -- ENUMERATED (31 values)
        cellsToRemoveList        CellIndexList              OPTIONAL,
        cellsToAddModList        CellsToAddModList          OPTIONAL,
        blackCellsToRemoveList   CellIndexList              OPTIONAL,
        blackCellsToAddModList   BlackCellsToAddModList     OPTIONAL,
        ...
    }

    5 OPTIONAL/DEFAULT fields in root: offsetFreq(DEFAULT), cellsToRemove,
    cellsToAddMod, blackCellsToRemove, blackCellsToAddMod.
    """
    has_ext = r.read_bool()

    # 5 optional/DEFAULT fields in root
    opt = r.read_bits(5)
    has_offset_freq = (opt >> 4) & 1
    has_cells_remove = (opt >> 3) & 1
    has_cells_add = (opt >> 2) & 1
    has_black_remove = (opt >> 1) & 1
    has_black_add = opt & 1

    # carrierFreq: ARFCN-ValueEUTRA -- INTEGER (0..65535)
    earfcn = r.read_constrained_int(0, 65535)

    # allowedMeasBandwidth: ENUMERATED {mbw6, mbw15, mbw25, mbw50, mbw75, mbw100}
    bw_idx = r.read_enum(6)
    bandwidth = ALLOWED_MEAS_BW_RBS[bw_idx] if bw_idx < len(ALLOWED_MEAS_BW_RBS) else 0

    # presenceAntennaPort1: BOOLEAN
    r.read_bool()

    # neighCellConfig: BIT STRING (SIZE (2))
    r.read_bits(2)

    # offsetFreq: Q-OffsetRange DEFAULT dB0 (index 15)
    offset = 0  # dB0 is default
    if has_offset_freq:
        off_idx = r.read_enum(31)
        offset = Q_OFFSET_DB[off_idx] if off_idx < len(Q_OFFSET_DB) else 0

    # cellsToRemoveList: CellIndexList -- SEQUENCE (SIZE (1..32)) OF INTEGER (1..32)
    if has_cells_remove:
        num = r.read_constrained_int(1, 32)
        for _ in range(num):
            r.read_constrained_int(1, 32)

    # cellsToAddModList: CellsToAddModList -- SEQUENCE (SIZE (1..32)) OF CellsToAddMod
    # CellsToAddMod ::= SEQUENCE {
    #     cellIndex      INTEGER (1..32),
    #     physCellId     PhysCellId,          -- INTEGER (0..503)
    #     cellIndividualOffset  Q-OffsetRange  -- ENUMERATED (31 values)
    # }
    cells: list[CellToAddMod] = []
    if has_cells_add:
        num = r.read_constrained_int(1, 32)
        for _ in range(num):
            cell_index = r.read_constrained_int(1, 32)
            pci = r.read_constrained_int(0, 503)
            off_idx = r.read_enum(31)
            cell_offset = Q_OFFSET_DB[off_idx] if off_idx < len(Q_OFFSET_DB) else 0
            cells.append(CellToAddMod(cell_index=cell_index, pci=pci, cell_offset=cell_offset))

    # blackCellsToRemoveList: CellIndexList -- SEQUENCE (SIZE (1..32)) OF INTEGER (1..32)
    if has_black_remove:
        num = r.read_constrained_int(1, 32)
        for _ in range(num):
            r.read_constrained_int(1, 32)

    # blackCellsToAddModList: BlackCellsToAddModList
    # SEQUENCE (SIZE (1..32)) OF BlackCellsToAddMod
    # BlackCellsToAddMod ::= SEQUENCE {
    #     cellIndex      INTEGER (1..32),
    #     physCellIdRange  PhysCellIdRange
    # }
    # PhysCellIdRange ::= SEQUENCE {
    #     start    PhysCellId,           -- INTEGER (0..503)
    #     range    ENUMERATED {n4,n8,...,n504} OPTIONAL  -- 16 values
    # }
    if has_black_add:
        num = r.read_constrained_int(1, 32)
        for _ in range(num):
            r.read_constrained_int(1, 32)   # cellIndex
            # PhysCellIdRange (no extension marker, 1 optional)
            has_range = r.read_bool()
            r.read_constrained_int(0, 503)  # start
            if has_range:
                r.read_enum(16)             # range

    if has_ext:
        skip_extension_additions(r)

    return MeasObjectEUTRA(
        earfcn=earfcn,
        bandwidth=bandwidth,
        offset=offset,
        cells=cells,
    )


# -----------------------------------------------------------------------
# MeasConfig decoder -- skips non-EUTRA objects, extracts EUTRA ones
# -----------------------------------------------------------------------

def _skip_meas_object_utra(r: UperReader) -> None:
    """Skip MeasObjectUTRA (index 1 in measObject CHOICE).

    Too complex to fully decode; skip via open-type wrapper is not available
    here since this is inside a CHOICE, not an extension. We skip the known
    root fields.

    MeasObjectUTRA ::= SEQUENCE {
        carrierFreq          ARFCN-ValueUTRA,       -- INTEGER (0..16383)
        offsetFreq           Q-OffsetRangeInterRAT DEFAULT 0, -- INTEGER (-15..15)
        cellsToRemoveList    CellIndexList          OPTIONAL,
        cellsToAddModList    CHOICE {
            cellsToAddModListUTRA-FDD,
            cellsToAddModListUTRA-TDD
        }                                           OPTIONAL,
        cellForWhichToReportCGI  PhysCellIdUTRA     OPTIONAL,
        ...
    }
    """
    has_ext = r.read_bool()

    # 3 optionals: offsetFreq(DEFAULT), cellsToRemoveList,
    # cellsToAddModList, cellForWhichToReportCGI = actually let me count:
    # offsetFreq is DEFAULT -> optional bit
    # cellsToRemoveList OPTIONAL
    # cellsToAddModList OPTIONAL
    # cellForWhichToReportCGI OPTIONAL
    # = 4 optional/DEFAULT fields
    opt = r.read_bits(4)
    has_offset = (opt >> 3) & 1
    has_cells_remove = (opt >> 2) & 1
    has_cells_add = (opt >> 1) & 1
    has_report_cgi = opt & 1

    r.read_constrained_int(0, 16383)  # carrierFreq

    if has_offset:
        r.read_constrained_int(-15, 15)  # offsetFreq

    if has_cells_remove:
        num = r.read_constrained_int(1, 32)
        for _ in range(num):
            r.read_constrained_int(1, 32)

    if has_cells_add:
        # CHOICE { cellsToAddModListUTRA-FDD(0), cellsToAddModListUTRA-TDD(1) }
        utra_choice = r.read_choice(2)
        if utra_choice == 0:
            # FDD: SEQUENCE (SIZE (1..32)) OF CellsToAddModUTRA-FDD
            # CellsToAddModUTRA-FDD ::= SEQUENCE {
            #     cellIndex  INTEGER (1..32),
            #     physCellId PhysCellIdUTRA-FDD  -- INTEGER (0..511)
            # }
            num = r.read_constrained_int(1, 32)
            for _ in range(num):
                r.read_constrained_int(1, 32)   # cellIndex
                r.read_constrained_int(0, 511)  # physCellId
        else:
            # TDD: SEQUENCE (SIZE (1..32)) OF CellsToAddModUTRA-TDD
            # CellsToAddModUTRA-TDD ::= SEQUENCE {
            #     cellIndex  INTEGER (1..32),
            #     physCellId PhysCellIdUTRA-TDD  -- INTEGER (0..127)
            # }
            num = r.read_constrained_int(1, 32)
            for _ in range(num):
                r.read_constrained_int(1, 32)   # cellIndex
                r.read_constrained_int(0, 127)  # physCellId

    if has_report_cgi:
        # PhysCellIdUTRA: CHOICE { fdd(0) INTEGER(0..511), tdd(1) INTEGER(0..127) }
        cgi_choice = r.read_choice(2)
        if cgi_choice == 0:
            r.read_constrained_int(0, 511)
        else:
            r.read_constrained_int(0, 127)

    if has_ext:
        skip_extension_additions(r)


def _skip_meas_object_geran(r: UperReader) -> None:
    """Skip MeasObjectGERAN (index 2 in measObject CHOICE).

    MeasObjectGERAN ::= SEQUENCE {
        carrierFreqs     CarrierFreqsGERAN,
        offsetFreq       Q-OffsetRangeInterRAT DEFAULT 0,
        ncc-Permitted    BIT STRING (SIZE (8)) DEFAULT '11111111'B,
        cellForWhichToReportCGI  PhysCellIdGERAN OPTIONAL,
        ...
    }
    """
    has_ext = r.read_bool()

    # 3 DEFAULT/OPTIONAL: offsetFreq(DEFAULT), ncc-Permitted(DEFAULT),
    # cellForWhichToReportCGI(OPTIONAL)
    opt = r.read_bits(3)
    has_offset = (opt >> 2) & 1
    has_ncc = (opt >> 1) & 1
    has_report_cgi = opt & 1

    # CarrierFreqsGERAN ::= SEQUENCE {
    #     startingARFCN   ARFCN-ValueGERAN,   -- INTEGER (0..1023)
    #     followingARFCNs CHOICE {
    #         explicitListOfARFCNs  ExplicitListOfARFCNs,  -- SEQUENCE (SIZE (0..31)) OF ARFCN
    #         equallySpacedARFCNs   SEQUENCE { arfcn-Spacing (1..8), numberOfFollowingARFCNs (0..31) },
    #         variableBitMapOfARFCNs  OCTET STRING (SIZE (1..16))
    #     }
    # }
    r.read_constrained_int(0, 1023)  # startingARFCN
    following_choice = r.read_choice(3)
    if following_choice == 0:
        # explicitListOfARFCNs: SEQUENCE (SIZE (0..31))
        num = r.read_constrained_int(0, 31)
        for _ in range(num):
            r.read_constrained_int(0, 1023)
    elif following_choice == 1:
        # equallySpacedARFCNs
        r.read_constrained_int(1, 8)   # arfcn-Spacing
        r.read_constrained_int(0, 31)  # numberOfFollowingARFCNs
    else:
        # variableBitMapOfARFCNs: OCTET STRING (SIZE (1..16))
        length = r.read_constrained_int(1, 16)
        r.skip_bits(length * 8)

    if has_offset:
        r.read_constrained_int(-15, 15)

    if has_ncc:
        r.read_bits(8)  # ncc-Permitted

    if has_report_cgi:
        # PhysCellIdGERAN ::= SEQUENCE {
        #     ncc  BIT STRING (SIZE (3)),
        #     bcc  BIT STRING (SIZE (3))
        # }
        r.read_bits(3)  # ncc
        r.read_bits(3)  # bcc

    if has_ext:
        skip_extension_additions(r)


def _skip_meas_object_cdma2000(r: UperReader) -> None:
    """Skip MeasObjectCDMA2000 (index 3 in measObject CHOICE).

    MeasObjectCDMA2000 ::= SEQUENCE {
        cdma2000-Type            CDMA2000-Type,       -- ENUMERATED {type1XRTT, typeHRPD}
        carrierFreq              CarrierFreqCDMA2000,
        searchWindowSize         INTEGER (0..15),
        offsetFreq               Q-OffsetRangeInterRAT DEFAULT 0,
        cellsToRemoveList        CellIndexList        OPTIONAL,
        cellsToAddModList        CellsToAddModListCDMA2000 OPTIONAL,
        cellForWhichToReportCGI  PhysCellIdCDMA2000   OPTIONAL,
        ...
    }
    """
    has_ext = r.read_bool()

    # 3 optional/DEFAULT: offsetFreq, cellsToRemoveList, cellsToAddModList,
    # cellForWhichToReportCGI = 4
    opt = r.read_bits(4)
    has_offset = (opt >> 3) & 1
    has_cells_remove = (opt >> 2) & 1
    has_cells_add = (opt >> 1) & 1
    has_report_cgi = opt & 1

    r.read_enum(2)  # cdma2000-Type

    # CarrierFreqCDMA2000 ::= SEQUENCE {
    #     bandClass   BandclassCDMA2000,  -- ENUMERATED (32 values)
    #     arfcn       ARFCN-ValueCDMA2000 -- INTEGER (0..2047)
    # }
    r.read_enum(32)                   # bandClass
    r.read_constrained_int(0, 2047)   # arfcn

    r.read_constrained_int(0, 15)     # searchWindowSize

    if has_offset:
        r.read_constrained_int(-15, 15)

    if has_cells_remove:
        num = r.read_constrained_int(1, 32)
        for _ in range(num):
            r.read_constrained_int(1, 32)

    if has_cells_add:
        # CellsToAddModListCDMA2000 ::= SEQUENCE (SIZE (1..32)) OF CellsToAddModCDMA2000
        # CellsToAddModCDMA2000 ::= SEQUENCE {
        #     cellIndex    INTEGER (1..32),
        #     physCellId   PhysCellIdCDMA2000  -- INTEGER (0..maxPNOffset=511)
        # }
        num = r.read_constrained_int(1, 32)
        for _ in range(num):
            r.read_constrained_int(1, 32)
            r.read_constrained_int(0, 511)

    if has_report_cgi:
        r.read_constrained_int(0, 511)  # PhysCellIdCDMA2000

    if has_ext:
        skip_extension_additions(r)


def _skip_report_config(r: UperReader) -> None:
    """Skip a single ReportConfigToAddMod entry.

    ReportConfigToAddMod ::= SEQUENCE {
        reportConfigId   ReportConfigId,          -- INTEGER (1..32)
        reportConfig     CHOICE {
            reportConfigEUTRA    ReportConfigEUTRA,
            reportConfigInterRAT ReportConfigInterRAT
        }
    }

    Both ReportConfigEUTRA and ReportConfigInterRAT are complex extensible
    sequences. We skip them entirely via extension addition handling.
    This is a best-effort skip -- these are complex structures.
    """
    r.read_constrained_int(1, 32)  # reportConfigId

    rc_choice = r.read_choice(2)
    if rc_choice == 0:
        # ReportConfigEUTRA -- extensible SEQUENCE
        _skip_report_config_eutra(r)
    else:
        # ReportConfigInterRAT -- extensible SEQUENCE
        _skip_report_config_inter_rat(r)


def _skip_report_config_eutra(r: UperReader) -> None:
    """Skip ReportConfigEUTRA.

    ReportConfigEUTRA ::= SEQUENCE {
        triggerType  CHOICE {
            event   SEQUENCE {
                eventId  CHOICE { eventA1, eventA2, eventA3, eventA4, eventA5 },
                hysteresis    Hysteresis,         -- INTEGER (0..30)
                timeToTrigger TimeToTrigger       -- ENUMERATED (16 values)
            },
            periodical SEQUENCE {
                purpose ENUMERATED { reportStrongestCells, reportCGI }
            }
        },
        triggerQuantity    ENUMERATED { rsrp, rsrq },
        reportQuantity     ENUMERATED { sameAsTriggerQuantity, both },
        maxReportCells     INTEGER (1..maxCellReport=8),
        reportInterval     ReportInterval,        -- ENUMERATED (16 values)
        reportAmount       ENUMERATED { r1,r2,r4,r8,r16,r32,r64,infinity },
        ...
    }
    """
    has_ext = r.read_bool()

    # No optionals in root
    trigger_choice = r.read_choice(2)
    if trigger_choice == 0:
        # event SEQUENCE
        event_choice = r.read_choice(5)  # eventA1..eventA5
        _skip_event_id(r, event_choice)
        r.read_constrained_int(0, 30)   # hysteresis
        r.read_enum(16)                 # timeToTrigger
    else:
        # periodical
        r.read_enum(2)  # purpose

    r.read_enum(2)  # triggerQuantity
    r.read_enum(2)  # reportQuantity
    r.read_constrained_int(1, 8)  # maxReportCells
    r.read_enum(16)  # reportInterval
    r.read_enum(8)   # reportAmount

    if has_ext:
        skip_extension_additions(r)


def _skip_event_id(r: UperReader, event_idx: int) -> None:
    """Skip an event threshold inside ReportConfigEUTRA.

    Events A1-A5 contain ThresholdEUTRA values:
        ThresholdEUTRA ::= CHOICE {
            threshold-RSRP   RSRP-Range,    -- INTEGER (0..97)
            threshold-RSRQ   RSRQ-Range     -- INTEGER (0..34)
        }
    A1: threshold1 only
    A2: threshold1 only
    A3: a3-Offset INTEGER (-30..30), reportOnLeave BOOLEAN
    A4: threshold1 only
    A5: threshold1, threshold2
    """
    if event_idx in (0, 1, 3):  # A1, A2, A4
        _skip_threshold_eutra(r)
    elif event_idx == 2:  # A3
        r.read_constrained_int(-30, 30)  # a3-Offset
        r.read_bool()  # reportOnLeave
    elif event_idx == 4:  # A5
        _skip_threshold_eutra(r)
        _skip_threshold_eutra(r)


def _skip_threshold_eutra(r: UperReader) -> None:
    """Skip ThresholdEUTRA CHOICE."""
    choice = r.read_choice(2)
    if choice == 0:
        r.read_constrained_int(0, 97)   # RSRP-Range
    else:
        r.read_constrained_int(0, 34)   # RSRQ-Range


def _skip_report_config_inter_rat(r: UperReader) -> None:
    """Skip ReportConfigInterRAT.

    ReportConfigInterRAT ::= SEQUENCE {
        triggerType  CHOICE {
            event   SEQUENCE {
                eventId CHOICE { eventB1, eventB2 },
                hysteresis    Hysteresis,
                timeToTrigger TimeToTrigger
            },
            periodical SEQUENCE {
                purpose ENUMERATED { reportStrongestCells, reportStrongestCellsForSON, reportCGI }
            }
        },
        maxReportCells   INTEGER (1..maxCellReport=8),
        reportInterval   ReportInterval,
        reportAmount     ENUMERATED (8 values),
        ...
    }
    """
    has_ext = r.read_bool()

    trigger_choice = r.read_choice(2)
    if trigger_choice == 0:
        # event
        event_choice = r.read_choice(2)  # B1 or B2
        if event_choice == 0:
            # eventB1: b1-Threshold CHOICE { b1-ThresholdUTRA, b1-ThresholdGERAN,
            #                                b1-ThresholdCDMA2000 }
            _skip_threshold_inter_rat(r)
        else:
            # eventB2: b2-Threshold1 (ThresholdEUTRA) + b2-Threshold2 (inter-RAT)
            _skip_threshold_eutra(r)
            _skip_threshold_inter_rat(r)
        r.read_constrained_int(0, 30)   # hysteresis
        r.read_enum(16)                 # timeToTrigger
    else:
        # periodical
        r.read_enum(3)  # purpose

    r.read_constrained_int(1, 8)  # maxReportCells
    r.read_enum(16)  # reportInterval
    r.read_enum(8)   # reportAmount

    if has_ext:
        skip_extension_additions(r)


def _skip_threshold_inter_rat(r: UperReader) -> None:
    """Skip inter-RAT threshold CHOICE.

    CHOICE {
        b1-ThresholdUTRA     ThresholdUTRA,      -- CHOICE { utra-RSCP(-5..91), utra-EcN0(0..49) }
        b1-ThresholdGERAN    ThresholdGERAN,      -- INTEGER (0..63)
        b1-ThresholdCDMA2000 ThresholdCDMA2000    -- INTEGER (0..63)
    }
    """
    choice = r.read_choice(3)
    if choice == 0:
        # ThresholdUTRA CHOICE
        utra_choice = r.read_choice(2)
        if utra_choice == 0:
            r.read_constrained_int(-5, 91)   # utra-RSCP
        else:
            r.read_constrained_int(0, 49)    # utra-EcN0
    elif choice == 1:
        r.read_constrained_int(0, 63)  # ThresholdGERAN
    else:
        r.read_constrained_int(0, 63)  # ThresholdCDMA2000


def _skip_quantity_config(r: UperReader) -> None:
    """Skip QuantityConfig.

    QuantityConfig ::= SEQUENCE {
        quantityConfigEUTRA      QuantityConfigEUTRA      OPTIONAL,
        quantityConfigUTRA       QuantityConfigUTRA       OPTIONAL,
        quantityConfigGERAN      QuantityConfigGERAN      OPTIONAL,
        quantityConfigCDMA2000   SetupRelease { ... }     OPTIONAL,
        ...
    }

    QuantityConfigEUTRA ::= SEQUENCE {
        filterCoefficientRSRP  FilterCoefficient DEFAULT fc4, -- ENUMERATED (15 values)
        filterCoefficientRSRQ  FilterCoefficient DEFAULT fc4  -- ENUMERATED (15 values)
    }
    """
    has_ext = r.read_bool()

    # 4 optionals
    opt = r.read_bits(4)

    if (opt >> 3) & 1:  # quantityConfigEUTRA
        # 2 DEFAULT fields
        eutra_opt = r.read_bits(2)
        if (eutra_opt >> 1) & 1:
            r.read_enum(15)  # filterCoefficientRSRP
        if eutra_opt & 1:
            r.read_enum(15)  # filterCoefficientRSRQ

    if (opt >> 2) & 1:  # quantityConfigUTRA
        # QuantityConfigUTRA ::= SEQUENCE {
        #     measQuantityUTRA-FDD  ENUMERATED {cpich-RSCP, cpich-EcN0},
        #     measQuantityUTRA-TDD  ENUMERATED {pccpch-RSCP}
        #     filterCoefficient    FilterCoefficient DEFAULT fc4
        # }
        qc_utra_opt = r.read_bits(1)  # 1 DEFAULT
        r.read_enum(2)   # measQuantityUTRA-FDD
        r.read_enum(1)   # measQuantityUTRA-TDD (single value -> 0 bits, but enum(1)=0 bits)
        if qc_utra_opt & 1:
            r.read_enum(15)

    if (opt >> 1) & 1:  # quantityConfigGERAN
        # QuantityConfigGERAN ::= SEQUENCE {
        #     measQuantityGERAN  ENUMERATED {rssi},
        #     filterCoefficient  FilterCoefficient DEFAULT fc2
        # }
        qc_geran_opt = r.read_bits(1)
        r.read_enum(1)  # single value
        if qc_geran_opt & 1:
            r.read_enum(15)

    if opt & 1:  # quantityConfigCDMA2000
        # SetupRelease: measQuantityCDMA2000 ENUMERATED { pilotStrength, pilotPnPhaseAndPilotStrength }
        # Simplified: CHOICE { release(0), setup(1) }
        sr_choice = r.read_choice(2)
        if sr_choice == 1:
            r.read_enum(2)  # measQuantityCDMA2000

    if has_ext:
        skip_extension_additions(r)


def _skip_meas_gap_config_setup(r: UperReader) -> None:
    """Skip MeasGapConfig setup body.

    setup ::= SEQUENCE {
        gapOffset  CHOICE {
            gp0  INTEGER (0..39),
            gp1  INTEGER (0..79),
            ...
        }
    }
    """
    # gapOffset is an extensible CHOICE
    gap_ext = r.read_bool()
    if not gap_ext:
        gap_choice = r.read_choice(2)
        if gap_choice == 0:
            r.read_constrained_int(0, 39)
        else:
            r.read_constrained_int(0, 79)
    else:
        # Extension -- use normally-small-number for choice index then open type
        skip_extension_additions(r)


# -----------------------------------------------------------------------
# MeasConfig decoder
# -----------------------------------------------------------------------

def _decode_meas_config(r: UperReader) -> tuple[list[MeasObjectEUTRA], bool, Optional[int]]:
    """Decode MeasConfig, extracting EUTRA measurement objects.

    MeasConfig ::= SEQUENCE {
        measObjectToRemoveList       MeasObjectToRemoveList       OPTIONAL,
        measObjectToAddModList       MeasObjectToAddModList       OPTIONAL,
        reportConfigToRemoveList     ReportConfigToRemoveList     OPTIONAL,
        reportConfigToAddModList     ReportConfigToAddModList     OPTIONAL,
        measIdToRemoveList           MeasIdToRemoveList           OPTIONAL,
        measIdToAddModList           MeasIdToAddModList           OPTIONAL,
        quantityConfig               QuantityConfig               OPTIONAL,
        measGapConfig                CHOICE { release, setup }    OPTIONAL,
        s-Measure                    RSRP-Range                   OPTIONAL,
        preRegistrationInfoHRPD      PreRegistrationInfoHRPD      OPTIONAL,
        speedStatePars               CHOICE { release, setup }    OPTIONAL,
        ...
    }

    11 OPTIONAL fields in root component.

    Returns:
        (meas_objects, has_gap_config, s_measure)
    """
    has_ext = r.read_bool()

    # 11 optional fields
    opt = r.read_bits(11)
    has_obj_remove      = (opt >> 10) & 1
    has_obj_add         = (opt >> 9) & 1
    has_rpt_remove      = (opt >> 8) & 1
    has_rpt_add         = (opt >> 7) & 1
    has_id_remove       = (opt >> 6) & 1
    has_id_add          = (opt >> 5) & 1
    has_quant           = (opt >> 4) & 1
    has_gap             = (opt >> 3) & 1
    has_s_measure       = (opt >> 2) & 1
    has_prereg_hrpd     = (opt >> 1) & 1
    has_speed_state     = opt & 1

    meas_objects: list[MeasObjectEUTRA] = []

    # measObjectToRemoveList: SEQUENCE (SIZE (1..maxObjectId=32)) OF MeasObjectId
    # MeasObjectId ::= INTEGER (1..maxObjectId=32)
    if has_obj_remove:
        num = r.read_constrained_int(1, 32)
        for _ in range(num):
            r.read_constrained_int(1, 32)

    # measObjectToAddModList: SEQUENCE (SIZE (1..maxObjectId=32)) OF MeasObjectToAddMod
    if has_obj_add:
        num = r.read_constrained_int(1, 32)
        for _ in range(num):
            # MeasObjectToAddMod ::= SEQUENCE {
            #     measObjectId  MeasObjectId,    -- INTEGER (1..32)
            #     measObject    CHOICE {
            #         measObjectEUTRA(0),
            #         measObjectUTRA(1),
            #         measObjectGERAN(2),
            #         measObjectCDMA2000(3)
            #     }
            # }
            r.read_constrained_int(1, 32)  # measObjectId

            # measObject: extensible CHOICE of 4 root alternatives
            obj_ext = r.read_bool()
            if not obj_ext:
                obj_choice = r.read_choice(4)
                if obj_choice == 0:
                    eutra = _decode_meas_object_eutra(r)
                    meas_objects.append(eutra)
                elif obj_choice == 1:
                    _skip_meas_object_utra(r)
                elif obj_choice == 2:
                    _skip_meas_object_geran(r)
                elif obj_choice == 3:
                    _skip_meas_object_cdma2000(r)
            else:
                # Extension choice (e.g., measObjectWLAN-r13, measObjectNR-r15)
                # Read normally-small-number for extended choice index, then open type
                _skip_extension_choice(r)

    # reportConfigToRemoveList: SEQUENCE (SIZE (1..maxReportConfigId=32)) OF ReportConfigId
    if has_rpt_remove:
        num = r.read_constrained_int(1, 32)
        for _ in range(num):
            r.read_constrained_int(1, 32)

    # reportConfigToAddModList
    if has_rpt_add:
        num = r.read_constrained_int(1, 32)
        for _ in range(num):
            _skip_report_config(r)

    # measIdToRemoveList: SEQUENCE (SIZE (1..maxMeasId=32)) OF MeasId
    if has_id_remove:
        num = r.read_constrained_int(1, 32)
        for _ in range(num):
            r.read_constrained_int(1, 32)

    # measIdToAddModList: SEQUENCE (SIZE (1..maxMeasId=32)) OF MeasIdToAddMod
    # MeasIdToAddMod ::= SEQUENCE {
    #     measId           MeasId,           -- INTEGER (1..32)
    #     measObjectId     MeasObjectId,     -- INTEGER (1..32)
    #     reportConfigId   ReportConfigId    -- INTEGER (1..32)
    # }
    if has_id_add:
        num = r.read_constrained_int(1, 32)
        for _ in range(num):
            r.read_constrained_int(1, 32)  # measId
            r.read_constrained_int(1, 32)  # measObjectId
            r.read_constrained_int(1, 32)  # reportConfigId

    # quantityConfig
    if has_quant:
        _skip_quantity_config(r)

    # measGapConfig: CHOICE { release(0), setup(1) }
    has_gap_config = False
    if has_gap:
        gap_choice = r.read_choice(2)
        if gap_choice == 1:
            has_gap_config = True
            _skip_meas_gap_config_setup(r)

    # s-Measure: RSRP-Range -- INTEGER (0..97)
    s_measure: Optional[int] = None
    if has_s_measure:
        s_measure = r.read_constrained_int(0, 97)

    # preRegistrationInfoHRPD: SEQUENCE {
    #     preRegistrationAllowed BOOLEAN,
    #     preRegistrationZoneId  PreRegistrationZoneIdHRPD OPTIONAL, -- INTEGER (0..255)
    #     secondaryPreRegistrationZoneIdList  ... OPTIONAL
    # }
    if has_prereg_hrpd:
        prereg_opt = r.read_bits(2)  # 2 optionals
        r.read_bool()  # preRegistrationAllowed
        if (prereg_opt >> 1) & 1:
            r.read_constrained_int(0, 255)  # preRegistrationZoneId
        if prereg_opt & 1:
            # SecondaryPreRegistrationZoneIdListHRPD: SEQUENCE (SIZE (1..2))
            num = r.read_constrained_int(1, 2)
            for _ in range(num):
                r.read_constrained_int(0, 255)

    # speedStatePars: CHOICE { release(0), setup(1) }
    if has_speed_state:
        ss_choice = r.read_choice(2)
        if ss_choice == 1:
            # setup ::= SEQUENCE {
            #     mobilityStateParameters  MobilityStateParameters,
            #     timeToTrigger-SF         SpeedStateScaleFactors
            # }
            # MobilityStateParameters ::= SEQUENCE {
            #     t-Evaluation   ENUMERATED {s30,s60,s120,s180,s240},
            #     t-HystNormal   ENUMERATED {s30,s60,s120,s180,s240},
            #     n-CellChangeMedium INTEGER (1..16),
            #     n-CellChangeHigh   INTEGER (1..16)
            # }
            r.read_enum(5)                # t-Evaluation
            r.read_enum(5)                # t-HystNormal
            r.read_constrained_int(1, 16)  # n-CellChangeMedium
            r.read_constrained_int(1, 16)  # n-CellChangeHigh
            # SpeedStateScaleFactors
            r.read_enum(4)  # sf-Medium
            r.read_enum(4)  # sf-High

    if has_ext:
        skip_extension_additions(r)

    return meas_objects, has_gap_config, s_measure


def _skip_extension_choice(r: UperReader) -> None:
    """Skip an extension CHOICE alternative (open type wrapper)."""
    # Normally-small-number for extended choice index
    marker = r.read_bits(1)
    if marker == 0:
        r.read_bits(6)  # choice index
    else:
        r.read_bits(8)  # semi-constrained
    # Open type wrapper
    length = read_open_type_length(r)
    r.skip_bits(length * 8)


# -----------------------------------------------------------------------
# Top-level decoder: DL-DCCH -> RRCConnectionReconfiguration -> measConfig
# -----------------------------------------------------------------------

def decode_rrc_reconfig_meas_config(
    log_time: int, msg_data: bytes
) -> LteRRCMeasConfig | None:
    """Decode measConfig from an RRCConnectionReconfiguration on DL-DCCH.

    Navigates the ASN.1 structure:
        DL-DCCH-Message
          -> message: DL-DCCH-MessageType (CHOICE c1 / messageClassExtension)
            -> c1: CHOICE of 16 (index 4 = rrcConnectionReconfiguration)
              -> RRCConnectionReconfiguration
                -> rrc-TransactionIdentifier: INTEGER (0..3)
                -> criticalExtensions: CHOICE (c1 / future)
                  -> c1: CHOICE of 8 (index 0 = r8)
                    -> RRCConnectionReconfiguration-r8-IEs
                      -> measConfig (OPTIONAL)

    Args:
        log_time: DIAG log timestamp.
        msg_data: Raw UPER-encoded DL-DCCH-Message bytes (from 0xB0C0 payload).

    Returns:
        LteRRCMeasConfig with extracted EUTRA measurement objects,
        or None if not an RRCConnectionReconfiguration or no measConfig present.
    """
    if not msg_data or len(msg_data) < 3:
        return None

    try:
        r = UperReader(msg_data)

        # DL-DCCH-MessageType: CHOICE { c1(0), messageClassExtension(1) }
        msg_type = r.read_choice(2)
        if msg_type != 0:
            return None

        # c1: CHOICE of 16 DL-DCCH messages
        # Index 4 = rrcConnectionReconfiguration
        c1_choice = r.read_choice(16)
        if c1_choice != 4:
            return None

        # RRCConnectionReconfiguration ::= SEQUENCE {
        #     rrc-TransactionIdentifier  RRC-TransactionIdentifier, -- INTEGER (0..3)
        #     criticalExtensions         CHOICE { c1, criticalExtensionsFuture }
        # }
        r.read_constrained_int(0, 3)  # rrc-TransactionIdentifier

        # criticalExtensions: CHOICE { c1(0), criticalExtensionsFuture(1) }
        crit_choice = r.read_choice(2)
        if crit_choice != 0:
            return None

        # c1: CHOICE of 8 (index 0 = rrcConnectionReconfiguration-r8)
        r8_choice = r.read_choice(8)
        if r8_choice != 0:
            return None

        # RRCConnectionReconfiguration-r8-IEs ::= SEQUENCE {
        #     measConfig                    MeasConfig                    OPTIONAL,
        #     mobilityControlInfo           MobilityControlInfo           OPTIONAL,
        #     dedicatedInfoNASList          SEQUENCE (SIZE(1..maxDRB)) OF DedicatedInfoNAS OPTIONAL,
        #     radioResourceConfigDedicated  RadioResourceConfigDedicated  OPTIONAL,
        #     securityConfigHO              SecurityConfigHO              OPTIONAL,
        #     nonCriticalExtension          ...                           OPTIONAL
        # }
        # Extensible SEQUENCE
        has_ext = r.read_bool()

        # 6 optional fields
        opt = r.read_bits(6)
        has_meas_config = (opt >> 5) & 1

        if not has_meas_config:
            # No measConfig in this reconfiguration message
            return LteRRCMeasConfig(log_time=log_time)

        # Decode measConfig
        meas_objects, has_gap, s_meas = _decode_meas_config(r)

        return LteRRCMeasConfig(
            log_time=log_time,
            meas_objects=meas_objects,
            has_gap_config=has_gap,
            s_measure=s_meas,
        )

    except (IndexError, ValueError):
        return None
