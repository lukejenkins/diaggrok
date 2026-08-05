# diaggrok-provenance: re
"""UPER decoders for LTE SIB bodies inside the SI container (#N).

These functions read through the UPER-encoded ASN.1 structure of each SIB
type, extracting structured fields AND advancing the UperReader bit position
past the SIB body — so the SI container walker can reach SIBs later in the
list (e.g., walk past SIB5 to reach SIB8 for time calibration). Callers that
only need the cursor advanced ignore the return value.

Originally written as pure skippers (module ``lte_rrc_sib_skip.py``,
functions ``skip_sibN``); field extraction grew in over #N/#N/#N/#N
until "skip" was a misnomer, so #N renamed the module and public API to
the dominant ``decode_*`` convention. The ``decode_sib6_body`` /
``decode_sib7_body`` names (vs plain ``decode_sib6/7``) disambiguate these
reader-positioned container walkers from the top-level record decoders in
``lte_rrc_sib6.py`` / ``lte_rrc_sib7.py``, mirroring
``nr5g_rrc_sib9.decode_sib9_body``. Private ``_skip_*`` helpers that only
advance the cursor keep their names.

Reference: 3GPP TS 36.331 §6.3.1, ITU-T X.691 (UPER)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from diaggrok.parsers.lte_rrc_sib import UperReader
from diaggrok.parsers.asn1_helpers import (
    PCI_RANGE_VALUES,
    Q_HYST_DB,
    Q_OFFSET_DB,
    read_open_type_length,
    skip_extension_additions,
)


# -----------------------------------------------------------------------
# Shared ASN.1 types
# -----------------------------------------------------------------------

def _skip_speed_state_scale_factors(r: UperReader) -> None:
    """SpeedStateScaleFactors: sf-Medium ENUM(4) + sf-High ENUM(4)."""
    r.read_enum(4)  # sf-Medium: oDot25, oDot5, oDot75, lDot0
    r.read_enum(4)  # sf-High


# -----------------------------------------------------------------------
# SIB2 skip + extract (access barring / RACH / common radio config, #N)
# -----------------------------------------------------------------------

# ENUMERATED value tables (TS 36.331), indexed by the UPER-decoded index.
_RA_PREAMBLES = [4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64]
_POWER_RAMPING_STEP_DB = [0, 2, 4, 6]
_PREAMBLE_INIT_POWER_DBM = list(range(-120, -88, 2))  # dBm-120..dBm-90, 16 vals
_PREAMBLE_TRANS_MAX = [3, 4, 5, 6, 7, 8, 10, 20, 50, 100, 200]
_AC_BARRING_FACTOR_PCT = [0, 5, 10, 15, 20, 25, 30, 40,
                          50, 60, 70, 75, 80, 85, 90, 95]
_AC_BARRING_TIME_S = [4, 8, 16, 32, 64, 128, 256, 512]
_UL_BANDWIDTH_RB = [6, 15, 25, 50, 75, 100]
_TIME_ALIGNMENT_TIMER = ["sf500", "sf750", "sf1280", "sf1920",
                         "sf2560", "sf5120", "sf10240", "infinity"]
_T300_T301_MS = [100, 200, 300, 400, 600, 1000, 1500, 2000]
_T310_MS = [0, 50, 100, 200, 500, 1000, 2000]
_N310 = [1, 2, 3, 4, 6, 8, 10, 20]
_T311_MS = [1000, 3000, 5000, 10000, 15000, 20000, 30000]
_N311 = [1, 2, 3, 4, 5, 6, 8, 10]


def _lut(table: list[int], idx: int) -> int | None:
    """Map a decoded ENUMERATED index to its value, guarding out-of-range."""
    return table[idx] if 0 <= idx < len(table) else None


@dataclass
class Sib2AccessParams:
    """Access-barring / RACH / common-radio-config parameters from LTE SIB2."""
    ac_barring_present: bool = False
    ac_barring_for_emergency: bool | None = None
    ac_barring_mo_signalling_factor_pct: int | None = None
    ac_barring_mo_signalling_time_s: int | None = None
    ac_barring_mo_data_factor_pct: int | None = None
    ac_barring_mo_data_time_s: int | None = None
    number_of_ra_preambles: int | None = None
    power_ramping_step_db: int | None = None
    preamble_initial_target_power_dbm: int | None = None
    preamble_trans_max: int | None = None
    prach_root_sequence_index: int | None = None
    prach_config_index: int | None = None
    reference_signal_power_dbm: int | None = None
    ul_carrier_freq: int | None = None          # ARFCN-ValueEUTRA (TDD: absent)
    ul_bandwidth_rb: int | None = None
    additional_spectrum_emission: int | None = None
    t300_ms: int | None = None
    t301_ms: int | None = None
    t310_ms: int | None = None
    n310: int | None = None
    t311_ms: int | None = None
    n311: int | None = None
    time_alignment_timer: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {'type': 'Sib2AccessParams',
                             'ac_barring_present': self.ac_barring_present}
        for k in ('ac_barring_for_emergency',
                  'ac_barring_mo_signalling_factor_pct',
                  'ac_barring_mo_signalling_time_s',
                  'ac_barring_mo_data_factor_pct',
                  'ac_barring_mo_data_time_s',
                  'number_of_ra_preambles', 'power_ramping_step_db',
                  'preamble_initial_target_power_dbm', 'preamble_trans_max',
                  'prach_root_sequence_index', 'prach_config_index',
                  'reference_signal_power_dbm', 'ul_carrier_freq',
                  'ul_bandwidth_rb', 'additional_spectrum_emission',
                  't300_ms', 't301_ms', 't310_ms', 'n310', 't311_ms', 'n311'):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        if self.time_alignment_timer:
            d['time_alignment_timer'] = self.time_alignment_timer
        return d


def decode_sib2(r: UperReader) -> Sib2AccessParams:
    """Decode SIB2 body: access-barring / RACH / common-radio-config.

    Dual-purpose (decode + advance), the same pattern as ``decode_sib3``:
    advances the UPER cursor past the whole SIB2 body (so the container walker
    can reach later SIBs) AND returns the extracted
    :class:`Sib2AccessParams`. Callers that only need to advance
    (``decode_si_time``, ``decode_si_neighbors``) ignore the return value.

    SystemInformationBlockType2 ::= SEQUENCE {
        ac-BarringInfo                  SEQUENCE { ... } OPTIONAL,
        radioResourceConfigCommon       RadioResourceConfigCommonSIB,
        ue-TimersAndConstants           UE-TimersAndConstants,
        freqInfo                        SEQUENCE { ... },
        mbsfn-SubframeConfigList        MBSFN-SubframeConfigList OPTIONAL,
        timeAlignmentTimerCommon        TimeAlignmentTimer,
        ...  -- extensions from v9.0.0 onwards
    }

    Reference: 3GPP TS 36.331 §6.3.1
    """
    out = Sib2AccessParams()

    has_ext = r.read_bool()

    # SIB2 root optionals: ac-BarringInfo, mbsfn-SubframeConfigList = 2
    opt_sib2 = r.read_bits(2)

    # ── ac-BarringInfo (optional SEQUENCE, extensible) ────────────
    if (opt_sib2 >> 1) & 1:
        _skip_ac_barring_info(r, out)

    # ── radioResourceConfigCommonSIB (mandatory) ──────────────────
    _skip_radio_resource_config_common_sib(r, out)

    # ── ue-TimersAndConstants (mandatory) ─────────────────────────
    _skip_ue_timers_and_constants(r, out)

    # ── freqInfo (mandatory SEQUENCE, not extensible) ─────────────
    # Optionals: ul-CarrierFreq, ul-Bandwidth = 2
    fi_opt = r.read_bits(2)
    if (fi_opt >> 1) & 1:
        out.ul_carrier_freq = r.read_constrained_int(0, 65535)  # ARFCN-ValueEUTRA
    if fi_opt & 1:
        out.ul_bandwidth_rb = _lut(_UL_BANDWIDTH_RB, r.read_enum(6))
    out.additional_spectrum_emission = r.read_constrained_int(1, 32)

    # ── mbsfn-SubframeConfigList (optional) ───────────────────────
    if opt_sib2 & 1:
        _skip_mbsfn_subframe_config_list(r)

    # ── timeAlignmentTimerCommon: ENUMERATED (8 values) ───────────
    out.time_alignment_timer = _TIME_ALIGNMENT_TIMER[r.read_enum(8)]

    # ── extensions ────────────────────────────────────────────────
    if has_ext:
        skip_extension_additions(r)

    return out


def _skip_ac_barring_info(r: UperReader, out: Sib2AccessParams) -> None:
    """Skip ac-BarringInfo SEQUENCE, extracting barring config into ``out``.

    ac-BarringInfo ::= SEQUENCE {
        ac-BarringForEmergency      BOOLEAN,
        ac-BarringForMO-Signalling  AC-BarringConfig OPTIONAL,
        ac-BarringForMO-Data        AC-BarringConfig OPTIONAL
    }
    AC-BarringConfig ::= SEQUENCE {
        ac-BarringFactor    ENUMERATED (16 values),
        ac-BarringTime      ENUMERATED (8 values),
        ac-BarringForSpecialAC  BIT STRING (SIZE (5))
    }
    """
    out.ac_barring_present = True
    opt = r.read_bits(2)  # two optionals: MO-Signalling, MO-Data
    out.ac_barring_for_emergency = r.read_bool()

    if (opt >> 1) & 1:  # ac-BarringForMO-Signalling
        out.ac_barring_mo_signalling_factor_pct = _lut(
            _AC_BARRING_FACTOR_PCT, r.read_enum(16))
        out.ac_barring_mo_signalling_time_s = _lut(
            _AC_BARRING_TIME_S, r.read_enum(8))
        r.read_bits(5)   # ac-BarringForSpecialAC

    if opt & 1:  # ac-BarringForMO-Data
        out.ac_barring_mo_data_factor_pct = _lut(
            _AC_BARRING_FACTOR_PCT, r.read_enum(16))
        out.ac_barring_mo_data_time_s = _lut(
            _AC_BARRING_TIME_S, r.read_enum(8))
        r.read_bits(5)   # ac-BarringForSpecialAC


def _skip_radio_resource_config_common_sib(
        r: UperReader, out: Sib2AccessParams) -> None:
    """Skip RadioResourceConfigCommonSIB, extracting RACH/PRACH/PDSCH into ``out``.

    RadioResourceConfigCommonSIB ::= SEQUENCE {
        rach-ConfigCommon           RACH-ConfigCommon,
        bcch-Config                 BCCH-Config,
        pcch-Config                 PCCH-Config,
        prach-Config                PRACH-Config,
        pdsch-ConfigCommon          PDSCH-ConfigCommon,
        pusch-ConfigCommon          PUSCH-ConfigCommon,
        pucch-ConfigCommon          PUCCH-ConfigCommon,
        soundingRS-UL-ConfigCommon  SoundingRS-UL-ConfigCommon,
        uplinkPowerControlCommon    UplinkPowerControlCommon,
        ul-CyclicPrefixLength       UL-CyclicPrefixLength,
        ...
    }
    """
    rrcc_ext = r.read_bool()  # extension marker
    # No root optionals — all 10 fields are mandatory

    _skip_rach_config_common(r, out)
    _skip_bcch_config(r)
    _skip_pcch_config(r)
    _skip_prach_config(r, out)
    _skip_pdsch_config_common(r, out)
    _skip_pusch_config_common(r)
    _skip_pucch_config_common(r)
    _skip_sounding_rs_ul_config_common(r)
    _skip_uplink_power_control_common(r)
    r.read_enum(2)  # ul-CyclicPrefixLength: len1, len2

    if rrcc_ext:
        skip_extension_additions(r)


def _skip_rach_config_common(r: UperReader, out: Sib2AccessParams) -> None:
    """Skip RACH-ConfigCommon (extensible SEQUENCE), extracting into ``out``.

    RACH-ConfigCommon ::= SEQUENCE {
        preambleInfo            SEQUENCE {
            numberOfRA-Preambles    ENUMERATED (16 values),
            preamblesGroupAConfig   SEQUENCE { ... } OPTIONAL
        },
        powerRampingParameters  SEQUENCE {
            powerRampingStep        ENUMERATED (4 values),
            preambleInitialReceivedTargetPower  ENUMERATED (16 values)
        },
        ra-SupervisionInfo      SEQUENCE {
            preambleTransMax        ENUMERATED (11 values),
            ra-ResponseWindowSize   ENUMERATED (8 values),
            mac-ContentionResolutionTimer  ENUMERATED (8 values)
        },
        maxHARQ-Msg3Tx          INTEGER (1..8),
        ...
    }
    """
    rach_ext = r.read_bool()

    # preambleInfo — 1 optional (preamblesGroupAConfig)
    pi_opt = r.read_bits(1)
    out.number_of_ra_preambles = _lut(_RA_PREAMBLES, r.read_enum(16))

    if pi_opt & 1:  # preamblesGroupAConfig (extensible)
        pga_ext = r.read_bool()
        r.read_enum(15)   # sizeOfRA-PreamblesGroupA: 15 values
        r.read_enum(8)    # messageSizeGroupA: ENUMERATED (4 values → b56, b144, b208, b256)
        r.read_enum(8)    # messagePowerOffsetGroupB: ENUMERATED (8 values)
        if pga_ext:
            skip_extension_additions(r)

    # powerRampingParameters (not extensible)
    out.power_ramping_step_db = _lut(_POWER_RAMPING_STEP_DB, r.read_enum(4))
    out.preamble_initial_target_power_dbm = _lut(
        _PREAMBLE_INIT_POWER_DBM, r.read_enum(16))

    # ra-SupervisionInfo (not extensible)
    out.preamble_trans_max = _lut(_PREAMBLE_TRANS_MAX, r.read_enum(11))
    r.read_enum(8)    # ra-ResponseWindowSize: 8 values
    r.read_enum(8)    # mac-ContentionResolutionTimer: 8 values

    r.read_constrained_int(1, 8)  # maxHARQ-Msg3Tx

    if rach_ext:
        skip_extension_additions(r)


def _skip_bcch_config(r: UperReader) -> None:
    """Skip BCCH-Config (not extensible).
    modificationPeriodCoeff: ENUMERATED {n2, n4, n8, n16} = 4 values.
    """
    r.read_enum(4)


def _skip_pcch_config(r: UperReader) -> None:
    """Skip PCCH-Config (not extensible).
    defaultPagingCycle: ENUMERATED {rf32..rf256} = 4 values.
    nB: ENUMERATED {fourT..oneT..etc} = 8 values.
    """
    r.read_enum(4)  # defaultPagingCycle
    r.read_enum(8)  # nB


def _skip_prach_config(r: UperReader, out: Sib2AccessParams) -> None:
    """Skip PRACH-Config (not extensible), extracting into ``out``.

    PRACH-Config ::= SEQUENCE {
        rootSequenceIndex       INTEGER (0..837),
        prach-ConfigInfo        PRACH-ConfigInfo
    }
    PRACH-ConfigInfo ::= SEQUENCE {
        prach-ConfigIndex       INTEGER (0..63),
        highSpeedFlag           BOOLEAN,
        zeroCorrelationZoneConfig  INTEGER (0..15),
        prach-FreqOffset        INTEGER (0..94)
    }
    """
    out.prach_root_sequence_index = r.read_constrained_int(0, 837)
    # PRACH-ConfigInfo (not extensible)
    out.prach_config_index = r.read_constrained_int(0, 63)
    r.read_bool()                     # highSpeedFlag
    r.read_constrained_int(0, 15)    # zeroCorrelationZoneConfig
    r.read_constrained_int(0, 94)    # prach-FreqOffset


def _skip_pdsch_config_common(r: UperReader, out: Sib2AccessParams) -> None:
    """Skip PDSCH-ConfigCommon (not extensible), extracting into ``out``.
    referenceSignalPower: INTEGER (-60..50)
    p-b: INTEGER (0..3)
    """
    out.reference_signal_power_dbm = r.read_constrained_int(-60, 50)
    r.read_constrained_int(0, 3)     # p-b


def _skip_pusch_config_common(r: UperReader) -> None:
    """Skip PUSCH-ConfigCommon (NOT extensible at root — TS 36.331 §6.3.2).

    PUSCH-ConfigCommon ::= SEQUENCE {
        pusch-ConfigBasic  SEQUENCE {
            n-SB                  INTEGER (1..4),
            hoppingMode           ENUMERATED {interSubFrame, intraAndInterSubFrame} = 2,
            pusch-HoppingOffset   INTEGER (0..98),
            enable64QAM           BOOLEAN
        },
        ul-ReferenceSignalsPUSCH  SEQUENCE {
            groupHoppingEnabled   BOOLEAN,
            groupAssignmentPUSCH  INTEGER (0..29),
            sequenceHoppingEnabled BOOLEAN,
            cyclicShift           INTEGER (0..7)
        }
    }

    The base PUSCH-ConfigCommon SEQUENCE carries no ``...`` extension marker —
    the Rel-12 ``enable64QAM-v1270`` addition rides in the enclosing
    RadioResourceConfigCommonSIB extension-additions block, NOT here (confirmed
    against the stock tshark lte-rrc dissector on the real 0xB0C0 corpus, #N).
    Reading a spurious extension bit here shifted every subsequent field by one
    bit and corrupted PUCCH/SRS/UE-timers — the latent bug the synthetic-only
    #N tests missed.
    """
    # pusch-ConfigBasic (not extensible)
    r.read_constrained_int(1, 4)     # n-SB
    r.read_enum(2)                    # hoppingMode
    r.read_constrained_int(0, 98)    # pusch-HoppingOffset
    r.read_bool()                     # enable64QAM

    # ul-ReferenceSignalsPUSCH (not extensible)
    r.read_bool()                     # groupHoppingEnabled
    r.read_constrained_int(0, 29)    # groupAssignmentPUSCH
    r.read_bool()                     # sequenceHoppingEnabled
    r.read_constrained_int(0, 7)     # cyclicShift


def _skip_pucch_config_common(r: UperReader) -> None:
    """Skip PUCCH-ConfigCommon (not extensible).
    deltaPUCCH-Shift: ENUMERATED {ds1, ds2, ds3} = 3 values
    nRB-CQI: INTEGER (0..98)
    nCS-AN: INTEGER (0..7)
    n1PUCCH-AN: INTEGER (0..2047)
    """
    r.read_enum(3)                    # deltaPUCCH-Shift
    r.read_constrained_int(0, 98)    # nRB-CQI
    r.read_constrained_int(0, 7)     # nCS-AN
    r.read_constrained_int(0, 2047)  # n1PUCCH-AN


def _skip_sounding_rs_ul_config_common(r: UperReader) -> None:
    """Skip SoundingRS-UL-ConfigCommon (CHOICE: release | setup).

    SoundingRS-UL-ConfigCommon ::= CHOICE {
        release  NULL,
        setup    SEQUENCE {
            srs-BandwidthConfig     ENUMERATED (8 values),
            srs-SubframeConfig      ENUMERATED (16 values),
            ackNackSRS-SimultaneousTransmission  BOOLEAN,
            srs-MaxUpPts            BOOLEAN OPTIONAL  -- conditional
        }
    }
    """
    choice = r.read_choice(2)
    if choice == 0:
        pass  # release: NULL
    else:  # setup
        opt = r.read_bits(1)  # srs-MaxUpPts optional
        r.read_enum(8)   # srs-BandwidthConfig
        r.read_enum(16)  # srs-SubframeConfig
        r.read_bool()    # ackNackSRS-SimultaneousTransmission
        if opt & 1:
            r.read_bool()  # srs-MaxUpPts


def _skip_uplink_power_control_common(r: UperReader) -> None:
    """Skip UplinkPowerControlCommon (not extensible).
    p0-NominalPUSCH:      INTEGER (-126..24)
    alpha:                 ENUMERATED (8 values)
    p0-NominalPUCCH:      INTEGER (-127..-96)
    deltaFList-PUCCH:      SEQUENCE { 5 ENUMERATED fields }
    deltaPreambleMsg3:     INTEGER (-1..6)
    """
    r.read_constrained_int(-126, 24)   # p0-NominalPUSCH
    r.read_enum(8)                      # alpha: al0..al1 (8 values)
    r.read_constrained_int(-127, -96)  # p0-NominalPUCCH

    # deltaFList-PUCCH: DeltaFList-PUCCH (not extensible)
    r.read_enum(3)  # deltaF-PUCCH-Format1:  ENUMERATED (3 values)
    r.read_enum(3)  # deltaF-PUCCH-Format1b: ENUMERATED (3 values)
    r.read_enum(4)  # deltaF-PUCCH-Format2:  ENUMERATED (4 values)
    r.read_enum(3)  # deltaF-PUCCH-Format2a: ENUMERATED (3 values)
    r.read_enum(3)  # deltaF-PUCCH-Format2b: ENUMERATED (3 values)

    r.read_constrained_int(-1, 6)  # deltaPreambleMsg3


def _skip_ue_timers_and_constants(r: UperReader, out: Sib2AccessParams) -> None:
    """Skip UE-TimersAndConstants (extensible SEQUENCE), extracting into ``out``.

    t300/t301 span 8 values; t310/t311 span 7 (both still 3-bit ENUMs, so the
    read width is unchanged); n310/n311 span 8.
    """
    ue_ext = r.read_bool()
    out.t300_ms = _lut(_T300_T301_MS, r.read_enum(8))
    out.t301_ms = _lut(_T300_T301_MS, r.read_enum(8))
    out.t310_ms = _lut(_T310_MS, r.read_enum(8))
    out.n310 = _lut(_N310, r.read_enum(8))
    out.t311_ms = _lut(_T311_MS, r.read_enum(8))
    out.n311 = _lut(_N311, r.read_enum(8))
    if ue_ext:
        skip_extension_additions(r)


def _skip_mbsfn_subframe_config_list(r: UperReader) -> None:
    """Skip MBSFN-SubframeConfigList: SEQUENCE (SIZE (1..8)) OF MBSFN-SubframeConfig.

    MBSFN-SubframeConfig ::= SEQUENCE {
        radioframeAllocationPeriod  ENUMERATED (6 values),
        radioframeAllocationOffset  INTEGER (0..7),
        subframeAllocation          CHOICE {
            oneFrame    BIT STRING (SIZE (6)),
            fourFrames  BIT STRING (SIZE (24))
        }
    }
    """
    num = r.read_constrained_int(1, 8)
    for _ in range(num):
        r.read_enum(6)                    # radioframeAllocationPeriod
        r.read_constrained_int(0, 7)     # radioframeAllocationOffset
        choice = r.read_choice(2)         # subframeAllocation
        if choice == 0:
            r.read_bits(6)  # oneFrame
        else:
            r.read_bits(24)  # fourFrames


# -----------------------------------------------------------------------
# SIB3 skip
# -----------------------------------------------------------------------

@dataclass
class Sib3ReselParams:
    """Cell reselection parameters from SIB3."""
    q_hyst_db: int                               # Hysteresis in dB (0..24)
    thresh_serving_low: int                       # ReselectionThreshold (0..31) = 2*value dB
    cell_resel_priority: int                      # CellReselectionPriority (0..7)
    s_non_intra_search: int | None = None         # ReselectionThreshold (0..31), optional
    q_rx_lev_min: int = 0                         # INTEGER (-70..-22), in dBm = 2*value
    s_intra_search: int | None = None             # ReselectionThreshold (0..31), optional
    t_resel_eutra: int = 0                        # T-Reselection (0..7) in seconds

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'type': 'Sib3ReselParams',
            'q_hyst_db': self.q_hyst_db,
            'thresh_serving_low': self.thresh_serving_low,
            'cell_resel_priority': self.cell_resel_priority,
            'q_rx_lev_min': self.q_rx_lev_min,
            't_resel_eutra': self.t_resel_eutra,
        }
        if self.s_non_intra_search is not None:
            d['s_non_intra_search'] = self.s_non_intra_search
        if self.s_intra_search is not None:
            d['s_intra_search'] = self.s_intra_search
        return d


def decode_sib3(r: UperReader) -> Sib3ReselParams:
    """Decode SIB3 body: cell reselection parameters (cursor advances past it).

    SystemInformationBlockType3 ::= SEQUENCE {
        cellReselectionInfoCommon   SEQUENCE {
            q-Hyst  ENUMERATED {dB0..dB24}  -- 16 values
            speedStateReselectionPars  SEQUENCE { ... } OPTIONAL
        },
        cellReselectionServingFreqInfo  SEQUENCE {
            s-NonIntraSearch  ReselectionThreshold OPTIONAL,  -- INTEGER (0..31)
            threshServingLow  ReselectionThreshold,
            cellReselectionPriority  CellReselectionPriority  -- INTEGER (0..7)
        },
        intraFreqCellReselectionInfo  SEQUENCE {
            q-RxLevMin           INTEGER (-70..-22),
            p-Max                INTEGER (-30..33) OPTIONAL,
            s-IntraSearch        ReselectionThreshold OPTIONAL,
            allowedMeasBandwidth AllowedMeasBandwidth OPTIONAL,
            presenceAntennaPort1 BOOLEAN,
            neighCellConfig      BIT STRING (SIZE (2)),
            t-ReselectionEUTRA   INTEGER (0..7),
            t-ReselectionEUTRA-SF SpeedStateScaleFactors OPTIONAL
        },
        ...  -- extensions
    }
    """
    # Extension marker
    has_ext = r.read_bool()

    # cellReselectionInfoCommon
    # Optional bitmap: 1 field (speedStateReselectionPars)
    has_speed = r.read_bool()
    q_hyst_idx = r.read_enum(16)  # q-Hyst: 16 values (dB0..dB24)
    q_hyst_db = Q_HYST_DB[q_hyst_idx] if q_hyst_idx < len(Q_HYST_DB) else 0
    if has_speed:
        # speedStateReselectionPars SEQUENCE
        # mobilityStateParameters SEQUENCE { 4 fields }
        # t-Evaluation / t-HystNormal are ENUMERATED {s30,s60,s120,s180,s240,
        # spare3..1} — 8 values = 3 bits each, NOT INTEGER (1..16) (#N).
        r.read_enum(8)   # t-Evaluation
        r.read_enum(8)   # t-HystNormal
        r.read_constrained_int(1, 16)  # n-CellChangeMedium: 1..16
        r.read_constrained_int(1, 16)  # n-CellChangeHigh: 1..16
        # q-HystSF SEQUENCE { sf-Medium ENUM(4), sf-High ENUM(4) }
        r.read_enum(4)  # sf-Medium
        r.read_enum(4)  # sf-High

    # cellReselectionServingFreqInfo
    # Optional: s-NonIntraSearch
    opt_csfi = r.read_bits(1)
    s_non_intra_search = None
    if opt_csfi:
        s_non_intra_search = r.read_constrained_int(0, 31)
    thresh_serving_low = r.read_constrained_int(0, 31)
    cell_resel_priority = r.read_constrained_int(0, 7)

    # intraFreqCellReselectionInfo
    # Optionals: p-Max, s-IntraSearch, allowedMeasBandwidth, t-ReselectionEUTRA-SF
    opt_ifcri = r.read_bits(4)
    q_rx_lev_min = r.read_constrained_int(-70, -22)
    if (opt_ifcri >> 3) & 1:
        r.read_constrained_int(-30, 33)  # p-Max
    s_intra_search = None
    if (opt_ifcri >> 2) & 1:
        s_intra_search = r.read_constrained_int(0, 31)
    if (opt_ifcri >> 1) & 1:
        r.read_enum(6)  # allowedMeasBandwidth: 6 values
    r.read_bool()  # presenceAntennaPort1
    r.read_bits(2)  # neighCellConfig: BIT STRING (SIZE (2))
    t_resel_eutra = r.read_constrained_int(0, 7)
    if opt_ifcri & 1:
        _skip_speed_state_scale_factors(r)

    # Skip extensions if present
    if has_ext:
        skip_extension_additions(r)

    return Sib3ReselParams(
        q_hyst_db=q_hyst_db,
        thresh_serving_low=thresh_serving_low,
        cell_resel_priority=cell_resel_priority,
        s_non_intra_search=s_non_intra_search,
        q_rx_lev_min=q_rx_lev_min,
        s_intra_search=s_intra_search,
        t_resel_eutra=t_resel_eutra,
    )


# -----------------------------------------------------------------------
# SIB4 skip + neighbor extraction
# -----------------------------------------------------------------------

@dataclass
class Sib4NeighCell:
    """A single intra-frequency neighbor cell from SIB4."""
    pci: int                 # PhysCellId (0..503)
    q_offset_db: int         # dB offset from Q-OffsetRange

    def to_dict(self) -> dict[str, Any]:
        return {'pci': self.pci, 'q_offset_db': self.q_offset_db}


@dataclass
class Sib4ExcludedRange:
    """An excluded PCI range from SIB4."""
    start: int               # PhysCellId (0..503)
    range_size: int | None   # n4..n504 mapped to count, None = single PCI

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {'start': self.start}
        if self.range_size is not None:
            d['range'] = self.range_size
        return d


@dataclass
class Sib4Neighbors:
    """Intra-frequency neighbor cells from SIB4."""
    pcis: list[int] = field(default_factory=list)
    cells: list[Sib4NeighCell] = field(default_factory=list)
    excluded: list[Sib4ExcludedRange] = field(default_factory=list)
    csg_range: Sib4ExcludedRange | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'type': 'Sib4Neighbors',
            'pcis': self.pcis,
        }
        if self.cells:
            d['cells'] = [c.to_dict() for c in self.cells]
        if self.excluded:
            d['excluded'] = [e.to_dict() for e in self.excluded]
        if self.csg_range is not None:
            d['csg_range'] = self.csg_range.to_dict()
        return d


def _read_phys_cell_id_range(r: UperReader) -> Sib4ExcludedRange:
    """PhysCellIdRange ::= SEQUENCE { start PhysCellId, range ENUM(16) OPTIONAL }.

    Non-extensible SEQUENCE with one optional field: per X.691 §18.2 the
    optional-presence bitmap precedes the components, so the ``range``
    presence bit comes FIRST, then ``start`` (9 bits), then the 4-bit range
    enum if present (#N — the original read start-then-bit, corrupting
    every PhysCellIdRange decode).
    """
    has_range = r.read_bool()
    start = r.read_constrained_int(0, 503)
    range_size = None
    if has_range:
        range_idx = r.read_enum(16)
        range_size = (
            PCI_RANGE_VALUES[range_idx]
            if range_idx < len(PCI_RANGE_VALUES) else None
        )
    return Sib4ExcludedRange(start=start, range_size=range_size)


def decode_sib4(r: UperReader) -> Sib4Neighbors:
    """Decode SIB4 body: intra-freq neighbor PCIs, q-offsets, excluded cell
    ranges, and CSG PCI range (cursor advances past the body).

    SystemInformationBlockType4 ::= SEQUENCE {
        intraFreqNeighCellList       IntraFreqNeighCellList OPTIONAL,
        intraFreqExcludedCellList    IntraFreqExcludedCellList OPTIONAL,
        csg-PhysCellIdRange          PhysCellIdRange OPTIONAL,
        ...
    }
    IntraFreqNeighCellList ::= SEQUENCE (SIZE (1..16)) OF IntraFreqNeighCellInfo
    IntraFreqNeighCellInfo ::= SEQUENCE {
        physCellId    PhysCellId,          -- INTEGER (0..503)
        q-OffsetCell  Q-OffsetRange,       -- ENUMERATED (31 values)
        ...  -- extensible (ext marker bit per entry)
    }
    """
    result = Sib4Neighbors()

    has_ext = r.read_bool()
    opt = r.read_bits(3)  # intraFreqNeighCellList, intraFreqExcludedCellList, csg-PhysCellIdRange

    if (opt >> 2) & 1:  # intraFreqNeighCellList present
        num_cells = r.read_constrained_int(1, 16)
        for _ in range(num_cells):
            # IntraFreqNeighCellInfo is extensible (has ... in ASN.1)
            cell_ext = r.read_bool()
            pci = r.read_constrained_int(0, 503)
            off_idx = r.read_enum(31)  # q-OffsetCell: Q-OffsetRange (31 values)
            q_offset_db = Q_OFFSET_DB[off_idx] if off_idx < len(Q_OFFSET_DB) else 0
            result.pcis.append(pci)
            result.cells.append(Sib4NeighCell(pci=pci, q_offset_db=q_offset_db))
            if cell_ext:
                skip_extension_additions(r)

    if (opt >> 1) & 1:  # intraFreqExcludedCellList
        num_excluded = r.read_constrained_int(1, 16)
        for _ in range(num_excluded):
            result.excluded.append(_read_phys_cell_id_range(r))

    if opt & 1:  # csg-PhysCellIdRange
        result.csg_range = _read_phys_cell_id_range(r)

    if has_ext:
        skip_extension_additions(r)

    return result


# -----------------------------------------------------------------------
# SIB5 skip + neighbor extraction
# -----------------------------------------------------------------------

@dataclass
class Sib5Neighbor:
    pci: int
    earfcn: int
    q_offset: int = 0  # raw enum index


# AllowedMeasBandwidth ENUMERATED {mbw6, mbw15, mbw25, mbw50, mbw75, mbw100}
# → measurement bandwidth in resource blocks (TS 36.331 §6.3.6).
_ALLOWED_MEAS_BW_RB = [6, 15, 25, 50, 75, 100]


@dataclass
class Sib5Carrier:
    """One InterFreqCarrierFreqInfo entry from SIB5 (#N).

    Scaled per TS 36.331 §6.3.4: Q-RxLevMin and ReselectionThreshold are
    signalled in 2 dB steps, so ``*_dbm`` / ``*_db`` fields hold 2× the raw
    IE value (matching tshark's rendering, e.g. raw -53 → "-106dBm").
    ``bands`` merges multiBandInfoList (v8h0, bands 1..64) and
    multiBandInfoList-v9e0 (bands 65..256) overlays for this carrier;
    ``earfcn_v9e0`` is the extended EARFCN when the Rel-8 dl-CarrierFreq
    saturates at 65535 (ARFCN-ValueEUTRA-v9e0).
    """
    earfcn: int
    q_rx_lev_min_dbm: int
    t_resel_eutra_s: int
    thresh_x_high_db: int
    thresh_x_low_db: int
    allowed_meas_bw_rb: int | None
    presence_antenna_port1: bool
    neigh_cell_config: int
    p_max_dbm: int | None = None
    cell_resel_priority: int | None = None
    q_offset_freq_db: int = 0            # DEFAULT dB0
    neighbors: list[Sib5Neighbor] = field(default_factory=list)
    excluded: list[Sib4ExcludedRange] = field(default_factory=list)
    bands: list[int] = field(default_factory=list)
    earfcn_v9e0: int | None = None
    # True for carriers signalled via interFreqCarrierFreqListExt-r12 (the
    # Rel-12 list extension beyond maxFreq=8; also carries EARFCN > 65535
    # natively via ARFCN-ValueEUTRA-r9). earfcn is the 18-bit r12 value.
    ext_r12: bool = False

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'earfcn': self.earfcn,
            'q_rx_lev_min_dbm': self.q_rx_lev_min_dbm,
            't_resel_eutra_s': self.t_resel_eutra_s,
            'thresh_x_high_db': self.thresh_x_high_db,
            'thresh_x_low_db': self.thresh_x_low_db,
            'presence_antenna_port1': self.presence_antenna_port1,
            'neigh_cell_config': self.neigh_cell_config,
            'q_offset_freq_db': self.q_offset_freq_db,
        }
        if self.allowed_meas_bw_rb is not None:
            d['allowed_meas_bw_rb'] = self.allowed_meas_bw_rb
        if self.p_max_dbm is not None:
            d['p_max_dbm'] = self.p_max_dbm
        if self.cell_resel_priority is not None:
            d['cell_resel_priority'] = self.cell_resel_priority
        if self.neighbors:
            d['neighbors'] = [
                {'pci': n.pci,
                 'q_offset_db': (Q_OFFSET_DB[n.q_offset]
                                 if n.q_offset < len(Q_OFFSET_DB) else None)}
                for n in self.neighbors]
        if self.excluded:
            d['excluded'] = [e.to_dict() for e in self.excluded]
        if self.bands:
            d['bands'] = self.bands
        if self.earfcn_v9e0 is not None:
            d['earfcn_v9e0'] = self.earfcn_v9e0
        if self.ext_r12:
            d['ext_r12'] = True
        return d


@dataclass
class Sib5Neighbors:
    """Inter-frequency neighbor cells from SIB5."""
    carriers: list[int] = field(default_factory=list)  # EARFCNs
    neighbors: list[Sib5Neighbor] = field(default_factory=list)
    carrier_info: list[Sib5Carrier] = field(default_factory=list)  # #N

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'type': 'Sib5Neighbors',
            'carriers': self.carriers,
            'neighbors': [{'pci': n.pci, 'earfcn': n.earfcn} for n in self.neighbors],
        }
        if self.carrier_info:
            d['carrier_info'] = [c.to_dict() for c in self.carrier_info]
        return d


def decode_sib5(r: UperReader) -> Sib5Neighbors:
    """Decode SIB5 body: per-carrier inter-freq reselection info, neighbor
    PCIs, excluded-PCI ranges, and v8h0/v9e0 multi-band overlays (cursor
    advances past the body).

    SystemInformationBlockType5 ::= SEQUENCE {
        interFreqCarrierFreqList  InterFreqCarrierFreqList,  -- SIZE (1..8)
        ...,
        lateNonCriticalExtension  OCTET STRING
            (CONTAINING SystemInformationBlockType5-v8h0-IEs) OPTIONAL,
        [[ interFreqCarrierFreqList-v1250 ... ]], ...
    }
    InterFreqCarrierFreqInfo ::= SEQUENCE {
        dl-CarrierFreq           ARFCN-ValueEUTRA,    -- INTEGER (0..65535)
        q-RxLevMin               Q-RxLevMin,           -- INTEGER (-70..-22)
        p-Max                    P-Max OPTIONAL,        -- INTEGER (-30..33)
        t-ReselectionEUTRA       T-Reselection,         -- INTEGER (0..7)
        t-ReselectionEUTRA-SF    SpeedStateScaleFactors OPTIONAL,
        threshX-High             ReselectionThreshold,  -- INTEGER (0..31)
        threshX-Low              ReselectionThreshold,  -- INTEGER (0..31)
        allowedMeasBandwidth     AllowedMeasBandwidth,  -- ENUMERATED (6)
        presenceAntennaPort1     BOOLEAN,
        cellReselectionPriority  CellReselectionPriority OPTIONAL, -- INTEGER (0..7)
        neighCellConfig          BIT STRING (SIZE (2)),
        q-OffsetFreq             Q-OffsetRange DEFAULT dB0, -- ENUMERATED (31)
        interFreqNeighCellList   InterFreqNeighCellList OPTIONAL, -- SIZE (1..16)
        interFreqExcludedCellList InterFreqExcludedCellList OPTIONAL,
        ...
    }
    """
    result = Sib5Neighbors()

    has_ext = r.read_bool()

    # interFreqCarrierFreqList: SEQUENCE (SIZE (1..8))
    num_carriers = r.read_constrained_int(1, 8)

    for _ in range(num_carriers):
        # InterFreqCarrierFreqInfo (extensible SEQUENCE)
        carrier_ext = r.read_bool()

        # Optional bitmap: p-Max, t-Resel-SF, cellReselPriority,
        # q-OffsetFreq(DEFAULT), interFreqNeighCellList, interFreqExcludedCellList
        # = 6 optionals in base
        opt = r.read_bits(6)

        earfcn = r.read_constrained_int(0, 65535)  # dl-CarrierFreq
        result.carriers.append(earfcn)

        q_rx_lev_min = r.read_constrained_int(-70, -22)  # q-RxLevMin

        p_max = None
        if (opt >> 5) & 1:  # p-Max
            p_max = r.read_constrained_int(-30, 33)

        t_resel = r.read_constrained_int(0, 7)  # t-ReselectionEUTRA

        if (opt >> 4) & 1:  # t-ReselectionEUTRA-SF
            _skip_speed_state_scale_factors(r)

        thresh_x_high = r.read_constrained_int(0, 31)  # threshX-High
        thresh_x_low = r.read_constrained_int(0, 31)   # threshX-Low
        meas_bw_idx = r.read_enum(6)  # allowedMeasBandwidth
        antenna_port1 = r.read_bool()  # presenceAntennaPort1

        priority = None
        if (opt >> 3) & 1:  # cellReselectionPriority
            priority = r.read_constrained_int(0, 7)

        neigh_cell_config = r.read_bits(2)  # neighCellConfig

        q_offset_freq_db = 0
        if (opt >> 2) & 1:  # q-OffsetFreq (has DEFAULT, present bit in bitmap)
            off_idx = r.read_enum(31)
            if off_idx < len(Q_OFFSET_DB):
                q_offset_freq_db = Q_OFFSET_DB[off_idx]

        carrier = Sib5Carrier(
            earfcn=earfcn,
            q_rx_lev_min_dbm=q_rx_lev_min * 2,
            t_resel_eutra_s=t_resel,
            thresh_x_high_db=thresh_x_high * 2,
            thresh_x_low_db=thresh_x_low * 2,
            allowed_meas_bw_rb=_lut(_ALLOWED_MEAS_BW_RB, meas_bw_idx),
            presence_antenna_port1=antenna_port1,
            neigh_cell_config=neigh_cell_config,
            p_max_dbm=p_max,
            cell_resel_priority=priority,
            q_offset_freq_db=q_offset_freq_db,
        )
        result.carrier_info.append(carrier)

        if (opt >> 1) & 1:  # interFreqNeighCellList
            num_neigh = r.read_constrained_int(1, 16)
            for _ in range(num_neigh):
                pci = r.read_constrained_int(0, 503)
                q_off = r.read_enum(31)
                neigh = Sib5Neighbor(pci=pci, earfcn=earfcn, q_offset=q_off)
                result.neighbors.append(neigh)
                carrier.neighbors.append(neigh)

        if opt & 1:  # interFreqExcludedCellList (a.k.a. interFreqBlackCellList)
            num_excl = r.read_constrained_int(1, 16)
            for _ in range(num_excl):
                carrier.excluded.append(_read_phys_cell_id_range(r))

        if carrier_ext:
            skip_extension_additions(r)

    # SIB5 extension additions: decode the lateNonCriticalExtension
    # (v8h0/v9e0 multi-band overlays), skip the rest.
    if has_ext:
        _read_sib5_extension_additions(r, result)

    return result


def _read_sib5_extension_additions(r: UperReader, result: Sib5Neighbors) -> None:
    """Consume SIB5's extension-additions block, decoding addition 0.

    Same wire walk as :func:`asn1_helpers.skip_extension_additions`, but two
    of SystemInformationBlockType5's extension additions are decoded instead
    of skipped (#N):

      addition 0 — ``lateNonCriticalExtension OCTET STRING (CONTAINING
        SystemInformationBlockType5-v8h0-IEs)``: the v8h0/v9e0 per-carrier
        multi-band overlays.
      addition 1 — the ``[[ interFreqCarrierFreqList-v1250,
        interFreqCarrierFreqListExt-r12 ]]`` version group: Ext-r12 carries
        ADDITIONAL inter-freq carriers (beyond the Rel-8 maxFreq=8 list, with
        native 18-bit EARFCNs and their own neighbour / excluded lists) —
        observed on real T99W175/EM9291-class SI messages in the corpus.

    Later additions (v1280+, scptm) are still skipped opaquely.
    """
    marker = r.read_bits(1)
    if marker == 0:
        num_ext = r.read_bits(6)
    else:
        num_ext = r.read_bits(8)

    bitmap = r.read_bits(num_ext + 1)

    for i in range(num_ext + 1):
        if not (bitmap >> (num_ext - i)) & 1:
            continue
        length = read_open_type_length(r)
        if i in (0, 1):
            # Capture and decode (never let a malformed overlay abort the
            # skip: the cursor is already advanced past the open type
            # either way).
            payload = bytes(r.read_bits(8) for _ in range(length))
            try:
                if i == 0:
                    _apply_sib5_late_extension(payload, result)
                else:
                    _apply_sib5_v1250_group(payload, result)
            except (IndexError, ValueError):
                pass
        else:
            r.skip_bits(length * 8)


def _apply_sib5_late_extension(payload: bytes, result: Sib5Neighbors) -> None:
    """Decode SystemInformationBlockType5-v8h0-IEs into ``result`` (#N).

    ``payload`` is the open-type content of the lateNonCriticalExtension
    addition: the encoding of the OCTET STRING itself (length determinant +
    octets), whose contents are the UPER encoding of:

    SystemInformationBlockType5-v8h0-IEs ::= SEQUENCE {
        interFreqCarrierFreqList-v8h0  SEQUENCE (SIZE (1..maxFreq)) OF
            InterFreqCarrierFreqInfo-v8h0        OPTIONAL,
        nonCriticalExtension  SystemInformationBlockType5-v9e0-IEs OPTIONAL
    }
    InterFreqCarrierFreqInfo-v8h0 ::= SEQUENCE {
        multiBandInfoList  MultiBandInfoList OPTIONAL
            -- SEQUENCE (SIZE (1..maxMultiBands=8)) OF FreqBandIndicator (1..64)
    }
    SystemInformationBlockType5-v9e0-IEs ::= SEQUENCE {
        interFreqCarrierFreqList-v9e0  SEQUENCE (SIZE (1..maxFreq)) OF
            InterFreqCarrierFreqInfo-v9e0        OPTIONAL,
        nonCriticalExtension  ... OPTIONAL       -- v10j0+, not decoded
    }
    InterFreqCarrierFreqInfo-v9e0 ::= SEQUENCE {
        dl-CarrierFreq-v9e0    ARFCN-ValueEUTRA-v9e0 OPTIONAL, -- (65536..262143)
        multiBandInfoList-v9e0 MultiBandInfoList-v9e0 OPTIONAL
            -- SIZE (1..8) OF MultiBandInfo-v9e0
    }
    MultiBandInfo-v9e0 ::= SEQUENCE {
        freqBandIndicator-v9e0  FreqBandIndicator-v9e0 OPTIONAL -- (65..256)
    }

    The lists parallel the Rel-8 interFreqCarrierFreqList by index (entry N
    extends carrier N). Validated bit-for-bit against stock tshark on the
    #N T99W175 vector (lateNonCriticalExtension e2309a709a7050011010 →
    bands [49], [42,49], [42,49] on carriers 1..3 and v9e0 band 66 on
    carrier 4).
    """
    rr = UperReader(payload)
    # OCTET STRING contents: unconstrained length determinant + octets.
    # Decode in place — the IEs start right after the length determinant,
    # which is byte-aligned here (open-type payloads always are).
    read_open_type_length(rr)

    # v8h0-IEs (not extensible): 2 optionals
    opt = rr.read_bits(2)
    if (opt >> 1) & 1:  # interFreqCarrierFreqList-v8h0
        num = rr.read_constrained_int(1, 8)
        for idx in range(num):
            if rr.read_bool():  # multiBandInfoList present
                nbands = rr.read_constrained_int(1, 8)
                bands = [rr.read_constrained_int(1, 64) for _ in range(nbands)]
                if idx < len(result.carrier_info):
                    result.carrier_info[idx].bands.extend(bands)

    if not opt & 1:  # no nonCriticalExtension (v9e0-IEs)
        return

    # v9e0-IEs (not extensible): 2 optionals
    opt9 = rr.read_bits(2)
    if (opt9 >> 1) & 1:  # interFreqCarrierFreqList-v9e0
        num = rr.read_constrained_int(1, 8)
        for idx in range(num):
            entry_opt = rr.read_bits(2)  # dl-CarrierFreq-v9e0, multiBandInfoList-v9e0
            if (entry_opt >> 1) & 1:
                earfcn_ext = rr.read_constrained_int(65536, 262143)
                if idx < len(result.carrier_info):
                    result.carrier_info[idx].earfcn_v9e0 = earfcn_ext
            if entry_opt & 1:
                nbands = rr.read_constrained_int(1, 8)
                for _ in range(nbands):
                    if rr.read_bool():  # freqBandIndicator-v9e0 present
                        band = rr.read_constrained_int(65, 256)
                        if idx < len(result.carrier_info):
                            result.carrier_info[idx].bands.append(band)
    # Deeper nonCriticalExtension (v10j0+) intentionally not decoded — the
    # payload is an isolated byte string, so stopping here can't derail the
    # outer cursor.


def _apply_sib5_v1250_group(payload: bytes, result: Sib5Neighbors) -> None:
    """Decode SIB5 extension-addition group 1 into ``result`` (#N).

    ``payload`` is the open-type content of the version group, encoded as a
    SEQUENCE of its components (X.691 §19.8 — one presence bit per member):

    [[  interFreqCarrierFreqList-v1250     InterFreqCarrierFreqList-v1250
            OPTIONAL,  -- SIZE (1..maxFreq) OF InterFreqCarrierFreqInfo-v1250
        interFreqCarrierFreqListExt-r12    InterFreqCarrierFreqListExt-r12
            OPTIONAL   -- SIZE (1..maxFreq) OF InterFreqCarrierFreqInfo-r12
    ]]
    InterFreqCarrierFreqInfo-v1250 ::= SEQUENCE {      -- not extensible
        reducedMeasPerformance-r12      ENUMERATED {true}  OPTIONAL, -- 0 bits
        q-QualMinRSRQ-OnAllSymbols-r12  Q-QualMin-r9       OPTIONAL  -- (-34..-3)
    }
    InterFreqCarrierFreqInfo-r12 ::= SEQUENCE {        -- extensible
        dl-CarrierFreq-r12          ARFCN-ValueEUTRA-r9,   -- (0..262143)
        q-RxLevMin-r12              Q-RxLevMin,
        p-Max-r12                   P-Max OPTIONAL,
        t-ReselectionEUTRA-r12      T-Reselection,
        t-ReselectionEUTRA-SF-r12   SpeedStateScaleFactors OPTIONAL,
        threshX-High-r12            ReselectionThreshold,
        threshX-Low-r12             ReselectionThreshold,
        allowedMeasBandwidth-r12    AllowedMeasBandwidth,
        presenceAntennaPort1-r12    PresenceAntennaPort1,
        cellReselectionPriority-r12 CellReselectionPriority OPTIONAL,
        neighCellConfig-r12         NeighCellConfig,
        q-OffsetFreq-r12            Q-OffsetRange DEFAULT dB0,
        interFreqNeighCellList-r12  InterFreqNeighCellList OPTIONAL,
        interFreqExcludedCellList-r12 InterFreqExcludedCellList OPTIONAL,
        q-QualMin-r12               Q-QualMin-r9 OPTIONAL,
        threshX-Q-r12               SEQUENCE { HighQ, LowQ } OPTIONAL,
        q-QualMinWB-r12             Q-QualMin-r9 OPTIONAL,
        multiBandInfoList-r12       MultiBandInfoList-r11 OPTIONAL, -- (1..256)
        reducedMeasPerformance-r12  ENUMERATED {true} OPTIONAL,     -- 0 bits
        q-QualMinRSRQ-OnAllSymbols-r12 Q-QualMin-r9 OPTIONAL,
        ...
    }

    The Ext-r12 entries are appended to ``result`` as additional
    :class:`Sib5Carrier` rows with ``ext_r12=True``.
    """
    rr = UperReader(payload)
    grp_opt = rr.read_bits(2)  # v1250 list, Ext-r12 list

    if (grp_opt >> 1) & 1:  # interFreqCarrierFreqList-v1250 (parallels Rel-8)
        num = rr.read_constrained_int(1, 8)
        for _ in range(num):
            entry_opt = rr.read_bits(2)
            # reducedMeasPerformance-r12: single-value ENUMERATED = 0 bits
            if entry_opt & 1:
                rr.read_constrained_int(-34, -3)  # q-QualMinRSRQ-OnAllSymbols

    if not grp_opt & 1:  # no interFreqCarrierFreqListExt-r12
        return

    num = rr.read_constrained_int(1, 8)
    for _ in range(num):
        entry_ext = rr.read_bool()
        opt = rr.read_bits(12)

        earfcn = rr.read_constrained_int(0, 262143)  # dl-CarrierFreq-r12
        q_rx_lev_min = rr.read_constrained_int(-70, -22)
        p_max = None
        if (opt >> 11) & 1:
            p_max = rr.read_constrained_int(-30, 33)
        t_resel = rr.read_constrained_int(0, 7)
        if (opt >> 10) & 1:
            _skip_speed_state_scale_factors(rr)
        thresh_x_high = rr.read_constrained_int(0, 31)
        thresh_x_low = rr.read_constrained_int(0, 31)
        meas_bw_idx = rr.read_enum(6)
        antenna_port1 = rr.read_bool()
        priority = None
        if (opt >> 9) & 1:
            priority = rr.read_constrained_int(0, 7)
        neigh_cell_config = rr.read_bits(2)
        q_offset_freq_db = 0
        if (opt >> 8) & 1:
            off_idx = rr.read_enum(31)
            if off_idx < len(Q_OFFSET_DB):
                q_offset_freq_db = Q_OFFSET_DB[off_idx]

        carrier = Sib5Carrier(
            earfcn=earfcn,
            q_rx_lev_min_dbm=q_rx_lev_min * 2,
            t_resel_eutra_s=t_resel,
            thresh_x_high_db=thresh_x_high * 2,
            thresh_x_low_db=thresh_x_low * 2,
            allowed_meas_bw_rb=_lut(_ALLOWED_MEAS_BW_RB, meas_bw_idx),
            presence_antenna_port1=antenna_port1,
            neigh_cell_config=neigh_cell_config,
            p_max_dbm=p_max,
            cell_resel_priority=priority,
            q_offset_freq_db=q_offset_freq_db,
            ext_r12=True,
        )
        result.carriers.append(earfcn)
        result.carrier_info.append(carrier)

        if (opt >> 7) & 1:  # interFreqNeighCellList-r12
            num_neigh = rr.read_constrained_int(1, 16)
            for _ in range(num_neigh):
                pci = rr.read_constrained_int(0, 503)
                q_off = rr.read_enum(31)
                neigh = Sib5Neighbor(pci=pci, earfcn=earfcn, q_offset=q_off)
                result.neighbors.append(neigh)
                carrier.neighbors.append(neigh)

        if (opt >> 6) & 1:  # interFreqExcludedCellList-r12
            num_excl = rr.read_constrained_int(1, 16)
            for _ in range(num_excl):
                carrier.excluded.append(_read_phys_cell_id_range(rr))

        if (opt >> 5) & 1:
            rr.read_constrained_int(-34, -3)   # q-QualMin-r12
        if (opt >> 4) & 1:                      # threshX-Q-r12
            rr.read_constrained_int(0, 31)
            rr.read_constrained_int(0, 31)
        if (opt >> 3) & 1:
            rr.read_constrained_int(-34, -3)   # q-QualMinWB-r12
        if (opt >> 2) & 1:                      # multiBandInfoList-r12
            nbands = rr.read_constrained_int(1, 8)
            for _ in range(nbands):
                carrier.bands.append(rr.read_constrained_int(1, 256))
        # (opt >> 1) reducedMeasPerformance-r12: 0-bit ENUMERATED {true}
        if opt & 1:
            rr.read_constrained_int(-34, -3)   # q-QualMinRSRQ-OnAllSymbols-r12

        if entry_ext:
            skip_extension_additions(rr)


# -----------------------------------------------------------------------
# SIB6 skip + neighbor extraction (#N)
# -----------------------------------------------------------------------

@dataclass
class Sib6Neighbors:
    """UTRAN (3G) neighbor frequencies from SIB6."""
    uarfcns_fdd: list[int] = field(default_factory=list)
    uarfcns_tdd: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Sib6Neighbors',
            'uarfcns_fdd': self.uarfcns_fdd,
            'uarfcns_tdd': self.uarfcns_tdd,
        }


def decode_sib6_body(r: UperReader) -> Sib6Neighbors:
    """Decode SIB6 body: UTRAN neighbor UARFCNs (cursor advances past it).

    ``_body`` suffix: this is the reader-positioned container walker; the
    top-level 0xB0C6-record decoder is ``lte_rrc_sib6.decode_sib6``.

    SystemInformationBlockType6 ::= SEQUENCE {
        carrierFreqListUTRA-FDD  CarrierFreqListUTRA-FDD OPTIONAL, -- SIZE (1..16)
        carrierFreqListUTRA-TDD  CarrierFreqListUTRA-TDD OPTIONAL, -- SIZE (1..16)
        t-ReselectionUTRA        T-Reselection,
        t-ReselectionUTRA-SF     SpeedStateScaleFactors OPTIONAL,
        ...
    }
    """
    result = Sib6Neighbors()
    has_ext = r.read_bool()
    opt = r.read_bits(3)  # FDD, TDD, t-Resel-SF

    if (opt >> 2) & 1:  # carrierFreqListUTRA-FDD
        num = r.read_constrained_int(1, 16)
        for _ in range(num):
            # CarrierFreqUTRA-FDD (extensible SEQUENCE)
            # Root: carrierFreq, cellReselectionPriority(OPT),
            #       threshX-High, threshX-Low, q-RxLevMin, p-MaxUTRA, q-QualMin
            fdd_ext = r.read_bool()
            fdd_opt = r.read_bits(1)  # 1 optional: cellReselectionPriority
            uarfcn = r.read_constrained_int(0, 16383)  # carrierFreq
            result.uarfcns_fdd.append(uarfcn)
            if fdd_opt & 1:
                r.read_constrained_int(0, 7)  # cellReselectionPriority
            r.read_constrained_int(0, 31)  # threshX-High
            r.read_constrained_int(0, 31)  # threshX-Low
            r.read_constrained_int(-60, -13)  # q-RxLevMin
            r.read_constrained_int(-50, 33)   # p-MaxUTRA
            r.read_constrained_int(-24, 0)    # q-QualMin
            if fdd_ext:
                skip_extension_additions(r)

    if (opt >> 1) & 1:  # carrierFreqListUTRA-TDD
        num = r.read_constrained_int(1, 16)
        for _ in range(num):
            # CarrierFreqUTRA-TDD (extensible SEQUENCE)
            # Root: carrierFreq, cellReselectionPriority(OPT),
            #       threshX-High, threshX-Low, q-RxLevMin, p-MaxUTRA
            tdd_ext = r.read_bool()
            tdd_opt = r.read_bits(1)  # 1 optional: cellReselectionPriority
            uarfcn = r.read_constrained_int(0, 16383)  # carrierFreq
            result.uarfcns_tdd.append(uarfcn)
            if tdd_opt & 1:
                r.read_constrained_int(0, 7)  # cellReselectionPriority
            r.read_constrained_int(0, 31)  # threshX-High
            r.read_constrained_int(0, 31)  # threshX-Low
            r.read_constrained_int(-60, -13)  # q-RxLevMin
            r.read_constrained_int(-50, 33)   # p-MaxUTRA
            if tdd_ext:
                skip_extension_additions(r)

    r.read_constrained_int(0, 7)  # t-ReselectionUTRA
    if opt & 1:
        _skip_speed_state_scale_factors(r)

    if has_ext:
        skip_extension_additions(r)

    return result


# -----------------------------------------------------------------------
# SIB7 skip + neighbor extraction (#N)
# -----------------------------------------------------------------------

@dataclass
class Sib7Neighbors:
    """GERAN (2G) neighbor frequencies from SIB7."""
    arfcns: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {'type': 'Sib7Neighbors', 'arfcns': self.arfcns}


def decode_sib7_body(r: UperReader) -> Sib7Neighbors:
    """Decode SIB7 body: GERAN ARFCNs (cursor advances past it).

    ``_body`` suffix: this is the reader-positioned container walker; the
    top-level record decoder is ``lte_rrc_sib7.decode_sib7``.

    SystemInformationBlockType7 ::= SEQUENCE {
        t-ReselectionGERAN       T-Reselection,
        t-ReselectionGERAN-SF    SpeedStateScaleFactors OPTIONAL,
        carrierFreqsInfoListGERAN CarrierFreqsInfoListGERAN OPTIONAL, -- SIZE (1..16)
        ...
    }
    """
    result = Sib7Neighbors()
    has_ext = r.read_bool()
    opt = r.read_bits(2)  # t-Resel-SF, carrierFreqsInfoList

    r.read_constrained_int(0, 7)  # t-ReselectionGERAN

    if (opt >> 1) & 1:
        _skip_speed_state_scale_factors(r)

    if opt & 1:  # carrierFreqsInfoListGERAN
        num = r.read_constrained_int(1, 16)
        for _ in range(num):
            # CarrierFreqsInfoGERAN (extensible SEQUENCE, empty ext)
            geran_ext = r.read_bool()
            # No root optionals — carrierFreqs and commonInfo are both mandatory

            # carrierFreqs: CarrierFreqsGERAN (not extensible)
            starting_arfcn = r.read_constrained_int(0, 1023)
            result.arfcns.append(starting_arfcn)
            # bandIndicator: ENUMERATED {arfcn-ValueGERAN-lsb, arfcn-ValueGERAN-rsb}
            r.read_enum(2)
            # followingARFCNs: CHOICE (3 alternatives)
            following_choice = r.read_choice(3)
            if following_choice == 0:
                # explicitListOfARFCNs: SEQUENCE (SIZE (0..31)) OF ARFCN-ValueGERAN
                num_arfcns = r.read_constrained_int(0, 31)
                for _ in range(num_arfcns):
                    arfcn = r.read_constrained_int(0, 1023)
                    result.arfcns.append(arfcn)
            elif following_choice == 1:
                # equallySpacedARFCNs
                r.read_constrained_int(1, 8)  # arfcn-Spacing
                r.read_constrained_int(0, 31)  # numberOfFollowingARFCNs
            elif following_choice == 2:
                # variableBitMapOfARFCNs: OCTET STRING (SIZE (1..16))
                vbm_len = r.read_constrained_int(1, 16)
                r.skip_bits(vbm_len * 8)

            # commonInfo SEQUENCE (not extensible)
            # 2 optionals: cellReselectionPriority, p-MaxGERAN
            ci_opt = r.read_bits(2)
            if (ci_opt >> 1) & 1:
                r.read_constrained_int(0, 7)  # cellReselectionPriority
            r.read_bits(8)  # ncc-Permitted: BIT STRING (SIZE (8))
            r.read_constrained_int(0, 45)  # q-RxLevMin (0..45)
            if ci_opt & 1:
                r.read_constrained_int(0, 39)  # p-MaxGERAN
            r.read_constrained_int(0, 31)  # threshX-High
            r.read_constrained_int(0, 31)  # threshX-Low

            if geran_ext:
                skip_extension_additions(r)

    if has_ext:
        skip_extension_additions(r)

    return result


# -----------------------------------------------------------------------
# Dispatch
# -----------------------------------------------------------------------

class DecodeFailed(Exception):
    """Raised when a SIB body cannot be decoded (cursor cannot be advanced)."""
    pass


# Map CHOICE index → decode function
# Index 0=sib2, 1=sib3, ..., 6=sib8, etc.
SIB_DECODERS = {
    0: decode_sib2,        # sib2
    1: decode_sib3,        # sib3
    2: decode_sib4,        # sib4
    3: decode_sib5,        # sib5
    4: decode_sib6_body,   # sib6
    5: decode_sib7_body,   # sib7
    # sib8 (index 6) — handled by the dedicated time decoder, not dispatched here
}
