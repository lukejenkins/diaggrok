# diaggrok-provenance: re
"""UPER decoders for NR SIBs (#N) — decode each SIB body (advancing the
reader past it) and capture its fields.

NR analog of ``lte_rrc_sib_decode.py``: these functions read through the
UPER-encoded ASN.1 structure of each NR SIB type. Two jobs at once (the
LTE module's dual-purpose pattern): (a) advance the ``UperReader`` bit
position exactly past the SIB body so the SI-container walker
(``nr5g_rrc_si``) can reach SIBs later in the ``sib-TypeAndInfo`` list —
in the observed corpus, SIB9 (network time, #N) always rides LAST
behind sib2 + sib4 + sib5 — and (b) return the decoded fields:

  * ``decode_sib2`` → ``NrSib2``: serving-cell reselection parameters.
  * ``decode_sib4`` → ``NrSib4``: inter-frequency neighbour carriers
    (dl_carrier_freq NR ARFCN + band list + reselection thresholds +
    any interFreqNeighCellList PCIs). #N "NR SIB4" row.
  * ``decode_sib5`` → ``NrSib5``: inter-RAT EUTRA neighbour carriers
    (carrier_freq EUTRA EARFCN + thresholds + any eutra-FreqNeighCellList
    PCIs) + t-ReselectionEUTRA. #N "NR SIB5" row.

Bit-exactness validation: the walker's SIB9 ``timeInfoUTC`` output matches
the stock tshark ``nr-rrc`` dissector on every distinct corpus SI message —
a single mis-skipped bit anywhere in sib2/sib4/sib5 would corrupt the
39-bit time value, so field-for-field equality pins every read below. The
sib4/sib5 field VALUES are additionally A/B'd against the tshark dissector
on all distinct corpus SI messages (v16, #N).

Reference: 3GPP TS 38.331 §6.2.2/§6.3.2, ITU-T X.691 (UPER)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from diaggrok.parsers.uper import UperReader
from diaggrok.parsers.asn1_helpers import skip_extension_additions


# -----------------------------------------------------------------------
# Shared ASN.1 leaf types (TS 38.331 §6.3.2)
# -----------------------------------------------------------------------

# q-Hyst ENUMERATED value → dB (16 values: dB0..dB6 by 1, then by 2)
Q_HYST_DB = [0, 1, 2, 3, 4, 5, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24]

# CellReselectionSubPriority ENUMERATED { oDot2, oDot4, oDot6, oDot8 }
SUB_PRIORITY_NAMES = ["oDot2", "oDot4", "oDot6", "oDot8"]


def _skip_threshold_nr(r: UperReader) -> None:
    """ThresholdNR: 3 optional INTEGER (0..127) fields, not extensible."""
    opt = r.read_bits(3)
    for i in range(3):
        if (opt >> (2 - i)) & 1:
            r.read_constrained_int(0, 127)


def _skip_speed_state_scale_factors(r: UperReader) -> None:
    """SpeedStateScaleFactors: sf-Medium ENUM(4) + sf-High ENUM(4)."""
    r.read_enum(4)
    r.read_enum(4)


def _skip_ssb_mtc(r: UperReader) -> None:
    """SSB-MTC: periodicityAndOffset CHOICE(6) + duration ENUM(5)."""
    choice = r.read_choice(6)  # sf5/sf10/sf20/sf40/sf80/sf160
    hi = (5, 10, 20, 40, 80, 160)[choice] - 1
    r.read_constrained_int(0, hi)
    r.read_enum(5)             # duration: sf1..sf5


def _skip_ssb_to_measure(r: UperReader) -> None:
    """SSB-ToMeasure CHOICE { short(4b), medium(8b), long(64b) bitmaps }."""
    choice = r.read_choice(3)
    r.skip_bits((4, 8, 64)[choice])


def _skip_ss_rssi_measurement(r: UperReader) -> None:
    """SS-RSSI-Measurement: measurementSlots BIT STRING (1..80) + endSymbol."""
    nbits = r.read_constrained_int(1, 80)
    r.skip_bits(nbits)
    r.read_constrained_int(0, 3)


def _skip_multi_freq_band_list_nr(r: UperReader) -> list[int]:
    """MultiFrequencyBandListNR-SIB: SIZE (1..8) OF NR-MultiBandInfo.

    Returns the list of ``freqBandIndicatorNR`` values present (bands whose
    OPTIONAL indicator was signalled); dual-purpose skip+extract, same pattern
    as ``decode_sib2``.
    """
    bands: list[int] = []
    n = r.read_constrained_int(1, 8)
    for _ in range(n):
        # NR-MultiBandInfo: freqBandIndicatorNR OPTIONAL, nr-NS-PmaxList OPTIONAL
        opt = r.read_bits(2)
        if (opt >> 1) & 1:
            bands.append(r.read_constrained_int(1, 1024))  # FreqBandIndicatorNR
        if opt & 1:
            n_pmax = r.read_constrained_int(1, 8)
            for _ in range(n_pmax):
                # NR-NS-PmaxValue: additionalPmax OPTIONAL + additionalSpectrumEmission
                has_pmax = r.read_bool()
                if has_pmax:
                    r.read_constrained_int(-30, 33)
                r.read_constrained_int(0, 7)  # AdditionalSpectrumEmission
    return bands


def _skip_mobility_state_parameters(r: UperReader) -> None:
    """MobilityStateParameters: t-Evaluation/t-HystNormal ENUM(8) + 2× INT (1..16)."""
    r.read_enum(8)
    r.read_enum(8)
    r.read_constrained_int(1, 16)
    r.read_constrained_int(1, 16)


# -----------------------------------------------------------------------
# SIB2 — skip + extract (serving-cell reselection parameters, #N row)
# -----------------------------------------------------------------------

@dataclass
class NrSib2:
    """Serving-cell reselection parameters extracted from NR SIB2."""
    q_hyst_db: Optional[int] = None            # cellReselectionInfoCommon
    cell_reselection_priority: Optional[int] = None   # serving freq (0..7)
    cell_reselection_sub_priority: str = ""    # oDot2..oDot8
    s_non_intra_search_p: Optional[int] = None # raw (0..31), dB = 2×raw
    thresh_serving_low_p: Optional[int] = None # raw (0..31), dB = 2×raw
    q_rxlevmin: Optional[int] = None           # raw (-70..-22), dBm = 2×raw
    s_intra_search_p: Optional[int] = None     # raw (0..31), dB = 2×raw
    t_reselection_nr: Optional[int] = None     # seconds (0..7)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {'type': 'NrSib2'}
        for k in ('q_hyst_db', 'cell_reselection_priority',
                  's_non_intra_search_p', 'thresh_serving_low_p',
                  'q_rxlevmin', 's_intra_search_p', 't_reselection_nr'):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        if self.cell_reselection_sub_priority:
            d['cell_reselection_sub_priority'] = (
                self.cell_reselection_sub_priority)
        return d


def decode_sib2(r: UperReader) -> NrSib2:
    """Decode SIB2 body (advancing the reader past it), extracting serving-cell reselection parameters.

    SIB2 ::= SEQUENCE {                      -- extensible, no root optionals
        cellReselectionInfoCommon SEQUENCE {     -- extensible
            nrofSS-BlocksToAverage           INTEGER (2..16)  OPTIONAL,
            absThreshSS-BlocksConsolidation  ThresholdNR      OPTIONAL,
            rangeToBestCell                  Q-OffsetRange    OPTIONAL,
            q-Hyst                           ENUMERATED (16),
            speedStateReselectionPars        SEQUENCE {...}   OPTIONAL,
            ... },
        cellReselectionServingFreqInfo SEQUENCE {  -- extensible
            s-NonIntraSearchP           INTEGER (0..31)  OPTIONAL,
            s-NonIntraSearchQ           INTEGER (0..31)  OPTIONAL,
            threshServingLowP           INTEGER (0..31),
            threshServingLowQ           INTEGER (0..31)  OPTIONAL,
            cellReselectionPriority     INTEGER (0..7),
            cellReselectionSubPriority  ENUMERATED (4)   OPTIONAL,
            ... },
        intraFreqCellReselectionInfo SEQUENCE {    -- extensible
            q-RxLevMin              INTEGER (-70..-22),
            q-RxLevMinSUL           INTEGER (-70..-22)  OPTIONAL,
            q-QualMin               INTEGER (-43..-12)  OPTIONAL,
            s-IntraSearchP          INTEGER (0..31),
            s-IntraSearchQ          INTEGER (0..31)     OPTIONAL,
            t-ReselectionNR         INTEGER (0..7),
            frequencyBandList       MultiFrequencyBandListNR-SIB OPTIONAL,
            frequencyBandListSUL    MultiFrequencyBandListNR-SIB OPTIONAL,
            p-Max                   INTEGER (-30..33)   OPTIONAL,
            smtc                    SSB-MTC             OPTIONAL,
            ss-RSSI-Measurement     SS-RSSI-Measurement OPTIONAL,
            ssb-ToMeasure           SSB-ToMeasure       OPTIONAL,
            deriveSSB-IndexFromCell BOOLEAN,
            ...,
            [[ t-ReselectionNR-SF SpeedStateScaleFactors OPTIONAL ]] },
        ... }
    """
    out = NrSib2()

    sib2_has_ext = r.read_bool()

    # -- cellReselectionInfoCommon ------------------------------------
    cric_has_ext = r.read_bool()
    cric_opt = r.read_bits(4)
    if (cric_opt >> 3) & 1:
        r.read_constrained_int(2, 16)     # nrofSS-BlocksToAverage
    if (cric_opt >> 2) & 1:
        _skip_threshold_nr(r)             # absThreshSS-BlocksConsolidation
    if (cric_opt >> 1) & 1:
        r.read_enum(31)                   # rangeToBestCell: Q-OffsetRange
    out.q_hyst_db = Q_HYST_DB[r.read_enum(16)]
    if cric_opt & 1:
        # speedStateReselectionPars: MobilityStateParameters + q-HystSF
        _skip_mobility_state_parameters(r)
        r.read_enum(4)                    # q-HystSF.sf-Medium
        r.read_enum(4)                    # q-HystSF.sf-High
    if cric_has_ext:
        skip_extension_additions(r)

    # -- cellReselectionServingFreqInfo --------------------------------
    csfi_has_ext = r.read_bool()
    csfi_opt = r.read_bits(4)
    if (csfi_opt >> 3) & 1:
        out.s_non_intra_search_p = r.read_constrained_int(0, 31)
    if (csfi_opt >> 2) & 1:
        r.read_constrained_int(0, 31)     # s-NonIntraSearchQ
    out.thresh_serving_low_p = r.read_constrained_int(0, 31)
    if (csfi_opt >> 1) & 1:
        r.read_constrained_int(0, 31)     # threshServingLowQ
    out.cell_reselection_priority = r.read_constrained_int(0, 7)
    if csfi_opt & 1:
        out.cell_reselection_sub_priority = (
            SUB_PRIORITY_NAMES[r.read_enum(4)])
    if csfi_has_ext:
        skip_extension_additions(r)

    # -- intraFreqCellReselectionInfo -----------------------------------
    ifcri_has_ext = r.read_bool()
    ifcri_opt = r.read_bits(9)
    out.q_rxlevmin = r.read_constrained_int(-70, -22)
    if (ifcri_opt >> 8) & 1:
        r.read_constrained_int(-70, -22)  # q-RxLevMinSUL
    if (ifcri_opt >> 7) & 1:
        r.read_constrained_int(-43, -12)  # q-QualMin
    out.s_intra_search_p = r.read_constrained_int(0, 31)
    if (ifcri_opt >> 6) & 1:
        r.read_constrained_int(0, 31)     # s-IntraSearchQ
    out.t_reselection_nr = r.read_constrained_int(0, 7)
    if (ifcri_opt >> 5) & 1:
        _skip_multi_freq_band_list_nr(r)  # frequencyBandList
    if (ifcri_opt >> 4) & 1:
        _skip_multi_freq_band_list_nr(r)  # frequencyBandListSUL
    if (ifcri_opt >> 3) & 1:
        r.read_constrained_int(-30, 33)   # p-Max
    if (ifcri_opt >> 2) & 1:
        _skip_ssb_mtc(r)                  # smtc
    if (ifcri_opt >> 1) & 1:
        _skip_ss_rssi_measurement(r)      # ss-RSSI-Measurement
    if ifcri_opt & 1:
        _skip_ssb_to_measure(r)           # ssb-ToMeasure
    r.read_bool()                         # deriveSSB-IndexFromCell
    if ifcri_has_ext:
        skip_extension_additions(r)

    if sib2_has_ext:
        skip_extension_additions(r)

    return out


# -----------------------------------------------------------------------
# SIB4 — skip + extract (inter-freq neighbour carriers, #N row)
# -----------------------------------------------------------------------

@dataclass
class NrSib4Carrier:
    """One inter-frequency neighbour carrier (InterFreqCarrierFreqInfo)."""
    dl_carrier_freq: int                       # NR ARFCN of the neighbour
    freq_band_list: list[int] = field(default_factory=list)  # band indicators
    q_rxlevmin: Optional[int] = None           # raw (-70..-22); dBm = 2×raw
    t_reselection_nr: Optional[int] = None     # seconds (0..7)
    thresh_x_high_p: Optional[int] = None       # raw (0..31); dB = 2×raw
    thresh_x_low_p: Optional[int] = None        # raw (0..31); dB = 2×raw
    p_max: Optional[int] = None                # dBm (-30..33), OPTIONAL
    cell_reselection_priority: Optional[int] = None  # (0..7), OPTIONAL
    cell_reselection_sub_priority: str = ""    # oDot2..oDot8, OPTIONAL
    neighbor_pcis: list[int] = field(default_factory=list)  # interFreqNeighCellList

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {'dl_carrier_freq': self.dl_carrier_freq}
        if self.freq_band_list:
            d['freq_band_list'] = self.freq_band_list
        for k in ('q_rxlevmin', 't_reselection_nr', 'thresh_x_high_p',
                  'thresh_x_low_p', 'p_max', 'cell_reselection_priority'):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        if self.cell_reselection_sub_priority:
            d['cell_reselection_sub_priority'] = (
                self.cell_reselection_sub_priority)
        if self.neighbor_pcis:
            d['neighbor_pcis'] = self.neighbor_pcis
        return d


@dataclass
class NrSib4:
    """SIB4 inter-frequency neighbour carrier list."""
    carriers: list[NrSib4Carrier] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'NrSib4',
            'carriers': [c.to_dict() for c in self.carriers],
        }


def _extract_inter_freq_carrier_freq_info(r: UperReader) -> NrSib4Carrier:
    """InterFreqCarrierFreqInfo (TS 38.331) — extensible, 17 opt/default bits.

    Dual-purpose skip+extract: walks the whole IE (bit-exact, as the SIB9-time
    pin proves) while capturing the neighbour-carrier fields for the #N
    SIB4 coverage row.
    """
    has_ext = r.read_bool()
    opt = r.read_bits(17)
    b = [(opt >> (16 - i)) & 1 for i in range(17)]
    #  0 frequencyBandList          1 frequencyBandListSUL
    #  2 nrofSS-BlocksToAverage     3 absThreshSS-BlocksConsolidation
    #  4 smtc                       5 ssb-ToMeasure
    #  6 ss-RSSI-Measurement        7 q-RxLevMinSUL
    #  8 q-QualMin                  9 p-Max
    # 10 t-ReselectionNR-SF        11 threshX-Q
    # 12 cellReselectionPriority   13 cellReselectionSubPriority
    # 14 q-OffsetFreq (DEFAULT)    15 interFreqNeighCellList
    # 16 interFreqBlackCellList
    out = NrSib4Carrier(
        dl_carrier_freq=r.read_constrained_int(0, 3279165))  # dl-CarrierFreq
    if b[0]:
        out.freq_band_list = _skip_multi_freq_band_list_nr(r)
    if b[1]:
        _skip_multi_freq_band_list_nr(r)
    if b[2]:
        r.read_constrained_int(2, 16)
    if b[3]:
        _skip_threshold_nr(r)
    if b[4]:
        _skip_ssb_mtc(r)
    r.read_enum(8)                        # ssbSubcarrierSpacing
    if b[5]:
        _skip_ssb_to_measure(r)
    r.read_bool()                         # deriveSSB-IndexFromCell
    if b[6]:
        _skip_ss_rssi_measurement(r)
    out.q_rxlevmin = r.read_constrained_int(-70, -22)      # q-RxLevMin
    if b[7]:
        r.read_constrained_int(-70, -22)
    if b[8]:
        r.read_constrained_int(-43, -12)
    if b[9]:
        out.p_max = r.read_constrained_int(-30, 33)
    out.t_reselection_nr = r.read_constrained_int(0, 7)    # t-ReselectionNR
    if b[10]:
        _skip_speed_state_scale_factors(r)
    out.thresh_x_high_p = r.read_constrained_int(0, 31)    # threshX-HighP
    out.thresh_x_low_p = r.read_constrained_int(0, 31)     # threshX-LowP
    if b[11]:
        r.read_constrained_int(0, 31)     # threshX-HighQ
        r.read_constrained_int(0, 31)     # threshX-LowQ
    if b[12]:
        out.cell_reselection_priority = r.read_constrained_int(0, 7)
    if b[13]:
        out.cell_reselection_sub_priority = SUB_PRIORITY_NAMES[r.read_enum(4)]
    if b[14]:
        r.read_enum(31)                   # q-OffsetFreq (Q-OffsetRange)
    if b[15]:
        n = r.read_constrained_int(1, 16)  # interFreqNeighCellList
        for _ in range(n):
            nc_ext = r.read_bool()
            nc_opt = r.read_bits(3)
            out.neighbor_pcis.append(r.read_constrained_int(0, 1007))  # physCellId
            r.read_enum(31)                  # q-OffsetCell
            for i in range(3):
                if (nc_opt >> (2 - i)) & 1:
                    r.read_constrained_int(1, 8)
            if nc_ext:
                skip_extension_additions(r)
    if b[16]:
        n = r.read_constrained_int(1, 16)  # interFreqBlackCellList
        for _ in range(n):
            # PCI-Range: start + range ENUM(16) OPTIONAL, not extensible
            has_range = r.read_bool()
            r.read_constrained_int(0, 1007)
            if has_range:
                r.read_enum(16)
    if has_ext:
        skip_extension_additions(r)
    return out


def decode_sib4(r: UperReader) -> NrSib4:
    """Decode SIB4 body (advancing the reader past it), extracting the inter-frequency neighbour carrier list.

    SIB4 ::= SEQUENCE {                       -- extensible
        interFreqCarrierFreqList  SEQUENCE (SIZE (1..maxFreq=8))
                                  OF InterFreqCarrierFreqInfo,
        lateNonCriticalExtension  OCTET STRING OPTIONAL,
        ... }
    """
    out = NrSib4()
    has_ext = r.read_bool()
    has_late_nce = r.read_bool()
    n = r.read_constrained_int(1, 8)
    for _ in range(n):
        out.carriers.append(_extract_inter_freq_carrier_freq_info(r))
    if has_late_nce:
        nbytes = r.read_length()
        r.skip_bits(nbytes * 8)
    if has_ext:
        skip_extension_additions(r)
    return out


# -----------------------------------------------------------------------
# SIB5 — skip + extract (inter-RAT EUTRA neighbour carriers, #N row)
# -----------------------------------------------------------------------

@dataclass
class NrSib5Carrier:
    """One inter-RAT EUTRA neighbour carrier (CarrierFreqEUTRA)."""
    carrier_freq: int                          # EUTRA EARFCN of the neighbour
    eutra_bands: list[int] = field(default_factory=list)  # eutra-multiBandInfo
    q_rxlevmin: Optional[int] = None           # raw (-70..-22); dBm = 2×raw
    q_qualmin: Optional[int] = None            # dB (-34..-3)
    p_max_eutra: Optional[int] = None          # dBm (-30..33)
    thresh_x_high: Optional[int] = None         # raw (0..31); dB = 2×raw
    thresh_x_low: Optional[int] = None          # raw (0..31); dB = 2×raw
    cell_reselection_priority: Optional[int] = None  # (0..7), OPTIONAL
    cell_reselection_sub_priority: str = ""    # oDot2..oDot8, OPTIONAL
    neighbor_pcis: list[int] = field(default_factory=list)  # eutra-FreqNeighCellList

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {'carrier_freq': self.carrier_freq}
        if self.eutra_bands:
            d['eutra_bands'] = self.eutra_bands
        for k in ('q_rxlevmin', 'q_qualmin', 'p_max_eutra', 'thresh_x_high',
                  'thresh_x_low', 'cell_reselection_priority'):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        if self.cell_reselection_sub_priority:
            d['cell_reselection_sub_priority'] = (
                self.cell_reselection_sub_priority)
        if self.neighbor_pcis:
            d['neighbor_pcis'] = self.neighbor_pcis
        return d


@dataclass
class NrSib5:
    """SIB5 inter-RAT EUTRA neighbour carrier list."""
    carriers: list[NrSib5Carrier] = field(default_factory=list)
    t_reselection_eutra: Optional[int] = None  # seconds (0..7)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'type': 'NrSib5',
            'carriers': [c.to_dict() for c in self.carriers],
        }
        if self.t_reselection_eutra is not None:
            d['t_reselection_eutra'] = self.t_reselection_eutra
        return d


def _extract_carrier_freq_eutra(r: UperReader) -> NrSib5Carrier:
    """CarrierFreqEUTRA (TS 38.331) — NOT extensible, 6 optional bits.

    Dual-purpose skip+extract for the #N SIB5 coverage row.
    """
    opt = r.read_bits(6)
    b = [(opt >> (5 - i)) & 1 for i in range(6)]
    # 0 eutra-multiBandInfoList  1 eutra-FreqNeighCellList
    # 2 eutra-BlackCellList      3 cellReselectionPriority
    # 4 cellReselectionSubPriority  5 threshX-Q
    out = NrSib5Carrier(
        carrier_freq=r.read_constrained_int(0, 262143))  # carrierFreq
    if b[0]:
        n = r.read_constrained_int(1, 8)  # EUTRA-MultiBandInfoList
        for _ in range(n):
            has_pmax_list = r.read_bool()
            out.eutra_bands.append(
                r.read_constrained_int(1, 256))  # eutra-FreqBandIndicator
            if has_pmax_list:
                n2 = r.read_constrained_int(1, 8)
                for _ in range(n2):
                    p_opt = r.read_bits(2)
                    if (p_opt >> 1) & 1:
                        r.read_constrained_int(-30, 33)
                    if p_opt & 1:
                        r.read_constrained_int(1, 288)
    if b[1]:
        n = r.read_constrained_int(1, 8)  # EUTRA-FreqNeighCellList
        for _ in range(n):
            nc_opt = r.read_bits(2)
            out.neighbor_pcis.append(
                r.read_constrained_int(0, 503))  # physCellId
            r.read_enum(31)                 # q-OffsetCell (EUTRA range, 31)
            if (nc_opt >> 1) & 1:
                r.read_constrained_int(1, 8)
            if nc_opt & 1:
                r.read_constrained_int(1, 8)
    if b[2]:
        n = r.read_constrained_int(1, 16)  # EUTRA-FreqBlackCellList
        for _ in range(n):
            has_range = r.read_bool()      # EUTRA-PhysCellIdRange
            r.read_constrained_int(0, 503)
            if has_range:
                r.read_enum(16)
    r.read_enum(6)                         # allowedMeasBandwidth
    r.read_bool()                          # presenceAntennaPort1
    if b[3]:
        out.cell_reselection_priority = r.read_constrained_int(0, 7)
    if b[4]:
        out.cell_reselection_sub_priority = SUB_PRIORITY_NAMES[r.read_enum(4)]
    out.thresh_x_high = r.read_constrained_int(0, 31)     # threshX-High
    out.thresh_x_low = r.read_constrained_int(0, 31)      # threshX-Low
    out.q_rxlevmin = r.read_constrained_int(-70, -22)     # q-RxLevMin
    out.q_qualmin = r.read_constrained_int(-34, -3)       # q-QualMin
    out.p_max_eutra = r.read_constrained_int(-30, 33)     # p-MaxEUTRA
    if b[5]:
        r.read_constrained_int(0, 31)      # threshX-HighQ
        r.read_constrained_int(0, 31)      # threshX-LowQ
    return out


def decode_sib5(r: UperReader) -> NrSib5:
    """Decode SIB5 body (advancing the reader past it), extracting the inter-RAT EUTRA neighbour carrier list.

    SIB5 ::= SEQUENCE {                       -- extensible
        carrierFreqListEUTRA      SEQUENCE (SIZE (1..maxEUTRA-Carrier=8))
                                  OF CarrierFreqEUTRA OPTIONAL,
        t-ReselectionEUTRA        INTEGER (0..7),
        t-ReselectionEUTRA-SF     SpeedStateScaleFactors OPTIONAL,
        lateNonCriticalExtension  OCTET STRING OPTIONAL,
        ... }
    """
    out = NrSib5()
    has_ext = r.read_bool()
    opt = r.read_bits(3)
    if (opt >> 2) & 1:
        n = r.read_constrained_int(1, 8)
        for _ in range(n):
            out.carriers.append(_extract_carrier_freq_eutra(r))
    out.t_reselection_eutra = r.read_constrained_int(0, 7)  # t-ReselectionEUTRA
    if (opt >> 1) & 1:
        _skip_speed_state_scale_factors(r)
    if opt & 1:
        nbytes = r.read_length()
        r.skip_bits(nbytes * 8)
    if has_ext:
        skip_extension_additions(r)
    return out
