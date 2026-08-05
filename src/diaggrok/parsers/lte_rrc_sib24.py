# diaggrok-provenance: re
"""UPER decoder for LTE SIB24 (NR cell reselection) body (#N).

SystemInformationBlockType24-r15 (``SIB24``, TS 36.331 Rel-15) carries the
5G-NR inter-RAT cell-reselection info an LTE cell broadcasts: a list of NR
carriers (``carrierFreqListNR-r15``), each with its ARFCN, band list,
reselection priority / sub-priority, threshX-High/Low, q-RxLevMin, p-MaxNR,
q-QualMin, SSB subcarrier spacing and SSB measurement-timing config.

SIB24 is an EXTENSION-series SIB: in the ``sib-TypeAndInfo`` CHOICE it lives in
the extension additions at ``ext_idx == 10`` (base alternatives sib1..sib11 are
the 0..? CHOICE roots; the extension numbering runs sib12=0, sib13=1, ...,
sib24=10). :func:`decode_si_sibs` reads its open-type length determinant and
hands the isolated body bytes here, exactly as it does for SIB16 (ext_idx 4).
Because the body is an isolated open type, a decode miss here can only affect
SIB24's own fields, never the surrounding SIB walk.

Field structure and every integer/enum width were taken from the authoritative
TS 36.331 v15 ASN.1 shipped in pycrate (``pycrate_asn1dir.RRCLTE``) and the
decoder is validated bit-for-bit against pycrate's own UPER decode of real and
synthetic PDUs (see ``test_lte_rrc_sib24.py``). diaggrok rolls its own UPER
reader (no pycrate runtime dependency); pycrate is used only as the offline
ground-truth oracle, the same role tshark plays for SIB5/SIB6/SIB7.

Scaling (matches the stock tshark ``lte-rrc`` rendering):
  * q-RxLevMin / threshX-High / threshX-Low are signalled in 2 dB steps, so the
    ``*_dbm`` / ``*_db`` fields hold 2x the raw IE value.
  * p-MaxNR and q-QualMin are signalled directly in dBm / dB.

Reference: 3GPP TS 36.331 Rel-15 (SystemInformationBlockType24-r15,
CarrierFreqNR-r15, MTC-SSB-NR-r15), ITU-T X.691 (UPER).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from diaggrok.parsers.uper import UperReader
from diaggrok.parsers.asn1_helpers import (
    read_open_type_length,
    skip_extension_additions,
)

# ENUMERATED value tables (TS 36.331 Rel-15), indexed by the UPER-decoded index.
_SUBCARRIER_SPACING_SSB_KHZ = [15, 30, 120, 240]        # kHz15, kHz30, kHz120, kHz240
_CELL_RESEL_SUB_PRIORITY = ["oDot2", "oDot4", "oDot6", "oDot8"]
_SSB_DURATION = ["sf1", "sf2", "sf3", "sf4", "sf5"]

# SEQUENCE OF size upper bounds (value assignments in TS 36.331 v15).
_MAX_FREQ_NR = 5           # maxFreqNR-r15  -> carrierFreqListNR SIZE (1..5)
_MAX_MULTI_BANDS_NR = 32   # maxMultiBandsNR-r15 -> MultiFrequencyBandListNR SIZE (1..32)
_MAX_NS_PMAX = 8           # maxNS-Pmax-r10 -> NS-PmaxListNR SIZE (1..8)


@dataclass
class Sib24NrCarrier:
    """One CarrierFreqNR-r15 entry from SIB24 (an NR reselection carrier)."""
    carrier_freq: int                       # ARFCN-ValueNR (0..3279165), raw
    bands: list[int] = field(default_factory=list)  # FreqBandIndicatorNR (1..1024)
    subcarrier_spacing_khz: int | None = None       # 15 / 30 / 120 / 240
    ssb_duration: str = ""                  # sf1..sf5 (from measTimingConfig)
    cell_resel_priority: int | None = None  # CellReselectionPriority (0..7)
    cell_resel_sub_priority: str | None = None      # oDot2..oDot8
    thresh_x_high_db: int = 0               # 2x raw ReselectionThreshold
    thresh_x_low_db: int = 0                # 2x raw ReselectionThreshold
    q_rx_lev_min_dbm: int = 0               # 2x raw Q-RxLevMin
    p_max_nr_dbm: int = 0                    # raw P-MaxNR (-30..33)
    q_qual_min_db: int | None = None        # raw Q-QualMin (-43..-12)
    derive_ssb_index_from_cell: bool = False

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'carrier_freq': self.carrier_freq,
            'thresh_x_high_db': self.thresh_x_high_db,
            'thresh_x_low_db': self.thresh_x_low_db,
            'q_rx_lev_min_dbm': self.q_rx_lev_min_dbm,
            'p_max_nr_dbm': self.p_max_nr_dbm,
            'derive_ssb_index_from_cell': self.derive_ssb_index_from_cell,
        }
        if self.bands:
            d['bands'] = self.bands
        if self.subcarrier_spacing_khz is not None:
            d['subcarrier_spacing_khz'] = self.subcarrier_spacing_khz
        if self.ssb_duration:
            d['ssb_duration'] = self.ssb_duration
        if self.cell_resel_priority is not None:
            d['cell_resel_priority'] = self.cell_resel_priority
        if self.cell_resel_sub_priority is not None:
            d['cell_resel_sub_priority'] = self.cell_resel_sub_priority
        if self.q_qual_min_db is not None:
            d['q_qual_min_db'] = self.q_qual_min_db
        return d


@dataclass
class Sib24NrReselection:
    """SIB24 body: NR inter-RAT cell-reselection carriers + t-ReselectionNR."""
    carriers: list[Sib24NrCarrier] = field(default_factory=list)
    t_resel_nr_s: int = 0                    # T-Reselection (0..7) in seconds

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Sib24NrReselection',
            't_resel_nr_s': self.t_resel_nr_s,
            'carriers': [c.to_dict() for c in self.carriers],
        }


def _skip_multi_freq_band_list_nr(r: UperReader) -> list[int]:
    """MultiFrequencyBandListNR-r15 ::= SEQUENCE (SIZE (1..32)) OF
    FreqBandIndicatorNR-r15 (INTEGER (1..1024)). Returns the band list."""
    num = r.read_constrained_int(1, _MAX_MULTI_BANDS_NR)
    return [r.read_constrained_int(1, 1024) for _ in range(num)]


def _decode_mtc_ssb_nr(r: UperReader) -> str:
    """MTC-SSB-NR-r15 ::= SEQUENCE {  -- not extensible
        periodicityAndOffset-r15  CHOICE { sf5(0..4), sf10(0..9), sf20(0..19),
            sf40(0..39), sf80(0..79), sf160(0..159) },
        ssb-Duration-r15  ENUMERATED { sf1, sf2, sf3, sf4, sf5 }
    }. Returns the ssb-Duration label (the reselection-relevant field)."""
    choice = r.read_choice(6)  # periodicityAndOffset-r15
    _po_bits = (4, 9, 19, 39, 79, 159)
    hi = _po_bits[choice] if 0 <= choice < len(_po_bits) else 4
    r.read_constrained_int(0, hi)              # periodicity/offset value
    dur_idx = r.read_enum(len(_SSB_DURATION))  # ssb-Duration-r15
    return _SSB_DURATION[dur_idx] if 0 <= dur_idx < len(_SSB_DURATION) else ""


def _skip_ss_rssi_measurement(r: UperReader) -> None:
    """SS-RSSI-Measurement-r15 ::= SEQUENCE {  -- not extensible
        measurementSlots-r15  BIT STRING (SIZE (1..80)),
        endSymbol-r15         INTEGER (0..3)
    }."""
    nbits = r.read_constrained_int(1, 80)  # constrained BIT STRING length
    r.skip_bits(nbits)
    r.read_constrained_int(0, 3)           # endSymbol-r15


def _skip_ns_pmax_list_nr(r: UperReader) -> None:
    """NS-PmaxListNR-r15 ::= SEQUENCE (SIZE (1..8)) OF NS-PmaxValueNR-r15.
    NS-PmaxValueNR-r15 ::= SEQUENCE {  -- not extensible
        additionalPmaxNR-r15  INTEGER (-30..33) OPTIONAL,
        additionalSpectrumEmissionNR-r15  INTEGER (0..7)
    }."""
    num = r.read_constrained_int(1, _MAX_NS_PMAX)
    for _ in range(num):
        opt = r.read_bits(1)               # additionalPmaxNR-r15 present?
        if opt & 1:
            r.read_constrained_int(-30, 33)
        r.read_constrained_int(0, 7)       # additionalSpectrumEmissionNR-r15


def _skip_threshold_list_nr(r: UperReader) -> None:
    """ThresholdListNR-r15 ::= SEQUENCE {  -- not extensible
        nr-RSRP-r15  INTEGER (0..127) OPTIONAL,
        nr-RSRQ-r15  INTEGER (0..127) OPTIONAL,
        nr-SINR-r15  INTEGER (0..127) OPTIONAL
    }."""
    opt = r.read_bits(3)
    if (opt >> 2) & 1:
        r.read_constrained_int(0, 127)
    if (opt >> 1) & 1:
        r.read_constrained_int(0, 127)
    if opt & 1:
        r.read_constrained_int(0, 127)


def _decode_carrier_freq_nr(r: UperReader) -> Sib24NrCarrier:
    """Decode one CarrierFreqNR-r15 (extensible SEQUENCE), advancing past it.

    Root component order and the 12 root optionals are taken verbatim from the
    TS 36.331 v15 ASN.1 (pycrate). The optional-presence bitmap precedes the
    components (X.691 §18), MSB = the first optional in declaration order.
    """
    ext = r.read_bool()          # extension marker
    opt = r.read_bits(12)        # 12 root optionals (see table below)
    # bit 11 multiBandInfoList        bit 5 threshX-Q
    # bit 10 multiBandInfoListSUL     bit 4 q-RxLevMinSUL
    # bit  9 measTimingConfig         bit 3 ns-PmaxListNR
    # bit  8 ss-RSSI-Measurement      bit 2 q-QualMin
    # bit  7 cellReselectionPriority  bit 1 maxRS-IndexCellQual
    # bit  6 cellReselectionSubPrio   bit 0 threshRS-Index

    carrier_freq = r.read_constrained_int(0, 3279165)   # carrierFreq-r15 (mand)
    out = Sib24NrCarrier(carrier_freq=carrier_freq)

    if (opt >> 11) & 1:          # multiBandInfoList-r15
        out.bands = _skip_multi_freq_band_list_nr(r)
    if (opt >> 10) & 1:          # multiBandInfoListSUL-r15
        _skip_multi_freq_band_list_nr(r)
    if (opt >> 9) & 1:           # measTimingConfig-r15 (MTC-SSB-NR-r15)
        out.ssb_duration = _decode_mtc_ssb_nr(r)

    scs_idx = r.read_enum(len(_SUBCARRIER_SPACING_SSB_KHZ))  # subcarrierSpacingSSB (mand)
    if 0 <= scs_idx < len(_SUBCARRIER_SPACING_SSB_KHZ):
        out.subcarrier_spacing_khz = _SUBCARRIER_SPACING_SSB_KHZ[scs_idx]

    if (opt >> 8) & 1:           # ss-RSSI-Measurement-r15
        _skip_ss_rssi_measurement(r)
    if (opt >> 7) & 1:           # cellReselectionPriority-r15
        out.cell_resel_priority = r.read_constrained_int(0, 7)
    if (opt >> 6) & 1:           # cellReselectionSubPriority-r15
        sp_idx = r.read_enum(len(_CELL_RESEL_SUB_PRIORITY))
        if 0 <= sp_idx < len(_CELL_RESEL_SUB_PRIORITY):
            out.cell_resel_sub_priority = _CELL_RESEL_SUB_PRIORITY[sp_idx]

    out.thresh_x_high_db = r.read_constrained_int(0, 31) * 2  # threshX-High (mand)
    out.thresh_x_low_db = r.read_constrained_int(0, 31) * 2   # threshX-Low (mand)

    if (opt >> 5) & 1:           # threshX-Q-r15 (2x ReselectionThresholdQ)
        r.read_constrained_int(0, 31)
        r.read_constrained_int(0, 31)

    out.q_rx_lev_min_dbm = r.read_constrained_int(-70, -22) * 2  # q-RxLevMin (mand)

    if (opt >> 4) & 1:           # q-RxLevMinSUL-r15
        r.read_constrained_int(-70, -22)

    out.p_max_nr_dbm = r.read_constrained_int(-30, 33)          # p-MaxNR (mand)

    if (opt >> 3) & 1:           # ns-PmaxListNR-r15
        _skip_ns_pmax_list_nr(r)
    if (opt >> 2) & 1:           # q-QualMin-r15
        out.q_qual_min_db = r.read_constrained_int(-43, -12)

    out.derive_ssb_index_from_cell = r.read_bool()             # deriveSSB (mand)

    if (opt >> 1) & 1:           # maxRS-IndexCellQual-r15
        r.read_constrained_int(1, 16)
    if opt & 1:                  # threshRS-Index-r15 (ThresholdListNR-r15)
        _skip_threshold_list_nr(r)

    if ext:
        skip_extension_additions(r)

    return out


def decode_sib24(payload: bytes, log_time: int = 0) -> Sib24NrReselection | None:
    """Decode a SIB24 body (isolated open-type bytes) into NR reselection info.

    SystemInformationBlockType24-r15 ::= SEQUENCE {  -- extensible
        carrierFreqListNR-r15    CarrierFreqListNR-r15  OPTIONAL,  -- SIZE (1..5)
        t-ReselectionNR-r15      T-Reselection,                    -- (0..7)
        t-ReselectionNR-SF-r15   SpeedStateScaleFactors OPTIONAL,
        lateNonCriticalExtension OCTET STRING OPTIONAL,
        ...
    }

    Returns ``None`` for an empty payload or a structurally impossible decode.
    ``log_time`` is accepted for signature parity with the other SIB decoders;
    SIB24 carries no time field.
    """
    if not payload:
        return None
    try:
        r = UperReader(payload)
        out = Sib24NrReselection()

        r.read_bool()                # extension marker
        opt = r.read_bits(3)         # carrierFreqListNR, t-ReselectionNR-SF, lateNCE
        if (opt >> 2) & 1:           # carrierFreqListNR-r15
            num = r.read_constrained_int(1, _MAX_FREQ_NR)
            for _ in range(num):
                out.carriers.append(_decode_carrier_freq_nr(r))
        out.t_resel_nr_s = r.read_constrained_int(0, 7)  # t-ReselectionNR (mand)
        if (opt >> 1) & 1:           # t-ReselectionNR-SF (SpeedStateScaleFactors)
            r.read_enum(4)           # sf-Medium
            r.read_enum(4)           # sf-High
        if opt & 1:                  # lateNonCriticalExtension (OCTET STRING)
            ln = read_open_type_length(r)
            r.skip_bits(ln * 8)
        return out
    except (IndexError, ValueError):
        return None
