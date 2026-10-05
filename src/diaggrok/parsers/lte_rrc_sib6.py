# diaggrok-provenance: re
"""LTE RRC SIB6 decoder — UTRAN (3G/WCDMA) neighbor cell list.

Decodes SystemInformationBlockType6 from a raw UPER-encoded payload to
extract UTRAN FDD and TDD neighbor frequency information including
reselection parameters.

From-scratch UPER decoder — no pycrate or other ASN.1 library dependency.

ASN.1 definition (3GPP TS 36.331 §6.3.1):

    SystemInformationBlockType6 ::= SEQUENCE {
        carrierFreqListUTRA-FDD      CarrierFreqListUTRA-FDD     OPTIONAL,
        carrierFreqListUTRA-TDD      CarrierFreqListUTRA-TDD     OPTIONAL,
        t-ReselectionUTRA            T-Reselection,               -- INTEGER (0..7)
        t-ReselectionUTRA-SF         SpeedStateScaleFactors       OPTIONAL,
        ...
    }

    CarrierFreqListUTRA-FDD ::= SEQUENCE (SIZE (1..maxUTRA-FDD-Carrier)) OF CarrierFreqUTRA-FDD
    CarrierFreqListUTRA-TDD ::= SEQUENCE (SIZE (1..maxUTRA-TDD-Carrier)) OF CarrierFreqUTRA-TDD

    maxUTRA-FDD-Carrier = 16
    maxUTRA-TDD-Carrier = 16

    CarrierFreqUTRA-FDD ::= SEQUENCE {
        carrierFreq                  ARFCN-ValueUTRA,             -- INTEGER (0..16383)
        cellReselectionPriority      CellReselectionPriority      OPTIONAL,  -- INTEGER (0..7)
        threshX-High                 ReselectionThreshold,         -- INTEGER (0..31)
        threshX-Low                  ReselectionThreshold,         -- INTEGER (0..31)
        q-RxLevMin                   INTEGER (-60..-13),
        p-MaxUTRA                    INTEGER (-50..33),
        q-QualMin                    INTEGER (-24..0),
        ...
    }

    CarrierFreqUTRA-TDD ::= SEQUENCE {
        carrierFreq                  ARFCN-ValueUTRA,             -- INTEGER (0..16383)
        cellReselectionPriority      CellReselectionPriority      OPTIONAL,  -- INTEGER (0..7)
        threshX-High                 ReselectionThreshold,         -- INTEGER (0..31)
        threshX-Low                  ReselectionThreshold,         -- INTEGER (0..31)
        q-RxLevMin                   INTEGER (-60..-13),
        p-MaxUTRA                    INTEGER (-50..33),
        ...
    }

    SpeedStateScaleFactors ::= SEQUENCE {
        sf-Medium                    ENUMERATED {oDot25, oDot5, oDot75, lDot0},
        sf-High                      ENUMERATED {oDot25, oDot5, oDot75, lDot0}
    }

Reference: 3GPP TS 36.331 v16.x, ITU-T X.691 (UPER)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from diaggrok.parsers.lte_rrc_sib import UperReader
from diaggrok.parsers.asn1_helpers import skip_extension_additions


# -----------------------------------------------------------------------
# Data structures
# -----------------------------------------------------------------------

@dataclass
class UTRANeighborFreq:
    """A single UTRAN FDD neighbor frequency with reselection parameters."""
    uarfcn: int                     # UTRAN ARFCN (0-16383)
    priority: Optional[int]         # Cell reselection priority (0-7), None if absent
    thresh_high: int                # Threshold for high-priority reselection (0-31)
    thresh_low: int                 # Threshold for low-priority reselection (0-31)
    q_rxlev_min: int                # Minimum RX level (-60 to -13 dBm)
    p_max: int                      # Max TX power (-50 to 33 dBm)
    q_qual_min: int                 # Minimum quality (-24 to 0 dB)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'uarfcn': self.uarfcn,
            'thresh_high': self.thresh_high,
            'thresh_low': self.thresh_low,
            'q_rxlev_min': self.q_rxlev_min,
            'p_max': self.p_max,
            'q_qual_min': self.q_qual_min,
        }
        if self.priority is not None:
            d['priority'] = self.priority
        return d


@dataclass
class UTRANeighborFreqTDD:
    """A single UTRAN TDD neighbor frequency with reselection parameters.

    TDD entries lack q-QualMin compared to FDD.
    """
    uarfcn: int                     # UTRAN ARFCN (0-16383)
    priority: Optional[int]         # Cell reselection priority (0-7), None if absent
    thresh_high: int                # Threshold for high-priority reselection (0-31)
    thresh_low: int                 # Threshold for low-priority reselection (0-31)
    q_rxlev_min: int                # Minimum RX level (-60 to -13 dBm)
    p_max: int                      # Max TX power (-50 to 33 dBm)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'uarfcn': self.uarfcn,
            'thresh_high': self.thresh_high,
            'thresh_low': self.thresh_low,
            'q_rxlev_min': self.q_rxlev_min,
            'p_max': self.p_max,
        }
        if self.priority is not None:
            d['priority'] = self.priority
        return d


@dataclass
class LteSIB6:
    """Decoded SIB6 — UTRAN (3G/WCDMA) neighbor frequency information."""
    log_time: int
    fdd_freqs: list[UTRANeighborFreq] = field(default_factory=list)
    tdd_freqs: list[UTRANeighborFreqTDD] = field(default_factory=list)
    t_reselection: int = 0          # Timer for UTRAN reselection (0-7 seconds)
    t_reselection_sf_medium: Optional[int] = None  # SpeedStateScaleFactors index
    t_reselection_sf_high: Optional[int] = None    # SpeedStateScaleFactors index

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'LteSIB6',
            'log_time': self.log_time,
            'fdd_freqs': [f.to_dict() for f in self.fdd_freqs],
            'tdd_freqs': [f.to_dict() for f in self.tdd_freqs],
            't_reselection': self.t_reselection,
        }


# -----------------------------------------------------------------------
# SIB6 UPER decoder
# -----------------------------------------------------------------------

def _decode_carrier_freq_utra_fdd(r: UperReader) -> UTRANeighborFreq:
    """Decode a single CarrierFreqUTRA-FDD from UPER.

    CarrierFreqUTRA-FDD is an extensible SEQUENCE with 1 OPTIONAL field
    (cellReselectionPriority) in the root component.

    Bit layout:
        1 bit   — extension marker
        1 bit   — optional bitmap (cellReselectionPriority present?)
        14 bits — carrierFreq (ARFCN-ValueUTRA: 0..16383)
        [3 bits — cellReselectionPriority (0..7) if present]
        5 bits  — threshX-High (0..31)
        5 bits  — threshX-Low (0..31)
        6 bits  — q-RxLevMin (-60..-13, range=47, 6 bits)
        7 bits  — p-MaxUTRA (-50..33, range=83, 7 bits)
        5 bits  — q-QualMin (-24..0, range=24, 5 bits)
    """
    has_ext = r.read_bool()

    # 1 optional field: cellReselectionPriority
    has_priority = r.read_bool()

    uarfcn = r.read_constrained_int(0, 16383)

    priority: Optional[int] = None
    if has_priority:
        priority = r.read_constrained_int(0, 7)

    thresh_high = r.read_constrained_int(0, 31)
    thresh_low = r.read_constrained_int(0, 31)
    q_rxlev_min = r.read_constrained_int(-60, -13)
    p_max = r.read_constrained_int(-50, 33)
    q_qual_min = r.read_constrained_int(-24, 0)

    if has_ext:
        skip_extension_additions(r)

    return UTRANeighborFreq(
        uarfcn=uarfcn,
        priority=priority,
        thresh_high=thresh_high,
        thresh_low=thresh_low,
        q_rxlev_min=q_rxlev_min,
        p_max=p_max,
        q_qual_min=q_qual_min,
    )


def _decode_carrier_freq_utra_tdd(r: UperReader) -> UTRANeighborFreqTDD:
    """Decode a single CarrierFreqUTRA-TDD from UPER.

    Same structure as FDD but without q-QualMin.
    """
    has_ext = r.read_bool()

    has_priority = r.read_bool()

    uarfcn = r.read_constrained_int(0, 16383)

    priority: Optional[int] = None
    if has_priority:
        priority = r.read_constrained_int(0, 7)

    thresh_high = r.read_constrained_int(0, 31)
    thresh_low = r.read_constrained_int(0, 31)
    q_rxlev_min = r.read_constrained_int(-60, -13)
    p_max = r.read_constrained_int(-50, 33)

    if has_ext:
        skip_extension_additions(r)

    return UTRANeighborFreqTDD(
        uarfcn=uarfcn,
        priority=priority,
        thresh_high=thresh_high,
        thresh_low=thresh_low,
        q_rxlev_min=q_rxlev_min,
        p_max=p_max,
    )


def extract_sib6(r: UperReader, log_time: int = 0) -> LteSIB6:
    """Full-field extraction of a SIB6 body from an EXISTING UperReader.

    The reader must be positioned at the first bit of the
    ``SystemInformationBlockType6`` body. Used both by :func:`decode_sib6`
    (fresh reader over a bare body) and by the SI-container walker
    ``lte_rrc_sib_time.decode_si_sib6`` (reader already advanced past the
    BCCH-DL-SCH / systemInformation-r8 preamble and any preceding SIBs).

    Structurally identical to ``lte_rrc_sib_decode.decode_sib6_body`` — same bit
    layout — but builds typed ``UTRANeighborFreq`` records instead of
    discarding the reselection parameters. Raises ``IndexError``/``ValueError``
    on a malformed bitstream (callers catch and self-gate).
    """
    result = LteSIB6(log_time=log_time)

    # SIB6 is an extensible SEQUENCE
    has_ext = r.read_bool()

    # 3 OPTIONAL fields in root: FDD list, TDD list, t-ReselectionUTRA-SF
    opt = r.read_bits(3)
    has_fdd = (opt >> 2) & 1
    has_tdd = (opt >> 1) & 1
    has_resel_sf = opt & 1

    # carrierFreqListUTRA-FDD: SEQUENCE (SIZE (1..16))
    if has_fdd:
        num_fdd = r.read_constrained_int(1, 16)
        for _ in range(num_fdd):
            result.fdd_freqs.append(_decode_carrier_freq_utra_fdd(r))

    # carrierFreqListUTRA-TDD: SEQUENCE (SIZE (1..16))
    if has_tdd:
        num_tdd = r.read_constrained_int(1, 16)
        for _ in range(num_tdd):
            result.tdd_freqs.append(_decode_carrier_freq_utra_tdd(r))

    # t-ReselectionUTRA: T-Reselection — INTEGER (0..7)
    result.t_reselection = r.read_constrained_int(0, 7)

    # t-ReselectionUTRA-SF: SpeedStateScaleFactors (OPTIONAL)
    if has_resel_sf:
        result.t_reselection_sf_medium = r.read_enum(4)
        result.t_reselection_sf_high = r.read_enum(4)

    # Skip extension additions if present
    if has_ext:
        skip_extension_additions(r)

    return result


def decode_sib6(log_time: int, data: bytes) -> LteSIB6 | None:
    """Decode SIB6 from raw UPER-encoded payload.

    Expects the raw SIB6 body (not wrapped in BCCH-DL-SCH or SI container).
    Returns None if the payload is too short or decoding fails.

    Args:
        log_time: DIAG log timestamp (modem-boot-relative).
        data: Raw UPER-encoded SIB6 payload bytes.

    Returns:
        LteSIB6 with decoded UTRAN neighbor frequencies, or None on failure.
    """
    # SIB6 minimum: 1 ext + 3 opt + 3 t-resel = 7 bits minimum (no FDD/TDD)
    if not data or len(data) < 1:
        return None

    try:
        return extract_sib6(UperReader(data), log_time)
    except (IndexError, ValueError):
        return None
