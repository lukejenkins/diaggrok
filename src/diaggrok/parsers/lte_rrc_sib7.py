# diaggrok-provenance: re
"""LTE SIB7 GERAN (2G/GSM) neighbor cell list decoder.

From-scratch UPER decoder for SystemInformationBlockType7, which carries
GERAN neighbor frequency information broadcast by LTE cells. Extracts
carrier frequency groups with ARFCN lists, reselection parameters, and
NCC permitted masks.

Navigates the ASN.1 UPER-encoded SystemInformation container:
    BCCH-DL-SCH -> c1 -> systemInformation -> criticalExtensions ->
    systemInformation-r8 -> sib-TypeAndInfo[N] -> sib7

Handles all three CarrierFreqsGERAN followingARFCNs CHOICE variants:
    - explicitListOfARFCNs: explicit ARFCN list (SIZE 0..31)
    - equallySpacedARFCNs: spacing + count
    - variableBitMapOfARFCNs: bitmap (OCTET STRING SIZE 1..16)

Standalone decoder -- no external dependencies (no pycrate).

Reference: 3GPP TS 36.331 section 6.3.1 (SIB7), ITU-T X.691 (UPER)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from diaggrok.parsers.uper import UperReader
from diaggrok.parsers.asn1_helpers import skip_extension_additions
from diaggrok.parsers.lte_rrc_sib_decode import (
    _skip_speed_state_scale_factors,
    SIB_DECODERS,
    DecodeFailed,
)


# -- Data types --------------------------------------------------------------

@dataclass
class GERANFreqGroup:
    """A single GERAN carrier frequency group from SIB7.

    Each group defines a starting ARFCN plus following ARFCNs (via one of
    three encoding methods), along with cell reselection parameters.
    """
    starting_arfcn: int             # Starting ARFCN (0-1023)
    band_indicator: str             # "dcs1800" or "pcs1900" (BandIndicatorGERAN)
    arfcn_list: list[int]           # All ARFCNs in this group (including starting)
    priority: Optional[int] = None  # CellReselectionPriority (0..7)
    ncc_permitted: int = 0xFF       # 8-bit NCC mask
    q_rxlev_min: int = 0            # Minimum RX level (0..45)
    p_max: Optional[int] = None     # Max TX power (0..39)
    thresh_high: int = 0            # ReselectionThreshold (0..31)
    thresh_low: int = 0             # ReselectionThreshold (0..31)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'starting_arfcn': self.starting_arfcn,
            'band_indicator': self.band_indicator,
            'arfcn_list': self.arfcn_list,
            'arfcn_count': len(self.arfcn_list),
            'ncc_permitted': f"0x{self.ncc_permitted:02X}",
            'q_rxlev_min': self.q_rxlev_min,
            'thresh_high': self.thresh_high,
            'thresh_low': self.thresh_low,
        }
        if self.priority is not None:
            d['priority'] = self.priority
        if self.p_max is not None:
            d['p_max'] = self.p_max
        return d


@dataclass
class LteSIB7:
    """Decoded SIB7: GERAN neighbor frequency information."""
    log_time: int
    t_reselection: int                            # T-Reselection (0..7)
    t_reselection_sf: Optional[tuple[int, int]] = None  # (sf_medium, sf_high) if present
    freq_groups: list[GERANFreqGroup] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'type': 'LteSIB7',
            'log_time': self.log_time,
            't_reselection': self.t_reselection,
            'freq_group_count': len(self.freq_groups),
            'total_arfcns': sum(len(g.arfcn_list) for g in self.freq_groups),
            'freq_groups': [g.to_dict() for g in self.freq_groups],
        }
        if self.t_reselection_sf is not None:
            d['t_reselection_sf_medium'] = self.t_reselection_sf[0]
            d['t_reselection_sf_high'] = self.t_reselection_sf[1]
        return d


# -- ARFCN decoding helpers --------------------------------------------------

# BandIndicatorGERAN ::= ENUMERATED { dcs1800(0), pcs1900(1) }  (TS 36.331)
_BAND_INDICATOR_NAMES = {
    0: "dcs1800",
    1: "pcs1900",
}


def _decode_explicit_list(r: UperReader, starting_arfcn: int) -> list[int]:
    """Decode explicitListOfARFCNs CHOICE.

    ExplicitListOfARFCNs ::= SEQUENCE (SIZE (0..31)) OF ARFCN-ValueGERAN
    ARFCN-ValueGERAN ::= INTEGER (0..1023)
    """
    arfcns = [starting_arfcn]
    num_following = r.read_constrained_int(0, 31)
    for _ in range(num_following):
        arfcn = r.read_constrained_int(0, 1023)
        arfcns.append(arfcn)
    return arfcns


def _decode_equally_spaced(r: UperReader, starting_arfcn: int) -> list[int]:
    """Decode equallySpacedARFCNs CHOICE.

    equallySpacedARFCNs ::= SEQUENCE {
        arfcn-Spacing           INTEGER (1..8),
        numberOfFollowingARFCNs INTEGER (0..31)
    }

    Generates ARFCNs: starting, starting+spacing, starting+2*spacing, ...
    """
    spacing = r.read_constrained_int(1, 8)
    num_following = r.read_constrained_int(0, 31)
    arfcns = [starting_arfcn]
    for i in range(1, num_following + 1):
        arfcns.append(starting_arfcn + i * spacing)
    return arfcns


def _decode_variable_bitmap(r: UperReader, starting_arfcn: int) -> list[int]:
    """Decode variableBitMapOfARFCNs CHOICE.

    variableBitMapOfARFCNs ::= OCTET STRING (SIZE (1..16))

    Each bit (MSB first) represents an ARFCN offset from starting_arfcn+1.
    Bit set = ARFCN present in the group.
    """
    arfcns = [starting_arfcn]
    vbm_len = r.read_constrained_int(1, 16)
    for byte_idx in range(vbm_len):
        octet = r.read_bits(8)
        for bit_idx in range(8):
            if (octet >> (7 - bit_idx)) & 1:
                offset = byte_idx * 8 + bit_idx + 1
                arfcns.append(starting_arfcn + offset)
    return arfcns


# -- CarrierFreqsGERAN decoder -----------------------------------------------

def _decode_carrier_freqs_geran(r: UperReader) -> tuple[int, str, list[int]]:
    """Decode CarrierFreqsGERAN (not extensible).

    CarrierFreqsGERAN ::= SEQUENCE {
        startingARFCN       ARFCN-ValueGERAN,         -- INTEGER (0..1023)
        bandIndicator       BandIndicatorGERAN,        -- ENUMERATED {lsb, rsb}
        followingARFCNs     CHOICE {
            explicitListOfARFCNs    ExplicitListOfARFCNs,
            equallySpacedARFCNs     SEQUENCE { ... },
            variableBitMapOfARFCNs  OCTET STRING (SIZE (1..16))
        }
    }

    Returns (starting_arfcn, band_indicator_name, arfcn_list).
    """
    starting_arfcn = r.read_constrained_int(0, 1023)
    band_ind = r.read_enum(2)  # ENUMERATED {lsb(0), rsb(1)}
    band_name = _BAND_INDICATOR_NAMES.get(band_ind, f"unknown({band_ind})")

    # followingARFCNs: CHOICE (3 alternatives, not extensible)
    following_choice = r.read_choice(3)

    if following_choice == 0:
        arfcns = _decode_explicit_list(r, starting_arfcn)
    elif following_choice == 1:
        arfcns = _decode_equally_spaced(r, starting_arfcn)
    elif following_choice == 2:
        arfcns = _decode_variable_bitmap(r, starting_arfcn)
    else:
        arfcns = [starting_arfcn]

    return starting_arfcn, band_name, arfcns


# -- commonInfo decoder -------------------------------------------------------

def _decode_common_info(r: UperReader) -> tuple[Optional[int], int, int, Optional[int], int, int]:
    """Decode CarrierFreqsInfoGERAN.commonInfo (not extensible).

    commonInfo ::= SEQUENCE {
        cellReselectionPriority  CellReselectionPriority OPTIONAL,  -- INTEGER (0..7)
        ncc-Permitted            BIT STRING (SIZE (8)),
        q-RxLevMin               INTEGER (0..45),
        p-MaxGERAN               INTEGER (0..39) OPTIONAL,
        threshX-High             ReselectionThreshold,               -- INTEGER (0..31)
        threshX-Low              ReselectionThreshold,               -- INTEGER (0..31)
    }

    Returns (priority, ncc_permitted, q_rxlev_min, p_max, thresh_high, thresh_low).
    """
    # 2 optionals: cellReselectionPriority, p-MaxGERAN
    opt = r.read_bits(2)

    priority = None
    if (opt >> 1) & 1:
        priority = r.read_constrained_int(0, 7)

    ncc_permitted = r.read_bits(8)  # BIT STRING (SIZE (8))
    q_rxlev_min = r.read_constrained_int(0, 45)

    p_max = None
    if opt & 1:
        p_max = r.read_constrained_int(0, 39)

    thresh_high = r.read_constrained_int(0, 31)
    thresh_low = r.read_constrained_int(0, 31)

    return priority, ncc_permitted, q_rxlev_min, p_max, thresh_high, thresh_low


# -- SIB7 body decoder -------------------------------------------------------

def _decode_sib7_body(r: UperReader) -> tuple[int, Optional[tuple[int, int]], list[GERANFreqGroup]]:
    """Decode SystemInformationBlockType7 body from current bit position.

    SystemInformationBlockType7 ::= SEQUENCE {
        t-ReselectionGERAN           T-Reselection,               -- INTEGER (0..7)
        t-ReselectionGERAN-SF        SpeedStateScaleFactors       OPTIONAL,
        carrierFreqsInfoList         CarrierFreqsInfoListGERAN    OPTIONAL,
        ...
    }

    Returns (t_reselection, t_reselection_sf, freq_groups).
    """
    has_ext = r.read_bool()
    # 2 optionals: t-ReselectionGERAN-SF, carrierFreqsInfoListGERAN
    opt = r.read_bits(2)

    t_reselection = r.read_constrained_int(0, 7)

    t_reselection_sf = None
    if (opt >> 1) & 1:
        sf_medium = r.read_enum(4)  # oDot25(0), oDot5(1), oDot75(2), lDot0(3)
        sf_high = r.read_enum(4)
        t_reselection_sf = (sf_medium, sf_high)

    freq_groups: list[GERANFreqGroup] = []

    if opt & 1:  # carrierFreqsInfoListGERAN present
        # CarrierFreqsInfoListGERAN ::= SEQUENCE (SIZE (1..maxGNFG)) OF CarrierFreqsInfoGERAN
        # maxGNFG = 16
        num_groups = r.read_constrained_int(1, 16)

        for _ in range(num_groups):
            # CarrierFreqsInfoGERAN (extensible SEQUENCE, no root optionals
            # -- carrierFreqs and commonInfo are both mandatory)
            geran_ext = r.read_bool()

            # carrierFreqs: CarrierFreqsGERAN
            starting_arfcn, band_name, arfcns = _decode_carrier_freqs_geran(r)

            # commonInfo
            priority, ncc_permitted, q_rxlev_min, p_max, thresh_high, thresh_low = (
                _decode_common_info(r)
            )

            freq_groups.append(GERANFreqGroup(
                starting_arfcn=starting_arfcn,
                band_indicator=band_name,
                arfcn_list=arfcns,
                priority=priority,
                ncc_permitted=ncc_permitted,
                q_rxlev_min=q_rxlev_min,
                p_max=p_max,
                thresh_high=thresh_high,
                thresh_low=thresh_low,
            ))

            if geran_ext:
                skip_extension_additions(r)

    if has_ext:
        skip_extension_additions(r)

    return t_reselection, t_reselection_sf, freq_groups


def extract_sib7(r: UperReader, log_time: int = 0) -> LteSIB7:
    """Full-field extraction of a SIB7 body from an EXISTING UperReader.

    The reader must be positioned at the first bit of the
    ``SystemInformationBlockType7`` body. Used both by :func:`decode_sib7`
    (which navigates a full BCCH-DL-SCH container to reach SIB7) and by the
    fused SI-container walker ``lte_rrc_sib_time.decode_si_sibs`` (reader
    already advanced past the systemInformation-r8 preamble and any preceding
    SIBs).

    Mirrors ``lte_rrc_sib6.extract_sib6``: consumes exactly the SIB7 body's
    bits — including any extension additions — so the shared cursor lands on
    the next ``sib-TypeAndInfo`` element. Raises ``IndexError``/``ValueError``
    on a malformed bitstream (callers catch and self-gate).
    """
    t_resel, t_resel_sf, groups = _decode_sib7_body(r)
    return LteSIB7(
        log_time=log_time,
        t_reselection=t_resel,
        t_reselection_sf=t_resel_sf,
        freq_groups=groups,
    )


# -- Top-level SI container navigation ----------------------------------------

# sib-TypeAndInfo CHOICE base indices (3GPP TS 36.331)
_SIB7_CHOICE_INDEX = 5  # sib2=0, sib3=1, sib4=2, sib5=3, sib6=4, sib7=5


def decode_sib7(msg_data: bytes, log_time: int = 0) -> LteSIB7 | None:
    """Decode SIB7 from a BCCH-DL-SCH UPER bitstream.

    Navigates the SystemInformation container to find SIB7, using structural
    body decoders to advance past preceding SIBs. No external dependencies.

    Args:
        msg_data: Raw UPER-encoded BCCH-DL-SCH message bytes.
        log_time: DIAG timestamp for this record.

    Returns:
        LteSIB7 with decoded GERAN neighbor frequency groups, or None if
        the message does not contain SIB7 or decoding fails.
    """
    if not msg_data or len(msg_data) < 5:
        return None

    try:
        r = UperReader(msg_data)

        # BCCH-DL-SCH-MessageType: CHOICE { c1(0), messageClassExtension(1) }
        msg_choice = r.read_choice(2)
        if msg_choice != 0:
            return None

        # c1: CHOICE { systemInformation(0), systemInformationBlockType1(1) }
        c1_choice = r.read_choice(2)
        if c1_choice != 0:  # must be systemInformation, not SIB1
            return None

        # SystemInformation -> criticalExtensions CHOICE
        # { systemInformation-r8(0), criticalExtensionsFuture(1) }
        crit_choice = r.read_choice(2)
        if crit_choice != 0:
            return None

        # systemInformation-r8 SEQUENCE (extensible)
        has_si_ext = r.read_bool()

        # sib-TypeAndInfo: SEQUENCE (SIZE (1..maxSIB)) OF CHOICE
        # maxSIB = 32
        num_sibs = r.read_constrained_int(1, 32)

        for sib_idx in range(num_sibs):
            # Each element: CHOICE { sib2(0)..sib11(9), ... }
            # Extension marker for the CHOICE
            is_extension = r.read_bool()

            if is_extension:
                # Extension SIBs (sib12+) -- cannot navigate past these
                return None

            # Base CHOICE: 10 alternatives (sib2..sib11 = indices 0..9)
            choice_idx = r.read_constrained_int(0, 9)

            if choice_idx == _SIB7_CHOICE_INDEX:
                # Found SIB7 -- decode it
                return extract_sib7(r, log_time)
            else:
                # Walk past this SIB body to reach subsequent SIBs
                decoder = SIB_DECODERS.get(choice_idx)
                if decoder is None:
                    return None  # No body decoder for this SIB type
                try:
                    decoder(r)
                except (DecodeFailed, IndexError, ValueError):
                    return None

    except (IndexError, ValueError):
        return None

    return None
