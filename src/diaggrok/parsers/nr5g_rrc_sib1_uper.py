# diaggrok-provenance: re
"""NR SIB1 cell identity decoder — from-scratch UPER (no pycrate).

Decodes NR BCCH-DL-SCH-Message containing systemInformationBlockType1
to extract cell identity (MCC/MNC/TAC/NCI) from cellAccessRelatedInfo, then
walks on into servingCellConfigCommon for the DL band list,
offsetToPointA, per-SCS carrier bandwidth, initial DL BWP SCS, SSB positions /
periodicity, TDD pattern(s) and ss-PBCH-BlockPower. Those fields are pinned to
stock tshark's nr-rrc.bcch.dl.sch values on real captured bodies. A
servingCellConfigCommon walk
failure keeps the identity and names the IE in ``scc_walk_stopped_at``.

From-scratch UPER decoder using the shared UperReader, following the same
pattern as lte_rrc_sib.py; it has no pycrate dependency.

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
    read_open_type_length,
    skip_extension_additions,
)
from diaggrok.parsers.nr5g_rrc_sib_decode import _skip_multi_freq_band_list_nr


# SubcarrierSpacing ENUMERATED {kHz15, kHz30, kHz60, kHz120, kHz240, spare3..1}.
_SCS_KHZ = (15, 30, 60, 120, 240)

# TS 38.101-1 (FR1) / 38.101-2 (FR2) Table 5.3.2-1: maximum transmission
# bandwidth configuration N_RB -> channel bandwidth MHz, keyed by SCS kHz.
_NRB_TO_MHZ_FR1 = {
    15: {25: 5, 52: 10, 79: 15, 106: 20, 133: 25, 160: 30, 188: 35, 216: 40,
         242: 45, 270: 50},
    30: {11: 5, 24: 10, 38: 15, 51: 20, 65: 25, 78: 30, 92: 35, 106: 40,
         119: 45, 133: 50, 162: 60, 189: 70, 217: 80, 245: 90, 273: 100},
    60: {11: 10, 18: 15, 24: 20, 31: 25, 38: 30, 44: 35, 51: 40, 58: 45,
         65: 50, 79: 60, 93: 70, 107: 80, 121: 90, 135: 100},
}
_NRB_TO_MHZ_FR2 = {
    60: {66: 50, 132: 100, 264: 200},
    120: {32: 50, 66: 100, 132: 200, 264: 400},
}
_FR2_MIN_BAND = 257  # n257 is the first FR2 band (TS 38.101-2 Table 5.2-1)


def nr_channel_bandwidth_mhz(scs_khz: Optional[int], nrb: Optional[int],
                             band: Optional[int] = None) -> Optional[int]:
    """Channel bandwidth MHz for a carrier of ``nrb`` PRBs at ``scs_khz``.

    FR1 unless ``band`` is an FR2 band (>= n257). Returns None when the
    (SCS, N_RB) pair is not a Table 5.3.2-1 maximum configuration.
    """
    if scs_khz is None or nrb is None:
        return None
    table = _NRB_TO_MHZ_FR2 if band is not None and band >= _FR2_MIN_BAND else _NRB_TO_MHZ_FR1
    return table.get(scs_khz, {}).get(nrb)


@dataclass
class NrScsCarrier:
    """SCS-SpecificCarrier (TS 38.331): one numerology's carrier in PRBs."""
    scs_khz: Optional[int]      # None for a spare SubcarrierSpacing code point
    carrier_bandwidth_prb: int  # INTEGER (1..275)
    offset_to_carrier: int      # INTEGER (0..2199), PRBs from point A

    def to_dict(self) -> dict[str, Any]:
        return {'scs_khz': self.scs_khz,
                'carrier_bandwidth_prb': self.carrier_bandwidth_prb,
                'offset_to_carrier': self.offset_to_carrier}


# TDD-UL-DL-Pattern dl-UL-TransmissionPeriodicity, and its -v1530 extension.
_TDD_PERIOD_MS = (0.5, 0.625, 1.0, 1.25, 2.0, 2.5, 5.0, 10.0)
_TDD_PERIOD_V1530_MS = (3.0, 4.0)


@dataclass
class NrTddPattern:
    """TDD-UL-DL-Pattern (TS 38.331)."""
    periodicity_ms: float
    dl_slots: int
    dl_symbols: int
    ul_slots: int
    ul_symbols: int

    def to_dict(self) -> dict[str, Any]:
        return {'periodicity_ms': self.periodicity_ms,
                'dl_slots': self.dl_slots, 'dl_symbols': self.dl_symbols,
                'ul_slots': self.ul_slots, 'ul_symbols': self.ul_symbols}


@dataclass
class NrSib1CellId:
    """Cell identity extracted from NR SIB1 via from-scratch UPER."""
    mcc: str
    mnc: str
    tac: int              # 24-bit tracking area code
    cell_id: int          # 36-bit NR Cell Identity (NCI)
    band: Optional[int] = None
    additional_plmns: list[PlmnIdentity] = field(default_factory=list)
    # trackingAreaCode is OPTIONAL in NR (TS 38.331 PLMN-IdentityInfo); its
    # absence means the cell only supports PSCell/SCell functionality (an
    # NSA-only cell). ``tac`` stays 0 then, so callers gating on a decoded
    # SIB1 keep the cell; this flag says the 0 is an absence.
    tac_present: bool = True
    # cellReservedForOperatorUse of the primary PLMN-IdentityInfo entry
    # (ENUMERATED { reserved, notReserved }, TS 38.331). None if not decoded.
    cell_reserved_for_operator_use: Optional[bool] = None
    # servingCellConfigCommon. ``band`` above is the first DL
    # freqBandIndicatorNR; ``bands`` is the whole DL frequencyBandList.
    # ``scs_khz`` / ``carrier_bandwidth_prb`` are the first DL
    # scs-SpecificCarrier (the only one on every corpus cell); the full list is
    # ``dl_carriers``. ``channel_bandwidth_mhz`` maps (SCS, N_RB) through TS
    # 38.101-1/-2 Table 5.3.2-1 and is None for a non-table N_RB.
    bands: list[int] = field(default_factory=list)
    offset_to_point_a: Optional[int] = None
    dl_carriers: list[NrScsCarrier] = field(default_factory=list)
    scs_khz: Optional[int] = None
    carrier_bandwidth_prb: Optional[int] = None
    channel_bandwidth_mhz: Optional[int] = None
    initial_dl_bwp_scs_khz: Optional[int] = None
    # Fields after the uplink config. They are only set when the walk reached
    # them inside the buffer. ``scc_walk_stopped_at`` names the IE where it
    # gave up otherwise.
    ssb_in_one_group: Optional[int] = None       # BIT STRING (8), MSB = SSB 0
    ssb_group_presence: Optional[int] = None     # BIT STRING (8), FR2 only
    ssb_periodicity_ms: Optional[int] = None
    tdd_reference_scs_khz: Optional[int] = None
    tdd_pattern1: Optional[NrTddPattern] = None
    tdd_pattern2: Optional[NrTddPattern] = None
    ss_pbch_block_power_dbm: Optional[int] = None
    scc_walk_stopped_at: Optional[str] = None

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
        if not self.tac_present:
            d['tac_present'] = False
        if self.bands:
            d['bands'] = list(self.bands)
        for k in ('offset_to_point_a', 'scs_khz', 'carrier_bandwidth_prb',
                  'channel_bandwidth_mhz', 'initial_dl_bwp_scs_khz',
                  'ssb_periodicity_ms', 'tdd_reference_scs_khz',
                  'ss_pbch_block_power_dbm', 'scc_walk_stopped_at'):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        if len(self.dl_carriers) > 1:
            d['dl_carriers'] = [c.to_dict() for c in self.dl_carriers]
        if self.ssb_in_one_group is not None:
            d['ssb_in_one_group'] = f'{self.ssb_in_one_group:08b}'
        if self.ssb_group_presence is not None:
            d['ssb_group_presence'] = f'{self.ssb_group_presence:08b}'
        for k in ('tdd_pattern1', 'tdd_pattern2'):
            v = getattr(self, k)
            if v is not None:
                d[k] = v.to_dict()
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
        # Encoded in 1 bit: NR has no LTE-style spare1/spare2 alternatives,
        # so a 2-bit read is wrong.
        c1_choice = r.read_choice(2)
        if c1_choice != 1:
            return None

        # SIB1 is NOT extensible per the published 38.331 ASN.1 (the spec
        # uses an explicit nonCriticalExtension chain rather than the `...`
        # marker). So there is no extension-presence bit at this position
        # — the optional bitmap starts immediately. Verified against pycrate's
        # compiled grammar (_ext is None on SIB1).
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
        primary_tac_present = False
        primary_cell_id = 0
        primary_reserved: Optional[bool] = None
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
            reserved = r.read_enum(2) == 0

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
                primary_tac_present = bool(has_tac)
                primary_cell_id = cell_id
                primary_reserved = reserved
            else:
                # Additional PLMN entries
                additional_plmns.extend(plmns)

        # Sanity checks
        if len(primary_mcc) != 3 or primary_cell_id == 0:
            return None

        result = NrSib1CellId(
            mcc=primary_mcc,
            mnc=primary_mnc,
            tac=primary_tac,
            cell_id=primary_cell_id,
            tac_present=primary_tac_present,
            additional_plmns=additional_plmns if additional_plmns else [],
            cell_reserved_for_operator_use=primary_reserved,
        )

    except (IndexError, ValueError):
        return None

    # Past the identity, a failure keeps the identity. The walk then reports
    # where it stopped instead of returning None.
    if (opt_bitmap >> 7) & 1:
        _walk_to_serving_cell_config_common(
            r, result, cari_has_ext,
            has_conn_est=bool((opt_bitmap >> 9) & 1),
            has_si_sched=bool((opt_bitmap >> 8) & 1))
    return result


class _Overrun(ValueError):
    """The walk read past the end of the PDU."""


def _check_inside(r: UperReader) -> None:
    # UperReader zero-pads past the end instead of raising, so an over-read
    # (a grammar slip, or a truncated PDU) would otherwise decode as zeros.
    if r.bit_pos > len(r.data) * 8:
        raise _Overrun()


def _walk_to_serving_cell_config_common(r: UperReader, res: NrSib1CellId,
                                        cari_has_ext: bool, has_conn_est: bool,
                                        has_si_sched: bool) -> None:
    """Walk from the end of plmn-IdentityInfoList through servingCellConfigCommon.

    Fills ``res`` in stages. A stage's fields are set only once the reader
    is confirmed still inside the PDU after that stage. On failure,
    ``res.scc_walk_stopped_at`` names the IE being read.
    """
    stage = 'cellAccessRelatedInfo'
    try:
        # CellAccessRelatedInfo's extension additions (Rel-16
        # cellReservedForFutureUse-r16 / npn-IdentityInfoList-r16, ...).
        if cari_has_ext:
            skip_extension_additions(r)
        stage = 'connEstFailureControl'
        if has_conn_est:
            _skip_conn_est_failure_control(r)
        stage = 'si-SchedulingInfo'
        if has_si_sched:
            _skip_si_scheduling_info(r)

        # ServingCellConfigCommonSIB ::= SEQUENCE {
        #     downlinkConfigCommon         DownlinkConfigCommonSIB,
        #     uplinkConfigCommon           UplinkConfigCommonSIB    OPTIONAL,
        #     supplementaryUplink          UplinkConfigCommonSIB    OPTIONAL,
        #     n-TimingAdvanceOffset        ENUMERATED {...}         OPTIONAL,
        #     ssb-PositionsInBurst         SEQUENCE {...},
        #     ssb-PeriodicityServingCell   ENUMERATED {ms5..ms160},
        #     tdd-UL-DL-ConfigurationCommon TDD-UL-DL-ConfigCommon  OPTIONAL,
        #     ss-PBCH-BlockPower           INTEGER (-60..50),
        #     ...
        # }
        stage = 'frequencyInfoDL'
        scc_ext = r.read_bool()
        scc_opt = r.read_bits(4)
        # DownlinkConfigCommonSIB ::= SEQUENCE { frequencyInfoDL,
        #     initialDownlinkBWP, bcch-Config, pcch-Config, ... }
        dl_ext = r.read_bool()
        # FrequencyInfoDL-SIB ::= SEQUENCE {  -- not extensible
        #     frequencyBandList       MultiFrequencyBandListNR-SIB,
        #     offsetToPointA          INTEGER (0..2199),
        #     scs-SpecificCarrierList SEQUENCE (SIZE (1..maxSCSs)) OF SCS-SpecificCarrier }
        bands = _skip_multi_freq_band_list_nr(r)
        offset_to_point_a = r.read_constrained_int(0, 2199)
        carriers = _read_scs_carrier_list(r)
        _check_inside(r)
        res.bands = bands
        res.band = bands[0] if bands else None
        res.offset_to_point_a = offset_to_point_a
        res.dl_carriers = carriers
        if carriers:
            res.scs_khz = carriers[0].scs_khz
            res.carrier_bandwidth_prb = carriers[0].carrier_bandwidth_prb
            res.channel_bandwidth_mhz = nr_channel_bandwidth_mhz(
                res.scs_khz, res.carrier_bandwidth_prb, res.band)

        stage = 'initialDownlinkBWP'
        res.initial_dl_bwp_scs_khz = _skip_bwp_downlink_common(r)
        stage = 'bcch-Config'
        _skip_ext_seq_with_enum(r, 4)  # BCCH-Config { modificationPeriodCoeff, ... }
        stage = 'pcch-Config'
        _skip_pcch_config(r)
        if dl_ext:
            skip_extension_additions(r)
        _check_inside(r)

        stage = 'uplinkConfigCommon'
        if (scc_opt >> 3) & 1:
            _skip_uplink_config_common_sib(r)
        stage = 'supplementaryUplink'
        if (scc_opt >> 2) & 1:
            _skip_uplink_config_common_sib(r)
        stage = 'n-TimingAdvanceOffset'
        if (scc_opt >> 1) & 1:
            r.read_enum(3)

        stage = 'ssb-PositionsInBurst'
        has_group_presence = r.read_bool()
        in_one_group = r.read_bits(8)
        group_presence = r.read_bits(8) if has_group_presence else None
        periodicity = (5, 10, 20, 40, 80, 160)[_read_enum_checked(r, 6)]
        stage = 'tdd-UL-DL-ConfigurationCommon'
        tdd = _read_tdd_ul_dl_config_common(r) if scc_opt & 1 else None
        stage = 'ss-PBCH-BlockPower'
        power = r.read_constrained_int(-60, 50)
        _check_inside(r)
        res.ssb_in_one_group = in_one_group
        res.ssb_group_presence = group_presence
        res.ssb_periodicity_ms = periodicity
        if tdd is not None:
            res.tdd_reference_scs_khz, res.tdd_pattern1, res.tdd_pattern2 = tdd
        res.ss_pbch_block_power_dbm = power
        del scc_ext  # Rel-16+ extension additions are not needed; stop here.
    except _Overrun:
        res.scc_walk_stopped_at = f'{stage}:overrun'
    except (IndexError, ValueError):
        res.scc_walk_stopped_at = stage


def _read_enum_checked(r: UperReader, n_values: int) -> int:
    v = r.read_enum(n_values)
    if v >= n_values:
        raise ValueError(f'enum index {v} >= {n_values}')
    return v


def _scs(code: int) -> Optional[int]:
    return _SCS_KHZ[code] if code < len(_SCS_KHZ) else None


def _skip_ext_seq_with_enum(r: UperReader, n_values: int) -> None:
    """An extensible SEQUENCE holding one mandatory ENUMERATED (BCCH-Config)."""
    ext = r.read_bool()
    r.read_enum(n_values)
    if ext:
        skip_extension_additions(r)


def _read_scs_carrier_list(r: UperReader) -> list[NrScsCarrier]:
    """scs-SpecificCarrierList: SEQUENCE (SIZE (1..maxSCSs=5)) OF SCS-SpecificCarrier.

    SCS-SpecificCarrier ::= SEQUENCE {
        offsetToCarrier     INTEGER (0..2199),
        subcarrierSpacing   SubcarrierSpacing,
        carrierBandwidth    INTEGER (1..maxNrofPhysicalResourceBlocks=275),
        ...,
        [[ txDirectCurrentLocation INTEGER (0..4095) OPTIONAL ]]
    }
    """
    out: list[NrScsCarrier] = []
    for _ in range(r.read_constrained_int(1, 5)):
        ext = r.read_bool()
        offset = r.read_constrained_int(0, 2199)
        scs = _scs(r.read_enum(8))
        nrb = r.read_constrained_int(1, 275)
        if ext:
            skip_extension_additions(r)
        out.append(NrScsCarrier(scs_khz=scs, carrier_bandwidth_prb=nrb,
                                offset_to_carrier=offset))
    return out


def _read_bwp(r: UperReader) -> Optional[int]:
    """BWP ::= SEQUENCE { locationAndBandwidth INTEGER (0..37949),
    subcarrierSpacing, cyclicPrefix ENUMERATED { extended } OPTIONAL }.

    Not extensible. Returns the SCS in kHz.
    """
    r.read_bits(1)  # cyclicPrefix presence; ENUMERATED {extended} is 0 bits
    r.read_constrained_int(0, 37949)
    return _scs(r.read_enum(8))


def _read_setup_release(r: UperReader) -> bool:
    """SetupRelease { X } ::= CHOICE { release NULL, setup X }. True on setup."""
    return r.read_choice(2) == 1


def _skip_bwp_downlink_common(r: UperReader) -> Optional[int]:
    """BWP-DownlinkCommon ::= SEQUENCE {
        genericParameters   BWP,
        pdcch-ConfigCommon  SetupRelease { PDCCH-ConfigCommon } OPTIONAL,
        pdsch-ConfigCommon  SetupRelease { PDSCH-ConfigCommon } OPTIONAL,
        ...
    }
    Returns the genericParameters SCS in kHz.
    """
    ext = r.read_bool()
    opt = r.read_bits(2)
    scs = _read_bwp(r)
    if (opt >> 1) & 1 and _read_setup_release(r):
        _skip_pdcch_config_common(r)
    if opt & 1 and _read_setup_release(r):
        # PDSCH-ConfigCommon ::= SEQUENCE {
        #     pdsch-TimeDomainAllocationList OPTIONAL, ... }
        p_ext = r.read_bool()
        if r.read_bool():
            _skip_time_domain_allocation_list(r)
        if p_ext:
            skip_extension_additions(r)
    if ext:
        skip_extension_additions(r)
    return scs


def _skip_time_domain_allocation_list(r: UperReader) -> None:
    """PDSCH-/PUSCH-TimeDomainResourceAllocationList: SIZE (1..16) OF
    SEQUENCE { k0|k2 INTEGER (0..32) OPTIONAL, mappingType ENUMERATED
    {typeA, typeB}, startSymbolAndLength INTEGER (0..127) }. Not extensible.
    """
    for _ in range(r.read_constrained_int(1, 16)):
        if r.read_bool():
            r.read_constrained_int(0, 32)
        r.read_enum(2)
        r.read_constrained_int(0, 127)


def _skip_pdcch_config_common(r: UperReader) -> None:
    """PDCCH-ConfigCommon ::= SEQUENCE {
        controlResourceSetZero              INTEGER (0..15)      OPTIONAL,
        commonControlResourceSet            ControlResourceSet   OPTIONAL,
        searchSpaceZero                     INTEGER (0..15)      OPTIONAL,
        commonSearchSpaceList               SEQUENCE (SIZE (1..4)) OF SearchSpace OPTIONAL,
        searchSpaceSIB1                     SearchSpaceId        OPTIONAL,
        searchSpaceOtherSystemInformation   SearchSpaceId        OPTIONAL,
        pagingSearchSpace                   SearchSpaceId        OPTIONAL,
        ra-SearchSpace                      SearchSpaceId        OPTIONAL,
        ...
    }
    SearchSpaceId ::= INTEGER (0..maxNrofSearchSpaces-1=39)
    """
    ext = r.read_bool()
    opt = r.read_bits(8)
    if (opt >> 7) & 1:
        r.read_constrained_int(0, 15)
    if (opt >> 6) & 1:
        _skip_control_resource_set(r)
    if (opt >> 5) & 1:
        r.read_constrained_int(0, 15)
    if (opt >> 4) & 1:
        for _ in range(r.read_constrained_int(1, 4)):
            _skip_search_space(r)
    for bit in (3, 2, 1, 0):
        if (opt >> bit) & 1:
            r.read_constrained_int(0, 39)
    if ext:
        skip_extension_additions(r)


def _skip_control_resource_set(r: UperReader) -> None:
    """ControlResourceSet ::= SEQUENCE {
        controlResourceSetId        INTEGER (0..11),
        frequencyDomainResources    BIT STRING (SIZE (45)),
        duration                    INTEGER (1..3),
        cce-REG-MappingType         CHOICE {
            interleaved SEQUENCE { reg-BundleSize ENUMERATED {n2, n3, n6},
                interleaverSize ENUMERATED {n2, n3, n6},
                shiftIndex INTEGER (0..274) OPTIONAL },
            nonInterleaved NULL },
        precoderGranularity         ENUMERATED {sameAsREG-bundle, allContiguousRBs},
        tci-StatesPDCCH-ToAddList       SEQUENCE (SIZE (1..64)) OF TCI-StateId OPTIONAL,
        tci-StatesPDCCH-ToReleaseList   SEQUENCE (SIZE (1..64)) OF TCI-StateId OPTIONAL,
        tci-PresentInDCI            ENUMERATED {enabled}    OPTIONAL,
        pdcch-DMRS-ScramblingID     INTEGER (0..65535)      OPTIONAL,
        ...
    }
    TCI-StateId ::= INTEGER (0..127)
    """
    ext = r.read_bool()
    opt = r.read_bits(4)
    r.read_constrained_int(0, 11)
    r.read_bits(45)
    r.read_constrained_int(1, 3)
    if r.read_choice(2) == 0:
        has_shift = r.read_bool()
        r.read_enum(3)
        r.read_enum(3)
        if has_shift:
            r.read_constrained_int(0, 274)
    r.read_enum(2)
    for bit in (3, 2):
        if (opt >> bit) & 1:
            for _ in range(r.read_constrained_int(1, 64)):
                r.read_constrained_int(0, 127)
    # bit 1: tci-PresentInDCI ENUMERATED {enabled} -- zero bits
    if opt & 1:
        r.read_constrained_int(0, 65535)
    if ext:
        skip_extension_additions(r)


# monitoringSlotPeriodicityAndOffset CHOICE: slot period per alternative.
# sl1 is NULL; slN carries INTEGER (0..N-1).
_SEARCH_SPACE_PERIODS = (1, 2, 4, 5, 8, 10, 16, 20, 40, 80, 160, 320, 640,
                         1280, 2560)


def _skip_search_space(r: UperReader) -> None:
    """SearchSpace ::= SEQUENCE {  -- NOT extensible (Rel-16 added SearchSpaceExt-r16)
        searchSpaceId                       SearchSpaceId,
        controlResourceSetId                INTEGER (0..11)     OPTIONAL,
        monitoringSlotPeriodicityAndOffset  CHOICE { sl1 NULL, sl2 .. sl2560 } OPTIONAL,
        duration                            INTEGER (2..2559)   OPTIONAL,
        monitoringSymbolsWithinSlot         BIT STRING (SIZE (14)) OPTIONAL,
        nrofCandidates                      SEQUENCE { 5 x ENUMERATED {n0..n8} } OPTIONAL,
        searchSpaceType                     CHOICE { common, ue-Specific } OPTIONAL
    }
    """
    opt = r.read_bits(6)
    r.read_constrained_int(0, 39)
    if (opt >> 5) & 1:
        r.read_constrained_int(0, 11)
    if (opt >> 4) & 1:
        period = _SEARCH_SPACE_PERIODS[_read_enum_checked(r, len(_SEARCH_SPACE_PERIODS))]
        if period > 1:
            r.read_constrained_int(0, period - 1)
    if (opt >> 3) & 1:
        r.read_constrained_int(2, 2559)
    if (opt >> 2) & 1:
        r.read_bits(14)  # uper-boundary: allow -- BIT STRING (SIZE (14)), not a length
    if (opt >> 1) & 1:
        for _ in range(5):
            r.read_enum(8)
    if opt & 1:
        if r.read_choice(2) == 0:
            _skip_search_space_common(r)
        else:
            # ue-Specific SEQUENCE { dci-Formats ENUMERATED {2 values}, ... }
            _skip_ext_seq_with_enum(r, 2)


def _skip_search_space_common(r: UperReader) -> None:
    """searchSpaceType.common ::= SEQUENCE {  -- not extensible
        dci-Format0-0-AndFormat1-0  SEQUENCE { ... }  OPTIONAL,
        dci-Format2-0  SEQUENCE { nrofCandidates-SFI SEQUENCE {
                           5 x ENUMERATED {n1, n2} OPTIONAL }, ... } OPTIONAL,
        dci-Format2-1  SEQUENCE { ... }  OPTIONAL,
        dci-Format2-2  SEQUENCE { ... }  OPTIONAL,
        dci-Format2-3  SEQUENCE { dummy1 ENUMERATED {8 values} OPTIONAL,
                           dummy2 ENUMERATED {n1, n2}, ... } OPTIONAL
    }
    """
    opt = r.read_bits(5)
    if (opt >> 4) & 1:
        _skip_empty_ext_seq(r)
    if (opt >> 3) & 1:
        ext = r.read_bool()
        sfi = r.read_bits(5)
        for _ in range(bin(sfi).count('1')):
            r.read_enum(2)
        if ext:
            skip_extension_additions(r)
    if (opt >> 2) & 1:
        _skip_empty_ext_seq(r)
    if (opt >> 1) & 1:
        _skip_empty_ext_seq(r)
    if opt & 1:
        ext = r.read_bool()
        if r.read_bool():
            r.read_enum(8)
        r.read_enum(2)
        if ext:
            skip_extension_additions(r)


def _skip_empty_ext_seq(r: UperReader) -> None:
    """SEQUENCE { ... } -- only the extension bit (plus any additions)."""
    if r.read_bool():
        skip_extension_additions(r)


# firstPDCCH-MonitoringOccasionOfPO CHOICE: INTEGER upper bound per alternative
# (each a SEQUENCE (SIZE (1..maxPO-perPF=4)) OF INTEGER (0..hi)).
_FIRST_PDCCH_MO_HI = (139, 279, 559, 1119, 2239, 4479, 8959, 17919)


def _skip_pcch_config(r: UperReader) -> None:
    """PCCH-Config ::= SEQUENCE {
        defaultPagingCycle      PagingCycle,  -- ENUMERATED {rf32, rf64, rf128, rf256}
        nAndPagingFrameOffset   CHOICE { oneT NULL, halfT INTEGER (0..1),
            quarterT (0..3), oneEighthT (0..7), oneSixteenthT (0..15) },
        ns                      ENUMERATED {four, two, one},
        firstPDCCH-MonitoringOccasionOfPO CHOICE { 8 alternatives } OPTIONAL,
        ...
    }
    """
    ext = r.read_bool()
    has_first = r.read_bool()
    r.read_enum(4)
    n_and_pf = _read_enum_checked(r, 5)
    if n_and_pf:
        r.read_constrained_int(0, (2, 4, 8, 16)[n_and_pf - 1] - 1)
    r.read_enum(3)
    if has_first:
        hi = _FIRST_PDCCH_MO_HI[r.read_choice(8)]
        for _ in range(r.read_constrained_int(1, 4)):
            r.read_constrained_int(0, hi)
    if ext:
        skip_extension_additions(r)


def _skip_uplink_config_common_sib(r: UperReader) -> None:
    """UplinkConfigCommonSIB ::= SEQUENCE {  -- not extensible (hence -v1700)
        frequencyInfoUL             FrequencyInfoUL-SIB,
        initialUplinkBWP            BWP-UplinkCommon,
        timeAlignmentTimerCommon    TimeAlignmentTimer  -- ENUMERATED, 8 values
    }
    FrequencyInfoUL-SIB ::= SEQUENCE {
        frequencyBandList       MultiFrequencyBandListNR-SIB  OPTIONAL,
        absoluteFrequencyPointA ARFCN-ValueNR                 OPTIONAL,
        scs-SpecificCarrierList SEQUENCE (SIZE (1..maxSCSs)) OF SCS-SpecificCarrier,
        p-Max                   P-Max  -- INTEGER (-30..33)   OPTIONAL,
        frequencyShift7p5khz    ENUMERATED {true}             OPTIONAL,
        ...
    }
    """
    ext = r.read_bool()
    opt = r.read_bits(4)
    if (opt >> 3) & 1:
        _skip_multi_freq_band_list_nr(r)
    if (opt >> 2) & 1:
        r.read_constrained_int(0, 3279165)
    _read_scs_carrier_list(r)
    if (opt >> 1) & 1:
        r.read_constrained_int(-30, 33)
    if ext:
        skip_extension_additions(r)
    _skip_bwp_uplink_common(r)
    r.read_enum(8)


def _skip_bwp_uplink_common(r: UperReader) -> None:
    """BWP-UplinkCommon ::= SEQUENCE {
        genericParameters   BWP,
        rach-ConfigCommon   SetupRelease { RACH-ConfigCommon }  OPTIONAL,
        pusch-ConfigCommon  SetupRelease { PUSCH-ConfigCommon } OPTIONAL,
        pucch-ConfigCommon  SetupRelease { PUCCH-ConfigCommon } OPTIONAL,
        ...
    }
    """
    ext = r.read_bool()
    opt = r.read_bits(3)
    _read_bwp(r)
    if (opt >> 2) & 1 and _read_setup_release(r):
        _skip_rach_config_common(r)
    if (opt >> 1) & 1 and _read_setup_release(r):
        # PUSCH-ConfigCommon ::= SEQUENCE {
        #     groupHoppingEnabledTransformPrecoding ENUMERATED {enabled} OPTIONAL,
        #     pusch-TimeDomainAllocationList  OPTIONAL,
        #     msg3-DeltaPreamble   INTEGER (-1..6)    OPTIONAL,
        #     p0-NominalWithGrant  INTEGER (-202..24) OPTIONAL, ... }
        p_ext = r.read_bool()
        p_opt = r.read_bits(4)
        if (p_opt >> 2) & 1:
            _skip_time_domain_allocation_list(r)
        if (p_opt >> 1) & 1:
            r.read_constrained_int(-1, 6)
        if p_opt & 1:
            r.read_constrained_int(-202, 24)
        if p_ext:
            skip_extension_additions(r)
    if opt & 1 and _read_setup_release(r):
        # PUCCH-ConfigCommon ::= SEQUENCE {
        #     pucch-ResourceCommon INTEGER (0..15)   OPTIONAL,
        #     pucch-GroupHopping   ENUMERATED {neither, enable, disable},
        #     hoppingId            INTEGER (0..1023) OPTIONAL,
        #     p0-nominal           INTEGER (-202..24) OPTIONAL, ... }
        p_ext = r.read_bool()
        p_opt = r.read_bits(3)
        if (p_opt >> 2) & 1:
            r.read_constrained_int(0, 15)
        r.read_enum(3)
        if (p_opt >> 1) & 1:
            r.read_constrained_int(0, 1023)
        if p_opt & 1:
            r.read_constrained_int(-202, 24)
        if p_ext:
            skip_extension_additions(r)
    if ext:
        skip_extension_additions(r)


def _skip_rach_config_generic(r: UperReader) -> None:
    """RACH-ConfigGeneric ::= SEQUENCE {
        prach-ConfigurationIndex    INTEGER (0..255),
        msg1-FDM                    ENUMERATED {one, two, four, eight},
        msg1-FrequencyStart         INTEGER (0..274),
        zeroCorrelationZoneConfig   INTEGER (0..15),
        preambleReceivedTargetPower INTEGER (-202..-60),
        preambleTransMax            ENUMERATED {n3 .. n200},  -- 11 values
        powerRampingStep            ENUMERATED {dB0, dB2, dB4, dB6},
        ra-ResponseWindow           ENUMERATED {sl1 .. sl80}, -- 8 values
        ...
    }
    """
    ext = r.read_bool()
    r.read_constrained_int(0, 255)
    r.read_enum(4)
    r.read_constrained_int(0, 274)
    r.read_constrained_int(0, 15)
    r.read_constrained_int(-202, -60)
    r.read_enum(11)
    r.read_enum(4)
    r.read_enum(8)
    if ext:
        skip_extension_additions(r)


# ssb-perRACH-OccasionAndCB-PreamblesPerSSB CHOICE: payload value count per
# alternative (oneEighth/oneFourth/oneHalf/one: ENUMERATED n4..n64 = 16;
# two: ENUMERATED n4..n32 = 8; four: INTEGER (1..16); eight: (1..8);
# sixteen: (1..4)).
_SSB_PER_RACH_VALUES = (16, 16, 16, 16, 8, 16, 8, 4)


def _skip_rach_config_common(r: UperReader) -> None:
    """RACH-ConfigCommon ::= SEQUENCE {
        rach-ConfigGeneric                  RACH-ConfigGeneric,
        totalNumberOfRA-Preambles           INTEGER (1..63)   OPTIONAL,
        ssb-perRACH-OccasionAndCB-PreamblesPerSSB CHOICE {...} OPTIONAL,
        groupBconfigured                    SEQUENCE {
            ra-Msg3SizeGroupA           ENUMERATED {16 values},
            messagePowerOffsetGroupB    ENUMERATED {8 values},
            numberOfRA-PreamblesGroupA  INTEGER (1..64) }  OPTIONAL,
        ra-ContentionResolutionTimer        ENUMERATED {sf8 .. sf64},
        rsrp-ThresholdSSB                   RSRP-Range (0..127) OPTIONAL,
        rsrp-ThresholdSSB-SUL               RSRP-Range          OPTIONAL,
        prach-RootSequenceIndex             CHOICE { l839 INTEGER (0..837),
                                                     l139 INTEGER (0..137) },
        msg1-SubcarrierSpacing              SubcarrierSpacing   OPTIONAL,
        restrictedSetConfig                 ENUMERATED {3 values},
        msg3-transformPrecoder              ENUMERATED {enabled} OPTIONAL,
        ...
    }
    """
    ext = r.read_bool()
    opt = r.read_bits(7)  # uper-boundary: allow -- 7-OPTIONAL bitmap, not a length
    _skip_rach_config_generic(r)
    if (opt >> 6) & 1:
        r.read_constrained_int(1, 63)
    if (opt >> 5) & 1:
        r.read_enum(_SSB_PER_RACH_VALUES[r.read_choice(8)])
    if (opt >> 4) & 1:
        r.read_enum(16)
        r.read_enum(8)
        r.read_constrained_int(1, 64)
    r.read_enum(8)
    if (opt >> 3) & 1:
        r.read_constrained_int(0, 127)
    if (opt >> 2) & 1:
        r.read_constrained_int(0, 127)
    if r.read_choice(2) == 0:
        r.read_constrained_int(0, 837)
    else:
        r.read_constrained_int(0, 137)
    if (opt >> 1) & 1:
        r.read_enum(8)
    r.read_enum(3)
    # bit 0: msg3-transformPrecoder ENUMERATED {enabled} -- zero bits
    if ext:
        skip_extension_additions(r)


def _read_tdd_ul_dl_config_common(
        r: UperReader) -> tuple[Optional[int], NrTddPattern, Optional[NrTddPattern]]:
    """TDD-UL-DL-ConfigCommon ::= SEQUENCE {
        referenceSubcarrierSpacing  SubcarrierSpacing,
        pattern1                    TDD-UL-DL-Pattern,
        pattern2                    TDD-UL-DL-Pattern  OPTIONAL,
        ...
    }
    """
    ext = r.read_bool()
    has_p2 = r.read_bool()
    ref_scs = _scs(r.read_enum(8))
    p1 = _read_tdd_pattern(r)
    p2 = _read_tdd_pattern(r) if has_p2 else None
    if ext:
        skip_extension_additions(r)
    return ref_scs, p1, p2


def _read_tdd_pattern(r: UperReader) -> NrTddPattern:
    """TDD-UL-DL-Pattern ::= SEQUENCE {
        dl-UL-TransmissionPeriodicity ENUMERATED {ms0p5 .. ms10},  -- 8 values
        nrofDownlinkSlots   INTEGER (0..maxNrofSlots=320),
        nrofDownlinkSymbols INTEGER (0..13),
        nrofUplinkSlots     INTEGER (0..320),
        nrofUplinkSymbols   INTEGER (0..13),
        ...,
        [[ dl-UL-TransmissionPeriodicity-v1530 ENUMERATED {ms3, ms4} OPTIONAL ]]
    }
    When -v1530 is present it replaces the root periodicity.
    """
    ext = r.read_bool()
    period = _TDD_PERIOD_MS[r.read_enum(8)]
    pat = NrTddPattern(periodicity_ms=period,
                       dl_slots=r.read_constrained_int(0, 320),
                       dl_symbols=r.read_constrained_int(0, 13),
                       ul_slots=r.read_constrained_int(0, 320),
                       ul_symbols=r.read_constrained_int(0, 13))
    if ext:
        v1530 = _read_first_extension_group(r)
        if v1530 is not None:
            # Group: SEQUENCE { dl-UL-TransmissionPeriodicity-v1530 OPTIONAL }
            g = UperReader(v1530)
            if g.read_bool():
                pat.periodicity_ms = _TDD_PERIOD_V1530_MS[g.read_enum(2)]
    return pat


def _read_first_extension_group(r: UperReader) -> Optional[bytes]:
    """Skip an extension-additions block, returning the first group's octets.

    Same wire layout as :func:`skip_extension_additions`. Returns None when
    the first addition is absent. A group longer than the rest of the PDU
    raises :class:`_Overrun` before any of it is read. ``read_bits`` builds
    its integer one bit at a time, so on a corrupted length (up to 64K+
    octets from the fragmented form) reading first would stall the decoder
    for minutes.
    """
    if r.read_bits(1) == 0:
        num_ext = r.read_bits(6)
    else:
        num_ext = r.read_bits(8)
    bitmap = r.read_bits(num_ext + 1)
    first: Optional[bytes] = None
    for i in range(num_ext + 1):
        if (bitmap >> (num_ext - i)) & 1:
            length = read_open_type_length(r)
            start = r.bit_pos
            if start + length * 8 > len(r.data) * 8:
                raise _Overrun()
            raw = r.read_bits(length * 8)
            if i == 0:
                first = raw.to_bytes(length, 'big')
            r.bit_pos = start + length * 8
    return first


def _skip_conn_est_failure_control(r: UperReader) -> None:
    """ConnEstFailureControl ::= SEQUENCE {  -- not extensible
        connEstFailCount            ENUMERATED {n1, n2, n3, n4},
        connEstFailOffsetValidity   ENUMERATED {s30 .. s900},  -- 8 values
        connEstFailOffset           INTEGER (0..15) OPTIONAL
    }
    """
    has_offset = r.read_bool()
    r.read_enum(4)
    r.read_enum(8)
    if has_offset:
        r.read_constrained_int(0, 15)


def _skip_si_scheduling_info(r: UperReader) -> None:
    """SI-SchedulingInfo ::= SEQUENCE {
        schedulingInfoList      SEQUENCE (SIZE (1..maxSI-Message=32)) OF SchedulingInfo,
        si-WindowLength         ENUMERATED {s5 .. s1280, s2560-v1710, s5120-v1710},
        si-RequestConfig        SI-RequestConfig    OPTIONAL,
        si-RequestConfigSUL     SI-RequestConfig    OPTIONAL,
        systemInformationAreaID BIT STRING (SIZE (24)) OPTIONAL,
        ...
    }
    SchedulingInfo ::= SEQUENCE {  -- not extensible
        si-BroadcastStatus  ENUMERATED {broadcasting, notBroadcasting},
        si-Periodicity      ENUMERATED {rf8 .. rf512},  -- 7 values
        sib-MappingInfo     SEQUENCE (SIZE (1..maxSIB-1=31)) OF SIB-TypeInfo
    }
    SIB-TypeInfo ::= SEQUENCE {  -- not extensible
        type        ENUMERATED {sibType2 .. sibType9, spare8 .. spare1, ...},
        valueTag    INTEGER (0..31)     OPTIONAL,
        areaScope   ENUMERATED {true}   OPTIONAL
    }
    si-WindowLength has 9 values in Rel-15 and 11 in Rel-17. Both fit 4 bits.
    """
    ext = r.read_bool()
    opt = r.read_bits(3)
    for _ in range(r.read_constrained_int(1, 32)):
        r.read_enum(2)
        r.read_enum(7)
        for _ in range(r.read_constrained_int(1, 31)):
            t_opt = r.read_bits(2)
            if r.read_bool():
                # Extended type value: normally-small non-negative number.
                if r.read_bool():
                    raise ValueError('SIB-TypeInfo type extension > 63')
                r.read_bits(6)
            else:
                r.read_enum(16)
            if (t_opt >> 1) & 1:
                r.read_constrained_int(0, 31)
    r.read_enum(11)
    if (opt >> 2) & 1:
        _skip_si_request_config(r)
    if (opt >> 1) & 1:
        _skip_si_request_config(r)
    if opt & 1:
        r.read_bits(24)
    if ext:
        skip_extension_additions(r)


def _skip_si_request_config(r: UperReader) -> None:
    """SI-RequestConfig ::= SEQUENCE {  -- not extensible
        rach-OccasionsSI SEQUENCE {
            rach-ConfigSI           RACH-ConfigGeneric,
            ssb-perRACH-Occasion    ENUMERATED {8 values} }  OPTIONAL,
        si-RequestPeriod    ENUMERATED {8 values}             OPTIONAL,
        si-RequestResources SEQUENCE (SIZE (1..maxSI-Message=32)) OF SEQUENCE {
            ra-PreambleStartIndex       INTEGER (0..63),
            ra-AssociationPeriodIndex   INTEGER (0..15) OPTIONAL,
            ra-ssb-OccasionMaskIndex    INTEGER (0..15) OPTIONAL }
    }
    """
    opt = r.read_bits(2)
    if (opt >> 1) & 1:
        _skip_rach_config_generic(r)
        r.read_enum(8)
    if opt & 1:
        r.read_enum(8)
    for _ in range(r.read_constrained_int(1, 32)):
        res_opt = r.read_bits(2)
        r.read_constrained_int(0, 63)
        if (res_opt >> 1) & 1:
            r.read_constrained_int(0, 15)
        if res_opt & 1:
            r.read_constrained_int(0, 15)


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
