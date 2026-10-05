"""0x14DE — OEM DRE multi-constellation measurement report.

Multi-constellation per-SV raw measurements emitted by the GNSS engine's
OEM DRE (Dead Reckoning Engine) feature. Structured as N sequential reports
per fix epoch, one per (constellation, band) slot.

Provenance and validation:

- The measurement struct layout (34 header fields + 36/38 SV fields) is
  derived from our own GNSS DIAG capture corpus, not from third-party
  decoder source. Where an external naming reference disagrees with the
  corpus, the corpus wins: the GPS + GLONASS C/N0 scale is 0.01 dB-Hz on
  MDM9207 / SDX20 V2 / SDX55 / MDM9607 (not 0.1 dB-Hz), and BeiDou sv_ids
  are 201..237 (PRN = sv_id − 200), not 401..437.
- On Telit FN980m firmware seq 2 is SBAS, seq 3 is GLONASS and seq 4 is
  Galileo (checked by sv_id range on FN980m and EG18-NA captures). The
  seq→constellation mapping is **firmware-vendor-specific** on SDX55:
  FN980m (Telit) uses seq=4→Galileo, seq=5→BeiDou; EM9190 (Sierra) uses
  seq=4→BeiDou, seq=5→Galileo. The parser therefore derives the
  constellation from the sv_id range (primary) and from the
  per-constellation system-time week encoded in ``gps_week`` (fallback for
  all-zero SV slots). The static seq table is a best-guess hint for
  Telit-family SDX55 firmware only.
- Only version byte 0x02 is observed. The MDM9607 EG25-G emits
  **v2-hybrid** records (1160 records, all byte0=0x02, uniform 1839 B — the
  v2-header / 109-byte-SV path, 0.01 dB-Hz). Against a same-antenna
  survey-grade LG290P: GPS L1 C/N0 vs LG290P MSM7 = 0.55 dB mean error
  (P95 1.06), Galileo L1 = 0.89 dB (P95 1.71); per-SV az/el within ±3°.
  Co-temporal F3 ``pp_columnpeaks.c`` per-SV ``CNo`` prints (25.5–33.6 dB)
  match the decoded ``cno_db``. A v1 layout (0.1 dB-Hz) appears only in an
  external reference and has never been observed, so it is not accepted.
- **Pseudorange** (EG25-G MDM9607 bench, same-antenna LG290P). The
  pseudorange is receiver time minus SV transmit time:
  ``pr_m = (gps_milliseconds − (…_pseudorange_ms_integral + …_ms_fraction))
  × c/1000`` (the ``…_ms_integral`` field is the SV **transmit**
  time-of-week in ms, not transit time). Against the LG290P raw code
  pseudorange (RTCM3 MSM7 → RINEX ``C1C``, interpolated to each modem
  epoch's TOW, one receiver-clock bias removed per constellation per
  epoch): **GPS unfiltered median 2.46 m / RMS 5.24 m** (n=1388 SV-epochs
  over 275 epochs), **filtered 2.20 m / RMS 4.14 m** (smoothed < raw, so
  the filtered/unfiltered split is real), Galileo ~1.4 m (n=20). Global
  scale slope = 0.99999971 (ideal 1.0). The LG290P is a different chip and
  decode path, so this validates the number itself, not only parser/firmware
  self-consistency.
- **Pseudorange, EG18-NA SDX20 V2** (5,406 0x14DE + 283 co-temporal 0x14E1
  SVPOLY records, same-antenna LG290P survey reference): the per-SV
  pseudorange minus the light-time-corrected geometric range to the fixed
  survey position regresses against the 0x14E1 ``other[0]`` SV clock bias
  at **slope 1.000005×(-c·1e-3), r=-0.999998, n=12,603 GPS SV-epochs**,
  post-rx-clock residual 28.2 m (filtered) / 29.0 m (unfiltered). This
  jointly grounds this code's pseudorange fields and 0x14E1's clock
  polynomial on a third silicon family (after EG25-G MDM9607 and FN980m
  SDX55).
- **EG12-GT (SDX20/MDM9x50)**: 1,065 records, all v=0x02, 100% parse;
  version byte and fixed 1839 B size are byte-identical to EG18-NA SDX20 V2.

The ``OemdreSv`` per-SV helper dataclass has no ``type`` JSON field and
keeps its descriptive name.

Log name: LOG_GNSS_OEMDRE_MEASUREMENT_REPORT
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from struct import calcsize
from typing import Any, Optional

from diaggrok.codes import LOG_GNSS_OEMDRE_MEASUREMENT_REPORT
from diaggrok.parsers.gnss_helpers import unpack_dict
from diaggrok.registry import register

# ---------------------------------------------------------------------------
# Struct format strings — corpus-confirmed OEMDRE measurement layout
# ---------------------------------------------------------------------------

# oemdre_measurement_report header (34 fields)
_OEMDRE_MEAS_HDR_FMT = '<BBBBBHBIIQBBffHIIIBBBHIffffBIIIIIB'
_OEMDRE_MEAS_HDR_SZ = calcsize(_OEMDRE_MEAS_HDR_FMT)
_OEMDRE_MEAS_HDR_FIELDS = [
    'version', 'reason', 'sv_count', 'seq_num', 'seq_max',
    'rf_loss', 'system_rtc_valid',
    'f_count', 'clock_resets', 'system_rtc_time',
    'gps_leap_seconds', 'gps_leap_seconds_unc',
    'gps_to_glo_bias_ms', 'gps_to_glo_bias_ms_unc',
    'gps_week', 'gps_milliseconds', 'gps_time_bias', 'gps_clock_time_unc',
    'gps_clock_source',
    'glo_clock_source', 'glo_year', 'glo_day', 'glo_milliseconds',
    'glo_time_bias', 'glo_clock_time_unc',
    'clock_freq_bias', 'clock_freq_unc',
    'frequency_source',
    'cdma_clock_info_0', 'cdma_clock_info_1', 'cdma_clock_info_2',
    'cdma_clock_info_3', 'cdma_clock_info_4',
    'source',
]
assert len(_OEMDRE_MEAS_HDR_FIELDS) == 34

# oemdre_measurement_report_sv v1 (36 fields, 109 bytes) — MDM9607 / SDX20 V2 hybrid
_OEMDRE_SV_FMT = '<HbIBBBBBHIIHHhfIffffIfffBIBfffffQIHB'
_OEMDRE_SV_SZ = calcsize(_OEMDRE_SV_FMT)
_OEMDRE_SV_FIELDS = [
    'sv_id', 'glo_frequency_index',
    'observation_state',
    'observations', 'good_observations', 'filter_stages',
    'predetect_interval', 'cycle_slip_count',
    'postdetections',
    'measurement_status', 'measurement_status2',
    'carrier_noise', 'rf_loss', 'latency',
    'filtered_meas_fraction', 'filtered_meas_integral',
    'filtered_time_unc', 'filtered_speed', 'filtered_speed_unc',
    'unfiltered_meas_fraction', 'unfiltered_meas_integral',
    'unfiltered_time_unc', 'unfiltered_speed', 'unfiltered_speed_unc',
    'multipath_estimate_valid', 'multipath_estimate',
    'direction_valid',
    'azimuth', 'elevation', 'doppler_acceleration',
    'fine_speed', 'fine_speed_unc',
    'carrier_phase',
    'f_count', 'parity_error_count', 'good_parity',
]
assert len(_OEMDRE_SV_FIELDS) == 36

# oemdre_measurement_report_sv v2 (38 fields, 112 bytes) — SDX55+
# Inserted after `direction_valid`: `direction_valid2` (B) + `reserved_v2` (H)
_OEMDRE_SV_V2_FMT = '<HbIBBBBBHIIHHhfIffffIfffBIBBHfffffQIHB'
_OEMDRE_SV_V2_SZ = calcsize(_OEMDRE_SV_V2_FMT)
_OEMDRE_SV_V2_FIELDS = [
    'sv_id', 'glo_frequency_index',
    'observation_state',
    'observations', 'good_observations', 'filter_stages',
    'predetect_interval', 'cycle_slip_count',
    'postdetections',
    'measurement_status', 'measurement_status2',
    'carrier_noise', 'rf_loss', 'latency',
    'filtered_meas_fraction', 'filtered_meas_integral',
    'filtered_time_unc', 'filtered_speed', 'filtered_speed_unc',
    'unfiltered_meas_fraction', 'unfiltered_meas_integral',
    'unfiltered_time_unc', 'unfiltered_speed', 'unfiltered_speed_unc',
    'multipath_estimate_valid', 'multipath_estimate',
    'direction_valid',
    'direction_valid2', 'reserved_v2',
    'azimuth', 'elevation', 'doppler_acceleration',
    'fine_speed', 'fine_speed_unc',
    'carrier_phase',
    'f_count', 'parity_error_count', 'good_parity',
]
assert len(_OEMDRE_SV_V2_FIELDS) == 38
_OEMDRE_V2_FIXED_SZ = 2783  # 95 header + 24 * 112
_OEMDRE_V2_MAX_SVS = 24


# OEM DRE sequence-number → constellation mapping (Telit SDX55 firmware).
#
# **This table is firmware-vendor-specific**. The seq
# ordering is set by the firmware's internal measurement engine and differs
# between Telit and Sierra on the same SDX55 chipset:
#
#   Telit FN980m (SDX55):    seq 4 → Galileo,  seq 5 → BeiDou
#   Sierra EM9190 (SDX55):   seq 4 → BeiDou,   seq 5 → Galileo
#
# The parser does not treat this static table as authoritative. It
# derives the constellation from sv_id range (primary) and from the
# per-constellation system-time week encoded in ``gps_week`` (fallback
# for all-zero SV slots). The table below is retained as a **Telit-style**
# fallback hint only — used when neither sv_id ranges nor gps_week yield
# a determination.
#
# Mapping (Telit FN980m, checked against sv_id ranges):
#
#   seq 1: sv_ids 1..32           → GPS L1
#   seq 2: sv_ids 33..64 (WAAS)   → SBAS L1
#   seq 3: sv_ids 65..96          → GLONASS G1 (slot + 64 encoding)
#   seq 4: sv_ids 301..336        → Galileo E1 (Telit ordering)
#   seq 5: sv_ids 201..237        → BeiDou B1 (Telit ordering; populated
#                                  on BeiDou-enabled Telit firmware only)
#   seq 6: ? (zero-filled)        → unknown, L5-band slot hypothesis
#   seq 7: ? (zero-filled)        → unknown, L5-band slot hypothesis
OEMDRE_SEQ_CONSTELLATION_TELIT = {
    1: 'GPS',
    2: 'SBAS',
    3: 'GLONASS',
    4: 'Galileo',
    5: 'BeiDou',
    6: 'unknown',
    7: 'unknown',
}

OEMDRE_SEQ_SIGNAL_TELIT = {
    1: 'L1',
    2: 'L1',
    3: 'G1',
    4: 'E1',
    5: 'B1',
    6: 'L5?',
    7: 'L5?',
}

# Backwards-compat aliases — consumers should migrate to the runtime
# derivation helpers (derive_constellation_from_svs / derive_constellation_from_week)
# or the explicit Telit/Sierra tables.
OEMDRE_SEQ_CONSTELLATION = OEMDRE_SEQ_CONSTELLATION_TELIT
OEMDRE_SEQ_SIGNAL = OEMDRE_SEQ_SIGNAL_TELIT

# Per-constellation GPS-week offsets. A non-GPS OEM DRE record's
# ``gps_week`` field carries that constellation's system-time week, not
# the true GPS week. Offsets: GPS week = const_week + GPS_WEEK_OFFSET.
#
#   Galileo System Time (GST) epoch: 1999-08-22 = GPS week 1024
#   BeiDou System Time (BDT) epoch:  2006-01-01 = GPS week 1356
#   GLONASS has no week concept — the field is zero-filled.
_GAL_GPS_WEEK_OFFSET = 1024
_BDS_GPS_WEEK_OFFSET = 1356


def derive_constellation_from_svs(svs: list['OemdreSv']) -> tuple[str, str] | None:
    """Derive (constellation, band) from sv_id ranges of populated SVs.

    Returns None if no populated SV matches a known range. The sv_id
    encoding is the same across Telit and Sierra SDX55 firmware:

      GPS:     1..32       (PRN = sv_id)
      SBAS:    33..64      (chipset-specific index, not NMEA PRN)
      GLONASS: 65..96      (slot = sv_id − 64)
      BeiDou:  201..237    (PRN = sv_id − 200)  — Sierra-observed
      Galileo: 301..336    (PRN = sv_id − 300)
    """
    for sv in svs:
        if 1 <= sv.sv_id <= 32:
            return 'GPS', 'L1'
        if 33 <= sv.sv_id <= 64:
            return 'SBAS', 'L1'
        if 65 <= sv.sv_id <= 96:
            return 'GLONASS', 'G1'
        if 201 <= sv.sv_id <= 237:
            return 'BeiDou', 'B1'
        if 301 <= sv.sv_id <= 336:
            return 'Galileo', 'E1'
    return None


def derive_constellation_from_week(gps_week: int) -> tuple[str, str] | None:
    """Derive (constellation, band) from the ``gps_week`` field.

    For non-GPS constellations OEM DRE encodes that constellation's own
    system-time week in the ``gps_week`` slot. Returns None if the value
    is ambiguous (e.g., truly GPS or SBAS, which both use GPS time).
    """
    if gps_week == 0:
        return 'GLONASS', 'G1'
    # GPS weeks in the corpus era are ≈ 2414 and up;
    # GST week ≈ GPS − 1024 ≈ 1390;
    # BDT week ≈ GPS − 1356 ≈ 1058.
    if 1300 <= gps_week < 2000:
        return 'Galileo', 'E1'
    if 800 <= gps_week < 1300:
        return 'BeiDou', 'B1'
    # gps_week >= 2000 or < 800: GPS/SBAS (both use true GPS time) or
    # an unrecognized future-era value; caller must disambiguate via seq_num
    # or sv_id presence.
    return None


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class OemdreSv:
    """Per-SV OEM DRE measurement record (internal helper for 0x14DE).

    Holds every field from both v1 (109-byte) and v2 (112-byte) struct layouts.
    The two v2-only fields (``direction_valid2``, ``reserved_v2``) are
    ``None`` for v1 records.

    ``cno_divisor`` carries the parser's CNR scale (0.01 dB-Hz on all
    validated v2 firmwares; the 0.1 dB-Hz v1 scale from an external
    reference has never been observed in a capture).

    No ``type`` JSON field — emitted as a nested dict inside the parent
    ``Diag0x14DE.to_dict()['svs']`` list. Helper dataclasses without a
    registered ``type`` keep their descriptive name.
    """
    # Identity
    sv_id: int                     # Per-constellation encoding (see sv_id_to_prn)
    glo_frequency_index: int       # signed — GLONASS freq slot only, 0 for others
    # Tracking state
    observation_state: int
    observations: int
    good_observations: int
    filter_stages: int
    predetect_interval: int
    cycle_slip_count: int           # firmware-zeroed on MDM9607 EG25-G (0/10125 SVs)
    postdetections: int
    # Measurement status bitmasks
    measurement_status: int
    measurement_status2: int
    # Signal quality
    carrier_noise: int             # raw uint16 — scale depends on version
    rf_loss: int                   # signed int16 — RF front-end loss
    latency: int                   # signed int16 — ms latency of measurement
    # Filtered pseudorange + velocity
    filtered_meas_fraction: float  # fractional ms
    filtered_meas_integral: int    # integer ms
    filtered_time_unc: float       # ms
    filtered_speed: float          # m/s — GROUNDED range-rate: matches d(PR)/dt to 1.63 m/s median, sign +, over 2890 GPS SV pairs
    filtered_speed_unc: float      # m/s
    # Unfiltered (raw) pseudorange + velocity
    unfiltered_meas_fraction: float
    unfiltered_meas_integral: int
    unfiltered_time_unc: float
    unfiltered_speed: float
    unfiltered_speed_unc: float
    # Multipath + direction
    multipath_estimate_valid: int  # u8 boolean — firmware-zeroed on MDM9607 EG25-G (always False)
    multipath_estimate: int        # u32 raw — firmware-zeroed on MDM9607 EG25-G (0/10125 SVs)
    direction_valid: int           # u8 boolean
    # Azimuth / elevation (radians)
    azimuth: float
    elevation: float
    # Dynamics
    doppler_acceleration: float    # m/s² — firmware-zeroed on MDM9607 EG25-G (0/10125 SVs)
    fine_speed: float              # filtered best-estimate speed (m/s) — firmware-zeroed on MDM9607 EG25-G (0/10125 SVs; use filtered_speed)
    fine_speed_unc: float          # m/s — firmware-zeroed on MDM9607 EG25-G
    # Carrier phase
    carrier_phase: int             # raw uint64 — firmware-zeroed on MDM9607 EG25-G (0/10125 SVs; DRE carrier-phase not emitted on this build)
    # Diagnostic
    f_count: int                   # u32 — measurement frame count
    parity_error_count: int        # u16 — GROUNDED: 0 at C/No≥30 dB, peaks in 10-25 dB marginal band
    good_parity: int               # u8 boolean — GROUNDED: True mean C/No 24.2 dB vs False 15.7 dB
    # v2-only extras
    direction_valid2: Optional[int] = None
    reserved_v2: Optional[int] = None
    # Parser state (not on the wire)
    cno_divisor: float = 0.01      # dB-Hz per raw count

    @property
    def prn(self) -> int:
        """Derive the per-constellation PRN from the raw sv_id.

        OEM DRE sv_id encoding (validated across Telit SDX55 and Sierra
        SDX55 firmware):

          GPS:     1..32     → PRN = sv_id
          SBAS:    33..64    → raw index (chipset-specific; not NMEA PRN)
          GLONASS: 65..96    → slot = sv_id − 64
          BeiDou:  201..237  → PRN = sv_id − 200  (Sierra-observed)
          Galileo: 301..336  → PRN = sv_id − 300
        """
        if 1 <= self.sv_id <= 32:
            return self.sv_id
        if 65 <= self.sv_id <= 96:
            return self.sv_id - 64
        if 201 <= self.sv_id <= 237:
            return self.sv_id - 200
        if 301 <= self.sv_id <= 336:
            return self.sv_id - 300
        return self.sv_id  # fallback, including SBAS raw index

    def to_dict(self) -> dict[str, Any]:
        d = {
            'sv_id': self.sv_id,
            'prn': self.prn,
            # Position / direction
            'az_deg': self.azimuth * 180.0 / math.pi,
            'el_deg': self.elevation * 180.0 / math.pi,
            'direction_valid': bool(self.direction_valid),
            # Signal quality
            'cno_db': self.carrier_noise * self.cno_divisor,
            'rf_loss': self.rf_loss,
            # GLONASS freq slot (only meaningful for GLONASS SVs)
            'glo_freq_index': self.glo_frequency_index,
            # Tracking state
            'obs_state': self.observation_state,
            'obs_total': self.observations,
            'obs_good': self.good_observations,
            'filter_stages': self.filter_stages,
            'latency': self.latency,
            'predetect_interval': self.predetect_interval,
            'postdetections': self.postdetections,
            # Raw pseudorange (filtered + unfiltered)
            'filtered_pseudorange_ms_integral': self.filtered_meas_integral,
            'filtered_pseudorange_ms_fraction': self.filtered_meas_fraction,
            'filtered_pseudorange_time_unc_ms': self.filtered_time_unc,
            'unfiltered_pseudorange_ms_integral': self.unfiltered_meas_integral,
            'unfiltered_pseudorange_ms_fraction': self.unfiltered_meas_fraction,
            'unfiltered_pseudorange_time_unc_ms': self.unfiltered_time_unc,
            # Velocity (filtered, unfiltered, and best-estimate "fine")
            'filtered_speed_mps': self.filtered_speed,
            'filtered_speed_unc_mps': self.filtered_speed_unc,
            'unfiltered_speed_mps': self.unfiltered_speed,
            'unfiltered_speed_unc_mps': self.unfiltered_speed_unc,
            'fine_speed_mps': self.fine_speed,
            'fine_speed_unc_mps': self.fine_speed_unc,
            'doppler_acceleration_mps2': self.doppler_acceleration,
            # Carrier phase
            'carrier_phase': self.carrier_phase,
            'cycle_slip_count': self.cycle_slip_count,
            # Quality / status
            'measurement_status': self.measurement_status,
            'measurement_status2': self.measurement_status2,
            'multipath_estimate': self.multipath_estimate,
            'multipath_estimate_valid': bool(self.multipath_estimate_valid),
            # Diagnostic
            'f_count': self.f_count,
            'parity_error_count': self.parity_error_count,
            'good_parity': bool(self.good_parity),
        }
        if self.direction_valid2 is not None:
            d['direction_valid2'] = bool(self.direction_valid2)
            d['reserved_v2'] = self.reserved_v2
        return d


@dataclass
class Diag0x14DE:
    """Multi-constellation raw measurement report (0x14DE).

    Holds every field from the 95-byte header + all SV records from the
    payload. The ``constellation`` / ``band`` strings are derived at parse
    time with priority: sv_id range → gps_week offset → Telit-style
    seq→const fallback table (the seq ordering is vendor-specific:
    Sierra and Telit differ on SDX55).
    """
    log_time: int
    # Header (all 34 fields)
    version: int
    reason: int
    sv_count: int
    seq_num: int
    seq_max: int
    rf_loss: int
    system_rtc_valid: int
    f_count: int
    clock_resets: int
    system_rtc_time: int
    gps_leap_seconds: int
    gps_leap_seconds_unc: int
    gps_to_glo_bias_ms: float
    gps_to_glo_bias_ms_unc: float
    gps_week: int
    gps_milliseconds: int
    gps_time_bias: int
    gps_clock_time_unc: int
    gps_clock_source: int
    glo_clock_source: int
    glo_year: int
    glo_day: int
    glo_milliseconds: int
    glo_time_bias: float
    glo_clock_time_unc: float
    clock_freq_bias: float
    clock_freq_unc: float
    frequency_source: int
    cdma_clock_info_0: int
    cdma_clock_info_1: int
    cdma_clock_info_2: int
    cdma_clock_info_3: int
    cdma_clock_info_4: int
    source: int
    # Derived / SV data
    svs: list[OemdreSv] = field(default_factory=list)
    constellation: str = ''  # populated from sv_id / gps_week / Telit fallback
    band: str = ''           # populated from sv_id / gps_week / Telit fallback

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x14DE',
            'log_time': self.log_time,
            'version': self.version,
            # Sequence + constellation
            'constellation': self.constellation,
            'band': self.band,
            'seq_num': self.seq_num,
            'seq_max': self.seq_max,
            'sv_count': self.sv_count,
            'reason': self.reason,
            # GPS clock
            'gps_week': self.gps_week,
            'gps_milliseconds': self.gps_milliseconds,
            'gps_time_bias': self.gps_time_bias,
            'gps_clock_time_unc': self.gps_clock_time_unc,
            'gps_clock_source': self.gps_clock_source,
            'gps_leap_seconds': self.gps_leap_seconds,
            'gps_leap_seconds_unc': self.gps_leap_seconds_unc,
            # GPS↔GLONASS time bias
            'gps_to_glo_bias_ms': self.gps_to_glo_bias_ms,
            'gps_to_glo_bias_ms_unc': self.gps_to_glo_bias_ms_unc,
            # GLONASS clock
            'glo_clock_source': self.glo_clock_source,
            'glo_year': self.glo_year,
            'glo_day': self.glo_day,
            'glo_milliseconds': self.glo_milliseconds,
            'glo_time_bias': self.glo_time_bias,
            'glo_clock_time_unc': self.glo_clock_time_unc,
            # Clock frequency state
            'clock_freq_bias': self.clock_freq_bias,
            'clock_freq_unc': self.clock_freq_unc,
            'frequency_source': self.frequency_source,
            # RTC + frame counters
            'rf_loss': self.rf_loss,
            'system_rtc_valid': bool(self.system_rtc_valid),
            'system_rtc_time': self.system_rtc_time,
            'f_count': self.f_count,
            'clock_resets': self.clock_resets,
            # CDMA / misc diagnostic
            'cdma_clock_info': [
                self.cdma_clock_info_0, self.cdma_clock_info_1,
                self.cdma_clock_info_2, self.cdma_clock_info_3,
                self.cdma_clock_info_4,
            ],
            'source': self.source,
            # Per-SV data
            'svs': [sv.to_dict() for sv in self.svs],
        }


# ---------------------------------------------------------------------------
# SV helper
# ---------------------------------------------------------------------------

def _build_oemdre_sv(d: dict, cno_divisor: float) -> OemdreSv:
    """Build an OemdreSv from an unpacked struct dict (v1 or v2)."""
    return OemdreSv(
        sv_id=d['sv_id'],
        glo_frequency_index=d['glo_frequency_index'],
        observation_state=d['observation_state'],
        observations=d['observations'],
        good_observations=d['good_observations'],
        filter_stages=d['filter_stages'],
        predetect_interval=d['predetect_interval'],
        cycle_slip_count=d['cycle_slip_count'],
        postdetections=d['postdetections'],
        measurement_status=d['measurement_status'],
        measurement_status2=d['measurement_status2'],
        carrier_noise=d['carrier_noise'],
        rf_loss=d['rf_loss'],
        latency=d['latency'],
        filtered_meas_fraction=d['filtered_meas_fraction'],
        filtered_meas_integral=d['filtered_meas_integral'],
        filtered_time_unc=d['filtered_time_unc'],
        filtered_speed=d['filtered_speed'],
        filtered_speed_unc=d['filtered_speed_unc'],
        unfiltered_meas_fraction=d['unfiltered_meas_fraction'],
        unfiltered_meas_integral=d['unfiltered_meas_integral'],
        unfiltered_time_unc=d['unfiltered_time_unc'],
        unfiltered_speed=d['unfiltered_speed'],
        unfiltered_speed_unc=d['unfiltered_speed_unc'],
        multipath_estimate_valid=d['multipath_estimate_valid'],
        multipath_estimate=d['multipath_estimate'],
        direction_valid=d['direction_valid'],
        azimuth=d['azimuth'],
        elevation=d['elevation'],
        doppler_acceleration=d['doppler_acceleration'],
        fine_speed=d['fine_speed'],
        fine_speed_unc=d['fine_speed_unc'],
        carrier_phase=d['carrier_phase'],
        f_count=d['f_count'],
        parity_error_count=d['parity_error_count'],
        good_parity=d['good_parity'],
        direction_valid2=d.get('direction_valid2'),
        reserved_v2=d.get('reserved_v2'),
        cno_divisor=cno_divisor,
    )


def _parse_oemdre_sv(sv_fmt, sv_fields, sv_sz, sv_data, sv_count, cno_divisor):
    """Parse SV records from OEM DRE measurement data.

    Skips zero-filled (sv_id==0, observation_state==0) padding slots. Handles
    both v1 (109-byte) and v2 (112-byte) SV layouts via the format arg.

    Note: on FN980m (SDX55) seq 5 has ``sv_count > 0`` but the SV slots are
    all zero-filled because the RF chain doesn't produce BeiDou measurements.
    The zero-padding filter catches those cleanly.
    """
    svs: list[OemdreSv] = []
    for i in range(sv_count):
        off = i * sv_sz
        if off + sv_sz > len(sv_data):
            break
        s = unpack_dict(sv_fmt, sv_fields, sv_data, off)
        if s['sv_id'] == 0 and s['observation_state'] == 0:
            continue
        svs.append(_build_oemdre_sv(s, cno_divisor))
    return svs


# ---------------------------------------------------------------------------
# Cross-checking against a live modem
# ---------------------------------------------------------------------------
# The Sierra Wireless EM9190 (SDX55) emits v=2 abundantly (2700 records, all
# version==2, in one GNSS capture), and its observations established the
# BeiDou sv_id encoding (201..237) and the Galileo/BeiDou seq ordering.
#
# The groundable surface is the PER-SV measurement block (the nested ``svs``
# list), which maps field-for-field to Sierra's AT!GPSSATINFO? per-satellite dump
# (SV id / elevation / azimuth / SNR). The 0x14DE header is GNSS-clock / RTC /
# time-bias state with no clean live-AT reference.
#
# Caveats when comparing:
#  * cond:sky-fix — the modem must be actively tracking SVs under open sky or the
#    SV slots are zero-filled padding (the parser drops sv_id==0 slots). Cover the
#    antenna as a negative control (SV list empties).
#  * Per-SV matching is by (constellation, PRN): 0x14DE encodes sv_id with a
#    per-constellation offset (PRN = sv_id, sv_id−64, sv_id−200, sv_id−300) and
#    exposes the decoded ``prn`` — match that to the AT!GPSSATINFO? SV number
#    within the same constellation before comparing C/N0 / az / el.
#  * 0x14DE rotates one (constellation, band) slot per seq_num, so a single record
#    holds only one constellation's SVs; AT!GPSSATINFO? lists all constellations
#    at once. Aggregate across a full seq cycle (seq 1..seq_max) before comparing
#    counts.

# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

@register(LOG_GNSS_OEMDRE_MEASUREMENT_REPORT, domain="gnss",
    name="0x14DE",
    description="Multi-constellation raw measurements via OEM DRE; full v2 header + per-SV struct coverage",
    version=7,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail="Clean-room: the OEMDRE measurement struct (all 34 header fields + all 36/38 per-SV fields) is derived from our own GNSS DIAG capture corpus, not from third-party decoder source. Version byte 0x02 on 100% of 269,875 records over 214 captures, in three size classes (2783 B v2-full with 24 x 112 B SV slots on SDX55; 1839 B v2-hybrid with 16 x 109 B SV slots on SDX20 V2 / MDM9607; one 1647 B record). Header f_count / week / TOW / sv_count / clock frequency bias match the firmware's own mc_gnssmeasreport.c F3 prints on an exact f_count join (EG25-G MDM9607 120/120, RM500Q-AE and SIM8202G-M2 SDX55), and per-SV cno_db matches mc_peak.c CNo 133/133. C/N0 (0.01 dB-Hz), az/el and pseudorange are independently validated against a same-antenna LG290P survey receiver. Constellation is derived from sv_id range, then gps_week, then a Telit-style seq table, because the seq ordering differs between vendors. A short header, a non-0x02 version byte, or a truncated SV body returns None. No black-box decoder (QCSuper/SCAT) covers this code.",
    issues=(),
    primary_issue=None,
    # Header: 34 fields per _OEMDRE_MEAS_HDR_FIELDS (all unpacked, all exposed).
    # Per-SV: 37 binary fields (38 v2 fields − reserved_v2 padding); all
    # exposed via OemdreSv.to_dict() inside the parent svs list.
    # 71 = 34 + 37; constellation/band/prn are derived, not counted.
    fields_identified=71,
    fields_parsed=71,
    supported_versions=[0x02],
    # v0x01 is not declared. No capture has ever carried it — 450,900
    # records, byte0 = 0x02 on every one — so it cannot be F3-grounded. Its
    # only provenance is an external-reference struct with a 0.1 dB-Hz C/N0
    # scale. A byte0 = 0x01 record returns None (the registry's unhandled
    # WARN + tally), so if one ever appears it is loud, not decoded under an
    # ungrounded scale.
    field_invariants={'version': {'enum': [0x02]}},
    # WiGLE tag: per-SV carrier_noise (CN0), azimuth, elevation, sv_id,
    # filter_stages, observations exposed at OemdreSv dataclass level —
    # same fix-quality-input evidence shape as 0x1477 (GPS L1 Meas Report)
    # and 0x1544 (GNSS SV Aggregate). Fix position lives in 0x1476, so
    # `position` role does not belong here.
    wigle_direct=True,
    wigle_roles=("gnss-quality",),
    # timebase_roles=("absolute-time", "ts-anchor") — the OEM-DRE-measurement member of the
    # already-tagged GNSS-measurement-report timebase family (GPS 0x1477/0x1478/
    # 0x147B, GLONASS 0x1480, BeiDou 0x1756). Its header carries a GPS-time epoch
    # in gps_week + gps_milliseconds (TOW), whose decode is independently
    # HW-VERIFIED vs the F3 mc_pqme `$PQME2` sentence (gps_week=2424 EXACT).
    # Timebase evidence (single-capture sequential decode + linear fit):
    #   * absolute-time — on true-GPS-week records (gps_week in the GPS range),
    #     decoded gps_week/ms -> UTC is monotonic and matches each capture's own
    #     wall-clock start plus a plausible GNSS TTFF:
    #       Quectel RM500Q-AE capture A — 134 recs, week 2422,
    #         first fix +38 s after capture start (TTFF).
    #       Quectel RM500Q-AE capture B — 106 recs, week 2421,
    #         first fix +55 s after capture start (TTFF).
    #     Decisive cross-system check: at the nearest ts64, each record's
    #     0x14DE->UTC vs the SAME capture's 0x1477 GPS-meas ->UTC is BOUNDED at
    #     exactly 1.000 s — one 1 Hz sampling tick, not an epoch error (a wrong
    #     week would skew by thousands of seconds), pinning the shared GPS epoch.
    #   * ts-anchor — ts64 paired with gps_milliseconds is a clean linear map:
    #       RM500Q-AE capture B:  R²=1.000000 (n=106)
    #       SIM8202G-M2:          R²=1.000000, x-check Δ 0.000 s (n=262)
    #     The slope is the chipset-invariant ~52428.8 ts64/ms (the known ts64
    #     rate). Per-capture-conditional, same as the sibling tags: a capture
    #     with a ts64 discontinuity (RM500Q-AE capture A, R²=0.28) is not
    #     a clean anchor — the tag asserts the relationship exists where ts64 is
    #     continuous, not that every capture qualifies.
    # SCOPE: the tag rests on the true-GPS-time records. The gps_week slot is a
    # PER-CONSTELLATION system-time week (derive_constellation_from_week) — the
    # GLONASS/BeiDou weeks are different epochs (covered by 0x1480/0x1756), and
    # SIM8202G-M2 emits the 0xFFFF sentinel week on its OEM-DRE records (TOW still
    # valid, so ts-anchor holds there but absolute-time does not). Header decode
    # unchanged; this is a metadata/capability tag.
    timebase_roles=("absolute-time", "ts-anchor"),
    # ---------------------------------------------------------------------
    # F3-VERDICT v0x02: GROUND
    # ---------------------------------------------------------------------
    # The firmware's OWN debug prints name these header quantities, in the SAME
    # captures, at the same epochs. Site: mc_gnssmeasreport.c, one print per
    # constellation per 1 Hz epoch:
    #     Gps_MeasBlk       - N SVs, FC f, Wk w,   Ms m, ClkBiasMs c
    #     Glo_MeasBlk       - N SVs, FC f, Days d, Ms m, ClkBiasMs c
    #     Gal_MeasBlk       - N SVs, FC f, Wk w,   Ms m, ClkBiasMs c
    #     QzssSbas_MeasBlk  - N SVs, FC f, Wk w,   Ms m, ClkBiasMs c
    #     "Clk Src: s, FreqBias: b m/s, FreqUnc: u m/s Sys: y"
    # and mc_peak.c "<SYS> PeakProcess(n) SV: i, FC: f, CNo: c" for per-SV C/N0.
    #
    # Join is on f_count as an EXACT key (never nearest-ts: the F3 print and the
    # log record sit in different sub-epoch slots per modem — SIM8202G aligns at
    # delta 0, RM500Q at delta +1000, i.e. one 1 kHz-counter epoch — so a
    # nearest-ts join silently pairs epoch N's print with epoch N-1's record).
    #
    #   EG25-G  MDM9607  1839 B  (30 epochs x 4 constellations = 120 records)
    #     f_count exact-key 120/120 · gps_week/glo_day 120/120 ·
    #     gps_/glo_milliseconds 120/120 · sv_count 120/120 ·
    #     clock_freq_bias 30/30 · clock_freq_unc 30/30
    #   RM500Q-AE SDX55   2783 B  f_count 266/268 · ms 266/266 · sv_count 266/266
    #   SIM8202G-M2 SDX55 2783 B  f_count 393/396 · ms 393/393 · sv_count 393/393
    #     (the per-block misses are boundary prints with no partner record)
    #   per-SV cno_db vs mc_peak.c CNo/10: 133/133 EXACT, median error +0.000 dB
    #
    # CONTROLS (why this is not a coincidental join):
    #   shuffle within block ....... ms 0.4-5 % · sv_count 16-90 %
    #   pooled shuffle (all const.). gps_week 28-33 %  <- the week is only
    #     discriminating on MDM9607, where it VARIES by constellation
    #     (GPS 2431, Galileo 1407, GLONASS days 957, QZSS/SBAS 2431 at one FC).
    #     On the two SDX55 captures the week is a corpus-constant (0xFFFF
    #     sentinel / 2422), so their 100 % week agreement is UNINFORMATIVE and
    #     is NOT claimed.
    #   decoy f_count keys ......... fc+1, fc+999, fc+1001, fc+7777 -> 0 hits;
    #     only fc+/-1000 (the adjacent 1 Hz epoch) matches, as it must.
    #   decoy per-SV keys .......... prn+/-1 -> 0 matches; random SV row -> 0 %
    #     exact, median error ~ -24 dB; adjacent epoch -> 3.3 % exact.
    # The prn and constellation DERIVATIONS are grounded transitively: both are
    # join keys, and the four-constellation MDM9607 join separates GPS /
    # GLONASS / Galileo / SBAS exactly as the firmware's own four block names do.
    #
    # Cross-oracle verdicts recorded for the same (code, version):
    #   0x60 DIAG_EVENT_REPORT_F .. PRESENT but SILENT. 785 event items / 18 ids
    #     in the MDM9607 capture; 14 are GNSS-named but ALL are lifecycle events
    #     (GPS_PD_SESSION_START/END, FIX_START/END, LM_SESSION_*, TLE_*,
    #     SPECTRUM_ANALYZER_STATUS). Payloads are 0-4 B substates;
    #     EVENT_GPS_PD_POSITION is declared "No Payload". None carries sv_count,
    #     f_count, a week/TOW or a per-SV C/N0. Structural corroboration only:
    #     30 EVENT_GPS_PD_FIX_START == 30 measurement epochs.
    #   black-box (qcsuper/SCAT) ... NO COVERAGE. qcsuper on the same capture
    #     emitted 3 records, all 0xB0C0 (LTE RRC OTA), and a header-only pcap;
    #     zero 0x14DE. F3 is the only in-capture oracle for this code.
    #
    # Corpus: 269,875 records over 214 captures, byte0 = 0x02 in 100 %.
    # Three size classes — 2783 B (182,297), 1839 B (87,577), 1647 B (1).
    # v0x01 is UNOBSERVED: a measured absence, not an assumption.
    # ---------------------------------------------------------------------
)
def parse_0x14de(log_time: int, data: bytes) -> Diag0x14DE | None:
    """Parse a LOG_GNSS_OEMDRE_MEASUREMENT_REPORT (0x14DE) log payload.

    Format variants:

    - **v1** (version byte = 1): not accepted. The external-reference
      layout (109-byte SV records, 0.1 dB-Hz) has never been observed in a
      capture; such a record returns None. The 109-byte SV layout is used
      by the v2-hybrid form.
    - **v2 hybrid** (version byte = 2): variable-size payload with v1-layout
      109-byte SV records but a v2 header. Observed on EG18-NA (SDX20 V2),
      EG12-GT and the EG25-G **MDM9607**, all at 1839 bytes (95 header +
      16 × 109 SV). Uses the 0.01 dB-Hz CNR scale — independently confirmed
      on MDM9607 against a same-antenna LG290P MSM7 reference (GPS L1
      0.55 dB, Galileo 0.89 dB mean C/N0 error; az/el ±3°).
    - **v2 full** (version byte = 2, SDX55+): fixed 2783-byte payload with
      95-byte header + 24 × 112-byte v2 SV slots. Observed on FN980m.
      0.01 dB-Hz CNR scale. Typically 6-7 seq slots emitted per fix.

    All v2 firmware validated so far (SDX20 V2, SDX55) emits reports on a
    rotating seq_num 1..seq_max schedule where each seq is a different
    (constellation, band) slot — see :data:`OEMDRE_SEQ_CONSTELLATION`.
    """
    # A short header returns None (registry WARN) instead of raising — a
    # raise crashes consumers.
    if len(data) < _OEMDRE_MEAS_HDR_SZ:
        return None
    if data[0] != 0x02:  # v0x01 undeclared (never observed), see @register
        return None
    hdr = unpack_dict(_OEMDRE_MEAS_HDR_FMT, _OEMDRE_MEAS_HDR_FIELDS, data)
    sv_count = hdr['sv_count']
    version = hdr['version']
    sv_data = data[_OEMDRE_MEAS_HDR_SZ:]

    if len(data) >= _OEMDRE_V2_FIXED_SZ:
        # v2 full: fixed-size packet with 112-byte SV records (SDX55+), 24 slots
        svs = _parse_oemdre_sv(
            _OEMDRE_SV_V2_FMT, _OEMDRE_SV_V2_FIELDS, _OEMDRE_SV_V2_SZ,
            sv_data, _OEMDRE_V2_MAX_SVS, cno_divisor=0.01)
    else:
        # v2 hybrid: v2 header with v1-format SV records (SDX20 V2)
        # carrier_noise units are 0.01 dB-Hz (v2 style) despite v1 SV layout
        # The hybrid body is a whole array of
        # 109-byte SV slots (1839 = 95 + 16 x 109; sv_count counts only the
        # populated slots). A body that is not a whole number of slots, or
        # holds fewer slots than sv_count, is truncated (or a truncated
        # 2783 B v2-full record) -> None instead of a silent partial decode.
        if len(sv_data) % _OEMDRE_SV_SZ or sv_count * _OEMDRE_SV_SZ > len(sv_data):
            return None
        max_svs = len(sv_data) // _OEMDRE_SV_SZ
        svs = _parse_oemdre_sv(
            _OEMDRE_SV_FMT, _OEMDRE_SV_FIELDS, _OEMDRE_SV_SZ,
            sv_data, min(sv_count, max_svs), cno_divisor=0.01)

    seq_num = hdr['seq_num']
    # Constellation derivation priority:
    #   1. sv_id range of populated SVs (robust across firmware vendors)
    #   2. gps_week heuristic (GLONASS/Galileo/BeiDou use distinct week offsets)
    #   3. Telit-style seq→const fallback table (legacy / best-guess)
    const_band = (
        derive_constellation_from_svs(svs)
        or derive_constellation_from_week(hdr['gps_week'])
        or (OEMDRE_SEQ_CONSTELLATION_TELIT.get(seq_num, 'unknown'),
            OEMDRE_SEQ_SIGNAL_TELIT.get(seq_num, ''))
    )
    constellation, band = const_band
    return Diag0x14DE(
        log_time=log_time,
        version=version,
        reason=hdr['reason'],
        sv_count=sv_count,
        seq_num=seq_num,
        seq_max=hdr['seq_max'],
        rf_loss=hdr['rf_loss'],
        system_rtc_valid=hdr['system_rtc_valid'],
        f_count=hdr['f_count'],
        clock_resets=hdr['clock_resets'],
        system_rtc_time=hdr['system_rtc_time'],
        gps_leap_seconds=hdr['gps_leap_seconds'],
        gps_leap_seconds_unc=hdr['gps_leap_seconds_unc'],
        gps_to_glo_bias_ms=hdr['gps_to_glo_bias_ms'],
        gps_to_glo_bias_ms_unc=hdr['gps_to_glo_bias_ms_unc'],
        gps_week=hdr['gps_week'],
        gps_milliseconds=hdr['gps_milliseconds'],
        gps_time_bias=hdr['gps_time_bias'],
        gps_clock_time_unc=hdr['gps_clock_time_unc'],
        gps_clock_source=hdr['gps_clock_source'],
        glo_clock_source=hdr['glo_clock_source'],
        glo_year=hdr['glo_year'],
        glo_day=hdr['glo_day'],
        glo_milliseconds=hdr['glo_milliseconds'],
        glo_time_bias=hdr['glo_time_bias'],
        glo_clock_time_unc=hdr['glo_clock_time_unc'],
        clock_freq_bias=hdr['clock_freq_bias'],
        clock_freq_unc=hdr['clock_freq_unc'],
        frequency_source=hdr['frequency_source'],
        cdma_clock_info_0=hdr['cdma_clock_info_0'],
        cdma_clock_info_1=hdr['cdma_clock_info_1'],
        cdma_clock_info_2=hdr['cdma_clock_info_2'],
        cdma_clock_info_3=hdr['cdma_clock_info_3'],
        cdma_clock_info_4=hdr['cdma_clock_info_4'],
        source=hdr['source'],
        svs=svs,
        constellation=constellation,
        band=band,
    )
