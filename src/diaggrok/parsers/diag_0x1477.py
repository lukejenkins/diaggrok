"""LOG_GNSS_GPS_MEASUREMENT_REPORT (0x1477) parser.

The per-SV GPS L1 measurement struct offsets/types are confirmed against a
GNSS DIAG capture corpus and the modem's own F3 prints (mc_peak.c per-SV
C/No, mc_gnssmeasreport.c GPS-meas-block header), with F3 self-identity on
RM500Q-AE (SDX55) and LM960 (SDX20). Not derived from third-party decoder
source. The companion log codes 0x1478 (LOG_GNSS_CLOCK_REPORT) and 0x147B
(LOG_GNSS_CD_DB_REPORT) live in ``diag_0x1478.py`` and ``diag_0x147b.py``.

A second SDX20 modem, the Quectel EG12-GT, confirms the per-SV layout in a
4-stream comparison against an LG290P reference receiver: 356 records, all
v=0x00, 100% parse. Az/el match the LG290P to +-3 deg; C/N0 runs ~6-7 dB low
(an antenna/gain-scale offset, not a parse defect).

Log name: LOG_GNSS_GPS_MEASUREMENT_REPORT_C
Also known as: LOG_GAN_CALL_RELEASE_COMPLETE
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from struct import calcsize
from typing import Any

from diaggrok.codes import LOG_GNSS_GPS_MEASUREMENT_REPORT
from diaggrok.parsers.gnss_helpers import unpack_dict
from diaggrok.registry import register

# ---------------------------------------------------------------------------
# Struct format strings — corpus-confirmed GPS L1 measurement layout
# ---------------------------------------------------------------------------

_GPS_MEAS_HDR_FMT = '<BIHIffffB'
_GPS_MEAS_HDR_SZ = calcsize(_GPS_MEAS_HDR_FMT)
_GPS_MEAS_HDR_FIELDS = [
    'version', 'f_count', 'week', 'milliseconds',
    'time_bias', 'clock_time_unc', 'clock_freq_bias', 'clock_freq_unc',
    'sv_count',
]

_GPS_SV_FMT = '<BBBBHBHhBHIffffIBIffiHffBI'
_GPS_SV_SZ = calcsize(_GPS_SV_FMT)
_GPS_SV_FIELDS = [
    'sv_id', 'observation_state', 'observations', 'good_observations',
    'parity_error_count', 'filter_stages', 'carrier_noise', 'latency',
    'predetect_interval', 'postdetections',
    'unfiltered_meas_integral', 'unfiltered_meas_fraction',
    'unfiltered_time_unc', 'unfiltered_speed', 'unfiltered_speed_unc',
    'measurement_status', 'misc_status', 'multipath_estimate',
    'azimuth', 'elevation',
    'carrier_phase_integral', 'carrier_phase_fraction',
    'fine_speed', 'fine_speed_unc',
    'cycle_slip_count', 'pad',
]
assert len(_GPS_SV_FIELDS) == 26


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class GpsSv:
    """Per-SV GPS L1 measurement record (70 bytes on the wire).

    Exposes every field from the 0x1477 SV struct — tracking counts, filter
    state, raw pseudorange (integral + fractional ms), raw/fine Doppler,
    carrier phase (integral + fractional), measurement / misc status bitmasks,
    multipath estimate, and cycle-slip counter.
    """
    sv_id: int
    observation_state: int      # uint8; tracking state machine
    observations: int           # uint8; total measurements taken
    good_observations: int      # uint8; measurements accepted by filter
    parity_error_count: int     # uint16; GPS nav-message parity decode errors
    filter_stages: int          # uint8; Kalman filter stage bitmask
    carrier_noise: int          # raw uint16, 0.01 dB-Hz units (see to_dict)
    latency: int                # signed int16; measurement latency (ms)
    predetect_interval: int     # uint8; coherent pre-detection integration
    postdetections: int         # uint16; non-coherent post-detection count
    unfiltered_meas_integral: int  # uint32; raw pseudorange integer ms
    unfiltered_meas_fraction: float  # float32; raw pseudorange fractional ms
    unfiltered_time_unc: float  # float32; pseudorange time uncertainty (ms)
    unfiltered_speed: float     # float32; raw Doppler / speed (m/s)
    unfiltered_speed_unc: float  # float32; raw speed uncertainty (m/s)
    measurement_status: int     # uint32; per-measurement status bitmask
    misc_status: int            # uint8; additional status bits
    multipath_estimate: int     # uint32; multipath error estimate
    azimuth: float              # float32; radians
    elevation: float            # float32; radians
    carrier_phase_integral: int   # signed int32; raw carrier phase integer part
    carrier_phase_fraction: int   # uint16; raw carrier phase fractional part
    fine_speed: float           # float32; filtered speed (m/s)
    fine_speed_unc: float       # float32; filtered speed uncertainty (m/s)
    cycle_slip_count: int       # uint8; carrier phase cycle slip counter
    pad: int                    # uint32; struct alignment padding (typically 0)

    def to_dict(self) -> dict[str, Any]:
        d = {
            'sv_id': self.sv_id,
            # Position / tracking
            'az_deg': self.azimuth * 180.0 / math.pi,
            'el_deg': self.elevation * 180.0 / math.pi,
            # Raw carrier_noise is in 0.01 dB-Hz units on all validated
            # chipsets (MDM9207, SDX20 V2, SDX55), not 0.1 dB-Hz
            # (cross-chipset validation against NMEA + LG290P).
            'cno_db': self.carrier_noise * 0.01,
            # Tracking state
            'obs_state': self.observation_state,
            'obs_total': self.observations,
            'obs_good': self.good_observations,
            'parity_error_count': self.parity_error_count,
            'filter_stages': self.filter_stages,
            'latency': self.latency,
            'predetect_interval': self.predetect_interval,
            'postdetections': self.postdetections,
            # Raw measurements (pseudorange + carrier phase)
            'pseudorange_ms_integral': self.unfiltered_meas_integral,
            'pseudorange_ms_fraction': self.unfiltered_meas_fraction,
            'pseudorange_time_unc_ms': self.unfiltered_time_unc,
            'carrier_phase_integral': self.carrier_phase_integral,
            'carrier_phase_fraction': self.carrier_phase_fraction,
            'cycle_slip_count': self.cycle_slip_count,
            # Velocity (raw and filtered)
            'speed_raw_mps': self.unfiltered_speed,
            'speed_raw_unc_mps': self.unfiltered_speed_unc,
            'fine_speed': self.fine_speed,       # kept for back-compat
            'fine_speed_unc': self.fine_speed_unc,  # kept for back-compat
            # Quality / status
            'measurement_status': self.measurement_status,
            'misc_status': self.misc_status,
            'multipath_estimate': self.multipath_estimate,
        }
        if self.pad:
            d['pad'] = self.pad
        return d


@dataclass
class Diag0x1477:
    log_time: int
    version: int
    f_count: int
    gps_week: int
    gps_milliseconds: int
    time_bias: float
    clock_time_unc: float
    clock_freq_bias: float
    clock_freq_unc: float
    svs: list[GpsSv] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1477',
            'log_time': self.log_time,
            'version': self.version,
            'f_count': self.f_count,
            'gps_week': self.gps_week,
            'gps_milliseconds': self.gps_milliseconds,
            'time_bias': self.time_bias,
            'clock_time_unc': self.clock_time_unc,
            'clock_freq_bias': self.clock_freq_bias,
            'clock_freq_unc': self.clock_freq_unc,
            'svs': [sv.to_dict() for sv in self.svs],
        }


# ---------------------------------------------------------------------------
# Hardware validation: per-SV GPS L1 measurements → NMEA $GPGSV
# ---------------------------------------------------------------------------
# Hold an outdoor sky-fix, then poll the modem's NMEA GSV (per-SV
# PRN/el/az/SNR) and RMC/GGA (UTC time) sentences in lockstep with the DIAG
# stream. Match each 0x1477 record to the nearest-in-time GSV batch by GPS PRN
# and compare az/el/CNo per SV. The CNo scale (0.01 dB-Hz) is validated this
# way against concurrent $GPGSV + LG290P references on MDM9207 / SDX20 V2 /
# SDX55.

# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

@register(LOG_GNSS_GPS_MEASUREMENT_REPORT, domain="gnss",
    name="0x1477",
    description="Per-SV carrier noise, azimuth, elevation, Doppler, measurement status; validated on MDM9207, SDX20 V2, SDX55, SDX20 (LM960)",
    version=7,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail="Clean-room: GPS L1 per-SV measurement struct confirmed from a GNSS DIAG capture corpus + the modem's own F3 (mc_peak.c per-SV C/No + mc_gnssmeasreport.c header; cno_db, sv_id, gps_week, ms and time_bias F3-verified on RM500Q-AE SDX55 and LM960A18 SDX20) — not from third-party decoder source. CNR scale is 0.01 dB-Hz (not 0.1), validated on EG18-NA SDX20 V2 and FN980m SDX55 LG290P-referenced captures. Truncated payloads (header < 28 B, or sv_count x 70 B overrunning the record) return None.",
    # Header: version, f_count, gps_week, gps_milliseconds, time_bias,
    # clock_time_unc, clock_freq_bias, clock_freq_unc. Body: svs[] (GpsSv
    # dataclass — every per-SV field decoded). 9 top-level named fields.
    fields_identified=9,
    fields_parsed=9,
    issues=(),
    primary_issue=None,
    supported_versions=[0x00],
    # Corpus-wide byte+0 invariant (75,499 records, all version=0x00).
    # Lifts the version=0
    # convention into the registry's field_invariants gate so a future
    # firmware emitting version != 0 fails fast rather than silently
    # mis-decoding the GPS measurement header.
    field_invariants={'version': {'enum': [0x00]}},
    # Per-SV carrier_noise +
    # azimuth/elevation + observation_state + parity_error_count are the
    # raw input the receiver uses to compute fix quality — exactly what
    # WiGLE's GNSS-capture quality columns reflect. Fix position lives in
    # 0x1476, so no `position` role here. CNR scale cross-chipset-validated
    # on MDM9207 / SDX20 V2 / SDX55.
    wigle_direct=True,
    wigle_roles=("gnss-quality",),
    # timebase_roles=("absolute-time", "ts-anchor"): the GPS-measurement
    # sibling of 0x1478 (LOG_GNSS_CLOCK_REPORT) and 0x147B, sharing the
    # gps_week + gps_milliseconds GPS-time header (hardware-verified against
    # F3 mc_gnssmeasreport and NMEA). Per-code, cross-chipset evidence
    # (single-capture sequential decode + linear fit):
    #   * absolute-time — decoded GPS time matches the capture's own wall-clock
    #     within ~1 min on two chipset generations:
    #       RM500Q-AE SDX55 drive capture — 658 valid-fix records, GPS->UTC
    #         21 s after the capture start, monotonic.
    #       LM960 SDX20 drive capture — 1246 valid-fix records, GPS->UTC
    #         36 s after the capture start, monotonic.
    #     gps_week=0xFFFF is the no-fix sentinel (field filled only on a fix).
    #   * ts-anchor — pairing each record's DIAG ts64 (log_time) with its header
    #     GPS time is a clean linear map ts64 -> GPS wall-clock:
    #       SDX55: R²=1.0, slope 52428.64 ts64/ms, residual RMS 0.17 ms (n=658)
    #       SDX20: R²=1.0, slope 52429.19 ts64/ms, residual RMS 2.31 ms (n=1246)
    #     Slope is the chipset-invariant ~52428.8 ts64-units/ms == the known ts64
    #     rate; residuals match 0x1478's (0.1/2.3 ms) almost exactly — 0x1477 and
    #     0x1478 are the GPS measurement + clock reports of the same GNSS
    #     subsystem epoch, stamped off the counter that drives ts64. This is a
    #     metadata/capability tag only.
    timebase_roles=("absolute-time", "ts-anchor"),
)
def parse_0x1477(log_time: int, data: bytes) -> Diag0x1477 | None:
    """Parse a LOG_GNSS_GPS_MEASUREMENT_REPORT (0x1477) log payload.

    CNR scale note: the raw ``carrier_noise`` field is a uint16 in
    **0.01 dB-Hz units**, not 0.1 dB-Hz. Verified empirically against
    concurrent NMEA ``$GPGSV`` output and LG290P ground truth on MDM9207
    (EG25-G), SDX20 V2 (EG18-NA), and SDX55 (FN980m). MDM9607 has not
    been independently validated; if a future capture shows a different
    scale there, add a version-gated divisor like ``diag_0x14de.py``
    does for 0x14DE.
    """
    # A short header or an sv_count x 70 B array that
    # overruns the record returns None (registry WARN) — never a raise, never
    # a record that silently drops the tail SVs.
    if len(data) < _GPS_MEAS_HDR_SZ:
        return None
    if data[0] != 0x00:
        return None
    hdr = unpack_dict(_GPS_MEAS_HDR_FMT, _GPS_MEAS_HDR_FIELDS, data)
    sv_count = hdr['sv_count']
    if _GPS_MEAS_HDR_SZ + sv_count * _GPS_SV_SZ > len(data):
        return None

    svs: list[GpsSv] = []
    sv_data = data[_GPS_MEAS_HDR_SZ:]
    for i in range(sv_count):
        off = i * _GPS_SV_SZ
        if off + _GPS_SV_SZ > len(sv_data):
            break
        s = unpack_dict(_GPS_SV_FMT, _GPS_SV_FIELDS, sv_data, off)
        # Skip unused channels and SVs with invalid measurements
        if s['sv_id'] == 0 or s['carrier_noise'] == 0:
            continue
        # Validate az/el are physically reasonable (filters partially-locked SVs)
        az, el = s['azimuth'], s['elevation']
        if not (-7.0 < az < 7.0 and -2.0 < el < 2.0):  # radians
            continue
        svs.append(GpsSv(
            sv_id=s['sv_id'],
            observation_state=s['observation_state'],
            observations=s['observations'],
            good_observations=s['good_observations'],
            parity_error_count=s['parity_error_count'],
            filter_stages=s['filter_stages'],
            carrier_noise=s['carrier_noise'],
            latency=s['latency'],
            predetect_interval=s['predetect_interval'],
            postdetections=s['postdetections'],
            unfiltered_meas_integral=s['unfiltered_meas_integral'],
            unfiltered_meas_fraction=s['unfiltered_meas_fraction'],
            unfiltered_time_unc=s['unfiltered_time_unc'],
            unfiltered_speed=s['unfiltered_speed'],
            unfiltered_speed_unc=s['unfiltered_speed_unc'],
            measurement_status=s['measurement_status'],
            misc_status=s['misc_status'],
            multipath_estimate=s['multipath_estimate'],
            azimuth=s['azimuth'],
            elevation=s['elevation'],
            carrier_phase_integral=s['carrier_phase_integral'],
            carrier_phase_fraction=s['carrier_phase_fraction'],
            fine_speed=s['fine_speed'],
            fine_speed_unc=s['fine_speed_unc'],
            cycle_slip_count=s['cycle_slip_count'],
            pad=s['pad'],
        ))

    return Diag0x1477(
        log_time=log_time,
        version=hdr['version'],
        f_count=hdr['f_count'],
        gps_week=hdr['week'],
        gps_milliseconds=hdr['milliseconds'],
        time_bias=hdr['time_bias'],
        clock_time_unc=hdr['clock_time_unc'],
        clock_freq_bias=hdr['clock_freq_bias'],
        clock_freq_unc=hdr['clock_freq_unc'],
        svs=svs,
    )
