"""Public zero-PII fixture for 0x1477 (GNSS GPS L1 measurement report).

Tier 1 (synthetic-only): header carries gps_week + gps_milliseconds (GPS
absolute time) -- per public_corpus.risk_tiers.RISK_TIER this frame must be
fully synthetic, built via public_corpus.support.synthetic -- no bytes
copied from any capture.

Targets the header + per-SV struct documented in diaggrok.parsers.diag_1477
(_GPS_MEAS_HDR_FMT / _GPS_SV_FMT): version must be 0x00 (the only
supported_versions entry / field_invariants enum), one SV entry with
azimuth/elevation inside the parser's plausibility filter
(-7 < az < 7, -2 < el < 2 radians) and a nonzero sv_id + carrier_noise so
the SV is not skipped.
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x1477 import parse_0x1477

# Fabricated header values (not from any real capture).
_GPS_WEEK = 2200          # u16 -- header field 'week'
_GPS_MS = 123456          # u32 -- header field 'milliseconds'
_TIME_BIAS = 0.001
_CLOCK_TIME_UNC = 0.002
_CLOCK_FREQ_BIAS = 0.003
_CLOCK_FREQ_UNC = 0.004

# Fabricated per-SV values (not from any real capture).
_SV_ID = 5
_CARRIER_NOISE_RAW = 4500   # u16 -- 0.01 dB-Hz units -> cno_db = 45.0
_AZIMUTH_RAD = 0.5          # within the parser's (-7, 7) filter
_ELEVATION_RAD = 0.3        # within the parser's (-2, 2) filter


def _synthetic_1477() -> bytes:
    """Build a 0x1477 payload: 28-byte header + one 70-byte SV record.

    Header format ``_GPS_MEAS_HDR_FMT = '<BIHIffffB'`` (28 bytes), fields
    transcribed from ``_GPS_MEAS_HDR_FIELDS`` in diag_0x1477.py:
      version=0x00 (parser rejects any other value), f_count=1, week=2200
      (fabricated), milliseconds=123456 (fabricated), time_bias/
      clock_time_unc/clock_freq_bias/clock_freq_unc (fabricated small
      floats), sv_count=1.

    Per-SV format ``_GPS_SV_FMT = '<BBBBHBHhBHIffffIBIffiHffBI'`` (70
    bytes), fields transcribed from ``_GPS_SV_FIELDS``: sv_id=5 (nonzero,
    required), carrier_noise=4500 (nonzero, required -- 0.01 dB-Hz ->
    45.0 dB-Hz), azimuth=0.5 rad / elevation=0.3 rad (both inside the
    parser's plausibility filter), remaining fields fabricated/zeroed.
    """
    hdr_fmt = '<BIHIffffB'
    hdr = pack(
        hdr_fmt,
        0x00,               # version
        1,                  # f_count
        _GPS_WEEK,          # week
        _GPS_MS,            # milliseconds
        _TIME_BIAS,
        _CLOCK_TIME_UNC,
        _CLOCK_FREQ_BIAS,
        _CLOCK_FREQ_UNC,
        1,                  # sv_count
    )
    assert len(hdr) == 28

    sv_fmt = '<BBBBHBHhBHIffffIBIffiHffBI'
    sv = pack(
        sv_fmt,
        _SV_ID,             # sv_id
        1,                  # observation_state
        10,                 # observations
        8,                  # good_observations
        0,                  # parity_error_count
        3,                  # filter_stages
        _CARRIER_NOISE_RAW,  # carrier_noise
        -2,                 # latency (signed)
        4,                  # predetect_interval
        20,                 # postdetections
        123456789,          # unfiltered_meas_integral
        0.5,                # unfiltered_meas_fraction
        0.1,                # unfiltered_time_unc
        1.5,                # unfiltered_speed
        0.05,               # unfiltered_speed_unc
        0x1,                # measurement_status
        0,                  # misc_status
        10,                 # multipath_estimate
        _AZIMUTH_RAD,       # azimuth
        _ELEVATION_RAD,     # elevation
        1000,               # carrier_phase_integral (signed)
        200,                # carrier_phase_fraction
        1.4,                # fine_speed
        0.02,               # fine_speed_unc
        0,                  # cycle_slip_count
        0,                  # pad
    )
    assert len(sv) == 70

    return hdr + sv


def test_1477_decodes_synthetic_frame():
    rec = parse_0x1477(1000, _synthetic_1477())
    assert rec is not None
    assert rec.version == 0x00
    assert rec.gps_week == 2200
    assert rec.gps_milliseconds == 123456
    assert len(rec.svs) == 1
    sv = rec.svs[0]
    assert sv.sv_id == 5
    assert sv.carrier_noise == 4500
    # cno_db = carrier_noise * 0.01 (#N cross-chipset-validated scale)
    assert sv.to_dict()['cno_db'] == 45.0
    assert sv.observations == 10
    assert sv.good_observations == 8
