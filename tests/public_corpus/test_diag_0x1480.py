"""Public zero-PII fixture for 0x1480 (GLONASS measurement report).

Tier 1 (synthetic-only): glonass_cycle_number/glonass_days/milliseconds
convert to absolute UTC (see public_corpus.risk_tiers.RISK_TIER[0x1480] ==
1), so this frame is built entirely from fabricated values via
public_corpus.support.synthetic -- no bytes are copied from any capture,
private test, or real DIAG log.

Targets the header format '<BIBHIffffB' (_GLO_MEAS_HDR_FMT, 29 bytes) plus
one 70-byte per-SV entry in format '<BbBBBBBHhBHIffffIBIffiHffBI'
(_GLO_SV_FMT), both documented in diaggrok.parsers.diag_0x1480.
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x1480 import parse_0x1480

# Fabricated header values (not from any real capture).
_VERSION = 0x00        # byte 0 -- gated: parser returns None unless == 0
_F_COUNT = 4200
_GLO_CYCLE = 8
_GLO_DAYS = 45
_MS = 12345678
_TIME_BIAS = 0.001
_CLOCK_TIME_UNC = 0.0002
_CLOCK_FREQ_BIAS = 1e-6
_CLOCK_FREQ_UNC = 2e-6
_SV_COUNT = 1

# Fabricated per-SV values.
_SV_ID = 70                 # GLONASS NMEA-range PRN (65-96)
_FREQ_INDEX = -3             # signed i8, GLONASS FDMA slot -7..+6
_OBS_STATE = 5
_CARRIER_NOISE_RAW = 3630    # u16 raw, 0.01 dB-Hz units -> 36.3 dB-Hz
_AZIMUTH = 1.0               # radians (fabricated, exact in float32)
_ELEVATION = 0.5             # radians (fabricated, exact in float32)


def _synthetic_sv() -> bytes:
    """One 70-byte GloSv entry, per _GLO_SV_FMT / _GLO_SV_FIELDS order in
    diag_0x1480.py. Values not asserted on are zero-filled."""
    return pack(
        '<BbBBBBBHhBHIffffIBIffiHffBI',
        _SV_ID,                  # sv_id (B)
        _FREQ_INDEX,              # frequency_index (b)
        _OBS_STATE,               # observation_state (B)
        0,                        # observations (B)
        0,                        # good_observations (B)
        0,                        # hamming_error_count (B)
        0,                        # filter_stages (B)
        _CARRIER_NOISE_RAW,       # carrier_noise (H)
        0,                        # latency (h)
        0,                        # predetect_interval (B)
        0,                        # postdetections (H)
        0,                        # unfiltered_meas_integral (I)
        0.0,                      # unfiltered_meas_fraction (f)
        0.0,                      # unfiltered_time_unc (f)
        0.0,                      # unfiltered_speed (f)
        0.0,                      # unfiltered_speed_unc (f)
        0,                        # measurement_status (I)
        0,                        # misc_status (B)
        0,                        # multipath_estimate (I)
        _AZIMUTH,                 # azimuth (f)
        _ELEVATION,               # elevation (f)
        0,                        # carrier_phase_integral (i)
        0,                        # carrier_phase_fraction (H)
        0.0,                      # fine_speed (f)
        0.0,                      # fine_speed_unc (f)
        0,                        # cycle_slip_count (B)
        0,                        # pad (I)
    )


def _synthetic_1480() -> bytes:
    hdr = pack(
        '<BIBHIffffB',
        _VERSION,
        _F_COUNT,
        _GLO_CYCLE,
        _GLO_DAYS,
        _MS,
        _TIME_BIAS,
        _CLOCK_TIME_UNC,
        _CLOCK_FREQ_BIAS,
        _CLOCK_FREQ_UNC,
        _SV_COUNT,
    )
    assert len(hdr) == 29
    sv = _synthetic_sv()
    assert len(sv) == 70
    return hdr + sv


def test_1480_decodes_synthetic_frame():
    rec = parse_0x1480(1000, _synthetic_1480())
    assert rec is not None
    assert rec.version == 0x00
    assert rec.glonass_cycle_number == _GLO_CYCLE
    assert rec.glonass_days == _GLO_DAYS
    assert rec.milliseconds == _MS
    assert len(rec.svs) == 1
    sv = rec.svs[0]
    assert sv.sv_id == _SV_ID
    assert sv.frequency_index == _FREQ_INDEX
    assert sv.carrier_noise == _CARRIER_NOISE_RAW
    assert sv.azimuth == _AZIMUTH
    assert sv.elevation == _ELEVATION
    # cno_db derivation (see #N): 0.01 dB-Hz scale -> 3630 * 0.01 == 36.3
    assert sv.to_dict()['cno_db'] == _CARRIER_NOISE_RAW * 0.01
