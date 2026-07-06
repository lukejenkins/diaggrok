"""Public zero-PII fixture for 0x1476 (GNSS Position Report).

Tier 1 (synthetic-only): decoded fields include lat_rad/lon_rad + gps_week/
gps_tow_ms (position + GNSS absolute time) -- per
public_corpus.risk_tiers.RISK_TIER this frame must be fully synthetic, built
via public_corpus.support.synthetic -- no bytes copied from any capture.

Targets the v1/v2 291-byte fixed-layout struct documented in
diaggrok.parsers.diag_0x1476 (_POS_FMT / _POS_FIELDS): version=7 (a
non-v10/v13/v24/mdm9600 value in the corpus-validated enum) selects the
plain 291-byte header+float-block+tail path with no trailer SV-block
decode, the simplest of the several dispatch branches.
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x1476 import parse_0x1476

# Fabricated header values (not from any real capture).
_VERSION = 7            # u8 @ [0] -- a member of the corpus enum {2,7,8,10,13,21,24};
                          # 7 < 13 and != 2/10, so it takes the plain _POS_FMT path
_GPS_WEEK = 2200          # u16 @ [23:25]
_GPS_TOW_MS = 123456      # u32 @ [25:29]
_LAT_RAD = 0.5            # f64 @ [40:48]
_LON_RAD = -1.0           # f64 @ [48:56]
_ALT_M = 100.0            # f32 @ [56:60] -- float-block index 0
_PDOP = 2.0               # f32 @ [236:240] -- float-block index 45
_HDOP = 1.0               # f32 @ [240:244] -- float-block index 46
_VDOP = 1.5               # f32 @ [244:248] -- float-block index 47
_NUM_GPS_SVS = 5          # u8 @ [285]
_TOTAL_GPS_SVS = 8        # u8 @ [286]
_NUM_GLO_SVS = 3          # u8 @ [287]
_TOTAL_GLO_SVS = 4        # u8 @ [288]
_NUM_BDS_SVS = 1          # u8 @ [289]
_TOTAL_BDS_SVS = 2        # u8 @ [290]


def _synthetic_1476() -> bytes:
    """Build a 291-byte v1/v2-class 0x1476 payload with fabricated fields.

    Layout transcribed from ``_POS_FMT`` / ``_POS_FIELDS`` in
    diag_0x1476.py, not from any capture. The struct format string is
    ``'<BIBIHIBHIHIBHIIdd' + 'f'*48 + 'BffffBBHffIIBBBBBB'`` (little-endian,
    no padding).

    Header (17 fields, bytes 0..55):
      [0]     u8  version         = 7 (fabricated)
      [1:5]   u32 f_count         = 0
      [5]     u8  pos_source      = 1 (WLS)
      [6:10]  u32 reserved1       = 0
      [10:12] u16 pos_vel_flag    = 0
      [12:16] u32 pos_vel_flag2   = 0
      [16]    u8  failure_code    = 0
      [17:19] u16 fix_events      = 0
      [19:23] u32 fake_align      = 0
      [23:25] u16 gps_week        = 2200 (fabricated)
      [25:29] u32 gps_tow_ms      = 123456 (fabricated, < 604,800,000)
      [29]    u8  glo_four_year   = 0
      [30:32] u16 glo_days        = 0
      [32:36] u32 glo_tow_ms      = 0
      [36:40] u32 pos_count       = 1
      [40:48] f64 lat_rad         = 0.5 (fabricated)
      [48:56] f64 lon_rad         = -1.0 (fabricated)

    Float block (48 floats, bytes 56..247): index0 = alt_m = 100.0, indices
    1..44 zero-filled, index45 = pdop = 2.0, index46 = hdop = 1.0,
    index47 = vdop = 1.5. (No pythagorean-identity check applies on this
    dispatch path -- that guard is MDM9600-specific.)

    Tail (18 fields, bytes 248..290): only the SV-count bytes at the end
    are non-zero (fabricated counts); the rest (ellipse/reliability/
    gnss-heading/sensor-mask fields) are zero-filled.
    """
    fmt = '<BIBIHIBHIHIBHIIdd' + 'f' * 48 + 'BffffBBHffIIBBBBBB'

    header_values = (
        _VERSION,   # version
        0,          # f_count
        1,          # pos_source
        0,          # reserved1
        0,          # pos_vel_flag
        0,          # pos_vel_flag2
        0,          # failure_code
        0,          # fix_events
        0,          # fake_align
        _GPS_WEEK,
        _GPS_TOW_MS,
        0,          # glo_four_year
        0,          # glo_days
        0,          # glo_tow_ms
        1,          # pos_count
        _LAT_RAD,
        _LON_RAD,
    )

    floats = [0.0] * 48
    floats[0] = _ALT_M       # alt_m
    floats[45] = _PDOP       # pdop
    floats[46] = _HDOP       # hdop
    floats[47] = _VDOP       # vdop

    tail_values = (
        0,          # ellipse_confidence
        0.0,        # ellipse_angle
        0.0,        # ellipse_semi_major
        0.0,        # ellipse_semi_minor
        0.0,        # pos_sigma_vertical
        0,          # horiz_reliability
        0,          # vert_reliability
        0,          # reserved2
        0.0,        # gnss_heading_rad
        0.0,        # gnss_heading_unc_rad
        0,          # sensor_data_mask
        0,          # sensor_aid_mask
        _NUM_GPS_SVS,
        _TOTAL_GPS_SVS,
        _NUM_GLO_SVS,
        _TOTAL_GLO_SVS,
        _NUM_BDS_SVS,
        _TOTAL_BDS_SVS,
    )

    body = pack(fmt, *header_values, *floats, *tail_values)
    assert len(body) == 291
    return body


def test_1476_decodes_synthetic_v1v2_frame():
    rec = parse_0x1476(1000, _synthetic_1476())
    assert rec is not None
    assert rec.version == 7
    assert rec.pos_source == 1
    assert rec.gps_week == 2200
    assert rec.gps_tow_ms == 123456
    assert rec.lat_rad == 0.5
    assert rec.lon_rad == -1.0
    assert rec.alt_m == 100.0
    assert rec.pdop == 2.0
    assert rec.hdop == 1.0
    assert rec.vdop == 1.5
    assert rec.num_gps_svs == 5
    assert rec.total_gps_svs == 8
    assert rec.num_glo_svs == 3
    assert rec.num_bds_svs == 1
