"""Public zero-PII fixture for 0x1837 (GNSS parsed position report).

Tier 1 (synthetic-only): latitude_deg/longitude_deg/altitude_m are explicit
decoded GNSS position fields (see public_corpus.risk_tiers.RISK_TIER[0x1837]
== 1), so this frame is built entirely from fabricated values via
public_corpus.support.synthetic -- no bytes are copied from any capture,
private test, or real DIAG log. The lat/lon/alt values below are made up
for this fixture; they do not correspond to any real receiver location.

Targets the v0x03 (61-byte) layout documented in diaggrok.parsers.diag_0x1837
(parser v5): version=3, u32 position_report_time_ms, u32 report_seq, u8
subtype (invariant const 2), 4 x f64 (lat/lon/alt/uncertainty), u8
horizontal_confidence_pct_candidate, f32 heading_rad, u16 gps_week, u32
gps_tow_ms, u8 v3_byte_53, 7-byte reserved_tail (invariant 0).
"""
from public_corpus.support.synthetic import diag_frame, pack
from diaggrok.parsers.diag_0x1837 import parse_0x1837

# Fabricated per-report values (not from any real capture or device).
_VERSION = 3
_REPORT_TIME_MS = 123456789    # u32 at [1:5] -- fabricated ms timetick
_REPORT_SEQ = 77               # u32 at [5:9] -- fabricated report sequence
_SUBTYPE = 2                   # u8 at [9] -- field_invariants pins this to 2
_LAT = 12.345                  # f64 at [10:18] -- fabricated decimal degrees
_LON = -67.890                 # f64 at [18:26] -- fabricated decimal degrees
_ALT = 1400.5                  # f64 at [26:34] -- fabricated metres (HAE)
_UNC = 3.2                     # f64 at [34:42] -- fabricated metres
_CONF = 95                     # u8 at [42] -- fabricated confidence byte
_HEADING = 1.5                 # f32 at [43:47] -- fabricated radians (exact in f32)
_WEEK = 2400                   # u16 at [47:49] -- fabricated GPS week
_TOW = 123000                  # u32 at [49:53] -- fabricated GPS TOW (ms)
_BYTE_53 = 4                   # u8 at [53] -- fabricated


def _synthetic_1837() -> bytes:
    """Build a v0x03 (61-byte) 0x1837 payload with fully fabricated fields.

    Offsets below are transcribed from the parser's own module docstring
    (layout section) in diag_0x1837.py, not from any capture:

      data[0]      version = 3                (supplied via diag_frame)
      data[1:5]    u32 position_report_time_ms = 123456789
      data[5:9]    u32 report_seq = 77
      data[9]      u8  subtype = 2             (field_invariants const)
      data[10:18]  f64 latitude_deg = 12.345
      data[18:26]  f64 longitude_deg = -67.890
      data[26:34]  f64 altitude_m = 1400.5
      data[34:42]  f64 position_uncertainty_m = 3.2
      data[42]     u8  horizontal_confidence_pct_candidate = 95
      data[43:47]  f32 heading_rad = 1.5
      data[47:49]  u16 gps_week = 2400
      data[49:53]  u32 gps_tow_ms = 123000
      data[53]     u8  v3_byte_53 = 4
      data[54:61]  7B  reserved_tail = 0       (field_invariants const)
    """
    rest = (
        pack('<I', _REPORT_TIME_MS)
        + pack('<I', _REPORT_SEQ)
        + pack('<B', _SUBTYPE)
        + pack('<d', _LAT)
        + pack('<d', _LON)
        + pack('<d', _ALT)
        + pack('<d', _UNC)
        + pack('<B', _CONF)
        + pack('<f', _HEADING)
        + pack('<H', _WEEK)
        + pack('<I', _TOW)
        + pack('<B', _BYTE_53)
        + bytes(7)        # reserved_tail (always 0)
    )
    assert len(rest) == 60
    data = diag_frame(0x1837, _VERSION, rest)
    assert len(data) == 61
    return data


def test_1837_decodes_synthetic_v3_frame():
    rec = parse_0x1837(1000, _synthetic_1837())
    assert rec is not None
    assert rec.version == 3
    assert rec.position_report_time_ms == _REPORT_TIME_MS
    assert rec.report_seq == _REPORT_SEQ
    assert rec.subtype == 2
    assert rec.latitude_deg == _LAT
    assert rec.longitude_deg == _LON
    assert rec.altitude_m == _ALT
    assert rec.position_uncertainty_m == _UNC
    assert rec.horizontal_confidence_pct_candidate == _CONF
    assert rec.heading_rad == _HEADING
    assert rec.gps_week == _WEEK
    assert rec.gps_tow_ms == _TOW
    assert rec.v3_byte_53 == _BYTE_53
    assert rec.reserved_tail == 0
