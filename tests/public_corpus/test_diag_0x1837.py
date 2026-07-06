"""Public zero-PII fixture for 0x1837 (GNSS per-fix position record).

Tier 1 (synthetic-only): latitude_deg/longitude_deg/altitude_m are explicit
decoded GNSS position fields (see public_corpus.risk_tiers.RISK_TIER[0x1837]
== 1), so this frame is built entirely from fabricated values via
public_corpus.support.synthetic -- no bytes are copied from any capture,
private test, or real DIAG log. The lat/lon/alt values below are made up
for this fixture; they do not correspond to any real receiver location.

Targets the v=3 (61-byte) layout documented in diaggrok.parsers.diag_0x1837:
version=3, u64 timestamp, u8 subtype (invariant const 2), 4 x f64
(lat/lon/alt/uncertainty), u32 session_marker, u32 counter_a, u32 counter_b,
u32 reserved_zero_1 (invariant 0), u24 reserved_zero_2 (invariant 0).
"""
from public_corpus.support.synthetic import diag_frame, pack
from diaggrok.parsers.diag_0x1837 import parse_0x1837

# Fabricated per-fix values (not from any real capture or device).
_VERSION = 3
_TIMESTAMP = 123456789012345   # u64 at [1:9] -- fabricated monotonic ms counter
_SUBTYPE = 2                   # u8 at [9] -- field_invariants pins this to 2
_LAT = 40.760                  # f64 at [10:18] -- fabricated decimal degrees
_LON = -111.891                # f64 at [18:26] -- fabricated decimal degrees
_ALT = 1400.5                  # f64 at [26:34] -- fabricated meters
_UNC = 3.2                     # f64 at [34:42] -- fabricated meters
_SESSION_MARKER = 42           # u32 at [42:46] -- fabricated boot-session tag
_COUNTER_A = 100                # u32 at [46:50] -- fabricated monotonic counter
_COUNTER_B = 200                # u32 at [50:54] -- fabricated monotonic counter


def _synthetic_1837() -> bytes:
    """Build a v=3 (61-byte) 0x1837 payload with fully fabricated fields.

    Offsets below are transcribed from the parser's own module docstring
    (v=3 layout section) in diag_0x1837.py, not from any capture:

      data[0]      version = 3                (supplied via diag_frame)
      data[1:9]    u64 timestamp = 123456789012345
      data[9]      u8  subtype = 2             (field_invariants const)
      data[10:18]  f64 latitude_deg = 40.760
      data[18:26]  f64 longitude_deg = -111.891
      data[26:34]  f64 altitude_m = 1400.5
      data[34:42]  f64 position_uncertainty_m = 3.2
      data[42:46]  u32 session_marker = 42
      data[46:50]  u32 counter_a = 100
      data[50:54]  u32 counter_b = 200
      data[54:58]  u32 reserved_zero_1 = 0     (field_invariants const)
      data[58:61]  u24 reserved_zero_2 = 0     (field_invariants const)
    """
    rest = (
        pack('<Q', _TIMESTAMP)
        + pack('<B', _SUBTYPE)
        + pack('<d', _LAT)
        + pack('<d', _LON)
        + pack('<d', _ALT)
        + pack('<d', _UNC)
        + pack('<I', _SESSION_MARKER)
        + pack('<I', _COUNTER_A)
        + pack('<I', _COUNTER_B)
        + pack('<I', 0)   # reserved_zero_1
        + bytes(3)        # reserved_zero_2 (u24, always 0)
    )
    assert len(rest) == 60
    data = diag_frame(0x1837, _VERSION, rest)
    assert len(data) == 61
    return data


def test_1837_decodes_synthetic_v3_frame():
    rec = parse_0x1837(1000, _synthetic_1837())
    assert rec is not None
    assert rec.version == 3
    assert rec.timestamp == _TIMESTAMP
    assert rec.subtype == 2
    assert rec.latitude_deg == _LAT
    assert rec.longitude_deg == _LON
    assert rec.altitude_m == _ALT
    assert rec.position_uncertainty_m == _UNC
    assert rec.session_marker == _SESSION_MARKER
    assert rec.counter_a == _COUNTER_A
    assert rec.counter_b == _COUNTER_B
    assert rec.reserved_zero_1 == 0
    assert rec.reserved_zero_2 == 0
    # seq_num is a v=2-only field; None on v=3 records.
    assert rec.seq_num is None
