"""Public zero-PII fixture for 0x188B (GNSS reference-position cache).

Tier 1 (synthetic-only): decoded fields include ref_lat_rad/ref_lon_rad and
a decimal-degree lat/lon mirror (see public_corpus.risk_tiers.RISK_TIER[
0x188B] == 1), so this fixture is built entirely from fabricated values via
public_corpus.support.synthetic -- no bytes are copied from any capture,
private test, or real DIAG log. The lat/lon values below are made up for
this fixture and do not correspond to any real receiver location.

Targets the v2/287B (SDX55) variant documented in
diaggrok.parsers.diag_0x188b: version=0x0002 (u16 LE), ref lat/lon in both
radians and decimal degrees, altitude/DOP-like scalars, a 3-entry position
history buffer, and a 12-byte altitude-echo block repeated 3x (asserted via
the parser's own ``altitude_echo_invariant_ok`` check).
"""
import struct

from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x188b import parse_0x188b


def _f32(value: float) -> float:
    """Round a Python float to its nearest f32 value (matches on-wire round-trip)."""
    return struct.unpack('<f', struct.pack('<f', value))[0]

# Fabricated field values (not from any real capture or location).
_VERSION = 2              # u16 LE at [0:2] -- field_invariants enum {0, 2}
_GEN_MARKER = 0x87        # data[2] -- fabricated
_FLAG = 0x00              # data[3] -- fabricated
_REF_LAT_RAD = 0.5        # f32 at [4:8] -- fabricated
_REF_LON_RAD = -1.2       # f32 at [8:12] -- fabricated
_ALTITUDE_REF_M = 1400.0  # f32 at [12:16] -- fabricated
_MEASUREMENT_16 = 20055.0  # f32 at [16:20] -- fabricated
_MEASUREMENT_20 = 5250.0   # f32 at [20:24] -- fabricated
_REF_LAT_DEG = 40.0        # f32 at [24:28] -- fabricated
_REF_LON_DEG = -109.0      # f32 at [28:32] -- fabricated
_ALTITUDE_FIX_M = 1402.5   # f32 at [32:36] -- fabricated
_DOP_H = 8.5               # f32 at [36:40] -- fabricated
_DOP_V = 5.5               # f32 at [40:44] -- fabricated

# The three position-history snapshots at [166], [226], [246] each carry
# (lat_rad, lon_rad, altitude_m, scalar_a, scalar_b). Per the parser's
# altitude-echo check, bytes [174:186] == [234:246] == [254:266] -- i.e.
# the (altitude_m, scalar_a, scalar_b) tail of every snapshot must be
# byte-identical. All three snapshots below share the same fabricated
# altitude/scalar tail (matching altitude_ref_m/measurement_16/
# measurement_20) so ``altitude_echo_invariant_ok`` comes back True.
_HIST = [
    (0.71, -1.90),
    (0.72, -1.91),
    (0.73, -1.92),
]


def _snapshot_bytes(lat_rad: float, lon_rad: float) -> bytes:
    return (
        pack('<f', lat_rad)
        + pack('<f', lon_rad)
        + pack('<f', _ALTITUDE_REF_M)
        + pack('<f', _MEASUREMENT_16)
        + pack('<f', _MEASUREMENT_20)
    )


def _synthetic_188b_v2() -> bytes:
    """Build the 287-byte v2/287B (SDX55) 0x188B payload.

    Offsets transcribed from diag_0x188b.py's "v2/287B field map":
      [0:2]    u16 LE version = 0x0002
      [2]      u8  gen_marker = 0x87
      [3]      u8  flag = 0x00
      [4:8]    f32 ref_lat_rad = 0.5
      [8:12]   f32 ref_lon_rad = -1.2
      [12:16]  f32 altitude_ref_m = 1400.0
      [16:20]  f32 measurement_16 = 20055.0
      [20:24]  f32 measurement_20 = 5250.0
      [24:28]  f32 ref_lat_deg = 40.0
      [28:32]  f32 ref_lon_deg = -109.0
      [32:36]  f32 altitude_fix_m = 1402.5
      [36:40]  f32 dop_h_like = 8.5
      [40:44]  f32 dop_v_like = 5.5
      [44:166] 122B unused (part of body_raw; not asserted -- fabricated
               fill pattern)
      [166:186] position_history[0] snapshot (20B)
      [186:226] 40B unused (part of body_raw; fabricated fill pattern)
      [226:246] position_history[1] snapshot (20B)
      [246:266] position_history[2] snapshot (20B)
      [266:287] 21B unused (part of body_raw; fabricated fill pattern)
    """
    buf = bytearray(bytes((i % 251) for i in range(287)))
    buf[0:2] = pack('<H', _VERSION)
    buf[2] = _GEN_MARKER
    buf[3] = _FLAG
    buf[4:8] = pack('<f', _REF_LAT_RAD)
    buf[8:12] = pack('<f', _REF_LON_RAD)
    buf[12:16] = pack('<f', _ALTITUDE_REF_M)
    buf[16:20] = pack('<f', _MEASUREMENT_16)
    buf[20:24] = pack('<f', _MEASUREMENT_20)
    buf[24:28] = pack('<f', _REF_LAT_DEG)
    buf[28:32] = pack('<f', _REF_LON_DEG)
    buf[32:36] = pack('<f', _ALTITUDE_FIX_M)
    buf[36:40] = pack('<f', _DOP_H)
    buf[40:44] = pack('<f', _DOP_V)
    buf[166:186] = _snapshot_bytes(*_HIST[0])
    buf[226:246] = _snapshot_bytes(*_HIST[1])
    buf[246:266] = _snapshot_bytes(*_HIST[2])
    data = bytes(buf)
    assert len(data) == 287
    return data


def test_188b_decodes_synthetic_v2_287b_frame():
    rec = parse_0x188b(1000, _synthetic_188b_v2())
    assert rec is not None
    assert rec.variant == 'v2_287B_sdx55'
    assert rec.version == _VERSION
    assert rec.gen_marker == _GEN_MARKER
    assert rec.flag == _FLAG
    assert rec.ref_lat_rad == _REF_LAT_RAD
    assert rec.ref_lon_rad == _f32(_REF_LON_RAD)
    assert rec.ref_lat_deg == _REF_LAT_DEG
    assert rec.ref_lon_deg == _REF_LON_DEG
    assert rec.altitude_ref_m == _ALTITUDE_REF_M
    assert rec.altitude_fix_m == _ALTITUDE_FIX_M
    assert rec.dop_h_like == _DOP_H
    assert rec.dop_v_like == _DOP_V
    assert rec.measurement_16 == _MEASUREMENT_16
    assert rec.measurement_20 == _MEASUREMENT_20
    assert rec.payload_size == 287
    assert rec.qcom_ref_lat_rad is None
    assert rec.qcom_ref_lon_rad is None
    assert rec.trailer is None
    assert rec.position_history is not None
    assert len(rec.position_history) == 3
    for snap, (lat, lon) in zip(rec.position_history, _HIST):
        assert snap.lat_rad == _f32(lat)
        assert snap.lon_rad == _f32(lon)
        assert snap.altitude_m == _ALTITUDE_REF_M
    # The three altitude-echo copies were built byte-identical, so the
    # parser's own cross-check must confirm the invariant.
    assert rec.altitude_echo_invariant_ok is True
    assert rec.altitude_ref_echo_m == _ALTITUDE_REF_M
