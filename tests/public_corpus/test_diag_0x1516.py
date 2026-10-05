"""Public zero-PII fixture for 0x1516 (GNSS engine parameter/config report).

Tier-1 (public_corpus.risk_tiers.RISK_TIER[0x1516] == 1): every frame is
built from fabricated values via struct packing -- no bytes are copied from
any capture, private test, or real DIAG log. The v=0x06 config table decoded
by diaggrok.parsers.diag_0x1516 is a firmware CONSTANT (identical fleet-wide,
carries no user data), but the byte pattern is still fabricated here so the
public tree stays capture-free; the real-corpus values are documented in the
parser module docstring, not asserted from a captured frame.

Covers the decode paths in diaggrok.parsers.diag_0x1516:
  * v=0x03 / v=0x06 shorter than the fixed record (295 B / 72 B) -> None
    (truncated).
  * v=0x03, longer than 295 B -> header + opaque body_raw tail only.
  * v=0x03, 295 B, registry version 6 -> the SDP sensor-calibration registry
    + SDP status (``sdp_registry`` / ``sdp_status``; F3-grounded); an
    unknown registry version is surfaced, not decoded.
  * v=0x06 -> the 72 B ME parameter table exposed as observed float32/u32
    fields in ``v06_config`` (F3-grounded).
"""
import struct

from public_corpus.support.synthetic import diag_frame, pack
from diaggrok.parsers.diag_0x1516 import parse_0x1516

# Fabricated values (not from any real capture).
_SUB_TYPE_V03 = 0x2A    # arbitrary fabricated sub-type for the v0x03 path
_BODY_LEN = 292         # bytes 4.. -> opaque tail; 292 zero-fill -> 296B total


def _synthetic_1516_v03() -> bytes:
    """A v0x03 payload one byte LONGER than the 295 B record, which takes the
    header-only path (the SDP decode is gated on exactly 295 B). A SHORTER
    v0x03 payload is truncated and returns None."""
    body = pack('<B', _SUB_TYPE_V03) + bytes(2) + bytes(_BODY_LEN)
    frame = diag_frame(0x1516, 0x03, body)
    assert len(frame) == 296
    return frame


def _synthetic_1516_v06() -> bytes:
    """Build a fabricated 72 B v0x06 frame with KNOWN config values at the
    grounded offsets, to exercise the ``v06_config`` decode."""
    data = bytearray(72)
    data[0] = 0x06        # version
    data[1] = 0x00        # sub_type (v0x06 form)
    data[13] = 0x01       # const flag (fabricated to match corpus shape)
    struct.pack_into('<f', data, 14, 5.0)
    struct.pack_into('<f', data, 18, 1.5)
    struct.pack_into('<f', data, 22, 0.8)
    struct.pack_into('<f', data, 26, 0.15)
    struct.pack_into('<f', data, 30, 0.0)
    struct.pack_into('<f', data, 34, 6.0)
    data[38:42] = bytes([0x92, 0x00, 0x02, 0x01])   # undecoded raw region
    struct.pack_into('<f', data, 42, 100.0)
    struct.pack_into('<f', data, 46, 0.01)
    struct.pack_into('<I', data, 50, 30)
    struct.pack_into('<I', data, 54, 45)
    struct.pack_into('<I', data, 58, 60)
    data[62:64] = bytes([0x02, 0x0a])               # undecoded raw region
    data[66] = 0x42       # fleet-varying byte
    data[68] = 0x14       # fleet-varying byte
    # diag_frame places version at byte 0 and body at byte 1..; feed body[1:].
    frame = diag_frame(0x1516, 0x06, bytes(data[1:]))
    assert len(frame) == 72
    return frame


def test_1516_v03_header_only():
    rec = parse_0x1516(1000, _synthetic_1516_v03())
    assert rec is not None
    assert rec.version == 0x03
    assert rec.sub_type == _SUB_TYPE_V03
    assert rec.payload_size == 296
    assert rec.v06_config is None
    assert 'v06_config' not in rec.to_dict()


def test_1516_v06_config_table():
    rec = parse_0x1516(1000, _synthetic_1516_v06())
    assert rec is not None
    assert rec.version == 0x06
    assert rec.sub_type == 0x00
    assert rec.payload_size == 72
    cfg = rec.v06_config
    assert cfg is not None
    assert cfg['f32_14'] == 5.0
    assert cfg['f32_18'] == 1.5
    assert abs(cfg['f32_22'] - 0.8) < 1e-6
    assert abs(cfg['f32_26'] - 0.15) < 1e-6
    assert cfg['f32_30'] == 0.0
    assert cfg['f32_34'] == 6.0
    assert cfg['f32_42'] == 100.0
    assert abs(cfg['f32_46'] - 0.01) < 1e-6
    assert cfg['u32_50'] == 30
    assert cfg['u32_54'] == 45
    assert cfg['u32_58'] == 60
    assert cfg['raw_38_41'] == '92000201'
    assert cfg['raw_62_63'] == '020a'
    assert cfg['var_66'] == 0x42
    assert cfg['var_68'] == 0x14
    # config surfaces through to_dict()
    assert rec.to_dict()['v06_config']['u32_58'] == 60


def _synthetic_1516_v03_sdp(registry_version: int = 6) -> bytes:
    """A fabricated 295 B v0x03 SDP-registry frame (values invented, laid out
    at the grounded offsets) to exercise the ``sdp_registry`` decode."""
    data = bytearray(295)
    data[0] = 0x03                      # version
    data[1] = 0x01                      # sub_type (v0x03 form)
    data[5] = 0x01                      # pair_index
    struct.pack_into('<I', data, 6, registry_version)
    struct.pack_into('<H', data, 10, 0x0101)
    data[12] = 0x01                     # time_known
    data[13] = 0xFF
    struct.pack_into('<Q', data, 14, 7 * 604_800_000 + 12_345)  # fabricated
    struct.pack_into('<3f', data, 42, 2.0, 2.0, 2.0)
    struct.pack_into('<3f', data, 98, 3.0, 3.0, 3.0)
    struct.pack_into('<f', data, 134, 0.5)
    struct.pack_into('<I', data, 154, 7)
    struct.pack_into('<f', data, 269, 12.5)
    data[262] = 0x02
    frame = diag_frame(0x1516, 0x03, bytes(data[1:]))
    assert len(frame) == 295
    return frame


def test_1516_v03_sdp_registry_decode():
    rec = parse_0x1516(1000, _synthetic_1516_v03_sdp())
    assert rec is not None
    assert rec.pair_index == 1
    assert rec.sdp_registry_version == 6
    reg = rec.sdp_registry
    assert reg['author'] == 257
    assert reg['time_known'] == 1
    assert reg['time_gps_week'] == 7
    assert reg['time_gps_ms_in_week'] == 12_345
    assert reg['accel_scale'] == [2.0, 2.0, 2.0]
    assert reg['gyro_scale'] == [3.0, 3.0, 3.0]
    assert reg['gyro_noise'] == 0.5
    assert reg['gvection_gval'] == 7
    assert rec.sdp_status['hepe_m'] == 12.5
    assert rec.sdp_status['sdp_state_candidate'] == 2
    d = rec.to_dict()
    assert d['sdp_registry']['time_gps_week'] == 7
    assert d['sdp_status']['hepe_m'] == 12.5


def test_1516_v03_unknown_registry_version_not_decoded():
    rec = parse_0x1516(1000, _synthetic_1516_v03_sdp(registry_version=9))
    assert rec is not None
    assert rec.sdp_registry_version == 9
    assert rec.sdp_registry is None
    assert 'sdp_registry' not in rec.to_dict()


def test_1516_v06_short_frame_returns_none():
    """A v0x06 frame shorter than 72 B is truncated and
    fails LOUDLY (None -> registry WARN) instead of a header-only record."""
    short = diag_frame(0x1516, 0x06, bytes(10))
    assert parse_0x1516(1000, short) is None


def test_1516_truncated_by_one_byte_returns_none_5171():
    """Each fixed record minus its last byte -> None; never raises."""
    for full in (_synthetic_1516_v06(), _synthetic_1516_v03_sdp()):
        assert parse_0x1516(1000, full) is not None
        assert parse_0x1516(1000, full[:-1]) is None
        for n in range(len(full)):
            parse_0x1516(1000, full[:n])  # never raises
