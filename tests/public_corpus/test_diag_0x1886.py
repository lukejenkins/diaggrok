"""Public zero-PII fixture for 0x1886 (Galileo E1/L1 measurement report).

Tier 1 (synthetic-only): the 811-byte "full" format carries per-SV
gps_tow_tick (explicitly named GPS time-of-week) and PRN identity (see
public_corpus.risk_tiers.RISK_TIER[0x1886] == 1), so this fixture is built
entirely from fabricated values via public_corpus.support.synthetic -- no
bytes are copied from any capture, private test, or real DIAG log.

Targets the simpler legacy 30-byte "indoor/degraded" format documented in
diaggrok.parsers.diag_0x1886 (no SV slots -- version/header_b1/header_b2 +
5 legacy scalar fields), which avoids needing per-SV PRN/GPS-time data
entirely while still exercising the real parser code path.
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x1886 import parse_0x1886

# Fabricated field values (not from any real capture).
_VERSION = 0            # data[0] -- field_invariants enum {0}
_HEADER_B1 = 6           # data[1] -- fabricated (chipset discriminator, not invariant)
_HEADER_B2 = 5           # data[2] -- fabricated (chipset discriminator, not invariant)
_FIELD_A = 700           # u16 LE at [3:5] -- fabricated
_SYSTEM_TIME = 1234      # u16 LE at [5:7] -- fabricated
_FLOAT_1 = 1.5           # f32 at [12:16] -- fabricated
_FLOAT_2 = 2.5           # f32 at [17:21] -- fabricated
_FLOAT_3 = 3.5           # f32 at [21:25] -- fabricated


def _synthetic_1886_legacy30() -> bytes:
    """Build the 30-byte legacy 0x1886 payload (no SV slots).

    Offsets transcribed from diag_0x1886.py's "30-byte 'indoor/degraded'
    format" section and the parser body's legacy-decode branch:
      [0]      u8   version = 0
      [1]      u8   header_b1 = 6
      [2]      u8   header_b2 = 5
      [3:5]    u16 LE field_a = 700
      [5:7]    u16 LE system_time = 1234
      [7:12]   5B   unused (not read by the parser)
      [12:16]  f32  float_legacy_1 = 1.5
      [16]     1B   unused (not read by the parser)
      [17:21]  f32  float_legacy_2 = 2.5
      [21:25]  f32  float_legacy_3 = 3.5
      [25:30]  5B   unused (not read by the parser; parser_format='legacy_30'
               requires total payload size <= 64 bytes)
    """
    data = (
        pack('<B', _VERSION)
        + pack('<B', _HEADER_B1)
        + pack('<B', _HEADER_B2)
        + pack('<H', _FIELD_A)
        + pack('<H', _SYSTEM_TIME)
        + bytes(5)
        + pack('<f', _FLOAT_1)
        + bytes(1)
        + pack('<f', _FLOAT_2)
        + pack('<f', _FLOAT_3)
        + bytes(5)
    )
    assert len(data) == 30
    return data


def test_1886_decodes_synthetic_legacy30_frame():
    rec = parse_0x1886(1000, _synthetic_1886_legacy30())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.header_b1 == _HEADER_B1
    assert rec.header_b2 == _HEADER_B2
    assert rec.payload_size == 30
    assert rec.field_a_u16 == _FIELD_A
    assert rec.system_time_u16 == _SYSTEM_TIME
    assert rec.float_legacy_1 == _FLOAT_1
    assert rec.float_legacy_2 == _FLOAT_2
    assert rec.float_legacy_3 == _FLOAT_3
    assert rec.parser_format == 'legacy_30'
    assert rec.svs == []
