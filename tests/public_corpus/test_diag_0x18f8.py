"""Public zero-PII fixture for 0x18F8 (GNSS misc status, EM7511 edge-case).

Tier 0 (real-snippet-eligible per public_corpus.risk_tiers.RISK_TIER[0x18F8]
== 0 -- "all sentinel/const fields, version/type_b/sentinel_a-d"). This
fixture is nonetheless built entirely from fabricated values via
public_corpus.support.synthetic for corpus consistency -- no bytes are
copied from any capture, private test, or real DIAG log.

Targets the fully-decoded 20-byte fixed layout documented in
diaggrok.parsers.diag_0x18f8: version (const 0x01, layer-1 gated), plus 8
further named constant/sentinel fields and a single varying ``measurement``
field.
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x18f8 import parse_0x18f8

# Fabricated field values (not from any real capture).
_VERSION = 0x01           # data[0] -- field_invariants const, layer-1 gated
_TYPE_B = 0x02            # data[1] -- field_invariants const
_SENTINEL_A = 0xFFFFFFFF  # u32 LE at [2:6] -- field_invariants const
_MEASUREMENT = 131        # u16 LE at [6:8] -- fabricated (valid range 121-168)
_SENTINEL_B = 0xFFFF      # u16 LE at [8:10] -- field_invariants const
_RESERVED_0 = 0x0000      # u16 LE at [10:12] -- field_invariants const
_SENTINEL_C = 0xFFFE      # u16 LE at [12:14] -- field_invariants const
_RESERVED_1 = 0x00        # data[14] -- field_invariants const
_CONST_7D = 0x7D          # data[15] -- field_invariants const
_SENTINEL_D = 0xFFFFFFFF  # u32 LE at [16:20] -- field_invariants const


def _synthetic_18f8() -> bytes:
    """Build the 20-byte fully-decoded 0x18F8 payload.

    Offsets transcribed from diag_0x18f8.py's "Layout (20 B fixed, version
    0x01)" section:
      [0]     u8  version = 0x01
      [1]     u8  type_b = 0x02
      [2:6]   u32 LE sentinel_a = 0xFFFFFFFF
      [6:8]   u16 LE measurement = 131
      [8:10]  u16 LE sentinel_b = 0xFFFF
      [10:12] u16 LE reserved_0 = 0x0000
      [12:14] u16 LE sentinel_c = 0xFFFE
      [14]    u8  reserved_1 = 0x00
      [15]    u8  const_7d = 0x7D
      [16:20] u32 LE sentinel_d = 0xFFFFFFFF
    """
    data = (
        pack('<B', _VERSION)
        + pack('<B', _TYPE_B)
        + pack('<I', _SENTINEL_A)
        + pack('<H', _MEASUREMENT)
        + pack('<H', _SENTINEL_B)
        + pack('<H', _RESERVED_0)
        + pack('<H', _SENTINEL_C)
        + pack('<B', _RESERVED_1)
        + pack('<B', _CONST_7D)
        + pack('<I', _SENTINEL_D)
    )
    assert len(data) == 20
    return data


def test_18f8_decodes_synthetic_frame():
    rec = parse_0x18f8(1000, _synthetic_18f8())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.type_b == _TYPE_B
    assert rec.sentinel_a == _SENTINEL_A
    assert rec.measurement == _MEASUREMENT
    assert rec.measurement_valid is True
    assert rec.sentinel_b == _SENTINEL_B
    assert rec.reserved_0 == _RESERVED_0
    assert rec.sentinel_c == _SENTINEL_C
    assert rec.reserved_1 == _RESERVED_1
    assert rec.const_7d == _CONST_7D
    assert rec.sentinel_d == _SENTINEL_D
