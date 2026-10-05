"""Public zero-PII fixture for 0x14B0 (GNSS data report, 166B fixed).

Tier 1 (synthetic-only): build_marker is an explicit 3-byte per-chipset
firmware fingerprint (see public_corpus.risk_tiers.RISK_TIER[0x14B0] == 1),
so this frame is built entirely from fabricated values via
public_corpus.support.synthetic -- no bytes are copied from any capture,
private test, or real DIAG log.

Targets the 166-byte fixed layout documented at the top of
diaggrok.parsers.diag_0x14b0: version=0x32 (hard-gated), a per-record
counter + firmware build marker, the 5 tagged f32 parameter slots, and the
6x4-byte trailing tail. f32 values below are exact binary fractions so the
struct pack/unpack round-trip is bit-exact.
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x14b0 import parse_0x14b0

# Fabricated values (not from any real capture). Offsets transcribed from
# the parser's own field-map docstring in diag_0x14b0.py.
_VERSION = 0x32                    # byte 0 -- hard-gated constant (50)
_COUNTER_BLOCK = bytes((1, 2, 3))   # [1:4]
_BUILD_MARKER = bytes((0x1f, 0x6d, 0x09))  # [4:7] -- fabricated chipset fingerprint
_VALUE_A = 0.25                    # f32 at [7:11] -- exact binary fraction
_VALUE_B = 0.5                     # f32 at [11:15] -- exact binary fraction
_LEAD_F32 = 2.0                    # f32 at [111:115] -- exact binary fraction
_PARAM_5 = 2.0                     # f32 at [117:121] -- one of the documented {2,3,5,10,20}
_PARAM_1 = 1.0                     # f32 at [122:126] -- one of the documented set
_PARAM_2 = 1.0                     # f32 at [127:131] -- one of the documented {0.48,1,1.2,3}
_PARAM_3 = 2.5                     # f32 at [132:136] -- within documented range 1.0..5.0
_PARAM_4 = 1.0                     # f32 at [137:141] -- corpus-constant 1.0
_TAIL_SLOT0 = bytes((0x01, 0x02, 0x03, 0x00))  # [141:145] -- low nibble of byte 3 == 0
_TAIL_TRAILER = 60                 # byte [165]

_TOTAL_LEN = 166


def _synthetic_14b0() -> bytes:
    body = (
        pack('<B', _VERSION)
        + _COUNTER_BLOCK
        + _BUILD_MARKER
        + pack('<f', _VALUE_A)
        + pack('<f', _VALUE_B)
        + pack('<B', 0)            # reserved_15
        + bytes((0xff, 0xff, 0xff, 0xff))  # sentinel_16_20
        + bytes(91)                 # zero-padding [20:111]
        + pack('<f', _LEAD_F32)
        + pack('<B', 0x05)          # tag_05
        + pack('<B', 0)             # reserved_116
        + pack('<f', _PARAM_5)
        + pack('<B', 0x01)          # tag_01
        + pack('<f', _PARAM_1)
        + pack('<B', 0x02)          # tag_02
        + pack('<f', _PARAM_2)
        + pack('<B', 0x03)          # tag_03
        + pack('<f', _PARAM_3)
        + pack('<B', 0x04)          # tag_04
        + pack('<f', _PARAM_4)
    )
    assert len(body) == 141
    tail_slots = _TAIL_SLOT0 + bytes(20)  # 5 more all-zero 4-byte slots
    assert len(tail_slots) == 24
    payload = body + tail_slots + pack('<B', _TAIL_TRAILER)
    assert len(payload) == _TOTAL_LEN
    return payload


def test_14b0_decodes_synthetic_frame():
    rec = parse_0x14b0(1000, _synthetic_14b0())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.counter_block == _COUNTER_BLOCK
    assert rec.build_marker == _BUILD_MARKER
    assert rec.value_a == _VALUE_A
    assert rec.value_b == _VALUE_B
    assert rec.lead_f32 == _LEAD_F32
    assert rec.tag_05 == 0x05
    assert rec.param_5 == _PARAM_5
    assert rec.tag_01 == 0x01
    assert rec.param_1 == _PARAM_1
    assert rec.tag_02 == 0x02
    assert rec.param_2 == _PARAM_2
    assert rec.tag_03 == 0x03
    assert rec.param_3 == _PARAM_3
    assert rec.tag_04 == 0x04
    assert rec.param_4 == _PARAM_4
    assert rec.tail_slots[0] == _TAIL_SLOT0
    assert rec.tail_trailer == _TAIL_TRAILER
    assert rec.payload_size == _TOTAL_LEN
