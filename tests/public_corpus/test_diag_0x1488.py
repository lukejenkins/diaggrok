"""Public zero-PII fixture for 0x1488 (GNSS config/measurement, 51B variant).

Tier 1 (synthetic-only): timestamp_u32 is a high-entropy named field with
undecided absolute-vs-relative semantics (see
public_corpus.risk_tiers.RISK_TIER[0x1488] == 1), so this frame is built
entirely from fabricated values via public_corpus.support.synthetic -- no
bytes are copied from any capture, private test, or real DIAG log.

Targets the 51-byte variant (size_class byte[0] == 0x00) layout documented
at the top of diaggrok.parsers.diag_0x1488: a 3-byte shared header followed
by 4 raw u32 fields and 6 f32 measurement fields, every byte named for this
variant. f32 values below are exact binary fractions so the struct
pack/unpack round-trip is bit-exact (no floating-point tolerance needed).
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x1488 import parse_0x1488

# Fabricated values (not from any real capture). Offsets transcribed from
# the parser's own docstring / field comments in diag_0x1488.py.
_SIZE_CLASS = 0x00       # byte 0 -- selects the 51B variant
_FLAGS_1 = 1             # byte 1 -- observed in {1, 3, 16} for 51B
_HEADER_2 = 0             # byte 2 -- observed 0 for 51B
_COUNTER_U32 = 12345      # u32LE at [3:7]
_TIMESTAMP_U32 = 67890    # u32LE at [7:11]
_RAW_0 = 111              # u32LE at [11:15]
_RAW_1 = 222              # u32LE at [15:19]
_F_MEASURE_0 = -0.25      # f32LE at [19:23] -- exact binary fraction
_F_VARIANCE_0 = 0.0009765625  # f32LE at [23:27] (1/1024) -- exact binary fraction
_F_HDOP_LIKE = 1.5        # f32LE at [27:31] -- exact binary fraction
_F_ELEV_LIKE = -2.25      # f32LE at [31:35] -- exact binary fraction
_RAW_FLAGS = 7            # u16LE at [37:39]
_F_BIAS_LIKE = 0.125      # f32LE at [39:43] -- exact binary fraction
_RAW_2 = 999              # u32LE at [43:47]
_F_MISC = 0.0625          # f32LE at [47:51] -- exact binary fraction


def _synthetic_1488_51b() -> bytes:
    """Build the 51-byte 0x1488 variant, every byte named per the
    diag_0x1488.py docstring's '51B variant layout (fully decoded)' table."""
    body = (
        pack('<B', _SIZE_CLASS)
        + pack('<B', _FLAGS_1)
        + pack('<B', _HEADER_2)
        + pack('<I', _COUNTER_U32)
        + pack('<I', _TIMESTAMP_U32)
        + pack('<I', _RAW_0)
        + pack('<I', _RAW_1)
        + pack('<f', _F_MEASURE_0)
        + pack('<f', _F_VARIANCE_0)
        + pack('<f', _F_HDOP_LIKE)
        + pack('<f', _F_ELEV_LIKE)
        + bytes(2)  # reserved_a [35:37] -- constant zero
        + pack('<H', _RAW_FLAGS)
        + pack('<f', _F_BIAS_LIKE)
        + pack('<I', _RAW_2)
        + pack('<f', _F_MISC)
    )
    assert len(body) == 51
    return body


def test_1488_decodes_synthetic_51b_frame():
    rec = parse_0x1488(1000, _synthetic_1488_51b())
    assert rec is not None
    assert rec.size_class == 0x00
    assert rec.version == 0x00  # back-compat alias for size_class
    assert rec.flags_1 == _FLAGS_1
    assert rec.header_2 == _HEADER_2
    assert rec.counter_u32 == _COUNTER_U32
    assert rec.timestamp_u32 == _TIMESTAMP_U32
    assert rec.raw_0 == _RAW_0
    assert rec.raw_1 == _RAW_1
    assert rec.f_measure_0 == _F_MEASURE_0
    assert rec.f_variance_0 == _F_VARIANCE_0
    assert rec.f_hdop_like == _F_HDOP_LIKE
    assert rec.f_elev_like == _F_ELEV_LIKE
    assert rec.reserved_a == b'\x00\x00'
    assert rec.raw_flags_37_39 == _RAW_FLAGS
    assert rec.f_bias_like == _F_BIAS_LIKE
    assert rec.raw_2 == _RAW_2
    assert rec.f_misc == _F_MISC
    assert rec.payload_size == 51
