"""Public zero-PII fixture for 0x1885 (GNSS measurement/status, sz=47 tail).

Tier 1 (synthetic-only): the parser exposes an opaque per-size ``extension``
region (see public_corpus.risk_tiers.RISK_TIER[0x1885] == 1), so this
fixture is built entirely from fabricated values via
public_corpus.support.synthetic -- no bytes are copied from any capture,
private test, or real DIAG log.

Targets the sz=47 structured-tail variant documented in
diaggrok.parsers.diag_0x1885: a 10-byte shared header (version, reserved_1,
counter_like, aux_4, reserved_a) plus the sz=47-specific tail fields
(sentinel_ref_ms, subtype_tag, prev_counter_ref / counter_echo_ok).
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x1885 import parse_0x1885

# Fabricated header values (not from any real capture).
_VERSION = 0x01         # data[0] -- field_invariants const
_RESERVED_1 = 0x00      # data[1] -- field_invariants const
_COUNTER_LIKE = 500     # u16 LE at [2:4] -- fabricated
_AUX_4 = 3              # data[4] -- fabricated small enum
_RESERVED_A_0 = 0       # data[5] -- first byte of the 5B all-zero reserved_a
_VARIANT_TAG = 0x01020000  # u32 LE at [10:14] -- fabricated (sz=47 dispatch
                           # is determined by total payload length, not this
                           # tag's exact bit pattern)


def _synthetic_1885_sz47() -> bytes:
    """Build a 47-byte sz=47 0x1885 payload with a structured tail.

    Offsets transcribed from diag_0x1885.py's module docstring ("Shared
    10-byte header" + "sz=47 tail"):
      [0]      u8  version = 0x01
      [1]      u8  reserved_1 = 0x00
      [2:4]    u16 LE counter_like = 500
      [4]      u8  aux_4 = 3
      [5:10]   5B  reserved_a = all zero
      [10:14]  u32 LE variant_tag = 0x01020000 (fabricated)
      [14:31]  17B all-zero mid-reserved
      [31:35]  u32 LE sentinel_ref_ms = 0xFFFFFFFF (invalid-reference sentinel)
      [35:39]  u32 LE subtype_tag = 2
      [39:43]  u32 LE prev_counter_ref -- set equal to header bytes [2:6] so
               sz47_counter_echo_ok comes back True (a legitimate, if rare,
               corpus outcome per the docstring's "1/3 records match" note)
      [43:47]  4B  trailing zero
    """
    header = (
        pack('<B', _VERSION)
        + pack('<B', _RESERVED_1)
        + pack('<H', _COUNTER_LIKE)
        + pack('<B', _AUX_4)
        + pack('<B', _RESERVED_A_0)
        + bytes(4)  # remaining 4 bytes of the 5B reserved_a region
    )
    assert len(header) == 10
    variant_tag = pack('<I', _VARIANT_TAG)
    mid_reserved = bytes(17)
    sentinel_ref_ms = pack('<I', 0xFFFFFFFF)
    subtype_tag = pack('<I', 2)
    # header[2:6] == counter_like(2B) + aux_4(1B) + reserved_a[0](1B)
    prev_counter_ref_bytes = header[2:6]
    trailing_zero = bytes(4)
    data = (
        header
        + variant_tag
        + mid_reserved
        + sentinel_ref_ms
        + subtype_tag
        + prev_counter_ref_bytes
        + trailing_zero
    )
    assert len(data) == 47
    return data


def test_1885_decodes_synthetic_sz47_frame():
    rec = parse_0x1885(1000, _synthetic_1885_sz47())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.reserved_1 == _RESERVED_1
    assert rec.counter_like == _COUNTER_LIKE
    assert rec.aux_4 == _AUX_4
    assert rec.reserved_a == bytes(5)
    assert rec.size_family == 'sz47'
    assert rec.payload_size == 47
    assert rec.sz47_sentinel_ref_ms == 0xFFFFFFFF
    assert rec.sz47_subtype_tag == 2
    # prev_counter_ref = u32 LE of header bytes [2:6]:
    # counter_like(500=0x01F4 LE: f4 01) + aux_4(3) + reserved_a[0](0)
    # -> bytes f4 01 03 00 -> 0x000301F4 = 197108
    assert rec.sz47_prev_counter_ref == 197108
    assert rec.sz47_counter_echo_ok is True
