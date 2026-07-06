"""Public zero-PII fixture for 0x1856 (BeiDou B1C session-init configuration).

Tier 1 (synthetic-only): the parser retains an undecoded/opaque ``raw`` tail
(the body past the 12-byte header, see public_corpus.risk_tiers.RISK_TIER[
0x1856] == 1), so this fixture is built entirely from fabricated values via
public_corpus.support.synthetic -- no bytes are copied from any capture,
private test, or real DIAG log.

Targets the 'tiny_16' size variant on v=0x04 (SDX62) documented in
diaggrok.parsers.diag_0x1856: version u8, u24 session_tag, u32 reserved_4
(corpus-invariant zero), u32 flags_8.
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x1856 import parse_0x1856

# Fabricated header values (not from any real capture).
_VERSION = 0x04           # data[0] -- field_invariants enum incl. 0x04 (SDX62)
_SESSION_TAG = 0x0ABCDE   # u24 LE at [1:4] -- fabricated boot-session id
_RESERVED_4 = 0           # u32 LE at [4:8] -- corpus-wide invariant zero
_FLAGS_8 = 0x0000002A     # u32 LE at [8:12] -- fabricated


def _synthetic_1856() -> bytes:
    """Build a 16-byte v=0x04 'tiny_16' 0x1856 payload.

    Header transcribed from diag_0x1856.py's "Header structure (12-byte
    minimum)" section:
      [0]      u8  version = 0x04
      [1:4]    u24 session_tag = 0x0ABCDE
      [4:8]    u32 LE reserved_4 = 0
      [8:12]   u32 LE flags_8 = 0x0000002A
    4 bytes of fabricated padding bring the total to 16 bytes -- classifies
    as size_variant 'tiny_16' per _classify_size().
    """
    header = (
        pack('<B', _VERSION)
        + _SESSION_TAG.to_bytes(3, 'little')
        + pack('<I', _RESERVED_4)
        + pack('<I', _FLAGS_8)
    )
    assert len(header) == 12
    padding = bytes([0x11, 0x22, 0x33, 0x44])
    data = header + padding
    assert len(data) == 16
    return data


def test_1856_decodes_synthetic_tiny16_frame():
    rec = parse_0x1856(1000, _synthetic_1856())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.session_tag == _SESSION_TAG
    assert rec.reserved_4 == _RESERVED_4
    assert rec.flags_8 == _FLAGS_8
    assert rec.payload_size == 16
    assert rec.size_variant == 'tiny_16'
    assert rec.constellation == 'BeiDou'
    assert rec.band == 'B1C'
