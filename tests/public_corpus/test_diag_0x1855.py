"""Public zero-PII fixture for 0x1855 (GPS L1C session-init configuration).

Tier 1 (synthetic-only): the parser retains an undecoded/opaque ``raw`` tail
(the body past the 16-byte header, see public_corpus.risk_tiers.RISK_TIER[
0x1855] == 1), so this fixture is built entirely from fabricated values via
public_corpus.support.synthetic -- no bytes are copied from any capture,
private test, or real DIAG log.

Targets the minimal 16-byte 'tiny_16' size variant on v=0x04 (SDX62)
documented in diaggrok.parsers.diag_0x1855: version u8, u24 session_tag,
u32 reserved_4, u32 config_word, u32 descriptor. The docstring's verified
self-consistency invariant ``descriptor & 0xFFFF == payload_size - 16``
holds here (payload_size=16 -> low 16 bits of descriptor = 0).
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x1855 import parse_0x1855

# Fabricated header values (not from any real capture).
_VERSION = 0x04           # data[0] -- field_invariants enum incl. 0x04 (SDX62)
_SESSION_TAG = 0x0ABCDE   # u24 LE at [1:4] -- fabricated boot-session id
_RESERVED_4 = 0           # u32 LE at [4:8] -- 0x00000000 in 98.2% of corpus
_CONFIG_WORD = 0x00112233  # u32 LE at [8:12] -- fabricated
_DESCRIPTOR = 0           # u32 LE at [12:16] -- low 16 bits must equal
                          # payload_size - 16 = 16 - 16 = 0 (parser-doc
                          # self-consistency invariant)


def _synthetic_1855() -> bytes:
    """Build a 16-byte v=0x04 'tiny_16' 0x1855 payload.

    Header transcribed from diag_0x1855.py's "Known header structure"
    section:
      [0]      u8  version = 0x04
      [1:4]    u24 session_tag = 0x0ABCDE
      [4:8]    u32 LE reserved_4 = 0
      [8:12]   u32 LE config_word = 0x00112233
      [12:16]  u32 LE descriptor = 0
    Total payload is exactly 16 bytes -- classifies as size_variant
    'tiny_16' per _classify_size().
    """
    data = (
        pack('<B', _VERSION)
        + _SESSION_TAG.to_bytes(3, 'little')
        + pack('<I', _RESERVED_4)
        + pack('<I', _CONFIG_WORD)
        + pack('<I', _DESCRIPTOR)
    )
    assert len(data) == 16
    return data


def test_1855_decodes_synthetic_tiny16_frame():
    rec = parse_0x1855(1000, _synthetic_1855())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.session_tag == _SESSION_TAG
    assert rec.reserved_4 == _RESERVED_4
    assert rec.config_word == _CONFIG_WORD
    assert rec.descriptor == _DESCRIPTOR
    assert rec.payload_size == 16
    assert rec.size_variant == 'tiny_16'
    assert rec.constellation == 'GPS'
    assert rec.band == 'L1C'
