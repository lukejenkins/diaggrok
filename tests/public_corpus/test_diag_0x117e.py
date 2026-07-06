"""Public zero-PII fixture for 0x117E (GPS multi-peaks verbose searcher).

Tier 1 (synthetic-only): the parser's own docstring flags the SV/Doppler
semantics as unresolved (doubt), so per public_corpus.risk_tiers.RISK_TIER
this frame is built entirely from fabricated values via
public_corpus.support.synthetic -- no bytes copied from any capture.

Targets the COMPACT record shape (58 bytes) documented in
diaggrok.parsers.diag_0x117e: byte[0] is NOT a version (it's the low byte
of the u16 record_seq counter at [0:2]) -- this code is version_less. The
compact-class drift guard requires reserved_2_6==0 @[2:6] and tag==0x0066
@[8:10] for the record to decode at all.
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x117e import parse_0x117e

# Fabricated compact-record values (not from any real capture).
_RECORD_SEQ = 1234       # u16 @ [0:2]
_LEN_MARKER = 0x32       # u8 @ [6] -- must equal payload_size - 8 == 58 - 8
_TIMESTAMP = 987654      # u32 @ [36:40]
_MEASUREMENT_RAW = 555555  # u32 @ [48:52]
_FIELD_52 = 7            # u32 @ [52:56]


def _synthetic_117e() -> bytes:
    """Build a 58-byte compact 0x117E payload with fabricated values.

    Offsets transcribed from the parser's own docstring/comments in
    diag_0x117e.py, not from any capture:

      [0:2]   u16  record_seq      = 1234 (fabricated fast counter)
      [2:6]   u32  reserved_2_6    = 0x00000000 (compact-class INVARIANT --
                                     the parser rejects any non-zero value)
      [6]     u8   len_marker      = 0x32 == payload_size(58) - 8
      [7]     u8   = 0x00
      [8:10]  u16  tag             = 0x0066 (compact-class INVARIANT --
                                     the parser rejects any other value)
      [10:36] 26 zero-filled bytes (unused by the compact decode path)
      [36:40] u32  timestamp       = 987654 (fabricated)
      [40:48] 8 zero-filled bytes (unused by the compact decode path)
      [48:52] u32  measurement_raw = 555555 (fabricated)
      [52:56] u32  field_52        = 7 (fabricated)
      [56:58] 2 trailing zero-filled bytes (payload_size 58 is 2B past the
              56B minimum the parser reads -- still a valid compact size
              per the docstring's 55/58/62 set)
    """
    body = (
        pack('<H', _RECORD_SEQ)
        + pack('<I', 0)                 # reserved_2_6 invariant
        + pack('<B', _LEN_MARKER)
        + pack('<B', 0)                 # byte[7]
        + pack('<H', 0x0066)            # tag invariant
        + bytes(26)                     # [10:36] gap
        + pack('<I', _TIMESTAMP)
        + bytes(8)                      # [40:48] gap
        + pack('<I', _MEASUREMENT_RAW)
        + pack('<I', _FIELD_52)
        + bytes(2)                      # [56:58] trailing pad
    )
    assert len(body) == 58
    return body


def test_117e_decodes_synthetic_compact_frame():
    rec = parse_0x117e(1000, _synthetic_117e())
    assert rec is not None
    assert rec.payload_size == 58
    assert rec.is_compact is True
    assert rec.record_seq == 1234
    assert rec.reserved_2_6 == 0
    assert rec.len_marker == 0x32
    assert rec.tag == 0x0066
    assert rec.timestamp == 987654
    assert rec.measurement_raw == 555555
    assert rec.field_52 == 7
