"""Public zero-PII fixture for 0x1589 (structural-header stub, legacy GnssStatus1589).

Tier-1 (public_corpus.risk_tiers.RISK_TIER[0x1589] == 1): chunk_3_10 docstring
candidate "u56 ts" is a doubt-flagged possible absolute-time field, so this
frame is built entirely from fabricated values via
public_corpus.support.synthetic -- no bytes are copied from any capture,
private test, or real DIAG log.

Targets the fixed 17-byte decode in diaggrok.parsers.diag_0x1589: version @0
(gated to 0x00), vendor_tag @1, record_type @2, chunk_3_10 @3:10, marker_10
@10 (gated to 0x00), marker_11 @11 (gated to 0x01), marker_12 @12 (gated to
0x00), triplet @13:16, reserved_16 @16 (gated to 0x00).
"""
from public_corpus.support.synthetic import diag_frame, pack
from diaggrok.parsers.diag_0x1589 import parse_0x1589

# Fabricated values (not from any real capture).
_VENDOR_TAG = 0x6D                       # byte 1 -- variant-B vendor tag
_RECORD_TYPE = 0x09                      # byte 2 -- variant-B record type
_CHUNK_3_10 = bytes([1, 2, 3, 4, 5, 6, 7])  # bytes 3..9 (7-byte varying chunk)
_TRIPLET = (0x03, 0x02, 0x05)             # bytes 13..15 (GNSS-shaped 3-tuple)


def _synthetic_1589() -> bytes:
    """Build a fixed 17-byte 0x1589 payload with fabricated variant-B values.

      data[0]     version = 0x00          (supplied via diag_frame)
      data[1]     vendor_tag = 0x6D        -> variant "B" (vendor_tag != 0x00)
      data[2]     record_type = 0x09
      data[3:10]  chunk_3_10 = 01 02 03 04 05 06 07
      data[10]    marker_10 = 0x00
      data[11]    marker_11 = 0x01
      data[12]    marker_12 = 0x00
      data[13:16] triplet = (0x03, 0x02, 0x05)
      data[16]    reserved_16 = 0x00
    """
    body = (
        pack('<B', _VENDOR_TAG)
        + pack('<B', _RECORD_TYPE)
        + _CHUNK_3_10
        + pack('<B', 0x00)   # marker_10
        + pack('<B', 0x01)   # marker_11
        + pack('<B', 0x00)   # marker_12
        + bytes(_TRIPLET)
        + pack('<B', 0x00)   # reserved_16
    )
    frame = diag_frame(0x1589, 0x00, body)
    assert len(frame) == 17
    return frame


def test_1589_decodes_synthetic_frame():
    rec = parse_0x1589(1000, _synthetic_1589())
    assert rec is not None
    assert rec.version == 0x00
    assert rec.vendor_tag == _VENDOR_TAG
    assert rec.record_type == _RECORD_TYPE
    assert rec.variant == "B"
    assert rec.chunk_3_10 == _CHUNK_3_10
    assert rec.marker_10 == 0x00
    assert rec.marker_11 == 0x01
    assert rec.marker_12 == 0x00
    assert rec.triplet == _TRIPLET
    assert rec.reserved_16 == 0x00
    assert rec.payload_size == 17
