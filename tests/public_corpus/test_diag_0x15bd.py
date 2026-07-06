"""Public zero-PII fixture for 0x15BD (rare GNSS report, RGS log packet).

Tier-1 (public_corpus.risk_tiers.RISK_TIER[0x15BD] == 1): the parser leaves
an undecoded body_raw tail, so this frame is built entirely from fabricated
values via public_corpus.support.synthetic -- no bytes are copied from any
capture, private test, or real DIAG log.

Targets the v=3 (modern) decode path in diaggrok.parsers.diag_0x15bd:
9-byte header (version @0, sub_type @1, counter @2, byte_3 @3,
record_type_tag @4, header_tick u32 @5:9) followed by one 28-byte
V3SubRecord (tick u32 @0, kind u8 @7, aux_u16 u16 @4, field_x u16 @12,
field_y i16 @16, field_z i16 @18, aux_byte u8 @26).
"""
from public_corpus.support.synthetic import diag_frame, pack
from diaggrok.parsers.diag_0x15bd import parse_0x15bd

# Fabricated header values (not from any real capture).
_SUB_TYPE = 1
_COUNTER = 7
_BYTE_3 = 0
_RECORD_TYPE_TAG = 10          # 0x0A -- corpus-wide invariant
_HEADER_TICK = 123_456         # u32 @5:9 -- log-emission tick

# Fabricated single v3 sub-record values (not from any real capture).
_SR_TICK = 1000                # u32 @0
_SR_AUX_U16 = 0xC050           # u16 @4
_SR_KIND = 0x57                # u8 @7 -- "kind A" tag
_SR_FIELD_X = 27000            # u16 @12
_SR_FIELD_Y = -870             # i16 @16
_SR_FIELD_Z = 2160             # i16 @18
_SR_AUX_BYTE = 5               # u8 @26


def _synthetic_subrecord() -> bytes:
    """Build one fabricated 28-byte V3SubRecord."""
    sr = (
        pack('<I', _SR_TICK)      # [0:4]
        + pack('<H', _SR_AUX_U16)  # [4:6]
        + pack('<B', 0x0F)         # [6] kind_marker_6 (kind-A marker)
        + pack('<B', _SR_KIND)     # [7] kind_tag
        + bytes(4)                 # [8:12] reserved
        + pack('<H', _SR_FIELD_X)  # [12:14]
        + bytes(2)                 # [14:16] reserved
        + pack('<h', _SR_FIELD_Y)  # [16:18]
        + pack('<h', _SR_FIELD_Z)  # [18:20]
        + bytes(4)                 # [20:24] reserved
        + pack('<B', 1)            # [24] end_tag_a
        + pack('<B', 1)            # [25] end_tag_b (kind A)
        + pack('<B', _SR_AUX_BYTE)  # [26] aux_byte
        + pack('<B', 1)            # [27] kind_marker_27 (kind A)
    )
    assert len(sr) == 28
    return sr


def _synthetic_15bd() -> bytes:
    """Build a v=3 0x15BD payload: 9-byte header + one 28-byte sub-record.

      data[0]    version = 3               (supplied via diag_frame)
      data[1]    sub_type = 1
      data[2]    counter = 7
      data[3]    byte_3 = 0
      data[4]    record_type_tag = 10 (0x0A)
      data[5:9]  u32 header_tick = 123456
      data[9:37] one 28-byte V3SubRecord (see _synthetic_subrecord)
    """
    header_tail = (
        pack('<B', _SUB_TYPE)
        + pack('<B', _COUNTER)
        + pack('<B', _BYTE_3)
        + pack('<B', _RECORD_TYPE_TAG)
        + pack('<I', _HEADER_TICK)
    )
    body = header_tail + _synthetic_subrecord()
    frame = diag_frame(0x15BD, 3, body)
    assert len(frame) == 37  # 9-byte header + 28-byte sub-record
    return frame


def test_15bd_decodes_synthetic_frame():
    rec = parse_0x15bd(1000, _synthetic_15bd())
    assert rec is not None
    assert rec.version == 3
    assert rec.sub_type == _SUB_TYPE
    assert rec.counter == _COUNTER
    assert rec.byte_3 == _BYTE_3
    assert rec.record_type_tag == _RECORD_TYPE_TAG
    assert rec.header_tick == _HEADER_TICK
    assert rec.payload_size == 37
    assert len(rec.v3_sub_records) == 1
    sr = rec.v3_sub_records[0]
    assert sr.tick == _SR_TICK
    assert sr.kind == _SR_KIND
    assert sr.aux_u16 == _SR_AUX_U16
    assert sr.field_x == _SR_FIELD_X
    assert sr.field_y == _SR_FIELD_Y
    assert sr.field_z == _SR_FIELD_Z
    assert sr.aux_byte == _SR_AUX_BYTE
    assert rec.v2_sub_records == []
