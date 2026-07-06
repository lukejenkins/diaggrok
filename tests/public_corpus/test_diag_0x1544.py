"""Public zero-PII fixture for 0x1544 (GNSS SV aggregate report).

Tier-1 (public_corpus.risk_tiers.RISK_TIER[0x1544] == 1): the body can carry
a plaintext NMEA sentence (lat/lon/UTC), so this frame is built entirely
from fabricated values via public_corpus.support.synthetic -- no bytes are
copied from any capture, private test, or real DIAG log.

Targets the 28-byte header decode in diaggrok.parsers.diag_0x1544 (format
'<BBBBBBBBBBBBHHIIHBB', 28 bytes) with an 8-byte "idle/keepalive" body
(body_len <= 8 and not a valid NMEA/binary-SV body), which deterministically
resolves to body_kind == 'idle' without needing to decode a real sentence.
"""
from public_corpus.support.synthetic import diag_frame, pack
from diaggrok.parsers.diag_0x1544 import parse_0x1544

# Fabricated header values (not from any real capture).
_SUB_TYPE = 1
_SEQUENCE_COUNTER = 5
_FLAGS = 0
_NUM_CONSTELLATIONS = 4
_FORMAT_TYPE = 1
_CONSTELLATION_MASK = 18
_REF_VALUE = 0xDEADBEEF   # ref_value is documented as polymorphic/opaque
_COUNTER2 = 44            # body_format_subcode
_BODY_LEN = 8             # idle body: too short for NMEA or binary-SV tables


def _synthetic_1544() -> bytes:
    """Build a 28-byte header + 8-byte idle-body 0x1544 payload.

    Header layout (offsets relative to payload start, matching
    diaggrok.parsers.diag_0x1544._HDR_FMT = '<BBBBBBBBBBBBHHIIHBB'):

      [0]     version = 0x02             (supplied via diag_frame)
      [1]     sub_type = 1
      [2]     sequence_counter = 5
      [3]     flags = 0
      [4]     num_constellations = 4
      [5:8]   reserved = 0
      [8]     format_type = 1
      [9:12]  reserved = 0
      [12:14] u16 constellation_mask = 18
      [14:16] u16 reserved = 0
      [16:20] u32 ref_value = 0xDEADBEEF
      [20:24] u32 counter2 = 44
      [24:26] u16 body_len = 8
      [26:28] reserved = 0

    Body (8 zero bytes): too short to satisfy the binary-SV body's minimum
    (8-byte body header + 28-byte slot = 36 bytes) and not a '$'-prefixed
    NMEA sentence, so the parser's body_kind discriminator falls through to
    'idle' deterministically.
    """
    header = (
        pack('<B', _SUB_TYPE)
        + pack('<B', _SEQUENCE_COUNTER)
        + pack('<B', _FLAGS)
        + pack('<B', _NUM_CONSTELLATIONS)
        + bytes(3)                       # [5:8] reserved
        + pack('<B', _FORMAT_TYPE)
        + bytes(3)                       # [9:12] reserved
        + pack('<H', _CONSTELLATION_MASK)
        + pack('<H', 0)                  # [14:16] reserved
        + pack('<I', _REF_VALUE)
        + pack('<I', _COUNTER2)
        + pack('<H', _BODY_LEN)
        + bytes(2)                       # [26:28] reserved
    )
    assert len(header) == 27  # + 1 version byte from diag_frame == 28
    body = bytes(_BODY_LEN)
    frame = diag_frame(0x1544, 0x02, header + body)
    assert len(frame) == 28 + _BODY_LEN
    return frame


def test_1544_decodes_synthetic_frame():
    rec = parse_0x1544(1000, _synthetic_1544())
    assert rec is not None
    assert rec.version == 0x02
    assert rec.sub_type == _SUB_TYPE
    assert rec.sequence_counter == _SEQUENCE_COUNTER
    assert rec.flags == _FLAGS
    assert rec.num_constellations == _NUM_CONSTELLATIONS
    assert rec.format_type == _FORMAT_TYPE
    assert rec.constellation_mask == _CONSTELLATION_MASK
    assert rec.ref_value == _REF_VALUE
    assert rec.counter2 == _COUNTER2
    assert rec.body_format_subcode == _COUNTER2
    assert rec.body_len == _BODY_LEN
    assert rec.body_kind == 'idle'
    assert rec.sv_slots is None
    assert rec.nmea_sentence is None
