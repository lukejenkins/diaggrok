"""Public zero-PII fixture for 0x1843 (Galileo E6 measurement skeleton).

Tier 1 (synthetic-only): the parser leaves a large undecoded/opaque region
(the raw 141-slot x 28-byte table is retained as ``raw``), so a real byte
snippet could hide PII in an unreviewed region (see
public_corpus.risk_tiers.RISK_TIER[0x1843] == 1). This fixture is built
entirely from fabricated values via public_corpus.support.synthetic -- no
bytes are copied from any capture, private test, or real DIAG log.

Targets the corpus-invariant header (version=0x01, record_id_byte=0x8d) plus
the 141 x 28-byte per-SV slot table documented in diaggrok.parsers.diag_0x1843:
HEADER_BYTES=4, SLOT_STRIDE=28, SLOT_COUNT=141, with one slot marked "active"
via the ACTIVE_SLOT_MARKER b'\\x85\\x40\\x00\\x01' at slot offset +3.
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x1843 import parse_0x1843

# Fabricated header values (not from any real capture).
_VERSION = 0x01          # data[0] -- field_invariants const
_RECORD_ID = 0x8D        # data[1] -- corpus-invariant per docstring
_STATE = 0x0000          # data[2:4] u16 LE header-state field
_SLOT_STRIDE = 28
_SLOT_COUNT = 141
_ACTIVE_MARKER = b'\x85\x40\x00\x01'


def _active_slot() -> bytes:
    """28-byte slot with the active-marker pattern at intra-slot +3.

    Layout transcribed from _decode_active_slot / ACTIVE_SLOT_MARKER in
    diag_0x1843.py:
      +0    u8  slot_flag = 0x00 (fabricated -- "locked" per docstring)
      +1    u8  fill = 0x00
      +2    u8  sv_id_or_state = 0x05 (fabricated)
      +3:7  active marker = 85 40 00 01
      +7:16 9 zero-filled bytes
      +16:19 u24 LE measurement_24 = 12345 (fabricated)
      +19:28 9 zero-filled bytes
    """
    slot = (
        pack('<B', 0x00)
        + pack('<B', 0x00)
        + pack('<B', 0x05)
        + _ACTIVE_MARKER
        + bytes(9)
        + pack('<BBB', 57, 48, 0)  # u24 LE 12345 = 0x003039 -> bytes 39 30 00
        + bytes(9)
    )
    assert len(slot) == _SLOT_STRIDE
    return slot


def _inactive_slot() -> bytes:
    return bytes(_SLOT_STRIDE)


def _synthetic_1843() -> bytes:
    header = pack('<B', _VERSION) + pack('<B', _RECORD_ID) + pack('<H', _STATE)
    assert len(header) == 4
    slots = _active_slot() + _inactive_slot() * (_SLOT_COUNT - 1)
    data = header + slots
    assert len(data) == 4 + _SLOT_COUNT * _SLOT_STRIDE == 3952
    return data


def test_1843_decodes_synthetic_frame_with_one_active_slot():
    rec = parse_0x1843(1000, _synthetic_1843())
    assert rec is not None
    assert rec.version == _VERSION
    # header_marker is the u32 LE reading of bytes [0:4]:
    # version | record_id<<8 | state<<16
    expected_header_marker = _VERSION | (_RECORD_ID << 8) | (_STATE << 16)
    assert rec.header_marker == expected_header_marker
    assert rec.slot_count == _SLOT_COUNT
    assert rec.slot_stride == _SLOT_STRIDE
    assert rec.active_slot_count == 1
    assert rec.payload_size == 3952
    assert rec.constellation == 'Galileo'
    assert rec.band == 'E6'
