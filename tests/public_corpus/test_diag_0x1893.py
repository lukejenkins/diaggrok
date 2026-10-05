"""Public zero-PII fixture for 0x1893 (GNSS measurement-engine status).

Tier 1 (synthetic-only): per-slot ``timestamp_u40`` is an ambiguous
absolute-time candidate (see public_corpus.risk_tiers.RISK_TIER[0x1893]
== 1), so this fixture is built entirely from fabricated values via
public_corpus.support.synthetic -- no bytes are copied from any capture,
private test, or real DIAG log.

Targets the 873-byte MDM9607/EG25-G variant documented in
diaggrok.parsers.diag_0x1893: 61-byte header + 14 x 58-byte measurement
slots, version_b=0x01 for this variant. One slot is built "occupied"
(non-zero timestamp_u40), the rest are empty (all-zero) slots.
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x1893 import parse_0x1893

# Fabricated header values (not from any real capture).
_VERSION = 0x01        # data[0] -- field_invariants const
_VERSION_B = 0x01      # data[1] -- 873B variant requires version_b=0x01
_SEQ_LO = 5            # data[2] -- fabricated
_COUNTER = 12345       # u32 LE at [3:7] -- fabricated
_FLAG_7 = 2            # data[7] -- fabricated
_FLAG_11 = 0x06        # data[11] -- fabricated (observed {0x00, 0x06} corpus-wide)
_MARKER_14 = 0x01      # data[14] -- field_invariants const
_FLAG_17 = 9           # data[17] -- fabricated
_HEADER_LEN = 61
_SLOT_LEN = 58
_NUM_SLOTS = 14

# Fabricated occupied-slot values (slot 0 only; slots 1..13 are empty/zero).
_SLOT0_TS_U40 = 123456789
_SLOT0_MARKER_A = 0x06
_SLOT0_MARKER_B = 0x01
_SLOT0_STATUS = 0x00


def _header() -> bytes:
    buf = bytearray(_HEADER_LEN)
    buf[0] = _VERSION
    buf[1] = _VERSION_B
    buf[2] = _SEQ_LO
    buf[3:7] = pack('<I', _COUNTER)
    buf[7] = _FLAG_7
    buf[11] = _FLAG_11
    buf[14] = _MARKER_14
    buf[17] = _FLAG_17
    return bytes(buf)


def _occupied_slot() -> bytes:
    buf = bytearray(_SLOT_LEN)
    buf[0:5] = _SLOT0_TS_U40.to_bytes(5, 'little')
    buf[8] = _SLOT0_MARKER_A
    buf[11] = _SLOT0_MARKER_B
    buf[14] = _SLOT0_STATUS
    return bytes(buf)


def _empty_slot() -> bytes:
    return bytes(_SLOT_LEN)


def _synthetic_1893_873b() -> bytes:
    """Build the 873-byte (61B header + 14x58B slots) 0x1893 payload.

    Header offsets and slot offsets transcribed from diag_0x1893.py's
    Diag0x1893 / CxmArbSlot1893 dataclasses and _parse_1893_slot:
      header [0]=version, [1]=version_b, [2]=seq_lo, [3:7]=counter,
              [7]=flag_7, [11]=flag_11, [14]=marker_14, [17]=flag_17
      slot [+0:+5]=u40 LE timestamp_u40, [+8]=marker_a, [+11]=marker_b,
           [+14]=status_flag
    """
    data = _header() + _occupied_slot() + _empty_slot() * (_NUM_SLOTS - 1)
    assert len(data) == _HEADER_LEN + _NUM_SLOTS * _SLOT_LEN == 873
    return data


def test_1893_decodes_synthetic_873b_frame():
    rec = parse_0x1893(1000, _synthetic_1893_873b())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.version_b == _VERSION_B
    assert rec.seq_lo == _SEQ_LO
    assert rec.counter == _COUNTER
    assert rec.flag_7 == _FLAG_7
    assert rec.flag_11 == _FLAG_11
    assert rec.marker_14 == _MARKER_14
    assert rec.flag_17 == _FLAG_17
    assert rec.payload_size == 873
    assert rec.occupied_count == 1
    assert len(rec.slots) == _NUM_SLOTS
    assert rec.slots[0].occupied is True
    assert rec.slots[0].timestamp_u40 == _SLOT0_TS_U40
    assert rec.slots[0].marker_a == _SLOT0_MARKER_A
    assert rec.slots[0].marker_b == _SLOT0_MARKER_B
    assert rec.slots[0].status_flag == _SLOT0_STATUS
    assert rec.slots[1].occupied is False
    assert rec.slots[1].timestamp_u40 == 0
