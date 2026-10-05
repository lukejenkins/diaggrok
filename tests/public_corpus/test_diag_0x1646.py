"""Public zero-PII fixture for 0x1646 (GLONASS RF bandpass status).

Tier-1 (public_corpus.risk_tiers.RISK_TIER[0x1646] == 1): the trailer region
remains undecoded, so this frame is built entirely from fabricated values
via public_corpus.support.synthetic -- no bytes are copied from any
capture, private test, or real DIAG log.

Targets the v=3 (449B) decode path in diaggrok.parsers.diag_0x1646: 13-byte
header (version @0, subtype @1, record_counter u16 @2:4, marker @4,
timestamp_a u32 @5:9, timestamp_b u32 @9:13) followed by 9 identical
44-byte v3 slots (see GnssRfGloBpSlot / _decode_slot_v3) and a 40-byte
zero-filled trailer (449 = 13 + 9*44 + 40).
"""
from public_corpus.support.synthetic import diag_frame, pack
from diaggrok.parsers.diag_0x1646 import parse_0x1646

# Fabricated header values (not from any real capture).
_SUBTYPE = 1                 # byte 1 -- corpus-wide constant
_RECORD_COUNTER = 42         # u16 @2:4
_MARKER = 0x0A               # byte 4 -- corpus-wide constant
_TIMESTAMP_A = 1000          # u32 @5:9 -- 1kHz metronome tick
_TIMESTAMP_B = 1050          # u32 @9:13 -- paired tick value

# Fabricated v3 slot values (not from any real capture) -- same values used
# for all 9 slots for simplicity; still fully fabricated, not corpus-derived.
_SLOT_METRIC_A = 23100        # u16 @0:2
_SLOT_RF_METRIC_1 = 1660      # i16 @16:18
_SLOT_RF_METRIC_2 = 1659      # i16 @20:22
_SLOT_RF_METRIC_3 = 50        # i16 @24:26
_SLOT_MARKER = 0x00010D0D     # u32 @32:36
_SLOT_FINAL_METRIC = 0x00117F2B  # u32 @40:44

_TRAILER_LEN = 40             # v3 trailer size


def _synthetic_slot() -> bytes:
    """Build one fabricated 44-byte v3 GnssRfGloBpSlot."""
    slot = (
        pack('<H', _SLOT_METRIC_A)   # [0:2] metric_a
        + pack('<B', 0)               # [2] pad
        + pack('<B', 0)               # [3] state_flag
        + pack('<I', 0x80000000)      # [4:8] sentinel
        + pack('<I', 0x00000200)      # [8:12] const1
        + pack('<I', 0)               # [12:16] reserved_zero
        + pack('<h', _SLOT_RF_METRIC_1)  # [16:18]
        + bytes(2)                    # [18:20] sign-ext pad
        + pack('<h', _SLOT_RF_METRIC_2)  # [20:22]
        + bytes(2)                    # [22:24] sign-ext pad
        + pack('<h', _SLOT_RF_METRIC_3)  # [24:26]
        + bytes(2)                    # [26:28] sign-ext pad
        + pack('<I', 0)               # [28:32] reserved_zero_2
        + pack('<I', _SLOT_MARKER)    # [32:36]
        + pack('<I', 0)               # [36:40] flags
        + pack('<I', _SLOT_FINAL_METRIC)  # [40:44]
    )
    assert len(slot) == 44
    return slot


def _synthetic_1646() -> bytes:
    """Build a v=3, 449-byte 0x1646 payload: 13B header + 9x44B slots + 40B trailer."""
    header_tail = (
        pack('<B', _SUBTYPE)
        + pack('<H', _RECORD_COUNTER)
        + pack('<B', _MARKER)
        + pack('<I', _TIMESTAMP_A)
        + pack('<I', _TIMESTAMP_B)
    )
    assert len(header_tail) == 12  # + 1 version byte from diag_frame == 13
    slots = _synthetic_slot() * 9
    trailer = bytes(_TRAILER_LEN)
    frame = diag_frame(0x1646, 3, header_tail + slots + trailer)
    assert len(frame) == 449
    return frame


def test_1646_decodes_synthetic_frame():
    rec = parse_0x1646(1000, _synthetic_1646())
    assert rec is not None
    assert rec.version == 3
    assert rec.subtype == _SUBTYPE
    assert rec.record_counter == _RECORD_COUNTER
    assert rec.marker == _MARKER
    assert rec.timestamp_a == _TIMESTAMP_A
    assert rec.timestamp_b == _TIMESTAMP_B
    assert rec.payload_size == 449
    assert rec.size_variant == 'v3_449'
    assert rec.slot_count == 9
    assert rec.slot_stride == 44
    assert rec.trailer_size == _TRAILER_LEN
    assert len(rec.slots) == 9
    slot0 = rec.slots[0]
    assert slot0.metric_a == _SLOT_METRIC_A
    assert slot0.state_flag == 0
    assert slot0.sentinel == 0x80000000
    assert slot0.const1 == 0x00000200
    assert slot0.rf_metric_1 == _SLOT_RF_METRIC_1
    assert slot0.rf_metric_2 == _SLOT_RF_METRIC_2
    assert slot0.rf_metric_3 == _SLOT_RF_METRIC_3
    assert slot0.slot_marker == _SLOT_MARKER
    assert slot0.final_metric == _SLOT_FINAL_METRIC
    assert slot0.flags2 is None
