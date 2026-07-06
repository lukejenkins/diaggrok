"""Public zero-PII fixture for 0x1494 (Large GNSS constellation data).

Tier 1 (synthetic-only): the parser leaves an undecoded body_raw tail (see
public_corpus.risk_tiers.RISK_TIER[0x1494] == 1), so this frame is built
entirely from fabricated values via public_corpus.support.synthetic -- no
bytes are copied from any capture, private test, or real DIAG log.

Targets the 3038-byte ("3038B") body-size class documented at the top of
diaggrok.parsers.diag_0x1494: version=0x01 (hard-gated), a 47-byte header,
and a 175-entry x 17-byte per-tracker-channel slot table starting at
offset 47 (the slot-decode path is only exercised when len(data) == 3038).
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x1494 import parse_0x1494

# Fabricated header values (not from any real capture). Offsets transcribed
# from the parser's own module docstring / field comments in diag_0x1494.py.
_VERSION = 0x01       # byte 0 -- hard-gated constant
_TYPE_HI = 0xa3        # byte 1 -- Qualcomm-default family (vs 0x89 SIMCom)
_TYPE_LO = 0x0d        # byte 2 -- Qualcomm-default family (vs 0x13 SIMCom)
_COUNTER = 7           # byte 5

_HEADER_LEN = 47
_SLOT_STRIDE = 17
_TOTAL_LEN = 3038      # selects the slot-decode path (len == 3038)

# Fabricated slot-0 values (one active per-tracker-channel slot).
_SLOT0_STATE_VALUE = -1234      # i32LE at slot [1:5]
_SLOT0_ACTIVE_FLAG = 0xFFFF     # u16LE at slot [5:7] -- "carrying valid data"
_SLOT0_PREV_AZ = 45             # u16LE at slot [7:9]
_SLOT0_PREV_EL = 30             # u16LE at slot [11:13]
_SLOT0_SIG_TYPE = 0x04          # byte at slot [15] -- primary signal slot
_SLOT0_PRN = 5                  # byte at slot [16] -- GPS PRN range 1..32


def _synthetic_slot(reserved_0, state_value, active_flag, prev_az, reserved_9_11,
                     prev_el, reserved_13_15, sig_type, prn) -> bytes:
    """One 17-byte per-tracker-channel slot, per the offsets documented in
    diag_0x1494.py's "Slot table" section."""
    slot = (
        pack('<B', reserved_0)
        + pack('<i', state_value)
        + pack('<H', active_flag)
        + pack('<H', prev_az)
        + pack('<H', reserved_9_11)
        + pack('<H', prev_el)
        + pack('<H', reserved_13_15)
        + pack('<B', sig_type)
        + pack('<B', prn)
    )
    assert len(slot) == _SLOT_STRIDE
    return slot


def _synthetic_1494() -> bytes:
    header = bytearray(_HEADER_LEN)
    header[0] = _VERSION
    header[1] = _TYPE_HI
    header[2] = _TYPE_LO
    header[5] = _COUNTER
    assert len(header) == _HEADER_LEN

    slot0 = _synthetic_slot(
        reserved_0=0, state_value=_SLOT0_STATE_VALUE, active_flag=_SLOT0_ACTIVE_FLAG,
        prev_az=_SLOT0_PREV_AZ, reserved_9_11=0, prev_el=_SLOT0_PREV_EL,
        reserved_13_15=0, sig_type=_SLOT0_SIG_TYPE, prn=_SLOT0_PRN,
    )
    # 174 more all-zero (inactive/uninitialized) slots -- 175 total, matching
    # the corpus-observed slot count for the 3038B body.
    other_slots = bytes(_SLOT_STRIDE) * 174
    # 16-byte unused tail -- floor((3038 - 47) / 17) == 175 slots consumed,
    # leaving 3038 - 47 - 175*17 == 16 bytes the parser never reads.
    tail = bytes(16)

    payload = bytes(header) + slot0 + other_slots + tail
    assert len(payload) == _TOTAL_LEN
    return payload


def test_1494_decodes_synthetic_frame():
    rec = parse_0x1494(1000, _synthetic_1494())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.type_hi == _TYPE_HI
    assert rec.type_lo == _TYPE_LO
    assert rec.counter == _COUNTER
    assert rec.payload_size == _TOTAL_LEN
    assert len(rec.slots) == 175
    slot0 = rec.slots[0]
    assert slot0.prn == _SLOT0_PRN
    assert slot0.sig_type == _SLOT0_SIG_TYPE
    assert slot0.active_flag == _SLOT0_ACTIVE_FLAG
    assert slot0.prev_az_deg == _SLOT0_PREV_AZ
    assert slot0.prev_el_deg == _SLOT0_PREV_EL
    assert slot0.state_value == _SLOT0_STATE_VALUE
    assert slot0.constellation == 'GPS'
    # slot 1 was left all-zero -> EMPTY constellation, inactive
    assert rec.slots[1].prn == 0
    assert rec.slots[1].constellation == 'EMPTY'
