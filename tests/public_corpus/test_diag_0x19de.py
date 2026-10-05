"""Public zero-PII fixture for 0x19DE (GNSS ME per-channel tracking state).

Tier 1 (risk_tiers.RISK_TIER[0x19DE] == 1): each per-slot sub-record holds
a 100/12-byte body_raw region that is only partially decoded (slot_state
+ prn_like + a nonzero-byte count + a u32 subtype prefix are named; the
rest of the body is preserved raw pending denser RE per the module
docstring). A real byte snippet of an undecoded region could carry
unknown PII the text-only leak_tokens guard can't see, so this fixture is
built entirely from fabricated values via public_corpus.support.synthetic
-- no bytes are copied from any capture, private test, or real DIAG log.

Targets the 536B size variant (16B header + 5x104B GPS slots, no
GLONASS) -- the simplest of the three documented size variants in
diaggrok.parsers.diag_0x19de. Offsets below are transcribed from the
parser's own module docstring / _SIZE_TABLE / _parse_slot, not from any
capture:

    data[0]     u8  version = 1                  (Layer-1 gate)
    data[1]     u8  total_slots = 5               (must == num_gps + num_glo)
    data[2:4]   u16 reserved1 = 0
    data[4:8]   u32 reserved2 = 0
    data[8:12]  u32 tick                          (free-running tick)
    data[12:16] u32 header_word3                  (unverified per-capture word)

    per-GPS-slot (104B, GPS_SLOT_SIZE), first slot at data[16:120]:
        slot[0]    u8  slot_id                    (ME tracking channel, NOT a PRN)
        slot[1]    u8  reserved = 0
        slot[2:4]  u16 LE signature = 0xA163       (SIG_GPS)
        slot[4:104] 100B body -- body_raw. Per _parse_slot:
            body[0]   prn_like (firmware-conditional, NOT a PRN in general)
            body[99]  slot_state (last byte of body == last byte of slot)
            body[0:4] LE u32 body_subtype_prefix_u32
            body_nonzero_count = count of nonzero bytes in body
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x19de import parse_0x19de, SIG_GPS

# --- header (16 B) ---
_VERSION = 1
_TOTAL_SLOTS = 5          # 5 GPS + 0 GLONASS -> matches the 536B size table entry
_TICK = 0x00BC_614E        # fabricated free-running tick value
_HEADER_WORD3 = 27         # fabricated per-capture constant (matches em9190 example in docstring, but chosen here, not copied from any capture record)

# --- one fabricated GPS slot (slot 0 of 5; the other 4 are all-zero-body
# filler slots with a valid signature so the size/slot-count invariant
# holds) ---
_SLOT0_ID = 3                # fabricated ME channel number (not a PRN)
_SLOT0_PRN_LIKE = 9           # fabricated body[0] -- firmware-conditional field, not asserted as a real PRN
_SLOT0_STATE = 2              # fabricated body[99] -- one of the observed enum values {0,1,2,5,8}
_SLOT0_SUBTYPE_TAIL = 0x0102  # fabricated bytes body[1:3] (part of the LE u32 subtype prefix along with body[0]/body[3])
_SLOT0_SUBTYPE_B3 = 0x00


def _gps_slot(slot_id: int, prn_like: int, state: int) -> bytes:
    """Build one fabricated 104B GPS slot: 4B slot header + 100B body.

    body[0]    = prn_like
    body[1]    = 0x02 (fabricated filler byte, part of body_subtype_prefix_u32)
    body[2]    = 0x01 (fabricated filler byte, part of body_subtype_prefix_u32)
    body[3]    = 0x00 (fabricated filler byte, part of body_subtype_prefix_u32)
      -> body_subtype_prefix_u32 = LE(prn_like, 0x02, 0x01, 0x00)
    body[4:99] = zero-filled (opaque region, not asserted on)
    body[99]   = state (slot_state)
    """
    body = bytearray(100)
    body[0] = prn_like
    body[1] = 0x02
    body[2] = 0x01
    body[3] = 0x00
    body[99] = state
    return pack('<B', slot_id) + pack('<B', 0) + pack('<H', SIG_GPS) + bytes(body)


def _empty_gps_slot(slot_id: int) -> bytes:
    """A dormant (all-zero-body) GPS slot with a valid GPS signature --
    needed only to satisfy the 536B size-table slot count; not asserted on.
    """
    return pack('<B', slot_id) + pack('<B', 0) + pack('<H', SIG_GPS) + bytes(100)


def _synthetic_19de() -> bytes:
    header = (
        pack('<B', _VERSION)
        + pack('<B', _TOTAL_SLOTS)
        + pack('<H', 0)          # reserved1
        + pack('<I', 0)          # reserved2
        + pack('<I', _TICK)
        + pack('<I', _HEADER_WORD3)
    )
    assert len(header) == 16

    slot0 = _gps_slot(_SLOT0_ID, _SLOT0_PRN_LIKE, _SLOT0_STATE)
    assert len(slot0) == 104

    filler_slots = b''.join(_empty_gps_slot(i) for i in (10, 11, 12, 13))
    assert len(filler_slots) == 4 * 104

    data = header + slot0 + filler_slots
    assert len(data) == 536
    return data


def test_19de_decodes_536b_variant():
    rec = parse_0x19de(1000, _synthetic_19de())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.total_slots == _TOTAL_SLOTS
    assert rec.tick == _TICK
    assert rec.header_word3 == _HEADER_WORD3
    assert rec.payload_size == 536
    assert rec.num_gps_slots == 5
    assert rec.num_glo_slots == 0
    assert len(rec.slots) == 5

    slot0 = rec.slots[0]
    assert slot0.slot_id == _SLOT0_ID
    assert slot0.signature == SIG_GPS
    assert slot0.constellation == 'gps'
    # slot_state is body[99] (the last byte of the 100B body) -- see _parse_slot.
    assert slot0.slot_state == _SLOT0_STATE
    assert slot0.is_active is True  # is_active <=> slot_state != 0
    # prn_like is body[0] -- fabricated here, NOT asserted as a real PRN
    # (firmware-conditional per the module docstring).
    assert slot0.prn_like == _SLOT0_PRN_LIKE
    # body_subtype_prefix_u32 = LE u32 over body[0:4] = (prn_like, 0x02, 0x01, 0x00).
    expected_subtype = _SLOT0_PRN_LIKE | (0x02 << 8) | (0x01 << 16) | (0x00 << 24)
    assert slot0.body_subtype_prefix_u32 == expected_subtype
    # nonzero bytes in the 100B body: body[0]=9, body[1]=2, body[2]=1, body[99]=2 -> 4 nonzero.
    assert slot0.body_nonzero_count == 4

    # The 4 filler slots are dormant (all-zero body -> slot_state == 0 -> inactive).
    for slot in rec.slots[1:]:
        assert slot.slot_state == 0
        assert slot.is_active is False
        assert slot.body_nonzero_count == 0

    assert rec.active_gps_slots == [slot0]
    assert rec.active_glonass_slots == []
