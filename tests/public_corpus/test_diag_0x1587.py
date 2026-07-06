"""Public zero-PII fixture for 0x1587 (GNSS tracking detail report).

Tier-1 (public_corpus.risk_tiers.RISK_TIER[0x1587] == 1): mid_raw (6B
opaque) + variable body_raw are undecoded, so this frame is built entirely
from fabricated values via public_corpus.support.synthetic -- no bytes are
copied from any capture, private test, or real DIAG log.

Targets the 20-byte header decode in diaggrok.parsers.diag_0x1587: version
@0 (gated to enum {0x0C..0x10}), counter_hi/counter_lo @1/@2, byte_3 @3,
flag_4 @4, state_5 @5, marker_6 @6 (gated to enum {0x05, 0x09, 0xFF}),
mid_raw @7:13 (opaque), byte_13/flag_14 (mirror pair) @13/@14,
pad_15_18 @15:19 (zero-padding), sentinel @19. Body is a minimum-valid
5-byte opaque tail.
"""
from public_corpus.support.synthetic import diag_frame, pack
from diaggrok.parsers.diag_0x1587 import parse_0x1587

# Fabricated values (not from any real capture).
_VERSION = 0x0F        # byte 0 -- one of the enum {0x0C, 0x0D, 0x0E, 0x0F, 0x10}
_COUNTER_HI = 0x11     # byte 1
_COUNTER_LO = 0x22     # byte 2
_BYTE_3 = 6            # byte 3 -- mirrors byte_13
_FLAG_4 = 1            # byte 4 -- mirrors flag_14
_STATE_5 = 0x72        # byte 5 -- GNSS tracking-state byte
_MARKER_6 = 0x09       # byte 6 -- one of the enum {0x05, 0x09, 0xFF}
_MID_RAW = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])  # bytes 7..12 (opaque)
_BYTE_13 = 6           # byte 13 -- mirror of byte_3
_FLAG_14 = 1           # byte 14 -- mirror of flag_4
_SENTINEL = 0x27       # byte 19 -- per-version tail marker
_BODY = bytes([0x01, 0x02, 0x03, 0x04, 0x05])  # 5-byte opaque body tail


def _synthetic_1587() -> bytes:
    """Build a 20-byte-header + 5-byte-body 0x1587 payload (25 bytes total).

      data[0]      version = 0x0F
      data[1]      counter_hi = 0x11
      data[2]      counter_lo = 0x22
      data[3]      byte_3 = 6            (mirrors byte_13)
      data[4]      flag_4 = 1            (mirrors flag_14)
      data[5]      state_5 = 0x72
      data[6]      marker_6 = 0x09
      data[7:13]   mid_raw = AA BB CC DD EE FF (opaque)
      data[13]     byte_13 = 6           (mirror of byte_3)
      data[14]     flag_14 = 1           (mirror of flag_4)
      data[15:19]  pad_15_18 = 00 00 00 00 (zero-padding)
      data[19]     sentinel = 0x27
      data[20:25]  body_raw = 5 fabricated opaque bytes
    """
    body = (
        pack('<B', _COUNTER_HI)
        + pack('<B', _COUNTER_LO)
        + pack('<B', _BYTE_3)
        + pack('<B', _FLAG_4)
        + pack('<B', _STATE_5)
        + pack('<B', _MARKER_6)
        + _MID_RAW
        + pack('<B', _BYTE_13)
        + pack('<B', _FLAG_14)
        + bytes(4)              # pad_15_18
        + pack('<B', _SENTINEL)
        + _BODY
    )
    assert len(body) == 19 + len(_BODY)  # + 1 version byte from diag_frame == 20 + body
    frame = diag_frame(0x1587, _VERSION, body)
    assert len(frame) == 20 + len(_BODY)
    return frame


def test_1587_decodes_synthetic_frame():
    rec = parse_0x1587(1000, _synthetic_1587())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.counter_hi == _COUNTER_HI
    assert rec.counter_lo == _COUNTER_LO
    assert rec.byte_3 == _BYTE_3
    assert rec.flag_4 == _FLAG_4
    assert rec.state_5 == _STATE_5
    assert rec.marker_6 == _MARKER_6
    assert rec.mid_raw == _MID_RAW
    assert rec.byte_13 == _BYTE_13
    assert rec.flag_14 == _FLAG_14
    assert rec.pad_15_18 == bytes(4)
    assert rec.sentinel == _SENTINEL
    assert rec.body_size == len(_BODY)
    assert rec.body_raw == _BODY
