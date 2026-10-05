"""Public zero-PII fixture for 0x1589 (SAP-SDP state-transition event, v0x00).

Tier-1 (public_corpus.risk_tiers.RISK_TIER[0x1589] == 1): [1:7] is a GNSS
absolute time (gps_week + gps_tow_ms), so this frame is built entirely from
fabricated values via public_corpus.support.synthetic -- no bytes are copied
from any capture, private test, or real DIAG log.

Targets the fixed 17-byte decode in diaggrok.parsers.diag_0x1589: version @0
(gated to 0x00), gps_week @1:3, gps_tow_ms @3:7, tick_ms @7:11, marker_11 @11
(gated to 0x01), marker_12 @12 (gated to 0x00), from_state @13, to_state @14,
event @15, reserved_16 @16 (gated to 0x00).
"""
from public_corpus.support.synthetic import diag_frame, pack
from diaggrok.parsers.diag_0x1589 import parse_0x1589

# Fabricated values (not from any real capture).
_GPS_WEEK = 1000
_GPS_TOW_MS = 123456
_TICK_MS = 7890
_TRANSITION = (0x03, 0x02, 0x05)          # (from_state, to_state, event)


def _synthetic_1589() -> bytes:
    body = (
        pack('<H', _GPS_WEEK)
        + pack('<I', _GPS_TOW_MS)
        + pack('<I', _TICK_MS)
        + pack('<B', 0x01)   # marker_11
        + pack('<B', 0x00)   # marker_12
        + bytes(_TRANSITION)
        + pack('<B', 0x00)   # reserved_16
    )
    frame = diag_frame(0x1589, 0x00, body)
    assert len(frame) == 17
    return frame


def test_1589_decodes_synthetic_frame():
    rec = parse_0x1589(1000, _synthetic_1589())
    assert rec is not None
    assert rec.version == 0x00
    assert rec.gps_week == _GPS_WEEK
    assert rec.gps_tow_ms == _GPS_TOW_MS
    assert rec.gps_time_valid is True
    assert rec.tick_ms == _TICK_MS
    assert rec.marker_11 == 0x01
    assert rec.marker_12 == 0x00
    assert (rec.from_state, rec.to_state, rec.event) == _TRANSITION
    assert rec.from_state_name == "HFAutoNotInjecting"
    assert rec.to_state_name == "HFAutoInjecting"
    assert rec.reserved_16 == 0x00
    assert rec.payload_size == 17
