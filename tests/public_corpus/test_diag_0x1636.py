"""Public zero-PII fixture for 0x1636 (GNSS_ME_RF_NOISE_EST notch-filter table).

Tier-1 (public_corpus.risk_tiers.RISK_TIER[0x1636] == 1): the parser carries
GNSS RTC time (rtc_ms) and leaves the v3 7-byte trailer undecoded
(trailer_raw), so these frames are built entirely from fabricated values via
public_corpus.support.synthetic -- no bytes are copied from any capture,
private test, or real DIAG log.

Targets the notch-table decode in diaggrok.parsers.diag_0x1636 (v3):
9-byte header (version u8 @0, rtc_ms u32 @1, i32 @5), then 8-byte notch
entries [notch_idx, flag_1, enabled, rfa, freq_hz i32]. v2 (225 B) / v3
(232 B) carry three fixed-capacity banks of 7 / 13 / 7 entries; v4 carries
banks of [count u8][13 x entry] (105 B each). Sizes are exact-match gated.
"""
from public_corpus.support.synthetic import diag_frame, pack
from diaggrok.parsers.diag_0x1636 import parse_0x1636

# Fabricated values (not from any real capture).
_RTC_MS = 0x00012345
_WORD5 = -1234
_BANKS = (7, 13, 7)
_TRAILER = b'\xa1\xa2\xa3\xa4\xa5\xa6\xa7'
# (bank, slot) -> (notch_idx, flag_1, enabled, rfa, freq_hz); all others zero.
_NOTCHES = {
    (0, 0): (0, 1, 1, 1, -1_000_000),
    (0, 1): (1, 1, 1, 0, 250_000),
    (1, 2): (2, 0, 1, 0, -777_000),
    (2, 6): (6, 1, 1, 1, 3_000_000),
}


def _entry(idx: int, f1: int, en: int, rfa: int, freq: int) -> bytes:
    return pack('<BBBBi', idx, f1, en, rfa, freq)


def _fixed_banks() -> bytes:
    out = b''
    for bank, cap in enumerate(_BANKS):
        for slot in range(cap):
            out += _entry(*_NOTCHES.get((bank, slot), (0, 0, 0, 0, 0)))
    return out


def _synthetic_1636_v3() -> bytes:
    """232-byte v3 frame: header + 27 fixed-capacity entries + 7-byte trailer."""
    body = pack('<I', _RTC_MS) + pack('<i', _WORD5) + _fixed_banks() + _TRAILER
    frame = diag_frame(0x1636, 3, body)
    assert len(frame) == 232
    return frame


def _synthetic_1636_v2() -> bytes:
    """225-byte v2 frame: header + 27 fixed-capacity entries, no trailer."""
    body = pack('<I', _RTC_MS) + pack('<i', _WORD5) + _fixed_banks()
    frame = diag_frame(0x1636, 2, body)
    assert len(frame) == 225
    return frame


def _synthetic_1636_v4() -> bytes:
    """219-byte v4 frame: header + 2 banks of [count][13 x entry].

    Bank 0 holds 2 notches; bank 1 holds 0 and its slots are filled with a
    fabricated 0xDE stale pattern the parser must not decode.
    """
    bank0 = (pack('<B', 2)
             + _entry(1, 0, 0, 1, -2_000_000)
             + _entry(4, 0, 0, 0, 444_000)
             + bytes(8 * 11))
    bank1 = pack('<B', 0) + b'\xde' * (8 * 13)
    body = pack('<I', _RTC_MS) + pack('<i', _WORD5) + bank0 + bank1
    frame = diag_frame(0x1636, 4, body)
    assert len(frame) == 9 + 2 * 105
    return frame


def test_1636_decodes_synthetic_v3_frame():
    rec = parse_0x1636(1000, _synthetic_1636_v3())
    assert rec is not None
    assert rec.version == 3
    assert rec.payload_size == 232
    assert rec.rtc_ms == _RTC_MS
    assert rec.xo_offset_ppm_q20 == _WORD5
    assert rec.header_word_5 is None
    assert rec.trailer_raw == _TRAILER
    assert [b.gnss for b in rec.banks] == [0, 1, 2]
    assert [len(b.notches) for b in rec.banks] == list(_BANKS)
    assert all(b.count is None for b in rec.banks)
    for (bank, slot), (idx, f1, en, rfa, freq) in _NOTCHES.items():
        n = rec.banks[bank].notches[slot]
        assert (n.slot, n.notch_idx, n.flag_1, n.enabled, n.rfa, n.freq_hz) == (
            slot, idx, f1, en, rfa, freq)
    assert rec.banks[1].notches[0].freq_hz == 0


def test_1636_decodes_synthetic_v2_frame():
    rec = parse_0x1636(1000, _synthetic_1636_v2())
    assert rec is not None
    assert rec.version == 2
    assert rec.xo_offset_ppm_q20 is None
    assert rec.header_word_5 == _WORD5 & 0xFFFFFFFF
    assert rec.trailer_raw is None
    assert rec.banks[2].notches[6].freq_hz == 3_000_000


def test_1636_decodes_synthetic_v4_frame():
    rec = parse_0x1636(1000, _synthetic_1636_v4())
    assert rec is not None
    assert rec.version == 4
    assert rec.xo_offset_ppm_q20 == _WORD5
    assert [(b.gnss, b.count, len(b.notches)) for b in rec.banks] == [
        (0, 2, 2), (1, 0, 0)]
    assert [(n.notch_idx, n.rfa, n.freq_hz) for n in rec.banks[0].notches] == [
        (1, 1, -2_000_000), (4, 0, 444_000)]


def test_1636_rejects_wrong_size_frames():
    # The retired 12-byte config_word stub frame no longer matches any version.
    assert parse_0x1636(1000, diag_frame(0x1636, 3, bytes(11))) is None
    assert parse_0x1636(1000, _synthetic_1636_v3()[:-1]) is None
    assert parse_0x1636(1000, _synthetic_1636_v4() + b'\x00') is None
    assert parse_0x1636(1000, diag_frame(0x1636, 5, bytes(231))) is None
