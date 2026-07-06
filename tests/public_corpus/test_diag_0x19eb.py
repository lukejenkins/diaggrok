"""Public zero-PII fixture for 0x19EB (GNSS GPS L5 per-SV measurement report).

Tier 1 (risk_tiers.RISK_TIER[0x19EB] == 1): the 32B header is preserved
raw as ``raw_header`` (docstring: "suggesting a packed timestamp /
sample-clock / receiver-state region" -- unresolved) and each 70B slot
keeps its full bytes as ``raw`` alongside the decoded fields. A real
byte snippet of either opaque region could carry unknown PII the
text-only leak_tokens guard can't see, so this fixture is built entirely
from fabricated values via public_corpus.support.synthetic -- no bytes
are copied from any capture, private test, or real DIAG log.

Layout transcribed from diaggrok.parsers.diag_0x19eb (docstring +
parse_0x19eb), not from any capture:

    data[0]      u8  version = 0x01                     (Layer-1 gate)
    data[1:32]   raw_header (31 B)                       -- opaque, filled with a
                 fabricated repeating byte pattern; not asserted field-by-field
    data[32:102] one 70B per-SV slot (entry_count = (n-32)//70 = 1):
        slot[0]  u8 prn               -- GPS PRN, 1..32 when populated
        slot[1]  u8 valid_flag        -- 0x05 == populated L5 measurement marker
        slot[2]  u8 cn0_quarter_db    -- CN0 x4 in quarter-dB-Hz
        slot[3]  u8 cn0_b3_quarter    -- duplicated CN0 candidate
        slot[18:22] f32 LE frac_18    -- normalized [0,1] per-epoch field
        slot[26:30] f32 LE doppler_hz       -- L5 carrier Doppler (Hz)
        slot[57:61] f32 LE doppler_hz_b     -- duplicated Doppler (== doppler_hz)
    (remaining slot bytes zero-filled; not asserted on)
"""
import struct

from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x19eb import parse_0x19eb

_VERSION = 0x01

# Header is 32B total: byte 0 is the version gate above, bytes [1:32] are the
# raw_header tail -- filled with a fabricated repeating pattern (0xAB), not
# copied from any capture.
_HEADER_FILL = 0xAB

# --- one fabricated populated L5 slot ---
_PRN = 14                     # fabricated GPS PRN (1..32 range required for `populated`)
_VALID_FLAG = 0x05            # populated-slot marker (parser constant _VALID_FLAG_POPULATED)
_CN0_QUARTER = 128             # u8 -> cn0_db_hz = 128 / 4.0 = 32.0 dB-Hz
_CN0_B3_QUARTER = 128          # duplicated CN0 candidate, chosen equal per the documented ~98% b3==b2 pattern
_FRAC_18 = 0.375               # fabricated normalized [0,1] value, exactly representable as f32
_DOPPLER_HZ = -482.5           # fabricated Doppler (Hz), exactly representable as f32
_DOPPLER_HZ_B = -482.5         # duplicated Doppler -- parser reads the same value from a second offset


def _synthetic_19eb() -> bytes:
    header = pack('<B', _VERSION) + bytes([_HEADER_FILL] * 31)
    assert len(header) == 32

    slot = bytearray(70)
    slot[0] = _PRN
    slot[1] = _VALID_FLAG
    slot[2] = _CN0_QUARTER
    slot[3] = _CN0_B3_QUARTER
    struct.pack_into('<f', slot, 18, _FRAC_18)
    struct.pack_into('<f', slot, 26, _DOPPLER_HZ)
    struct.pack_into('<f', slot, 57, _DOPPLER_HZ_B)

    data = header + bytes(slot)
    assert len(data) == 102
    return data


def test_19eb_decodes_synthetic_populated_slot():
    rec = parse_0x19eb(1000, _synthetic_19eb())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.payload_size == 102
    assert rec.entry_count == 1
    assert len(rec.raw_header) == 32
    assert rec.raw_header[0] == _VERSION
    assert rec.raw_header[1:] == bytes([_HEADER_FILL] * 31)

    entry = rec.entries[0]
    assert entry.prn == _PRN
    assert entry.valid_flag == _VALID_FLAG
    assert entry.populated is True   # valid_flag == 0x05 and 1 <= prn <= 32
    assert entry.cn0_quarter_db == _CN0_QUARTER
    assert entry.cn0_b3_quarter == _CN0_B3_QUARTER
    # cn0_db_hz = cn0_quarter_db / 4.0
    assert entry.cn0_db_hz == 32.0
    assert entry.doppler_hz == _DOPPLER_HZ
    assert entry.doppler_hz_b == _DOPPLER_HZ_B
    assert entry.frac_18 == _FRAC_18
    assert len(entry.raw) == 70


def test_19eb_sentinel_slot_has_none_measurement_fields():
    # A second, non-populated (sentinel) slot: valid_flag != 0x05 -> the
    # parser leaves all derived measurement fields as None.
    header = pack('<B', _VERSION) + bytes([_HEADER_FILL] * 31)
    sentinel = bytearray(70)
    sentinel[0] = 0        # prn == 0 -> outside the 1..32 populated range anyway
    sentinel[1] = 0x00     # not the 0x05 populated marker
    data = header + bytes(sentinel)
    assert len(data) == 102

    rec = parse_0x19eb(1000, data)
    assert rec is not None
    entry = rec.entries[0]
    assert entry.populated is False
    assert entry.cn0_db_hz is None
    assert entry.doppler_hz is None
    assert entry.doppler_hz_b is None
    assert entry.frac_18 is None
