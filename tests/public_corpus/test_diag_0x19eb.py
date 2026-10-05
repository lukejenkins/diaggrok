"""Public zero-PII fixture for 0x19EB (GNSS GPS L5 per-SV measurement report).

Tier 1 (risk_tiers.RISK_TIER[0x19EB] == 1): each 70B slot keeps its full
bytes as ``raw`` alongside the decoded fields, and the 32B header is kept
raw as ``raw_header`` too. A real byte snippet of either region could carry
unknown PII the text-only leak_tokens guard can't see, so this fixture is
built entirely from fabricated values via public_corpus.support.synthetic --
no bytes are copied from any capture, private test, or real DIAG log.

Layout transcribed from diaggrok.parsers.diag_0x19eb:
the per-SV 70B slot is the SAME struct as 0x1477's GpsSv (L1), preceded by
a 32B header.

    data[0]      u8  version = 0x01                     (Layer-1 gate; L1 0x1477 is 0x00)
    data[1:32]   header tail (<IHIffffIB) -- f_count, gps_week, gps_ms,
                 time_bias, clock_time_unc, clock_freq_bias, clock_freq_unc,
                 l5_reserved(u32), sv_count(u8); fabricated, mostly not asserted
    data[32:102] one 70B per-SV slot (entry_count = (n-32)//70 = 1), the
                 shared 0x1477 GpsSv struct <BBBBHBHhBHIffffIBIffiHffBI:
        slot[0]     u8  sv_id (PRN)          -- 1..32 when populated
        slot[1]     u8  observation_state    -- 5/7 measured, 0/1 candidate/acquiring
        slot[7:9]   u16 carrier_noise        -- CN0, x0.01 dB-Hz
        slot[14:18] u32 unfiltered_meas_integral   -- pseudorange integer ms
        slot[18:22] f32 unfiltered_meas_fraction   -- pseudorange fractional ms [0,1]
        slot[26:30] f32 unfiltered_speed     -- raw range-rate m/s
        slot[43:47] f32 azimuth (radians)
        slot[47:51] f32 elevation (radians)
    (remaining slot bytes zero-filled; not asserted on)
"""
import math
import struct

from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x19eb import parse_0x19eb

_VERSION = 0x01
_HEADER_FILL = 0xAB   # fabricated fill for the header tail, not from any capture

# --- one fabricated populated (tracking-locked) L5 slot ---
_PRN = 14                        # fabricated GPS PRN (1..32 required for `populated`)
_OBS_STATE = 0x05                # tracking-locked state (SDX55/62; SDX65 M3100 uses 7)
_CARRIER_NOISE = 3200            # u16 -> cn0 = 3200 * 0.01 = 32.0 dB-Hz
_PR_INTEGRAL = 393323348         # u32 fabricated pseudorange integer ms
_PR_FRACTION = 0.375             # f32 pseudorange fractional ms, exactly representable
_RANGE_RATE = -482.5             # f32 raw range-rate m/s, exactly representable
_AZ_RAD = 1.5                    # f32 azimuth in radians (~85.9 deg)
_EL_RAD = 0.5                    # f32 elevation in radians (~28.6 deg)


def _synthetic_19eb(obs_state: int = _OBS_STATE, prn: int = _PRN) -> bytes:
    header = pack('<B', _VERSION) + bytes([_HEADER_FILL] * 31)
    assert len(header) == 32

    slot = bytearray(70)
    slot[0] = prn
    slot[1] = obs_state
    struct.pack_into('<H', slot, 7, _CARRIER_NOISE)
    struct.pack_into('<I', slot, 14, _PR_INTEGRAL)
    struct.pack_into('<f', slot, 18, _PR_FRACTION)
    struct.pack_into('<f', slot, 26, _RANGE_RATE)
    struct.pack_into('<f', slot, 43, _AZ_RAD)
    struct.pack_into('<f', slot, 47, _EL_RAD)

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

    entry = rec.entries[0]
    assert entry.prn == _PRN
    assert entry.observation_state == _OBS_STATE
    # in_report (header sv_count byte == 0xAB fill >= 1), CN0 > 0, 1 <= prn <= 32
    assert entry.in_report is True
    assert entry.populated is True
    # CN0 is carrier_noise * 0.01 (offset 7-8), the same scale as 0x1477 L1.
    assert entry.cn0_db_hz == 32.0
    assert len(entry.raw) == 70

    d = entry.to_dict()
    assert d["prn"] == _PRN
    assert d["cno_db"] == 32.0
    assert d["pseudorange_ms_integral"] == _PR_INTEGRAL
    assert abs(d["pseudorange_ms_fraction"] - _PR_FRACTION) < 1e-6
    assert abs(d["speed_raw_mps"] - _RANGE_RATE) < 1e-3
    assert abs(d["az_deg"] - math.degrees(_AZ_RAD)) < 1e-3
    assert abs(d["el_deg"] - math.degrees(_EL_RAD)) < 1e-3


def test_19eb_sentinel_slot_has_none_measurement_fields():
    # A non-populated (sentinel) slot: PRN 0 is not a GPS PRN -> the parser
    # leaves cn0_db_hz None and emits no measurement keys in the entry dict.
    data = _synthetic_19eb(obs_state=0x00, prn=0)
    rec = parse_0x19eb(1000, data)
    assert rec is not None
    entry = rec.entries[0]
    assert entry.populated is False
    assert entry.cn0_db_hz is None
    assert "cno_db" not in entry.to_dict()
