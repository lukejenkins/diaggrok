"""Public zero-PII fixture for 0x14FD (GNSS data report).

Tier 1 (synthetic-only): both variants carry the serving-cell key and a
position (location PII); see public_corpus.risk_tiers.RISK_TIER
[0x14FD] == 1. So EVERY frame here is built from fabricated values via
public_corpus.support.synthetic -- no bytes (and, critically, no real
coordinates) are copied from any capture, private test, or real DIAG log.

Covers both documented variants (field-map at the top of
diaggrok.parsers.diag_0x14fd):
  * 218B / v=0x08: TLE serving-cell record — cell identity (MCC/MNC/TAC-or-LAC/
    RAT/cell id + LTE PCI/EARFCN or GSM ARFCN/BSIC/band), GPS-time <-> slow-clock
    anchor, the serving cell's learned position (i32 lat/lon, i16 alt), and the
    auxiliary block. Cell identity is location-identifying and the cell position
    is a location, so every value here is fabricated (MCC 001 / MNC 01 is the
    ITU test network).
  * 391B / v=0x0a: the GNSS fix handed to the TLE, tagged with the serving cell
    — cell identity (MCC [2:4] / MNC / TAC / cell id / PCI / EARFCN), the fix
    (lat/lon/alt f32 [43:55], horizontal/vertical uncertainty, fix_valid_mask
    gating velocity and the time/leap block, speed, heading, GPS week/ms) and a
    14-slot percentage contribution split. Identity and position are both
    location-identifying, so every value here is fabricated.
"""
import pytest

from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x14fd import parse_0x14fd

# Fabricated values (not from any real capture). Offsets transcribed from
# the parser's own field-map docstring in diag_0x14fd.py.
_VERSION = 0x08   # byte 0 -- 218B variant (0x0a selects the 391B variant)
_STATE = 0x05     # byte 1 -- RF/state-dependent discriminator
_BYTE2 = 0x00     # byte 2
_BYTE3 = 0x00     # byte 3 -- 0x00 on the 218B variant (0x01 on 391B)
_BODY_LEN = 214   # 218B total - 4B header


def _synthetic_14fd() -> bytes:
    """Build the 218-byte 0x14FD payload: 4-byte header + opaque zero body,
    per the "218B variant: byte0=0x08, byte3=0x00" corpus decomposition."""
    header = pack('<B', _VERSION) + pack('<B', _STATE) + pack('<B', _BYTE2) + pack('<B', _BYTE3)
    assert len(header) == 4
    body = bytes(_BODY_LEN)
    payload = header + body
    assert len(payload) == 218
    return payload


def test_14fd_decodes_synthetic_frame():
    rec = parse_0x14fd(1000, _synthetic_14fd())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.state == _STATE
    assert rec.byte2 == _BYTE2
    assert rec.byte3 == _BYTE3
    assert rec.payload_size == 218
    assert rec.body_raw == bytes(_BODY_LEN)
    # 218B variant has no v0x0a fix block ...
    assert rec.latitude_deg is None
    assert rec.position_valid is None
    # ... and an all-zero body decodes to empty / invalid v0x08 blocks.
    assert rec.rat == 0
    assert rec.pci is None and rec.arfcn is None  # unknown RAT: no RAT-specific fields
    assert rec.cell_pos_valid is False
    assert rec.time_anchor_valid is False


# --- 218B / v=0x08 TLE serving-cell record (fabricated values) ----------------
_V08_MCC = 1            # ITU test network 001-01
_V08_MNC = 1
_V08_TAC = 0x1234
_V08_ECI = 0x0ABCDE1    # fabricated 28-bit cell identity
_V08_PCI = 123
_V08_EARFCN = 66786     # > 65535: exercises the u32 width (Band-66 range)
_V08_GPS_WEEK = 2400
_V08_GPS_MS = 123456789
_V08_SLOW_CLOCK = 987654321
_V08_CELL_LAT = 12.3456   # fabricated, obviously-not-real coordinates
_V08_CELL_LON = -65.4321
_V08_CELL_ALT = 111
_V08_TICK_MS = 4242424     # a GPS ms-of-week when the time type is 1
_V08_TIME_UNC_NS = 1207651 # anchor time uncertainty, ns (1.207651 ms)
_V08_AUX1_LAT = 12.3500
_V08_AUX1_LON = -65.4300
_V08_AUX2_LAT = 38.0      # the TLE's MCC-level default slot value
_V08_AUX2_LON = -117.0
_V08_LAT_SCALE = 180.0 / 2**32
_V08_LON_SCALE = 360.0 / 2**32


def _synthetic_14fd_v08(*, rat: int = 3, cell_pos: bool = True,
                        time_anchor: bool = True) -> bytes:
    """Build a 218-byte v=0x08 serving-cell record at the documented offsets."""
    buf = bytearray(218)
    buf[0:4] = pack('<BBBB', 0x08, 0x05, 0x02, 0x00)
    buf[4:10] = pack('<HHH', _V08_MCC, _V08_MNC, _V08_TAC)
    buf[10] = rat
    buf[11] = 0x07
    buf[12:16] = pack('<I', _V08_ECI)
    if rat == 3:
        buf[30:38] = pack('<II', _V08_PCI, _V08_EARFCN)
    elif rat == 1:
        buf[30:34] = pack('<HBB', 685, 45, 2)   # ARFCN, BSIC, band
    if time_anchor:
        buf[45:51] = pack('<IH', _V08_GPS_MS, _V08_GPS_WEEK)
        buf[55:59] = pack('<I', _V08_TIME_UNC_NS)
        buf[74:78] = pack('<I', _V08_SLOW_CLOCK)
    if cell_pos:
        buf[88:98] = pack('<iih', round(_V08_CELL_LAT / _V08_LAT_SCALE),
                          round(_V08_CELL_LON / _V08_LON_SCALE), _V08_CELL_ALT)
        buf[101] = 1                            # time type: GPS ms-of-week
        buf[102:108] = pack('<IH', _V08_TICK_MS, _V08_GPS_WEEK)
    buf[157:173] = pack('<iiii',
                        round(_V08_AUX1_LAT / _V08_LAT_SCALE),
                        round(_V08_AUX2_LAT / _V08_LAT_SCALE),
                        round(_V08_AUX1_LON / _V08_LON_SCALE),
                        round(_V08_AUX2_LON / _V08_LON_SCALE))
    buf[187] = 1
    buf[188:194] = pack('<IH', _V08_TICK_MS, _V08_GPS_WEEK)
    buf[207:209] = pack('<H', _V08_TAC)
    return bytes(buf)


def test_14fd_v08_lte_serving_cell_record():
    rec = parse_0x14fd(3000, _synthetic_14fd_v08())
    assert rec is not None
    assert rec.version == 0x08
    assert (rec.mcc, rec.mnc, rec.tac_lac) == (_V08_MCC, _V08_MNC, _V08_TAC)
    assert rec.rat == 3
    assert rec.cell_id == _V08_ECI
    assert rec.pci == _V08_PCI
    assert rec.earfcn == _V08_EARFCN
    assert rec.arfcn is None and rec.bsic is None and rec.gsm_band is None
    assert rec.time_anchor_valid is True
    assert rec.time_anchor_gps_week == _V08_GPS_WEEK
    assert rec.time_anchor_gps_ms == _V08_GPS_MS
    assert rec.time_anchor_slow_clock == _V08_SLOW_CLOCK
    assert rec.time_anchor_unc_ns == _V08_TIME_UNC_NS
    assert rec.cell_pos_valid is True
    assert rec.cell_lat_deg == pytest.approx(_V08_CELL_LAT, abs=1e-6)
    assert rec.cell_lon_deg == pytest.approx(_V08_CELL_LON, abs=1e-6)
    assert rec.cell_alt_m == _V08_CELL_ALT
    assert rec.cell_pos_time_type == 1
    assert rec.cell_pos_time_ms == _V08_TICK_MS
    assert rec.cell_pos_gps_week == _V08_GPS_WEEK
    assert rec.aux1_lat_deg == pytest.approx(_V08_AUX1_LAT, abs=1e-6)
    assert rec.aux1_lon_deg == pytest.approx(_V08_AUX1_LON, abs=1e-6)
    assert rec.aux2_lat_deg == pytest.approx(_V08_AUX2_LAT, abs=1e-6)
    assert rec.aux2_lon_deg == pytest.approx(_V08_AUX2_LON, abs=1e-6)
    assert rec.aux_time_type == 1
    assert rec.aux_time_ms == _V08_TICK_MS
    assert rec.aux_time_gps_week == _V08_GPS_WEEK
    assert rec.aux_tac_lac == _V08_TAC
    # v0x0a-only fix fields stay None on a v0x08 record.
    assert rec.latitude_deg is None and rec.position_valid is None
    d = rec.to_dict()
    assert d['earfcn'] == _V08_EARFCN and d['pci'] == _V08_PCI
    assert 'arfcn' not in d
    assert d['cell_lat_deg'] == rec.cell_lat_deg


def test_14fd_v08_gsm_serving_cell_record():
    rec = parse_0x14fd(3000, _synthetic_14fd_v08(rat=1))
    assert rec.rat == 1
    assert (rec.arfcn, rec.bsic, rec.gsm_band) == (685, 45, 2)
    assert rec.pci is None and rec.earfcn is None
    d = rec.to_dict()
    assert d['arfcn'] == 685 and 'earfcn' not in d


def test_14fd_v08_empty_blocks_are_invalid_not_garbage():
    rec = parse_0x14fd(3000, _synthetic_14fd_v08(cell_pos=False, time_anchor=False))
    assert rec.cell_pos_valid is False
    assert rec.cell_lat_deg == 0.0 and rec.cell_lon_deg == 0.0
    assert rec.time_anchor_valid is False
    assert rec.time_anchor_gps_week == 0
    assert rec.time_anchor_unc_ns == 0
    assert rec.cell_pos_time_type == 0
    # identity still decodes independently of the empty blocks
    assert rec.cell_id == _V08_ECI


def test_14fd_v08_position_on_the_equator_is_still_valid():
    # The no-fix sentinel is "lat AND lon both zero" (the whole block zeroed);
    # a real cell position with exactly one zero coordinate must stay valid.
    buf = bytearray(_synthetic_14fd_v08())
    buf[88:92] = pack('<i', 0)                 # latitude exactly 0 (equator)
    rec = parse_0x14fd(3000, bytes(buf))
    assert rec.cell_lat_deg == 0.0
    assert rec.cell_lon_deg == pytest.approx(_V08_CELL_LON, abs=1e-6)
    assert rec.cell_pos_valid is True


def test_14fd_v08_unknown_rat_leaves_rat_specific_bytes_raw():
    rec = parse_0x14fd(3000, _synthetic_14fd_v08(rat=2))
    assert rec.rat == 2
    assert rec.pci is None and rec.earfcn is None and rec.arfcn is None
    assert rec.mcc == _V08_MCC


def test_14fd_v08_truncated_frame_returns_none():
    # v5: a truncated frame fails LOUDLY (None ->
    # registry WARN) instead of degrading silently to a header-only record.
    payload = _synthetic_14fd_v08()
    assert parse_0x14fd(3000, payload) is not None
    assert parse_0x14fd(3000, payload[:120]) is None
    assert parse_0x14fd(3000, payload[:-1]) is None


# --- 391B / v=0x0a fix-tagged serving-cell record (fabricated values) -------
_V0A_VERSION = 0x0a
_V0A_STATE = 0x05
_V0A_MCC = 1            # ITU test network 001-01 (byte2/byte3 = MCC low/high)
_V0A_MNC = 1
_V0A_TAC = 0x1234
_V0A_ECI = 0x0ABCDE1    # fabricated 28-bit cell identity
_V0A_PCI = 123
_V0A_EARFCN = 66786     # > 65535: exercises the u32 width (Band-66 range)
# Fabricated, obviously-not-real coordinates (mid-Atlantic null island vicinity)
# — no real captured position is ever committed (location PII).
_SYN_LAT = 12.3456
_SYN_LON = -65.4321
_SYN_ALT = 111.5
_SYN_HUNC = 32.5
_SYN_VUNC = 13.25
_SYN_SPEED = 7.75
_SYN_HEADING = 4.75     # radians
_SYN_WEEK = 2400
_SYN_MS = 123456449
_SYN_CONTRIB = [0, 0, 76, 24] + [0] * 10   # 14 slots summing to 100
_SYN_LEAP = 18


def _synthetic_14fd_v0a(*, fix: bool = True, mask: int = 0x07,
                        mcc: int = _V0A_MCC) -> bytes:
    """Build a 391-byte v=0x0a frame at the documented offsets. With
    ``fix=False`` it mirrors the corpus no-fix record: the serving-cell identity
    is present and everything from [43] is zero. ``mask`` is fix_valid_mask
    [63] and gates the velocity / time blocks."""
    buf = bytearray(391)
    buf[0:2] = pack('<BB', _V0A_VERSION, _V0A_STATE)
    buf[2:4] = pack('<H', mcc)
    buf[4:12] = pack('<HHI', _V0A_MNC, _V0A_TAC, _V0A_ECI)
    buf[12] = 0x04
    buf[35:43] = pack('<HHI', _V0A_PCI, _V0A_TAC, _V0A_EARFCN)
    if not fix:
        return bytes(buf)
    buf[43:63] = pack('<fffff', _SYN_LAT, _SYN_LON, _SYN_ALT, _SYN_HUNC, _SYN_VUNC)
    buf[63] = mask
    if mask & 0x02:
        buf[65:69] = pack('<f', _SYN_SPEED)
        buf[73:77] = pack('<f', _SYN_HEADING)
    buf[81:87] = pack('<HI', _SYN_WEEK, _SYN_MS)
    buf[89:103] = bytes(_SYN_CONTRIB)
    if mask & 0x04:
        buf[103] = _SYN_LEAP
        buf[105] = 1
        buf[106:112] = pack('<IH', _SYN_MS, _SYN_WEEK)
    buf[114:116] = b'\x02\x01'
    return bytes(buf)


def test_14fd_v0a_decodes_synthetic_fix_and_cell():
    rec = parse_0x14fd(2000, _synthetic_14fd_v0a())
    assert rec is not None
    assert rec.version == _V0A_VERSION
    assert rec.payload_size == 391
    # serving-cell identity
    assert (rec.mcc, rec.mnc, rec.tac_lac) == (_V0A_MCC, _V0A_MNC, _V0A_TAC)
    assert (rec.byte2, rec.byte3) == (_V0A_MCC & 0xff, _V0A_MCC >> 8)
    assert rec.cell_id == _V0A_ECI
    assert (rec.pci, rec.earfcn) == (_V0A_PCI, _V0A_EARFCN)
    assert rec.rat is None and rec.arfcn is None   # v0x08-only fields
    # the fix
    assert rec.latitude_deg == pytest.approx(_SYN_LAT, abs=1e-4)
    assert rec.longitude_deg == pytest.approx(_SYN_LON, abs=1e-4)
    assert rec.altitude_m == pytest.approx(_SYN_ALT, abs=1e-3)
    assert rec.position_valid is True
    assert rec.hor_unc_m == pytest.approx(_SYN_HUNC)
    assert rec.vert_unc_m == pytest.approx(_SYN_VUNC)
    assert rec.fix_valid_mask == 0x07
    assert rec.speed_mps == pytest.approx(_SYN_SPEED)
    assert rec.heading_rad == pytest.approx(_SYN_HEADING)
    assert (rec.fix_gps_week, rec.fix_gps_ms) == (_SYN_WEEK, _SYN_MS)
    assert rec.contrib_pct == _SYN_CONTRIB and sum(rec.contrib_pct) == 100
    assert rec.leap_seconds == _SYN_LEAP
    # v0x08-only blocks stay None on a v0x0a record
    assert rec.time_anchor_valid is None and rec.cell_lat_deg is None
    d = rec.to_dict()
    assert d['latitude_deg'] == rec.latitude_deg
    assert d['earfcn'] == _V0A_EARFCN and d['cell_id'] == _V0A_ECI
    assert d['contrib_pct'] == _SYN_CONTRIB
    assert 'cell_lat_deg' not in d and 'rat' not in d


def test_14fd_v0a_mask_gates_velocity_and_leap():
    # mask 5 (no velocity bit): the zero-filled [65:81] is "not reported", not
    # a measured 0 m/s; mask 1 (position only): no leap block either.
    rec5 = parse_0x14fd(2000, _synthetic_14fd_v0a(mask=0x05))
    assert rec5.speed_mps is None and rec5.heading_rad is None
    assert rec5.leap_seconds == _SYN_LEAP
    rec1 = parse_0x14fd(2000, _synthetic_14fd_v0a(mask=0x01))
    assert rec1.speed_mps is None and rec1.leap_seconds is None
    assert rec1.position_valid is True
    assert rec1.fix_gps_week == _SYN_WEEK   # the fix time is not bit2-gated


def test_14fd_v0a_no_fix_record_still_names_the_cell():
    rec = parse_0x14fd(2000, _synthetic_14fd_v0a(fix=False))
    assert rec is not None
    assert rec.version == _V0A_VERSION
    assert rec.cell_id == _V0A_ECI and rec.earfcn == _V0A_EARFCN
    assert rec.latitude_deg == 0.0
    assert rec.longitude_deg == 0.0
    assert rec.position_valid is False
    assert rec.fix_valid_mask == 0
    assert rec.contrib_pct == [0] * 14
    assert rec.speed_mps is None and rec.leap_seconds is None


def test_14fd_v0a_non_us_mcc_is_not_an_invariant_violation():
    # byte3 is the MCC high byte on v0x0a: MCC 724 -> byte3 0x02. v3 pinned
    # byte3 to {0x00, 0x01}, which would have flagged every such record.
    from diaggrok.registry import check_invariants, parser_info
    rec = parse_0x14fd(2000, _synthetic_14fd_v0a(mcc=724))
    assert rec.mcc == 724 and rec.byte3 == 0x02
    assert check_invariants(parser_info(0x14FD), rec) == []


def test_14fd_v0a_truncated_frame_returns_none():
    # v5: see the v08 counterpart above.
    payload = _synthetic_14fd_v0a()
    assert parse_0x14fd(2000, payload) is not None
    assert parse_0x14fd(2000, payload[:200]) is None
    assert parse_0x14fd(2000, payload[:-1]) is None
    for n in range(len(payload)):
        parse_0x14fd(2000, payload[:n])  # never raises
