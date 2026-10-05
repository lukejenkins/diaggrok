"""Public zero-PII fixture for 0x1C90 (GNSS Client API SV Report, v0x06).

Tier 1 (risk_tiers.RISK_TIER[0x1C90] == 1): the never-zeroed slots past
``sv_count`` carry leftover AP heap text, including plaintext NMEA with a
real position. This fixture builds a FABRICATED GPGGA sentence at runtime
from separately-fabricated numeric parts (degrees/minutes as int/float
constants), never as a finished coordinate string literal -- so no
``\\d{3,5}\\.\\d{3,}[NSEW]``-shaped token appears in this file's source text
(the pii_scan.leak_tokens guard flags that shape even for synthetic data).
The checksum is computed programmatically, matching NMEA 0183 Sec 5.3.

Layout transcribed from diaggrok.parsers.diag_0x1c90:

    data[0]     u8  version = 0x06
    data[1:5]   u32 LE sv_count (0..176)
    data[5:]    176 x 38-byte GnssSv slots, first sv_count live:
                <H I f f f H f I d H> sv_id, constellation, cn0, elevation,
                azimuth, options_mask, carrier_frequency_hz,
                signal_type_mask, baseband_cn0, glo_frequency
    total size  6693 B = 5 + 176*38
"""
from struct import pack

from diaggrok.parsers.diag_0x1c90 import (
    EXPECTED_VERSION_1C90, PAYLOAD_LEN, SV_SLOT_LEN, parse_0x1c90,
)

# --- fabricated SV slots: (sv_id, constellation, cn0, elev, az, options,
# carrier_hz, signal_mask, baseband_cn0, glo_frequency) ---
_SVS = (
    (5, 1, 40.0, 30.0, 120.0, 0xDF, 1575.42e6, 0x01, 36.0, 0),   # GPS L1, used in fix
    (70, 3, 30.0, 10.0, 200.0, 0xDA, 1602.0e6, 0x10, 26.0, 8),   # GLONASS k=0, not used
)

# --- fabricated GGA numeric parts (assembled into the sentence at runtime;
# no finished coordinate token is ever written as a literal below) ---
_LAT_DEG = 45          # fabricated degrees
_LAT_MIN = 12.0        # fabricated minutes -- 45 + 12/60 = 45.2 exactly
_LAT_HEM = 'N'
_LON_DEG = 122         # fabricated degrees
_LON_MIN = 6.0         # fabricated minutes -- 122 + 6/60 = 122.1 exactly
_LON_HEM = 'W'
_UTC_TIME = '090000.00'
_FIX_QUALITY = 1
_NUM_SATELLITES = 6
_HDOP = 0.9
_ALTITUDE_M = 30.0


def _nmea_checksum(body: str) -> str:
    """NMEA 0183 Sec 5.3 checksum: XOR of all bytes strictly between $ and *."""
    cs = 0
    for ch in body:
        cs ^= ord(ch)
    return f'{cs:02X}'


def _build_gga() -> str:
    lat_field = f'{_LAT_DEG:02d}{_LAT_MIN:07.4f}'
    lon_field = f'{_LON_DEG:03d}{_LON_MIN:07.4f}'
    body = (
        'GPGGA,' + _UTC_TIME + ','
        + lat_field + ',' + _LAT_HEM + ','
        + lon_field + ',' + _LON_HEM + ','
        + str(_FIX_QUALITY) + ',' + str(_NUM_SATELLITES) + ','
        + f'{_HDOP:.1f}' + ',' + f'{_ALTITUDE_M:.1f}' + ',M,'
        + '0.0,M,,'
    )
    return '$' + body + '*' + _nmea_checksum(body)


def _synthetic_1c90() -> bytes:
    header = pack('<BI', EXPECTED_VERSION_1C90, len(_SVS))
    slots = b''.join(pack('<HIfffHfIdH', *sv) for sv in _SVS)
    assert len(slots) == len(_SVS) * SV_SLOT_LEN
    # Stale residue past the live slots: the fabricated GGA, then zeros
    # (deliberately NOT ascii, so nothing else looks NMEA-shaped).
    stale = _build_gga().encode('ascii') + b'\r\n'
    data = header + slots + stale
    data += bytes(PAYLOAD_LEN - len(data))
    assert len(data) == PAYLOAD_LEN
    return data


def test_1c90_decodes_synthetic_sv_report():
    rec = parse_0x1c90(1000, _synthetic_1c90())
    assert rec is not None
    assert rec.version == EXPECTED_VERSION_1C90
    assert rec.sv_count == 2
    assert rec.payload_size == PAYLOAD_LEN

    gps, glo = rec.to_dict()['svs']
    assert gps['sv_id'] == 5 and gps['constellation_name'] == 'GPS'
    assert gps['cn0_dbhz'] == 40.0 and gps['elevation_deg'] == 30.0 and gps['azimuth_deg'] == 120.0
    assert gps['used_in_fix'] is True
    assert gps['signal_types'] == ['GPS_L1CA']
    assert abs(gps['carrier_frequency_hz'] - 1575.42e6) < 100   # f32 precision
    assert glo['constellation_name'] == 'GLONASS'
    assert glo['used_in_fix'] is False and glo['glo_frequency'] == 8
    assert glo['signal_types'] == ['GLONASS_G1']
    assert rec.to_dict()['used_in_fix_count'] == 1


def test_1c90_nmea_only_from_stale_tail():
    rec = parse_0x1c90(1000, _synthetic_1c90())
    assert rec.nmea_sentences == (_build_gga(),)
    assert rec.nmea_talkers == ('$GPGGA',)
    d = rec.to_dict()
    assert d['nmea_sentence_count'] == 1
    assert d['stale_tail_len'] == PAYLOAD_LEN - 5 - 2 * SV_SLOT_LEN


def test_1c90_rejects_sv_count_past_array():
    bad = bytearray(_synthetic_1c90())
    bad[1:5] = pack('<I', 177)
    assert parse_0x1c90(0, bytes(bad)) is None


def test_1c90_truncated_returns_none_5171():
    # The 176-slot array is fixed-size; a payload one
    # byte short (or halved) is truncated and must return None, never raise.
    good = _synthetic_1c90()
    assert parse_0x1c90(0, good) is not None
    assert parse_0x1c90(0, good[:-1]) is None
    assert parse_0x1c90(0, good[: len(good) // 2]) is None
    assert parse_0x1c90(0, good + bytes(4)) is not None
