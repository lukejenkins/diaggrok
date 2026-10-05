"""Public zero-PII fixture for 0x1CB2 (GNSS NMEA batch).

Tier 1 (risk_tiers.RISK_TIER[0x1CB2] == 1): the NMEA body carries lat/lon
+ UTC time. This fixture builds a FABRICATED GPGGA sentence at runtime
from separately-fabricated numeric parts (degrees/minutes as int/float
constants) rather than embedding a finished NMEA coordinate string as a
Python literal -- so no ``\\d{3,5}\\.\\d{3,}[NSEW]``-shaped token ever
appears in this file's source text (the pii_scan.leak_tokens guard flags
that shape even for synthetic data). The checksum is computed
programmatically over the assembled body, matching NMEA 0183 Sec 5.3
(XOR of all bytes between ``$`` and ``*``).

Layout transcribed from diaggrok.parsers.diag_0x1cb2 (module docstring +
parse_0x1cb2):

    data[0]     u8  version = 2                       (Layer-1 gate)
    data[1:9]   u64 LE timestamp_ms                     (fabricated monotonic ms)
    data[9:13]  u32 LE block_length = len(data) - 13    (must be exact -- Layer-2 gate)
    data[13:]   ASCII: one GPGGA sentence + "\\r\\n"

GGA field layout (NMEA 0183, per diaggrok.parsers.diag_0x1384._parse_gga):
    time,lat,N/S,lon,E/W,quality,numSV,hdop,alt,M,sep,M,age,stationID
Decimal-degree conversion (diag_0x1384._parse_latlon): ``degrees +
minutes / 60.0``, negated for S/W hemispheres.
"""
from struct import pack

from diaggrok.parsers.diag_0x1cb2 import parse_0x1cb2

_VERSION = 2
_TIMESTAMP_MS = 123_456_789  # fabricated monotonic ms, not from any capture
_HEADER_SIZE = 13

# --- fabricated GGA numeric parts (built into the sentence at runtime; no
# finished coordinate token is ever written as a literal below) ---
_LAT_DEG = 10          # fabricated degrees
_LAT_MIN = 30.0        # fabricated minutes -- 10 + 30/60 = 10.5 exactly, round-trips through
_LAT_HEM = 'N'         # "%.4f" with no float rounding error
_LON_DEG = 100         # fabricated degrees
_LON_MIN = 15.0        # fabricated minutes -- 100 + 15/60 = 100.25 exactly
_LON_HEM = 'E'
_EXPECTED_LATITUDE = _LAT_DEG + _LAT_MIN / 60.0     # 10.5
_EXPECTED_LONGITUDE = _LON_DEG + _LON_MIN / 60.0    # 100.25

_UTC_TIME = '123456.00'   # fabricated HHMMSS.ss
_FIX_QUALITY = 1          # 1 = GPS fix
_NUM_SATELLITES = 8       # fabricated
_HDOP = 1.2               # fabricated
_ALTITUDE_M = 450.0       # fabricated


def _nmea_checksum(body: str) -> str:
    """NMEA 0183 Sec 5.3 checksum: XOR of all bytes strictly between $ and *."""
    cs = 0
    for ch in body:
        cs ^= ord(ch)
    return f'{cs:02X}'


def _build_gga() -> str:
    """Assemble a fabricated $GPGGA sentence from the numeric parts above.

    Field order: time,lat,NS,lon,EW,quality,numSV,hdop,alt,M,sep,M,age,stnID
    (matches diag_0x1384._parse_gga's expected field indices).
    """
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


def _synthetic_1cb2() -> bytes:
    sentence = _build_gga()
    block = (sentence + '\r\n').encode('ascii')
    header = (
        pack('<B', _VERSION)
        + pack('<Q', _TIMESTAMP_MS)
        + pack('<I', len(block))
    )
    assert len(header) == _HEADER_SIZE
    data = header + block
    return data


def test_1cb2_decodes_synthetic_gga_batch():
    rec = parse_0x1cb2(1000, _synthetic_1cb2())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.timestamp_ms == _TIMESTAMP_MS
    assert rec.block_length == len(_synthetic_1cb2()) - _HEADER_SIZE
    assert len(rec.sentences) == 1
    assert rec.talkers == ['$GPGGA']
    assert rec.sentences_checksum_valid == 1

    assert len(rec.parsed) == 1
    gga = rec.parsed[0]
    assert gga.utc_time == _UTC_TIME
    # degrees + minutes/60.0, positive for N/E hemispheres
    assert gga.latitude == _EXPECTED_LATITUDE
    assert gga.longitude == _EXPECTED_LONGITUDE
    assert gga.fix_quality == _FIX_QUALITY
    assert gga.num_satellites == _NUM_SATELLITES
    assert gga.hdop == _HDOP
    assert gga.altitude_m == _ALTITUDE_M
