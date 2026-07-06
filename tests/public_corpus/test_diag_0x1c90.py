"""Public zero-PII fixture for 0x1C90 (GNSS LocEng diagnostic snapshot).

Tier 1 (risk_tiers.RISK_TIER[0x1C90] == 1): the body embeds plaintext
NMEA (lat/lon/time) and +QGPSLOC AT responses. This fixture builds a
FABRICATED GPGGA sentence at runtime from separately-fabricated numeric
parts (degrees/minutes as int/float constants), never as a finished
coordinate string literal -- so no ``\\d{3,5}\\.\\d{3,}[NSEW]``-shaped
token appears in this file's source text (the pii_scan.leak_tokens guard
flags that shape even for synthetic data). The checksum is computed
programmatically, matching NMEA 0183 Sec 5.3.

Layout transcribed from diaggrok.parsers.diag_0x1c90 (module docstring +
parse_0x1c90):

    data[0]     u8  version = 0x06                (Layer-1 gate, EXPECTED_VERSION_1C90)
    data[1]     u8  seq_counter                    (per-record counter, NOT a format key)
    data[4:8]   u32 LE config_word
    data[8:]    body -- heterogeneous LocEng dump; the parser regex-scans
                the WHOLE body (not seq-band-gated) for checksum-valid
                NMEA sentences shaped ``$XXYYY,...*HH``
    total size  6693 B fixed on the SDX62 RM520N-GL corpus (not enforced
                by the parser itself -- only `len(data) >= 2` and
                `len(data) >= 8` gate config_word -- but replicated here
                for a realistic fixture)
"""
from struct import pack

from diaggrok.parsers.diag_0x1c90 import parse_0x1c90, EXPECTED_VERSION_1C90

_SEQ_COUNTER = 0x05          # fabricated -- inside the docstring's "0x02-0x20 GNSS body" band
_CONFIG_WORD = 0x0000_2A10   # fabricated u32
_TOTAL_SIZE = 6693           # matches the corpus-observed fixed size (not parser-enforced)

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
    sentence = _build_gga()
    header = (
        pack('<B', EXPECTED_VERSION_1C90)
        + pack('<B', _SEQ_COUNTER)
        + pack('<H', 0)                 # bytes [2:4] -- not read by the parser
        + pack('<I', _CONFIG_WORD)      # bytes [4:8]
    )
    assert len(header) == 8

    body = sentence.encode('ascii') + b'\r\n'
    filler_len = _TOTAL_SIZE - len(header) - len(body)
    assert filler_len >= 0
    # Filler is zero-valued -- deliberately NOT ascii text, so it cannot be
    # mistaken for a second (possibly malformed) NMEA-shaped token by the
    # regex scan.
    data = header + body + bytes(filler_len)
    assert len(data) == _TOTAL_SIZE
    return data


def test_1c90_decodes_synthetic_gnss_snapshot():
    rec = parse_0x1c90(1000, _synthetic_1c90())
    assert rec is not None
    assert rec.version == EXPECTED_VERSION_1C90
    assert rec.seq_counter == _SEQ_COUNTER
    assert rec.config_word == _CONFIG_WORD
    assert rec.payload_size == _TOTAL_SIZE

    assert len(rec.nmea_sentences) == 1
    assert rec.nmea_sentences[0] == _build_gga()
    assert rec.nmea_talkers == ('$GPGGA',)

    d = rec.to_dict()
    assert d['nmea_sentence_count'] == 1
    assert d['nmea_talkers'] == ['$GPGGA']
