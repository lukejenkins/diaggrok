"""Public zero-PII fixture for 0x1482 (GNSS measurement data).

Tier 1 (synthetic-only): byte_27 is explicitly named a "firmware variant
identifier" (see public_corpus.risk_tiers.RISK_TIER[0x1482] == 1), so this
frame is built entirely from fabricated values via
public_corpus.support.synthetic -- no bytes are copied from any capture,
private test, or real DIAG log.

Targets the 107-byte ("107_mdm9x" size class) layout documented at the top
of diaggrok.parsers.diag_0x1482: version=0, subtype=0x0da3, a handful of
cross-chipset signature markers, and the 7-entry meas_counts array at
offsets 62/66/70/74/78/82/86.
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x1482 import parse_0x1482

# Fabricated header/marker values (not from any real capture). Offsets are
# transcribed from the parser's own docstring/comments in diag_0x1482.py.
_VERSION = 0x00                    # byte 0 -- hard-gated
_SUBTYPE = 0x0da3                  # u16LE at [1:3] -- hard-gated
_TICK_COUNTER_LO = 0x010203        # u24LE at [5:8]
_COUNTER_B9 = 7                    # byte 9
_SIG_9AC1FE = (0x9a, 0xc1, 0xfe)   # bytes [10:13] -- signature check
_VARYING_COUNTER = 0x0A0B0C        # u24LE at [13:16]
_HEADER_SIG = 0x57                 # byte 16
_SIG_1227 = 0x1227                 # u16LE at [33:35] (bytes 27 12)
_SUB_COUNTER = 4242                # u16LE at [35:37]
_SIG_B066 = 0xb066                 # u16LE at [41:43] (bytes 66 b0)
_MEAS_TAG = 0x0009                 # u16LE at [60:62]
_MEAS_COUNTS = (3, 4, 5, 6, 7, 8, 9)  # u8 at 62, 66, 70, 74, 78, 82, 86
_BYTE_27 = 0x00                    # firmware-variant identifier -- enum {0,1}


def _synthetic_1482() -> bytes:
    """Build a 107-byte ("107_mdm9x" size class) 0x1482 payload with
    fabricated marker/count values; all non-asserted bytes are zero-filled."""
    buf = bytearray(107)
    buf[0] = _VERSION
    buf[1:3] = pack('<H', _SUBTYPE)
    buf[3] = 0
    buf[4] = 0
    buf[5] = _TICK_COUNTER_LO & 0xFF
    buf[6] = (_TICK_COUNTER_LO >> 8) & 0xFF
    buf[7] = (_TICK_COUNTER_LO >> 16) & 0xFF
    buf[9] = _COUNTER_B9
    buf[10:13] = bytes(_SIG_9AC1FE)
    buf[13] = _VARYING_COUNTER & 0xFF
    buf[14] = (_VARYING_COUNTER >> 8) & 0xFF
    buf[15] = (_VARYING_COUNTER >> 16) & 0xFF
    buf[16] = _HEADER_SIG
    buf[27] = _BYTE_27
    buf[33:35] = pack('<H', _SIG_1227)
    buf[35:37] = pack('<H', _SUB_COUNTER)
    buf[41:43] = pack('<H', _SIG_B066)
    buf[60:62] = pack('<H', _MEAS_TAG)
    for off, val in zip((62, 66, 70, 74, 78, 82, 86), _MEAS_COUNTS):
        buf[off] = val
    return bytes(buf)


def test_1482_decodes_synthetic_frame():
    rec = parse_0x1482(1000, _synthetic_1482())
    assert rec is not None
    assert rec.version == 0x00
    assert rec.subtype == _SUBTYPE
    assert rec.header_signature == _HEADER_SIG
    assert rec.tick_counter_lo == _TICK_COUNTER_LO
    assert rec.counter_b9 == _COUNTER_B9
    assert rec.sig_9ac1fe_ok is True
    assert rec.varying_counter == _VARYING_COUNTER
    assert rec.sig_1227_ok is True
    assert rec.sig_b066_ok is True
    assert rec.sub_counter == _SUB_COUNTER
    assert rec.meas_tag_0009_ok is True
    assert rec.meas_counts == list(_MEAS_COUNTS)
    assert rec.byte_27 == _BYTE_27
    assert rec.size_class == '107_mdm9x'
    assert rec.payload_size == 107
