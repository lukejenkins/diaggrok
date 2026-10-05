"""Public zero-PII fixture for 0x1D23 (LOG_GNSS_POWER_PROFILING_REPORT_C v0x04).

Tier 1 (synthetic-only, see public_corpus.risk_tiers.RISK_TIER[0x1D23] == 1).
This fixture is built entirely from fabricated values via
public_corpus.support.synthetic -- no bytes are copied from any capture,
private test, or real DIAG log.

Targets the only decode path the parser supports: a fixed 54-byte record
with version == 4. Offsets are transcribed from the live ``parse_0x1d23``
code (unpack_from offsets), not from the module's prose:

    [0]       u8     version = 4
    [1:5]     u32    reserved_1
    [5:32]    27xu8  pwrprf_u8
    [32:36]   u32    pwrprf_u32_27
    [36:38]   u16    pwrprf_u16_28
    [38:42]   u32    dpo_dwell_ms
    [42:54]   3xu32  tail_u32_a / b / c
    total = 54 B
"""
from public_corpus.support.synthetic import diag_frame, pack
from diaggrok.parsers.diag_0x1d23 import parse_0x1d23

_VERSION = 4

# Fabricated values (not from any real capture).
_RESERVED = 0x00000000
_PWRPRF_U8 = tuple(range(1, 28))
_COL27 = 0x00000000
_COL28 = 0x0123
_DWELL = 0x000001F4       # 500 ms
_TAIL = (0x11111111, 0x22222222, 0x33333333)


def _synthetic_1d23() -> bytes:
    """Build a version=4, 54-byte 0x1D23 record from fabricated bytes.

    ``diag_frame`` supplies the version byte at data[0]; the 53 body bytes
    are assembled here.
    """
    body = (pack('<I', _RESERVED) + bytes(_PWRPRF_U8) + pack('<I', _COL27)
            + pack('<H', _COL28) + pack('<I', _DWELL) + pack('<3I', *_TAIL))
    assert len(body) == 53

    data = diag_frame(0x1D23, _VERSION, body)
    assert len(data) == 54
    return data


def test_1d23_decodes_synthetic_frame():
    rec = parse_0x1d23(1000, _synthetic_1d23())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.payload_size == 54
    assert rec.reserved_1 == _RESERVED
    assert rec.pwrprf_u8 == _PWRPRF_U8
    assert rec.pwrprf_u32_27 == _COL27
    assert rec.pwrprf_u16_28 == _COL28
    assert rec.dpo_dwell_ms == _DWELL
    assert rec.dpo_active is True
    assert (rec.tail_u32_a, rec.tail_u32_b, rec.tail_u32_c) == _TAIL
    assert rec.pwrprf_columns == [*_PWRPRF_U8, _COL27, _COL28, _DWELL]
