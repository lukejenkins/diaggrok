"""Public zero-PII fixture for 0x1899 (GNSS status/heartbeat tick).

Tier 0 (synthetic-only): although every byte in this code is a pure
enum/status/counter/reserved value with no cell/position/identity content,
public_corpus.risk_tiers.RISK_TIER records 0x1899 as tier-0 (no PII risk).
This fixture is nonetheless built entirely from fabricated values via
public_corpus.support.synthetic for corpus consistency -- no bytes are
copied from any capture, private test, or real DIAG log.

Targets the fully-decoded 108-byte fixed layout documented in
diaggrok.parsers.diag_0x1899: version (const 2), a free-running u8 counter,
a 5-state status_byte_2 enum, plus the 4 corpus-wide named constants
(status_flag_10, rate_ms, status_flag_85) and 101 reserved-zero bytes that
must all be zero for the record to parse.
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x1899 import parse_0x1899

# Fabricated field values (not from any real capture).
_VERSION = 2          # data[0] -- field_invariants const
_COUNTER = 42         # data[1] -- fabricated free-running counter
_STATUS_BYTE_2 = 1    # data[2] -- 1 == 'tracking' per GNSS_STATUS_1899_STATES
_STATUS_FLAG_10 = 1   # data[10] -- field_invariants const
_RATE_MS = 1000       # u16 LE at [58:60] -- field_invariants const
_STATUS_FLAG_85 = 3   # data[85] -- field_invariants const


def _synthetic_1899() -> bytes:
    """Build the 108-byte fully-decoded 0x1899 payload.

    Offsets transcribed from diag_0x1899.py's "Field map (v4)":
      [0]      u8 version = 2
      [1]      u8 counter = 42
      [2]      u8 status_byte_2 = 1
      [3:10]   7B reserved = 0
      [10]     u8 status_flag_10 = 1
      [11:58]  47B reserved = 0
      [58:60]  u16 LE rate_ms = 1000
      [60:85]  25B reserved = 0
      [85]     u8 status_flag_85 = 3
      [86:108] 22B reserved = 0
    """
    data = (
        pack('<B', _VERSION)
        + pack('<B', _COUNTER)
        + pack('<B', _STATUS_BYTE_2)
        + bytes(7)
        + pack('<B', _STATUS_FLAG_10)
        + bytes(47)
        + pack('<H', _RATE_MS)
        + bytes(25)
        + pack('<B', _STATUS_FLAG_85)
        + bytes(22)
    )
    assert len(data) == 108
    return data


def test_1899_decodes_synthetic_frame():
    rec = parse_0x1899(1000, _synthetic_1899())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.counter == _COUNTER
    assert rec.status_byte_2 == _STATUS_BYTE_2
    assert rec.status_byte_2_name == 'tracking'
    assert rec.status_flag_10 == _STATUS_FLAG_10
    assert rec.rate_ms == _RATE_MS
    assert rec.status_flag_85 == _STATUS_FLAG_85
    assert rec.all_invariants_ok is True
    assert rec.payload_size == 108
