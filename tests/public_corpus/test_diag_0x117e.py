"""Public zero-PII fixture for 0x117E (GPS multi-peaks verbose searcher).

Tier 1 (synthetic-only, per public_corpus.risk_tiers.RISK_TIER): every value is
fabricated via public_corpus.support.synthetic -- no bytes copied from any
capture.

Targets the 58 B ``d58`` search-grid descriptor documented in
diaggrok.parsers.diag_0x117e (v5): a common 8 B header (u32 record_seq,
u16 fragment == 0 for a descriptor, u16 body_len == size - 8), then the
descriptor body. byte[0] is the low byte of record_seq, not a version -- the
code is version_less. The drift guards are body_len and tag == 0x0066.
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x117e import parse_0x117e

# Fabricated values (not from any real capture).
_RECORD_SEQ = 1234
_SV = 7
_SEARCH_MODE = 3
_GRID = (1, 4, 24)
_JOB_ID = 0x00030701
_MS = 987654
_DOPPLER = -4096
_CODE_PHASE = 555555


def _synthetic_117e() -> bytes:
    """Build a 58-byte ``d58`` descriptor with fabricated values.

      [0:4]   u32 record_seq  [4:6] u16 fragment = 0  [6:8] u16 body_len = 50
      [8:10]  u16 tag = 0x0066 (drift guard)
      [11] u8 sv  [12] u8 search_mode
      [25:31] u16 x3 grid_a / grid_n / grid_m
      [33:37] u32 job_id  [37:41] u32 ms  [45:49] i32 doppler
      [49:53] u32 code_phase
    """
    body = (
        pack('<IHH', _RECORD_SEQ, 0, 50)
        + pack('<H', 0x0066)
        + bytes(1)                                   # [10]
        + pack('<BB', _SV, _SEARCH_MODE)             # [11], [12]
        + bytes(12)                                  # [13:25]
        + pack('<3H', *_GRID)                        # [25:31]
        + bytes(2)                                   # [31:33]
        + pack('<II', _JOB_ID, _MS)                  # [33:41]
        + bytes(4)                                   # [41:45]
        + pack('<iI', _DOPPLER, _CODE_PHASE)         # [45:53]
        + bytes(5)                                   # [53:58]
    )
    assert len(body) == 58
    return body


def test_117e_decodes_synthetic_descriptor():
    rec = parse_0x117e(1000, _synthetic_117e())
    assert rec is not None
    assert rec.record_kind == 'descriptor' and rec.layout == 'd58'
    assert rec.record_seq == _RECORD_SEQ
    assert rec.body_len == 50
    assert (rec.sv, rec.search_mode) == (_SV, _SEARCH_MODE)
    assert (rec.grid_a, rec.grid_n, rec.grid_m) == _GRID
    assert rec.job_id == _JOB_ID and rec.ms == _MS
    assert rec.doppler == _DOPPLER and rec.code_phase == _CODE_PHASE
    assert rec.dump_bytes_u8 == 1 * 4 * (24 + 4)
