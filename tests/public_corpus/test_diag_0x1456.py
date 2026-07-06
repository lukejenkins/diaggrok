"""Public zero-PII fixture for 0x1456 (GNSS heartbeat).

Tier 0 (real-snippet-eligible per public_corpus.risk_tiers.RISK_TIER --
version/flag/state/aux6-8 pure enum/status, fully decoded, no opaque tail)
-- but built synthetically anyway per the recipe doc's "when in doubt,
synthesize" guidance, keeping the corpus uniform.

Targets the 11-byte fixed layout documented in diaggrok.parsers.diag_0x1456:
5 named varying bytes + 6 invariant reserved-zero bytes, all 11 bytes
decoded (no undecoded tail).
"""
from diaggrok.parsers.diag_0x1456 import parse_0x1456

# Fabricated values (not from any real capture).
_FLAG = 1     # u8 @ [1] -- bistate
_STATE = 3    # u8 @ [2] -- multi-valued enum
_AUX6 = 1     # u8 @ [6] -- bistate
_AUX7 = 5     # u8 @ [7] -- multi-valued
_AUX8 = 9     # u8 @ [8] -- multi-valued


def _synthetic_1456() -> bytes:
    """Build an 11-byte 0x1456 payload with fabricated status bytes.

    Offsets transcribed from the parser's own docstring/comments in
    diag_0x1456.py, not from any capture:

      [0]  u8  version  = 0x00 (parser rejects any other value)
      [1]  u8  flag     = 1 (fabricated bistate)
      [2]  u8  state     = 3 (fabricated multi-valued enum)
      [3]  u8  reserved  = 0x00 (INVARIANT -- parser rejects non-zero)
      [4]  u8  reserved  = 0x00 (INVARIANT)
      [5]  u8  reserved  = 0x00 (INVARIANT)
      [6]  u8  aux6      = 1 (fabricated bistate)
      [7]  u8  aux7      = 5 (fabricated)
      [8]  u8  aux8      = 9 (fabricated)
      [9]  u8  reserved  = 0x00 (INVARIANT -- parser rejects non-zero)
      [10] u8  reserved  = 0x00 (INVARIANT)
    """
    body = bytes([
        0x00,       # version
        _FLAG,
        _STATE,
        0x00, 0x00, 0x00,  # reserved [3,4,5]
        _AUX6,
        _AUX7,
        _AUX8,
        0x00, 0x00,        # reserved [9,10]
    ])
    assert len(body) == 11
    return body


def test_1456_decodes_synthetic_frame():
    rec = parse_0x1456(1000, _synthetic_1456())
    assert rec is not None
    assert rec.version == 0x00
    assert rec.flag == 1
    assert rec.state == 3
    assert rec.aux6 == 1
    assert rec.aux7 == 5
    assert rec.aux8 == 9
    assert rec.payload_size == 11
