"""Public zero-PII fixture for 0x1455 (GNSS epoch counter).

Tier 0 (real-snippet-eligible per public_corpus.risk_tiers.RISK_TIER --
version/sequence(monotonic)/flags/reserved only, fully decoded, no opaque
tail) -- but built synthetically anyway per the recipe doc's "when in
doubt, synthesize" guidance, keeping the corpus uniform.

Targets the 7-byte fixed layout documented in diaggrok.parsers.diag_0x1455:
every byte is named, all 7 bytes decoded (no undecoded tail).
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x1455 import parse_0x1455

# Fabricated values (not from any real capture).
_SEQUENCE = 12345  # u32 @ [1:5]


def _synthetic_1455() -> bytes:
    """Build a 7-byte 0x1455 payload with a fabricated sequence counter.

    Offsets transcribed from the parser's own docstring/comments in
    diag_0x1455.py, not from any capture:

      [0]    u8    version   = 0x00 (parser rejects any other value)
      [1:5]  u32LE sequence  = 12345 (fabricated monotonic epoch counter)
      [5]    u8    flags     = 0x02 (corpus-wide constant)
      [6]    u8    reserved_6 = 0x00 (corpus-wide constant)
    """
    body = (
        pack('<B', 0x00)               # version
        + pack('<I', _SEQUENCE)        # sequence
        + pack('<B', 0x02)             # flags
        + pack('<B', 0x00)             # reserved_6
    )
    assert len(body) == 7
    return body


def test_1455_decodes_synthetic_frame():
    rec = parse_0x1455(1000, _synthetic_1455())
    assert rec is not None
    assert rec.version == 0x00
    assert rec.sequence == 12345
    assert rec.flags == 0x02
    assert rec.reserved_6 == 0x00
    assert rec.payload_size == 7
