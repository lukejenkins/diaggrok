"""Public zero-PII fixture for 0x147B (GNSS clock/cell database report).

Tier 1 (synthetic-only): the header carries gps_week + gps_ms (GPS absolute
time) -- per public_corpus.risk_tiers.RISK_TIER this frame must be fully
synthetic, built via public_corpus.support.synthetic -- no bytes copied
from any capture.

Targets the 11-byte header documented in diaggrok.parsers.diag_0x147b:
version=11 (0x0B, SDX20 V2 / MDM9650 / MDM9207-OCPU) requires an exact
535-byte record per ``_VERSION_TO_SIZE`` -- the parser's Layer-1
(version, len) gate rejects any other pairing.
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x147b import parse_0x147b

# Fabricated header values (not from any real capture).
_VERSION = 11             # u8 @ [0] -- SDX20 V2 class, requires len == 535
_F_COUNT = 777             # u32 @ [1:5]
_GPS_WEEK = 2100           # u16 @ [5:7]
_GPS_MS = 45000            # u32 @ [7:11]
_RECORD_SIZE = 535         # exact size required for version 11


def _synthetic_147b() -> bytes:
    """Build a 535-byte v=11 0x147B payload with a fabricated header.

    Offsets transcribed from the parser's own docstring/comments in
    diag_0x147b.py, not from any capture:

      [0]     u8   version  = 11 (parser rejects unlisted values)
      [1:5]   u32  f_count  = 777 (fabricated)
      [5:7]   u16  gps_week = 2100 (fabricated)
      [7:11]  u32  gps_ms   = 45000 (fabricated)
      [11:535] 524 zero-filled bytes -- the body region, preserved as
               ``raw`` by the parser and not yet RE'd (#N)
    """
    header = pack('<BIHI', _VERSION, _F_COUNT, _GPS_WEEK, _GPS_MS)
    assert len(header) == 11
    body = header + bytes(_RECORD_SIZE - len(header))
    assert len(body) == _RECORD_SIZE
    return body


def test_147b_decodes_synthetic_frame():
    rec = parse_0x147b(1000, _synthetic_147b())
    assert rec is not None
    assert rec.version == 11
    assert rec.f_count == 777
    assert rec.gps_week == 2100
    assert rec.gps_ms == 45000
    assert len(rec.raw) == 535
