"""Public zero-PII fixture for 0x1478 (GNSS clock report).

Tier 1 (synthetic-only): the header carries gps_week + gps_ms (GPS absolute
time) -- per public_corpus.risk_tiers.RISK_TIER this frame must be fully
synthetic, built via public_corpus.support.synthetic -- no bytes copied
from any capture.

Targets the 13-byte header documented in diaggrok.parsers.diag_0x1478:
version=0x03 (SDX20 V2) requires an exact 174-byte record per
``_VERSION_TO_SIZE`` -- the parser's Layer-1 (version, len) gate rejects
any other pairing.
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x1478 import parse_0x1478

# Fabricated header values (not from any real capture).
_VERSION = 0x03           # u8 @ [0] -- SDX20 V2, requires len == 174 (_VERSION_TO_SIZE)
_FLAGS = 0x01ff           # u16 @ [1:3] -- dominant corpus value (all 9 constellation bits)
_F_COUNT = 555            # u32 @ [3:7]
_GPS_WEEK = 2222          # u16 @ [7:9]
_GPS_MS = 333444          # u32 @ [9:13]
# Per-constellation engine time (F3-grounded, #N). Fabricated but built
# to honour the physical invariants the parser docstring documents:
#   bds_ms == gps_ms - 14000 (the fixed 14 s BDT-GPST offset)
#   glo_ms is a distinct GLONASS day/week-framed value
_BDS_MS = _GPS_MS - 14000  # u32 @ [40:44]
_GLO_MS = 171426           # u32 @ [25:29] (fabricated, distinct stream)
_RECORD_SIZE = 174        # exact size required for version 0x03


def _synthetic_1478() -> bytes:
    """Build a 174-byte v=0x03 0x1478 payload with a fabricated header + body.

    Offsets transcribed from the parser's own docstring/comments in
    diag_0x1478.py, not from any capture:

      [0]     u8   version  = 0x03 (SDX20 V2; parser rejects unlisted values)
      [1:3]   u16  flags    = 0x01ff (fabricated, dominant corpus value)
      [3:7]   u32  f_count  = 555 (fabricated)
      [7:9]   u16  gps_week = 2222 (fabricated)
      [9:13]  u32  gps_ms   = 333444 (fabricated)
      [25:29] u32  glo_ms   = fabricated GLONASS engine time (F3-grounded offset)
      [40:44] u32  bds_ms   = gps_ms - 14000 (F3-grounded offset; BDT-GPST 14 s)
      remaining body bytes zero-filled -- preserved as ``raw`` by the parser
      and not yet RE'd (#N)
    """
    buf = bytearray(_RECORD_SIZE)
    buf[0:13] = pack('<BHIHI', _VERSION, _FLAGS, _F_COUNT, _GPS_WEEK, _GPS_MS)
    buf[25:29] = pack('<I', _GLO_MS)
    buf[40:44] = pack('<I', _BDS_MS)
    assert len(buf) == _RECORD_SIZE
    return bytes(buf)


def test_1478_decodes_synthetic_frame():
    rec = parse_0x1478(1000, _synthetic_1478())
    assert rec is not None
    assert rec.version == 0x03
    assert rec.flags == 0x01ff
    assert rec.f_count == 555
    assert rec.gps_week == 2222
    assert rec.gps_ms == 333444
    assert rec.glo_ms == _GLO_MS
    assert rec.bds_ms == _BDS_MS
    # The F3-grounded BDT-GPST invariant the parser docstring documents.
    assert rec.gps_ms - rec.bds_ms == 14000
    assert len(rec.raw) == 174
