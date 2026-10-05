"""Public zero-PII fixture for 0x1D2E (GNSS/config cell-array record).

Tier 1 (synthetic-only, see public_corpus.risk_tiers.RISK_TIER[0x1D2E] == 1):
counter cells carry a modem-specific ``raw`` tail and the record carries an
undecoded ``trailer_raw`` -- opaque regions where a real byte snippet could
carry PII the text-only leak_tokens guard cannot see. This fixture is built
entirely from fabricated values via public_corpus.support.synthetic -- no
bytes are copied from any capture, private test, or real DIAG log.

Targets the smallest clean cell-array shape the parser accepts: n_counters=1
(payload_size == 86 + 37*1 == 123), matching the documented v0x01/subversion
0x01 header + one counter cell + one trailer cell layout. Offsets below are
transcribed from diaggrok.parsers.diag_0x1d2e's live ``parse_0x1d2e`` code
(the gates it checks and the unpack_from offsets it reads), not from the
module's prose narrative:

    Header -- 49 B, data[0:49]
      [0]      u8   version = 0x01
      [1]      u8   subversion = 0x01
      [11]     u8   n_counters_m1 = n_counters - 1 (redundant length, gated)
      [18:23]  5 B  tag1 = FF FF 00 <tag> 00 (data[18],[19],[22] gated)
      [23:28]  5 B  tag2 = FF FF 00 <tag> 00 (data[23],[24],[27] gated)
      [28:30]  u16  field_pre
      [30:32]  u16  magic
      [32]     u8   field_32
      [38]     u8   marker_0d = 0x0D (gated)
      [39]     u8   marker_0f = 0x0F (gated)
      [48]     u8   n_counters (length prefix, gated == (size-49)//37 - 1... )

    Counter cell -- 37 B, data[49:86] for n_counters=1
      [+0]      u8   index = 0
      [+11:13]  u16  value

    Trailer cell -- 37 B, data[86:123] (always present, k=n_counters)
      [+1]      u8   mask = 2**n_counters - 1 (not gated, just decoded)
"""
from public_corpus.support.synthetic import diag_frame, pack
from diaggrok.parsers.diag_0x1d2e import parse_0x1d2e

_VERSION = 0x01
_SUBVERSION = 0x01
_N_COUNTERS = 1

# Fabricated tag/field values (not from any real capture). The tag's 4th
# byte is documented as modem-specific (0x06 RM520 / 0x08 Sierra); the
# parser only gates bytes [18],[19],[22] (== 0xFF,0xFF,0x00) and
# [23],[24],[27] (== 0xFF,0xFF,0x00) -- the 4th byte itself is unconstrained,
# so any fabricated value works.
_TAG_MODEM_BYTE = 0x06
_FIELD_PRE = 0x0000
_MAGIC = 0x8737
_FIELD_32 = 0x0A
_COUNTER_VALUE = 0x0300     # u16LE at counter-cell +11
_TRAILER_CHECKSUM_LIKE = 0x83  # trailer +33, cosmetic only (not asserted)


def _synthetic_1d2e() -> bytes:
    """Build a version=1/subversion=1, n_counters=1 (123-byte) 0x1D2E record.

    ``diag_frame`` supplies the version byte at data[0]; the rest of the
    49-byte header + 1 counter cell + 1 trailer cell is assembled here.
    """
    header = bytearray(49)
    header[1] = _SUBVERSION
    # data[2:11] -- 9 B reserved (zero); data[11] is the redundant length.
    header[11] = _N_COUNTERS - 1
    # data[12:18] -- 6 B reserved (zero).
    header[18:23] = bytes([0xFF, 0xFF, 0x00, _TAG_MODEM_BYTE, 0x00])
    header[23:28] = bytes([0xFF, 0xFF, 0x00, _TAG_MODEM_BYTE, 0x00])
    header[28:30] = pack('<H', _FIELD_PRE)
    header[30:32] = pack('<H', _MAGIC)
    header[32] = _FIELD_32
    # data[33:38] -- 5 B reserved (zero).
    header[38] = 0x0D
    header[39] = 0x0F
    # data[40:48] -- 8 B reserved / modem-specific (zero here; not gated).
    header[48] = _N_COUNTERS
    assert len(header) == 49

    counter_cell = bytearray(37)
    counter_cell[0] = 0  # index (0-based, k=0 for the only counter cell)
    counter_cell[11:13] = pack('<H', _COUNTER_VALUE)
    assert len(counter_cell) == 37

    trailer_cell = bytearray(37)
    trailer_cell[0] = 0x01
    trailer_cell[1] = (1 << _N_COUNTERS) - 1  # presence bitmask
    trailer_cell[5] = 0x04
    trailer_cell[8] = 0x0C
    trailer_cell[12:14] = bytes([0x01, 0x02])
    trailer_cell[33] = _TRAILER_CHECKSUM_LIKE
    assert len(trailer_cell) == 37

    # diag_frame prepends the version byte, so the body starts at header[1:].
    body = bytes(header[1:]) + bytes(counter_cell) + bytes(trailer_cell)
    data = diag_frame(0x1D2E, _VERSION, body)
    assert len(data) == 123
    return data


def test_1d2e_decodes_synthetic_frame():
    rec = parse_0x1d2e(1000, _synthetic_1d2e())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.subversion == _SUBVERSION
    assert rec.n_counters == _N_COUNTERS
    assert rec.n_cells == _N_COUNTERS + 1
    assert rec.payload_size == 123
    assert rec.tag1 == bytes([0xFF, 0xFF, 0x00, _TAG_MODEM_BYTE, 0x00])
    assert rec.tag2 == bytes([0xFF, 0xFF, 0x00, _TAG_MODEM_BYTE, 0x00])
    assert rec.field_pre == _FIELD_PRE
    assert rec.magic == _MAGIC
    assert rec.field_32 == _FIELD_32
    assert len(rec.counters) == 1
    assert rec.counters[0].index == 0
    assert rec.counters[0].value == _COUNTER_VALUE
    # trailer_mask == 2**n_counters - 1 == 1 for n_counters=1.
    assert rec.trailer_mask == 1
