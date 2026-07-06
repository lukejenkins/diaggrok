"""Public zero-PII fixture for 0x1D23 (GNSS power profiling structural stub).

Tier 1 (synthetic-only, see public_corpus.risk_tiers.RISK_TIER[0x1D23] == 1):
the parser leaves an undecoded ``body_raw`` tail (the 28-byte context block +
parts of the 24-byte trailer are opaque/unresolved), so a real byte snippet
could carry PII the text-only leak_tokens guard cannot see. This fixture is
built entirely from fabricated values via public_corpus.support.synthetic --
no bytes are copied from any capture, private test, or real DIAG log.

Targets the only decode path the parser supports: a fixed 54-byte record
with version == 4 (the ``field_invariants`` enum gate). Offsets below are
transcribed from diaggrok.parsers.diag_0x1d23's dataclass field comments and
the live ``parse_0x1d23`` code (unpack_from offsets), not from the module's
prose narrative:

    [0]          u8    version = 4
    [0:0x1C]     28 B  context_block (includes the version byte at [0])
    [0x1C:0x28]  3xu32 trailer_u32_a/b/c (unpack_from('<3I', data, 0x1C))
    [0x28:0x2C]  u32   counter_u32_a
    [0x2C:0x30]  4 B   gap (unused by the parser)
    [0x30:0x34]  u32   counter_u32_b
    [0x34:0x36]  2 B   trailer_tail
    total = 0x36 = 54 B (matches the parser's ``len(data) != 54`` gate)
"""
from public_corpus.support.synthetic import diag_frame, pack
from diaggrok.parsers.diag_0x1d23 import parse_0x1d23

_VERSION = 4

# Fabricated trailer/counter values (not from any real capture).
_TRAILER_A = 0x11111111   # u32LE at 0x1C
_TRAILER_B = 0x22222222   # u32LE at 0x20
_TRAILER_C = 0x33333333   # u32LE at 0x24
_COUNTER_A = 0x00000A00   # u32LE at 0x28
_COUNTER_B = 0x00000B00   # u32LE at 0x30
_TAIL = b"\xAB\xCD"       # 2 B at 0x34..0x36


def _synthetic_1d23() -> bytes:
    """Build a version=4, 54-byte 0x1D23 record from fabricated bytes.

    ``diag_frame`` supplies the version byte at data[0]; everything after
    that is assembled here so the total record is exactly 54 bytes
    (data[0] + 53 body bytes == 54).
    """
    # data[1:0x1C] -- 27 bytes of fabricated "context" filler (the parser
    # does not decode any individual field in this region beyond storing
    # it verbatim in context_block/body_raw).
    context_extra = bytes(range(1, 28))
    assert len(context_extra) == 27

    trailer = pack('<3I', _TRAILER_A, _TRAILER_B, _TRAILER_C)
    assert len(trailer) == 12

    counter_a = pack('<I', _COUNTER_A)
    gap = bytes(4)  # data[0x2C:0x30] -- not read by the parser
    counter_b = pack('<I', _COUNTER_B)

    body = context_extra + trailer + counter_a + gap + counter_b + _TAIL
    assert len(body) == 53

    data = diag_frame(0x1D23, _VERSION, body)
    assert len(data) == 54
    return data


def test_1d23_decodes_synthetic_frame():
    rec = parse_0x1d23(1000, _synthetic_1d23())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.payload_size == 54
    # context_block == data[0:0x1C] == version byte + the 27 fabricated
    # filler bytes.
    assert rec.context_block == bytes([_VERSION]) + bytes(range(1, 28))
    assert rec.trailer_u32_a == _TRAILER_A
    assert rec.trailer_u32_b == _TRAILER_B
    assert rec.trailer_u32_c == _TRAILER_C
    assert rec.counter_u32_a == _COUNTER_A
    assert rec.counter_u32_b == _COUNTER_B
    assert rec.trailer_tail == _TAIL
