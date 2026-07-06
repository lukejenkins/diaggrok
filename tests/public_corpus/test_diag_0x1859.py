"""Public zero-PII fixture for 0x1859 (GNSS XTRA assistance server URL event).

Tier 1 (synthetic-only): the decoded payload embeds a hostname string (see
public_corpus.risk_tiers.RISK_TIER[0x1859] == 1 -- config/identifier ASCII
carriage per the parser's own ascii_kinds tag), so this fixture is built
entirely from fabricated values via public_corpus.support.synthetic -- no
bytes are copied from any capture, private test, or real DIAG log. The
Pascal-string hostname parts below ("aaaaaaaaa" / "bbbbbbbbb" / "ccc") are
made-up placeholder labels, not any real XTRA/assistance server name.

Targets the fully-decoded 104-byte payload documented in
diaggrok.parsers.diag_0x1859: u32LE version (layer-1 gated to 1), a
Pascal-string-encoded hostname starting at byte 16, a fixed 3-byte magic
before/after the hostname, and a 56-byte zero-filled trailer.
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x1859 import parse_0x1859

# Fabricated field values (not from any real capture).
_VERSION = 1              # u32LE at [0:4] -- field_invariants enum {1}
_RECORD_MARKER = 0x41     # u8 at [4]
_MAGIC = b'\x00\x01\x00'  # 3B constant at [5:8] and again at [41:44]
_FLAG_8 = 256             # u32LE at [8:12] -- fabricated
_RESERVED_12 = 0          # u32LE at [12:16] -- always 0 per docstring
_PART_1 = 'aaaaaaaaa'     # 9 chars -- fabricated placeholder label
_PART_2 = 'bbbbbbbbb'     # 9 chars -- fabricated placeholder label
_PART_3 = 'ccc'           # 3 chars -- fabricated placeholder label
_ENTRY_COUNT = 1          # u32LE -- fabricated, matches docstring's "1 observed"


def _pascal(s: str) -> bytes:
    encoded = s.encode('ascii')
    return bytes([len(encoded)]) + encoded


def _synthetic_1859() -> bytes:
    """Build the fully-decoded 104-byte 0x1859 payload.

    Offsets transcribed from diag_0x1859.py's payload field map:
      [0:4]    u32LE version = 1
      [4]      u8    record_marker = 0x41
      [5:8]    3B    magic_pre = 00 01 00
      [8:12]   u32LE flag_8 = 256
      [12:16]  u32LE reserved_12 = 0
      [16]     u8    host_part_1_len = 9, [17:26] "aaaaaaaaa"
      [26]     u8    host_part_2_len = 9, [27:36] "bbbbbbbbb"
      [36]     u8    host_part_3_len = 3, [37:40] "ccc"
      [40]     u8    host_terminator = 0
      [41:44]  3B    magic_post = 00 01 00
      [44:48]  u32LE entry_count = 1
      [48:104] 56B   zero-filled trailer
    """
    header = (
        pack('<I', _VERSION)
        + pack('<B', _RECORD_MARKER)
        + _MAGIC
        + pack('<I', _FLAG_8)
        + pack('<I', _RESERVED_12)
    )
    assert len(header) == 16
    hostname = _pascal(_PART_1) + _pascal(_PART_2) + _pascal(_PART_3)
    # host_terminator (0x00) doubles as the zero-length-string sentinel
    # that _decode_pascal_strings stops on.
    trailer_head = pack('<B', 0) + _MAGIC + pack('<I', _ENTRY_COUNT)
    padding = bytes(56)
    data = header + hostname + trailer_head + padding
    assert len(data) == 104
    return data


def test_1859_decodes_synthetic_frame():
    rec = parse_0x1859(1000, _synthetic_1859())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.record_marker == _RECORD_MARKER
    assert rec.magic_pre == _MAGIC
    assert rec.flag_8 == _FLAG_8
    assert rec.reserved_12 == _RESERVED_12
    assert rec.host_parts == [_PART_1, _PART_2, _PART_3]
    assert rec.host_terminator == 0
    assert rec.magic_post == _MAGIC
    assert rec.entry_count == _ENTRY_COUNT
    assert rec.trailer_zero_bytes == 56
    assert rec.xtra_host == f'{_PART_1}.{_PART_2}.{_PART_3}'
    assert rec.payload_size == 104
