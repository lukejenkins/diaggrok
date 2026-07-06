"""Public zero-PII fixture for 0x147D (GNSS nav DB, companion to 0x147C).

Tier 1 (synthetic-only): body_raw / body_slots are left undecoded (the
parser docstring flags them as pending ephemeris-baseline correlation) --
per public_corpus.risk_tiers.RISK_TIER this frame must be fully synthetic,
built via public_corpus.support.synthetic -- no bytes copied from any
capture.

Targets the 16-byte header + 46-byte-stride slot table documented in
diaggrok.parsers.diag_0x147d: version=0x05 paired with the fixed 3665-byte
"mdm9x07_3665" size class (the parser's joint (size, version) gate), which
lands the SDX55-only slot validators at ``None`` (they only fire on the
4717-byte size class) while still exercising the corpus-generic
``body_slots`` decode.
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x147d import parse_0x147d

# Fabricated header values (not from any real capture).
_VERSION = 0x05           # u8 @ [0] -- paired with len == 3665 (joint gate)
_SCOPE_ID = 300_000       # u24LE @ [1:4]
_MARKER_5_7 = 0x1091      # u16LE @ [5:7] -- modal header-state word
_SIZE_FLAG = 0x00         # u8 @ [7] -- 0x00 on the 3665B size class
_RECORD_SIZE = 3665       # exact size required for version 0x05


def _synthetic_147d() -> bytes:
    """Build a 3665-byte v=0x05 0x147D payload with a fabricated header.

    Offsets transcribed from the parser's own docstring/comments in
    diag_0x147d.py, not from any capture:

      [0]     u8    version         = 0x05 (parser rejects unlisted values;
                                      paired with len==3665 by the joint gate)
      [1:4]   u24LE scope_id        = 300000 (fabricated per-record id)
      [4]     u8    = 0x00 (const separator)
      [5:7]   u16LE marker_bytes_5_7 = 0x1091 (fabricated, modal corpus value)
      [7]     u8    size_flag       = 0x00 (fabricated, 3665B convention)
      [8:16]  8 zero-filled bytes (reserved)
      [16:3665] zero-filled body -- the 46-byte-stride slot table starting
                at offset 440 is exposed structurally (``body_slots``) but
                stays raw (undecoded) per the parser's own documented scope
    """
    header = (
        pack('<B', _VERSION)
        + pack('<BBB',
               _SCOPE_ID & 0xFF, (_SCOPE_ID >> 8) & 0xFF, (_SCOPE_ID >> 16) & 0xFF)
        + pack('<B', 0x00)                # [4] const separator
        + pack('<H', _MARKER_5_7)         # [5:7]
        + pack('<B', _SIZE_FLAG)          # [7]
        + bytes(8)                        # [8:16] reserved
    )
    assert len(header) == 16
    body = header + bytes(_RECORD_SIZE - len(header))
    assert len(body) == _RECORD_SIZE
    return body


def test_147d_decodes_synthetic_frame():
    rec = parse_0x147d(1000, _synthetic_147d())
    assert rec is not None
    assert rec.version == 0x05
    assert rec.scope_id == 300_000
    assert rec.marker_bytes_5_7 == 0x1091
    assert rec.sig_1091_ok is True
    assert rec.size_flag == 0x00
    assert rec.size_class == "mdm9x07_3665"
    assert rec.payload_size == 3665
    assert rec.body_slot_table_start == 440
    assert rec.body_slot_stride == 46
    # (3665 - 440) // 46 == 70 complete 46B slots fit in the zero-filled body.
    assert len(rec.body_slots) == 70
    # 3665B is not the SDX55 4717B class, so the SDX55-only validators
    # correctly stay None on this size class.
    assert rec.slot_0_sdx55_format_ok is None
