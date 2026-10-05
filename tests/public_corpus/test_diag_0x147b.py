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
               ``raw`` by the parser and not yet RE'd
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


# --- v18 (0x12, SDX55) — legacy 11-byte header, exact 1011-byte record ---
def _synthetic_147b_v18() -> bytes:
    """Build a 1011-byte v=18 payload with a fabricated legacy header.

    Same legacy offsets as v11 (f_count@1, gps_week@5, gps_ms@7); the
    difference vs v11 is the record size (1011 vs 535) and the larger body.
    F3-grounded on SDX55 RM500Q-AE.
    """
    header = pack('<BIHI', 18, 19608627, 2432, 353117448)
    assert len(header) == 11
    body = header + bytes(1011 - len(header))
    assert len(body) == 1011
    return body


def test_147b_decodes_synthetic_v18():
    rec = parse_0x147b(1000, _synthetic_147b_v18())
    assert rec is not None
    assert rec.version == 18
    assert rec.f_count == 19608627
    assert rec.gps_week == 2432
    assert rec.gps_ms == 353117448
    assert len(rec.raw) == 1011


# --- v23 (0x17, SDX62) — +2-shifted 13-byte header, exact 2464-byte record ---
def _synthetic_147b_v23(gps_week: int = 2427) -> bytes:
    """Build a 2464-byte v=23 payload with a fabricated shifted header.

    v23 (SDX62 RM520N-GL) inserts a 2-byte u16 at [1:3], shifting the frame
    counter and GPS timestamp by +2 relative to the legacy layout:

      [0]     u8   version  = 23 (0x17)
      [1:3]   u16  1        (usually 1 in the corpus; 6/7/0xa0 also seen)
      [3:7]   u32  f_count  = 820082172 (fabricated; real corpus is monotonic)
      [7:9]   u16  gps_week = 2427 (real fix) / 0xFFFF (no-fix sentinel)
      [9:13]  u32  gps_ms   = 278610421 (fabricated)
      [13:2464] zero-filled body (preserved as ``raw``, not yet RE'd)

    Offsets transcribed from the parser's ``_HEADER_OFFSETS`` and F3-grounded
    on RM520N-GL — NOT copied from a capture. The legacy (1,5,7) offsets
    would mis-decode this as gps_week=12513.
    """
    header = pack('<BHIHI', 23, 0x0001, 820082172, gps_week, 278610421)
    assert len(header) == 13
    body = header + bytes(2464 - len(header))
    assert len(body) == 2464
    return body


def test_147b_decodes_synthetic_v23():
    rec = parse_0x147b(1000, _synthetic_147b_v23())
    assert rec is not None
    assert rec.version == 23
    assert rec.f_count == 820082172
    assert rec.gps_week == 2427
    assert rec.gps_ms == 278610421
    assert len(rec.raw) == 2464


def test_147b_v23_no_fix_sentinel():
    """A no-fix v23 record reads gps_week @7 as the 0xFFFF sentinel.

    Regression lock for the +2 header shift: the legacy @5 offset could not
    produce a clean 0xFFFF here (it would read into the body).
    """
    rec = parse_0x147b(1000, _synthetic_147b_v23(gps_week=0xFFFF))
    assert rec is not None
    assert rec.version == 23
    assert rec.gps_week == 0xFFFF


# --- v0 (0x00, MDM9600) — legacy 11-byte header, exact 183-byte record ---
def test_147b_decodes_synthetic_v0():
    """v0 (Sierra MC7700 class) uses the legacy offsets at an exact 183 B.

    Fabricated values. gps_week 1100 stands in for the 10-bit-rolled week the
    real MDM9600 receiver reports (true week - 1024); the parser returns it
    as-is (parser v8+ accepts v0)."""
    header = pack('<BIHI', 0, 4321, 1100, 7000)
    rec = parse_0x147b(1000, header + bytes(183 - len(header)))
    assert rec is not None
    assert (rec.version, rec.f_count, rec.gps_week, rec.gps_ms) == (0, 4321, 1100, 7000)


def test_147b_v0_rejects_wrong_size():
    """A zero byte-0 at any length other than 183 is not a v0 record."""
    header = pack('<BIHI', 0, 4321, 1100, 7000)
    assert parse_0x147b(1000, header + bytes(535 - len(header))) is None


# --- v21 (0x15, SDX65) and v24 (0x18, SDX72) — +2-shifted 13-byte header ---
def _synthetic_shifted(version: int, size: int, hdr_u16: int) -> bytes:
    """[0] version, [1:3] u16 (usually 1 — NOT a constant), [3:7] f_count,
    [7:9] gps_week, [9:13] gps_ms; fabricated values, zero-filled body."""
    header = pack('<BHIHI', version, hdr_u16, 5500, 2100, 9000)
    assert len(header) == 13
    return header + bytes(size - len(header))


def test_147b_decodes_synthetic_v21():
    rec = parse_0x147b(1000, _synthetic_shifted(21, 2248, 1))
    assert rec is not None
    assert (rec.version, rec.f_count, rec.gps_week, rec.gps_ms) == (21, 5500, 2100, 9000)
    assert len(rec.raw) == 2248


def test_147b_v24_f_count_is_u32_at_3():
    """v24 f_count is u32@3 regardless of the [1:3] u16 (0x00a0 here).

    [1:3] is a separate u16, not part of a u32@1 counter: the real corpus has
    [1:3] in {1, 7, 0xa0}."""
    rec = parse_0x147b(1000, _synthetic_shifted(24, 2472, 0x00a0))
    assert rec is not None
    assert (rec.version, rec.f_count, rec.gps_week, rec.gps_ms) == (24, 5500, 2100, 9000)


def test_147b_layer2_enum_admits_every_decoded_version():
    """``diaggrok.parse`` does not run the Layer-2 ``field_invariants`` check,
    so assert it directly: every version the parser decodes must also pass
    the declared version enum (a version dropped from the enum alone would
    otherwise be flagged downstream while every parse test stays green)."""
    import diaggrok
    from diaggrok.registry import check_invariants

    entry = diaggrok.parser_info(0x147B)
    legacy = {0: 183, 8: 445, 9: 503, 11: 535, 18: 1011}
    shifted = {21: 2248, 23: 2464, 24: 2472}
    for v, size in legacy.items():
        h = pack('<BIHI', v, 1, 2100, 9000)
        rec = parse_0x147b(0, h + bytes(size - len(h)))
        assert rec is not None and check_invariants(entry, rec) == [], v
    for v, size in shifted.items():
        rec = parse_0x147b(0, _synthetic_shifted(v, size, 1))
        assert rec is not None and check_invariants(entry, rec) == [], v
