"""Public zero-PII fixture for 0x15BD (rare GNSS report, RGS log packet).

Tier-1 (public_corpus.risk_tiers.RISK_TIER[0x15BD] == 1): the parser leaves
an undecoded body_raw tail, so this frame is built entirely from fabricated
values via public_corpus.support.synthetic -- no bytes are copied from any
capture, private test, or real DIAG log.

Targets the v=3 (modern) decode path in diaggrok.parsers.diag_0x15bd:
9-byte header (version @0, sub_type @1, counter @2, byte_3 @3,
record_type_tag @4, header_tick u32 @5:9) followed by the fixed array of
ten 28-byte sub-records (builders zero-pad a shorter list to ten, since a
payload shorter than 285/289 B is truncated -> None), each a
V3SubRecord (tick u32 @0, kind u8 @7, aux_u16 u16 @4, field_x u16 @12,
field_y i16 @16, field_z i16 @18, aux_byte u8 @26).
"""
from public_corpus.support.synthetic import diag_frame, pack
from diaggrok.parsers.diag_0x15bd import parse_0x15bd

# Fabricated header values (not from any real capture).
_SUB_TYPE = 1
_COUNTER = 7
_BYTE_3 = 0
_RECORD_TYPE_TAG = 10          # 0x0A -- corpus-wide invariant
_HEADER_TICK = 123_456         # u32 @5:9 -- log-emission tick

# Fabricated single v3 sub-record values (not from any real capture).
_SR_TICK = 1000                # u32 @0
_SR_AUX_U16 = 0xC050           # u16 @4
_SR_KIND = 0x57                # u8 @7 -- "kind A" tag
_SR_FIELD_X = 27000            # u16 @12
_SR_FIELD_Y = -870             # i16 @16
_SR_FIELD_Z = 2160             # i16 @18
_SR_AUX_BYTE = 5               # u8 @26


_SR_SESSION_TAG = 0xAC         # u8 @6 -- per-capture constant, kind-A only
_SR_END_TAG_B = 0x01           # u8 @25 -- sub-record class tag
_SR_BYTE_27 = 0xE8             # u8 @27 -- live, unidentified, kind-A only
_SR_FLAG_14 = 0                # u16 @14 -- 0 except RG520N-NA (==1)


def _synthetic_subrecord(
    *,
    tick: int = _SR_TICK,
    kind: int = _SR_KIND,
    session_tag: int = _SR_SESSION_TAG,
    end_tag_b: int = _SR_END_TAG_B,
    byte_27: int = _SR_BYTE_27,
    flag_14: int = _SR_FLAG_14,
    field_y: int = _SR_FIELD_Y,
) -> bytes:
    """Build one fabricated 28-byte V3SubRecord.

    Byte [6] defaults to 0xAC, not 0x0F: the capture corpus shows 17
    distinct values there, constant per capture, so 0x0F is not a format
    constant. Byte [27] likewise defaults to a nonzero value -- it is live on
    98.7% of kind-A sub-records, not a constant 1.
    """
    sr = (
        pack('<I', tick)           # [0:4]
        + pack('<H', _SR_AUX_U16)  # [4:6]
        + pack('<B', session_tag)  # [6] possibly_session_tag (kind-A only)
        + pack('<B', kind)         # [7] kind_tag
        + bytes(4)                 # [8:12] reserved
        + pack('<H', _SR_FIELD_X)  # [12:14]
        + pack('<H', flag_14)      # [14:16] flag_14
        + pack('<h', field_y)      # [16:18]
        + pack('<h', _SR_FIELD_Z)  # [18:20]
        + bytes(4)                 # [20:24] reserved
        + pack('<B', 1)            # [24] end_tag_a
        + pack('<B', end_tag_b)    # [25] end_tag_b -- real class tag
        + pack('<B', _SR_AUX_BYTE)  # [26] aux_byte
        + pack('<B', byte_27)      # [27] byte_27 -- live, unidentified
    )
    assert len(sr) == 28
    return sr


def _synthetic_15bd() -> bytes:
    """Build a v=3 0x15BD payload: 9-byte header + one 28-byte sub-record.

      data[0]    version = 3               (supplied via diag_frame)
      data[1]    sub_type = 1
      data[2]    counter = 7
      data[3]    byte_3 = 0
      data[4]    record_type_tag = 10 (0x0A)
      data[5:9]  u32 header_tick = 123456
      data[9:37] one 28-byte V3SubRecord (see _synthetic_subrecord)
    """
    return _synthetic_15bd_with([_synthetic_subrecord()])


def _pad10(subrecords: list[bytes]) -> list[bytes]:
    """Zero-pad a sub-record list to the fixed array of 10: a
    shorter payload is truncated and parses to None."""
    return list(subrecords) + [bytes(28)] * (10 - len(subrecords))


def _synthetic_15bd_with(
    subrecords: list[bytes], header_tick: int = _HEADER_TICK
) -> bytes:
    """Build a v=3 0x15BD payload from an explicit sub-record list
    (zero-padded to the fixed 10 sub-records)."""
    subrecords = _pad10(subrecords)
    header_tail = (
        pack('<B', _SUB_TYPE)
        + pack('<B', _COUNTER)
        + pack('<B', _BYTE_3)
        + pack('<B', _RECORD_TYPE_TAG)
        + pack('<I', header_tick)
    )
    frame = diag_frame(0x15BD, 3, header_tail + b''.join(subrecords))
    assert len(frame) == 9 + 28 * len(subrecords)
    return frame


def test_15bd_decodes_synthetic_frame():
    rec = parse_0x15bd(1000, _synthetic_15bd())
    assert rec is not None
    assert rec.version == 3
    assert rec.sub_type == _SUB_TYPE
    assert rec.counter == _COUNTER
    assert rec.byte_3 == _BYTE_3
    assert rec.record_type_tag == _RECORD_TYPE_TAG
    assert rec.header_tick == _HEADER_TICK
    assert rec.payload_size == 289
    assert len(rec.v3_sub_records) == 10
    sr = rec.v3_sub_records[0]
    assert sr.tick == _SR_TICK
    assert sr.kind == _SR_KIND
    assert sr.aux_u16 == _SR_AUX_U16
    assert sr.field_x == _SR_FIELD_X
    assert sr.field_y == _SR_FIELD_Y
    assert sr.field_z == _SR_FIELD_Z
    assert sr.aux_byte == _SR_AUX_BYTE
    assert rec.v2_sub_records == []


def test_15bd_counter16_composes_low_and_high_bytes():
    """byte[2..3] is a single u16LE record counter:
    counter (byte 2) is the low byte, byte_3 (byte 3) the high byte.

    Verified across RM520N-GL (v=3) and MC7455 (v=2) by exact +1 monotonicity
    and a byte_3 carry at each byte-2 wrap. Here counter=7, byte_3=0 → 7.
    """
    rec = parse_0x15bd(1000, _synthetic_15bd())
    assert rec is not None
    assert rec.counter16 == _COUNTER | (_BYTE_3 << 8)
    assert rec.counter16 == 7
    assert rec.to_dict()['counter16'] == 7


def test_15bd_counter16_carry_at_byte2_wrap():
    """When byte 2 wraps 255→0, byte_3 carries 0→1 — the signature that
    identified byte_3 as the counter high byte (not an 'unidentified' flag)."""
    # Build a frame with counter=0x00 (byte 2) and byte_3=0x01 (byte 3):
    # counter16 = 0x0100 = 256 = the record just after a byte-2 wrap.
    header_tail = (
        pack('<B', _SUB_TYPE)
        + pack('<B', 0x00)          # byte 2 (counter low) wrapped to 0
        + pack('<B', 0x01)          # byte 3 (counter high) carried to 1
        + pack('<B', _RECORD_TYPE_TAG)
        + pack('<I', _HEADER_TICK)
    )
    frame = diag_frame(0x15BD, 3, header_tail + b''.join(_pad10([_synthetic_subrecord()])))
    rec = parse_0x15bd(1000, frame)
    assert rec is not None
    assert rec.counter == 0x00
    assert rec.byte_3 == 0x01
    assert rec.counter16 == 256


# ---------------------------------------------------------------------------
# Sub-record bytes [6], [14:16], [25], [27], and the sub-record class tag
# that kind_tag alone cannot express. Corpus basis for every claim
# referenced below: 7,465 records / 73 captures / 45 chipsets.
# ---------------------------------------------------------------------------

def test_15bd_v3_exposes_the_four_previously_dropped_bytes():
    """Bytes [6], [14:16], [25] and [27] must be decoded, not just
    [0:8], [12:14], [16:20] and [26].

    Byte [27] alone is nonzero in 6,326/6,408 kind-A sub-records (98.7%) and
    in 0/66,182 non-kind-A, so dropping it would discard live payload on
    nearly every kind-A sub-record in the corpus.
    """
    rec = parse_0x15bd(1000, _synthetic_15bd())
    assert rec is not None
    sr = rec.v3_sub_records[0]
    assert sr.possibly_session_tag == _SR_SESSION_TAG   # [6]
    assert sr.flag_14 == _SR_FLAG_14                    # [14:16]
    assert sr.end_tag_b == _SR_END_TAG_B                # [25]
    assert sr.byte_27 == _SR_BYTE_27                    # [27]
    d = sr.to_dict()
    for key in ('possibly_session_tag', 'flag_14', 'end_tag_b', 'byte_27'):
        assert key in d, f'{key} must reach to_dict(), not just the dataclass'


def test_15bd_end_tag_b_distinguishes_the_0x11_class_kind_tag_cannot():
    """byte [25] == 0x11 is a sub-record class as common as 0x0D (32,995 vs
    33,120 corpus-wide) that ``kind_tag`` alone cannot express: both carry
    ``kind_tag == 0x00``, so a binary A/B model lumps them together.

    ``end_tag_b`` is a **per-sub-record sample type**, not a whole-record
    mode: 0x0D and 0x11 can appear in the same payload (see
    :func:`test_15bd_end_tag_b_classes_interleave` and the V3SubRecord
    docstring). This test only pins that ``kind_tag``
    cannot separate the two classes but ``end_tag_b`` can.
    """
    kind_b_0d = _synthetic_subrecord(
        kind=0x00, session_tag=0, end_tag_b=0x0D, byte_27=0)
    kind_b_11 = _synthetic_subrecord(
        kind=0x00, session_tag=0, end_tag_b=0x11, byte_27=0)
    rec = parse_0x15bd(1000, _synthetic_15bd_with([kind_b_0d, kind_b_11]))
    assert rec is not None
    a, b = rec.v3_sub_records[:2]
    # kind_tag is identical -- it cannot tell these apart...
    assert a.kind == b.kind == 0x00
    # ...but end_tag_b can.
    assert a.end_tag_b == 0x0D
    assert b.end_tag_b == 0x11


def test_15bd_end_tag_b_classes_interleave():
    """0x0D, 0x11 and kind-A (0x01) are per-sub-record sample types that
    FREELY INTERLEAVE in one record; a payload is not all-0x11 or all-0x0D.

    Continuous-measurement drive captures fill all ten 1 Hz slots with the
    same measurement class (pure ``0x0D×10`` / ``0x11×10``), so they *look*
    like a whole-record mode, while stationary bench captures interleave
    kind-A status sub-records and show 0x0D and 0x11 co-occurring. Seen
    byte-for-byte on two drop-free bench captures: an EM9291 capture (a real
    record decodes ``DDDQQQQAQQ`` = 3×0x0D + 6×0x11 + 1×kind-A) and an
    RM500Q-AE capture (``AQAAAAAAAD``). Those bytes stay
    out of this Tier-1 public fixture; this test reproduces the *shape*
    synthetically -- the exact class multiset of the em9291 record -- and pins
    that the parser decodes every slot's class independently, in order.
    """
    # Same class multiset + order as the real em9291 DDDQQQQAQQ record.
    pattern = [0x0D, 0x0D, 0x0D, 0x11, 0x11, 0x11, 0x11, 0x01, 0x11, 0x11]
    subs = [
        _synthetic_subrecord(
            kind=(0x57 if tag == 0x01 else 0x00),
            session_tag=(0x93 if tag == 0x01 else 0),
            end_tag_b=tag,
            byte_27=(0x77 if tag == 0x01 else 0))
        for tag in pattern
    ]
    rec = parse_0x15bd(1000, _synthetic_15bd_with(subs))
    assert rec is not None
    assert len(rec.v3_sub_records) == 10
    # Every slot's class decodes independently, in the order emitted.
    assert [sr.end_tag_b for sr in rec.v3_sub_records] == pattern
    tags = {sr.end_tag_b for sr in rec.v3_sub_records}
    assert tags == {0x0D, 0x11, 0x01}, 'all three classes coexist in one record'
    # kind-A slot is the only one carrying kind_tag 0x57 + a session tag.
    kind_a = [sr for sr in rec.v3_sub_records if sr.end_tag_b == 0x01]
    assert len(kind_a) == 1 and kind_a[0].kind == 0x57


def test_15bd_header_tick_is_the_last_subrecord_tick():
    """``header_tick`` == ``v3_sub_records[-1].tick`` in 7,053/7,259 records
    and that +1 in the remaining 206 -- nothing else, ever.

    Measured against sub-record [0], the delta looks like a chipset-specific
    quantity; it is just the span of the 10-sub-record window. Both fields must be surfaced for the relation to
    be checkable, which is what this test pins.
    """
    ticks = [_SR_TICK + 1000 * i for i in range(10)]
    subs = [_synthetic_subrecord(tick=t) for t in ticks]
    rec = parse_0x15bd(1000, _synthetic_15bd_with(subs, header_tick=ticks[-1]))
    assert rec is not None
    assert len(rec.v3_sub_records) == 10
    assert rec.header_tick == rec.v3_sub_records[-1].tick
    assert 0 <= rec.header_tick - rec.v3_sub_records[-1].tick <= 1
    # ...and the weaker sub-record [0] relation also holds:
    assert rec.header_tick > rec.v3_sub_records[0].tick


def test_15bd_v3_flag_14_is_not_always_zero():
    """[14:16] is documented "always 0" but is a constant 1 on Quectel
    RG520N-NA (390/72,590 sub-records, exactly 2 captures). A parser that
    drops it cannot represent that chipset's payload."""
    sr = _synthetic_subrecord(flag_14=1)
    rec = parse_0x15bd(1000, _synthetic_15bd_with([sr]))
    assert rec is not None
    assert rec.v3_sub_records[0].flag_14 == 1


# ---------------------------------------------------------------------------
# v=2 (MC7455 MDM9x30 legacy) -- signedness and field-name alignment with v=3
# ---------------------------------------------------------------------------

def _synthetic_v2_subrecord(*, raw_16: int, raw_18: int) -> bytes:
    """One fabricated 28-byte V2SubRecord; [16:18]/[18:20] set as raw u16."""
    sr = (
        pack('<B', 0x76)        # [0]     slot_id
        + pack('<B', 5)         # [1]     tag_a
        + pack('<B', 7)         # [2]     tag_b
        + pack('<B', 0x57)      # [3]     tag_c
        + bytes(8)              # [4:12]  reserved
        + pack('<H', 26173)     # [12:14] field_x (also exposed as the "tick" alias)
        + bytes(2)              # [14:16] reserved
        + pack('<H', raw_16)    # [16:18] field_y
        + pack('<H', raw_18)    # [18:20] field_z
        + bytes(4)              # [20:24] reserved
        + pack('<B', 1)         # [24]    end_tag_a
        + pack('<B', 0x0D)      # [25]    end_tag_b
        + bytes(2)              # [26:28] reserved
    )
    assert len(sr) == 28
    return sr


def _synthetic_15bd_v2(subrecords: list[bytes]) -> bytes:
    header_tail = (
        pack('<B', _SUB_TYPE)
        + pack('<B', _COUNTER)
        + pack('<B', _BYTE_3)
        + pack('<B', _RECORD_TYPE_TAG)
    )
    return diag_frame(0x15BD, 2, header_tail + b''.join(_pad10(subrecords)))


def test_15bd_v2_field_y_and_z_are_signed_not_unsigned():
    """v=2 [16:18]/[18:20] are ``<h``, not ``<H``.

    A u16 histogram over all 2,060 v=2 sub-records in the corpus is bimodal
    at the two extremes and EMPTY in between -- 310 in 0..4,095 and 1,750
    (85.0%) in 61,440..65,535 -- which is the signature of a signed field
    misread as unsigned. The same offsets are ``<h`` on v=3, whose range
    genuinely spans -5,369..3,544.

    0xF852 == 63,570 unsigned, -1,966 signed; an unsigned read would report
    63,570-class values for 85% of the v=2 corpus.
    """
    rec = parse_0x15bd(1000, _synthetic_15bd_v2(
        [_synthetic_v2_subrecord(raw_16=0xF852, raw_18=0xF9A0)]))
    assert rec is not None
    assert rec.version == 2
    sub = rec.v2_sub_records[0]
    assert sub.field_y == -1966      # NOT 63570
    assert sub.field_z == -1632      # NOT 63904
    # Back-compat aliases carry the signed values too.
    assert sub.field_a == -1966
    assert sub.field_b == -1632


def test_15bd_v2_tick_is_a_deprecated_alias_for_field_x():
    """v=2 byte [12:14] is v=3's ``field_x``, not a clock: v=2 has no
    millisecond tick at all (that is the v=3-only u32 at [0:4]). The
    ``tick`` name survives only as an alias."""
    rec = parse_0x15bd(1000, _synthetic_15bd_v2(
        [_synthetic_v2_subrecord(raw_16=100, raw_18=200)]))
    assert rec is not None
    sub = rec.v2_sub_records[0]
    assert sub.field_x == 26173
    assert sub.tick == sub.field_x
    d = sub.to_dict()
    assert d['field_x'] == 26173 and d['tick'] == 26173
    assert d['end_tag_b'] == 0x0D


# ---------------------------------------------------------------------------
# v=2 -- the whole sub-record is the v=3 layout; [0:4] is time_s in SECONDS.
# Every value below is fabricated.
# ---------------------------------------------------------------------------

_V2_TIME_S = 0x4A3B2C1D        # u32 @0 -- fabricated seconds value
_V2_AUX_U16 = 0x2C1D           # u16 @4 -- == time_s & 0xFFFF on kind A
_V2_SESSION_TAG = 0x2B         # u8 @6
_V2_BYTE_27 = 0x91             # u8 @27
_V2_AUX_BYTE = 0x3C            # u8 @26


def _synthetic_v2_full_subrecord(*, time_s: int, kind_a: bool) -> bytes:
    """One fabricated 28-byte v=2 sub-record in the v=3 layout."""
    sr = (
        pack('<I', time_s)                                  # [0:4]   time_s
        + pack('<H', _V2_AUX_U16 if kind_a else 0)          # [4:6]   aux_u16
        + pack('<B', _V2_SESSION_TAG if kind_a else 0)      # [6]
        + pack('<B', 0x57 if kind_a else 0)                 # [7]     kind
        + bytes(4)                                          # [8:12]
        + pack('<H', 31000)                                 # [12:14] field_x
        + bytes(2)                                          # [14:16] flag_14
        + pack('<h', -500)                                  # [16:18] field_y
        + pack('<h', 250)                                   # [18:20] field_z
        + bytes(4)                                          # [20:24]
        + pack('<B', 1)                                     # [24]
        + pack('<B', 0x01 if kind_a else 0x0D)              # [25]    end_tag_b
        + pack('<B', _V2_AUX_BYTE if kind_a else 0)         # [26]
        + pack('<B', _V2_BYTE_27 if kind_a else 0)          # [27]
    )
    assert len(sr) == 28
    return sr


def test_15bd_v2_time_s_is_the_u32_at_subrecord_offset_0():
    """v=2 [0:4] is one u32 -- ``time_s``, whole SECONDS of the DIAG-timestamp
    clock (== floor(ts64 s) of the record in 243/243 real records; F3
    ``gpstask.c:957`` calls it ``time_stamp_local``). The ``slot_id`` /
    ``tag_a`` aliases are just its bytes [0]/[1], and the "tag_b 7 / tag_c
    0x57" pair that looks invariant in short captures is its upper bytes."""
    subs = [_synthetic_v2_full_subrecord(time_s=_V2_TIME_S + i, kind_a=False)
            for i in range(10)]
    rec = parse_0x15bd(1000, _synthetic_15bd_v2(subs))
    assert rec is not None and rec.version == 2
    assert len(rec.v2_sub_records) == 10
    s0, s9 = rec.v2_sub_records[0], rec.v2_sub_records[-1]
    assert s0.time_s == _V2_TIME_S
    assert s9.time_s == _V2_TIME_S + 9
    assert s0.slot_id == _V2_TIME_S & 0xFF
    assert s0.tag_a == (_V2_TIME_S >> 8) & 0xFF
    # v=2 has no header_tick: payload [5:9] is sub-record 0's time_s.
    assert rec.header_tick == s0.time_s
    assert s9.to_dict()['time_s'] == _V2_TIME_S + 9


def test_15bd_v2_kind_a_bytes_4_to_8_and_26_27_decode_as_v3():
    """The kind-A trio at [4:8] (aux_u16, possibly_session_tag, kind 0x57)
    and [26]/[27] decode on v=2 too -- they sit at the same offsets as on
    v=3, and kind A always carries end_tag_b 0x01."""
    rec = parse_0x15bd(1000, _synthetic_15bd_v2(
        [_synthetic_v2_full_subrecord(time_s=_V2_TIME_S, kind_a=True),
         _synthetic_v2_full_subrecord(time_s=_V2_TIME_S, kind_a=False)]))
    assert rec is not None
    a, b = rec.v2_sub_records[:2]
    assert (a.kind, a.aux_u16, a.possibly_session_tag) == (0x57, _V2_AUX_U16, _V2_SESSION_TAG)
    assert a.aux_u16 == a.time_s & 0xFFFF
    assert (a.end_tag_b, a.aux_byte, a.byte_27, a.flag_14) == (0x01, _V2_AUX_BYTE, _V2_BYTE_27, 0)
    assert (b.kind, b.aux_u16, b.possibly_session_tag, b.end_tag_b) == (0, 0, 0, 0x0D)
    d = a.to_dict()
    for k in ('aux_u16', 'possibly_session_tag', 'kind', 'flag_14', 'aux_byte', 'byte_27'):
        assert k in d
    assert (a.field_x, a.field_y, a.field_z) == (31000, -500, 250)


def test_15bd_v2_time_s_is_not_the_v3_millisecond_tick():
    """Same offset, different quantity: on v=3 [0:4] of a sub-record is the
    millisecond ``tick`` (after a 9-byte header); on v=2 it is ``time_s`` in
    seconds (after a 5-byte header). A v=2 payload must never populate
    v3_sub_records, nor a v=3 payload v2_sub_records."""
    rec = parse_0x15bd(1000, _synthetic_15bd_v2(
        [_synthetic_v2_full_subrecord(time_s=_V2_TIME_S, kind_a=False)]))
    assert rec is not None
    assert rec.v3_sub_records == []
    assert rec.v2_sub_records[0].time_s == _V2_TIME_S


def test_15bd_truncated_payload_returns_none_5171():
    """v8: v=3 289 B / v=2 285 B are a fixed header +
    10 x 28 B sub-records; one byte short -> None (registry WARN) instead of
    silently dropping the partial tail sub-record. Never raises."""
    for frame, size in ((_synthetic_15bd(), 289),
                        (_synthetic_15bd_v2([_synthetic_v2_subrecord(raw_16=1, raw_18=2)]), 285)):
        assert len(frame) == size
        assert parse_0x15bd(1000, frame) is not None
        assert parse_0x15bd(1000, frame[:-1]) is None
        for n in range(len(frame)):
            assert parse_0x15bd(1000, frame[:n]) is None
