"""Public zero-PII fixture for 0x4179 (LTE intra-freq neighbor measurement).

Tier 1 (synthetic-only, see public_corpus.risk_tiers.RISK_TIER[0x4179] == 1):
``camp_context_u32`` is flagged in the parser's own field comment as a
"serving-cell / coarse-time candidate" -- so this frame is built entirely
from fabricated values via public_corpus.support.synthetic -- no bytes are
copied from any capture, private test, or real DIAG log.

Targets the simplest supported shape: v=0x08 (FN980m/RM5xx/SIM8202G-M2)
at exactly the base size (77 B), which also happens to satisfy the
on-formula stacked-preamble law with block_count=1 (sz == c0 + stride*B ==
14 + 63*1 == 77), so the single measurement block IS the tail block
(no multi-layer / no prev-window decode paths are exercised). Offsets
below are transcribed from diaggrok.parsers.diag_0x4179's live
``parse_0x4179`` / ``_LAYOUT[0x08]`` code, not the module's prose
narrative:

    Prefix (15 B), data[0:15]:
      [0]     u8   version = 0x08
      [1]     u8   sub_format = 0x01               (RM520N-GL constant)
      [2]     u8   prefix_flag_a (in {1,3})
      [3:5]   u16  seq_u16
      [5:8]   3 B  format_const_raw = 00 02 00      (RM520N-GL constant)
      [8:12]  u32  camp_context_u32
      [12]    u8   block_count (blkcount_off, must mirror the size law)
      [13]    u8   prefix_flag_b (in {0,4})
      [14]    u8   prefix_tag = 0x01                (RM520N-GL constant)

    Preamble (11 B), data[15:26] -- the ONE block (also the tail block):
      [+0:3]  3 B  marker = 23 00 00
      [+3:7]  u32  value (per-block counter/ts-shaped)
      [+7:10] 3 B  const = c0 00 04
      [+10]   u8   delim = 0x00 (final block)

    Gap (3 B, data[26:29]) -- constant 0x00 fill.

    Tail Block48 (48 B), data[29:77]:
      arrayA[6] u32 LE @ data[29:53]
      arrayB[6] u32 LE @ data[53:77]
"""
from public_corpus.support.synthetic import diag_frame, pack
from diaggrok.parsers.diag_0x4179 import parse_0x4179

_VERSION = 0x08

# Fabricated prefix values (not from any real capture).
_SUB_FORMAT = 0x01
_PREFIX_FLAG_A = 1
_SEQ = 4660
_FORMAT_CONST = b"\x00\x02\x00"
_CAMP_CONTEXT = 0x0A0B0C0D
_BLOCK_COUNT = 1
_PREFIX_FLAG_B = 0
_PREFIX_TAG = 0x01

# Fabricated preamble value (not from any real capture).
_PREAMBLE_MARKER = b"\x23\x00\x00"
_PREAMBLE_CONST = b"\xc0\x00\x04"
_PREAMBLE_VALUE = 0x11223344

# Fabricated tail arrays -- arrayB non-strictly descending, arrayA
# byte3==0/byte2<=4 on populated (arrayB!=0) slots, matching the Block48
# invariants the parser's tail-array read expects corpus-wide.
_ARRAY_A = [1000, 2000, 3000, 0, 0, 0]
_ARRAY_B = [500, 400, 300, 0, 0, 0]


def _synthetic_4179() -> bytes:
    """Build a v=0x08, base-size (77-byte) 0x4179 record from fabricated
    bytes. ``diag_frame`` supplies the version byte at data[0]; the rest
    (prefix tail + preamble + gap + tail Block48) is assembled here.
    """
    prefix_tail = (
        bytes([_SUB_FORMAT])                # data[1]
        + bytes([_PREFIX_FLAG_A])           # data[2]
        + pack('<H', _SEQ)                  # data[3:5]
        + _FORMAT_CONST                      # data[5:8]
        + pack('<I', _CAMP_CONTEXT)          # data[8:12]
        + bytes([_BLOCK_COUNT])             # data[12]
        + bytes([_PREFIX_FLAG_B])           # data[13]
        + bytes([_PREFIX_TAG])              # data[14]
    )
    assert len(prefix_tail) == 14  # prefix_size(15) minus the version byte

    preamble = (
        _PREAMBLE_MARKER
        + pack('<I', _PREAMBLE_VALUE)
        + _PREAMBLE_CONST
        + bytes([0x00])  # delim == 0 -> final (and only) block
    )
    assert len(preamble) == 11

    gap = bytes(3)  # data[26:29] -- constant 0x00 fill for v=0x08

    tail_block = pack('<6I', *_ARRAY_A) + pack('<6I', *_ARRAY_B)
    assert len(tail_block) == 48

    body = prefix_tail + preamble + gap + tail_block
    assert len(body) == 76  # 77-byte record minus the version byte

    data = diag_frame(0x4179, _VERSION, body)
    assert len(data) == 77
    return data


def test_4179_decodes_synthetic_frame():
    rec = parse_0x4179(1000, _synthetic_4179())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.payload_size == 77
    assert rec.header_size == 29
    assert rec.block_count == _BLOCK_COUNT
    assert rec.block_count_mirror_ok is True
    assert rec.seq_u16 == _SEQ
    assert rec.camp_context_u32 == _CAMP_CONTEXT
    assert rec.prefix_flag_a == _PREFIX_FLAG_A
    assert rec.prefix_flag_b == _PREFIX_FLAG_B
    assert rec.sub_format == _SUB_FORMAT
    assert rec.format_const_raw == _FORMAT_CONST
    assert rec.prefix_tag == _PREFIX_TAG
    assert rec.prefix_const_ok is True

    assert len(rec.preambles) == 1
    assert rec.preambles[0]["value"] == _PREAMBLE_VALUE
    assert rec.preambles[0]["marker_ok"] is True
    assert rec.preambles[0]["const_ok"] is True
    assert rec.preambles[0]["is_final"] is True

    assert rec.array_a_raw == _ARRAY_A
    assert rec.array_b_raw == _ARRAY_B
    assert rec.earfcn_or_freq == [1000, 2000, 3000, None, None, None]
    assert rec.measurement_raw == [500, 400, 300, None, None, None]
    assert rec.measured_cell_count == 3

    # Base-size record -> no multi-layer blocks, no prior-window decode.
    assert rec.blocks == []
    assert rec.block_trailers_zeroed is True
    assert rec.prev_measured_cell_count is None
