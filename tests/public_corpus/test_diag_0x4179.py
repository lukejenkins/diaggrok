"""Public zero-PII fixture for 0x4179 (WCDMA PN search results).

Tier 1 (synthetic-only, see public_corpus.risk_tiers.RISK_TIER[0x4179] == 1):
the record carries a UARFCN + per-task scrambling codes (cell identity, no
PII) -- this frame is nonetheless built entirely from fabricated values via
public_corpus.support.synthetic; no bytes are copied from any capture,
private test, or real DIAG log.

Targets the simplest supported shape: v=0x08 (SDX55/SDX62 family) at exactly
the base size (77 B): one search task (one preamble) with one result set,
which satisfies the size law with num_tasks=1 / results_per_task=1
(sz == 14 + 1*(15 + 48*1) == 77). Offsets are transcribed from
diaggrok.parsers.diag_0x4179's live ``parse_0x4179`` / ``_LAYOUT[0x08]``:

    Prefix (15 B), data[0:15]:
      [0]     u8   version = 0x08
      [1]     u8   sub_format = 0x01               (RM520N-GL constant)
      [2]     u8   prefix_flag_a
      [3:5]   u16  prefix_u16_at3 (unnamed)
      [5:8]   3 B  format_const_raw = 00 02 00      (RM520N-GL constant)
      [8:10]  u16  uarfcn
      [10:12] 2 B  unnamed
      [12]    u8   num_tasks (must mirror the size law)
      [13]    u8   prefix_flag_b
      [14]    u8   prefix_tag = 0x01                (RM520N-GL constant)

    Preamble (11 B), data[15:26] -- the ONE task:
      [+0]    u8   marker = 0x23
      [+1]    u8   flags (0 = one result set)
      [+2]    u8   00
      [+3:5]  2 B  unnamed word
      [+5:7]  u16  scr_code = psc * 16
      [+7:9]  2 B  const = c0 00
      [+9]    u8   flag_a
      [+10]   u8   0x00 -> final (last) task

    Gap (3 B, data[26:29]) -- constant 0x00 fill.

    Peaks (48 B), data[29:77]:
      peak_pos_cx8[6] u32 LE @ data[29:53]   (chip x8, < 307200)
      peak_energy[6]  u32 LE @ data[53:77]   (descending, zero-fill)
"""
from public_corpus.support.synthetic import diag_frame, pack
from diaggrok.parsers.diag_0x4179 import parse_0x4179

_VERSION = 0x08

# Fabricated prefix values (not from any real capture).
_SUB_FORMAT = 0x01
_PREFIX_FLAG_A = 1
_U16_AT3 = 4660
_FORMAT_CONST = b"\x00\x02\x00"
_UARFCN = 9700
_PREFIX_WORD = b"\x0b\x0a"
_NUM_TASKS = 1
_PREFIX_FLAG_B = 0
_PREFIX_TAG = 0x01

# Fabricated task preamble values (not from any real capture).
_PSC = 321
_PREAMBLE_WORD = b"\x33\x44"

# Fabricated peaks -- energies non-increasing, positions < 307200 on reported
# slots, matching the peak-block invariants the parser gates on corpus-wide.
_PEAK_POS = [1000, 2000, 3000, 0, 0, 0]
_PEAK_ENG = [500, 400, 300, 0, 0, 0]


def _synthetic_4179() -> bytes:
    """Build a v=0x08, base-size (77-byte) 0x4179 record from fabricated
    bytes. ``diag_frame`` supplies the version byte at data[0]; the rest
    (prefix tail + preamble + gap + peaks) is assembled here.
    """
    prefix_tail = (
        bytes([_SUB_FORMAT])                # data[1]
        + bytes([_PREFIX_FLAG_A])           # data[2]
        + pack('<H', _U16_AT3)              # data[3:5]
        + _FORMAT_CONST                      # data[5:8]
        + pack('<H', _UARFCN)                # data[8:10]
        + _PREFIX_WORD                       # data[10:12]
        + bytes([_NUM_TASKS])               # data[12]
        + bytes([_PREFIX_FLAG_B])           # data[13]
        + bytes([_PREFIX_TAG])              # data[14]
    )
    assert len(prefix_tail) == 14  # prefix_size(15) minus the version byte

    preamble = (
        b"\x23\x00\x00"                      # marker, flags=0, 00
        + _PREAMBLE_WORD                     # [+3:5]
        + pack('<H', _PSC * 16)              # scr_code
        + b"\xc0\x00"                        # const
        + b"\x04"                            # flag_a
        + b"\x00"                            # final (only) task
    )
    assert len(preamble) == 11

    gap = bytes(3)  # data[26:29] -- constant 0x00 fill for v=0x08

    peaks = pack('<6I', *_PEAK_POS) + pack('<6I', *_PEAK_ENG)
    assert len(peaks) == 48

    body = prefix_tail + preamble + gap + peaks
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
    assert rec.num_tasks == _NUM_TASKS
    assert rec.num_tasks_mirror_ok is True
    assert rec.results_per_task == 1
    assert rec.tasks_capped is False
    assert rec.uarfcn == _UARFCN
    assert rec.prefix_u16_at3 == _U16_AT3
    assert rec.prefix_flag_a == _PREFIX_FLAG_A
    assert rec.prefix_flag_b == _PREFIX_FLAG_B
    assert rec.sub_format == _SUB_FORMAT
    assert rec.format_const_raw == _FORMAT_CONST
    assert rec.prefix_tag == _PREFIX_TAG
    assert rec.prefix_const_ok is True

    assert len(rec.preambles) == 1
    assert rec.preambles[0]["psc"] == _PSC
    assert rec.preambles[0]["scr_code"] == _PSC * 16
    assert rec.preambles[0]["marker_ok"] is True
    assert rec.preambles[0]["const_ok"] is True
    assert rec.preambles[0]["is_final"] is True
    assert rec.psc_list == [_PSC]

    assert rec.array_a_raw == _PEAK_POS
    assert rec.array_b_raw == _PEAK_ENG
    assert rec.peak_pos_cx8 == [1000, 2000, 3000, None, None, None]
    assert rec.peak_energy == [500, 400, 300, None, None, None]
    assert rec.peaks_reported == 3

    assert len(rec.tasks) == 1
    assert rec.tasks[0].psc == _PSC
    assert rec.tasks[0].results[0].peak_energy == rec.peak_energy
    assert rec.tasks[0].trailer_raw == b""
    assert rec.block_trailers_zeroed is True
