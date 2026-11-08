"""GNSS/RF state flag (0x197F) — 4 B state word, plus a 9,244 B capture form.

Sibling pair with 0x1980 — both codes emit an identical 4-byte payload
during airplane-mode and SIM power-cycle transitions. All 39 observed
records (30 airplane + 9 SIM per code) carry the same constant u32 value
0xC002F2A0. The two codes appear in the same events with the same
counts, suggesting they are the same state word reported by two
different subsystems simultaneously.

Layout (4 B fixed):
    [0:4]  u32 LE  state_word — observed constant 0xC002F2A0 across all records

## The 9,244 B capture form, decoded since v3

Until v3 the parser dropped this form without decoding it (the census's
``0x02 @ 9244 B`` row, 1,055 records). It is always exactly 9,244 B and always
starts ``02 01 00 00``. Seen on 15+ models (T99W640, FT980m, FX3100, LV55,
RXM-G1, FX2000, SIM8202G, M2100, T99W373, RM500Q, EM9190, EM9291, T99W175,
M2000, FN980), i.e. SDX55 / SDX62 / SDX65 / SDX72 class parts.

    [0:4]      u32  format_word    0x00000102 on every record (gated)
    [4:8]      u32  word_4         24-bit varying value (byte 7 is 0)
    [8:12]     u32  stream_id      1..32, 1-4 values per capture
    [12:16]    u32  capture_index  monotonic within one stream_id (139/142
                                   and 113/113 steps increase on M2000)
    [16:20]    u32  word_16        6 or 0 (follows stream_id on M2000)
    [20:24]    u32  word_20        1, 2 or 8 (8 on T99W640)
    [24:4120]  block_a, 4,096 B    smooth: the even and the odd bytes each
                                   trace a slow waveform (8-bit I/Q pairs,
                                   2,048 samples)
    [4120:]    block_b, 5,124 B    near-random as bytes; read as 10-bit LE
                                   signed values it smooths best of the
                                   packings tried (2,048 complex samples x 2 x
                                   10 bit = 5,120 B), CANDIDATE only

F3 puts 43-47 % of these records on PA autopin prints (control 0, below), and
autopin works on feedback-receiver IQ captures. So the likeliest reading is
a Tx-reference / FBRx sample-capture dump. The blocks are kept raw
(``block_a`` / ``block_b``). Any other format word, or any size other than
4 B or 9,244 B, is dropped with a WARN naming the reason, so a new form gets
noticed.

On the smallest capture of each of the 18 models carrying this form,
113 / 113 records decode, block A is smooth on
every one, block B near-random on every one. Corpus total (sidecars): 1,446
records on 82 captures, all 9,244 B / byte 0 0x02, with no other non-4 B size.

## byte-0 is not a version

byte-0 is **not** a DIAG version field — it is the **low byte of the
constant u32 `state_word`** (0xC002F2A0 LE ⇒ byte-0 == 0xA0). The entire
4-byte payload is a single all-constant state word across 39/39 observed
records; there is no version axis to gate. The parser rejects any foreign
payload via the strict `state_word` enum gate (strictly stronger than a
byte-0 gate would be), so a `field_invariants["version"]={enum:[0xA0]}`
declaration would be semantically false (0xA0 is a constant fragment, not a
version) while adding zero protection. The parser is declared
`version_less=True`, like 0x117B.

## F3 evidence per byte-0 key

Corpus tooling keys this version-less code on byte 0, so each key is
assessed separately. All F3-bearing captures (``0x79`` / ``0x99`` /
``0x98``-wrapped) were joined, comparing the co-emission rate within ±1 /
±10 ms of each record against the same rate at record time ±5 s:

* **v0xa0: no F3 available.** The ``0xC002F2A0`` state-word form lives on 6
  captures (EM7511 / MC7411 MDM9250 + one RM520N fragment), none of which
  carries F3.
* **v0x00: event grounded (the value is a constant).** 125 records /
  31 captures, overwhelmingly ``00 00 00 00``: the same 4 B state word holding
  0 (rejected by the ``0xC002F2A0`` gate). 80 records on all 18 F3-bearing
  captures: within ±10 ms, 95-96 % of records sit on an LTE RRC connection
  release (``lte_rrc_stm.c`` ``... LTE_RRC_CONN_RELEASED_INDI``, 17 captures),
  and within ±1 ms 84 % on RF front-end sleep (``[FEM tracker] ... sleep``,
  ``[ELNA] sleep()``, ``[ASM] sleep()``, 14 captures). The control rate is 0.
  So this key is an event-locked state word emitted at RRC release / RF
  sleep, consistent with the "mode-transition state flag" reading.
* **v0x02: inconclusive.** The 9,244 B structured form (parser rejects it):
  166 records on all 19 F3-bearing captures. 43-47 % co-fire with the PA
  autopin calibration prints (``rflm_autopin_proc.cc`` ``... done_handler``,
  7 captures, control 0): an RF-PA context, not GNSS. No print carries the
  body's values.
* **v0x1c: event grounded (the value is a per-build constant).** 195 records /
  27 captures, SDX55 only. Every record carries one word per firmware build:
  ``0xD801861C`` (R500L5, 168) or ``0xD801841C`` (RM500Q-AE, 26), so byte 0 is
  again the low byte of a data word. On the 119 records of qdb-resolved
  captures, all of them (both builds) sit within +/-1 ms of the LTE Tx-chain
  de-init (``rfcommon_xpt_deinit_tx``, ``rflm_vswr_capt_deinit``,
  ``[PA] sleep()``; control 0), emitted between ``rflte_core_xpt_deinit_tx``
  and ``rfcommon_xpt_deinit_tx``. The word does not follow the Tx handle
  those prints carry. Where only plaintext F3 is present, 78 % sit within
  +/-10 ms of the LTE ML1 tune manager ``FW_EXEC -> INACTIVE``. 101 records
  are followed within 1 ms by a 0x1980 4 B record carrying the same word or 0.

## What the 4 B word is (CANDIDATE)

Two words found on R500L5 records fall inside the modem image's code, and
both are return addresses: each is the instruction packet right after a
``call`` (one call targets a short wrapper with 405 call sites). The
``0xD80xxxxx`` words lie outside every loaded segment, in the demand-paged
code region, and are not resolved. So the word is most likely the return
address of the call site that emitted the record. It is kept raw.
"""
from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.parsers._short_form_4b import ShortForm4B, parse_short_form_4b
from diaggrok.registry import register

logger = logging.getLogger(__name__)
_LAYOUT_ALARMS: Counter = Counter()

#: The 9,244 B capture form: 24 B header + block A + block B.
_CAPTURE_SIZE = 9244
_CAPTURE_FORMAT_WORD = 0x00000102   # u32@0, "02 01 00 00" on every record
_CAPTURE_HEADER = 24
_CAPTURE_BLOCK_A = 4096             # [24:4120]
_CAPTURE_BLOCK_B = _CAPTURE_SIZE - _CAPTURE_HEADER - _CAPTURE_BLOCK_A  # 5124


def _layout_alarm(data: bytes, why: str) -> None:
    """WARN on a dropped record, naming its form and the reason.

    The registry's own WARN fires once per (code, byte 0), so a second
    unsupported size behind an already-seen byte 0 would go unreported.
    Logs the 1st, 10th, 100th, ... per (byte 0, len, reason).
    """
    key = (data[0] if data else None, len(data), why)
    _LAYOUT_ALARMS[key] += 1
    n = _LAYOUT_ALARMS[key]
    if str(n).rstrip("0") != "1":
        return
    logger.warning(
        "diaggrok 0x197F layout issue #%d: byte0=0x%02X len=%d head=%s — %s "
        "", n, data[0] if data else 0, len(data),
        data[:8].hex(), why,
    )


@dataclass
class Diag0x197F:
    """0x197F — GNSS/RF state flag, 4B fixed, constant state word."""
    log_time: int
    state_word: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x197F',
            'log_time': self.log_time,
            'state_word': self.state_word,
            'state_word_hex': f'{self.state_word:08x}',
        }


@dataclass
class Diag0x197FCapture:
    """0x197F 9,244 B capture form: 24 B header + two sample blocks.

    Header fields are named by their observed behaviour; the blocks are kept
    raw (see the module docstring, "The 9,244 B capture form").
    """
    log_time: int
    format_word: int        # u32@0, 0x00000102 on every record
    word_4: int             # u32@4, 24-bit varying value (byte 7 is 0)
    stream_id: int          # u32@8, one capture_index sequence per value
    capture_index: int      # u32@12, monotonic within a stream_id
    word_16: int            # u32@16
    word_20: int            # u32@20
    block_a: bytes          # [24:4120], 4,096 B
    block_b: bytes          # [4120:9244], 5,124 B
    payload_size: int = _CAPTURE_SIZE

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x197FCapture',
            'log_time': self.log_time,
            'format_word': self.format_word,
            'format_word_hex': f'{self.format_word:08x}',
            'word_4': self.word_4,
            'stream_id': self.stream_id,
            'capture_index': self.capture_index,
            'word_16': self.word_16,
            'word_20': self.word_20,
            'block_a_hex': self.block_a.hex(),
            'block_b_hex': self.block_b.hex(),
            'payload_size': self.payload_size,
        }


def _parse_capture(log_time: int, data: bytes) -> Diag0x197FCapture | None:
    fmt = unpack_from('<I', data, 0)[0]
    if fmt != _CAPTURE_FORMAT_WORD:
        _layout_alarm(data, f"9244 B form with format word 0x{fmt:08x}, "
                            "expected 0x00000102; record dropped")
        return None
    w4, stream, idx, w16, w20 = unpack_from('<5I', data, 4)
    a_end = _CAPTURE_HEADER + _CAPTURE_BLOCK_A
    return Diag0x197FCapture(
        log_time=log_time, format_word=fmt, word_4=w4, stream_id=stream,
        capture_index=idx, word_16=w16, word_20=w20,
        block_a=bytes(data[_CAPTURE_HEADER:a_end]), block_b=bytes(data[a_end:]),
    )


@register(
    0x197F, domain="gnss",
    name="0x197F",
    description=("GNSS/RF state flag (0x197F) — 4 B state word / short form, plus a "
                 "9,244 B capture form (24 B header + two raw sample blocks)"),
    version=3,
    issues=(),
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE from 39 EM7511 MDM9250 records (airplane + SIM cycle): "
        "all-constant payload 0xC002F2A0. F3 by byte-0 key: v0xa0 has no "
        "F3-bearing capture; the v0x00 (all-zero) form is event-locked to RRC "
        "connection release / RF sleep (95% vs 0% control, 17-18 captures); the "
        "v0x02 form co-fires with PA autopin prints (inconclusive); the v0x1c "
        "form (per-build constant word, SDX55) sits on the LTE Tx-chain de-init "
        "(119/119 qdb-resolved records within 1 ms, control 0). The 9,244 B "
        "form (format word 0x00000102, 15+ models) decodes its header; its "
        "two blocks stay raw since v3. Every unsupported size or format "
        "word WARNs with its reason."
    ),
    # Payload is a single u32 (state_word). Every observed record has
    # identical value 0xC002F2A0 across 39 EM7511 samples; "constant field"
    # still counts as an identified + parsed semantic field.
    fields_identified=7,
    fields_parsed=7,
    field_invariants={"state_word": {"enum": [0xC002F2A0]}},
    # Version-less: byte-0 is the low byte of the constant u32 state_word
    # (0xA0), NOT a DIAG version. The state_word enum gate below already
    # rejects every foreign payload; gating byte-0 would be redundant and
    # semantically wrong. See the module docstring.

    version_less=True,
)
def parse_0x197f(
    log_time: int, data: bytes,
) -> Diag0x197F | Diag0x197FCapture | ShortForm4B | None:
    # Dispatch on length first: a 9,244 B record whose first word happened to
    # be 0xC002F2A0 must never be typed as the 4 B state word.
    if len(data) == _CAPTURE_SIZE:
        return _parse_capture(log_time, data)
    if len(data) != 4:
        _layout_alarm(data, "unsupported size (known: 4 B state word / short "
                            "form, 9244 B capture form); record dropped")
        return None
    state_word = unpack_from('<I', data, 0)[0]
    if state_word != 0xC002F2A0:
        # Any other 4 B word is the shared short form, a real teardown
        # event record.
        return parse_short_form_4b(0x197F, log_time, data)
    return Diag0x197F(
        log_time=log_time,
        state_word=state_word,
    )
