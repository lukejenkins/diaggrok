"""GNSS/RF state flag (0x197F) — 4B fixed, constant state word.

Sibling pair with 0x1980 — both codes emit an identical 4-byte payload
during airplane-mode and SIM power-cycle transitions. All 39 observed
records (30 airplane + 9 SIM per code) carry the same constant u32 value
0xC002F2A0. The two codes appear in the same events with the same
counts, suggesting they are the same state word reported by two
different subsystems simultaneously.

Layout (4 B fixed):
    [0:4]  u32 LE  state_word — observed constant 0xC002F2A0 across all records

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
  captures (EM7511 / MC7411 MDM9x50 + one RM520N fragment), none of which
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
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


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


@register(
    0x197F, domain="gnss",
    name="0x197F",
    description="GNSS/RF state flag (0x197F) — 4B fixed, constant u32 during mode transitions",
    version=1,
    issues=(),
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE from 39 EM7511 MDM9650 records (airplane + SIM cycle): "
        "all-constant payload 0xC002F2A0. F3 by byte-0 key: v0xa0 has no "
        "F3-bearing capture; the v0x00 (all-zero) form is event-locked to RRC "
        "connection release / RF sleep (95% vs 0% control, 17-18 captures); the "
        "v0x02 form co-fires with PA autopin prints (inconclusive)."
    ),
    # Payload is a single u32 (state_word). Every observed record has
    # identical value 0xC002F2A0 across 39 EM7511 samples; "constant field"
    # still counts as an identified + parsed semantic field.
    fields_identified=1,
    fields_parsed=1,
    field_invariants={"state_word": {"enum": [0xC002F2A0]}},
    # Version-less: byte-0 is the low byte of the constant u32 state_word
    # (0xA0), NOT a DIAG version. The state_word enum gate below already
    # rejects every foreign payload; gating byte-0 would be redundant and
    # semantically wrong. See the module docstring.

    version_less=True,
)
def parse_0x197f(log_time: int, data: bytes) -> Diag0x197F | None:
    if len(data) < 4:
        return None
    state_word = unpack_from('<I', data, 0)[0]
    if state_word != 0xC002F2A0:
        return None
    return Diag0x197F(
        log_time=log_time,
        state_word=state_word,
    )
