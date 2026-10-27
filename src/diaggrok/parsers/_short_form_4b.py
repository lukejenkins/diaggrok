# diaggrok-provenance: re
"""Shared 4-byte short-form record for codes whose 4 B form is a real event.

Eight codes emit, besides their full layout, a bare 4-byte record: 0x1849,
0x184A, 0x18F7, 0x1917, 0x192A, 0x19FE and 0x197F, 0x1980. The 4 B form was long filed as HDLC framing residue and
returned ``None``. That label is refuted for all eight:

* **Event-locked.** In F3-bearing captures the records sit on RF / L1
  teardown prints (``RX_TUNED -> INACTIVE``, ``RF stop confirmed``, PA
  ``sleep()``, ``RRC_STOP_LOWER_LAYER_REQ``, ``rfcommon_stop_service``):
  0.88-1.00 of records within +/-1-10 ms against 0.00-0.10 at record time
  +/-5 s, on 11 captures over 9 modem families.
* **Not fragments.** On 74-100 % (per code) of the captures that carry a
  code's 4 B form, the code emits no larger record at all, so there is
  nothing for the 4 B record to be a piece of.
* **Code-specific content.** The word is mostly 0, otherwise a stable
  per-code value (e.g. 0xC002F2A0 on 0x197F/0x1980, 0xC002EE40 on 0x18F7),
  shaped like a QDSP6 virtual address.

Codes fire in groups at one teardown (0x1849/0x184A/0x18F7/0x1917 together,
0x192A/0x19FE together), so the likeliest reading is a per-code "stop" record
a subsystem emits when it de-initialises. The word's meaning is unknown and is
kept raw.

Byte 0 is data here, never a version, so the record carries no ``version`` key
and a code's byte-0 version invariant does not apply to it. Only ``len == 4``
is accepted; any other short size still returns ``None`` so the registry WARN
reports it.
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

SHORT_FORM_SIZE = 4

#: The codes whose 4 B form is RE-evidenced as a real event (F3 lock above).
#: A code must be listed here to use the helper, and the version-loudness
#: checks exempt exactly (listed code, 4 B) and nothing else: byte 0 of these
#: records is data, the way a ``version_less`` parser's is.
SHORT_FORM_CODES = frozenset({
    0x1849, 0x184A, 0x18F7, 0x1917, 0x192A, 0x19FE,
    0x197F, 0x1980,
})


def is_short_form(code: int, size: int) -> bool:
    """True for a listed code's 4 B form, where byte 0 is not a version."""
    return size == SHORT_FORM_SIZE and code in SHORT_FORM_CODES


@dataclass
class ShortForm4B:
    """Bare 4 B event record: one u32 LE word (semantics unknown)."""
    code: int
    log_time: int
    word: int
    payload_size: int = SHORT_FORM_SIZE

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'ShortForm4B',
            'code': self.code,
            'log_time': self.log_time,
            'word': self.word,
            'word_hex': f'{self.word:08x}',
            'payload_size': self.payload_size,
        }


def parse_short_form_4b(code: int, log_time: int, data: bytes) -> ShortForm4B | None:
    """Decode a 4 B short-form record, or ``None`` for any other length or an
    unlisted code."""
    if not is_short_form(code, len(data)):
        return None
    return ShortForm4B(code=code, log_time=log_time, word=unpack_from('<I', data, 0)[0])
