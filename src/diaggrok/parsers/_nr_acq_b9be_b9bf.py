# diaggrok-provenance: re
"""Shared decode for 0xB9BE (acquisition request) and 0xB9BF (acquisition confirm).

Both records open with the same 8-byte prefix and carry the same radio-frame
time word at offset 4, packed one of two ways depending on the silicon:

* **u16 form** (SDX55: 0xB9BE v0x01, 0xB9BF v0x05)::

      bits  0- 9  sfn
      bits 10-13  subframe
      bits 14-15  zero
      byte  6     time_flag {0, 1}
      byte  7     time_hi {0, 1}

* **u32 form** (SDX65: 0xB9BE v0x02, 0xB9BF v0x06; SDX72: 0xB9BE v0x04)::

      bits  0- 9  zero
      bit     10  time_flag {0, 1}
      bits 11-14  zero
      bits 15-18  subframe
      bits 19-28  sfn
      bits 29-31  time_hi, 0b001 on every attested record

  This is the same packing 0xB958 v0x01 uses on SDX65.

Both forms are grounded against the 52.4288 MHz DIAG timestamp clock (see the
two parsers). The confirm's time word repeats the request's except where the
parser docstrings say otherwise.

``time_hi`` is 1 on every record except the two whose cell uses a 15 kHz SSB
subcarrier spacing (band n71), where it is 0, so it may be the SSB numerology.
With two such records that is a CANDIDATE, and ``time_hi`` is not part of
``frame_valid``.

The NR-ARFCN -> frequency check implements the NR global frequency raster
(3GPP TS 38.104 section 5.4.2.1), which both records' frequency fields obey.
"""
from __future__ import annotations

from dataclasses import dataclass

#: Subframes per 10 ms radio frame — bounds the ``subframe`` field.
SUBFRAMES_PER_FRAME = 10

#: u32-form bits that are zero on every attested record (0-9 and 11-14).
_U32_ZERO_MASK = 0x7BFF


@dataclass(frozen=True)
class TimeWord:
    """A decoded radio-frame time word (offset 4 of both records)."""

    raw: int
    sfn: int
    subframe: int
    time_flag: int
    time_hi: int
    #: False when a bit the attested shape keeps zero is set, time_flag is not
    #: 0/1, or subframe > 9. Fail-visible: the record still decodes.
    frame_valid: bool


def decode_time_u16(word: int) -> TimeWord:
    """SDX55 form: sfn/subframe in the low u16, flag in byte 6, time_hi in byte 7."""
    low = word & 0xFFFF
    sfn, subframe = low & 0x3FF, (low >> 10) & 0xF
    time_flag = (word >> 16) & 0xFF
    frame_valid = (
        (low >> 14) == 0
        and subframe < SUBFRAMES_PER_FRAME
        and time_flag in (0, 1)
    )
    return TimeWord(word, sfn, subframe, time_flag, word >> 24, frame_valid)


def decode_time_u32(word: int) -> TimeWord:
    """SDX65 / SDX72 form: sfn bits 19-28, subframe bits 15-18, flag bit 10."""
    sfn, subframe = (word >> 19) & 0x3FF, (word >> 15) & 0xF
    frame_valid = (word & _U32_ZERO_MASK) == 0 and subframe < SUBFRAMES_PER_FRAME
    return TimeWord(word, sfn, subframe, (word >> 10) & 1, word >> 29, frame_valid)


def nr_arfcn_to_khz(arfcn: int) -> int | None:
    """Centre frequency in kHz for an NR-ARFCN on the global raster, else None."""
    if 0 <= arfcn <= 599_999:
        return arfcn * 5
    if 600_000 <= arfcn <= 2_016_666:
        return 3_000_000 + 15 * (arfcn - 600_000)
    if 2_016_667 <= arfcn <= 3_279_165:
        return 24_250_080 + 60 * (arfcn - 2_016_667)
    return None
