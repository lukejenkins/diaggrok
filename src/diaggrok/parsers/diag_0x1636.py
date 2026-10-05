"""0x1636 — GNSS_ME_RF_NOISE_EST: the GNSS notch-filter table, F3-mirrored.

## The body is the per-constellation notch table

The record is not a noise-floor array. It is the table of jammer / spur
**notch filters** the GNSS RF front end has armed, one bank per constellation:
a frequency per notch, an index, and the flags the firmware's notch manager
prints next to it. Every frequency in a bank is printed, one line per notch, by
the notch-manager F3 sites, and those lines join the co-emitted record
exactly. They are the oracles:

* ``gpsfft_spannotchmgr.c:1760`` ``RFA Notch GNSS %d, Idx %d, NotchF %d,
  OFF/ON %d`` and ``:1767`` ``SpAn Notch GNSS %d, Idx %d, NotchF(preXO) %d,
  OFF/ON %d``, plus ``:1775 / :1781 / :1787`` ``SpAn PreNotch GNSS %d,
  NotchF(preXO) %d, OFF/ON %d`` (plaintext ``0x79`` on the EM7455).
  The EG25-G emits the same line 1760 as the hashed
  ``0x92:f4bd8b61`` with the same ``[GNSS, Idx, F, 1]`` arguments.
* ``navrx_digGen9Otfsa.cpp:276`` ``RFA BP %d Idx %u, F %d`` and ``:282``
  ``SpAn BP %d idx %u, F %d Pole %d`` (EG18-NA, QSR4).
* ``navrx_digGen9VTv4Otfsa.cpp:436`` ``SpAn BP %d idx %u, F %ld Pole %d``,
  ``:1705`` / ``:1739`` ``Final Meas F %d, …`` and ``:2819``
  ``nav_DigXoCompensateNotch: Gnss %u BP %u NotchInd %u XoAdjFreq %ld``
  (RM500Q SDX55 and RM520N-GL SDX62, QSR4).

Corpus check (146 captures / 9,939 records, <= 300 records each,
the smallest capture per modem directory and form): 100% parse, 0 invariant
violations on every form (v2 2,744, v3 3,982, 744B v4 2,333, 849B v4 880);
v2/v3 ``notch_idx == slot`` on every non-zero slot, ``enabled == 0`` exactly when
``freq_hz == 0``, ``flag_1`` 1/0/1 per bank without exception.

Measured joins (print → the next 0x1636 record, F matched exactly):

==========================  ========  ============  ==========================
capture                     form      site          match
==========================  ========  ============  ==========================
EM7455 (MDM9x30)            225B v2   :1760 RFA     631 / 631
                                      :1767 SpAn    425 / 425
                                      :17xx PreNotch 136 / 136 (slot 0)
EG25-G (MDM9x07)            225B v2   0x92:f4bd8b61 132 / 132
EG18-NA (SDX20)             232B v3   :276 RFA      1144 / 1144
RM500Q-AE (SDX55)           744B v4   :1705 Final   76 / 76
RM520N-GL (SDX62)           849B v4   :436 SpAn     11 / 11
==========================  ========  ============  ==========================

## Layout

Common 9-byte header:

======  =====  =================  ============================================
offset  type   field              ground
======  =====  =================  ============================================
+0      u8     version            enum {2, 3, 4}
+1      u32    rtc_ms             GNSS RTC msec: equals co-temporal ``RTC=%d``
                                  / ``Ms %d`` / ``RTCMS: %ld`` prints on all
                                  four platforms (``sm_api.c:319`` 88/88)
+5      i32    xo_offset_ppm_q20  v3/v4: tracks ``RefOscOffsetPPM %ld
                                  @2^-20`` printed at the same tick (RM520N-GL
                                  -7,760,377 vs -7,760,279). CANDIDATE label,
                                  not an identity. v2 does not carry it: the
                                  word is exposed raw as ``header_word_5``.
======  =====  =================  ============================================

8-byte notch entry, used by every version:

======  =====  ============  ==================================================
offset  type   field         ground
======  =====  ============  ==================================================
+0      u8     notch_idx     the printed ``Idx`` / ``idx`` / ``NotchInd``.
                             v2 slot 0 carries 0x32 (PreNotch slot)
+1      u8     flag_1        v2/v3: 1 on banks 0 and 2, 0 on bank 1 (GLONASS);
                             no F3 label. v4: stale, not initialised
+2      u8     enabled       v2/v3: the printed ``OFF/ON`` (1 in 1192 / 1192
                             prints; 0 only on empty slots). v4: stale on SDX55
+3      u8     rfa           1 = ``RFA Notch`` / PreNotch, 0 = ``SpAn Notch``
                             (by which site printed it). v4 agrees: the fixed
                             RFA frequencies (-2,000,000, -1,098,000,
                             3,120,000 Hz) carry 1, the 11 / 11 SpAn-printed
                             RM520N-GL notches carry 0
+4      i32    freq_hz       ``NotchF`` / ``NotchF(preXO)`` / ``F``, Hz
======  =====  ============  ==================================================

* **v2 (225 B, MDM9x07/9x30)** and **v3 (232 B, MDM9x40/9x50/SDX20)**: three
  fixed-capacity banks of 7 / 13 / 7 entries at +9, bank index = the printed
  ``GNSS %d`` (bank 1 is GLONASS, confirmed by ``Band center= %d, GLO IF``).
  On v2, slot 0 of each bank is the PreNotch (idx 0x32). On v3 slot 0 is
  normally an ordinary notch (idx 0, printed by ``SpAn BP %d idx 0``; 294 of
  11,946 sampled v3 slot-0 entries carry 0x32). v3 appends a 7-byte
  trailer at +225 that no F3 site prints and that carries ASCII fragments
  (``soe``, ``ns/``) in the corpus: stale padding, kept as ``trailer_raw``.
* **v4 (744 B SDX55 = 7 banks, 849 B SDX62 = 8 banks)**: from +9, banks of
  ``[count u8][13 × entry]`` (105 B). Bank index = the printed ``Gnss %u``
  (27,335 ``XoCompensateNotch`` prints on RM520N-GL: Gnss 0/1/2 → bank 0/1/2).
  Entries are **packed**: slot ``i`` holds whatever ``notch_idx`` its byte says
  (RM500Q bank 0 slot 0 = notch 1). Slots past ``count`` hold stale memory
  (``de ad`` on an EM9190 count-0 bank) and are not decoded.

Bytes 1-2 of a v4 entry are not reliable (SDX55 carries non-0/1 values in
both, SDX62 in byte 1), so they are surfaced raw, never interpreted.

Log name: LOG_EVENT_LTE_ESM_OUTGOING_MSG
Also known as: LOG_LTE_ESM_OUTGOING_MSG, LOG_LTE_NAS_OUTGOING_EVENT
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

_HDR = 9
_ENTRY = 8
_V2_BANKS = (7, 13, 7)          # fixed-capacity banks, slot 0 = PreNotch
_V2_SIZE = _HDR + _ENTRY * sum(_V2_BANKS)   # 225
_V3_SIZE = _V2_SIZE + 7                     # 232: + 7-byte trailer
_V4_SLOTS = 13
_V4_BANK = 1 + _ENTRY * _V4_SLOTS           # 105: [count][13 x entry]
PRENOTCH_IDX = 0x32


@dataclass
class Notch1636:
    """One notch-filter entry (8 bytes)."""
    slot: int
    notch_idx: int
    flag_1: int
    enabled: int
    rfa: int
    freq_hz: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "slot": self.slot,
            "notch_idx": self.notch_idx,
            "flag_1": self.flag_1,
            "enabled": self.enabled,
            "rfa": self.rfa,
            "freq_hz": self.freq_hz,
        }


@dataclass
class NotchBank1636:
    """One constellation's notch bank; ``gnss`` is the bank index."""
    gnss: int
    count: int | None            # v4 only; v2/v3 banks are fixed-capacity
    notches: list[Notch1636] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "gnss": self.gnss,
            "count": self.count,
            "notches": [n.to_dict() for n in self.notches],
        }


@dataclass
class Diag0x1636:
    """0x1636 — GNSS notch-filter table (see module docstring)."""
    log_time: int
    version: int
    rtc_ms: int
    xo_offset_ppm_q20: int | None
    header_word_5: int | None
    banks: list[NotchBank1636]
    trailer_raw: bytes | None
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x1636",
            "log_time": self.log_time,
            "version": self.version,
            "rtc_ms": self.rtc_ms,
            "xo_offset_ppm_q20": self.xo_offset_ppm_q20,
            "header_word_5": self.header_word_5,
            "banks": [b.to_dict() for b in self.banks],
            "trailer_raw": self.trailer_raw,
            "payload_size": self.payload_size,
        }


def _entry(data: bytes, off: int, slot: int) -> Notch1636:
    return Notch1636(
        slot=slot,
        notch_idx=data[off],
        flag_1=data[off + 1],
        enabled=data[off + 2],
        rfa=data[off + 3],
        freq_hz=unpack_from('<i', data, off + 4)[0],
    )


@register(
    0x1636, domain="gnss",
    name="0x1636",
    description=(
        "0x1636 — GNSS_ME_RF_NOISE_EST: per-constellation GNSS notch-filter "
        "table (RFA / SpAn / PreNotch notches, freq Hz), header GNSS RTC ms + "
        "XO offset; every notch mirrored by the notch-manager F3 prints"
    ),
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Full layout on all 3 versions, F3-joined. "
        "gpsfft_spannotchmgr.c:1760/1767/17xx RFA/SpAn/PreNotch Notch prints "
        "(EM7455 0x79; EG25-G 0x92:f4bd8b61) and navrx_digGen9[VTv4]Otfsa.cpp "
        "RFA/SpAn/Final Meas/XoCompensateNotch prints (EG18-NA, RM500Q, "
        "RM520N-GL) land on the record's notch entries exactly. Bytes 1-2 of "
        "a v4 entry and the v3 trailer stay raw."
    ),
    issues=(),
    fields_identified=11,
    fields_parsed=11,
    field_invariants={"version": {"enum": [2, 3, 4]}},
)
def parse_0x1636(log_time: int, data: bytes) -> Diag0x1636 | None:
    # Layer-1 version gate.
    if len(data) < _HDR or data[0] not in (2, 3, 4):
        return None
    version = data[0]
    n = len(data)
    if version == 2 and n != _V2_SIZE:
        return None
    if version == 3 and n != _V3_SIZE:
        return None
    if version == 4 and (n - _HDR) % _V4_BANK:
        return None

    rtc_ms = unpack_from('<I', data, 1)[0]
    word5 = unpack_from('<i', data, 5)[0]
    banks: list[NotchBank1636] = []
    if version in (2, 3):
        off = _HDR
        for gnss, cap in enumerate(_V2_BANKS):
            bank = NotchBank1636(gnss=gnss, count=None)
            for slot in range(cap):
                bank.notches.append(_entry(data, off, slot))
                off += _ENTRY
            banks.append(bank)
    else:
        for gnss in range((n - _HDR) // _V4_BANK):
            base = _HDR + gnss * _V4_BANK
            count = data[base]
            bank = NotchBank1636(gnss=gnss, count=count)
            for slot in range(min(count, _V4_SLOTS)):
                bank.notches.append(_entry(data, base + 1 + slot * _ENTRY, slot))
            banks.append(bank)

    return Diag0x1636(
        log_time=log_time,
        version=version,
        rtc_ms=rtc_ms,
        xo_offset_ppm_q20=word5 if version != 2 else None,
        header_word_5=(word5 & 0xFFFFFFFF) if version == 2 else None,
        banks=banks,
        trailer_raw=bytes(data[_V2_SIZE:]) if version == 3 else None,
        payload_size=n,
    )
