"""0x1C46 — IMS timer-subsystem F3 trace marker (NR5G ML1 range).

First seen in a 5-modem drive capture (RM500Q-AE / RM520N-GL / EM9291 /
SIM8202G-M2 / FN980m).

Fixed 304 B payload, **byte-identical across every corpus record** (54/54,
304 B, byte0=0x00) — spanning four chipset families and four vendors
(RM520N-GL SDX62 / EM9291 SDX62 / FN980 SDX55 / SIM8202G-M2 SDX55). The
canonical name is ``LOG_IMS_ICS_TIMER``; the payload is an F3/QSR-style trace
template, not a measurement record — it embeds human-readable subsystem
strings rather than bitpacked fields:

    [0]      u8    version       (0x00 in corpus)
    [1]      u8    sub_flag      (0x01 in corpus)
    [2:..]   cstr  func_marker   'IMMTimerMgr::StartTimer'  (originating fn)
    ...      ...   (null-padded fixed-width char buffers)
    embedded text, in order:
        'IMMTimerMgr::StartTimer'      — originating function symbol
        'SINGO_LTE_3G_RESELEC_TIMER'   — the timer being started (enum name)
        'SINGO_LTE_3G_RESELEC_TIM'     — truncated copy (fixed-buffer spill)
        'Unknown timerID:'             — embedded log-payload label (see the
                                         message-database cross-check below —
                                         NOT an F3 format string)

Message-database cross-check
----------------------------
The F3/QSR format-string tables of two build-matched message databases
(RM520N-GL, 407,917 records; SIM8202G-M2, 354,589) show:

  * ``IMMTimerMgr::StartTimer`` — GROUNDED. Both carry the exact F3 site
    ``SCEN_PDN:IMMTimerMgr::StartTimer() | timerID:%d, timerValue:%d msecs``
    (``IMMTimerMgr.cpp``, SCEN_PDN / PDN-scenario IMS subsystem). So the log's
    originating function is a real firmware F3 site and the event semantics are
    a StartTimer(timerID, timerValue_msecs) call.
  * ``SINGO_LTE_3G_RESELEC_TIMER`` — 0 format-string hits in either, as
    expected: it is a timer *enum name* carried as log-payload data, not a
    printf format string.
  * ``Unknown timerID:`` — **0 format-string hits in either.** It is not an
    F3 message format string. The nearest real F3 site is
    ``SCEN_PDN:IMMTimerMgr::GetTimerValueInMillSecs | Unhandled timerID:%d``
    (note: *Unhandled*, with a ``%d``, NOT *Unknown*). ``Unknown timerID:`` is
    therefore embedded **log-payload data**, not an F3 format-string-table
    entry.

Because the payload is byte-identical, only the DIAG ``log_time`` varies
between records; the *content* is a constant template for this particular
timer event (LTE→3G reselection). A different timer event would carry
different embedded strings, so the parser extracts the ASCII runs
**dynamically** rather than hardcoding offsets — this stays correct for
unseen 0x1C46 events while still naming the leading function symbol.

F3 grounding (v0x00): live co-emission
--------------------------------------
13 F3-bearing captures emit 0x1C46 (16 records): T99W175 (SDX55) x3, EM9190
(SDX55) x2, RM520N-GL LTE band-sweep (SDX62) x5, SIM8202G-M2 (SDX55) x3. All
13 were joined. On **every record (16/16)** the firmware prints, 0.02-0.03 ms
before the log::

    IMMTimerMgr::StartTimer() | timerID:SINGO_LTE_3G_RESELEC_TIMER, TimerValue:2000 msecs

It names the same function as ``func_marker`` and the same timer as the first
timer-name buffer. The control windows (record time ±5 s, 32 of them) hold
no StartTimer print at all. So each record IS the log of one
``IMMTimerMgr::StartTimer()`` call, and the two leading buffers are
F3-grounded: the originating function and the started timer's name.
``IMMTimerMgr::IsTimerRunning(): timerID=<same timer>`` also fires at
0.0 ms. The F3 additionally prints ``TimerValue:2000 msecs``, a value the
304 B payload does NOT carry (no u16/u32 2000 anywhere in it).

byte-0 is not a version
-----------------------
byte[0]=0x00 is the fixed leading byte of this **static F3/QSR descriptor
template**, NOT a DIAG version. The 304 B payload is a constant descriptor —
byte-identical across 4 chipset families / 4 vendors, byte[0]=0x00 on every
record — whose *content* is symbol/format-string text, not a versioned
bitfield struct. A ``field_invariants["version"]={enum:[0x00]}`` would be
semantically false (0x00 is descriptor residue, not a version selector) and
would actively harm the parser: it extracts ASCII runs **dynamically** so it
stays correct for an unseen timer event carrying different embedded strings,
and a version gate would instead *reject* (return ``None`` on) any future
event whose byte-0 differed — the opposite of the graceful degradation this
parser is designed for. Declared ``version_less=True`` (as for 0xB0D2 /
0x117E / 0x1378 — byte-0 is a constant descriptor byte, not a version). The
dynamic string extraction still degrades gracefully (empty ``func_marker`` /
``text_fields``) on any payload content; a payload shorter than the fixed
304 B is treated as truncated and returns ``None`` (registry WARN).

Log name: LOG_IMS_ICS_TIMER
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from diaggrok.registry import register


def _leading_symbol(data: bytes, off: int = 2) -> str:
    """Return the printable-ASCII run starting at ``off`` (empty if the byte
    at ``off`` is not printable). Captures the originating-function symbol
    that F3 trace records place right after the version/sub_flag prefix."""
    if off >= len(data) or not (0x20 <= data[off] < 0x7F):
        return ""
    end = off
    while end < len(data) and 0x20 <= data[end] < 0x7F:
        end += 1
    return data[off:end].decode("ascii")


def _text_runs(data: bytes, min_len: int = 4) -> list[str]:
    """Extract every printable-ASCII run of >= ``min_len`` chars, in order.
    Surfaces the embedded subsystem / timer / format strings without
    assuming fixed field offsets."""
    runs: list[str] = []
    start: int | None = None
    for i, b in enumerate(data):
        if 0x20 <= b < 0x7F:
            if start is None:
                start = i
        else:
            if start is not None and i - start >= min_len:
                runs.append(data[start:i].decode("ascii"))
            start = None
    if start is not None and len(data) - start >= min_len:
        runs.append(data[start:].decode("ascii"))
    return runs


_FIXED_SIZE = 304  # attested fixed record size


@dataclass
class Diag0x1C46:
    """0x1C46 — IMS timer-subsystem F3 trace marker."""
    log_time: int
    version: int
    sub_flag: int
    payload_size: int
    func_marker: str          # originating-function symbol at offset 2
    text_fields: list[str]    # all embedded ASCII runs (>=4 chars), in order
    body_raw: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x1C46",
            "log_time": self.log_time,
            "version": self.version,
            "sub_flag": self.sub_flag,
            "payload_size": self.payload_size,
            "func_marker": self.func_marker,
            "text_fields": self.text_fields,
            "body_raw": self.body_raw,
        }


@register(
    0x1C46,
    name="0x1C46",
    description="0x1C46 — IMS timer-subsystem F3 trace marker (embedded ASCII); NR5G ML1 range",
    version=4,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Fixed 304 B; byte-identical across all corpus records (54/54, "
        "byte0=0x00) spanning 4 chipsets / 4 vendors: RM520N-GL (SDX62), EM9291 "
        "(SDX62), FN980 (SDX55), SIM8202G-M2 (SDX55). Payload is an F3/QSR "
        "trace template (canonical LOG_IMS_ICS_TIMER), not a measurement "
        "record: embeds 'IMMTimerMgr::StartTimer' (originating fn), "
        "'SINGO_LTE_3G_RESELEC_TIMER' (timer enum name), and 'Unknown "
        "timerID:' (embedded log label, not an F3 format string — 0 hits in "
        "two build-matched message databases; nearest site '..."
        "GetTimerValueInMillSecs | Unhandled timerID:%d'). The leading "
        "function symbol and all embedded ASCII runs are extracted "
        "dynamically. F3-grounded: on all 13 F3-bearing captures (T99W175/"
        "EM9190/SIM8202G-M2 SDX55, RM520N-GL SDX62) 16/16 records co-emit "
        "'IMMTimerMgr::StartTimer() | timerID:SINGO_LTE_3G_RESELEC_TIMER, "
        "TimerValue:2000 msecs' 0.02-0.03 ms before the log (control +-5 s: "
        "0/32). byte-0 is a constant descriptor byte, so the parser is "
        "version_less; payloads shorter than 304 B return None (registry WARN)."
    ),
    source_url="",
    issues=(),
    ascii_kinds=("f3-debug",),  # IMM/SINGO timer-subsystem F3 trace: 'IMMTimerMgr::StartTimer', 'SINGO_LTE_3G_RESELEC_TIMER', 'Unknown timerID:' — also seen on EM9291 SDX62
    # byte-0=0x00 is the constant leading byte of the static F3/QSR descriptor
    # template, NOT a DIAG version (every record / 4 chipset families). A
    # byte-0 version enum would be semantically false and would reject future
    # timer-events with a differing byte-0, defeating the dynamic ASCII
    # extraction. See the module docstring.
    version_less=True,
    # version, sub_flag, func_marker, text_fields — 4 semantic fields in
    # to_dict; payload_size + body_raw are framework, not RE-deliverables.
    fields_identified=4,
    fields_parsed=4,
    # WiGLE: none. A constant 304 B IMS StartTimer template (byte-identical
    # across 4 chipset families) carries no identity, signal, position or
    # UTC. (False, ()) records that decision explicitly so tag-suggestion
    # tooling does not re-propose this code.
    wigle_direct=False,
    wigle_roles=(),
)
def parse_0x1c46(log_time: int, data: bytes) -> Diag0x1C46 | None:
    # The record is a fixed 304 B descriptor (54/54 corpus records). A
    # shorter payload is truncated — return None (registry WARN) rather than
    # handing back a record with a silently clipped string tail.

    if len(data) < _FIXED_SIZE:
        return None
    return Diag0x1C46(
        log_time=log_time,
        version=data[0],
        sub_flag=data[1],
        payload_size=len(data),
        func_marker=_leading_symbol(data, 2),
        text_fields=_text_runs(data[2:]),
        body_raw=data[2:],
    )
