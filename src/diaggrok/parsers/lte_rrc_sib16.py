# diaggrok-provenance: re
"""LTE RRC SIB16 network time decoder (UPER, from-scratch).

Decodes SystemInformationBlockType16-r9 from UPER-encoded payloads to
extract UTC network time for DIAG timestamp calibration.

``timeInfoUTC-r9`` semantics (3GPP TS 36.331 §6.3.1 field description): "the
number of UTC seconds in **10 ms units** since 00:00:00 on Gregorian calendar
date **1 January, 1900**" — i.e. ``value / 100`` = seconds since the 1900
epoch. This is byte-for-byte the same field as NR SIB9's ``timeInfoUTC``
(TS 38.331), and ``nr5g_rrc_sib9.py`` uses exactly this conversion, validated
against real RM520N-GL/EM9190/… broadcasts + tshark (#N/#N).

⚠️ HISTORY (#N, refuted 2026-07-19): this decoder previously interpreted
the field as **GPS seconds since 1980-01-06** with a leap-second subtraction.
That was wrong, and provably so:
  * The ASN.1 range is INTEGER (0..549755813887) = 2**39-1. As 10ms-since-1900
    that spans ~174 years (→ year 2074) — a sensible time field. As
    GPS-seconds it would span ~17,000 years, absurd for a broadcast clock.
  * TS 36.331's own field prose says 10 ms units since 1900 (identical to the
    NR SIB9 analog).
  * A real 2026 broadcast is ≈3.99e11 in this field; the old GPS-seconds path
    fed that to ``1980 + 3.99e11 s`` → year ~14600 → the #N overflow guard
    returned ``utc_datetime=None``, silently masking the bug.
The old test vectors were synthetic self-encodings (never a real broadcast),
so they locked the bug in rather than catching it.

ASN.1 definition (3GPP TS 36.331):

    SystemInformationBlockType16-r9 ::= SEQUENCE {
        timeInfo-r9                      SEQUENCE {
            timeInfoUTC-r9                   INTEGER (0..549755813887),
            dayLightSavingTime-r9            BIT STRING (SIZE (2))  OPTIONAL,
            leapSeconds-r9                   INTEGER (-127..128)    OPTIONAL,
            localTimeOffset-r9               INTEGER (-63..64)      OPTIONAL
        } OPTIONAL,
        lateNonCriticalExtension         OCTET STRING    OPTIONAL,
        ...
    }

UPER encoding notes:
    - timeInfoUTC-r9: constrained INTEGER 0..549755813887 -> range 549755813888
      -> 39 bits (2^39 - 1 = 549755813887 is the max).
    - dayLightSavingTime-r9: BIT STRING (SIZE (2)) -> 2 bits + 1 presence bit
    - leapSeconds-r9: constrained INTEGER -127..128 -> range 255 -> 8 bits + 1 presence bit
    - localTimeOffset-r9: constrained INTEGER -63..64 -> range 127 -> 7 bits + 1 presence bit

The ``leapSeconds`` field is the broadcast GPS-UTC offset (informational, for
GPS<->UTC conversion); it is NOT subtracted from ``timeInfoUTC`` — the latter
is already a UTC-referenced 1900-epoch counter.

This parser operates on the raw SIB16 UPER payload extracted from the
SystemInformation container (0xB0C0 frames). The outer RRC OTA frame
parsing and SIB identification are handled upstream.

Reference: 3GPP TS 36.331 v16.x, ITU-T X.691 (UPER)
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from diaggrok.parsers.lte_rrc_sib import UperReader

# 00:00:00 on Gregorian 1 January 1900 — the timeInfoUTC epoch (TS 36.331).
_EPOCH_1900 = datetime(1900, 1, 1, tzinfo=timezone.utc)


@dataclass
class LteSIB16Time:
    """Decoded SIB16 network time."""
    log_time: int
    time_info_utc: int               # raw 39-bit 10ms-unit counter since 1900
    utc_datetime: Optional[datetime] # converted UTC (None if out of range)
    leap_seconds: Optional[int]      # broadcast GPS-UTC offset (None if absent)
    dst: Optional[int]               # dayLightSavingTime bits (0-3, None if absent)
    local_time_offset: Optional[int] # half-hour units from UTC (None if absent)

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'LteSIB16Time',
            'log_time': self.log_time,
            'time_info_utc': self.time_info_utc,
            'utc_iso': self.utc_datetime.isoformat() if self.utc_datetime is not None else None,
            'utc_timestamp': self.utc_datetime.timestamp() if self.utc_datetime is not None else None,
            'leap_seconds': self.leap_seconds,
            'dst': self.dst,
            'local_time_offset': self.local_time_offset,
        }


def timeinfo_utc_to_datetime(time_info_utc: int) -> Optional[datetime]:
    """Convert a SIB16 ``timeInfoUTC`` value to a UTC datetime.

    Per TS 36.331 the counter is 10 ms units since 1900-01-01 00:00:00 — the
    same semantics as NR SIB9 (``nr5g_rrc_sib9.timeinfo_utc_to_datetime``).
    A max-range 39-bit value lands in year ~2074, in range; the guard keeps
    the bad-input→None contract uniform (#N) for any pathological input.
    """
    try:
        return _EPOCH_1900 + timedelta(milliseconds=10 * time_info_utc)
    except OverflowError:
        return None


def decode_sib16(payload: bytes, log_time: int = 0) -> LteSIB16Time | None:
    """Decode SIB16 from a UPER-encoded payload.

    The payload is the raw SIB16 content after the sib-TypeAndInfo CHOICE
    has been resolved upstream. It starts at the SIB16 SEQUENCE.

    Returns None if the payload is too short or timeInfo is absent.
    """
    if not payload or len(payload) < 2:
        return None

    try:
        r = UperReader(payload)

        # SystemInformationBlockType16-r9 is an extensible SEQUENCE.
        # Extension marker: 1 bit
        _has_extension = r.read_bool()

        # Optional presence bitmap for base SEQUENCE fields:
        #   timeInfo-r9:                1 bit
        #   lateNonCriticalExtension:   1 bit
        has_time_info = r.read_bool()
        _has_late_nce = r.read_bool()

        if not has_time_info:
            return None

        # timeInfo-r9 SEQUENCE (no extension marker, 3 OPTIONAL fields)
        # Presence bitmap: dayLightSavingTime, leapSeconds, localTimeOffset
        has_dst = r.read_bool()
        has_leap = r.read_bool()
        has_offset = r.read_bool()

        # timeInfoUTC-r9: INTEGER (0..549755813887) → 39-bit min-bits field
        # (UPER constrained int is always a min-bits field, any range — #N).
        # 10 ms units since 1900-01-01 (TS 36.331), NOT GPS seconds (#N).
        time_info_utc = r.read_constrained_int(0, 549755813887)

        # dayLightSavingTime-r9: BIT STRING (SIZE (2))
        dst = None
        if has_dst:
            dst = r.read_bits(2)

        # leapSeconds-r9: INTEGER (-127..128) — broadcast GPS-UTC offset,
        # informational; NOT applied to the timeInfoUTC wall clock.
        leap_seconds = None
        if has_leap:
            leap_seconds = r.read_constrained_int(-127, 128)

        # localTimeOffset-r9: INTEGER (-63..64), half-hour units from UTC.
        local_time_offset = None
        if has_offset:
            local_time_offset = r.read_constrained_int(-63, 64)

        utc_dt = timeinfo_utc_to_datetime(time_info_utc)

        return LteSIB16Time(
            log_time=log_time,
            time_info_utc=time_info_utc,
            utc_datetime=utc_dt,
            leap_seconds=leap_seconds,
            dst=dst,
            local_time_offset=local_time_offset,
        )

    except (IndexError, ValueError):
        return None
