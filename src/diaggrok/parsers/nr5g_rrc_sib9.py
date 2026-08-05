# diaggrok-provenance: re
"""NR SIB9 network time decoder — from-scratch UPER (no pycrate).

Decodes the NR BCCH-DL-SCH ``SystemInformation`` message (c1=0) far enough
to reach a **SIB9** entry in ``sib-TypeAndInfo`` and extract its ``timeInfo``
(UTC network time + DST / leap-second / local-offset hints). SIB9 is the NR
analog of LTE SIB16 (#N network-time umbrella; coverage row on #N).

ASN.1 path (3GPP TS 38.331):

    BCCH-DL-SCH-Message ::= SEQUENCE { message BCCH-DL-SCH-MessageType }
    BCCH-DL-SCH-MessageType ::= CHOICE {
        c1 CHOICE {
            systemInformation           SystemInformation,     -- index 0
            systemInformationBlockType1 SIB1                   -- index 1
        },
        messageClassExtension SEQUENCE {}
    }
    SystemInformation ::= SEQUENCE {
        criticalExtensions CHOICE {
            systemInformation        SystemInformation-IEs,    -- index 0
            criticalExtensionsFuture-r16 CHOICE { ... }        -- index 1
        }
    }
    SystemInformation-IEs ::= SEQUENCE {
        sib-TypeAndInfo SEQUENCE (SIZE (1..maxSIB=32)) OF CHOICE {
            sib2 SIB2, sib3 SIB3, sib4 SIB4, sib5 SIB5,
            sib6 SIB6, sib7 SIB7, sib8 SIB8, sib9 SIB9,
            ...  -- Rel-16+: sib10-v1610, sib11-v1610, ...
        },
        lateNonCriticalExtension OCTET STRING OPTIONAL,
        nonCriticalExtension SEQUENCE {} OPTIONAL
    }
    SIB9 ::= SEQUENCE {
        timeInfo SEQUENCE {
            timeInfoUTC          INTEGER (0..549755813887),  -- 39 bits
            dayLightSavingTime   BIT STRING (SIZE (2)) OPTIONAL,
            leapSeconds          INTEGER (-127..128) OPTIONAL,
            localTimeOffset      INTEGER (-63..64) OPTIONAL
        } OPTIONAL,
        lateNonCriticalExtension OCTET STRING OPTIONAL,
        ...
    }

``timeInfoUTC`` semantics (TS 38.331 field description): "the number of UTC
seconds in 10 ms units since 00:00:00 on Gregorian calendar date 1 January,
1900" — i.e. ``value / 100`` = seconds since the 1900 epoch. The value refers
to the SFN boundary at or immediately after the end of the SI window in which
SIB9 is transmitted.

NOTE: the sibling LTE decoder ``lte_rrc_sib16.py`` decodes the byte-identical
field with the SAME semantics (10 ms units since 1900). It previously read the
field as GPS seconds since 1980, but that was refuted (#N, 2026-07-19) via
the ASN.1 range + TS 36.331 prose + this decoder's broadcast-validated
conversion; both decoders now agree. See the empirical wall-clock validation
recorded on #N/#N for the corpus cross-check.

Decode reach: ``decode_sib9_body`` operates on an already-positioned
``UperReader`` — the SI-container walker (``nr5g_rrc_si.decode_nr_si``)
structurally skips the preceding SIB bodies (in the observed corpus SIB9
always rides LAST behind sib2 + sib4 + sib5; see the #N gate) and then
invokes it. ``decode_nr_si_sib9`` remains as a direct entry for the
sib9-first case (synthetic vectors / future corpora).

Reference: 3GPP TS 38.331 v16.x, ITU-T X.691 (UPER)
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from diaggrok.parsers.uper import UperReader
from diaggrok.parsers.asn1_helpers import skip_extension_additions

# 00:00:00 on Gregorian 1 January 1900 — the timeInfoUTC epoch (TS 38.331).
_EPOCH_1900 = datetime(1900, 1, 1, tzinfo=timezone.utc)

@dataclass
class NrSib9Time:
    """Decoded NR SIB9 network time."""
    log_time: int
    time_info_utc: int               # raw 39-bit 10ms-unit counter since 1900
    utc_datetime: Optional[datetime] # converted UTC (None if out of range)
    leap_seconds: Optional[int]      # GPS-UTC offset (None if not broadcast)
    dst: Optional[int]               # dayLightSavingTime bits (0-3, None if absent)
    local_time_offset: Optional[int] # 15-min units from UTC (None if absent)

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'NrSib9Time',
            'log_time': self.log_time,
            'time_info_utc': self.time_info_utc,
            'utc_iso': (self.utc_datetime.isoformat()
                        if self.utc_datetime is not None else None),
            'utc_timestamp': (self.utc_datetime.timestamp()
                              if self.utc_datetime is not None else None),
            'leap_seconds': self.leap_seconds,
            'dst': self.dst,
            'local_time_offset': self.local_time_offset,
        }


def timeinfo_utc_to_datetime(time_info_utc: int) -> Optional[datetime]:
    """Convert a SIB9 ``timeInfoUTC`` value to a UTC datetime.

    Per TS 38.331 the counter is 10 ms units since 1900-01-01 00:00:00.
    Returns ``None`` when the conversion overflows ``datetime`` range
    (year 1..9999) — a max-range 39-bit value lands in year ~2074, in range,
    but guard anyway to keep the bad-input→None contract uniform with the
    LTE SIB16 decoder (#N).
    """
    try:
        return _EPOCH_1900 + timedelta(milliseconds=10 * time_info_utc)
    except OverflowError:
        return None


def decode_sib9_body(r: UperReader, log_time: int) -> NrSib9Time | None:
    """Decode a SIB9 body from an already-positioned UperReader.

    The reader must sit on the first bit of the SIB9 SEQUENCE (i.e. the
    sib-TypeAndInfo CHOICE tag has been consumed). Consumes the whole SIB9
    body (including extension additions) so a container walker could
    continue past it. Returns None when timeInfo is absent or the decode
    ran past the end of the buffer.
    """
    try:
        # SIB9 ::= SEQUENCE — extensible, 2 root optionals
        # (timeInfo, lateNonCriticalExtension).
        has_ext = r.read_bool()
        has_time_info = r.read_bool()
        has_late_nce = r.read_bool()
        if not has_time_info:
            return None

        # timeInfo SEQUENCE — not extensible, 3 optionals.
        has_dst = r.read_bool()
        has_leap = r.read_bool()
        has_offset = r.read_bool()

        # timeInfoUTC: INTEGER (0..549755813887) → 39-bit min-bits field
        # (UPER constrained int is always min-bits, any range — #N).
        time_info_utc = r.read_constrained_int(0, 549755813887)

        dst = None
        if has_dst:
            dst = r.read_bits(2)             # BIT STRING (SIZE (2))

        leap_seconds = None
        if has_leap:
            leap_seconds = r.read_constrained_int(-127, 128)

        local_time_offset = None
        if has_offset:
            local_time_offset = r.read_constrained_int(-63, 64)

        # Consume trailing body parts so the reader lands after SIB9.
        if has_late_nce:
            nbytes = r.read_length()
            r.skip_bits(nbytes * 8)
        if has_ext:
            skip_extension_additions(r)

        # Overrun guard: every field above must have come from real payload
        # bits, not the reader's implicit zero-padding past the buffer end.
        if r.bit_pos > len(r.data) * 8:
            return None

        return NrSib9Time(
            log_time=log_time,
            time_info_utc=time_info_utc,
            utc_datetime=timeinfo_utc_to_datetime(time_info_utc),
            leap_seconds=leap_seconds,
            dst=dst,
            local_time_offset=local_time_offset,
        )

    except (IndexError, ValueError):
        return None


def decode_nr_si_sib9(log_time: int, msg_data: bytes) -> NrSib9Time | None:
    """Decode SIB9 timeInfo from a BCCH-DL-SCH SystemInformation message
    whose FIRST sib-TypeAndInfo element is sib9.

    Direct entry for the sib9-first framing (synthetic vectors / future
    corpora). For real corpus messages — where SIB9 rides behind
    sib2/sib4/sib5 — use ``nr5g_rrc_si.decode_nr_si``, which skips the
    preceding bodies and calls :func:`decode_sib9_body`.
    """
    if not msg_data or len(msg_data) < 3:
        return None

    try:
        r = UperReader(msg_data)

        # Outer navigation — same gates as peek_nr_si_sib_tags.
        if r.read_choice(2) != 0:
            return None
        if r.read_choice(2) != 0:
            return None
        if r.read_choice(2) != 0:
            return None
        r.read_bits(2)                       # IEs optional bitmap
        r.read_constrained_int(1, 32)        # sib-TypeAndInfo count

        # First element CHOICE: 1 ext bit + 3-bit root index.
        if r.read_bool():
            return None                      # extension-series SIB (sib10+)
        if r.read_bits(3) != 7:              # root index 7 == sib9
            return None

        return decode_sib9_body(r, log_time)

    except (IndexError, ValueError):
        return None
