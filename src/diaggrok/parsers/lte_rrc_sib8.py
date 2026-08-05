# diaggrok-provenance: re
"""LTE RRC SIB8 CDMA system time decoder (UPER, from-scratch).

Decodes SystemInformationBlockType8 from UPER-encoded payloads to extract
CDMA2000 system time for DIAG timestamp calibration.

SIB8 carries CDMA system time that networks broadcast for UE handover
and timing synchronisation with CDMA2000 networks. The synchronous time
field is in 10ms units since 1980-01-06 00:00:00 (the CDMA/GPS epoch), per
3GPP TS 36.331 (see the field-unit note below).

ASN.1 definition (3GPP TS 36.331):

    SystemInformationBlockType8 ::= SEQUENCE {
        systemTimeInfo               SystemTimeInfoCDMA2000    OPTIONAL,
        searchWindowSize             INTEGER (0..15)           OPTIONAL,
        parametersHRPD               SEQUENCE { ... }          OPTIONAL,
        parameters1XRTT              SEQUENCE { ... }          OPTIONAL,
        ...
    }

    SystemTimeInfoCDMA2000 ::= SEQUENCE {
        cdma-EUTRA-Synchronisation   BOOLEAN,
        cdma-SystemTime              CHOICE {
            synchronousSystemTime        BIT STRING (SIZE (39)),
            asynchronousSystemTime       BIT STRING (SIZE (49))
        }
    }

UPER encoding notes:
    - SIB8 is an extensible SEQUENCE: 1 extension marker bit, then
      4-bit optional presence bitmap for the base fields.
    - SystemTimeInfoCDMA2000 is a non-extensible SEQUENCE (no ext marker).
    - cdma-SystemTime CHOICE has 2 alternatives: 1 bit index.
    - synchronousSystemTime: BIT STRING (SIZE (39)) -> 39 bits, fixed.
      Value is CDMA system time in 10ms (0.01s) units since the GPS epoch
      (3GPP TS 36.331 §6.3.1: "the unit is 10 ms based on a 1.2288 Mcps
      chip rate").
    - asynchronousSystemTime: BIT STRING (SIZE (49)) -> 49 bits, fixed.
      Value is CDMA system time in units of 8 CDMA2000 chips at 1.2288 Mcps
      (3GPP TS 36.331 §6.3.1), i.e. one unit = 8 / 1228800 s.

Time base (GPS vs UTC): CDMA2000 system time is GPS time, counted from the
1980-01-06 epoch with NO leap seconds in the count. GPS time therefore runs
ahead of UTC by the accumulated leap-second offset (+18 s since 2017-01-01,
unchanged through 2026). The datetime this decoder returns is GPS-based; a
caller that needs strict civil UTC must subtract the current GPS-UTC offset.
For the DIAG ts64 time-anchor use case the constant bias cancels out.

This parser operates on the raw SIB8 UPER payload extracted from the
SystemInformation container (0xB0C0 frames). The outer RRC OTA frame
parsing and SIB identification are handled upstream.

Reference: 3GPP TS 36.331 v16.x, C.S0005-A (cdma2000 sync), ITU-T X.691
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from diaggrok.parsers.lte_rrc_sib import UperReader

# CDMA/GPS epoch: January 6, 1980 00:00:00 UTC
_CDMA_EPOCH = datetime(1980, 1, 6, tzinfo=timezone.utc)

# Synchronous time unit: 10ms per tick (3GPP TS 36.331 §6.3.1)
_SYNC_TICK_SECONDS = 0.01

# Asynchronous time unit: 8 CDMA2000 chips per tick at the 1.2288 Mcps chip
# rate (3GPP TS 36.331 §6.3.1) -> one tick = 8 / 1228800 s.
_ASYNC_CHIP_RATE = 1228800
_ASYNC_CHIPS_PER_TICK = 8


@dataclass
class LteSIB8CdmaTime:
    """Decoded CDMA system time from SIB8."""
    log_time: int
    is_synchronous: bool             # True = sync (39-bit), False = async (49-bit)
    cdma_system_time_raw: int        # Raw value (80ms units if sync, chips if async)
    utc_datetime: Optional[datetime] # Converted UTC
    cdma_eutra_sync: bool            # Whether CDMA-EUTRA synchronisation is maintained

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'LteSIB8CdmaTime',
            'log_time': self.log_time,
            'is_synchronous': self.is_synchronous,
            'cdma_system_time_raw': self.cdma_system_time_raw,
            'utc_iso': self.utc_datetime.isoformat() if self.utc_datetime else None,
            'utc_timestamp': self.utc_datetime.timestamp() if self.utc_datetime else None,
            'cdma_eutra_sync': self.cdma_eutra_sync,
        }


def cdma_sync_to_utc(raw_ticks: int) -> datetime:
    """Convert synchronous CDMA system time (10ms ticks) to a datetime.

    CDMA synchronous system time counts 10ms intervals since the GPS epoch
    (1980-01-06 00:00:00), per 3GPP TS 36.331 §6.3.1. The returned datetime
    is GPS-based (tzinfo=UTC for arithmetic convenience); it runs ahead of
    civil UTC by the current GPS-UTC leap-second offset (+18 s in 2026).
    See the module docstring's "Time base" note.
    """
    seconds = raw_ticks * _SYNC_TICK_SECONDS
    return _CDMA_EPOCH + timedelta(seconds=seconds)


def cdma_async_to_utc(raw_ticks: int) -> datetime:
    """Convert asynchronous CDMA system time to a datetime.

    Asynchronous system time counts in units of 8 CDMA2000 chips at the
    1.2288 Mcps chip rate (3GPP TS 36.331 §6.3.1) since the GPS epoch, so
    one tick = 8 / 1228800 s. Returned datetime is GPS-based (see
    :func:`cdma_sync_to_utc`).
    """
    seconds = raw_ticks * _ASYNC_CHIPS_PER_TICK / _ASYNC_CHIP_RATE
    return _CDMA_EPOCH + timedelta(seconds=seconds)


def decode_sib8(payload: bytes, log_time: int = 0) -> LteSIB8CdmaTime | None:
    """Decode SIB8 from a UPER-encoded payload.

    The payload is the raw SIB8 content after the sib-TypeAndInfo CHOICE
    has been resolved upstream. It starts at the SIB8 SEQUENCE.

    Returns None if the payload is too short or systemTimeInfo is absent.
    """
    if not payload or len(payload) < 2:
        return None

    try:
        r = UperReader(payload)

        # SystemInformationBlockType8 is an extensible SEQUENCE.
        # Extension marker: 1 bit
        _has_extension = r.read_bool()

        # Optional presence bitmap for the 4 base SEQUENCE fields:
        #   systemTimeInfo(bit3), searchWindowSize(bit2),
        #   parametersHRPD(bit1), parameters1XRTT(bit0)
        opt_bitmap = r.read_bits(4)

        has_system_time = (opt_bitmap >> 3) & 1
        if not has_system_time:
            return None

        # --- SystemTimeInfoCDMA2000 (non-extensible SEQUENCE) ---

        # cdma-EUTRA-Synchronisation: BOOLEAN
        cdma_eutra_sync = r.read_bool()

        # cdma-SystemTime: CHOICE { synchronousSystemTime(0),
        #                           asynchronousSystemTime(1) }
        time_choice = r.read_choice(2)

        if time_choice == 0:
            # synchronousSystemTime: BIT STRING (SIZE (39))
            raw_value = r.read_bits(39)
            utc_dt = cdma_sync_to_utc(raw_value)
            return LteSIB8CdmaTime(
                log_time=log_time,
                is_synchronous=True,
                cdma_system_time_raw=raw_value,
                utc_datetime=utc_dt,
                cdma_eutra_sync=cdma_eutra_sync,
            )
        else:
            # asynchronousSystemTime: BIT STRING (SIZE (49))
            raw_value = r.read_bits(49)
            utc_dt = cdma_async_to_utc(raw_value)
            return LteSIB8CdmaTime(
                log_time=log_time,
                is_synchronous=False,
                cdma_system_time_raw=raw_value,
                utc_datetime=utc_dt,
                cdma_eutra_sync=cdma_eutra_sync,
            )

    except (IndexError, ValueError):
        return None
