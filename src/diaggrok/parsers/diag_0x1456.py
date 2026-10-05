"""0x1456 - CGPS tracking-DPO status (11B fixed; every byte F3-labelled).

The canonical name ``LOG_CGPS_MC_TRACK_DPO_STATUS_C`` is confirmed by the
firmware's own F3 string ``mc_srchstrategy.c: "Log packet allocation for
LOG_CGPS_MC_TRACK_DPO_STATUS_C failed"``. The "GNSS Heartbeat" label some
tables use is a nickname for the ~1 Hz cadence. An older name table lists the
code as ``LOG_RMAC_CARRIER_STATE_CHANGED`` (CDMA reverse-MAC), but that is a
different subsystem and does not apply.

Byte map (F3-grounded, see below):
  [0]     u8   version                 = 0x00 (the only version in the corpus)
  [1]     u8   tracking_state          F3 "Tracking State %u"
  [2:6]   u32  acq_track_state_change  F3 "Acq/Track State Change %u" — a
                                         running count, not a phase enum
  [6]     u8   dpo_active              F3 "DPO_Active:%d"
  [7:11]  u32  dpo_state_change        F3 "DPO State Change %u" (= "ActCnt")

F3 grounding. ``mc_gnsssearchstrategy.c`` prints
``Tracking State %u, Acq/Track State Change %u, DPO State Change %u`` a few
hundred ticks before every record (lag p50 0-687 ticks). Joined on the nearest
preceding print, all three arguments match on **1,792/1,792** paired records
across six firmware builds: EG25-G MDM9607 (qsr_legacy, line 7574), CarCom-G1
MDM9250 (qsr4, 8147), EG18-NA SDX20 (8883), M3100 (10449), EM160R SDX24 (9787)
and SIM8202G-M2 SDX55 (10835). ``dpo_active`` equals the ``DPO_Active:%d`` of
the ``mc_srchstrategy.c`` "VER 46 DPO_Active:%d Enable:%d Forced %d ActCnt %d"
print that follows the record on 237/237 EG18-NA records (285/289 against the
preceding one: the 4 misses are transition edges); the M3100's
``FIX_START_IND … DPO Active: %d`` agrees. ``ActCnt`` in the same print equals
``dpo_state_change``.

Bytes 3-5 and 9-10 are the two counters' high bytes, not reserved padding;
they read as zero on most captures only because the counts are small. EM160R
(SDX24) prints ``Acq/Track State Change 2656`` = 0x0A60, so byte 3 = 0x0A.
``flag``/``state``/``aux6``/``aux7``/``aux8`` are older byte-level names over
these fields, kept as read-only aliases; ``state`` is the low byte of a
counter, not a DPO phase.

Log name: LOG_CGPS_MC_TRACK_DPO_STATUS_C
Also known as: LOG_CGPS_MC_TRACK_DYNAMIC_POWER_OPTIMIZATION_STATUS, LOG_CGPS_MC_TRACKING_DPO_STATUS
Also seen applied to this code, but belonging to a different log: LOG_RMAC_CARRIER_STATE_CHANGED
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

LOG_GNSS_HEARTBEAT_1456 = 0x1456

_1456_VERSION = 0x00


@dataclass
class Diag0x1456:
    log_time: int
    version: int                  # [0]    0x00
    tracking_state: int           # [1]    F3 "Tracking State"
    acq_track_state_change: int   # [2:6]  F3 "Acq/Track State Change" (u32 count)
    dpo_active: int               # [6]    F3 "DPO_Active"
    dpo_state_change: int         # [7:11] F3 "DPO State Change" (u32 count)
    payload_size: int

    # Older byte-level names, kept read-only for back-compat.
    @property
    def flag(self) -> int:
        return self.tracking_state

    @property
    def state(self) -> int:
        return self.acq_track_state_change & 0xFF

    @property
    def aux6(self) -> int:
        return self.dpo_active

    @property
    def aux7(self) -> int:
        return self.dpo_state_change & 0xFF

    @property
    def aux8(self) -> int:
        return (self.dpo_state_change >> 8) & 0xFF

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1456',
            'log_time': self.log_time,
            'version': self.version,
            'tracking_state': self.tracking_state,
            'acq_track_state_change': self.acq_track_state_change,
            'dpo_active': self.dpo_active,
            'dpo_state_change': self.dpo_state_change,
            # older byte-level keys, kept for back-compat
            'flag': self.flag,
            'state': self.state,
            'aux6': self.aux6,
            'aux7': self.aux7,
            'aux8': self.aux8,
            'payload_size': self.payload_size,
        }


@register(
    LOG_GNSS_HEARTBEAT_1456, domain="gnss",
    name="0x1456",
    description="CGPS tracking-DPO status (0x1456, LOG_CGPS_MC_TRACK_DPO_STATUS_C; ~1Hz) - 11B: tracking state, acq/track + DPO state-change counts, DPO active (F3-grounded)",
    version=4,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Every byte F3-labelled by mc_gnsssearchstrategy.c 'Tracking State "
        "%u, Acq/Track State Change %u, DPO State Change %u' (1,792/1,792 on "
        "six builds: EG25-G, CarCom-G1, EG18-NA, M3100, EM160R, SIM8202G) and "
        "mc_srchstrategy.c 'DPO_Active:%d' (237/237 EG18-NA). Bytes 3-5 / 9-10 "
        "are the u32 counters' high bytes (EM160R count 2656 -> byte 3 = "
        "0x0A). 11-byte fixed size across a 67,045-record / 194-capture corpus."
    ),
    source_url="",
    fields_identified=6, fields_parsed=6,
    issues=(),
    primary_issue=None,
    supported_versions=[0x00],
    field_invariants={'version': {'enum': [0x00]}},
)
def parse_0x1456(log_time: int, data: bytes) -> Diag0x1456 | None:
    if len(data) != 11:
        return None
    if data[0] != _1456_VERSION:
        return None
    tracking_state, acq, dpo_active, dpo = unpack_from('<BIBI', data, 1)
    return Diag0x1456(
        log_time=log_time,
        version=data[0],
        tracking_state=tracking_state,
        acq_track_state_change=acq,
        dpo_active=dpo_active,
        dpo_state_change=dpo,
        payload_size=len(data),
    )
