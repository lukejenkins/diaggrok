"""0x1589 — LOG_GNSS_SAP_SDP_EVENTS v0x00: SDP HF-auto state-transition event (F3-grounded, full decode).

Every byte of the fixed 17-byte v0x00 record is named and F3-grounded.
It is one SAP-SDP (Sensor-Assisted Positioning /
Sensor Data Processor) state-machine transition, stamped with the PE time fix
the transition fired on:

  [0]      version        u8   corpus-wide 0x00 (Layer-1 gate)
  [1:3]    gps_week       u16  GPS week of the PE time fix; 0 = no GPS time yet
  [3:7]    gps_tow_ms     u32  GPS time-of-week, ms; 0 when gps_week == 0
  [7:11]   tick_ms        u32  SDP/PE "Tick" ms clock (since boot) at the same instant
  [11]     marker_11      u8   corpus-wide 0x01 (undecoded const — candidate state-machine id)
  [12]     marker_12      u8   corpus-wide 0x00
  [13]     from_state     u8   SDP state left
  [14]     to_state       u8   SDP state entered
  [15]     event          u8   SDP event that drove the transition
  [16]     reserved_16    u8   corpus-wide 0x00

F3 grounding (EG18-NA SDX20, 4 records / 3 captures, all 4 match): co-temporal with each record the firmware prints
``lbs_sdp_ssd.c:1066 SDP SSD: GpsWeek %d, GpsMs %lu`` (week exact, ms within
1 ms), ``sdp_core.c:7024 Received PE time info Tick %d, wk %d, ms %d``
(tick_ms − Tick == gps_tow_ms − ms on every record: 72/62, 507/507, 26/26,
749/738 ms — the two clocks move together, i.e. one PE time sample), and the
transition itself: ``sdp_core.c:3616 event E for state S`` followed by the
``<S> - leaving`` / ``<T> - Initial`` pair, with (S, T, E) == (from_state,
to_state, event) exactly — (2,3,4) = HFAutoInjecting → HFAutoNotInjecting on
event 4, (3,2,5) = HFAutoNotInjecting → HFAutoInjecting on event 5 (the PE
update). Consecutive records chain (to_state of one == from_state of the
next) across every multi-record capture on 8 vendors, e.g. CFW-3212
(7,6,3) → (6,7,17) → (7,1,8). The week decode also holds corpus-wide: 32/32
records with gps_week != 0 fall on their capture's date.

Caveats for readers of the raw bytes: [1]/[2] are the two bytes of gps_week,
not a tag + record type (0x09 is the high byte for weeks 2304..2559, so it
can look constant, and its value follows the calendar, not the build). An
all-zero header is gps_week == 0 (a boot-time transition before the engine
has GPS time). Byte 10 is the top byte of tick_ms and becomes non-zero once
tick_ms >= 2**24 ms (~4.7 h uptime). The [13:16] triplet is
(from_state, to_state, event), not SV counts.

Despite the canonical log name ``LOG_EVENT_IPSEC_IKE_NAT_DETECTED``, this is
a GNSS log: the co-temporal F3 prints come from ``sdp_core.c``, with zero
IPsec/IKE prints, matching the alias ``LOG_GNSS_SAP_SDP_EVENTS``. Oracles: qcsuper/SCAT do not decode 0x1589
(``skipped_preflight``); no ``0x60`` event frames in the grounding captures.

Log name: LOG_EVENT_IPSEC_IKE_NAT_DETECTED
Also known as: LOG_GNSS_SAP_SDP_EVENTS
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from diaggrok.registry import register

V0_SIZE = 17

# SDP HF-auto state names, F3-grounded on EG18-NA (sdp_core.c
# "<name> - Initial" / "<name> - leaving" prints bracketing each transition).
# Other state numbers (1, 6, 7 seen corpus-wide) have no F3 label yet and are
# surfaced raw.
SDP_STATE_NAMES: dict[int, str] = {
    2: "HFAutoInjecting",
    3: "HFAutoNotInjecting",
}


@dataclass
class Diag0x1589:
    """0x1589 v0x00 — one SAP-SDP state transition + its PE time fix (17 B)."""
    log_time: int
    version: int
    gps_week: int
    gps_tow_ms: int
    gps_time_valid: bool
    tick_ms: int
    marker_11: int
    marker_12: int
    from_state: int
    to_state: int
    event: int
    from_state_name: str | None
    to_state_name: str | None
    reserved_16: int
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x1589",
            "log_time": self.log_time,
            "version": self.version,
            "gps_week": self.gps_week,
            "gps_tow_ms": self.gps_tow_ms,
            "gps_time_valid": self.gps_time_valid,
            "tick_ms": self.tick_ms,
            "marker_11": self.marker_11,
            "marker_12": self.marker_12,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "event": self.event,
            "from_state_name": self.from_state_name,
            "to_state_name": self.to_state_name,
            "reserved_16": self.reserved_16,
            "payload_size": self.payload_size,
        }


@register(
    0x1589, domain="gnss",
    name="0x1589",
    description="0x1589 — GNSS SAP-SDP state-transition event (F3-grounded full decode): GPS week/TOW + SDP tick ms + (from_state, to_state, event), 17 B v0x00",
    version=4,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail="Full decode of the 17 B v0x00 record from EG18-NA (SDX20) and RM520N-GL captures; subsystem F3-confirmed as GNSS SAP-SDP (not IPsec). Every byte F3-grounded on EG18-NA — [1:3] gps_week + [3:7] gps_tow_ms (== 'SDP SSD: GpsWeek, GpsMs' within 1 ms), [7:11] tick_ms (tracks 'Received PE time info Tick' with the same delta as GpsMs), [13:16] (from_state, to_state, event) == 'event E for state S' + '<S> - leaving' / '<T> - Initial'. Bytes 11, 12 and 16 are constant across the corpus and stay unnamed; state numbers other than 2/3 have no F3 label.",
    source_url="",
    issues=(),
    primary_issue=None,
    field_invariants={
        "version": {"enum": [0x00]},
        "marker_11": {"enum": [0x01]},
        "marker_12": {"enum": [0x00]},
        "reserved_16": {"enum": [0x00]},
    },
    supported_versions=(0x00,),
    fields_identified=11,
    fields_parsed=11,
)
def parse_0x1589(log_time: int, data: bytes) -> Diag0x1589 | None:
    # Layer-1 gate first (byte-0 version), then the fixed-size gate: every
    # corpus record (N=104) is exactly 17 B.
    if len(data) < 1 or data[0] != 0x00:
        return None
    if len(data) < V0_SIZE:
        return None
    gps_week = int.from_bytes(data[1:3], "little")
    from_state, to_state, event = data[13], data[14], data[15]
    return Diag0x1589(
        log_time=log_time,
        version=data[0],
        gps_week=gps_week,
        gps_tow_ms=int.from_bytes(data[3:7], "little"),
        gps_time_valid=gps_week != 0,
        tick_ms=int.from_bytes(data[7:11], "little"),
        marker_11=data[11],
        marker_12=data[12],
        from_state=from_state,
        to_state=to_state,
        event=event,
        from_state_name=SDP_STATE_NAMES.get(from_state),
        to_state_name=SDP_STATE_NAMES.get(to_state),
        reserved_16=data[16],
        payload_size=len(data),
    )
