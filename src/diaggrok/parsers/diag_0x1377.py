"""
⚠️⚠️⚠️  MULTI-VERSION CODE — ONE MODEM EMITS MORE THAN ONE VERSION  ⚠️⚠️⚠️

A SINGLE modem (same firmware, same capture session) emits 0x1377 at MULTIPLE
version bytes, and **each version byte selects a DIFFERENT payload layout** —
the decoded output can differ completely from one version to the next. Do NOT
assume one layout, one parser branch, or one ground-truth recipe covers this
code: handle and validate EACH version separately (coverage is per
(modem, code, VERSION)).

Versions seen on one device: 0x02, 0x07
Observed on 1 modem(s) in the corpus: sierra/em7511
  e.g. sierra/em7511 emitted 0x02×5, 0x07×22 in a single capture.

Evidence: per-capture byte-0 histograms across the corpus.
═══════════════════════════════════════════════════════════════════════════

0x1377 — CGPS report event, 4B fixed: event_type + event_data + 2B zero.

Split from `lte_misc.py`, where it was mislabelled
"LTE status"; the vendor name is LOG_CGPS_REP_EVT_LOG_PACKET_C).

Layout::

    [0]    version     u8   — EVENT TYPE, not a layout version (see below)
    [1]    sub_status  u8   — event data: the receiver state on 0x02, 0 on 0x07
    [2:4]  reserved    u16  — 0x0000 on every corpus record

Byte 0 is kept under the name ``version`` because the per-version F3 review keys
``(code, v0xNN)`` on it, and each value is still its own unit of F3 work.

## Grounding (F3-VERDICT v0x02 + v0x07)

Byte 0 is the TM report-event discriminator. One firmware emits both values
in one session, each co-emitted with a different TM event:

* **0x02 = receiver-state event.** It fires inside the LM→TM hand-off, between
  ``=LM TASK= RCVR state changed to X`` and ``TM: Received event
  TM_PD_EVENT_GPS_{DONE,IDLE,BEGIN} from LM``. Byte 1 is the state:
  1 = OFF (GPS_DONE), 2 = IDLE (GPS_IDLE), 3 = ON (GPS_BEGIN). F3 matched
  16/16, |dt| ≤ 0.09 ms, 0 disagreements, on EG18-NA (SDX20), T99W373,
  EM060K-GL and R500L5. The 0x60 plane labels the same records with
  EVENT_GPS_LM_MGP_{OFF,IDLE,ON} (1301/1300/1299), 7/7, ≤ 1.2 ms
  (EM060K-GL + R500L5). ⚠️ EVENT_GNSS_RCVR_STATE numbers these 0/1/2 and
  the LM PD_API event ids are 4/2, so neither enum is this byte.
* **0x07 = position-report event.** It fires at ``tm_util.c:411 Formatting
  Position Data for TM-Core``. M3100 matched 618/618 both ways. RM500Q-AE
  nosim matched 270/276; its 6 misses still carry the upstream ``report
  final fix to protocol`` print, so 276/276. Final fixes that formatted no
  position (3) emit no record. On the 0x60 plane it is EVENT_GPS_PD_POSITION
  (614): EM061K-GL 30/30 1:1, and every record on RM500Q gnss_comparison
  (63/63 ≤ 0.63 ms). That capture's event surplus is LOG-plane drop under
  EVENT_DIAG_DROP_DEBUG, not a firing rule (irregular 1–15 s gaps).
  Byte 1 is 0 on every 0x07 record. This agrees with the per-fix fan-out
  co-emission seen independently in 0x1987.

Corpus (467 sidecars / 230,495 records): byte1 ≠ 0 occurs on exactly the
0x02 records of every capture (0 exceptions). On 0x02: OFF 80 / IDLE 138 /
ON 131. Bytes 2–3 are 0 everywhere.

Log name: LOG_CGPS_REP_EVT_LOG_PACKET_C
Also known as: LOG_CGPS_SESSION_REPORT, LOG_GPSONE_XTRA_END_DOWNLOAD, LOG_INTERNAL_CGPS_SESSION_REPORT
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


# F3-grounded names (module docstring § Grounding). Byte 0 → TM report event;
# byte 1 on the 0x02 event → receiver state.
EVENT_NAMES_1377: dict[int, str] = {0x02: "RCVR_STATE", 0x07: "POSITION_REPORT"}
RCVR_STATES_1377: dict[int, str] = {1: "OFF", 2: "IDLE", 3: "ON"}


@dataclass
class Diag0x1377:
    """CGPS report event (0x1377) — 4B fixed: event type + event data + 2B zero."""
    log_time: int
    version: int
    sub_status: int
    reserved: int

    @property
    def event(self) -> str:
        return EVENT_NAMES_1377.get(self.version, f"UNKNOWN_0x{self.version:02x}")

    @property
    def rcvr_state(self) -> str | None:
        """Receiver state on the 0x02 event; None on every other event."""
        if self.version != 0x02:
            return None
        return RCVR_STATES_1377.get(self.sub_status, f"UNKNOWN_{self.sub_status}")

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1377',
            'log_time': self.log_time,
            'version': self.version,
            'event': self.event,
            'sub_status': self.sub_status,
            'rcvr_state': self.rcvr_state,
            'reserved': self.reserved,
        }


# --- Ground-truth recipe -------------------------------------------
# Authored offline for Sierra EM9291 (SWIX65C_02.17.08.00, SDX62)
# — the modem with the largest zero-recipe corpus. ⚠️ SUBSYSTEM HONESTY: this
# parser is *titled* "LTE status", but the vendor-official name is
# LOG_CGPS_REP_EVT_LOG_PACKET_C (a CGPS report-event log packet).
# Source-precedence puts the vendor name first, so this is a CGPS / GNSS
# session-report EVENT code, NOT an LTE measurement — every field grounds against
# the GNSS subsystem (sky-fix + AT!GPS*), not LTE. EM9291 emits v=0x07 (confirmed
# from real records: byte0=0x07, 4B). hw_run_performed=False — hypothesis only.
# Superseded by the F3 grounding above. sub_status is not a session
# subtype: it is 0 on every 0x07 (position-report) record and is the receiver
# state OFF/IDLE/ON on the 0x02 event.

# Layer-1 gate on the DECLARED version enum. The parser used to
# return a record for any version, so the registry's unknown-version WARN
# never fired.
_VERSIONS_1377_4918: tuple[int, ...] = (0x02, 0x07)


@register(0x1377,
    name="0x1377",
    description="CGPS report event (0x1377) — 4B fixed: event type (0x02 receiver "
                "state / 0x07 position report) + event data + reserved",
    version=4, author="Luke Jenkins", author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail="Cross-gen RE from MDM9607 + MDM9x50 + SDX20 + SDX20V2 + SDX55; "
                  "v2 field_invariants from N=31,692 corpus walk; v4 F3 + 0x60 "
                  "grounding of both event types",
    issues=(),
    fields_identified=3, fields_parsed=3,
    # Layer-2 invariant net. 0x1377 was the only parser in this
    # 0x13xx cluster lacking field_invariants. No byte-0 dispatch is needed
    # (every version shares the 4B layout). Validated across N=31,692
    # records / 175 captures:
    #   version    {0x07: 31,582, 0x02: 110}      → enum [0x02, 0x07]
    #   sub_status {0: 31,582, 1: 36, 2: 39, 3: 35} (1/2/3 only on v=0x02)
    #   reserved   0x0000 on every record         → enum [0x0000]
    # v4: rcvr_state is None (unchecked) off the 0x02 event, so its enum flags
    # a new receiver state there without a per-version invariant form.
    field_invariants={
        "version": {"enum": [0x02, 0x07]},
        "sub_status": {"enum": [0x00, 0x01, 0x02, 0x03]},
        "rcvr_state": {"enum": ["OFF", "IDLE", "ON"]},
        "reserved": {"enum": [0x0000]},
    })
def parse_0x1377(log_time: int, data: bytes) -> Diag0x1377 | None:
    # Size is a fixed 4B across the entire corpus (N=31,692). Gate exactly,
    # matching the cluster convention — a longer payload claiming this code
    # is a framing artifact, not a variant, and must not silently truncate.
    if not data or data[0] not in _VERSIONS_1377_4918:  # loud gate
        return None
    if len(data) != 4:
        return None
    # NOTE: 0x1377 is intentionally LAYER-2-enforced (not Layer-1 gated):
    # the parser parses any version structurally and check_invariants flags
    # an off-enum version (see test_invariant_rejects_off_enum_version).
    # Registered in audit_field_invariants_version_gates.LAYER2_INTENTIONAL
    #, mirroring the 0x1476 precedent.
    return Diag0x1377(
        log_time=log_time, version=data[0], sub_status=data[1],
        reserved=unpack_from('<H', data, 2)[0],
    )
