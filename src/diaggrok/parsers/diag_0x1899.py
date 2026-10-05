"""0x1899 — geofence-manager WiFi motion-detector state log.

F3-grounded: each record is committed by the GNSS **geofence manager** —
``gm_log.c:288 "Logging WIFI motion detector state"`` is printed ≤ 1 ms before
every record, 1:1 (e.g. 151 records ↔ 151 prints, both directions, on a C-V2X
OBU; a +250 ms control scores 0). That supports the name
``LOG_GNSS_GEOFENCE_MOTION_DETECTION_WIFI_STATE`` over the older table name
``LOG_EVENT_PM_BATT_TEMP_OUT_OF_RANGE``. The neighbouring ``gm_core.c`` /
``gm_ebee.c`` prints ("Fix type", "Setting Inside Geofence", "Backoff
Selected") come from the same pass. No print labels byte[1] (counter) or
byte[2] (state), which stay as decoded below.
Cadence is NOT always 1 Hz despite the constant ``rate_ms`` = 1000: a C-V2X
OBU emits at 100 ms.

See the module body for the field map and the evidence behind it.

Log name: LOG_EVENT_PM_BATT_TEMP_OUT_OF_RANGE
Also known as: LOG_GNSS_GEOFENCE_MOTION_DETECTION_WIFI_STATE
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


# ---------------------------------------------------------------------------
# 0x1899 — GNSS geofence status tick (108B fixed, 106/108 bytes constant)
# ---------------------------------------------------------------------------
# Cross-chipset corpus: 3380 records across 6 chipset generations — LM960
# SDX20, EG18-NA SDX20 V2, EP06A MDM9x07, FN980m SDX55, EM7511 MDM9650,
# plus GNSS-diag 5-min captures on several networks and after cold resets.
# Across this corpus, only bytes [1] and [2] actually vary:
#
#   - `byte[1]` — free-running u8 counter (all 256 values observed).
#     **+1 per record, 635/635 consecutive deltas on the two biggest
#     captures** — a strict `+1 mod 256` frame counter, one tick per 0x1899
#     record.
#   - `byte[2]` — small-enum engine-internal state field.  Distribution
#     across the 3380-record corpus: {0: 2601 (77%), 1: 657 (19%),
#     2: 109 (3%), 3: 9 (0.3%), 4: 4 (0.1%)}.  Values {0,1,2,3,4} observed.
#
# byte[2] is NOT a GNSS fix-lifecycle state machine, even though in a
# handful of captures it co-varies with the GNSS session.  Three
# independent lines of evidence rule that reading out:
#
#   1. HW/QMI ground truth (RM520N-GL SDX62): byte[2] stays 0 during a HELD
#      FIX, so 0 cannot mean "idle, pre-fix".
#   2. F3 ground truth (EG18-NA cold GNSS start): the GNSS fix became valid
#      (mgp `FixVal 1`, `New fix saved as best`, `TPC:ALE position` with real
#      Lat/Lon) ~1 s BEFORE byte[2] flipped 0→1, and the flip coincided with
#      NO discrete engine event — it happened mid-tracking.  A "tracking"
#      state would flip AT fix acquisition, not a second later.
#   3. Same-unit contradiction (EG18-NA boot + GNSS): byte[2] stayed 0 for
#      ALL 242 records despite a full GNSS session on the SAME unit/firmware
#      that flipped to 1 in the cold start.  A fix-lifecycle byte cannot
#      read 0 throughout one GNSS session and 0→1 in another.
#
# byte[2] is therefore an UNLABELLED engine-internal state byte (values
# {0,1,2,3,4}; 3/4 seen only on one LM960 firmware build).  Its physical
# meaning is unknown and demonstrably NOT a fix state — the names are
# neutral `state_<n>`.
#
# The empirical invariant "within any capture the status sequence is
# monotonic non-decreasing" holds on all 47 captures that
# contain 0x1899 records — useful as a corruption-detection heuristic.
#
# All 106 other bytes are bit-exact constants across 6 chipsets,
# including the values named status_flag_10, rate_ms, and
# status_flag_85. Those names remain for back-compat but are really
# cross-chipset CONSTANTS, not runtime-variable flags:
#
#   - `status_flag_10` = 0x01 at [10]  → cross-chipset CONSTANT
#   - `rate_ms`        = 1000 (0x03E8) at [58:60] → CONSTANT u16 LE
#   - `status_flag_85` = 0x03 at [85]  → cross-chipset CONSTANT
#
# Field map:
#
#     [0]       u8     version            = 0x02 (CONSTANT across chipsets)
#     [1]       u8     counter            u8 frame counter, +1 mod 256
#     [2]       u8     status_byte_2      engine-internal state enum, values
#                                         {0,1,2,3,4}; meaning unknown, NOT a
#                                         fix state (see above)
#     [3:10]    7B     reserved           all zero (CONSTANT)
#     [10]      u8     status_flag_10     = 0x01 (CONSTANT)
#     [11:58]  47B     reserved           all zero (CONSTANT)
#     [58:60]  u16LE   rate_ms            = 1000 (CONSTANT)
#     [60:85]  25B     reserved           all zero (CONSTANT)
#     [85]      u8     status_flag_85     = 0x03 (CONSTANT)
#     [86:108] 22B     reserved           all zero (CONSTANT)

# Status-byte-2 enum mapping.  NEUTRAL labels only: the physical meaning of
# byte[2] is unknown and it is not a GNSS fix-lifecycle state (see the field
# map above).  Values 3/4 are seen on a single LM960 firmware build only.
# Fix-progression names (idle_pre_fix/tracking/post_cold_reset_recovery)
# would contradict the RM520N held-fix=0 and the EG18-NA same-unit 0-vs-0→1
# observations.
GNSS_STATUS_1899_STATES: dict[int, str] = {
    0: 'state_0',
    1: 'state_1',
    2: 'state_2',
    3: 'state_3',  # LM960 only
    4: 'state_4',  # LM960 only
}


# Reserved-zero byte positions (101 bytes).  Bytes 3..9 (7), 11..57 (47),
# 60..84 (25), 86..107 (22) = 101 bytes total.  These are 0x00 on every
# observed 0x1899 record (24,873 records / 133 captures).
_RESERVED_ZERO_OFFSETS: tuple[int, ...] = tuple(
    list(range(3, 10)) + list(range(11, 58)) + list(range(60, 85)) + list(range(86, 108))
)


@dataclass
class Diag0x1899:
    """GNSS geofence status tick report (0x1899) — 108B, every byte accounted for."""
    log_time: int
    version: int
    counter: int                     # u8 frame counter, +1 mod 256 per record
    status_byte_2: int               # raw state enum value
    status_byte_2_name: str          # mapped name from GNSS_STATUS_1899_STATES or 'unknown_<n>'
    status_flag_10: int
    rate_ms: int
    status_flag_85: int
    all_invariants_ok: bool          # True iff 4 named constants match AND all
                                     # 101 reserved-byte positions are zero;
                                     # always True on accepted records
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1899',
            'log_time': self.log_time,
            'version': self.version,
            'counter': self.counter,
            'status_byte_2': self.status_byte_2,
            'status_byte_2_name': self.status_byte_2_name,
            'status_flag_10': self.status_flag_10,
            'rate_ms': self.rate_ms,
            'status_flag_85': self.status_flag_85,
            'all_invariants_ok': self.all_invariants_ok,
            'payload_size': self.payload_size,
        }


# --- Notes for validation ----------------------------------------------------
# 108B geofence WiFi-motion state log: 106/108 bytes are constant, so only two
# fields carry information — byte[1] counter (strict +1/record cadence) and
# byte[2] engine-internal state (not a fix-state machine; see the field map
# above). Naming: older tables list this code as
# LOG_EVENT_PM_BATT_TEMP_OUT_OF_RANGE or as
# LOG_GNSS_GEOFENCE_MOTION_DETECTION_WIFI_STATE; the F3 commit print
# (gm_log.c) supports the geofence name. SIM8202G-M2 (SIMCom SDX55, v=0x02)
# is a convenient validation target.

@register(
    0x1899, domain="gnss",
    name="0x1899",
    description="GNSS geofence WiFi motion-detector state log (gm_log.c commit, F3-grounded) — 108B, every byte accounted for",
    version=9,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE across LM960, EG18-NA, EP06A, FN980m, EM7511, MC7455 "
        "and cold-reset captures (24,873 records / 133 captures / 7+ chipset "
        "generations). 106/108 bytes are bit-exact constant: 4 named "
        "constants (version=2, status_flag_10=1, rate_ms=1000, "
        "status_flag_85=3) plus 101 reserved-zero positions hold corpus-wide "
        "and are hard-rejected before any other byte read; all_invariants_ok "
        "is retained for back-compat and is always True on accepted records. "
        "byte[1] is a +1/record u8 counter; byte[2] is a small-enum "
        "engine-internal state {0,1,2,3,4} whose physical meaning is UNKNOWN "
        "— F3 and HW ground truth show it is NOT a fix-lifecycle state. The "
        "subsystem is F3-grounded: gm_log.c 'Logging WIFI motion detector "
        "state' commits every record 1:1 (<=1 ms)."
    ),
    source_url="",
    issues=(),
    # Every byte accounted for: 2 varying bytes (counter, status_byte_2) + 4
    # named constants (version=2, status_flag_10=1, rate_ms=1000,
    # status_flag_85=3) + 101 reserved-zero bytes verified by
    # all_invariants_ok.  All 9 emitted fields are parsed on every record.
    fields_identified=9,
    fields_parsed=9,
    field_invariants={
        # The 4 named constants are both hard-rejected at layer-1 AND
        # declared at layer-2. payload_size is the 108B fixed-size dispatch.
        "version": {"enum": [2]},
        "status_flag_10": {"enum": [1]},
        "rate_ms": {"enum": [1000]},
        "status_flag_85": {"enum": [3]},
        "payload_size": {"enum": [108]},
    },
)
def parse_0x1899(log_time: int, data: bytes) -> Diag0x1899 | None:
    if len(data) < 108:
        return None
    if data[0] != 2:
        return None
    # Hard `return None` rejection BEFORE any other byte read (a soft
    # boolean would let a foreign 108B payload through with a garbage
    # status_byte_2). Corpus (24,873 records / 133 captures): 4 named
    # constants + 101 reserved-zero bytes hold corpus-wide. Reject any
    # record that fails any of them.

    invariants_ok = (
        data[0] == 2
        and data[10] == 1
        and unpack_from('<H', data, 58)[0] == 1000
        and data[85] == 3
        and all(data[i] == 0 for i in _RESERVED_ZERO_OFFSETS)
    )
    if not invariants_ok:
        return None
    status_byte_2 = data[2]
    return Diag0x1899(
        log_time=log_time,
        version=data[0],
        counter=data[1],
        status_byte_2=status_byte_2,
        status_byte_2_name=GNSS_STATUS_1899_STATES.get(status_byte_2, f'unknown_{status_byte_2}'),
        status_flag_10=data[10],
        rate_ms=unpack_from('<H', data, 58)[0],
        status_flag_85=data[85],
        all_invariants_ok=True,
        payload_size=len(data),
    )


