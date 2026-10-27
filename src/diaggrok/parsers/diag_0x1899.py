"""0x1899 — geofence-manager WiFi motion-detector state log.

F3-grounded: each record is committed by the GNSS **geofence manager** —
``gm_log.c:288 "Logging WIFI motion detector state"`` is printed ≤ 1 ms before
every record, 1:1 (e.g. 151 records ↔ 151 prints, both directions, on a C-V2X
OBU; a +250 ms control scores 0). That supports the name
``LOG_GNSS_GEOFENCE_MOTION_DETECTION_WIFI_STATE`` over the older table name
``LOG_EVENT_PM_BATT_TEMP_OUT_OF_RANGE``. The neighbouring ``gm_core.c`` /
``gm_ebee.c`` prints ("Fix type", "Setting Inside Geofence", "Backoff
Selected") come from the same pass. No print labels the record sequence
counter at [1:5], the only varying field.
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
# 0x1899 — GNSS geofence status tick (108B fixed, 104/108 bytes constant)
# ---------------------------------------------------------------------------
# Cross-chipset corpus: LM960 SDX20, EG18-NA SDX20 V2, EP06A MDM9x07, FN980m
# SDX55, EM7511 MDM9650, RM520N-GL SDX62, plus long-uptime units: the Kapsch
# RIS-9260 (same 81UMV91M21 modem as the 81umv91m21 captures, same physical
# unit; it adds only uptime, not a second device), the Ficosa CarCom
# MDM9250 and the Casa CFW-3212 (RG520N). Only [1:5] varies.
#
# [1:5] is ONE u32 LE record sequence counter, +1 per record. v1..v9 split it
# into a u8 `counter` at [1], a small-enum "engine-internal state"
# `status_byte_2` at [2], and reserved-zero bytes at [3] and [4]. A runtime
# census showed v9 dropping 2,337 records, all v0x02 108 B and all from those
# long-uptime units, whose only difference was byte[3] != 0. In those 16
# captures:
#
#   - byte[2] (with byte[3]) advances by exactly +1 when byte[1] wraps 255->0.
#     The RIS-9260 capture holds [2:4] = 2086 for 235 records, 2087 for
#     exactly 256, then 2088.
#   - [1:4] read as u24 LE is a +1-per-record count (0x0826FF -> 0x082700).
#
# So the "state" byte was bits 8..15 of the count. That is why it looked like
# a small enum {0..4} on short, freshly booted captures (count < 1,280), why it
# was "monotonic non-decreasing within a capture", and why an earlier F3
# pass saw it flip 0->1 about 1 s into an established fix with no engine event
# (the count crossed 255->256). The earlier fix-lifecycle names (refuted by
# that F3 pass) and the neutral `state_<n>` names that replaced them are both
# dropped. `counter` and `status_byte_2` stay as the sequence's low and
# second bytes for back-compat.
#
# byte[4] is 0 on every corpus record (largest count seen ~0x0828xx, at a
# 100 ms .. 18.5 s cadence). It is read as the sequence MSB, not gated as
# reserved, so a platform with > 2**24 records of uptime is not dropped. The
# remaining 99 reserved-zero bytes keep the gate tight.
#
# The other bytes are bit-exact constants across every chipset:
#
#   - `status_flag_10` = 0x01 at [10]  → cross-chipset CONSTANT
#   - `rate_ms`        = 1000 (0x03E8) at [58:60] → CONSTANT u16 LE
#   - `status_flag_85` = 0x03 at [85]  → cross-chipset CONSTANT
#
# Field map:
#
#     [0]       u8     version            = 0x02 (CONSTANT across chipsets)
#     [1:5]    u32LE   sequence           record count, +1 per record
#                                         (counter = [1], status_byte_2 = [2])
#     [5:10]    5B     reserved           all zero (CONSTANT)
#     [10]      u8     status_flag_10     = 0x01 (CONSTANT)
#     [11:58]  47B     reserved           all zero (CONSTANT)
#     [58:60]  u16LE   rate_ms            = 1000 (CONSTANT)
#     [60:85]  25B     reserved           all zero (CONSTANT)
#     [85]      u8     status_flag_85     = 0x03 (CONSTANT)
#     [86:108] 22B     reserved           all zero (CONSTANT)


# Reserved-zero byte positions (99 bytes).  Bytes 5..9 (5), 11..57 (47),
# 60..84 (25), 86..107 (22) = 99 bytes total, zero on every corpus record.
_RESERVED_ZERO_OFFSETS: tuple[int, ...] = tuple(
    list(range(5, 10)) + list(range(11, 58)) + list(range(60, 85)) + list(range(86, 108))
)


@dataclass
class Diag0x1899:
    """GNSS geofence WiFi motion-detector state log (0x1899) — 108B, every byte accounted for."""
    log_time: int
    version: int
    sequence: int                    # u32 LE [1:5] record count, +1 per record
    counter: int                     # sequence low byte ([1]); back-compat
    status_byte_2: int               # sequence bits 8..15 ([2]); back-compat, NOT a state
    status_flag_10: int
    rate_ms: int
    status_flag_85: int
    all_invariants_ok: bool          # True iff 4 named constants match AND all
                                     # 99 reserved-byte positions are zero;
                                     # always True on accepted records
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1899',
            'log_time': self.log_time,
            'version': self.version,
            'sequence': self.sequence,
            'counter': self.counter,
            'status_byte_2': self.status_byte_2,
            'status_flag_10': self.status_flag_10,
            'rate_ms': self.rate_ms,
            'status_flag_85': self.status_flag_85,
            'all_invariants_ok': self.all_invariants_ok,
            'payload_size': self.payload_size,
        }


# --- Notes for validation ----------------------------------------------------
# 108B geofence WiFi-motion state log: 104/108 bytes are constant, so the only
# field carrying information is the u32 LE record sequence at [1:5] (see the
# field map above). Naming: older tables list this code as
# LOG_EVENT_PM_BATT_TEMP_OUT_OF_RANGE or as
# LOG_GNSS_GEOFENCE_MOTION_DETECTION_WIFI_STATE; the F3 commit print
# (gm_log.c) supports the geofence name. SIM8202G-M2 (SIMCom SDX55, v=0x02)
# is a convenient validation target.

@register(
    0x1899, domain="gnss",
    name="0x1899",
    description="GNSS geofence WiFi motion-detector state log (gm_log.c commit, F3-grounded) — 108B, every byte accounted for",
    version=10,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE across LM960, EG18-NA, EP06A, FN980m, EM7511, MC7455 "
        "and cold-reset captures (24,873 records / 133 captures / 7+ chipset "
        "generations), plus long-uptime units (Kapsch RIS-9260 = same "
        "81UMV91M21 modem / same physical unit, uptime only; Ficosa CarCom "
        "MDM9250; Casa CFW-3212) (2,337 records / 16 captures). 104/108 bytes are "
        "bit-exact constant: 4 named constants (version=2, status_flag_10=1, "
        "rate_ms=1000, status_flag_85=3) plus 99 reserved-zero positions hold "
        "corpus-wide and are hard-rejected; all_invariants_ok is retained for "
        "back-compat and is always True on accepted records. [1:5] is a u32 LE "
        "record sequence, +1 per record; byte[2] (formerly read as a state "
        "enum) is its bits 8..15 and steps exactly when byte[1] wraps. The "
        "subsystem is F3-grounded: gm_log.c 'Logging WIFI motion detector "
        "state' commits every record 1:1 (<=1 ms)."
    ),
    source_url="",
    issues=(),
    # Every byte accounted for: the u32 LE sequence at [1:5] (also exposed as
    # its counter / status_byte_2 bytes) + 4 named constants (version=2,
    # status_flag_10=1, rate_ms=1000, status_flag_85=3) + 99 reserved-zero
    # bytes verified by all_invariants_ok.  All 9 emitted fields are parsed
    # on every record.
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
    # status_byte_2). Corpus: 4 named constants + 99 reserved-zero bytes hold
    # corpus-wide. Reject any record that fails any of them.

    invariants_ok = (
        data[0] == 2
        and data[10] == 1
        and unpack_from('<H', data, 58)[0] == 1000
        and data[85] == 3
        and all(data[i] == 0 for i in _RESERVED_ZERO_OFFSETS)
    )
    if not invariants_ok:
        return None
    return Diag0x1899(
        log_time=log_time,
        version=data[0],
        sequence=unpack_from('<I', data, 1)[0],
        counter=data[1],
        status_byte_2=data[2],
        status_flag_10=data[10],
        rate_ms=unpack_from('<H', data, 58)[0],
        status_flag_85=data[85],
        all_invariants_ok=True,
        payload_size=len(data),
    )


