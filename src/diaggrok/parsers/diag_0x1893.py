"""0x1893 - MCS_CXM coexistence manager low-priority arbitration log.

Coexistence (domain="coex"), NOT GNSS. Typed parser for four size variants.

**F3-grounded subsystem identity:** the firmware's Coexistence-Manager logger
`cxm_trace.c` prints
`MCS_CXM: CXM entered cxm_send_log. Log Code: 0x1893` from its own commit path
(the resolved runtime value names the code), observed across SDX55-class
modems (RM500Q-AE / FN980 / SIM8202GM2 / T99W640). 0x1893 sits in the
contiguous CXM priority block 0x1892-0x1895
(SMEM_DATA / LOW_PRIO / MEDIUM_PRIO / HIGH_PRIO), matching the name
`LOG_MCS_CXM_LOW_PRIO` found in an independent name table. Sibling 0x1894 is
the same CXM family, and its payload is likewise a slotted arbitration table.

**This is not a GNSS measurement-engine status log**, despite older name
tables and its neighbours in the code range. A "GNSS_ME_NAVIC_MEAS" title does
not match the records (MDM9207 EG25-G has no NavIC yet still emits this
code), and on an RM520N-GL `occupied_count` modals at 14 (the structural slot
max) regardless of satellites-in-view (12-21), i.e. it does NOT track
satellite count as a GNSS measurement log would. The firmware CXM commit-path
message settles it: this is a coexistence arbitration table.

Four layout variants distinguished by total payload size:
  888B: SDX5x/SDX62 (62B header + 14×59B slots). version_b=0x02.
  873B: MDM9607 EG25-G (61B header + 14×58B slots). version_b=0x01.
  468B: MDM9x30 MC7455/EM7455 (34B header + 14×31B slots). version_b=0x01.
  453B: MDM9x35 AirCard 791L (33B header + 14×30B slots). version_b=0x01.

All four are one grammar: a 3-byte prefix ``[0] version, [1] version_b,
[2] seq_lo`` then 15 slots of a per-build slot length
(3 + 15×59 = 888, 3 + 15×58 = 873, 3 + 15×31 = 468, 3 + 15×30 = 453). The
"header" the parser names is that prefix plus slot 0 (counter = slot-0
timestamp, flag_11 = slot-0 marker_a, marker_14 = slot-0 marker_b), which is
why its field offsets are identical across variants. ``seq_lo`` equals the
number of occupied slots (incl. slot 0) on 6/6 sampled records of all four
sizes (CANDIDATE; kept under its old name). Other sizes (e.g. a 618 B
kismet-carried record) are unattested and return None (registry WARN).

Field offsets within header and slot are identical between variants
through marker_14; only the trailing pad byte differs. The 14 slots are
CXM arbitration slots (not GNSS measurement slots); per-slot field
semantics (marker_a/b, status_flag, timestamp_u40) remain opaque CXM
internals with no external reference to check them against.

Log name: LOG_MCS_CXM_LOW_PRIO
Also seen applied to this code, but belonging to a different log: LOG_EVENT_CPC_CONFIG_ACTION
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


# Scope of the decode: `occupied_count` is the number of active (non-zero
# timestamp) CXM arbitration slots; it modals at the structural max of 14 and
# does NOT track any external observable (no satellite-count correlation on
# an RM520N-GL). The per-slot fields (marker_a/b, status_flag, timestamp_u40)
# are opaque CXM internals with no external reference, so they are
# deliberately NOT grounded. version = 0x01 is the DIAG payload version byte;
# the RM520N-GL emits the 888-byte (version_b=0x02) SDX62 form.

@dataclass
class CxmArbSlot1893:
    """One CXM arbitration slot in a 0x1893 record (59 B)."""
    occupied: bool
    timestamp_u40: int   # [+0..+4] little-endian u40, 0 if slot empty
    marker_a: int        # [+8]  expected 0x06 when occupied
    marker_b: int        # [+11] expected 0x01 when occupied
    status_flag: int     # [+14] varies (0x00, 0x04, ...)

    def to_dict(self) -> dict[str, Any]:
        return {
            'occupied': self.occupied,
            'timestamp_u40': self.timestamp_u40,
            'marker_a': self.marker_a,
            'marker_b': self.marker_b,
            'status_flag': self.status_flag,
        }


@dataclass
class Diag0x1893:
    """MCS_CXM low-prio arbitration log (0x1893) - 62 B header + 14 × 59 B slots."""
    log_time: int
    version: int       # [0]  const 0x01
    version_b: int       # [1]  const 0x02
    seq_lo: int          # [2]
    counter: int         # [3..6] u32 LE
    flag_7: int          # [7]
    flag_11: int         # [11] state flag; varies in {0x00, 0x06} corpus-wide
    marker_14: int       # [14] const 0x01
    flag_17: int         # [17]
    slots: list[CxmArbSlot1893]
    occupied_count: int
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1893',
            'log_time': self.log_time,
            'version': self.version,
            'version_b': self.version_b,
            'seq_lo': self.seq_lo,
            'counter': self.counter,
            'flag_7': self.flag_7,
            'flag_11': self.flag_11,
            'marker_14': self.marker_14,
            'flag_17': self.flag_17,
            'occupied_count': self.occupied_count,
            'slots': [s.to_dict() for s in self.slots],
            'payload_size': self.payload_size,
        }


_CXM_1893_NUM_SLOTS = 14
# Layout variants - distinguished by total payload size.
# 888B: SDX5x/SDX62 (62B header + 14×59B slots). version_b=0x02.
# 873B: MDM9607 EG25-G (61B header + 14×58B slots). version_b=0x01.
# 468B / 453B: MDM9x30 / MDM9x35, same grammar with 31 / 30 B slots.
# Field offsets within header and slot are identical between variants
# through marker_14; only the trailing pad byte differs.
_CXM_1893_VARIANT = {
    888: (62, 59, 0x02),  # (header_len, slot_len, expected_version_b)
    873: (61, 58, 0x01),
    468: (34, 31, 0x01),  # MC7455/EM7455 MDM9x30, 3 + 15×31
    453: (33, 30, 0x01),  # AirCard 791L MDM9x35, 3 + 15×30
}


def _parse_1893_slot(data: bytes, base: int) -> CxmArbSlot1893:
    # u40 LE timestamp = lower 5 bytes treated as u64 with high 3 bytes 0
    ts_bytes = data[base : base + 5] + b"\x00\x00\x00"
    ts_u40 = unpack_from("<Q", ts_bytes, 0)[0]
    occupied = ts_u40 != 0
    return CxmArbSlot1893(
        occupied=occupied,
        timestamp_u40=ts_u40,
        marker_a=data[base + 8],
        marker_b=data[base + 11],
        status_flag=data[base + 14],
    )


@register(
    0x1893, domain="coex",
    name="0x1893",
    description=(
        "MCS_CXM coexistence-manager low-priority arbitration log (0x1893) - "
        "four-variant typed parser. 888B SDX5x/SDX62 (62B+14×59B), 873B "
        "MDM9607 EG25-G (61B+14×58B), 468B MDM9x30 and 453B MDM9x35, shared "
        "field semantics. F3-grounded as CXM (not GNSS) via the cxm_trace.c "
        "commit-path message"
    ),
    version=7,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE. 888B layout validated across 6 chipsets/vendors "
        "(SDX55 EM9190/FN980/RM500Q-AE, SDX62 RM520N-GL, MDM9640 EP06A, "
        "SDX20 LM960) on 2,084 records; 17,210 records in total across all "
        "variants. All layouts are a 3-byte prefix + 15 slots (3 + 15×59 / "
        "58 / 31 / 30); the 468 B MDM9x30 (MC7455/EM7455) and 453 B MDM9x35 "
        "(AirCard 791L) records share the grammar (slot timestamps, "
        "marker_b=1 and seq_lo == occupied-slot count all line up). The 873B "
        "EG25-G MDM9607 variant has the same field positions through "
        "marker_14, distinguished by version_b (0x01 vs 888B's 0x02). "
        "byte[11] is a state flag (flag_11, {0x00, 0x06}), not a constant "
        "marker. marker_a (slot +8) is NOT pinned across variants: 888B is "
        "always 0x06 when occupied, 873B varies {0x00, 0x06} within a single "
        "record. The subsystem is F3-grounded as MCS_CXM via the firmware's "
        "cxm_send_log commit path; per-slot semantics remain opaque."
    ),
    source_url="",
    fields_identified=10,
    fields_parsed=10,
    issues=(),
    # Layer-2 plausibility - 17,210 records:
    #   version (offset 0): 0x01 across 100% of records
    #   version_b (offset 1): 0x01 on 873B (MDM9607 EG25-G) / 0x02 on 888B (SDX5x/SDX62)
    #   marker_14 (offset 14): 0x01 across 100% of records, both variants
    # The parser already returns None on mismatch; declaring these as
    # field_invariants makes the audit toolchain catch corpus-scale
    # violations without modifying parser dispatch.

    field_invariants={
        "version": {"enum": [1]},
        "version_b": {"enum": [1, 2]},
        "marker_14": {"enum": [1]},
    },
)
def parse_0x1893(log_time: int, data: bytes) -> Diag0x1893 | None:
    variant = _CXM_1893_VARIANT.get(len(data))
    if variant is None:
        return None
    header_len, slot_len, expected_version_b = variant
    if data[0] != 0x01 or data[1] != expected_version_b:
        return None
    if data[14] != 0x01:
        return None
    counter = unpack_from('<I', data, 3)[0]
    slots: list[CxmArbSlot1893] = []
    occupied = 0
    for i in range(_CXM_1893_NUM_SLOTS):
        slot = _parse_1893_slot(data, header_len + i * slot_len)
        slots.append(slot)
        if slot.occupied:
            occupied += 1
    return Diag0x1893(
        log_time=log_time,
        version=data[0],
        version_b=data[1],
        seq_lo=data[2],
        counter=counter,
        flag_7=data[7],
        flag_11=data[11],
        marker_14=data[14],
        flag_17=data[17],
        slots=slots,
        occupied_count=occupied,
        payload_size=len(data),
    )
