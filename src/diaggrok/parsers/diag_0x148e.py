"""0x148E — Small GNSS status report (18B fixed; corpus-validated byte map).

Cross-chipset RE corpus: 34,393 records / 177 captures / 15 chipset
families.  18-byte fixed-size payload.

Corpus-wide invariants:
  [0]  = 0x01 (1798/1798 sampled records on 50-capture sample —
                   likely 100% corpus-wide)
  [12] = 0x00
  [13] = 0x00
  [15] = 0x00
  [16] = 0x00
  [17] = 0x00

Varying bytes (multi-valued across corpus):
  [1]    param_a — multi-modal (top: 0x48 36.8%, 0x40 14.1%, 0x54 12.8%);
                    most values have low 2 bits zero (4-byte aligned hint)
  [2:4]  u16LE counter1 — wraparound counter; increments by 5 per record
                           on M2000 captures, by 1280 per record on FN980
                           cold-reset
  [4]    code4 — small varying enum (0x00 dominant, 0x01 also seen)
  [5:7]  u16LE value_a
  [7:9]  u16LE field_b — CHIPSET-DEPENDENT (live-grounded on EG25-G):
                           * SDX20 (EG18-NA) + SDX55 (FN980) + M2000: reads
                             0x7fff (i16 max) — a SATURATION/UNAVAILABLE
                             sentinel — or 0x0000 (engine idle). Not a live
                             measurement on these families.
                           * MDM9607 (EG25-G): reads an ACTUAL small per-epoch
                             metric, corpus range 132..395 (mean ~252), NEVER
                             0x0000 or 0x7fff across 959 corpus + 13 live
                             records. So 0x7fff is an SDX-family sentinel,
                             not a "measuring" flag — MDM9607 exposes the
                             real value the SDX parts saturate away. Best
                             current read: a per-epoch cross-correlation
                             performance metric (matches the canonical log
                             name LOG_GNSS_CC_PERFORMANCE_STATS_C +
                             co-temporal cc_slicer.c F3).
  [9]    count_c — small varying int (MDM9607: 17..19).  PARTITION HALF:
                           count_c + code11 == 21 in 959/959 corpus + 13/13
                           live EG25-G records, and ~92-100% on EG18-NA.
                           21 is a FIXED internal resource count (cross-
                           correlation channels), NOT the SV count — in a
                           live capture the sum stayed 21 while the
                           co-temporal AT-tracked SV count rose 21->25.
                           count_c/code11 partition those 21 CC resources
                           between two states.
  [10]   code10 — small varying enum (corpus-wide varied; MDM9607: 0x00 in
                           959/959 corpus + 13/13 live records).
  [11]   code11 — PARTITION HALF (MDM9607: 2..4): see count_c above,
                           count_c + code11 == 21.  NOT tracked-SV count
                           (stayed 3-4 while tracked SVs went 21->25 live).
                           M2000 shows 0x04 dominant, then 0x01/0x02/0x05.
  [14]   aux14 — multi-valued in some captures (most are 0x00)

Every non-reserved byte is exposed as a field; bytes [12, 13, 15, 16, 17]
are validated as reserved zero.

Log name: LOG_GNSS_CC_PERFORMANCE_STATS_C
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from diaggrok.registry import register

LOG_GNSS_STATUS_148E = 0x148E

_148E_VERSION = 0x01


# Ground truth (live-grounded on EG25-G/MDM9607). The canonical log name
# LOG_GNSS_CC_PERFORMANCE_STATS_C identifies this as GNSS cross-correlation
# (CC) engine performance stats.
#
# A live EG25-G (MDM9607) DIAG capture (0x148E plus extended F3, GNSS on,
# gnssconfig=1, fix acquired) grounds three field facts, each independently
# reproduced against the 959-record EG25-G corpus:
#   * count_c[9] + code11[11] == 21 (13/13 live, 959/959 corpus). 21 is a FIXED
#     internal CC-resource count, NOT the SV count — the sum held at 21 while
#     the co-temporal AT-tracked SV count rose 21->25. So count_c/code11 are a
#     complementary two-state partition of 21 cross-correlation resources.
#     This is corroborated by the 111k co-temporal cc_slicer.c F3 records (the
#     CC slicer scheduling correlator channel jobs) in the same capture.
#     COLD START (a 276-record capture spanning BLIND_SEARCH->3D fix): the
#     ==21 invariant is
#     POST-INIT, not from-record-0. 275/276 summed to 21, but the SINGLE first
#     record (engine cold-init) was a sentinel: count_c=240 (0xF0), code11=9
#     (sum 249), param_a=0x30 (vs the steady 0x44). Reading: at cold init the
#     CC-resource pool is unallocated (0xF0 = uninitialized/reset marker); the
#     21-partition is established from record 2 on. DO NOT add a
#     field_invariant asserting sum==21 — it would REJECT the legitimate
#     cold-init record. The correct predicate is "sum==21 XOR the 0xF0 init
#     sentinel". Steady-state-only corpora never exposed this record.
#     THREE-BYTE SENTINEL (same 276-record cold-start capture): the cold-init
#     sentinel is a THREE-byte marker, all co-located on the first record
#     (verified by decoding the record, not just marginals): param_a=0x30 AND
#     count_c=0xF0 AND
#     code10=0xFF (full bytes 0130000c007633ad01f0ff0900002c000000). It
#     parses cleanly (reserved [12,13]/[15:18] are zero). See the code10 note
#     below — code10=0xFF is the same class of init marker as count_c=0xF0.
#   * field_b[7:9] is CHIPSET-DEPENDENT: a real per-epoch metric on MDM9607
#     (132..395, never 0/0x7fff), but a 0x7fff saturation sentinel / 0x0000
#     idle marker on SDX20/SDX55 (EG18-NA, FN980, M2000). 0x7fff does not
#     mean "actively measuring".
#   * code10[10] == 0x00 on MDM9607 in STEADY STATE (959/959 corpus + 13/13
#     live + 275/276 cold-start). But the first (cold-init) record reads
#     code10=0xFF — the SAME init-sentinel class as
#     count_c=0xF0. So "code10==0x00" is a POST-INIT invariant: DO NOT promote
#     it to a field_invariant, it would reject the legitimate cold-init
#     record. Correct predicate: "code10==0x00 XOR the 0xFF init sentinel".
#     Steady-state-only corpora never exposed the 0xFF value.
# counter1 is a per-record wraparound counter (epoch cadence), a monotonic
# base. param_a/code4/value_a/aux14 remain opaque CC-stat bytes with no clean
# external reference and are intentionally not grounded. version is structural
# (0x01). Open: the exact semantics of each side of the 21-resource
# partition (count_c vs code11) needs firmware RE of the cc_* subsystem —
# it is below the AT/NMEA/F3-summary surface a host can reach. The live
# grounding was done on the EG25-G; the other chipsets share the
# 18B/v=0x01 layout.

@dataclass
class Diag0x148E:
    log_time: int
    version: int           # byte 0 — constant 0x01
    param_a: int           # byte 1 — multi-valued code
    counter1: int          # bytes [2:4] u16LE — wraparound counter
    code4: int             # byte 4 — small varying enum
    value_a: int           # bytes [5:7] u16LE
    field_b: int           # bytes [7:9] u16LE
    count_c: int           # byte 9
    code10: int            # byte 10 — small varying enum
    code11: int            # byte 11
    aux14: int             # byte 14
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x148E',
            'log_time': self.log_time,
            'version': self.version,
            'param_a': self.param_a,
            'counter1': self.counter1,
            'code4': self.code4,
            'value_a': self.value_a,
            'field_b': self.field_b,
            'count_c': self.count_c,
            'code10': self.code10,
            'code11': self.code11,
            'aux14': self.aux14,
            'payload_size': self.payload_size,
        }


@register(
    LOG_GNSS_STATUS_148E, domain="gnss",
    name="0x148E",
    issues=(),
    description="Small GNSS status report (0x148E) — 18B fixed; corpus-validated byte map",
    version=2,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE, cross-validated against a 34,393-record corpus / "
        "177 captures / 15 chipset families; every non-reserved byte is "
        "exposed and bytes [12, 13, 15, 16, 17] are validated as reserved "
        "zero. Live-grounded on EG25-G (MDM9607) with co-temporal F3 and "
        "AT-tracked SV counts: count_c + code11 partition a fixed pool of 21 "
        "cross-correlation resources (not the SV count) after a cold-init "
        "sentinel record; field_b is a live per-epoch metric on MDM9607 but "
        "a 0x7fff/0x0000 sentinel on SDX20/SDX55. param_a, code4, value_a "
        "and aux14 remain opaque."
    ),
    source_url="",
    fields_identified=11, fields_parsed=11,
    # Layer-2 invariants from the cross-chipset corpus walk
    # (34,393 records / 177 captures / 15 chipset families). version is
    # corpus-wide 0x01; payload_size is strictly 18B. The parser already
    # Layer-1-gates both (size != 18 → None, byte[0] != 0x01 → None);
    # declared here so the invariant is visible to downstream Layer-2
    # audit consumers. Byte-level reserved-zero invariants at
    # [12,13,15,16,17] are also Layer-1-enforced but live in fixed body
    # offsets, not in surfaced field names — left out of the enum since
    # there's no corresponding to_dict key.
    field_invariants={
        "version": {"enum": [0x01]},
        "payload_size": {"enum": [18]},
    },
)
def parse_0x148e(log_time: int, data: bytes) -> Diag0x148E | None:
    if len(data) != 18:
        return None
    if data[0] != _148E_VERSION:
        return None
    # Defensive: corpus-wide reserved-zero invariants at bytes
    # [12, 13, 15, 16, 17] — non-zero indicates framing collision with
    # another 0x14xx code.  Bytes [4] and [10] DO vary across the
    # corpus and must NOT be asserted constant.
    if data[12] != 0 or data[13] != 0:
        return None
    if data[15] != 0 or data[16] != 0 or data[17] != 0:
        return None
    counter1 = data[2] | (data[3] << 8)
    value_a = data[5] | (data[6] << 8)
    field_b = data[7] | (data[8] << 8)
    return Diag0x148E(
        log_time=log_time,
        version=data[0],
        param_a=data[1],
        counter1=counter1,
        code4=data[4],
        value_a=value_a,
        field_b=field_b,
        count_c=data[9],
        code10=data[10],
        code11=data[11],
        aux14=data[14],
        payload_size=len(data),
    )
