"""0x1852 — IPA ring dump, ring B.

**Subsystem: IPA (the modem's IP Accelerator). F3-grounded per version.**
Not LTE ML1. 0x1852 is one record of the IPA stats dump. The same dump
carries 0x184F "Data Modem IPA Stats" and 0x1962 "IPA TCP ACK COAL Stats"
(canonical log names), 0x1850,
0x1851, 0x1963 and, on v3 builds, 0x1C6E/0x1C6F/0x1C71 (LOG_IPA_*_STATS).
0x1851 is the first ring of the same dump, with the same layout.

The byte-level tie: the u32 at +1 (``dump_tick``) matches the tick at +1 or +4
of the other records of the same dump. Sibling minus 0x1851/0x1852 tick is 0
on 7,625 pairs, -1 on 1,077 and +1 on 18. It is never more than one tick
apart (95 captures, all three versions).

F3 on each version's own records (+-2 ms join, scored against the same
records shifted by +-0.25..5 s)::

    v1  MC7455 MDM9x30  F3 and 0x60 absent in all 3 bearing captures. The
                        tick equals 0x184F's in the same dump
    v2  EG18-NA SDX20   2/2 flushed with the IPA task shutdown
                        (ipa_ctl_task.c:737 "UL/DL/Prod shutdown done!",
                        a2_log task exit, ipa_ctl_clk.c:1026) at +0.009 and
                        +0.018 ms. Elsewhere on v2 F3 does not name the
                        trigger: an MDM9150 build dumps every 1.000 s
                        and prints no IPA/A2 F3; MDM9250 prints none;
                        LM960 and em7565 show no enriched site (1 of 59
                        em7565 "A2 turned OFF" prints is followed by a dump).
                        an MDM9650 build also dumps every 1.000 s
    v3  LV55 SDX55      68/68 ipa_log.c:2468 IPA_UL_PRIORITY_PKTS_STATS at
                        +0.008 ms. All 68 prints of that site fall on a dump
                        (68x the shifted background). Triggered by 36
                        UL-pipe stops + 32 starts (ipa_ctl_clk.c:1397/1449)
    v3  T99W175 SDX55   14/14 at a fixed -198.80 ms after ipa_ipfltr.c:8684
                        "programming DL rule type 39 to HW" (CU/GC builds);
                        1/1 ipa_log.c:2963 at +0.012 ms (VZ build)
    v3  RM520N-GL SDX62 2/2 ipa_ctl_clk.c:1368 at -0.094 ms, ipa_log.c:2963
                        at +0.011 ms
    v3  T99W373 SDX62   11/11 ipa_log.c:2967 at +0.005 ms (66x), ipa_log.c:2989
                        11/11, ipa_ctl_clk.c:1386 pipe stopped 10/11 at -0.30 ms
    v3  M3100 SDX65     10/10 ipa_log.c:2963 at +0.006 ms, ipa_ctl_clk.c:1368 8/10
                        at -0.059 ms
    v3  EM9291 SDX62    8/8 ipa_log.c:2967 at +0.006 ms
    v3  T99W640 SDX72   19/19 ipa_ctl_clk.c:1465 "DL producer pipe stopped"
                        at -0.096 ms, ipa_log.c:3318 at +0.006 ms

No lte_* site falls within +-2 ms of any LV55 v3 record. An apparent LTE
ML1 association appears only with a +-200-tick window in a capture holding
~908k ML1 prints, where any record would match by chance. 0x60 is present and silent (T99W373 1,915 events, M3100 603, T99W175
111, RM520N-GL 63; none recurs at record times). qcsuper and SCAT emit
nothing for this code.

Layout (``_ipa_ring_dump.py``). A 12-byte header (version, dump_tick,
3 zero bytes, ring_size=32, write_index), then the first 1024 bytes of a
32-slot ring. ``write_index`` is the next slot to write. An unwrapped ring
holds exactly slots [0, write_index). Once wrapped, reading from write_index
gives non-decreasing entry timestamps. Entries are 32 bytes on every build,
SDX72 included. Only 0x1851 switches to 80 bytes on SDX72. The shared helper
still detects the stride from the body rather than trusting the header.

Why +8 is a slot count and not a byte stride: SDX72's 0x1851 ring uses
80-byte entries while +8 still reads 32. 0x1963 (same dump) carries the same
header, with ring_size 32 and write_index < 32, around 12-byte entries.

Measured on a stratified sample of 1,059 records from 95
captures (every module/firmware group; not the whole corpus): 0 parse
failures, 0 invariant violations. The sidecar-exhaustive census is 27,883
records, all 1036 B with byte0 in {1,2,3}. Results:
  - stride resolves on every record, and it is 32 B on every one
  - unwrapped rings fill exactly slots [0, write_index): 197/197
  - within a stream_id, seq never steps backward in ring order: +1..+127
    (mod 256) on 19,175/19,216 pairs, exactly +1 on 19,002
  - attr == 0 exactly when length == 0, on all 31,024 entries
The timestamp (u24 at +25 on v2/v3, u32 at +20 on v1) is a CANDIDATE. It is
non-decreasing modulo 2^24 in ring order on 1,053/1,054 v2/v3 rings,
but its clock is not settled. On most rings the newest entry lags dump_tick by tens to
hundreds of ticks, while the LV55 0x1852 ring wraps 2^24 twice in 16 entries.

Stays offset-named/raw: attr, kind, length, and entry bytes 8..23 / 28..31.
F3 is silent on what the ring entries describe.

Log name: LOG_EVENTS_DS_GPRS_PACKET_RESOURCE_REQUEST
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from diaggrok.parsers._ipa_ring_dump import SIZE, decode
from diaggrok.registry import register


@dataclass
class Diag0x1852:
    """0x1852 — IPA ring dump (ring B): header + decoded ring entries."""
    log_time: int
    version: int
    dump_tick: int
    ring_size: int
    write_index: int
    entry_stride: int | None
    entries: tuple[dict[str, Any], ...]
    body_raw: bytes
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x1852",
            "log_time": self.log_time,
            "version": self.version,
            "dump_tick": self.dump_tick,
            "ring_size": self.ring_size,
            "write_index": self.write_index,
            "entry_stride": self.entry_stride,
            "entries": [dict(e) for e in self.entries],
            "body_raw": self.body_raw,
            "payload_size": self.payload_size,
        }


@register(
    0x1852,
    name="0x1852",
    description="0x1852 — IPA ring dump, ring B: 1036 B = 12 B header (ver, dump tick shared with 0x184F/0x1850/0x1962/0x1C6x, ring_size, write_index) + 1024 B ring window (32 B entries on every build). F3-grounded IPA, not LTE ML1",
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail="Clean-room RE across MDM9x30/SDX20/MDM9150/MDM9250/SDX55/SDX62/SDX72 captures; F3 null-model join per version (ipa_log.c / ipa_ctl_clk.c / ipa_ctl_task.c sites) and dump-tick identity with the canonically named IPA stats records.",
    issues=(),
    fields_identified=13,
    fields_parsed=11,
    field_invariants={"version": {"enum": [1, 2, 3]}},
)
def parse_0x1852(log_time: int, data: bytes) -> Diag0x1852 | None:
    if len(data) != SIZE:
        return None
    if data[0] not in (1, 2, 3):
        return None
    r = decode(data)
    if r is None:
        return None
    return Diag0x1852(
        log_time=log_time,
        version=r["version"],
        dump_tick=r["dump_tick"],
        ring_size=r["ring_size"],
        write_index=r["write_index"],
        entry_stride=r["entry_stride"],
        entries=tuple(r["entries"]),
        body_raw=r["body_raw"],
        payload_size=len(data),
    )
