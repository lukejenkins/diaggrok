"""0x145E — LOG_CGPS_ME_RAPID_SEARCH_REPORT_C: GPS rapid-search queue snapshot.

The GNSS measurement engine's cold-start **rapid (sky) search** keeps one queue
of GPS-L1CA SVs it has not found yet. Each time the rapid search declares a
detection it drops that SV from the queue and emits this record: a cumulative
bitmask of the SVs dropped so far, followed by the remaining queue.

Two on-wire versions share one layout. v0x02 has a 4-byte-wider mask field:

  v0x01 (MDM9x30 — Sierra MC7455), 9-byte header:
    [0]     u8     version            0x01
    [1:5]   u32LE  detected_sv_mask   bit n -> GPS PRN n+1 (cumulative)
    [5:9]   u32LE  num_entries        == (len - 9) / 4
    [9:]    entries[num_entries]

  v0x02 (MDM9607 — Quectel EG95-NA), 13-byte header:
    [0]     u8     version            0x02
    [1:5]   u32LE  detected_sv_mask   bit n -> GPS PRN n+1 (cumulative)
    [5:9]   u32LE  detected_sv_mask_hi  RAW, 0 in all 9 records. CANDIDATE upper
                                      word of a u64 mask (SV ids 33..64)
    [9:13]  u32LE  num_entries        == (len - 13) / 4
    [13:]   entries[num_entries]

  entry (4 B, both versions):
    [0]     u8     sv_id        GPS PRN 1..32, or 33..37 (see below)
    [1]     u8     entry_flags  RAW; observed {0x08, 0x04, 0x01}
    [2:4]   u16LE  order_key    RAW; the queue's sort key (see below)

## Grounding

Neither bearing capture has F3 (0x79/0x99/0x98/0x92 all 0) or a 0x60 event
frame (outer opcodes are only 0x10), and QCSuper/SCAT do not decode 0x145E. So
the references here are the **co-emitted, already-grounded GNSS logs in the same
capture**, matched by stream order. Stream order is used because the MC7455's
per-code DIAG timestamps use different epochs:

* **0x148A GPS record (F3-grounded masks)**: every set bit in
  ``detected_sv_mask`` is an SV that 0x148A's next GPS record moves from
  Unknown (+48) to KnownVisible (+32) + Dedicated (+56). This holds for 12 of 13
  detections: EG95 PRNs 6, 7, 32, 16, 17, 14, 9, 21, 3, whose final 0x148A
  KnownVisible set is exactly those 9, and MC7455 PRNs 24, 32, 2.
* **0x1526 per-SV measurement**: for the same 12, the dropped PRN's
  first valid C/N0 (23.9..38.8 dB-Hz) is on ``meas_task_id`` 1 (the
  candidate-verify stage) 4..15 stream records before this record.
  Verifies that fail (no C/N0) never drop an SV.
* **The 13th (MC7455 PRN 16) is a false alarm.** The rapid search dropped it
  with no verify before it. Its 5 later task-1 verifies all fail, it never
  reaches Dedicated, and 0x148A later marks it KnownNotVisible (below the
  horizon) once the almanac arrives. So the mask records a *declared detection*,
  not a confirmed acquisition. That is why it is named ``detected``, not
  ``acquired``.

Measured on all 13 records (4 v0x01 + 9 v0x02, 100% each):

* ``num_entries == (len - H) / 4``.
* The queue is exactly {GPS PRN 1..32} minus the detected PRNs, plus five
  fixed slots 33..37. So ``num_entries == 37 - popcount(detected_sv_mask)``.
* Each record in a session sets exactly one new mask bit, and the first
  record has exactly one bit set. The record is emitted *on* a detection.
* Entries with ``entry_flags == 0x08`` come first and are sorted ascending
  by ``order_key`` (always > 0). The other entries have ``order_key == 0``
  and are sorted by (flags desc, sv_id asc).
* Per SV, ``order_key`` never decreases from one record to the next (11/11
  transitions; strictly increasing 10/11).

Corpus walk, both versions: 2 captures, 671,071 records, 13/13 0x145E
parsed, 0 invariant violations. Every structural check passes on every
record. Cross-log checks, v0x01 / v0x02: verify within 32 records 3/4 / 9/9;
0x148A promotion at the next GPS record 3/4 (+1 not promoted) / 9/9.

Still raw / CANDIDATE:

* ``order_key`` is not a clock: on EG95 it grows across records 3..6, which
  share one receiver epoch (0x1526 rcvr_time 36760 ms), and no field of the
  verify record matches it. It is an ordering/priority key whose unit is
  unknown.
* ``entry_flags`` 0x04 appears only on EG95 PRN 1 and 4. 0x148A puts both in
  Unknown like the other queued SVs, so nothing observed separates them.
  0x01 marks every 33..37 slot.
* sv_id 33..37 are the five extra slots in the GPS/QZSS-L1CA search-task
  namespace: 0x1526 tasks 0/1 carry sv_id 33..37 on both captures, and the
  0x148A GPS record's mask covers bits 32..36. They are likely QZSS, but no
  record in the corpus detects one, so that stays a CANDIDATE.
* ``detected_sv_mask_hi`` (v0x02) could be the high word of a u64 mask or a
  separate field. It is 0 in the whole corpus, so it is exposed raw.

Log name: LOG_CGPS_ME_RAPID_SEARCH_REPORT_C
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


_KNOWN_VERSIONS = (0x01, 0x02)
# version -> (header_size, num_entries offset)
_LAYOUT = {0x01: (9, 5), 0x02: (13, 9)}
_ENTRY_SIZE = 4
# entry_flags value carried by every queued GPS PRN that has an order_key.
FLAG_KEYED = 0x08


@dataclass
class RapidSearchEntry:
    """One queue slot: sv_id + raw flags + raw sort key."""
    sv_id: int
    entry_flags: int
    order_key: int

    def to_dict(self) -> dict[str, int]:
        return {
            'sv_id': self.sv_id,
            'entry_flags': self.entry_flags,
            'order_key': self.order_key,
        }


@dataclass
class Diag0x145E:
    """GPS rapid-search queue snapshot (0x145E), v0x01/v0x02."""
    log_time: int
    version: int                  # [0] u8; {0x01, 0x02}
    detected_sv_mask: int         # [1:5] u32LE; bit n -> GPS PRN n+1
    num_entries: int              # u32LE at [5] (v1) / [9] (v2)
    entries: list[RapidSearchEntry] = field(default_factory=list)
    detected_sv_mask_hi: int | None = None   # [5:9] u32LE, v0x02 only; raw

    @property
    def detected_prns(self) -> list[int]:
        return [i + 1 for i in range(32) if self.detected_sv_mask >> i & 1]

    @property
    def keyed_sv_ids(self) -> list[int]:
        """sv_ids of the FLAG_KEYED entries, in queue order."""
        return [e.sv_id for e in self.entries if e.entry_flags == FLAG_KEYED]

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'type': 'Diag0x145E',
            'log_time': self.log_time,
            'version': self.version,
            'detected_sv_mask': self.detected_sv_mask,
            'detected_prns': self.detected_prns,
            'num_entries': self.num_entries,
            'keyed_sv_ids': self.keyed_sv_ids,
            'entries': [e.to_dict() for e in self.entries],
        }
        if self.detected_sv_mask_hi is not None:
            d['detected_sv_mask_hi'] = self.detected_sv_mask_hi
        return d


@register(
    0x145E, domain="gnss",
    name="0x145E",
    description=(
        "LOG_CGPS_ME_RAPID_SEARCH_REPORT_C — GPS rapid-search queue snapshot, "
        "emitted per declared detection: cumulative detected-PRN mask + the "
        "remaining queue (sv_id, raw flags, raw sort key); v0x01/v0x02. "
        "In-capture 0x148A/0x1526-grounded."
    ),
    version=2,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE, 13 records / 2 captures: MC7455 MDM9x30 (4, v0x01) + "
        "EG95-NA MDM9607 (9, v0x02). Header = u32 detected-SV "
        "mask @1 (+ raw u32 @5 on v0x02) + u32 num_entries; body = 4-B entries "
        "(sv_id, flags, u16 sort key). No F3, 0x60 events or QCSuper/SCAT "
        "output on either capture. Grounded on co-emitted logs in stream order: each new mask bit "
        "is promoted Unknown->KnownVisible+Dedicated in the next 0x148A GPS record "
        "and has its first valid 0x1526 task-1 (verify) C/N0 4..15 records earlier, "
        "for 12/13. The 13th (MC7455 PRN 16) is a false alarm: later verifies all "
        "fail and 0x148A marks it KnownNotVisible."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    # Every byte is exposed: version, detected_sv_mask, num_entries, sv_id
    # (grounded) + entry_flags, order_key, detected_sv_mask_hi (named for
    # position/role only, values raw).
    fields_parsed=7,
    fields_identified=7,
    field_invariants={"version": {"enum": list(_KNOWN_VERSIONS)}},
)
def parse_0x145e(log_time: int, data: bytes) -> Diag0x145E | None:
    """Parse a 0x145E record. Returns None on an unknown version or a length
    that disagrees with the record's own ``num_entries``, so a new layout
    shows up as a parse miss rather than a wrong decode."""
    if len(data) < 2:
        return None
    version = data[0]
    layout = _LAYOUT.get(version)
    if layout is None:
        return None
    header_size, n_off = layout
    if len(data) < header_size:
        return None
    num_entries = unpack_from("<I", data, n_off)[0]
    if len(data) != header_size + num_entries * _ENTRY_SIZE:
        return None
    entries = [
        RapidSearchEntry(
            sv_id=data[o],
            entry_flags=data[o + 1],
            order_key=unpack_from("<H", data, o + 2)[0],
        )
        for o in range(header_size, len(data), _ENTRY_SIZE)
    ]
    return Diag0x145E(
        log_time=log_time,
        version=version,
        detected_sv_mask=unpack_from("<I", data, 1)[0],
        num_entries=num_entries,
        entries=entries,
        detected_sv_mask_hi=unpack_from("<I", data, 5)[0] if version == 0x02 else None,
    )
