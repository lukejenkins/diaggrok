"""0x18E8 — counter-array stats report: 16B header + N typed counter entries.

Every record is a 16-byte header followed by ``num_entries`` typed counter
entries. One-entry records dominate the corpus; the multi-entry 1624B/2504B
records expose the layout, which tiles EVERY record:

  Header (16 B):
    [0]      u8  version = 0x01 (100% corpus-wide)
    [1]      u8  num_entries — 1 on 32/40/64/72/88/280 B, 0x1a=26 on 1624 B,
                 0x2d=45 on 2504 B. It is an entry count, not a size-format
                 id (so [0:2] is not a u16 "version_magic" 0x0101/0x1a01/0x2d01).
    [2..7]   = 0 (padding)
    [8..15]  u64 LE timestamp — 19.2 MHz QTimer ticks. GROUNDED (below).
             It is one u64, not an `sfn` (u32 @8) + `component_id` (u32 @12)
             pair: a "rare 0x01 at +13" and a slowly rising "component index"
             are simply the high bytes of the clock.

  Entry (repeated num_entries times, 4-byte aligned):
    +0  u16 LE stat_id   — 0x03E8..0x042F (1000..1071) on u8-array entries,
                            0xFF00..0xFFF0 on u32-array entries
    +2  u8   num_elements - 1   (0x3f → 64, 0x1f → 32, 0x31 → 50, 0x27 → 40,
                            0x0f → 16, 0x09 → 10 elements)
    +3  u8   type: high nibble 0xA (100%), low nibble = element width in
                   bytes (0xa1 → u8 array, 0xa4 → u32 array)
    +4  num_elements × width bytes of LE counters, zero-padded to 4 bytes

  Record tail: zero padding to an 8-byte-aligned total size.

  The apparent per-size "body magic" at [17..19] is just the FIRST entry's
  descriptor bytes 1..3 (stat_id high byte + length + type). The 88B form
  carries 64 u8 counters, not 14 u32 bins — reading it as u32 bins produces
  spurious "0x8000000" values. Size does not identify the chipset: 280B is
  emitted by every family in the corpus, 88B by SDX62/SDX65/SDX72 (EM9291,
  T99W640, CFW-3212, RM520N), and 1624B/2504B by T99W175 (SDX55) and M3100
  as well as RM520N.

Tiling evidence (stratified sample, 47,413 records / 45 captures / 26 modem
families — every size class, including the 32/40/64/72 B T99W640 forms,
~19k records corpus-wide): 100% of records tile exactly under the entry
rule, with 0 overruns; the tail residual is 0 or 4 bytes and always zero —
the 8-byte alignment pad.

Timestamp grounding (in-capture oracle = the DIAG log-header clock): on an
18,094-record T99W640 survey capture, the per-pair slope
Δpayload_u64 / Δheader_ts clusters at 0.36620–0.36623 (5,378 pairs), vs
19.2 MHz / 52.4288 MHz = 0.366211 expected. 9 backward steps = modem
reboots inside the capture (the QTimer restarts).

F3: no F3 site labels any stat_id or counter (also N/A on an RXM-G1). What
F3 DOES show is WHEN it is emitted: in the same T99W640 capture (5.4 M F3
records), sites within ±0.2 ms of a 0x18E8 record are dominated by
sleep/wake prints — `tcxomgr_rot_client_handling.c:805` 96%,
`slpc.c:1785`/`:1866` (VSTMR_READ / SLAM wake) 82%, `fws_sleep.c:190`
("FWS resume command") 82%, `fws_sleep.c:240` ("FWS sleep request") 73% —
against a 1.3% baseline. So the report is flushed on the modem's sleep/wake
cycle. QCSuper and SCAT do not decode 0x18E8.

Semantics still OPEN: what each stat_id counts. The "LTE ML1 DL Stats" title
(and the LOG_LTE_ML1_DL_STATS constant) is a working name with no external
support — name tables list the code as RESERVED. At the whole-record level,
histogram_sum rises under DL traffic relative to idle on an RM520N-GL.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_LTE_ML1_DL_STATS
from diaggrok.registry import register

_HEADER_LEN = 16
_DESC_LEN = 4
_TYPE_TAG = 0xA           # high nibble of the entry type byte (100% corpus)
_WIDTH_FMT = {1: 'B', 2: 'H', 4: 'I', 8: 'Q'}


@dataclass
class Diag0x18E8Entry:
    stat_id: int          # u16 LE @ +0
    num_elements: int     # u8 @ +2, stored as count-1
    elem_width: int       # low nibble of u8 @ +3 (bytes per element)
    values: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            'stat_id': self.stat_id,
            'num_elements': self.num_elements,
            'elem_width': self.elem_width,
            'values': self.values,
            'values_sum': sum(self.values),
        }


@dataclass
class Diag0x18E8:
    log_time: int
    version: int                  # u8 @ 0
    num_entries: int              # u8 @ 1
    timestamp: int                # u64 LE @ 8 — 19.2 MHz QTimer ticks
    entries: list[Diag0x18E8Entry] = field(default_factory=list)
    histogram_sum: int = 0        # sum over every entry's counters

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x18E8',
            'log_time': self.log_time,
            'version': self.version,
            'num_entries': self.num_entries,
            'timestamp': self.timestamp,
            'entries': [e.to_dict() for e in self.entries],
            'histogram_sum': self.histogram_sum,
        }


# Validation note: no AT/QMI command returns these counters, so the fields
# can only be grounded by CORRELATION of entries[].values (keyed by
# entries[].stat_id) with observable DL activity, not by value equality.

@register(LOG_LTE_ML1_DL_STATS,
    name="0x18E8",
    description=(
        "Counter-array stats report — 16B header (u8 version=1, u8 "
        "num_entries, u64 19.2 MHz QTimer timestamp) + num_entries typed "
        "entries (u16 stat_id, u8 count-1, u8 type 0xA<width>, LE counter "
        "array padded to 4B), record padded to 8B. One-entry records are "
        "32/40/64/72/88/280 B; 26/45-entry records are 1624/2504 B."
    ),
    version=8,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE. byte1 is an entry count, not a format id; [8..15] is "
        "one u64 19.2 MHz QTimer timestamp (slope vs the DIAG header clock "
        "0.36621 = 19.2/52.4288); the body is num_entries TLV-like entries "
        "(u16 stat_id, u8 count-1, u8 0xA<width>, counters padded to 4B), "
        "record padded to 8B. Tiling verified on a 47,413-record / 45-capture "
        "/ 26-family stratified sample (0 overruns), including the 32/40/64/72 "
        "B T99W640 forms (~19k records). Size does not identify the chipset "
        "(280B on every family; 88B on SDX62/65/72). A payload that ends inside "
        "the last entry's 4-byte pad or before the 8-byte-aligned record size "
        "is truncated and returns None (registry WARN). F3 shows the record is "
        "flushed on the sleep/wake cycle but labels no counter; histogram_sum "
        "rises under DL vs idle on an RM520N-GL. Per-stat_id semantics open."
    ),
    source_url="https://github.com/lukejenkins",
    issues=(),
    primary_issue=None,
    # version + num_entries + timestamp + entries(stat_id, num_elements,
    # elem_width, values) + histogram_sum
    fields_identified=8,
    fields_parsed=8,
    supported_versions=[0x01],
    field_invariants={
        'version': {'enum': [0x01]},
    },
)
def parse_0x18e8(log_time: int, data: bytes) -> Diag0x18E8 | None:
    """Parse 0x18E8 — header + num_entries typed counter-array entries.

    Returns None for: short payload, version != 1, non-zero [2..7] padding,
    num_entries == 0, an entry whose type tag nibble != 0xA or whose width is
    not 1/2/4/8, an entry (incl. its 4-byte pad) overrunning the payload, a
    payload shorter than the 8-byte-aligned record size (truncated), or
    a tail that is not a < 8-byte all-zero alignment pad.
    """
    size = len(data)
    if size < _HEADER_LEN + _DESC_LEN:
        return None
    version = data[0]
    if version != 0x01:
        return None
    if any(data[2:8]):
        return None
    num_entries = data[1]
    if num_entries == 0:
        return None
    timestamp = unpack_from('<Q', data, 8)[0]

    entries: list[Diag0x18E8Entry] = []
    pos = _HEADER_LEN
    for _ in range(num_entries):
        if pos + _DESC_LEN > size:
            return None
        stat_id = unpack_from('<H', data, pos)[0]
        num_elements = data[pos + 2] + 1
        type_byte = data[pos + 3]
        width = type_byte & 0x0F
        if type_byte >> 4 != _TYPE_TAG or width not in _WIDTH_FMT:
            return None
        body_len = num_elements * width
        start = pos + _DESC_LEN
        if start + body_len > size:
            return None
        values = list(unpack_from(f'<{num_elements}{_WIDTH_FMT[width]}', data, start))
        entries.append(Diag0x18E8Entry(
            stat_id=stat_id,
            num_elements=num_elements,
            elem_width=width,
            values=values,
        ))
        pos = start + (body_len + 3) // 4 * 4

    # The last entry's 4-byte pad and the record's 8-byte alignment pad are
    # part of the layout (100% of the tiling sample). A payload that ends
    # before them is truncated (pos > size would otherwise give an empty
    # tail and silently absorb a lost byte).

    if pos > size or size < (pos + 7) // 8 * 8:
        return None
    tail = data[pos:]
    if len(tail) >= 8 or any(tail):
        return None

    return Diag0x18E8(
        log_time=log_time,
        version=version,
        num_entries=num_entries,
        timestamp=timestamp,
        entries=entries,
        histogram_sum=sum(sum(e.values) for e in entries),
    )
