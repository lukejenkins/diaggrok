"""0x1850 — IPA data-path log-dump record.

**Subsystem: IPA (the modem's IP Accelerator), F3-grounded per version.**
Not LTE ML1 and not LTE NAS. Emitted inside the
``ipa_log.c`` stats dump that fires on every IPA UL/DL producer-pipe start or
stop (``ipa_ctl_clk.c``) and on IPA task shutdown. Evidence on each version's own records:

    v2  EG18-NA   2/2  +0.018 ms after ipa_ctl_task shutdown ("UL/DL/Prod
                      shutdown done!", ipa_ctl_clk shutdown gate request)
    v3  LV55     67/67 ipa_log.c:2468 IPA_UL_PRIORITY_PKTS_STATS at +0.044 ms
                      (67 prints total, all on a 0x1850; 67x over shifted
                      background), 35 pipe-stop + 32 pipe-start
    v3  SDX62/VZ  3/3  ipa_ctl_clk.c:1368 at -0.04 ms + ipa_log.c:2963
    v3  T99W175 14/14  IPA filter-rule programming at a fixed -198.78 ms
    v4  EM9291    8/8  ipa_log.c:2967 at +0.091 ms (4,203 lte_* prints: none enriched)
    v5  R562L5    8/8  ipa_log.c:2969 IPA_UL_PRIORITY_PKTS_STATS at +0.090 ms and
                      ipa_log.c:2991 IPA_UL_LL_PRIORITY_PKTS_STATS at +0.108 ms
                      (8 prints each, all on a 0x1850; shifted null 0.00);
                      5 at ipa_ctl_clk.c:1386 "DL producer pipe stopped",
                      3 at ipa_ctl_clk.c:1429 "All UL producer pipes started"
    v6  T99W640  18/18 ipa_log.c:3318 at +0.066 ms, ipa_ctl_clk.c:1465 at -0.027 ms
    v1  MC7455   F3 and 0x60 absent in every bearing capture

The burst also carries the canonically named IPA stats family
(0x1C6E/0x1C6F/0x1C71 LOG_IPA_*_STATS, 0x1D8D LOG_IPA_LOW_LAT_LOG) on
v3/v4/v6. On v1/v2 the record instead shares an exact ts64 with 0x184F,
0x1851, 0x1852, 0x1962 and 0x1963. An apparent LTE ML1 association appears
only with a +-200-tick window in a capture holding ~908k ML1 prints
(coincidental hits). It is not a NAS log either: 0/78 same-capture EMM PDUs (0xB0EC/0xB0ED) occur
inside any payload, event 1966 EVENT_LTE_EMM_OTA_INCOMING_MSG never lands
within +-2 ms of a record, and C-V2X RSUs with zero NAS traffic emit hundreds.

Layout (measured across 1,850 records / 31 (version,size) classes)::

    off  size  field
      0   u8   version        {1,2,3,4,5,6}; Layer-1 gate
      1   u32  counter        v1/v2/v3   (pad[3] @5 = 0)
      4   u32  counter        v4/v5/v6   (pad[3] @1 = 0)
      8        4 x sub-table: u16 total, u16 count_a, u16 count_b, u16 aux,
               then total x entry (20 B on v2/v3, 26 B on v4/v5/v6)
      ...      tail           remainder (v2/v3 5192 B fixed buffer only)

``total == count_a + count_b`` holds on every sub-table of 1,844/1,850 records.
The 6 exceptions are the 4 v1 records (different body) and 2 RIS-9260 v2
fragments (the RIS-9260 carries the same MDM9150 modem, not a separate device) that still parse 4 tables. The variable sizes of v3 (1160..1640,
20 B steps), v4 (1600..1912, 26 B steps) and v6 (1444..2302) are one grammar
with varying table counts, not separate formats. v4/v5/v6 and v3-variable
records end exactly after table 4. v2/v3 5192 B is a fixed buffer with a tail.

v5: 8 records, all 2796 B, from one Orbic R562L5 (SDX62) F3-armed capture. They have the v4/v6 header
(3 zero pad bytes, counter u32 @4 at ~1171.9/s) and 26 B is the only entry
stride at which all 8 walk 4 tables with total == count_a + count_b and end
exactly at 2796 B. Note the SDX62 RM520N-GL emits v3 here, so the version
tracks the IPA build, not the chipset family.

The counter increases between records and resets at boot. It runs at about 1024/s on
v1/v2 and 1171.9/s on v3/v4/v6. CANDIDATE only: 32.768 kHz/32 and
19.2 MHz/2^14, timer-shaped, units unconfirmed. ``entries[].key`` is the
u16 at entry+0 (small ID-shaped integers in sorted runs). F3 is SILENT on
what the four tables hold, so count_a/count_b/aux and the entry bytes stay
offset-named/raw. v1 (MDM9x30 MC7455) has a different body (176-byte
repeating blocks / s16 pairs) and is exposed header + raw only.
Truncation: a v2/v3/v4/v6 record whose 4-table walk
overruns the payload (or breaks ``total == count_a + count_b``), a v2/v3
tail-bearing record shorter than the 5192 B fixed buffer, and a v1 record
shorter than its 2072 B buffer all return None (registry WARN) instead of a
record with ``tables=None`` / a short tail. This makes the 2 RIS-9260 v2
fragments (3048 / 4448 B) decline loudly.

``hdr_words`` (u16 @8..18) is kept for compatibility. It overlaps table 1's
header and first entry key.

Log name: LOG_EVENTS_DS_GPRS_TBF_RELEASE
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

_HEADER = 20  # bytes covered by version + header_raw + hdr_words[0:6]
_ENTRY_SIZE = {2: 20, 3: 20, 4: 26, 5: 26, 6: 26}
_N_TABLES = 4
# Fixed-buffer sizes: v2/v3 records that carry a tail after table 4 are
# the 5192 B fixed buffer; v1 is a 2072 B opaque buffer (6/6 corpus records).
# A shorter record of either kind is truncated and returns None (registry WARN).
_V23_BUFFER_LEN = 5192
_V1_BUFFER_LEN = 2072


def _walk_tables(data: bytes, entry_size: int):
    """Walk the 4 sub-tables at offset 8. Return (tables, end) or (None, 8)
    when the ``total == count_a + count_b`` grammar does not hold."""
    tables = []
    off = 8
    for _ in range(_N_TABLES):
        if off + 8 > len(data):
            return None, 8
        total, count_a, count_b, aux = unpack_from("<4H", data, off)
        body = off + 8
        if total != count_a + count_b or body + total * entry_size > len(data):
            return None, 8
        entries = [
            {"key": unpack_from("<H", data, e)[0], "raw": data[e:e + entry_size]}
            for e in range(body, body + total * entry_size, entry_size)
        ]
        tables.append({"total": total, "count_a": count_a, "count_b": count_b,
                       "aux": aux, "entries": entries})
        off = body + total * entry_size
    return tables, off


@dataclass
class Diag0x1850:
    """0x1850 — IPA data-path log dump: version + counter + 4 sub-tables + tail."""
    log_time: int
    version: int
    header_raw: bytes
    hdr_words: tuple[int, ...]
    body_raw: bytes
    payload_size: int
    counter: int
    entry_size: int | None
    tables: list[dict[str, Any]] | None
    tail_raw: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x1850",
            "log_time": self.log_time,
            "version": self.version,
            "counter": self.counter,
            "entry_size": self.entry_size,
            "tables": self.tables,
            "tail_raw": self.tail_raw,
            "header_raw": self.header_raw,
            "hdr_words": list(self.hdr_words),
            "body_raw": self.body_raw,
            "payload_size": self.payload_size,
        }


@register(
    0x1850,
    name="0x1850",
    description="0x1850 — IPA data-path log dump: version + counter + 4 sub-tables (total=a+b; 20B/26B entries) + tail (v∈{1,2,3,4,5,6}; F3-grounded IPA per version, not LTE ML1 / not NAS)",
    version=6,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail="Clean-room RE across MDM9x30/MDM9250/SDX20/SDX55/SDX62/SDX65/SDX72 captures (1,850 records, 31 (version,size) classes), F3-grounded per version against ipa_log.c / ipa_ctl_clk.c / ipa_ctl_task.c sites. Versions 1-6 decoded; v5 is the 2796 B Orbic R562L5 (SDX62) form with the v4/v6 header and 26 B entries (F3-grounded 8/8, ipa_log.c:2969/2991). A record whose 4-table walk overruns the payload, a v2/v3 tail-bearing record shorter than the 5192 B fixed buffer, or a v1 record shorter than its 2072 B buffer returns None. Table contents and the counter clock remain unconfirmed.",
    issues=(),
    fields_identified=6,
    fields_parsed=6,
    field_invariants={"version": {"enum": [1, 2, 3, 4, 5, 6]}},
)
def parse_0x1850(log_time: int, data: bytes) -> Diag0x1850 | None:
    if len(data) < _HEADER:
        return None
    version = data[0]
    if version not in (1, 2, 3, 4, 5, 6):
        return None
    hdr_words = tuple(unpack_from("<H", data, off)[0] for off in range(8, 20, 2))
    counter = unpack_from("<I", data, 4 if version in (4, 5, 6) else 1)[0]
    entry_size = _ENTRY_SIZE.get(version)
    tables, end = _walk_tables(data, entry_size) if entry_size else (None, 8)
    if version == 1:
        if len(data) < _V1_BUFFER_LEN:
            return None  # truncated v1 buffer
    elif tables is None:
        return None  # table walk overran / broke total=a+b: truncated
    elif version in (2, 3) and end < len(data) < _V23_BUFFER_LEN:
        return None  # tail-bearing fixed buffer cut short
    return Diag0x1850(
        log_time=log_time,
        version=version,
        header_raw=data[1:8],
        hdr_words=hdr_words,
        body_raw=data[_HEADER:],
        payload_size=len(data),
        counter=counter,
        entry_size=entry_size,
        tables=tables,
        tail_raw=data[end:] if tables is not None else b"",
    )
