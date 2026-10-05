"""0x1885 — GNSS measurement/status (variable size: 35/36/40/42/44/47/51/54B).

F3-grounded: the record is emitted from **SLIM** (the Sensor/Location
Interface Manager of the location stack). 98 % of records co-fire (≤ 1 ms)
with ``slim_*`` / ``loc_client*`` prints, and the u32 @[2:6] equals SLIM's
current timetick printed at the same instant:
``slim_core.c "[SLIM] Next timeout event: %u, now=%u"`` arg1 and
``slim_core.c "[SLIM] Processing log timer event: param=%u time=%u"`` arg1 (the
log timer that commits the record), plus ``mbm_rbtree.c "… at Timetick: %u"`` —
≤ 1 ms, controls (+500 / +7000 ms) 0. Exposed as ``slim_time_ms``; the older
``counter_like`` (u16 @2) and ``aux_4`` (@4) are its low bytes (kept for
compatibility), and ``reserved_a`` [5] is its top byte (non-zero once the tick
passes 2^24 ms ≈ 4.7 h). ``sz47_prev_counter_ref`` [39:43] is therefore a
previous SLIM timetick.

Corpus coverage: 654 records across 34 captures on 7 chipsets — LM960
(SDX20), FN980 / RM500Q (SDX55), EG18-NA, MC7455 (MDM9230), EM9190 and
EG12-GT — plus a 163-record sz=54 family that adds Sierra EM9291.

Shared 10-byte header (invariant across all sampled records):
  [0]    u8 version = 0x01
  [1]    u8 reserved_1 = 0x00
  [2:4]  u16 LE counter_like (varies; 17-20 uniq per size)
  [4]    u8 aux_4 (small enum per size)
  [5:10] 5 bytes reserved_a = 0x0000000000 (all zero 87/87)

Size-variant tag at [10:14]: 4 bytes whose layout differs per size:
  sz=35: [10]=0x02 [11]=0x00 [12]=0x04 [13]=0x01 (rm500q SDX55 + SIM8202G-M2;
         9/9 records across 3 captures. [10]=0x01 is the sz=36 tag, not sz=35)
  sz=36: [10]=0x01 [11]=0x00 [12]=varies [13]∈{0,1} [14:16]=0x0000
         ([10]=0x01 on 23/23 records; no other size carries [10]=0x01)
  sz=40: [10]=0x00 [11]=0x0a [12]=0x02 [13]∈{0,1} [14:16]=0x0000
  sz=42: [10]=0x00 [11]=0x00 [12]=0xff [13]=0x00 (rm500q + eg18na so far)
  sz=44: [10]=0x00 [11]=0x02 [12]=0x02 [13]∈{1,2} [14:16]=0x0000
  sz=47: [10]=0x00 [11]∈{0,14} [12]=0x02 [13]=0x01 [14:16]=0x0000
  sz=51: [10]=0x02 [11]=0x01 [12]=0x02 [13]=0x00 [14:16]=0x0000
  sz=54: [10]=0x00 [11]=0x04 [12]∈{0x01,0xff} [13]∈{0,1,2} [14:16]=0x0000
         (163 records / 17 captures; variant-tag low byte [11]=0x04; seen on
          Sierra EM9291 (SDX65, SWIX65C). Header, variant_tag and reserved_a
          all conform to the shared model.)

sz=47 tail:
  Bytes [31:35] = 0xffffffff (sentinel "invalid_reference_ms"): 3/3 records ✓
  Bytes [35:39] u32 LE = 2 (subtype_tag): 3/3 records ✓
  Bytes [14:31] = 17B all-zero (mid-reserved): 3/3 records ✓
  Bytes [43:47] = 4B all-zero (trailing reserved): 3/3 records ✓
  Bytes [39:43] u32 LE — a previous-epoch reference, not an integrity echo
    of header [2:6]: 1/3 records match the header value exactly, 2/3 are
    exactly 1 less than the header counter. The tail counter is the
    previous measurement epoch's counter, equal to the header counter only
    when consecutive epochs share a counter value. Exposed both as the raw
    u32 (sz47_prev_counter_ref) and as a "matches header" bool
    (sz47_counter_echo_ok, kept for backward compatibility); consumers
    should prefer the u32 value and compute their own delta.

(✓ = holds on every record checked.)

sz=36 tail enum:
  Bytes [30:36] have a tri-modal 6-byte tail structure:
    Mode A (success):     [30]=sub_seq u8 ∈ {0,1,...,12,...}, [31]=0x02,
                          [32:36]=0x00000000
    Mode B (error -13):   [30:32]=0x0000, [32:36]=0xfffffff3
                          (i32 LE = -13; plausible GPS "not available")
    Mode C (rm500q -1):   [30:32]=0xffff (i16 LE = -1), [32:36]=0x00000000
                          (chipset-specific, observed only on rm500q SDX55;
                          plausible "no measurement available" with a
                          different sentinel encoding)
  Treat [30:36] as a 6-byte (sub_seq + status_code) tagged-union region.

Length gate: the payload size is the layout selector — there is no declared
length — so a size outside the attested families (35/36/40/42/44/47/51/54)
returns None (registry WARN) instead of a silent ``other_<n>`` record, and a
[10]=0x01 (sz=36 tag) record shorter than 36 B is a truncated sz=36, not a
sz=35, and returns None too.

This parser extracts the 10-byte header, the 4-byte variant_tag, the
size_family classification, and (for sz=47 only) the structured-tail
fields. The extension region [14:] is exposed raw.

Known gaps:
  * Per-byte decode of the sz=35/40/42/44/51 extension regions (sz=42 is
    seen on few chipsets so far).
  * Mode A/B/C status code semantics (needs correlation of [30:32]/[32:36]
    against AT/NMEA fix-quality state at the same timestamp, from paired-AT
    captures of GNSS startup/restart scenarios).

Log name: LOG_EVENT_MTP_FORMAT_STORE_STARTED
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


# Naming: older name tables list this code as
# LOG_EVENT_MTP_FORMAT_STORE_STARTED / RESERVED, which does not match the
# observed content. The payload is a GNSS measurement/status record emitted
# by SLIM (sz=36 Mode B = -13, plausibly "GPS not available").
# version=0x01 is a corpus-wide invariant for this code.

@dataclass
class Diag0x1885:
    """GNSS measurement/status (0x1885) — variable size (35/36/40/42/44/47/51/54B).

    10-byte shared header + size-variant dispatch tag + extension region.
    See module docstring above for field semantics and corpus evidence.
    """
    log_time: int
    version: int          # [0] = 0x01 (constant 89/89)
    reserved_1: int       # [1] = 0x00 (constant 89/89)
    counter_like: int     # [2:4] u16 LE
    aux_4: int            # [4] small enum
    reserved_a: bytes     # [5:10] 5B all-zero 89/89
    variant_tag: int      # [10:14] u32 LE — encodes size-variant family
    slim_time_ms: int     # [2:6] u32 LE — SLIM timetick (ms), F3-grounded
    size_family: str      # derived: sz35/sz36/sz40/sz42/sz44/sz47/sz51/sz54
    extension: bytes      # [14:] size-variant specific payload (pending RE)
    # sz=47-only structured-tail fields. Set to None on every other size
    # variant so downstream consumers can dispatch cleanly.
    sz47_sentinel_ref_ms: int | None     # sz=47 [31:35] — 0xffffffff "invalid"
    sz47_subtype_tag: int | None         # sz=47 [35:39] u32 LE = 2 (constant)
    # prev_counter_ref is the raw u32 LE at [39:43]: a "previous measurement
    # epoch counter" reference (header - {0,1}), not an integrity echo of
    # header [2:6]. The bool stays for backward compatibility.
    sz47_prev_counter_ref: int | None    # sz=47 [39:43] u32 LE — header[2:6] - {0,1}
    sz47_counter_echo_ok: bool | None    # sz=47 [39:43] == header [2:6] (deprecated; use sz47_prev_counter_ref)
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1885',
            'log_time': self.log_time,
            'version': self.version,
            'reserved_1': self.reserved_1,
            'counter_like': self.counter_like,
            'aux_4': self.aux_4,
            'slim_time_ms': self.slim_time_ms,
            'reserved_a_all_zero': self.reserved_a == b'\x00' * 5,
            'variant_tag': self.variant_tag,
            'size_family': self.size_family,
            'extension_bytes': len(self.extension),
            'sz47_sentinel_ref_ms': self.sz47_sentinel_ref_ms,
            'sz47_subtype_tag': self.sz47_subtype_tag,
            'sz47_prev_counter_ref': self.sz47_prev_counter_ref,
            'sz47_counter_echo_ok': self.sz47_counter_echo_ok,
            'payload_size': self.payload_size,
        }


_GNSS_1885_SIZE_FAMILY = {35: 'sz35', 36: 'sz36', 40: 'sz40', 42: 'sz42',
                          44: 'sz44', 47: 'sz47', 51: 'sz51', 54: 'sz54'}
# variant_tag byte [10] of the sz=36 family (23/23 records; no other size uses it).
_SZ36_TAG_10 = 0x01


@register(
    0x1885, domain="gnss",
    name="0x1885",
    description="SLIM location status (0x1885) — variable size (35..54B) shared header (slim_time_ms F3-grounded) + sz=47 structured tail",
    version=8,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE across 654 records / 34 captures on LM960 (SDX20), "
        "FN980 and RM500Q (SDX55), EG18-NA, MC7455 (MDM9230), EM9190 and "
        "EG12-GT, plus a 163-record sz=54 family on Sierra EM9291. F3-grounded: the record is emitted by SLIM — it "
        "co-fires (<=1 ms) with slim_*/loc_client* F3 on 98% of records, and "
        "u32 [2:6] equals SLIM's timetick (slim_core.c 'now=%u' / 'Processing "
        "log timer event … time=%u' arg1, <=1 ms, controls 0), exposed as "
        "slim_time_ms. The 10-byte shared header is fully named; 8 size "
        "variants (35/36/40/42/44/47/51/54 B) dispatch via variant_tag at "
        "[10:14]; version == 0x01 and reserved_1 == 0x00 are corpus-wide "
        "invariants. sz=47 structured tail: 0xffffffff sentinel at [31:35], "
        "u32 subtype_tag at [35:39], and [39:43] = header[2:6] or "
        "header[2:6]-1 — a previous-epoch counter (`sz47_prev_counter_ref`), "
        "not an integrity echo; `sz47_counter_echo_ok` (bool) is kept, "
        "deprecated. sz=36 carries a tri-modal status tail (Mode C, "
        "[30:32]=0xffff, seen only on RM500Q). Size is the only layout "
        "selector, so an unattested size, or a sz=36-tagged ([10]=0x01) "
        "payload shorter than 36 B, returns None (registry WARN). Gaps: the "
        "sz=35/40/42/44/51 extension regions and the Mode A/B/C status "
        "semantics."
    ),
    source_url="",
    issues=(),
    # Partial: 10-byte shared header + variant_tag + size_family +
    # extension metadata + 4 sz=47-specific fields are all named (13 fields);
    # the sz=47 extension is almost fully accounted for, but the
    # sz=35/36/40/42/44/51 extension regions are still opaque pending more
    # captures and Mode A/B/C status code RE.
    fields_identified=14,
    fields_parsed=13,
    field_invariants={
        # version + reserved_1 are corpus-wide invariants across 654 records /
        # 7 chipsets. The parser tolerates every attested size_family, so
        # size is NOT pinned here; only the byte-0 and byte-1 constants.

        "version": {"enum": [0x01]},
        "reserved_1": {"enum": [0x00]},
    },
)
def parse_0x1885(log_time: int, data: bytes) -> Diag0x1885 | None:
    if len(data) < 14:
        return None
    # Byte-0 version + byte-1 reserved-zero gate BEFORE any other byte
    # read, so the sz=47 branch never reads bytes [31:43] of a record whose
    # version is unvalidated. Corpus (654 records, 7 chipsets):
    # version == 0x01 and reserved_1 == 0x00 are corpus-wide invariants.
    if data[0] != 0x01 or data[1] != 0x00:
        return None
    # No declared length — the size selects the layout, so an
    # unattested size is undecodable (loud None), and a sz=36-tagged record
    # cut to 35 B must not masquerade as the sz=35 family.
    if len(data) not in _GNSS_1885_SIZE_FAMILY:
        return None
    if data[10] == _SZ36_TAG_10 and len(data) < 36:
        return None
    sz47_ref = None
    sz47_subtype = None
    sz47_prev_counter = None
    sz47_echo_ok = None
    if len(data) == 47:
        sz47_ref = unpack_from('<I', data, 31)[0]
        sz47_subtype = unpack_from('<I', data, 35)[0]
        sz47_prev_counter = unpack_from('<I', data, 39)[0]
        sz47_echo_ok = data[39:43] == data[2:6]
    return Diag0x1885(
        log_time=log_time,
        version=data[0],
        reserved_1=data[1],
        counter_like=unpack_from('<H', data, 2)[0],
        aux_4=data[4],
        reserved_a=bytes(data[5:10]),
        variant_tag=unpack_from('<I', data, 10)[0],
        slim_time_ms=unpack_from('<I', data, 2)[0],
        size_family=_GNSS_1885_SIZE_FAMILY[len(data)],
        extension=bytes(data[14:]),
        sz47_sentinel_ref_ms=sz47_ref,
        sz47_subtype_tag=sz47_subtype,
        sz47_prev_counter_ref=sz47_prev_counter,
        sz47_counter_echo_ok=sz47_echo_ok,
        payload_size=len(data),
    )
