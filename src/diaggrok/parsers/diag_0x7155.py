"""0x7155 = LOG_UMTS_NAS_HPLMN_SEARCH_START — cross-vendor parser.

**A NAS PLMN-search marker, not a GNSS event.** On LM960 boot captures
0x7155 co-fires with GNSS startup, but the firmware's own F3 prints place
it in NAS:

  In EM7565 F3 captures (F3 fully resolved), **every** 0x7155 emission
  (3 records / 2 captures) fires ~750-920 ts64 ticks *before* a coherent
  PLMN-search burst — ``reg_state.c "HPLMN Search Timer expired"`` →
  ``emm_reg_handler.c "PLMN_SEARCH_REQ"`` → ``lte_rrc_plmn_search.c
  "Processing PLMN search request / Starting Automatic search"`` →
  ``mm_multimode_handler.c "Setting mm_plmn_search_in_progress to 1"`` —
  with **zero** GNSS-engine F3 (no mgp/cgps/pdsm/sv) anywhere in the
  window.

This matches the canonical name ``LOG_UMTS_NAS_HPLMN_SEARCH_START`` and the
non-GNSS capture contexts (manual PLMN scan, AT+COPS, surveys). 0x7155 is a
**NAS HPLMN/PLMN-search-start marker**. The LM960 co-firing with GNSS
startup is explained by boot triggering both GNSS startup *and* network
re-registration (PLMN search) in the same window. (0x7160 is the one
genuinely GNSS-flavored member of that co-firing group — it carries $PQWP
NMEA.)

The per-slot 4-byte records are a search/registration state snapshot, not
GNSS receiver channels.

## Cross-vendor record content (7 chipsets, 4 vendors)

Captured during boot / warm-restart / manual-PLMN-scan / COPS scenarios.
The corpus holds **N=9 records across 7 chipsets and 4 vendors**:

| Chipset                    | Vendor  | byte[0] | bytes[1..8]                   |
|----------------------------|---------|--------:|-------------------------------|
| LM960 SDX20                | Telit   | 0x02    | ``ff ff ff 02 13 01 84 01``   |
| MC7455 MDM9x30             | Sierra  | 0x02    | ``13 00 10 02 13 00 10 01``   |
| SIM7600NA-H MDM9607        | SIMCom  | 0x01    | ``13 00 10 02 ff ff ff ff``   |
| EM7565 MDM9x50             | Sierra  | 0x01    | ``13 ...``  (num_slots=1)     |
| EM9291 SDX65               | Sierra  | 0x02    | ``13 ...``  (num_slots=2)     |
| MC7411 (survey)            | Sierra  | 0x01    | ``13 ...``  (num_slots=1)     |
| RG520N-NA (survey)         | Quectel | 0x02    | ``13 ...``  (num_slots=2)     |

After bytes [1..(4*byte[0])] the buffer is 0xff-filled to the 81-byte
total — uninitialized storage rather than zero-padding.

**num_slots gate validated at N=9:** byte[0] takes only {0x01, 0x02} across
all 9 records / 7 chipsets — the ``field_invariants={"num_slots": {"enum":
[1, 2]}}`` gate holds, and every record parses cleanly (verified
MC7411/RG520N/EM9291 through ``parse_0x7155``). byte[0] is a slot-count
geometry discriminator, not a version byte.

## Structure: byte[0] = slot count + N × 4-byte slot table

The data fits cleanly under the slot-table hypothesis:

```
off    type   name             notes
0      u8     num_slots        1 (SIMCom) or 2 (Telit, Sierra) — also
                               doubles as the "sub_type" discriminator
1+4i   4B     slots[i]         per-slot 4-byte record (i in 0..num_slots-1)
                               last byte of slot is a per-slot index
                               (slot 0 ends in 0x02, slot 1 ends in 0x01
                               on Telit + Sierra)
1+4N   ...    fill             0xff fill to total length 81B
```

Each slot's first 3 bytes carry per-chipset configuration data (Sierra
+ SIMCom share ``13 00 10`` on slot 0; Telit's slot 0 is mostly 0xff
fill, suggesting an LM960-firmware-specific edge case or deliberate
"empty slot" semantics).  Slot trailer byte cycles ``02 → 01`` across
the two-slot records, behaving like a slot-position index.

## Not a static template

The LM960 byte content is identical across its warm-restart and boot+GNSS
captures, but MC7455 and SIM7600 records carry the same 81-byte envelope
with different bytes per chipset family. This is a per-slot state snapshot
(search/registration state, per the F3 evidence above), not a constant.

## Open RE questions

- What is the ``13 00 10`` constant?  (vendor-stable cross-Sierra/SIMCom,
  absent on Telit — a shared MDM9x30/MDM9607 firmware-base default that
  LM960's separately-derived SDX20 image doesn't carry.  Given the
  HPLMN-search grounding, likely a PLMN-list / search-scope field.)
- Why does LM960 emit slot 0 as mostly-fill?  Could indicate an "empty"
  slot carrying only the trailer index byte, or a search state where
  slot 0 of the snapshot was unset.
- Are slots strictly 4 bytes everywhere, or is the stride variable?
  (need a 3+ slot capture to discriminate)
- Do the per-slot bytes correlate with the EHPLMN/RPLMN MCC/MNC the
  co-temporal ``lte_rrc_plmn_search.c`` F3 prints?  (the cleanest next
  lever, since an F3-bearing capture is known to emit 0x7155)

## First-byte gate

``num_slots`` at byte[0] is a geometry count, not a version byte. The fixed
81-byte payload size is a plausible envelope for a hypothetical future
firmware that re-uses byte 0 as a version (1-5 range), shrinks per-slot
encoding, and emits 81 bytes total — a loose ``0 <= num_slots <=
_MAX_SLOTS`` gate would happily mis-decode such a record.

The cross-vendor corpus shows a closed enum ``num_slots in {1, 2}`` — 1 on
SIMCom, 2 on Telit + Sierra — so the parser enforces:

  - **Layer-1 (parser body):** ``if num_slots not in _OBSERVED_NUM_SLOTS:
    return None`` (hard rejection, no partial record with ``slots=[]``).
  - **Layer-2 (@register):** ``field_invariants={"num_slots":
    {"enum": [1, 2]}}`` for registry.check_invariants() enforcement.

Any future capture with a different ``num_slots`` value surfaces as a
no-parser miss instead of being silently mis-decoded as an extreme-
num_slots state snapshot.

Log name: LOG_UMTS_NAS_HPLMN_SEARCH_START
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from diaggrok.registry import register


_LOG_CODE = 0x7155
_PAYLOAD_SIZE = 81
_SLOT_SIZE = 4
_FILL_BYTE = 0xFF
# Observed sub_type values across the LM960 / MC7455 / SIM7600 corpus.
# Higher values are theoretically possible but unobserved; the cap is the
# maximum that fits in the 80-byte slot
# region (80/4 = 20).
_MAX_SLOTS = (_PAYLOAD_SIZE - 1) // _SLOT_SIZE
# First-byte gate — closed cross-vendor enum.
# 1 on SIMCom MDM9607; 2 on Telit SDX20 + Sierra MDM9x30.  Any drift
# is rejected at layer-1 (parser body) and flagged at layer-2 (registry
# field_invariants) so a future firmware re-using byte 0 as a
# version slot surfaces as a no-parser miss rather than a mis-decoded
# extreme-num_slots record.
_OBSERVED_NUM_SLOTS: tuple[int, ...] = (1, 2)


@dataclass
class Diag0x7155:
    """Parsed 0x7155 (LOG_UMTS_NAS_HPLMN_SEARCH_START) slot-table record.

    F3-confirmed as an HPLMN/PLMN-search-start marker, NOT a GNSS event
    (see module docstring). The slot-table byte structure is unchanged.
    """
    log_time: int
    num_slots: int             # byte[0] — also the sub_type discriminator
    slots: list[bytes]         # num_slots × 4-byte slot bytes
    fill_bytes: int            # number of trailing 0xFF padding bytes
    payload_size: int
    body_raw: bytes

    @property
    def sub_type(self) -> int:
        """Alias for ``num_slots`` — the byte[0] discriminator that
        partitions chipset families (1 = SIMCom MDM9607; 2 = Telit
        SDX20 + Sierra MDM9x30).  Higher values theoretically possible
        but unobserved.
        """
        return self.num_slots

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x7155',
            'log_time': self.log_time,
            'num_slots': self.num_slots,
            'sub_type': self.num_slots,
            'slots': [s.hex() for s in self.slots],
            'fill_bytes': self.fill_bytes,
            'payload_size': self.payload_size,
        }


@register(
    _LOG_CODE, domain="nas",
    name="0x7155",
    description=(
        "LOG_UMTS_NAS_HPLMN_SEARCH_START — fixed 81B record "
        "decoded as a slot-table: byte[0] = num_slots, followed by N × "
        "4-byte slot records, 0xff fill to 81B.  Cross-vendor: 1 slot "
        "on SIMCom MDM9607, 2 slots on Telit SDX20 + Sierra MDM9x30.  "
        "F3-confirmed to fire ~750-920 ticks before a PLMN_SEARCH_REQ "
        "burst (EM7565 F3 captures); not a GNSS-engine-start event."
    ),
    version=2,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE from a 3-chipset corpus: LM960 SDX20 (Telit), "
        "MC7455 MDM9x30 (Sierra), SIM7600NA-H MDM9607 (SIMCom), extended to "
        "9 records / 7 chipsets / 4 vendors. Not a static template — same "
        "81B envelope but byte content differs per chipset family.  "
        "Semantic role F3-grounded: co-temporal with HPLMN/PLMN-search start "
        "(EM7565 F3 captures, 3/3 records), not a GNSS-lifecycle event."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_parsed=4,       # num_slots + slots + fill_bytes + payload_size
    fields_identified=4,
    # Layer-2 first-byte gate:
    # ``num_slots`` is observed only as 1 (SIMCom MDM9607) or 2
    # (Telit SDX20 + Sierra MDM9x30) across the cross-vendor corpus.
    # The layer-1 guard below rejects anything else; this declaration
    # surfaces drift via registry.check_invariants() in case the
    # parser-body gate is ever bypassed.
    field_invariants={"num_slots": {"enum": list(_OBSERVED_NUM_SLOTS)}},
    # RE-evidenced version-less: parser names byte 0 `num_slots`; corpus byte0 spans 2 value(s) over 22 records.
    version_less=True,
)
def parse_0x7155(log_time: int, data: bytes) -> Diag0x7155 | None:
    """Parse a 0x7155 record (fixed 81 bytes).

    Returns None on length mismatch — the record family is strictly
    81 bytes across all observed chipsets, so any other size signals
    a different family or corruption.

    Layer-1 byte-0 gate: also returns None if ``num_slots`` (byte[0]) is
    outside the closed cross-vendor enum ``_OBSERVED_NUM_SLOTS = (1, 2)``.
    ``num_slots = data[0]`` is read as a geometry count, and the 81-byte
    envelope is a plausible size for a future firmware re-using byte 0 as
    a version byte (the usual DIAG convention).  Hard rejection here,
    plus the layer-2 ``field_invariants`` enum on the @register call,
    ensures any drift surfaces as a no-parser miss rather than a
    silently-mis-decoded extreme-num_slots state snapshot (no partial
    record with ``slots=[]`` for out-of-range counts).
    """
    if len(data) != _PAYLOAD_SIZE:
        return None

    num_slots = data[0]
    if num_slots not in _OBSERVED_NUM_SLOTS:
        return None

    slot_region_end = 1 + num_slots * _SLOT_SIZE
    slots = [
        data[1 + i * _SLOT_SIZE:1 + (i + 1) * _SLOT_SIZE]
        for i in range(num_slots)
    ]
    # Verify trailing fill is all 0xff — sanity check, no failure
    fill_region = data[slot_region_end:]
    fill_bytes = sum(1 for b in fill_region if b == _FILL_BYTE)

    return Diag0x7155(
        log_time=log_time,
        num_slots=num_slots,
        slots=slots,
        fill_bytes=fill_bytes,
        payload_size=_PAYLOAD_SIZE,
        body_raw=data,
    )
