"""GNSS Global Time Services / GTS events (0x18AE) — compact + full variants.

This is NOT an "LTE ML1 Measurement Report" and carries no per-cell
RSRP/RSRQ, despite older descriptions of the code. The item-type name is
``LOG_GNSS_GLOBAL_TIME_SERVICES_EVENTS`` (GTS = Global Time Services), and F3
ground truth confirms it:

  - An MC7411 survey capture that emits 0x18AE (4,315×) also runs the GTS
    subsystem — F3 sites ``gts.c`` / ``lte_ml1_pos_gts.c`` fire over the
    *identical* diag-tick window as the records (83% of 0x18AE records within
    ~1s of a GTS F3 print, 100% within ~5s).
  - v0x04 (LM960 SDX20): the identity holds on the LM960's *own* F3. One
    survey capture carries 1,154,318 v0x04 records AND 219,785 GTS-subsystem
    F3 prints (``gts.c`` ×210,041, ``gts_log.c`` / ``gts_api.c`` ×4,536 each,
    ``lte_ml1_pos_gts.c`` ×672; no non-GTS prints in the set). 84.32% of
    records sit within 0.5s of a GTS print (flat to 5s — co-emission is
    bimodal: tight-lock vs a >5s GTS-silent idle gap where the SysFN counter
    free-runs), replicating the MC7411 83%@1s on SDX20. ``gts.c:502`` prints
    the ``sfn_counter`` field verbatim:
    ``GTS: OstmrDiff SysFN ( … ) after latch ( … ). Accept.``
  - GTS F3 content is unambiguous: ``GTS: BestGPSTime - No valid GPS Time``,
    ``Capturing gts data`` / ``Sending GPS GTS data``, ``Processing LTE Time
    Msg``, and ``GTS: OstmrDiff SysFN ( … ) after latch ( … )`` — GTS latches
    the LTE **SysFN** to translate cellular time into GPS time.
  - v0x05 (MDM9250 C-V2X modem): the identity transfers cross-silicon. v0x05
    is the structural twin of v0x04. A 41.3-min drive capture carries
    2,170,942 v0x05 records (100% of 0x18AE) AND 1,215,845 GTS-subsystem F3
    prints (``gts.c`` dominant + ``gts_drsync.c`` / ``gts_log.c`` /
    ``gts_api.c``; no non-GTS prints). GTS runs at 486.6 prints/s (C-V2X
    needs continuous GPS-time sync), so co-emission is coincidental at any
    window >=20ms (null=100%); the discriminating signal is at tight windows
    — 5ms: 91.7% real vs 64.8% null, 2ms: 71.3% vs 31.6% null. The 432B
    v0x05 full form decodes to the identical 20-slot array (counter_a
    +75/slot, counter_b +2/slot), confirming byte-level format transfer.
  - v0x08 (SDX62/SDX72): the strongest F3 grounding on this code — not
    temporal co-emission but a **byte-exact content match**. v0x08 is the
    SDX62/SDX72 generation (RM520N-GL, EM9291, Casa CFW-3212, T99W640). Its
    dominant 75-byte form is emitted **1:1** with the ``gts.c:6842`` F3
    print, which renders the record's own fields::

        GetGtsTime P 1 Tsrc 1 W 2423 Ms 334283943 B 0.234736 Tu 0.001372
                   U 0x2755a5dc7b FC 1 8802675

    Zipping the two streams in capture order matches **100%** on every field
    that carries discriminating variance, on two independent vendors:
    RM520N-GL 9,965/9,965 and Casa CFW-3212 1,224/1,224. See the
    ``source_detail`` for the per-field evidence.
  - This explains why 0x18AE fires in BOTH an LTE camp with no GNSS fix and
    a GNSS-only capture (dominant carrier, 777×): time services run
    continuously regardless of fix. A per-cell measurement report would not.
  - No RSRP/RSRQ field exists anywhere in the payload — consistent with GTS,
    inconsistent with a measurement report.

The structural decode is subsystem-agnostic: ``sfn_counter`` is the
GTS-latched SysFN (F3 prints "SysFN"), and the 432B 20-slot array is a GTS
time-tag/sample buffer, NOT per-cell measurements.

Compact 15-byte records (v4, SDX20): The u32 at [3:7] encodes the SysFN
counter in bits 20-31 (monotonically increasing, latched per GTS interval)
and scheduling/status data in bits 0-19.
v6 records (emitted on MDM9150 **and** SDX55): the DOMINANT form is 16 bytes
(15.1M records corpus-wide, from the MDM9150 — the same 81UMV91M21 modem,
captured inside the Kapsch RIS-9260 RSU), NOT 3 bytes — `06 <sub> <b2> 01 <u32@[4:8]>` + zero
pad, with an 8B twin (`06 03 00 01 <u32@[4:8]>`). The u32 at [4:8] is the real
varying payload (a monotonic GTS counter, exposed RAW as ``v6_value``); the
u16 at [1:3] (``compact_status``) captures only the constant subtype. The 3B
and 75B forms (SDX55: EM9190 / M2000) carry just ``compact_status``.

Log name: LOG_GNSS_GLOBAL_TIME_SERVICES_EVENTS
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_GNSS_GLOBAL_TIME_SERVICES_EVENTS
from diaggrok.registry import register


# Validation note for the 432-byte v=0x04 FULL form (a fixed 20-slot array):
# the slots are a GTS time-tag/sample buffer, not per-cell measurements, so
# reading field0_u8 as a cell signal level or num_entries_populated as a
# measured-cell count is wrong. On an LM960, num_entries_populated is a
# constant 20 (array capacity, never a cell count) and field0_u8 is never
# populated — both consistent with "not a measurement report".
# counter_a/counter_b/index_u16 are monotonic tick/sample counters and marker
# is a terminator byte — none are RF quantities.

@dataclass
class Diag0x18AE:
    """GNSS Global Time Services / GTS events (0x18AE).

    Not an "LTE ML1 Measurement Report" (see the module docstring).

    Compact 15-byte records (v4, SDX20): The u32 at [3:7] encodes the
    GTS-latched SysFN counter in bits 20-31 (monotonically increasing) and
    scheduling/status data in bits 0-19.
    v6 records (emitted on MDM9150 **and** SDX55): the DOMINANT form is 16 bytes
(15.1M records corpus-wide, from the MDM9150 — the same 81UMV91M21 modem,
captured inside the Kapsch RIS-9260 RSU), NOT 3 bytes — `06 <sub> <b2> 01 <u32@[4:8]>` + zero
pad, with an 8B twin (`06 03 00 01 <u32@[4:8]>`). The u32 at [4:8] is the real
varying payload (a monotonic GTS counter, exposed RAW as ``v6_value``); the
u16 at [1:3] (``compact_status``) captures only the constant subtype. The 3B
and 75B forms (SDX55: EM9190 / M2000) carry just ``compact_status``.
    """

    log_time: int
    version: int
    payload_size: int
    sfn_counter: int | None = None  # bits 20-31 of u32 at [3:7] (v4): GTS-latched SysFN
    sched_data: int | None = None   # bits 0-19 of u32 at [3:7] (v4)
    compact_status: int | None = None  # u16 at [1:3] for compact (3B v6)
    # v6 dominant 16B form (MDM9150; and its 8B twin) is `06 <sub> <b2> 01
    # <u32@[4:8]> ...` — a type-tagged GTS record whose real varying payload is
    # the u32 at [4:8] (monotonic counter; compact_status only carries the
    # constant subtype). Surfaced RAW as a CANDIDATE GTS counter — physical
    # semantics unidentified, F3-grounded to the GTS subsystem only (WNC
    # 81UMV91M21 / MDM9150).
    v6_value: int | None = None  # u32 LE at [4:8] on v6 len>=8 records
    # v4 432B full form: a fixed 20-slot entry array, each slot 20B,
    # framed as 26B header + 20×20B entries + 6B trailer. This is a GTS
    # time-tag/sample buffer (NOT per-cell measurements).
    # ``full_entries`` holds the structurally-decoded slots;
    # ``num_entries_populated`` counts the leading non-all-zero slots (the
    # array is zero-padded when fewer than 20 samples are present).
    full_entries: list[dict[str, int]] | None = None
    num_entries_populated: int | None = None
    # --- v0x08 (SDX62 / SDX72) GTS event fields -----------------------------
    # ``gts_event_type`` is the byte at [1] — the GTS event discriminator, and
    # the STABLE key for this version: the payload SIZE is not (event 0x01 is
    # 465B on SDX62 but 602B on SDX72; event 0x10 is 5976B vs 7013B).
    gts_event_type: int | None = None
    # The seven fields below are F3-CONFIRMED byte-exact against the record's
    # own ``gts.c:6842 GetGtsTime`` print (see the module docstring).
    gts_time_src: int | None = None    # [6]     u8   — F3 "Tsrc"
    gps_week: int | None = None        # [7:9]   u16  — F3 "W"
    gps_msec: int | None = None        # [9:13]  u32  — F3 "Ms" (ms into GPS week)
    clock_bias_s: float | None = None  # [13:17] f32  — F3 "B"  (seconds)
    time_unc_s: float | None = None    # [17:25] f64  — F3 "Tu" (seconds)
    ustmr: int | None = None           # [26:34] u64  — F3 "U"  (USTMR tick)
    fcount: int | None = None          # [39:43] u32  — F3 "FC" (LTE frame count)
    # RAW/CANDIDATE — these two vary per record but are printed by NO F3 site
    # in any capture that carries them, so they are surfaced unnamed rather
    # than guessed at.
    v8_raw_u32_35: int | None = None   # [35:39] u32, ~2.09e7, varies
    v8_raw_i32_44: int | None = None   # [44:48] i32, small negative, drifts

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'type': 'Diag0x18AE',
            'log_time': self.log_time,
            'version': self.version,
            'payload_size': self.payload_size,
        }
        if self.sfn_counter is not None:
            d['sfn_counter'] = self.sfn_counter
            d['sched_data'] = self.sched_data
        if self.compact_status is not None:
            d['compact_status'] = self.compact_status
        if self.v6_value is not None:
            d['v6_value'] = self.v6_value
        if self.full_entries is not None:
            d['num_entries_populated'] = self.num_entries_populated
            d['full_entries'] = self.full_entries
        if self.gts_event_type is not None:
            d['gts_event_type'] = self.gts_event_type
        for key in ('gts_time_src', 'gps_week', 'gps_msec', 'clock_bias_s',
                    'time_unc_s', 'ustmr', 'fcount',
                    'v8_raw_u32_35', 'v8_raw_i32_44'):
            val = getattr(self, key)
            if val is not None:
                d[key] = val
        return d


# --- v4 432B full-form geometry --------------------------------------------
# 432 = 26B header + 20 entry slots × 20B + 6B trailer. The 20-byte entry
# stride and its internal field offsets are confirmed across 3 chipset
# generations (LM960 SDX20, EM7511 SDX24, MC7411 MDM9x40 — same column
# layout, same per-entry counter arithmetic). The byte at header offset 16
# is NOT the entry size (it takes both 0x05 and 0x14 across chipsets) — the
# entry stride is a fixed 20.
_V4_FULL_SIZE = 432
_V4_FULL_HDR = 26
_V4_FULL_ENTRY = 20
_V4_FULL_NENT = 20


# --- v8 GTS event types ----------------------------------------------------
# The byte at [1] on a v0x08 record is the GTS EVENT TYPE. It — not the payload
# size — is the stable discriminator across silicon: the same event type is a
# different length on SDX62 vs SDX72.
#
#   event  SDX62 size   SDX72 size   grounding
#   0x09      75 B         75 B      1:1 with F3 ``gts.c:6842 GetGtsTime``
#   0x0c       3 B          3 B      body-less event
#   0x01     465 B        602 B      structural only
#   0x10    5976 B       7013 B      structural only
#   0x14       —           4 B       structural only
#   0x0f       —          11 B       structural only
_V8_EVENT_GET_GTS_TIME = 0x09
# Byte offsets inside the event-0x09 body, every one F3-confirmed byte-exact
# against that record's own GetGtsTime print.
_V8_MIN_LEN = 48  # through the last decoded field ([44:48])


# --- Per-(version, event) record sizes ---------------------------------------
# Byte [1] is the event type on EVERY version (not only v0x08): v4/v5 0x04 is
# the 15 B SysFN record, 0x03 the 7 B form, 0x01 the 432 B 20-slot array, etc.
# No event carries a length field, so the payload size is the only delimiter.
# For each attested (version, event) a payload is accepted when its size is an
# attested size or LONGER than every attested size; a shorter, unattested size
# cannot be told apart from a truncated record and returns None (registry
# WARN). (version, event) pairs not listed here are passed through as before.
# Every (version, event, size) seen in a 1,814-record cross-check over 14
# small captures matches this table.
_EVENT_SIZES: dict[tuple[int, int], tuple[int, ...]] = {
    (0x04, 0x01): (432,), (0x04, 0x03): (7,), (0x04, 0x04): (15,),
    (0x04, 0x08): (15,), (0x04, 0x09): (50,), (0x04, 0x0c): (2,),
    (0x05, 0x01): (432,), (0x05, 0x03): (7,), (0x05, 0x04): (15,),
    (0x05, 0x0a): (56,), (0x05, 0x0d): (57,),
    (0x06, 0x09): (75,), (0x06, 0x0c): (3,), (0x06, 0x0f): (11,),
    (0x08, 0x01): (465, 602), (0x08, 0x09): (75,), (0x08, 0x0c): (3,),
    (0x08, 0x0e): (4,), (0x08, 0x0f): (11,), (0x08, 0x10): (600, 5976, 7013),
    (0x08, 0x14): (4,),
}


def _truncated(version: int, data: bytes) -> bool:
    """True when ``data`` is shorter than its (version, event) record."""
    if len(data) < 2:
        return True
    sizes = _EVENT_SIZES.get((version, data[1]))
    if sizes is None:
        return False
    return len(data) not in sizes and len(data) < max(sizes)


def _decode_v4_full_entries(data: bytes) -> list[dict[str, int]]:
    """Decode the 20-slot entry array of a v4 432B record.

    Each 20-byte slot exposes four structurally-confirmed fields plus a
    marker byte. Field *roles* are named; physical semantics are NOT claimed.
    This is a GTS time-tag/sample buffer (0x18AE = GNSS Global Time Services,
    F3-confirmed), so ``field0_u8`` is NOT a cell signal level and the slot
    count is NOT a measured-cell count.

    Observed per-entry behavior (LM960 SDX20, all 20 slots populated):
      - ``field0_u8`` (rel 0): wide-range u8, ~constant within a record,
        varies across records/chipsets (NOT a signal level; role
        unidentified).
      - ``counter_a`` (rel 1:3, u16 LE): monotonic +75 per populated slot.
      - ``index_u16`` (rel 12:14, u16 LE): small integer (12..19 observed).
      - ``counter_b`` (rel 14:16, u16 LE): monotonic +2 per slot AND
        continuous across records (+40 = 20×2 per record) — a global counter.
      - ``marker`` (rel 16, u8): 0 on measurement slots; nonzero on the
        terminator slot (chipset-keyed: 0x2c on LM960, 0x10 on MC7411).
    Bytes rel 3:12 and 17:20 are reserved (mostly zero; ~0.85% nonzero on
    MC7411 — left undecoded, NOT asserted as a const invariant).
    """
    entries: list[dict[str, int]] = []
    for k in range(_V4_FULL_NENT):
        off = _V4_FULL_HDR + k * _V4_FULL_ENTRY
        slot = data[off:off + _V4_FULL_ENTRY]
        if not any(slot):
            continue  # zero-padded trailing slot
        entries.append({
            'field0_u8': slot[0],
            'counter_a': unpack_from('<H', slot, 1)[0],
            'index_u16': unpack_from('<H', slot, 12)[0],
            'counter_b': unpack_from('<H', slot, 14)[0],
            'marker': slot[16],
        })
    return entries


@register(LOG_GNSS_GLOBAL_TIME_SERVICES_EVENTS,
    name="0x18AE",
    wigle_direct=True,
    wigle_roles=("signal",),
    description="GNSS Global Time Services (GTS) events — compact (15B/3B SysFN/status) and full (432B/75B GTS time-tag array) forms, version-dependent (not an LTE ML1 measurement report)",
    version=10,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE over a 43.9M-record / 705-capture corpus on SDX20, "
        "SDX24, MDM9x40, MDM9250, MDM9150, SDX55, SDX62 and SDX72. Byte [0] is "
        "the version and byte [1] the event type on every version; a payload "
        "shorter than the attested size of its (version, event) record returns "
        "None (registry WARN). "
        "v0x04 (SDX20) / v0x05 (MDM9250): the 15B compact record carries the "
        "GTS-latched SysFN in bits 20-31 of u32 [3:7] (gts.c:502 prints it "
        "verbatim as 'GTS: OstmrDiff SysFN'); the 432B full form is a 26B "
        "header + 20 × 20B slots + 6B trailer whose per-slot fields (field0_u8, "
        "counter_a +75/slot, index_u16, counter_b +2/slot, marker) are "
        "confirmed across SDX20 (LM960), SDX24 (EM7511) and MDM9x40 (MC7411), "
        "physical semantics unidentified. GTS identity: an LM960 capture with "
        "1,154,318 v0x04 records and 219,785 GTS-subsystem F3 prints (84.32% "
        "within 0.5s), and an MDM9250 drive with 2,170,942 v0x05 records and "
        "1,215,845 GTS prints (5ms: 91.7% vs 64.8% null). On an LM960 in "
        "single-cell limited service the 432B array reports 20 populated slots "
        "(array capacity, not a cell count). "
        "v0x06 (MDM9150 — the WNC 81UMV91M21 in the Kapsch RIS-9260 RSU — plus "
        "SDX55 3B/75B): the dominant 16B form (15,086,253 records) is "
        "`06 <sub> <b2> 01 <u32>` with an 8B twin; the monotonic u32 at [4:8] is "
        "surfaced RAW as v6_value for every >=8B form. GTS-subsystem F3 "
        "(`GTS: BestGPSTime - SrcModule`, `GTS: Latch %u,RTC %lu,...`, "
        "`GetClockAndRtc`) runs at ~773 prints/s; at tight windows records "
        "cluster far tighter than uniform-random ticks (1ms: 63.8% vs 23.0% "
        "null; 2ms: 76.4% vs 37.5%; 5ms: 89.7% vs 71.8%). "
        "v0x08 (SDX62 RM520N-GL / EM9291 / Casa CFW-3212, SDX72 T99W640): GTS "
        "events keyed on the event byte, not the size (event 0x01 is 465B on "
        "SDX62 vs 602B on SDX72; 0x10 is 5976B vs 7013B). The dominant 75B "
        "event 0x09 (365,960 of 426,764 records) is emitted 1:1 with the F3 "
        "print `gts.c:6842 GetGtsTime P %d Tsrc %d W %d Ms %d B %f Tu %f "
        "U 0x%llx FC %d %d`; zipping the streams in capture order matches 100% "
        "on every discriminating field on two vendors (RM520N-GL 9,965/9,965, "
        "an exact count identity; CFW-3212 1,224/1,224). Distinct values "
        "carried by the match (RM520N-GL / CFW-3212): ms@[9:13] 5,861/825, "
        "ustmr@[26:34] 5,867/825, fcount@[39:43] 5,861/825, bias_f32@[13:17] "
        "2,644/331, unc_f64@[17:25] 214/479, time_src@[6] 2/2. The F3's `P` and "
        "`FC`-flag are constant 1, so bytes [5], [25], [38], [43] matching them "
        "is constant-vs-constant with no discriminating power and they are not "
        "claimed; `W` (GPS week) is constant within a capture and grounded "
        "across captures (2420 / 2422 / 2423). Independently of F3, "
        "gps_week+gps_msec decoded to UTC lands a few seconds after each "
        "capture's own wall-clock start on three vendors. [35:39] u32 and "
        "[44:48] i32 vary but are named by no F3 site, so they are surfaced RAW. "
        "A T99W640 bring-up capture has week=0 in all 1,412 75B records — GTS "
        "running with no valid GPS time, matching the F3 string `GTS: "
        "BestGPSTime - No valid GPS Time`."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    # version, payload_size, sfn_counter, sched_data, compact_status,
    # v6_value, num_entries_populated + 5 per-entry structural fields
    # (field0_u8, counter_a, index_u16, counter_b, marker)  = 12
    # + v0x08: gts_event_type, gts_time_src, gps_week, gps_msec,
    #   clock_bias_s, time_unc_s, ustmr, fcount, v8_raw_u32_35, v8_raw_i32_44
    #   = 10 more.
    fields_identified=22,
    fields_parsed=22,
    field_invariants={
        "version": {"enum": [0x04, 0x05, 0x06, 0x08]},
        "payload_size": {"enum": [
            2, 3, 4, 7, 8, 11, 15, 16, 39, 42, 50, 56, 57, 65, 73, 75,
            432, 433, 465, 600, 602, 3178, 5976, 7013,
        ]},
    },
)
def parse_0x18ae(log_time: int, data: bytes) -> Diag0x18AE | None:
    """Parse 0x18AE -- GNSS Global Time Services (GTS) events.

    (Not an "LTE ML1 Measurement Report"; see the module docstring.)

    Version 4 (SDX20) / Version 5 (MDM9250) — structurally identical:
      Compact records (15B): extracts the GTS-latched SysFN u32 at [3:7].
      Full records (432B): decodes the 20-slot GTS time-tag array
        into ``full_entries`` (structural fields per slot) + ``num_entries_populated``.
      v0x05 also emits 50/7/57/56B forms sharing the same header; the shared
        SysFN u32 at [3:7] is extracted, the 57/56B tails stay undecoded.
    Version 6 (MDM9150 16B dominant + SDX55 3B/75B) — GTS subsystem F3-grounded
    on the WNC 81UMV91M21 / MDM9150:
      Dominant 16B form (and its 8B twin): `06 <sub> <b2> 01 <u32@[4:8]>` — the
        u32 at [4:8] is the real varying payload (monotonic GTS counter),
        surfaced RAW as ``v6_value``; ``compact_status`` (u16 at [1:3]) is the
        constant subtype byte.
      Compact records (3B): extracts compact_status u16 at [1:3] only.
      Larger forms (65/73/433/3178B): u32 at [4:8] also extracted; the rest of
        the body is recorded but not decoded.
    Version 8 (SDX62: RM520N-GL / EM9291 / Casa CFW-3212 — and SDX72: T99W640)
    — GTS events keyed on the EVENT-TYPE byte at [1], not on the payload size.
      Event 0x09 (75B, dominant — 86% of v0x08): the full GTS time record. It
        is emitted **1:1** with the firmware's own ``gts.c:6842 GetGtsTime``
        F3 print, which renders these very fields, so every offset is
        F3-confirmed byte-exact rather than inferred:
        ``gts_time_src`` [6], ``gps_week`` [7:9], ``gps_msec`` [9:13],
        ``clock_bias_s`` f32 [13:17], ``time_unc_s`` f64 [17:25],
        ``ustmr`` u64 [26:34], ``fcount`` [39:43].
        Two further varying ints ([35:39], [44:48]) are printed by NO F3 site
        and are surfaced RAW as ``v8_raw_u32_35`` / ``v8_raw_i32_44``.
        The bytes at [5] and [43] are 0x01 wherever F3 exists to compare, so
        they match the F3's *constant* ``P`` / ``FC``-flag against a constant —
        no discriminating power, therefore NOT claimed as those fields.
      Event 0x0c (3B): a body-less event; only ``gts_event_type`` is set.
      Events 0x01 / 0x10 / 0x14 / 0x0f: structural only — ``gts_event_type``
        is set and the body is left undecoded. Their sizes are silicon-keyed
        (0x01 is 465B on SDX62 but 602B on SDX72; 0x10 is 5976B vs 7013B),
        which is exactly why the event byte, not the size, is the key.
    Returns None for payloads shorter than 2 bytes, and for a payload
    shorter than the attested record size of its (version, event-byte) pair —
    a truncated record (see ``_EVENT_SIZES``).
    """
    if len(data) < 2:
        return None
    version = data[0]
    if version not in (0x04, 0x05, 0x06, 0x08):
        return None
    if _truncated(version, data):
        return None

    sfn_counter: int | None = None
    sched_data: int | None = None
    compact_status: int | None = None
    v6_value: int | None = None
    full_entries: list[dict[str, int]] | None = None
    num_entries_populated: int | None = None
    gts_event_type: int | None = None
    gts_time_src: int | None = None
    gps_week: int | None = None
    gps_msec: int | None = None
    clock_bias_s: float | None = None
    time_unc_s: float | None = None
    ustmr: int | None = None
    fcount: int | None = None
    v8_raw_u32_35: int | None = None
    v8_raw_i32_44: int | None = None

    if version in (4, 5) and len(data) >= 7:
        # v0x05 (MDM9250) is the cross-silicon twin of v0x04 (SDX20), also
        # F3-GTS grounded — same `05|04 <sub> 01 <u32@[3:7]>` header, same
        # 432B 20-slot GTS time-tag array with the identical counter_a
        # +75/slot & counter_b +2/slot arithmetic. So v0x05 is decoded
        # through the v0x04 path verbatim.
        # The u32 at [3:7] is the same header field in both the 15B compact
        # form and the 26B header of the 432B full form — extract it for
        # both.
        raw = unpack_from('<I', data, 3)[0]
        if raw != 0:
            sfn_counter = (raw >> 20) & 0xFFF  # bits 20-31: SFN counter
            sched_data = raw & 0xFFFFF          # bits 0-19: scheduling data
        if len(data) == _V4_FULL_SIZE:
            # 432B full form: also decode the 20-slot entry array.
            full_entries = _decode_v4_full_entries(data)
            num_entries_populated = len(full_entries)
    elif version == 6 and len(data) >= 3:
        compact_status = unpack_from('<H', data, 1)[0]
        # v6 dominant 16B form (MDM9150; 15.1M records corpus-wide) and its 8B
        # twin carry the actual payload as a u32 at [4:8] — a monotonic GTS
        # counter — after the `06 <sub> <b2> 01` header. compact_status above
        # captures only the constant subtype; extract the real field here.
        # RAW/CANDIDATE (GTS subsystem F3-grounded; field semantics
        # unidentified). Present on every observed v6 form >= 8B (16/8/65/73/
        # 433/3178B); the byte at [3] is a constant 0x01 across the corpus but
        # is NOT asserted as an invariant (a populated body may fill it).
        if len(data) >= 8:
            v6_value = unpack_from('<I', data, 4)[0]
    elif version == 8 and len(data) >= 2:
        # v0x08 (SDX62 / SDX72) — GTS events, keyed on the event-type byte at
        # [1], NOT on the payload size (the same event is a different length on
        # SDX62 vs SDX72). See _V8_EVENT_* above.
        gts_event_type = data[1]
        if gts_event_type == _V8_EVENT_GET_GTS_TIME and len(data) >= _V8_MIN_LEN:
            # Event 0x09 is emitted 1:1 with the firmware's own
            # ``gts.c:6842 GetGtsTime`` F3 print, which renders these very
            # fields — so each offset below is F3-confirmed byte-exact, not
            # inferred from column variance.

            gts_time_src = data[6]
            gps_week = unpack_from('<H', data, 7)[0]
            gps_msec = unpack_from('<I', data, 9)[0]
            clock_bias_s = unpack_from('<f', data, 13)[0]
            time_unc_s = unpack_from('<d', data, 17)[0]
            ustmr = unpack_from('<Q', data, 26)[0]
            fcount = unpack_from('<I', data, 39)[0]
            # RAW/CANDIDATE — vary per record, named by no F3 site.
            v8_raw_u32_35 = unpack_from('<I', data, 35)[0]
            v8_raw_i32_44 = unpack_from('<i', data, 44)[0]

    return Diag0x18AE(
        log_time=log_time,
        version=version,
        payload_size=len(data),
        sfn_counter=sfn_counter,
        sched_data=sched_data,
        compact_status=compact_status,
        v6_value=v6_value,
        full_entries=full_entries,
        num_entries_populated=num_entries_populated,
        gts_event_type=gts_event_type,
        gts_time_src=gts_time_src,
        gps_week=gps_week,
        gps_msec=gps_msec,
        clock_bias_s=clock_bias_s,
        time_unc_s=time_unc_s,
        ustmr=ustmr,
        fcount=fcount,
        v8_raw_u32_35=v8_raw_u32_35,
        v8_raw_i32_44=v8_raw_i32_44,
    )
