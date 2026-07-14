"""GLONASS RF bandpass status parser (0x1646) — #N.

Observed across **13 modem families spanning 5+ QCA chipset generations**
(MDM9x07, MDM9x40, MDM9x50, SDX20, SDX55, SDX62) — one of the most
broadly-attested GNSS log codes in the corpus (~30,000 records as of
session ``0f1a`` 2026-05-09).

## Cross-generation size split (real RE finding)

| Modems / chipset                                          | `version` | Payload |
|-----------------------------------------------------------|-----------|---------|
| MC7455 (MDM9x40)                                          | `0x02`    | 445 B   |
| EM9190/EM7511/EG25-G/EP06A/EG18NA/RM500Q/RM520N/FN980/    |           |         |
| LM960/SIM7600/EG12-GT/LV55                                | `0x03`    | 449 B   |

Both variants share an identical 13-byte fixed header AND a 9-element
slot array of 44-byte slots. The 4-byte v2→v3 size delta lives in the
trailer (36 B v2 / 40 B v3) — slot stride invariant across versions.

## ⚠ But the slot INTERNAL layout is NOT version-invariant

Session ``0f1a`` (2026-05-09) discovered that while slot stride is 44 B in
both versions, the bytes inside the slot are **shifted by 4 bytes around
the marker** between v2 and v3. The session ``kali`` (2026-05-07) finding
that promoted slot[0] internals to i16/u16 fields was based on v3
fixtures only and the layout it documented does NOT apply to v2.

**Verified by aligning the `0d 0d 01 00`-family marker across all 4
fixtures** (`tools/parser_corpus_summary.py` did not surface this
because it scans single-byte distributions, not aligned multi-byte
patterns):

| Fixture                | size | marker offsets (within record) | inter-marker stride | first-marker slot offset |
|------------------------|-----:|--------------------------------|---------------------|--------------------------|
| eg25g_mdm9x07 (v3)     | 449  | 45,89,...,441 (10 hits)         | 44                  | +32                      |
| mc7455_mdm9x40 (v2)    | 445  | 41,85,...,437 (10 hits)         | 44                  | +28                      |

The em9190 and rm520ngl v3 fixtures show 1 and 0 marker hits
respectively because their slot+33 byte is `0x11` not `0x0d` — but the
slot+32 byte is uniformly populated and the slot+34..+35 = `01 00` tail
is invariant on v3. The em9190 + rm520 results don't contradict the
layout, they just have a different slot_marker high byte.

Concrete v2 vs v3 alignment of slot[0] (eg25g v3 + mc7455 v2 dump):

```
v3 eg25g  +0..+3:  54 6f 00 00     u16 metric_a, +0x00 pad, +0x00 state_flag
v2 mc7455 +0..+3:  00 00 00 80     u32 sentinel low (NO metric_a/flag here)

v3 eg25g  +4..+7:  00 00 00 80     u32 sentinel = 0x80000000
v2 mc7455 +4..+7:  00 02 00 00     u32 const1   = 0x00000200  ← v3 const1 lives here on v2

v3 eg25g  +8..+11: 00 02 00 00     u32 const1   = 0x00000200
v2 mc7455 +8..+11: 00 00 00 00     u32 reserved zero          ← v3 reserved zero lives here on v2

v3 eg25g  +16..+19: 7b 06 00 00    i16 rf_metric_1 + 2-byte sign-ext
v2 mc7455 +12..+15: 75 07 00 00    i16 rf_metric_1 + 2-byte sign-ext  ← shifted -4

v3 eg25g  +32..+35: 0d 0d 01 00    u32 slot_marker
v2 mc7455 +28..+31: 0d 0d 01 00    u32 slot_marker  ← shifted -4

v3 eg25g  +40..+43: 2b 7f 11 00    u32 final_metric (4 bytes)
v2 mc7455 +36..+43: 76 05 07 57    u32 flags2  ← v3 dropped these 4 bytes
                    3d 66 00 00    u32 final_metric

v2 has TWO u32 values in the post-flags region (8 bytes); v3 has ONE
(4 bytes). That's where v3 saved 4 bytes per slot — but the savings are
spent again in the trailer (40 B v3 vs 36 B v2). Net per-slot delta is
0; payload delta of +4 lives entirely in the trailer.
```

This is the size-invariance ≠ format-invariance trap from the project's
core memory: matching slot stride does NOT imply matching slot internal
layout. v2 and v3 are decoded by different code paths.

## Known structure (header invariants verified across 5 chipset families)

- `byte[0]`     = `version` — `0x02` on MDM9x40, `0x03` on MDM9x07+SDX2x/5x/6x.
- `byte[1]`     = `0x01` constant — subtype / report-class selector.
- `byte[2:4]`   = u16 record counter (per-record monotonic per chipset).
- `byte[4]`     = `0x0a` constant — marker / format tag.
- `byte[5:9]`   = u32 timestamp_a — **1 ms (1 kHz) monotonic system tick**.
  #N cadence-sweep: linear in record ts64 at R²=1.0, Δts64/Δtick == 52428.8 ==
  exactly 1 ms (ts64 unit 1/52428800 s), cross-chipset (LV55 SDX55 + CFW3212 SDX62).
  This is why the code carries `timebase_roles=("metronome",)`.
- `byte[9:13]`  = u32 timestamp_b — paired tick value (correlated with _a).

## v3 slot layout (44 B — 9 slots × 3 chipsets verified)

```
+0..+1   : u16   metric_a       (e.g. EP06A=23100, EM9190=32584 — plausible C/N0×100)
+2       : u8    pad            (0x00 corpus-wide)
+3       : u8    state_flag     (0x00 91.8% / 0x80 8.2% — per-record state discriminator)
+4..+7   : u32   sentinel       (0x80000000 constant)
+8..+11  : u32   const1         (0x00000200 = 512 — coefficient base)
+12..+15 : u32   reserved_zero
+16..+17 : i16   rf_metric_1    (range -32768..+32767, scale ≈ 0.01 dB)
+18..+19 : pad   sign-ext of rf_metric_1 (0x00 0x00 if positive, 0xff 0xff if negative)
+20..+21 : i16   rf_metric_2    (paired with _1, often within ±20 LSB)
+22..+23 : pad   sign-ext of rf_metric_2
+24..+25 : i16   rf_metric_3    (e.g. AGC level)
+26..+27 : pad   sign-ext of rf_metric_3
+28..+31 : u32   reserved_zero_2 (0x00000000 typically; 0xffffffff sentinel on rm520)
+32..+35 : u32   slot_marker    (0x0001 0d 0d / 0x0001 0d 11 — varies, +33..+35 = 0d 01 00)
+36..+39 : u32   flags
+40..+43 : u32   final_metric
```

i16 sign-extension verified at 100% across **27 slot positions** (3 v3
chipsets × 9 slots) in session ``0f1a`` 2026-05-09. The +3 state_flag
finding (0x80 in 8.2% of records) was originally attributed to a corpus-
wide v3 phenomenon by session ``kali`` 2026-05-07 but session ``0f1a``
showed that some of that 8.2% may have been v2 MC7455 records mis-aligned
into the v3 framing — the corrected per-version split is open follow-up.

## v2 slot layout (44 B — shifted -4 from v3 around the marker)

```
+0..+3   : u32   sentinel       (0x80000000 — v3's at +4)
+4..+7   : u32   const1         (0x00000200 — v3's at +8)
+8..+11  : u32   reserved_zero  (v3's at +12)
+12..+13 : i16   rf_metric_1
+14..+15 : pad   sign-ext
+16..+17 : i16   rf_metric_2
+18..+19 : pad   sign-ext
+20..+21 : i16   rf_metric_3
+22..+23 : pad   sign-ext
+24..+27 : u32   reserved_zero_2
+28..+31 : u32   slot_marker
+32..+35 : u32   flags
+36..+39 : u32   flags2         (v3 dropped these 4 bytes)
+40..+43 : u32   final_metric
```

i16 sign-extension verified at 100% across 9 slot positions on the v2
MC7455 fixture in session ``0f1a`` 2026-05-09. Note v2 has NO equivalent
of v3's metric_a / state_flag at slot start — those fields appear to be
v3-only additions.

## TBD for full closure (#N)

- Per-slot semantic identity — which of the 9 slots maps to which
  GLONASS frequency-channel-number / RF chain? Slot internals match
  closely across slots within a chipset (e.g. eg25g rf_metric_1 ranges
  +1659..+1660 across all 9 slots) — likely the same band sampled at
  different frequency offsets, not 9 distinct bands.
- Trailer layout (36 B on v2 / 40 B on v3) — contains a 10th marker
  pattern at trailer+28 (v2) / trailer+32 (v3), suggesting it may be a
  smaller "10th slot" with a vestigial structure. RE pending.
- AT cross-check via `AT$QCRFCAL?` / `AT+QGPSCFG="glonassnmeatype"`
  for GLONASS RF state.
- Why 9 slots, not 14? Settled: 9 is a fixed front-end configuration
  constant (RTCM-paired LG290P validation, session `0ec1`, 2026-04-27)
  — the LG290P sees 3-6 GLONASS PRNs in stationary captures while the
  DUT always emits exactly 9 slots. Most likely 9 = QCA GNSS_ME GLONASS
  bandpass filter banks.

## Test fixtures

- `<redacted-pii>` — 449B v3 (Sierra SDX55)
- `<redacted-pii>` — 449B v3 (Quectel MDM9x07)
- `<redacted-pii>` — 449B v3 (Quectel SDX62)
- `<redacted-pii>` — **445B v2** (Sierra MDM9x40)

=== names-block:start (auto-generated by tools/inject_names_block_parsers.py) ===

Names by source (from sources/DIAG_LOG_INDEX.yaml):
    canonical: LOG_WCDMA_RLC_CONFIG
        source: qxdm_3_12_714_2017_diag_log_codes (authority: community)
    aliases:
        LOG_TCXOMGR_RGS_RETRIEVAL_LOG
            source: qxdm_itemtype_list_zukgit_2025_04_03

Source-precedence (#N): vendor_official > observation >
community (specification) > community (reference).
=== names-block:end ===
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


LOG_GNSS_ME_RF_GLO_BP = 0x1646


# Body-layout constants (RE'd 2026-04-25, internals refined 2026-05-09)
HEADER_BYTES = 13              # fixed packet header through timestamp_b
SLOT_COUNT = 9                 # constant across v2 + v3 (likely # of QCA bandpass filter banks)
SLOT_STRIDE = 44               # per-slot bytes
SLOT_ARRAY_BYTES = SLOT_COUNT * SLOT_STRIDE  # 396
# Trailer = payload - HEADER_BYTES - SLOT_ARRAY_BYTES = 36 (v2) / 40 (v3).


@dataclass
class GnssRfGloBpSlot:
    """One of 9 GLONASS RF filter-bank slots inside a 0x1646 record.

    Both v2 and v3 slots are 44 B but their internal layouts differ by a
    4-byte shift around the slot_marker (see module docstring). Fields
    that are v3-only (metric_a, state_flag) are populated as None on v2.
    """
    index: int                 # 0..8
    # v3-only fields (None on v2)
    metric_a: int | None       # u16 at v3+0..+1; absent on v2
    state_flag: int | None     # u8 at v3+3 (0x00 / 0x80); absent on v2
    # Shared structure (offsets differ between v2 and v3)
    sentinel: int              # u32 = 0x80000000 typically
    const1: int                # u32 = 0x00000200 (= 512) typically
    reserved_zero: int         # u32 typically 0
    rf_metric_1: int           # i16, sign-extended
    rf_metric_2: int           # i16, sign-extended
    rf_metric_3: int           # i16, sign-extended
    reserved_zero_2: int       # u32 typically 0; 0xffffffff sentinel on rm520
    slot_marker: int           # u32 (e.g. 0x00010d0d, 0x00010d11)
    flags: int                 # u32
    final_metric: int          # u32 (last 4 bytes of slot)
    # v2-only field (None on v3)
    flags2: int | None         # u32 — present only on v2 (v3 dropped these 4 bytes)

    def to_dict(self) -> dict[str, Any]:
        return {
            'index': self.index,
            'metric_a': self.metric_a,
            'state_flag': self.state_flag,
            'sentinel': self.sentinel,
            'const1': self.const1,
            'reserved_zero': self.reserved_zero,
            'rf_metric_1': self.rf_metric_1,
            'rf_metric_2': self.rf_metric_2,
            'rf_metric_3': self.rf_metric_3,
            'reserved_zero_2': self.reserved_zero_2,
            'slot_marker': self.slot_marker,
            'flags': self.flags,
            'final_metric': self.final_metric,
            'flags2': self.flags2,
        }


def _decode_slot_v3(slot_bytes: bytes, slot_index: int) -> GnssRfGloBpSlot:
    """Decode a v3 (449B record) slot — i16/u16 layout verified 2026-05-09."""
    return GnssRfGloBpSlot(
        index=slot_index,
        metric_a=unpack_from('<H', slot_bytes, 0)[0],
        state_flag=slot_bytes[3],
        sentinel=unpack_from('<I', slot_bytes, 4)[0],
        const1=unpack_from('<I', slot_bytes, 8)[0],
        reserved_zero=unpack_from('<I', slot_bytes, 12)[0],
        rf_metric_1=unpack_from('<h', slot_bytes, 16)[0],
        rf_metric_2=unpack_from('<h', slot_bytes, 20)[0],
        rf_metric_3=unpack_from('<h', slot_bytes, 24)[0],
        reserved_zero_2=unpack_from('<I', slot_bytes, 28)[0],
        slot_marker=unpack_from('<I', slot_bytes, 32)[0],
        flags=unpack_from('<I', slot_bytes, 36)[0],
        final_metric=unpack_from('<I', slot_bytes, 40)[0],
        flags2=None,
    )


def _decode_slot_v2(slot_bytes: bytes, slot_index: int) -> GnssRfGloBpSlot:
    """Decode a v2 (445B record) slot — shifted -4 from v3 around the marker."""
    return GnssRfGloBpSlot(
        index=slot_index,
        metric_a=None,
        state_flag=None,
        sentinel=unpack_from('<I', slot_bytes, 0)[0],
        const1=unpack_from('<I', slot_bytes, 4)[0],
        reserved_zero=unpack_from('<I', slot_bytes, 8)[0],
        rf_metric_1=unpack_from('<h', slot_bytes, 12)[0],
        rf_metric_2=unpack_from('<h', slot_bytes, 16)[0],
        rf_metric_3=unpack_from('<h', slot_bytes, 20)[0],
        reserved_zero_2=unpack_from('<I', slot_bytes, 24)[0],
        slot_marker=unpack_from('<I', slot_bytes, 28)[0],
        flags=unpack_from('<I', slot_bytes, 32)[0],
        flags2=unpack_from('<I', slot_bytes, 36)[0],
        final_metric=unpack_from('<I', slot_bytes, 40)[0],
    )


@dataclass
class Diag0x1646:
    """GLONASS RF bandpass status (0x1646) — v3 slot internals decoded.

    Header fields + 9 decoded slots (v2 or v3 layout per ``size_variant``).
    Per-slot semantic identity (which slot ↔ which GLONASS FCN / RF
    chain) and trailer layout remain open (#N).
    """
    log_time: int
    version: int               # 0x02 (MDM9x40) or 0x03 (MDM9x07+SDX2x/5x/6x)
    subtype: int               # constant 0x01
    record_counter: int        # u16 at [2:4]
    marker: int                # constant 0x0a at [4]
    timestamp_a: int           # u32 at [5:9]
    timestamp_b: int           # u32 at [9:13]
    payload_size: int
    size_variant: str          # 'v2_445' | 'v3_449' | 'unknown'
    # Body-layout findings (RE'd 2026-04-25 — variance scan)
    slot_count: int            # constant 9 across v2 + v3
    slot_stride: int           # constant 44
    trailer_size: int          # 36 (v2) or 40 (v3) — v2→v3 4B delta lives here, not in slots
    slots: list[GnssRfGloBpSlot] = field(default_factory=list)
    raw: bytes = b''
    constellation: str = 'GLONASS'
    band: str = 'L1OF/L2OF'

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1646',
            'log_time': self.log_time,
            'version': self.version,
            'subtype': self.subtype,
            'record_counter': self.record_counter,
            'marker': self.marker,
            'timestamp_a': self.timestamp_a,
            'timestamp_b': self.timestamp_b,
            'payload_size': self.payload_size,
            'size_variant': self.size_variant,
            'slot_count': self.slot_count,
            'slot_stride': self.slot_stride,
            'trailer_size': self.trailer_size,
            'slots': [s.to_dict() for s in self.slots],
            'constellation': self.constellation,
            'band': self.band,
            'parser_status': 'partial',
            'parser_note': (
                f'9 × 44B slots decoded ({self.size_variant} layout); '
                'trailer + per-slot semantic identity open — see #N'
            ),
        }


def _classify_size(payload_size: int, version: int) -> str:
    if version == 0x02 and payload_size == 445:
        return 'v2_445'
    if version == 0x03 and payload_size == 449:
        return 'v3_449'
    return 'unknown'


# --- Ground-truth recipe (#N) -------------------------------------------
# Authored offline (<redacted-ref>, EC25 batch) — hypothesis only, no HW run.
# Target = Quectel EC25-AF (MDM9607); v=0x03 (449B) confirmed emitted on the
# ec25 correlate capture (211 records). GLONASS RF front-end / per-FCN bandpass
# state — a 9-slot array. ⚠ Per the docstring, which slot ↔ which GLONASS FCN
# is STILL OPEN, so grounding is by SET / RANK correlation across slots vs the
# GLONASS GSV rows, NOT slot[i]→specific-SV value-equality.

@register(
    LOG_GNSS_ME_RF_GLO_BP, domain="gnss",
    name="0x1646",
    description="GLONASS L1/L2 RF front-end + per-FCN state — header + 9-slot internals decoded (v2 + v3)",
    version=6,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    # METRONOME (#N cadence-sweep): the header field timestamp_a (u32 @5) is a
    # monotonic system tick that is a clean linear function of the record ts64 —
    # R²=1.0 with Δts64/Δtick == 52428.8 on BOTH a Wistron LV55 (SDX55) and a
    # Casa CFW-3212 (SDX62) capture. 52428.8 ts64-units == exactly 1 ms (ts64 unit
    # = 1/52428800 s), so timestamp_a is a 1 kHz / 1 ms hardware clock. Independent
    # of ts64 (a separate counter, not ts64/2^k like 0xB116's), and monotonic, so it
    # is usable for cross-file alignment, ts64 reset/gap detection, and resampling.
    # Cadence is GNSS-engine-state-dependent (not a fixed wall-rate) → "metronome"
    # only (NOT ts-anchor: it carries no mapping to wall/GPS time, just a tick).
    timebase_roles=("metronome",),
    source_detail=(
        "v6 (2026-06-25, #N cadence-sweep): tagged timebase_roles=(metronome,). "
        "The documented header field timestamp_a (u32 @5) is monotonic and linear in "
        "the record ts64 — R²=1.0 on both LV55 SDX55 (n=42) and CFW-3212 SDX62 "
        "(n=122), Δts64/Δtimestamp_a == 52428.8 == exactly 1 ms (ts64 unit 1/52428800 "
        "s), i.e. a 1 kHz system tick. Cross-chipset, so usable as a metronome for "
        "cross-file alignment + ts64 gap detection. No wall/GPS-time mapping in the "
        "body, so metronome only (not ts-anchor/absolute-time).\n"
        "v4 (2026-05-09, <redacted-ref> <redacted-ref>): per-slot internals "
        "promoted from raw bytes to named fields. Verified i16 sign-extension "
        "at 100% across 36 slot positions (3 v3 chipsets × 9 slots + 1 v2 "
        "chipset × 9 slots). Discovered v2 (MC7455 MDM9x40) slot internal "
        "layout is shifted -4 bytes from v3 around the slot_marker — kali "
        "session's slot[0] field promotion was v3-specific despite the "
        "(correct) 'slot stride invariant' finding. v2 marker at slot+28, "
        "v3 marker at slot+32; v2 has a flags2 u32 at slot+36 that v3 "
        "dropped. Net per-slot delta is 0; v2→v3 +4B payload delta lives "
        "entirely in the trailer (verified by tools/parser_corpus_summary). "
        "field_invariants now restricts version to {0x02, 0x03}.\n"
        "Inherited from v3 (2026-05-07, session kali): slot internal type "
        "refinement — what v2 framed as u32 metric_a / i32 rf_metric_{1,2,3} "
        "is actually u16+pad / i16+sign-ext. Corpus-walked 28,656 records / "
        "250 captures to verify byte distributions at the candidate sign-"
        "extension offsets.\n"
        "Inherited from v2 (2026-04-25): structural finding — 9 × 44B slot "
        "array after the 13B header, with 36B (v2) / 40B (v3) trailer holding "
        "the v2→v3 4B delta. Slot stride invariant across chipset generations."
    ),
    source_url="",
    field_invariants={"version": {"enum": [0x02, 0x03]}},
    # Header (8) + structural (3) + slot fields (12 distinct semantic fields
    # multiplied by 9 slots, but counted once per unique field role) = 23 parsed.
    # Trailer + per-slot semantic identity (which slot ↔ which FCN) still open.
    fields_parsed=23,
    fields_identified=25,
    issues=(),
)
def parse_0x1646(log_time: int, data: bytes) -> Diag0x1646 | None:
    """Parse a LOG_GNSS_ME_RF_GLO_BP (0x1646) log payload.

    Returns the decoded record with all 9 slot internals when the payload
    matches a known (size, version) profile; falls back to skeleton output
    (empty slots list) on unknown profiles so downstream consumers never
    see a partial-decode crash.
    """
    if len(data) < HEADER_BYTES:
        return None
    version = data[0]
    if version not in (0x02, 0x03):
        return None
    payload_size = len(data)
    trailer_size = max(0, payload_size - HEADER_BYTES - SLOT_ARRAY_BYTES)
    size_variant = _classify_size(payload_size, version)

    slots: list[GnssRfGloBpSlot] = []
    if size_variant in ('v2_445', 'v3_449') and len(data) >= HEADER_BYTES + SLOT_ARRAY_BYTES:
        decode_slot = _decode_slot_v3 if size_variant == 'v3_449' else _decode_slot_v2
        for i in range(SLOT_COUNT):
            start = HEADER_BYTES + i * SLOT_STRIDE
            slots.append(decode_slot(data[start:start + SLOT_STRIDE], i))

    return Diag0x1646(
        log_time=log_time,
        version=version,
        subtype=data[1],
        record_counter=unpack_from('<H', data, 2)[0],
        marker=data[4],
        timestamp_a=unpack_from('<I', data, 5)[0],
        timestamp_b=unpack_from('<I', data, 9)[0],
        payload_size=payload_size,
        size_variant=size_variant,
        slot_count=SLOT_COUNT,
        slot_stride=SLOT_STRIDE,
        trailer_size=trailer_size,
        slots=slots,
        raw=bytes(data),
    )
