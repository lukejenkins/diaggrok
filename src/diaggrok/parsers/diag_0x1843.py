"""Galileo E6 measurement skeleton parser (0x1843) — #N.

Observed across 3+ chipsets at fixed 3952B; header invariants
verified across SDX55 (EM9190), SDX20 (LM960), MDM9x07 (EG25-G).

## Layout (RE'd 2026-04-24, corpus-verified 2026-04-27, refreshed 2026-04-28)

```
+0:  u8    version          = 0x01 (corpus-invariant, 47,828/47,828 records)
+1:  u8    record_id_byte   = 0x8d (corpus-invariant, 47,828/47,828 records)
+2:  u16le header_state     varies — see "Header-state field" below
+4:  N × per-SV slot        (N = 141, stride = 28 B, total 3948 B)
```

Total: 4 + 141 × 28 = 3952 B exactly.

### Header-state field (bytes [+2:+4])

Corpus walk across 233 captures / 47,828 records (session `0b1d`,
`/rtcm-revisit` #N re-pass after #N closed the .zst-decompression
gap that left session `42c5` with an incomplete 117-capture / 12,821-
record view). Bytes at offsets +2 and +3 are NOT constant zero.
Observed u16 LE values:

| u16 LE | bytes | records | seen on |
|--------|-------|--------:|---------|
| `0x0000` | `00 00` | 45,773 (95.7%) | LG290P-paired captures (steady-state); most stationary + steady wardriving |
| `0xd80d` | `0d d8` | 1,433 (3.0%) | FN980 cold-reset captures, RM500Q wardriving, `<redacted-pii>*` GNSS sessions |
| `0xd816` | `16 d8` | 217 (0.5%) | Inseego M2000 5-min sessions only — same firmware, same chipset family (SDX55), distinct state value |
| `0xff00` | `00 ff` | 39 (0.1%) | FN980 `<redacted-pii>` only |
| `0xff01` | `01 ff` | 47 (0.1%) | FN980 `<redacted-pii>` (39) + wardriving fn980m capture (8) |
| `0xd80b` | `0b d8` | 62 (0.1%) | Inseego M2000 60s session only — distinct from the M2000 5-min `0xd816` value |
| `0xc002` | `02 c0` | 19 (0.0%) | EM7511 `<redacted-pii>` only |

45 captures show **intra-capture** variance at +2 (vs 10 in the prior
incomplete-corpus walk), the strongest signal that this is a real per-
record state field rather than a per-firmware constant. Variance
correlates with GNSS-subsystem state transitions (cold reset, full
reboot, post-reset, sustained-tracking session boundaries).

Two patterns to note:

- **Inseego M2000** captures emit alternating ZERO / NON-ZERO records
  within a single session, with the non-zero u16 differing across
  ostensibly-similar firmware sessions (5-min sessions show `0xd816`,
  the 60s session shows `0xd80b`). That's consistent with the non-zero
  u16 being a session-counter / restart-state register fixed within
  one session but distinct between sessions.
- **FN980 06_boot_plus_gnss_post_reset** holds +3=0xff while +2 toggles
  0x00/0x01 within the same capture — a 1-bit fast-toggling state
  superimposed on a slower-changing high byte.

The earlier "01 8d 00 00 is constant" claim was a fixture-bias artefact
— all three test fixtures (EM9190 / LM960 / EG25-G) were drawn from
steady-state captures, missing the state-transition modes.

The `header_marker` u32 field still carries the literal `bytes[0:4]` LE
value, so consumers comparing it to `0x00008d01` will see one of the
variant values (`0xd80d8d01`, `0xc0028d01`, …) on state-transition
records — those are *correct*, not corruptions.

### Per-SV slot layout (28 B, mostly opaque)

```
+0:  u8     reserved/fill (often 0x00)
+1:  u8     stride_marker (often 0x1c = 28 in active slots)
+2:  u8     sv_index_or_state
+3:  u32    active_marker = 0x01004085 (LE) when slot is filled, else zero
+7:  9 B    zero
+16: u32    metric_or_cn0 (e.g. 0x003dd885 — pattern 0x003dxxxx common)
+20: 8 B    zero
```

Slot is treated as "active" (a satellite is being tracked there) iff bytes
[+3..+7] == `85 40 00 01`. Inactive slots are all-zero (or near-zero) padding.

## Cross-chipset findings

- 3952B fixed-size and 4B header (`+0 = 0x01`, `+1 = 0x8d`, `+2:+4` state
  field) verified across EM9190 (SDX55), LM960 (SDX20), EG25-G (MDM9x07);
  also EM7511 (SDX55), EP06A/EG18NA/EG12-GT (MDM9x07), FN980 (SDX55),
  m2000 (SDX55 hotspot), RM500Q-AE (SDX55), MC7455 (MDM9x30), SimCom
  SIM7600NA, wistron lv55, **and** RM520N-GL (SDX62, added 2026-04-28
  via the rm520ngl 2026-04-21 + 2026-04-27 LG290P captures).
- Bytes `+0=0x01` and `+1=0x8d` are corpus-invariant; bytes `+2:+4` are a
  per-record state field (see "Header-state field" above). The widely-
  cited "`01 8d 00 00` constant" was a fixture-bias claim — retracted.
- **SDX62 uses the SAME 4B + 141 × 28B record skeleton as SDX55** (session
  ``kali`` 2026-05-07 finding) — the v3 docstring's "chipset-divergent
  per-slot layout" framing was overstated. The structural divergence is at
  per-slot-byte invariants only; the record-level shape, slot stride, and
  measurement-offset position are all identical across chipset families.
  Slot-internal differences on SDX62 (rm520ngl 25-record walk over
  ``gnss_comparison_lg290p_2026-04-27``):

  | slot offset | SDX55/SDX20/MDM9x07 | SDX62 (older firmware) |
  |------------:|---------------------|-------|
  | +0          | 0x00 / 0x80 (slot_flag) | 0x00 / 0x01 / 0x03 / 0x09 (4 values) |
  | +1          | 0x1c (chipset-family marker — NOT the stride) | 0x13 |
  | +2          | varies (sv_id_or_state) | 0x00 / 0x01 |
  | +3..+6      | ``85 40 00 01`` (active_marker) | 4-pattern set: ``07 c6 40 09`` / ``07 c6 40 06`` / ``08 d0 00 03`` / ``08 84 00 04`` |
  | +7..+15     | 0 (reserved) | 0 (same) |
  | +16..+18    | u24 measurement | u24 measurement (SAME offset!) |
  | +19..+27    | 0 (reserved) | 0 (same) |

  Critically, the `_count_active_slots = 0` reading on SDX62 is an
  artefact of the parser checking for the exact ``85 40 00 01`` marker
  bytes — the SDX62 records DO contain measurements at slot+16..+18
  (3,525 slot samples × 256 distinct LSB values), they just use a
  4-pattern set at slot+3..+6 instead of a single active-marker.  This is
  consistent with the splitter-paired LG290P confirming 5-6 Galileo
  PRNs locked on E6 sigid=8 during the SDX62 capture.  See #N.

  **2026-05-21 update (RM520N-GL R03A03 firmware divergence — #N).**
  The "older firmware" SDX62 layout above does NOT match the firmware on
  ``RM520NGLAAR03A03M4G`` (~94 records across two paired LG290P+PocketSDR
  captures, 2026-05-21 run2/run3).  R03A03 emits 0x1843 with the canonical
  4B header + 141×28B skeleton (header invariants ``+0=0x01``, ``+1=0x8d``
  still hold), but the per-slot tag distribution differs sharply:

  - Every slot is populated (0 all-zero slots out of 6486 in run2 / 6768
    in run3) — no "active vs inactive" notion.
  - Four large strata partition the 141-slot table by joint key
    ``(slot+3, slot+1)``:

    | stratum | slot+3 | slot+1 (run2/run3) | slot+2 | slots/rec |
    |---|---|---|---|---|
    | A | 0x85 | 0x1c / 0x1c | ∈ {0x09, 0x0c, 0x19, 0x59} (5 vals) | ~50 |
    | B | 0x04 | **0x02 / 0x16** (session-counter, flips by 0x14) | 0x00 | ~50 |
    | C | 0x85 | 0x07 / 0x07 | 0x33 | ~20 |
    | D | 0x04 | **0x01 / 0x15** (same session-flip) | 0x00 | ~20 |

  - ``85 40 00 01`` is NOT present at slot+3..+6 (so canonical
    active-marker detection still returns ``active_slot_count = 0`` on
    R03A03), but neither is the "older-firmware" 4-pattern set
    (``07 c6 40 09`` etc.).  R03A03 uses ``85 10 40 00`` (1383 in r2) /
    ``04 40 00 01`` (917) / ``85 10 80 00`` (911) and others.
  - **slot+18 is NOT a PRN.** It takes ALL 64 values {0..63} uniformly in
    every large stratum on both runs, which would be impossible for a
    real PRN field (truth differs between runs).  Within a sub-stratum,
    slot+18 sequences are monotonic with constant decrement (e.g.
    ``[16, 11, 7, 2, 62, 57, 53, 48, 44, 39, 35]``).  slot+18 is the high
    byte of a u22 measurement at ``slot[+16:+19]`` with top 2 bits
    reserved.
  - Small strata at e.g. ``(0x07, 0x01..0x06)`` and ``(0x07, 0x0f/0x10)``
    appear in BURSTS in the first 1-2 records of each run and then go to
    zero — GNSS subsystem init / state-transition events, not periodic
    per-SV measurements.

  Together this means: **on RM520N-GL R03A03, 0x1843 is structurally a
  per-correlator-channel state log, NOT a per-SV measurement table.**
  The 29% byte-diff between two paired captures (reported in #N
  comment 4510933736) is dominated by the session-counter byte at slot+1
  in 0x04-prefix strata plus monotonic measurement-vector evolution, not
  per-SV PRN content.  0x1843 is therefore **eliminated as a candidate
  for the SDX62 per-SV L1C/B1C measurement carrier hunt** (#N).
- Active-slot density observations below are only valid on SDX55 / SDX20
  / MDM9x07: EM9190 sees ~50 active slots per record (heavy E6
  tracking); LM960 sees ~2 (sparse — likely a sync-only state). SDX62
  is excluded until its slot layout is RE'd.

## Per-slot internals (RE'd 2026-04-27 from EM9190 + LM960 fixtures)

Cross-fixture variance analysis on 54 active EM9190 slots and 2 active
LM960 slots gave a clean structural breakdown:

```
+0  : u8   slot_flag       0x00 (28/54) or 0x80 (26/54) on SDX55/SDX20/
                           MDM9x07 — likely "tracked-locked" vs
                           "currently-acquiring".  SDX62: 0x00/0x01/
                           0x03/0x09 (different value range — semantics TBD).
+1  : u8   chipset_family_marker  0x1c on SDX55/SDX20/MDM9x07; 0x13 on
                           SDX62.  The session ``kali`` corpus walk
                           refuted v3's "stride_self_tag = 0x1c = 28 =
                           STRIDE" interpretation — the byte is NOT the
                           stride (it's 0x13 on SDX62 where the stride is
                           still 28).  Real semantics: chipset-family
                           signal-type marker.
+2  : u8   sv_id_or_state  varies (≤8 distinct values per record;
                           matches GAL E6 SV count expectation)
+3  : u32  active_marker   0x01004085 LE (already used for active detect)
+7  : 9 B  reserved zero
+16 : u24  measurement_24  3-byte LE measurement (~85% unique values;
                           candidate for C/N0 or integrator output)
+19 : 9 B  reserved zero
```

The 24-bit measurement at +16..18 is the primary slot-internal observable —
across 54 active slots, 46+ distinct values for the LSB and 48 for the
mid byte mean this is a real measurement field, not a counter.

## TBD for full closure (#N)

- Map `sv_id_or_state` byte values back to Galileo PRN numbering
  (PRN 1-36 expected; observed values 0x23, 0x51, 0x52, 0x56, 0x71,
  0x73, 0x74 — non-trivial encoding).  RTCM ground truth is available:
  every LG290P-paired capture (15 of them in this corpus) carries
  Galileo MSM7 type=1097 with sigid=8 (6C — E6 Commercial Service pilot)
  and named PRNs.  Cross-correlation tooling (timestamp-aligned modem
  active-slot list × LG290P E6 PRN list) would give the encoding directly.
- Decode the +2/+3 u16 LE state field. Observed values across the
  47,828-record corpus: `0x0000` (95.7%), `0xd80d` (3.0%), `0xd816`
  (0.5%, M2000-only), `0xff00` / `0xff01` (0.2%, FN980 boot+gnss),
  `0xd80b` (0.1%, M2000 60s), `0xc002` (0.0%, EM7511 reboot). Variance
  correlates with GNSS subsystem cold/warm reset transitions and with
  session boundaries; the M2000-specific values plus the FN980 toggling
  pattern hint at a per-session counter (high byte) plus a fast 1-bit
  toggle (low byte).
- Verify the 24-bit measurement units (C/N0 in dB-Hz × 100? doppler
  residual? carrier-phase fraction?) — needs AT-side cross-check or
  RINEX-pair correlation.
- Cross-validate active-slot count against parallel `LOG_GNSS_GAL_MEASUREMENT_
  REPORT_C` (0x1886) records on the same capture timestamp.
- AT cross-check via `AT$QGPSCFG="gpsnmeatype",X` for E6-tracked SVs.
- **RE the SDX62 per-slot layout.** RM520N-GL captures emit 0x1843 with
  the same 4B header + 141-slot × 28-byte structure, but use a
  different active-marker byte arrangement (`85 40 00 01` is absent;
  motifs like `85 10 40 00` / `07 c6 40 09` recur instead). Two
  LG290P-paired SDX62 captures with 107 combined records and full E6
  PRN truth ([7, 26, 29, 30, 33] on 2026-04-21; [4, 10, 11, 12, 19, 21]
  on 2026-04-27) are available for fixture-based variance analysis.
  **2026-05-21 update:** R03A03 firmware exposes a *different* per-slot
  layout from the older SDX62 captures above (see "RM520N-GL R03A03
  firmware divergence" in the cross-chipset findings section).  Two
  PocketSDR-paired R03A03 captures (94 records, 2026-05-21 run2/run3)
  rule out per-SV measurement-table semantics on R03A03 — slot+18 is the
  high byte of a u22 measurement, NOT a PRN field.  Folding the R03A03
  layout into the SDX62 active-slot detection is open; a separate
  Galileo E6 carrier (or different log code) needs to be located before
  #N can close on R03A03.

## Test fixtures

- `<redacted-pii>` — Sierra EM9190 SDX55 (3952B)
- `<redacted-pii>` — Telit LM960 SDX20 (3952B)
- `<redacted-pii>` — Quectel EG25-G MDM9x07 (3952B)

## Legacy fields

`time_counter_a` (bytes [4:8]) and `time_counter_b` (bytes [8:12]) were
documented in v1 as header timestamps but actually overlap with **slot 0's
body**. They're retained for backward compatibility but consumers should
prefer the new structural fields (`slot_count`, `active_slot_count`).

=== names-block:start (auto-generated by tools/inject_names_block_parsers.py) ===

Names by source (from sources/DIAG_LOG_INDEX.yaml):
    canonical: LOG_EVENTS_DS_GPRS_MAC_MSG_RECEIVED
        source: qxdm_3_12_714_2017_diag_log_codes (authority: community)
    aliases:
        LOG_EVENTS_GPRS_DS_MAC_MSG_RECEIVED
            source: qxdm_3_12_714_2017_diag_log_codes
        RESERVED
            source: qxdm_itemtype_list_zukgit_2025_04_03

Source-precedence (#N): vendor_official > observation >
community (specification) > community (reference).
=== names-block:end ===
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_GNSS_ME_GAL_E6
from diaggrok.registry import register


# Structural constants (RE'd 2026-04-24, header invariants corpus-verified 2026-04-27)
HEADER_BYTES = 4              # bytes [+0:+4] prefix; +0=0x01, +1=0x8d invariant; +2:+4 = u16le state
SLOT_STRIDE = 28              # per-SV slot size in bytes
SLOT_COUNT = 141              # (3952 - 4) / 28 = 141 exactly
ACTIVE_SLOT_MARKER = b'\x85\x40\x00\x01'  # bytes [+3:+7] within an active slot
ACTIVE_MARKER_OFFSET = 3      # offset within slot where the marker appears

# Layer-1 version gate (corpus-invariant: 47,828/47,828 records have data[0]=0x01
# across 233 captures spanning SDX20/MDM9x07/SDX55/SDX62, session `0b1d`
# 2026-04-28).  Future firmware revisions emitting 0x1843 with a different
# format-version byte MUST be rejected at parse time rather than silently
# mis-decoded into 141 garbage slots.
_EXPECTED_VERSION = 0x01


def _count_active_slots(data: bytes) -> int:
    """Count slots whose [+3:+7] bytes match the active-marker pattern."""
    count = 0
    for i in range(SLOT_COUNT):
        slot_start = HEADER_BYTES + i * SLOT_STRIDE
        marker_start = slot_start + ACTIVE_MARKER_OFFSET
        if marker_start + 4 > len(data):
            break
        if data[marker_start:marker_start + 4] == ACTIVE_SLOT_MARKER:
            count += 1
    return count


def _decode_active_slot(slot: bytes) -> dict[str, Any]:
    """Decode a single 28-byte active slot into its identified fields.

    Per-slot layout RE'd 2026-04-27 from cross-chipset variance analysis.
    Only invoked on slots where the active-marker pattern was already
    detected, so this never sees zero-padded inactive slots.
    """
    return {
        'slot_flag': slot[0],          # 0x00 (locked) or 0x80 (acquiring) — provisional
        'sv_id_or_state': slot[2],     # GAL PRN encoding TBD (#N)
        'measurement_24': (             # u24 LE at +16..18 — primary observable
            slot[16] | (slot[17] << 8) | (slot[18] << 16)
        ),
    }


def decode_slots(data: bytes) -> list[dict[str, Any]]:
    """Return per-active-slot decoded fields from a 0x1843 payload.

    Yields one dict per active slot, with the slot index, the decoded
    flag/sv_id/measurement_24 fields, and the raw 28-byte slot bytes.
    Inactive slots are skipped.  See `_decode_active_slot` for layout.
    """
    out: list[dict[str, Any]] = []
    for i in range(SLOT_COUNT):
        slot_start = HEADER_BYTES + i * SLOT_STRIDE
        if slot_start + SLOT_STRIDE > len(data):
            break
        slot = data[slot_start:slot_start + SLOT_STRIDE]
        marker_start = ACTIVE_MARKER_OFFSET
        if slot[marker_start:marker_start + 4] != ACTIVE_SLOT_MARKER:
            continue
        decoded = _decode_active_slot(slot)
        decoded['slot_index'] = i
        out.append(decoded)
    return out


@dataclass
class Diag0x1843:
    """Galileo E6 measurement report (0x1843) — skeleton + slot enumeration.

    Identifies header bytes and the 141-slot × 28-byte per-SV array, plus
    counts how many slots are actively tracking. Per-slot internal decode
    (sv_id, cn0, doppler, carrier-phase) remains open (see #N).

    E6 is the Galileo Commercial Service signal at **1278.75 MHz**,
    distinct from E1 (1575.42 MHz) and E5a (1176.45 MHz). RINEX 3.04
    obs codes for E6 pilot are the B-suffix family: ``C6B L6B D6B S6B``.
    The ``constellation`` / ``band`` fields are set so the RINEX writer
    (``apps/diaggpsd/rinex_writer.py``) can route records to the E6
    obs-code group once per-SV measurements are decoded (#N umbrella).
    """
    log_time: int
    version: int
    header_marker: int        # bytes [0:4] as u32 — varies with header_state (see docstring)
    time_counter_a: int       # u32 at offset 4 — LEGACY: slot-0 body bleed-through
    time_counter_b: int       # u32 at offset 8 — LEGACY: slot-0 body bleed-through
    payload_size: int
    # New structural findings (2026-04-24)
    slot_count: int           # constant 141 for the 3952B variant
    slot_stride: int          # constant 28
    active_slot_count: int    # how many slots have the active-marker pattern
    raw: bytes                # full payload retained for future RE
    constellation: str = 'Galileo'
    band: str = 'E6'

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1843',
            'log_time': self.log_time,
            'version': self.version,
            'header_marker': self.header_marker,
            'time_counter_a': self.time_counter_a,
            'time_counter_b': self.time_counter_b,
            'payload_size': self.payload_size,
            'slot_count': self.slot_count,
            'slot_stride': self.slot_stride,
            'active_slot_count': self.active_slot_count,
            'constellation': self.constellation,
            'band': self.band,
            'parser_status': 'skeleton',
            'parser_note': (
                '4B header + 141×28B slots; slot internals open — see #N '
                '(E6 infra — #N wired via band=E6)'
            ),
        }


# --- #N ground-truth recipe (Inseego M2000 / SDX55 target) ---------------
# Authored OFFLINE — every field is an unverified hypothesis until a hardware
# run flips hw_run_performed=True. Subsystem is GNSS (codes.py names this
# LOG_GNSS_ME_GAL_E6, Galileo E6); the names-block community alias
# "LOG_EVENTS_DS_GPRS_MAC_MSG_RECEIVED" is a low-authority mis-label
# contradicted by the 47,828-record RE + LG290P RTCM E6 ground truth (#N).
# The M2000 is a strong target: it is one of only two modems whose header-
# state field carries the distinctive 0xd816 (5-min sessions) / 0xd80b (60s
# session) values, and its SDX55 active-marker (85 40 00 01) is the variant
# the slot-active detection was built for. Only to_dict-exposed fields are
# grounded; the per-slot 24-bit C/N0 candidate is a skeleton field (slot
# internals unparsed) so it is documented in notes, not as a FieldGround.

@register(
    LOG_GNSS_ME_GAL_E6, domain="gnss",
    name="0x1843",
    description="Galileo E6 signal measurements — skeleton + 141-slot enum, slot internals pending (#N)",
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "v3 (2026-05-23, <redacted-ref> closure-rigor): added layer-1 byte-0 "
        "version gate (``data[0] != 0x01 → return None``) + matching "
        "layer-2 ``field_invariants={'version': {'enum': [0x01]}}``.  "
        "Corpus authority: <redacted-ref> 47,828/47,828 records across "
        "233 captures (SDX20 / MDM9x07 / SDX55 / SDX62).  Closes the "
        "silent-mis-parse hazard where a future firmware emitting "
        "0x1843 with a different format byte would still produce a "
        "141-slot decomposition.  No behavior change on existing "
        "captures.  "
        "v2 (2026-04-24): structural finding — 4B header + 141 × 28B per-SV "
        "slots, active-slot marker `85 40 00 01` at slot offset +3. "
        "Cross-chipset verified on EM9190 (SDX55), LM960 (SDX20), EG25-G (MDM9x07). "
        "Header invariants tightened 2026-04-27 (<redacted-ref>, /rtcm-revisit "
        "#N) via 117-capture corpus walk; refreshed 2026-04-28 (<redacted-ref>) "
        "after #N closed the .zst-decompression gap, expanding the corpus to "
        "233 captures / 47,828 records: bytes +0=0x01 and +1=0x8d are "
        "corpus-invariant (47,828/47,828 records); bytes +2:+4 form a u16le "
        "state field that varies with GNSS-subsystem state transitions and adds "
        "M2000-only `0xd816` / `0xd80b` and FN980-only `0xff00` / `0xff01` to the "
        "previously-known `0x0000` / `0xd80d` / `0xc002` set. Session 0b1d also "
        "discovered SDX62 slot-layout divergence: RM520N-GL emits 0x1843 with "
        "the canonical 3952B size + 4B-header layout but the per-SV slot "
        "active-marker `85 40 00 01` is absent (107/107 records have "
        "active_slot_count=0 despite splitter-paired LG290P confirming 5–6 "
        "Galileo PRNs on E6 sigid=8 — the SDX62 ABI evidently uses a different "
        "marker arrangement)."
    ),
    source_url="",
    # 11 named fields parsed (header + structural enum + active-slot count);
    # per-slot internals still opaque as raw — skeleton.
    # 11 parsed / 12 identified. (#N)
    fields_parsed=11,
    fields_identified=12,
    issues=(),
    # Layer-2 invariant (closure-rigor pass 2026-05-23, <redacted-ref>): byte 0
    # ``version`` is stably 0x01 across the 47,828-record / 233-capture
    # corpus walked in <redacted-ref> (SDX20 / MDM9x07 / SDX55 / SDX62).
    # Declared as enum so future format drift surfaces via
    # ``check_invariants()`` even if the parser-body layer-1 gate is
    # bypassed.  Matches the canonical two-layer defense pattern
    # established by 0xb80d / 0x7154 / 0x7155.
    field_invariants={"version": {"enum": [_EXPECTED_VERSION]}},
)
def parse_0x1843(log_time: int, data: bytes) -> Diag0x1843 | None:
    """Parse a LOG_GNSS_ME_GAL_E6 (0x1843) log payload — skeleton (#N).

    Layer-1 first-byte version-gate: ``version = data[0]`` MUST be the
    first byte validated.  Only ``0x01`` is corpus-observed; any other
    value indicates a firmware-format change that would silently
    mis-parse the downstream 141-slot grid if the gate were missing.
    """
    if len(data) < 12:
        return None
    if data[0] != _EXPECTED_VERSION:
        return None
    return Diag0x1843(
        log_time=log_time,
        version=data[0],
        header_marker=unpack_from('<I', data, 0)[0],
        time_counter_a=unpack_from('<I', data, 4)[0],
        time_counter_b=unpack_from('<I', data, 8)[0],
        payload_size=len(data),
        slot_count=SLOT_COUNT if len(data) == 3952 else (len(data) - HEADER_BYTES) // SLOT_STRIDE,
        slot_stride=SLOT_STRIDE,
        active_slot_count=_count_active_slots(data),
        raw=bytes(data),
    )
