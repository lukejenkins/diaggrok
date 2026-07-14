"""LTE ML1 measurement parsers (0x18AC).

0x18AC — ML1 Inter-frequency Measurement
    Per-carrier measurements for neighbor cells on different frequencies.
    Emitted alongside 0x18AB. Two on-wire variants observed in the
    2026-05-08 corpus walk (131 captures, 341,742 records):
        v=0x01 / 70B  — SDX20 / older  (34.4% of records)
        v=0x04 / 119B — SDX55+ / SDX62 (65.6% of records)
    No v=0x02/0x03/0x05+ observed in any capture; the registry's
    field_invariants enum locks the recognition envelope.

0x18AB is parsed by lte_ml1_intra.py.

Reverse-engineered from SDX20 (LM960) and SDX55 (RM500Q) DLF captures.

v1: initial RE with heuristic per-entry decode for both versions.
v2 (#N metadata hygiene): declare version-enum field_invariant,
    reject records whose version byte isn't in {0x01, 0x04}, expose
    fields_identified=fields_parsed=2 at the header level.
v3 (#N v=4 58B-stride landing, 2026-05-24): cross-chipset-validated
    v=4 body framing as 3B outer header + 2× 58B cell records. Magic-byte
    anchors at absolute offsets 6, 23, 64, 81 declared as field_invariants
    and hard-rejected at parse time (validated against ~50K records across
    M2000/EM9190/FN980m/RM500Q/RM520N-GL — Inseego/Sierra/Telit/Quectel,
    SDX55 + SDX62). Per-cell measurement-word decode (PCI/RSRP/RSRQ at
    intra-cell +8..+14) remains stubbed pending AT+QENG cross-check.
v5 (#N v=1 70B cross-chipset structural framing, 2026-05-25):
    Cross-chipset histogram on 3 v=1 70B chipset families (LM960 Telit
    SDX20, MC7411 Sierra MDM9x07, EG18-NA Quectel SDX20 V2) — 18,561
    v=1 records across 4 captures — revealed that the v=1 body has the
    **same 2-cell-record skeleton as v=4**, just with shorter per-cell
    records (34B instead of 58B). The cell-magic anchors at intra-cell
    +0 (entry_marker == 0x01) and +3 (magic_a == 0x09) are IDENTICAL in
    position and value between v=1 and v=4 — a cross-version Qualcomm-
    spec invariant. v=1 magic_b sits at intra-cell +16 (vs v=4's +20)
    but takes the same 0x01 value. The bimodal f32-LE sign+exp byte at
    intra-cell +11 (0x3e/0xbe split ~45/45%) is also present in v=1,
    confirming that the per-cell measurement-region structure carries
    forward to SDX55+ — older firmware just exposes fewer high-card
    measurement bytes per cell.

    Replaces the prior v1 heuristic 3-carrier decode (which was wrong:
    `num_carriers` byte at outer +1 is a per-cell-semantic value, not
    a carrier-count divisor — dividing 68B by 3 produced phantom 22B
    blocks). The new framing:

        [0]     u8   version = 0x01
        [1]     u8   num_carriers (observed 0x01/0x02/0x03; not invariant)
        [2..35] cell record 1 (34B)
        [36..69] cell record 2 (34B)

    Per-cell magic-byte anchors (3 per cell, cross-vendor universal):
        intra +0  == 0x01  entry_marker
        intra +3  == 0x09  magic_a (== v=4 intra +3 magic_a)
        intra +16 == 0x01  magic_b
    Mismatch hard-rejects the record (mirrors the v=4 stride gate).

    Per-cell surfaces exposed for future field RE:
        intra +11 meas_high_byte (f32-LE sign+exp byte, bimodal 0x3e/0xbe)

    The heuristic `entries[]` list with guessed earfcn/pci/rsrp/rsrq
    values is removed for v=1 records — per the project closure rule
    "no records emitted with zero RSRP/RSRQ when corpus shows non-zero,
    no records emitted with guessed values either." Downstream WiGLE
    aggregation (tools/dlf_to_wigle.py) will simply skip v=1 0x18AC
    records until per-cell semantic decode lands (AT+QENG cross-check).

v4 (#N cross-chipset measurement-region characterization, 2026-05-25):
    Re-walked the same 5 cross-vendor v=4 fixtures (49,943 records,
    anchors-passed) with per-intra-cell-offset byte cardinality, u16-LE
    range, and float32-LE high-byte analysis. Findings:

    - `num_carriers == 1` is INVARIANT across all 49,943 records / 5
      chipsets / 4 vendors. Declared as a hard invariant. A future
      multi-carrier firmware variant will correctly fail this gate.
    - `num_cells` byte (outer +2) takes values {0x01, 0x02, 0x03, 0x16}.
      0x16 (=22) is not consistent with a literal cell count — likely a
      measurement-class enum. Echoed at intra-cell +1 in both cells. NOT
      declared as a hard invariant (semantic uncertain; new firmware may
      introduce values outside this set).
    - Intra-cell +11 byte is bimodal {0x3e dominant, 0xbe dominant} with
      ~10–15 neighbor values across vendors. This is the IEEE 754 byte-3
      (sign + top exponent bits) of an f32-LE measurement spanning
      intra-cell +8..+11. Decoded magnitude ≈ 0.125–0.5 (both signs);
      semantic unidentified (candidate: normalized SINR delta, doppler,
      or freq-offset estimate — not RSRP/RSRQ dBm directly). Surfaced
      on the cell record as `meas_high_byte` for downstream RE.
    - Intra-cell +19 byte ∈ {0x3e, 0x3f, 0x40}: per-chipset bimodal
      M2000 = 0x3f always, EM9190 = 0x40 always, Quectel/Telit mixed.
      Surfaced as `state_byte_19` — soft anchor, not invariant-enforced
      (cross-vendor split rules out single-value enum).
    - Intra-cell +7 and +2 bytes are vendor-firmware-specific (M2000 +7
      = 0x1f vs FN980m +7 = 0x03; M2000 +2 = 0x6f vs FN980m +2 = 0x6d).
      Documented but not exposed — they're vendor fingerprints, not
      semantic fields.
    - Intra-cell +25 byte varies widely per vendor (M2000: card=2;
      FN980m: card=9; RM500Q: card=17). Likely a per-vendor counter
      or status byte. Documented; not surfaced.

    No u16-LE offset cluster matches the PCI plausibility profile
    (0–503, low cardinality, narrow range). Either PCI lives in a
    non-aligned bit field within the +8..+25 region, or single-carrier
    captures don't exercise enough neighbor-PCI variety to reveal it.
    PCI/RSRP/RSRQ semantics remain open; recommend acquiring a paired
    DIAG × AT+QENG="neighbourcell" capture before claiming offsets.

=== names-block:start (auto-generated by tools/inject_names_block_parsers.py) ===

Names by source (from sources/DIAG_LOG_INDEX.yaml):
    canonical: LOG_GNSS_GTS_TIME_UPDATE
        source: qxdm_itemtype_list_zukgit_2025_04_03 (authority: community)
    aliases: (none recorded)

Source-precedence (#N): vendor_official > observation >
community (specification) > community (reference).
=== names-block:end ===
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from diaggrok.registry import register

LOG_LTE_ML1_INTER_FREQ_MEAS = 0x18AC

# v=4 framing constants. The 58-byte cell-record stride and the 4 magic-byte
# anchors below were cross-chipset-validated on 2026-05-16 against ~50K v=4
# records spanning Inseego M2000, Sierra EM9190, Telit FN980m, Quectel RM500Q,
# and Quectel RM520N-GL (4 SDX55 vendors + 1 SDX62). Other anchors observed
# on a single M2000 reference (offsets +5, +10, +22) were rejected as
# vendor-firmware artifacts after cross-validation.
_V4_RECORD_SIZE = 119
_V4_OUTER_HEADER_SIZE = 3
_V4_CELL_SIZE = 58
_V4_NUM_CELLS = 2
_V4_MAGIC_A_OFF = 6   # intra-cell +3 (cell1 abs 6, cell2 abs 64)
# intra-cell +3 is a PER-BUILD value (constant within a capture, varies across
# firmware), NOT a universal magic constant (#N, 2026-06-18). 0x09 across the
# original 5-vendor SDX55/62 RE cohort; 0x05 on RM520N-GL A0.303 (6,503 records
# that the prior single-value gate silently rejected despite intra+2==0x76,
# intra+20==0x01, num_carriers==1, valid f32, 119 B). Gate now accepts the
# OBSERVED enum; a third build value fails the gate (a known re-RE trigger, not
# silent garbage). The cross-firmware anchor is intra+20 (magic_b) == 0x01.
_V4_MAGIC_A_VALS = (0x05, 0x09)
_V4_MAGIC_B_OFF = 23  # intra-cell +20 (cell1 abs 23, cell2 abs 81)
_V4_MAGIC_B_VAL = 0x01

# v=4 per-cell byte surfaces exposed in v4-of-the-parser (#N 2026-05-25).
# Both offsets are intra-cell — add cell base (3 / 61) for absolute offset.
_V4_MEAS_HIGH_BYTE_OFF = 11   # IEEE 754 byte-3 of an f32-LE at +8..+11
_V4_STATE_BYTE_19_OFF = 19    # cross-vendor anchor candidate (∈ {0x3e, 0x3f, 0x40})

# v=1 framing constants (#N 2026-05-25 v=1 cross-chipset structural pass).
# Validated on 18,561 records across 4 captures / 3 chipset families
# (LM960 Telit SDX20, MC7411 Sierra MDM9x07, EG18-NA Quectel SDX20 V2):
# every anchor below holds at 100.0% on every capture.
_V1_RECORD_SIZE = 70
_V1_OUTER_HEADER_SIZE = 2
_V1_CELL_SIZE = 34
_V1_NUM_CELLS = 2
# Intra-cell offsets shared with v=4 (cross-version Qualcomm-spec anchors):
_V1_ENTRY_MARKER_OFF = 0    # intra +0 == 0x01 (cell1 abs 2, cell2 abs 36)
_V1_ENTRY_MARKER_VAL = 0x01
_V1_MAGIC_A_OFF = 3         # intra +3 == 0x09 (cell1 abs 5, cell2 abs 39)
_V1_MAGIC_A_VAL = 0x09
_V1_MAGIC_B_OFF = 16        # intra +16 == 0x01 (cell1 abs 18, cell2 abs 52)
_V1_MAGIC_B_VAL = 0x01
# Surface exposed for future field RE — not invariant-enforced:
_V1_MEAS_HIGH_BYTE_OFF = 11  # f32-LE sign+exp byte, bimodal 0x3e/0xbe (mirrors v=4)


@dataclass
class LteMl1InterFreqEntry:
    """Single inter-frequency measurement entry."""
    earfcn: int
    pci: int
    rsrp: float
    rsrq: float

    def to_dict(self) -> dict[str, Any]:
        return {
            'earfcn': self.earfcn,
            'pci': self.pci,
            'rsrp': self.rsrp,
            'rsrq': self.rsrq,
        }


@dataclass
class LteMl1InterFreqV4Cell:
    """v=4 per-cell record (58B intra-cell).

    Exposes the cell-record byte range, the two cross-chipset magic-byte
    anchors, and two characterized-but-not-decoded byte surfaces:

    - `meas_high_byte` (intra +11): byte-3 of an f32-LE candidate at
      intra-cell +8..+11. Observed bimodal {0x3e ≈ positive small,
      0xbe ≈ negative small} indicating a signed-magnitude measurement
      around 0.125–0.5 absolute. Exposed so downstream T1.5+
      ground-truthing can correlate against AT+QENG without re-parsing.
    - `state_byte_19` (intra +19): observed cross-vendor enum
      {0x3e, 0x3f, 0x40}. Per-chipset bimodal — not a hard invariant.

    Per-field PCI/RSRP/RSRQ semantics remain pending AT+QENG cross-check.
    See #N for the open RE work.
    """
    index: int
    abs_offset: int
    magic_a: int  # intra +3, validated 0x09 across 5 vendors
    magic_b: int  # intra +20, validated 0x01 across 5 vendors
    meas_high_byte: int  # intra +11, f32-LE sign+exp byte (bimodal 0x3e/0xbe)
    state_byte_19: int   # intra +19, enum {0x3e, 0x3f, 0x40}
    raw: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            'index': self.index,
            'abs_offset': self.abs_offset,
            'magic_a': self.magic_a,
            'magic_b': self.magic_b,
            'meas_high_byte': self.meas_high_byte,
            'state_byte_19': self.state_byte_19,
            'raw_hex': self.raw.hex(),
        }


@dataclass
class LteMl1InterFreqV1Cell:
    """v=1 per-cell record (34B intra-cell).

    Cross-chipset-validated on 18,561 v=1 records across LM960 Telit SDX20,
    MC7411 Sierra MDM9x07, and EG18-NA Quectel SDX20 V2 (#N, 2026-05-25).
    Three magic-byte anchors are universal across all 3 vendors / 4 captures
    (intra +0 == 0x01, intra +3 == 0x09, intra +16 == 0x01); the first two
    share their position and value with the v=4 58B cell records, indicating
    a cross-version Qualcomm-spec invariant.

    `meas_high_byte` (intra +11) is the byte-3 of an f32-LE measurement
    spanning intra +8..+11, observed bimodal {0x3e ≈ +small, 0xbe ≈ -small}
    at ~45/45% per cell across vendors — same pattern as v=4 intra +11.
    Semantic still open pending AT+QENG cross-check (#N).
    """
    index: int
    abs_offset: int
    entry_marker: int     # intra +0,  validated 0x01 across 3 vendors
    magic_a: int          # intra +3,  validated 0x09 across 3 vendors (== v=4 magic_a)
    magic_b: int          # intra +16, validated 0x01 across 3 vendors
    meas_high_byte: int   # intra +11, f32-LE sign+exp byte (bimodal 0x3e/0xbe)
    raw: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            'index': self.index,
            'abs_offset': self.abs_offset,
            'entry_marker': self.entry_marker,
            'magic_a': self.magic_a,
            'magic_b': self.magic_b,
            'meas_high_byte': self.meas_high_byte,
            'raw_hex': self.raw.hex(),
        }


@dataclass
class Diag0x18AC:
    """ML1 Inter-frequency Measurement (0x18AC)."""
    log_time: int
    version: int
    num_carriers: int
    entries: list[LteMl1InterFreqEntry] = field(default_factory=list)
    # v=4-only: outer-header num_cells + cell records + flattened anchor
    # values for registry-side check_invariants() enforcement.
    num_cells: int | None = None
    v4_cells: list[LteMl1InterFreqV4Cell] = field(default_factory=list)
    cell1_magic_a: int | None = None
    cell1_magic_b: int | None = None
    cell2_magic_a: int | None = None
    cell2_magic_b: int | None = None
    # v=4-only mirror of num_carriers so the field_invariants enum
    # {1} only applies to v=4 records (v=1 SDX20 uses 3-carrier layout
    # and would otherwise be falsely rejected). check_invariants()
    # ignores None for v=1.
    v4_num_carriers: int | None = None
    # v=1-only: 2x 34B cell records + flattened anchor values for
    # registry-side check_invariants() enforcement. All None on v=4.
    v1_cells: list[LteMl1InterFreqV1Cell] = field(default_factory=list)
    v1_cell1_entry_marker: int | None = None
    v1_cell1_magic_a: int | None = None
    v1_cell1_magic_b: int | None = None
    v1_cell2_entry_marker: int | None = None
    v1_cell2_magic_a: int | None = None
    v1_cell2_magic_b: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'type': 'Diag0x18AC',
            'log_time': self.log_time,
            'version': self.version,
            'num_carriers': self.num_carriers,
            'entries': [e.to_dict() for e in self.entries],
        }
        if self.version == 0x04:
            d['num_cells'] = self.num_cells
            d['v4_cells'] = [c.to_dict() for c in self.v4_cells]
            d['cell1_magic_a'] = self.cell1_magic_a
            d['cell1_magic_b'] = self.cell1_magic_b
            d['cell2_magic_a'] = self.cell2_magic_a
            d['cell2_magic_b'] = self.cell2_magic_b
            d['v4_num_carriers'] = self.v4_num_carriers
        elif self.version == 0x01:
            d['v1_cells'] = [c.to_dict() for c in self.v1_cells]
            d['v1_cell1_entry_marker'] = self.v1_cell1_entry_marker
            d['v1_cell1_magic_a'] = self.v1_cell1_magic_a
            d['v1_cell1_magic_b'] = self.v1_cell1_magic_b
            d['v1_cell2_entry_marker'] = self.v1_cell2_entry_marker
            d['v1_cell2_magic_a'] = self.v1_cell2_magic_a
            d['v1_cell2_magic_b'] = self.v1_cell2_magic_b
        return d


# Ground-truth recipe (#N). RM520N-GL (SDX62) emits v=0x04 (it is one of the
# 5 cross-validated v=4 chipsets). This is a DISCOVERY design, not a confirmation:
# the per-cell PCI/RSRP/RSRQ semantics are open (#N). The parser surfaces
# meas_high_byte (byte-3 of an undecoded f32-LE measurement) — the recipe
# prescribes the AT+QENG="neighbourcell" correlation that recovers its identity
# AND scale. The magic_a/magic_b anchors are structural constants (not grounded).

@register(LOG_LTE_ML1_INTER_FREQ_MEAS, domain="lte-signal",
    name="0x18AC",
    description="Per-carrier inter-frequency cell measurements (neighbor frequencies)",
    version=14,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "SDX20/SDX55/SDX62 DLF capture analysis. v3 (2026-05-24, #N) "
        "landed the cross-chipset-validated v=4 body framing as 3B outer "
        "header + 2x 58B cell records with 4 magic-byte anchors at abs "
        "offsets 6, 23, 64, 81 (validated on ~50K v=4 records across 5 "
        "vendors / SDX55 + SDX62). v4 (2026-05-25, #N) added a hard "
        "num_carriers={1} invariant after re-walking the same 5 fixtures "
        "(49,943 anchors-passed records, 100% num_carriers=1), and "
        "exposed two characterized-but-not-decoded per-cell surfaces: "
        "meas_high_byte (intra +11; f32-LE sign+exp byte, bimodal 0x3e/0xbe) "
        "and state_byte_19 (intra +19; enum {0x3e, 0x3f, 0x40}). v5 "
        "(2026-05-25, #N) landed v=1 70B cross-chipset structural framing "
        "after a per-offset histogram on 18,561 v=1 records across 4 captures "
        "/ 3 chipset families (LM960 Telit SDX20, MC7411 Sierra MDM9x07, "
        "EG18-NA Quectel SDX20 V2): same 2-cell skeleton as v=4 but with "
        "34B per-cell records, 6 cross-vendor magic-byte anchors (3 per cell, "
        "all 100% across all captures), and intra-cell +0/+3 anchors shared "
        "with v=4 — a cross-version Qualcomm-spec invariant. Heuristic "
        "v=1 carrier-block decode (entries[] with guessed earfcn/pci/rsrp/rsrq) "
        "removed per the project closure rule (no records emitted with "
        "guessed values). Per-cell PCI/RSRP/RSRQ semantics still pending "
        "AT+QENG cross-check for both v=1 and v=4."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=14,
    fields_parsed=14,
    field_invariants={
        "version": {"enum": [0x01, 0x04]},
        # v4_num_carriers: invariantly 1 across 49,943 v=4 records / 5
        # chipsets / 4 vendors (2026-05-25 re-walk, #N). Scoped to v=4
        # via the v4_num_carriers field (None on v=1 records so v=1 SDX20
        # 3-carrier layout isn't falsely rejected). A future multi-carrier
        # v=4 firmware variant will correctly fail this gate rather than
        # emit silent garbage from a wrong-shaped body decode.
        "v4_num_carriers": {"enum": [1]},
        # v=4 58B-stride anchors. magic_b (intra+20) == 0x01 is the genuinely
        # cross-firmware constant (every capture examined). magic_a (intra+3) is
        # a PER-BUILD value — 0x09 (SDX55/62 cohort) / 0x05 (RM520N-GL A0.303);
        # its enum is the OBSERVED set, so a future build value is rejected
        # rather than silently mis-parsed (#N). Only populated on v=4
        # records; check_invariants() ignores None.
        "cell1_magic_a": {"enum": list(_V4_MAGIC_A_VALS)},
        "cell1_magic_b": {"enum": [_V4_MAGIC_B_VAL]},
        "cell2_magic_a": {"enum": list(_V4_MAGIC_A_VALS)},
        "cell2_magic_b": {"enum": [_V4_MAGIC_B_VAL]},
        # v=1 34B-stride anchors — cross-chipset validated on 18,561 records
        # across 3 chipset families (LM960 / MC7411 / EG18-NA). Only
        # populated on v=1 records; check_invariants() ignores None for v=4.
        # Intra +0 and intra +3 share their position and value with v=4
        # — a cross-version Qualcomm-spec invariant.
        "v1_cell1_entry_marker": {"enum": [_V1_ENTRY_MARKER_VAL]},
        "v1_cell1_magic_a":      {"enum": [_V1_MAGIC_A_VAL]},
        "v1_cell1_magic_b":      {"enum": [_V1_MAGIC_B_VAL]},
        "v1_cell2_entry_marker": {"enum": [_V1_ENTRY_MARKER_VAL]},
        "v1_cell2_magic_a":      {"enum": [_V1_MAGIC_A_VAL]},
        "v1_cell2_magic_b":      {"enum": [_V1_MAGIC_B_VAL]},
    },
    wigle_direct=True,
    wigle_roles=("signal", "pci-earfcn-bridge", "rat-context"),
)
def parse_0x18ac(log_time: int, data: bytes) -> Diag0x18AC | None:
    """Parse 0x18AC — LTE ML1 Inter-Frequency Measurement.

    Header (both variants):
        [0]    u8   version (0x01 on SDX20 / older, 0x04 on SDX55+ / SDX62)
        [1]    u8   num_carriers

    Records whose version byte isn't in {0x01, 0x04} return None — the body
    layout is version-specific and decoding an unknown version against the
    wrong layout would produce silent garbage.

    v=0x04 framing (119B, SDX55+ / SDX62), cross-chipset-validated:
        [0]      u8   version = 0x04
        [1]      u8   num_carriers
        [2]      u8   num_cells  (observed values: 0x01, 0x02, 0x03)
        [3..60]  cell record 1  (58B)
        [61..118] cell record 2 (58B)

    Per-cell magic-byte anchors (cross-vendor universal, 5 chipsets / ~50K
    records / SDX55+SDX62): intra-cell offset +3 == 0x09 and intra-cell
    offset +20 == 0x01. Mismatch hard-rejects the record. Per-cell
    measurement words at intra-cell +8..+14 are exposed as raw bytes but
    not yet decoded into PCI/RSRP/RSRQ (AT+QENG cross-check pending, #N).

    v=0x01 framing (70B, SDX20 / older), cross-chipset-validated:
        [0]      u8   version = 0x01
        [1]      u8   num_carriers (observed 0x01/0x02/0x03; not invariant)
        [2..35]  cell record 1 (34B)
        [36..69] cell record 2 (34B)

    Per-cell magic-byte anchors (3 per cell, cross-vendor universal on
    18,561 records / 3 chipset families): intra +0 == 0x01 (entry_marker),
    intra +3 == 0x09 (magic_a), intra +16 == 0x01 (magic_b). Mismatch
    hard-rejects the record. Intra-cell +0 and +3 share their position
    and value with v=4, a cross-version Qualcomm-spec invariant. Per-cell
    PCI/RSRP/RSRQ semantics still pending AT+QENG cross-check (#N).
    """
    if len(data) < 2:
        return None

    version = data[0]
    if version not in (0x01, 0x04):
        return None
    num_carriers = data[1]

    entries: list[LteMl1InterFreqEntry] = []

    if version == 0x04:
        if len(data) != _V4_RECORD_SIZE:
            return None
        # Per-slot magic-byte gate (#N anchors; #N single-cell fix).
        # ~50K records confirm a POPULATED slot carries magic_a (intra+3) in
        # the observed per-build set and magic_b (intra+20) == 0x01. On
        # single-populated-cell records one 58B slot is zero-padding whose
        # anchors are BOTH 0x00 — perfectly correlated (intra+3==0x00 iff
        # intra+20==0x00 on the empty slot; the 0x00 at intra+3 is padding,
        # not a third magic_a build value). The old gate required BOTH slots
        # to be populated and silently dropped these records (EM9291 SWIX65C:
        # 2 records lived only in the cell-2 slot). Now each slot is one of:
        #   POPULATED — magic_a ∈ _V4_MAGIC_A_VALS and magic_b == 0x01
        #   EMPTY     — magic_a == 0x00 and magic_b == 0x00 (padding)
        #   INVALID   — anything else → hard-reject (format-invariance guard)
        # At least one slot must be populated; an all-padding record is not a
        # usable measurement and is rejected.
        cell1_off = _V4_OUTER_HEADER_SIZE
        cell2_off = _V4_OUTER_HEADER_SIZE + _V4_CELL_SIZE
        c1ma = data[_V4_MAGIC_A_OFF]
        c1mb = data[_V4_MAGIC_B_OFF]
        c2ma = data[_V4_MAGIC_A_OFF + _V4_CELL_SIZE]
        c2mb = data[_V4_MAGIC_B_OFF + _V4_CELL_SIZE]
        c1_pop = c1ma in _V4_MAGIC_A_VALS and c1mb == _V4_MAGIC_B_VAL
        c2_pop = c2ma in _V4_MAGIC_A_VALS and c2mb == _V4_MAGIC_B_VAL
        c1_empty = c1ma == 0x00 and c1mb == 0x00
        c2_empty = c2ma == 0x00 and c2mb == 0x00
        if (not c1_pop and not c1_empty) or (not c2_pop and not c2_empty):
            return None
        if not c1_pop and not c2_pop:
            return None  # both slots empty padding — no measurement
        num_cells = data[2]
        v4_cells = [
            LteMl1InterFreqV4Cell(
                index=idx,
                abs_offset=off,
                magic_a=data[off + _V4_MAGIC_A_OFF - _V4_OUTER_HEADER_SIZE],
                magic_b=data[off + _V4_MAGIC_B_OFF - _V4_OUTER_HEADER_SIZE],
                meas_high_byte=data[off + _V4_MEAS_HIGH_BYTE_OFF],
                state_byte_19=data[off + _V4_STATE_BYTE_19_OFF],
                raw=bytes(data[off:off + _V4_CELL_SIZE]),
            )
            for idx, off, pop in ((0, cell1_off, c1_pop), (1, cell2_off, c2_pop))
            if pop
        ]
        # Record-level magic fields feed check_invariants(); an empty slot's
        # magic stays None so the enum invariant skips it (0x00 isn't a build
        # value). check_invariants() ignores None — same as the v=1 path.
        return Diag0x18AC(
            log_time=log_time,
            version=version,
            num_carriers=num_carriers,
            entries=entries,  # per-cell PCI/RSRP/RSRQ decode pending (#N)
            num_cells=num_cells,
            v4_cells=v4_cells,
            cell1_magic_a=c1ma if c1_pop else None,
            cell1_magic_b=c1mb if c1_pop else None,
            cell2_magic_a=c2ma if c2_pop else None,
            cell2_magic_b=c2mb if c2_pop else None,
            v4_num_carriers=num_carriers,
        )

    # version == 0x01 — 70B SDX20-era body, cross-chipset-validated framing
    # (#N v5, 2026-05-25). Same 2-cell skeleton as v=4 but with 34B
    # per-cell records and 6 cross-vendor magic-byte anchors.
    if len(data) != _V1_RECORD_SIZE:
        return None
    v1_cell1_off = _V1_OUTER_HEADER_SIZE
    v1_cell2_off = _V1_OUTER_HEADER_SIZE + _V1_CELL_SIZE
    c1_marker = data[v1_cell1_off + _V1_ENTRY_MARKER_OFF]
    c1_ma     = data[v1_cell1_off + _V1_MAGIC_A_OFF]
    c1_mb     = data[v1_cell1_off + _V1_MAGIC_B_OFF]
    c2_marker = data[v1_cell2_off + _V1_ENTRY_MARKER_OFF]
    c2_ma     = data[v1_cell2_off + _V1_MAGIC_A_OFF]
    c2_mb     = data[v1_cell2_off + _V1_MAGIC_B_OFF]
    # 6-anchor magic gate. 18,561 records confirm these are cross-vendor
    # invariant on LM960 / MC7411 / EG18-NA; mismatch means the record
    # isn't a v=1 SDX20-era ML1 inter-freq measurement.
    if (c1_marker != _V1_ENTRY_MARKER_VAL or c1_ma != _V1_MAGIC_A_VAL
            or c1_mb != _V1_MAGIC_B_VAL):
        return None
    if (c2_marker != _V1_ENTRY_MARKER_VAL or c2_ma != _V1_MAGIC_A_VAL
            or c2_mb != _V1_MAGIC_B_VAL):
        return None
    v1_cells = [
        LteMl1InterFreqV1Cell(
            index=0,
            abs_offset=v1_cell1_off,
            entry_marker=c1_marker,
            magic_a=c1_ma,
            magic_b=c1_mb,
            meas_high_byte=data[v1_cell1_off + _V1_MEAS_HIGH_BYTE_OFF],
            raw=bytes(data[v1_cell1_off:v1_cell1_off + _V1_CELL_SIZE]),
        ),
        LteMl1InterFreqV1Cell(
            index=1,
            abs_offset=v1_cell2_off,
            entry_marker=c2_marker,
            magic_a=c2_ma,
            magic_b=c2_mb,
            meas_high_byte=data[v1_cell2_off + _V1_MEAS_HIGH_BYTE_OFF],
            raw=bytes(data[v1_cell2_off:v1_cell2_off + _V1_CELL_SIZE]),
        ),
    ]
    return Diag0x18AC(
        log_time=log_time,
        version=version,
        num_carriers=num_carriers,
        entries=entries,  # always empty for v=1; per-cell PCI/RSRP/RSRQ
                          # decode pending AT+QENG cross-check (#N)
        v1_cells=v1_cells,
        v1_cell1_entry_marker=c1_marker,
        v1_cell1_magic_a=c1_ma,
        v1_cell1_magic_b=c1_mb,
        v1_cell2_entry_marker=c2_marker,
        v1_cell2_magic_a=c2_ma,
        v1_cell2_magic_b=c2_mb,
    )
