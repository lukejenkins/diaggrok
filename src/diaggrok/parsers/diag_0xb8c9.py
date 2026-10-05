"""NR5G L1 Measurement Results (0xB8C9).

Per-cell aggregate NR5G ML1 measurement results. Variable size.

Header (16 bytes) — offsets measured corpus-wide, version-aware
(4,747,762 records / 301 captures):
    [0]     u8   version — 0x00 SDX62/newer (2,532,692 = 53%) / 0x02
                 SDX55/SDX65 (2,215,070 = 47%). The registry version invariant.
    [1]     u8   0x00 (invariant, both versions — 4,747,762/4,747,762)
    [2]     u8   companion byte — the true chipset-family/FORMAT discriminator,
                 finer-grained than [0]:
                   0x00 on v0x02 (SDX55/SDX65) — 2,215,070
                   0x02 on v0x00 (SDX62: RM520N-GL/EM9291/RG520N-NA/cfw3212)
                        — 2,516,808
                   0x03 on v0x00 (T99W640 / Dell DW5934e) —
                        15,884; a distinct byte2 sub-format that byte0 alone
                        (0x00) does not separate. Exposed raw as ``companion``.
    [3]     u8   0x00 (invariant, both versions)
    [4:8]   u32  record_descriptor — on v0x02 the low byte [4]=0xFC is a fixed
                 marker; on v0x00 (both byte2=0x02 and 0x03) [4:8] is per-record
                 DATA, not a marker → v0x00 is a distinct header layout.
    [8:12]  u32  meas_config (bitpacked; tracks RAN state — idle 3/4 →
                 connected-DL 4/5 → band-lock 5 → settle 6)
    [12:16] u32  data_field

Body: per-cell result blocks surfaced RAW as ``(cell_word, meas_a, meas_b)``
u32 triplets. A bitpacked RSRP/RSRQ/SINR/beam reading is a hypothesis, not a
decode; ``num_cells`` is a size-derived CANDIDATE. Measured constant 12 on
RM520N-GL across idle/connected-DL(171k)/band-lock — a fixed measurement-slot
count, not a live-neighbour or traffic-driven count. Per-cell words do not
expose serving PCI 260 on a stationary single-cell camp → per-cell fields stay
PARTIAL pending a neighbour-rich / mobility drive.

Per-chipset version map (corpus-wide, byte0 / byte2):
    v0x02 (SDX55/65, [2]=0x00): RM500Q, EM9190, RXM-G1, SIM8202, LV55, M2000
    v0x00 (SDX62, [2]=0x02):    RM520N-GL, EM9291, RG520N-NA, cfw3212
    v0x00 (T99W640, [2]=0x03):  Foxconn/Dell DW5934e
A shared size does not imply a shared format — each version is grounded on its own;
the [2]=0x03 sub-format shares byte0 with SDX62 but carries new size classes
(244B/532B) not seen on SDX62 (see F3-VERDICT block below).

Fires with 0xB8C0 (Config) and 0xB8C8 (Trigger) as a related NR5G ML1
measurement cluster (shared subsystem, not a 1:1 snapshot instant).

Log name: LOG_NR5G_LL1_FW_RX_CONTROL_AGC
Also known as: NR5G LL1 FW RX Control AGC
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

# --- Ground-truth recipe ------------------------------------------------
# 0xB8C9 carries per-cell NR5G L1 measurement entries, but to_dict() exposes
# them as raw u32 triplets (cell_word, meas_a, meas_b) — a bitpacked
# RSRP/RSRQ/SINR/beam reading is a hypothesis, not a decode, so this recipe is
# a discovery design (recover identity AND scale), not a numeric-equality
# check. Naming caveat: the canonical log name is
# LOG_NR5G_LL1_FW_RX_CONTROL_AGC, which points at RX-AGC control rather than
# serving-cell RAN metrics — so each candidate word should be tested against
# BOTH a serving RSRP/RSRQ/SINR interpretation AND an AGC-gain interpretation
# before either is accepted. RM520N-GL (SDX62, v0x00) is the recommended
# validation modem. Fires synchronously with 0xB8C0 (Config) / 0xB8C8
# (Trigger) — pair by timestamp for measurement-config context.
#
# ── F3-VERDICT v0x02: GROUND (SDX55/SDX65) ──
# Structural + version-enumeration grounding, corpus-wide over all 2,215,070 v0x02
# records (301-capture sweep; emitters RM500Q/EM9190/RXM-G1/SIM8202/LV55/M2000).
# Header invariants [0]=0x02, [1]=0x00, [2]=0x00 (companion), [3]=0x00; [4]=0xFC
# marker (v0x02-specific); sizes {16 sentinel, 84, 156}. 16B sentinel form
# 02000000fc0c0000fe041000fe041000.
# ── F3-VERDICT v0x00: GROUND (SDX62 + T99W640) ──
# Structural + version-enumeration grounding, corpus-wide over all 2,532,692 v0x00
# records. byte0=0x00 splits by the [2] companion into two format sub-families:
#   • [2]=0x02 SDX62 (RM520N-GL/EM9291/RG520N-NA/cfw3212) — 2,516,808 records,
#     sizes {100, 180, 308}, [4:8] per-record data.
#   • [2]=0x03 T99W640/DW5934e (Foxconn, one firmware build) — 15,884 records
#     over 9 captures, sizes {100, 180, 244, 308, 532} — the 244B/532B classes
#     are not emitted by SDX62, so this is a real distinct sub-format, not
#     HDLC-misframe noise (coherent counts on one modem/firmware). The parser's
#     byte0 enum [0x00,0x02] lets it through as "v0x00"; ``companion`` is
#     exposed so a consumer can separate it.
# Oracles (both versions):
#   • F3: present and build-matched (RXM-G1 100% resolved; RM500Q nrfw_meas.c +
#     rfe_nr5g_* sites) but silent on this code's per-cell fields — the meas F3
#     sites label RF-measurement execution (IRAT tune, script build, RF
#     handles), never the ML1 per-cell result values here.
#   • QCSuper / SCAT: no decode — proprietary NR5G L1, not an RRC/NAS OTA
#     message (QCSuper emits GSMTAP RRC/NAS frames only; SCAT does not handle
#     this code).
#   • 0x60 events: absent in the F3-mask captures — not a source for L1 results.
#   • AT-side (T0→T2, RM500Q-AE v0x02): several fields (entries_count,
#     meas_config, entries_meas_b_min) show high raw |r| vs rsrp_prx but r_Δ
#     collapses toward 0 (co-drift, not causation) — rejected pending in-motion
#     data. Per-cell semantics stay PARTIAL.

@dataclass
class Nr5gL1MeasResultEntry:
    """A single cell measurement result entry."""

    cell_word: int  # primary u32 with cell measurement data
    meas_a: int  # u32 measurement word A
    meas_b: int  # u32 measurement word B

    def to_dict(self) -> dict[str, Any]:
        return {
            "cell_word": self.cell_word,
            "meas_a": self.meas_a,
            "meas_b": self.meas_b,
        }


@dataclass
class Diag0xB8C9:
    """NR5G L1 Measurement Results (0xB8C9)."""

    log_time: int
    version: int
    companion: int  # raw [2] — chipset-family/format discriminator (0x00 SDX55, 0x02 SDX62, 0x03 T99W640)
    record_descriptor: int
    meas_config: int
    num_cells: int
    payload_size: int
    entries: list[Nr5gL1MeasResultEntry] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": "Diag0xB8C9",
            "log_time": self.log_time,
            "version": self.version,
            "companion": self.companion,
            "record_descriptor": self.record_descriptor,
            "meas_config": self.meas_config,
            "num_cells": self.num_cells,
            "payload_size": self.payload_size,
        }
        if self.entries:
            d["entries"] = [e.to_dict() for e in self.entries[:8]]
        return d


def _element_overrun(data: bytes, start: int) -> bool:
    """True when a declared TLV element runs past the end of ``data``.

    Every element opens with a u32 header type:8 | length:12 | flags:12
    (length INCLUDES the header). Two framings are attested:
      * 0xFC container (all v0x02 and SDX62 / most T99W640 v0x00 records):
        its length covers the rest of the record (size-4 / size-12);
        consecutive 0xFC containers are walked as a chain.
      * 0xFD lead element (the 5440 B T99W640 [2]=0x03 record): a 64 B
        element followed by a FLAT list of elements (type 0x04 len 80 ...,
        0xFE len 4 terminator) that tiles the record.
    Any other leading word is unknown framing and is not judged here.
    Bytes after a 0xFC chain are tolerated (trailing data is out of scope);
    the flat 0xFD list must reach its 0xFE terminator, else it is truncated.
    """
    off = start
    if off + 4 > len(data) or data[off] not in (0xFC, 0xFD):
        return False
    flat = data[off] == 0xFD
    while off + 4 <= len(data) and (flat or data[off] == 0xFC):
        hdr = unpack_from("<I", data, off)[0]
        length = (hdr >> 8) & 0xFFF
        if length < 4:
            return False
        if off + length > len(data):
            return True
        off += length
        if flat and hdr & 0xFF == 0xFE:
            return False  # terminator reached; anything after it is tolerated
    # A flat list has no outer length, so its 0xFE terminator is the
    # structural end: running out of bytes before it means truncation.
    return flat


@register(
    0xB8C9,
    name="0xB8C9",
    description="NR5G L1 per-cell aggregate measurement results — variable-payload (16-532B), v=0x02 (SDX55/65, GROUND) + v=0x00 (SDX62 + T99W640, GROUND)",
    version=8,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Two versions, each grounded structurally corpus-wide (2,215,070 v0x02 "
        "SDX55/SDX65 + 2,532,692 v0x00 records over 301 captures). The "
        "companion byte [2] separates v0x00 into SDX62 ([2]=0x02) and "
        "T99W640 ([2]=0x03, with 244/532B size classes SDX62 never emits). "
        "The body is a 0xFC container (u32 type:8|length:12, length incl. "
        "header; at [4] on v0x02, [12] on v0x00) or, on the large T99W640 "
        "record, a 0xFD-led flat element list; an element overrunning the "
        "payload (truncated record) returns None (registry WARN). Per-cell "
        "entries are surfaced as raw 12-byte (cell_word, meas_a, meas_b) u32 "
        "triplets after the 16B header; the triplet walk is format-blind. "
        "num_cells is constant 12 on RM520N-GL (a fixed slot count). F3 is "
        "present but silent on the per-cell fields, QCSuper/SCAT do not "
        "decode this code, and AT-side correlations do not survive the "
        "co-drift test, so per-cell semantics stay partial. Cross-modem "
        "fixtures from RM500Q + RM520N-GL."
    ),
    source_url="",
    fields_identified=7,
    fields_parsed=7,
    issues=(),
    field_invariants={
        "version": {"enum": [0x00, 0x02]},
    },
    wigle_direct=False,
    wigle_roles=("rat-context",),
)
def parse_0xb8c9(log_time: int, data: bytes) -> Diag0xB8C9 | None:
    if len(data) < 16:
        return None
    version = data[0]
    if version not in (0x00, 0x02):
        return None
    # The element framing starts at [4] on v0x02 and at [12] on v0x00
    # (both [2]=0x02 SDX62 and [2]=0x03 T99W640, after the v0x00 preamble).
    # A declared element overrunning the payload means truncation — fail loud
    # (registry WARN) instead of silently dropping the partial last triplet.
    if _element_overrun(data, 4 if version == 0x02 else 12):
        return None
    companion = data[2]  # raw [2] — format discriminator (see docstring)
    record_descriptor = unpack_from("<I", data, 4)[0]
    meas_config = unpack_from("<I", data, 8)[0]

    # Estimate num_cells from body size (each cell block is ~36 bytes)
    extra = len(data) - 16
    num_cells = data[12] & 0x0F if len(data) > 12 else 0
    if num_cells == 0 and extra > 0:
        num_cells = max(1, extra // 36)

    # Extract per-cell measurement entries as triplets of u32 words
    entries: list[Nr5gL1MeasResultEntry] = []
    off = 16
    while off + 12 <= len(data):
        cell_word = unpack_from("<I", data, off)[0]
        meas_a = unpack_from("<I", data, off + 4)[0]
        meas_b = unpack_from("<I", data, off + 8)[0]
        # Skip all-zero blocks (padding)
        if cell_word != 0 or meas_a != 0 or meas_b != 0:
            entries.append(Nr5gL1MeasResultEntry(
                cell_word=cell_word, meas_a=meas_a, meas_b=meas_b
            ))
        off += 12

    return Diag0xB8C9(
        log_time=log_time,
        version=version,
        companion=companion,
        record_descriptor=record_descriptor,
        meas_config=meas_config,
        num_cells=num_cells,
        payload_size=len(data),
        entries=entries,
    )
