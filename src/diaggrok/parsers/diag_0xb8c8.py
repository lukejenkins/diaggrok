"""NR5G L1 Measurement Trigger (0xB8C8).

Small variable-payload records (16-68B) indicating NR5G ML1 measurement
trigger events. 16B sentinel when idle; 24/28/36/44B when triggers fire.

Header (16 bytes) — offsets measured corpus-wide, version-aware
(2,020,811 records / 289 captures):
    [0]     u8   version — 0x02 SDX55/SDX65 (572,776 = 28%) / 0x00 SDX62
                 (1,448,035 = 72%). The registry version invariant.
    [1]     u8   0x00 (invariant, both versions — 2,020,811/2,020,811)
    [2]     u8   companion byte — 0x00 on v0x02 (SDX55), 0x02 on v0x00
                 (SDX62). PERFECTLY anti-tracks [0] corpus-wide (byte0=0x02
                 ⟺ byte2=0x00 ×572,776; byte0=0x00 ⟺ byte2=0x02 ×1,448,035).
                 Exposed raw as ``companion``; same structure as 0xB8C0's [2].
    [3]     u8   0x00 (invariant, both versions)
    [4:8]   u32  record_descriptor — on v0x02 the low byte [4]=0xFC is a
                 fixed marker; on v0x00 [4:8] is NOT a marker but per-record
                 data (varied 0x00..0xFF), so the two versions have GENUINELY
                 DIFFERENT header layouts, not just a version tag.
    [8:12]  u32  trigger_config (includes trigger type in low bits)
    [12:16] u32  tail / counter

Body (when > 16 bytes): per-trigger entries; ``num_triggers`` counts
8-byte strides past the 16B header (a size-derived CANDIDATE, not a
field-decoded count).

Per-chipset version map (corpus-wide, byte0):
    v0x02 (SDX55/SDX65): RM500Q, EM9190, RXM-G1, SIM8202, LV55, M2000, FN980
    v0x00 (SDX62):       RM520N-GL, EM9291, RG520N-NA, cfw3212
A shared size does not imply a shared format — each version is grounded on its own.

Fires with 0xB8C0 (Config) and 0xB8C9 (Results) as a related NR5G ML1
measurement cluster (they share a subsystem, not a 1:1 snapshot instant —
see 0xB8C0 for the tick-offset measurement).
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


# --- Ground-truth recipe -------------------------------------------------
# Offline recipe (not hardware-run). The Telit FN980m (SDX55) emits v=0x02.
# Corpus caveat: every FN980m 0xB8C8 record in the corpus is the 16B sentinel
# (idle — num_triggers=0); the 8-byte per-trigger entries only appear when NR5G
# L1 measurement events actually fire. So this is an event-correlation recipe
# with a capture prerequisite: drive NR5G mobility (cell edge, handover,
# neighbour appearing) so measurement triggers populate the body. The fields
# ground by co-variation with observable NR signal changes, not by equality with
# any single AT reply.
#
# ── F3-VERDICT v0x02: GROUND (SDX55/SDX65) ──
# Structural + version-enumeration grounding, corpus-wide over all 572,776 v0x02
# records (289-capture sweep; emitters RM500Q/EM9190/RXM-G1/SIM8202/LV55/M2000/
# FN980). Header invariants: [0]=0x02, [1]=0x00, [2]=0x00 (companion, the version
# discriminator — anti-tracks [0]), [3]=0x00; [4]=0xFC descriptor marker (v0x02-
# specific); sizes {16 sentinel, 28, 36, 44}. 16B sentinel form
# 02000000fc0c0000fe041000fe041000 (shares the B8C0/B8C9 SDX55 sentinel shape,
# byte0 aside).
# ── F3-VERDICT v0x00: GROUND (SDX62) ──
# Structural + version-enumeration grounding, corpus-wide over all 1,448,035 v0x00
# records (emitters RM520N-GL/EM9291/RG520N-NA/cfw3212). Header: [0]=0x00,
# [1]=0x00, [2]=0x02 (companion), [3]=0x00; [4:8] is per-record data (not the
# v0x02 0xFC marker) → v0x00 is a distinct header layout; sizes {24, 44}.
# Oracles (both versions):
#   • F3: present and build-matched (RXM-G1, 100% resolved) but silent on this
#     code's trigger fields — the meas F3 sites (rflte_mc_meas.c, rfmeas_mc.c,
#     rfmeas_mdsp.c, lte_LL1_meas_ncell.c) label RF-measurement execution (IRAT
#     tune-away, script build, RF handles, source/target tech), never the ML1
#     trigger values this code snapshots. No 1:1 co-emission site.
#   • QCSuper / SCAT: no decode — this is proprietary NR5G L1, not an RRC/NAS
#     OTA message (QCSuper emits only GSMTAP RRC/NAS frames; SCAT does not
#     handle this code).
#   • 0x60 events: absent in the F3-mask captures; events report state
#     transitions, not per-slot L1 trigger values — not a source for these fields.
#   • AT-side (T0→T2 correlation, RM500Q-AE v0x02): trigger_config vs rsrp_prx
#     r=−0.957 (r_Δ −0.689, survives the co-drift test — highest |r| in the
#     run), +0.877 vs sinr_prx. A field named trigger_config behaving like a
#     signal magnitude is flagged CANDIDATE (stationary/1-cell/300s regime; an
#     in-motion recapture is needed to confirm). Body per-trigger fields stay
#     PARTIAL pending a neighbour-rich / mobility drive.

@dataclass
class Diag0xB8C8:
    """NR5G L1 Measurement Trigger (0xB8C8)."""

    log_time: int
    version: int
    companion: int  # raw [2] — chipset-family/format discriminator (anti-tracks version)
    record_descriptor: int
    trigger_config: int
    payload_size: int
    num_triggers: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB8C8",
            "log_time": self.log_time,
            "version": self.version,
            "companion": self.companion,
            "record_descriptor": self.record_descriptor,
            "trigger_config": self.trigger_config,
            "payload_size": self.payload_size,
            "num_triggers": self.num_triggers,
        }


@register(
    0xB8C8,
    name="0xB8C8",
    description="NR5G L1 measurement trigger events — small variable-payload (16-68B), v=0x02 (SDX55/65, GROUND) + v=0x00 (SDX62, GROUND)",
    version=7,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Two versions, each grounded structurally corpus-wide (572,776 v0x02 "
        "SDX55/SDX65 + 1,448,035 v0x00 SDX62 records over 289 captures). The "
        "companion byte [2] anti-tracks the version, and the header layouts "
        "differ ([4]=0xFC marker only on v0x02). The body is a 0xFC container "
        "(u32 type:8|length:12, length incl. header) at [4] (v0x02) / [12] "
        "(v0x00); a container whose length overruns the payload (truncated "
        "record) returns None (registry WARN). Sizes 16B (sentinel) to 68B; "
        "8-byte trigger entries follow the 16B header. Cross-modem fixtures "
        "from RM500Q + RM520N-GL. F3 is present but silent on the trigger "
        "fields, and QCSuper/SCAT do not decode this code; the "
        "trigger_config↔rsrp_prx correlation is a candidate only, and "
        "num_triggers is size-derived."
    ),
    source_url="",
    fields_identified=6,
    fields_parsed=6,
    issues=(),
    field_invariants={
        "version": {"enum": [0x00, 0x02]},
    },
    wigle_direct=False,
    wigle_roles=("rat-context",),
)
def parse_0xb8c8(log_time: int, data: bytes) -> Diag0xB8C8 | None:
    if len(data) < 16:
        return None
    version = data[0]
    if version not in (0x00, 0x02):
        return None
    # The body is a 0xFC container (u32 header type:8 | length:12,
    # length incl. header) at [4] on v0x02 and at [12] on v0x00 (after the
    # v0x00 preamble); its length equals size-4 / size-12 on every sampled
    # record. A container overrunning the payload means truncation — fail
    # LOUD (registry WARN). Bytes beyond the container chain are tolerated.
    off = 4 if version == 0x02 else 12
    while off + 4 <= len(data) and data[off] == 0xFC:
        clen = (unpack_from("<I", data, off)[0] >> 8) & 0xFFF
        if clen < 4:
            break
        if off + clen > len(data):
            return None
        off += clen
    companion = data[2]  # raw [2] — anti-tracks version (see docstring)
    record_descriptor = unpack_from("<I", data, 4)[0]
    trigger_config = unpack_from("<I", data, 8)[0]

    extra = len(data) - 16
    num_triggers = max(0, extra // 8) if extra > 0 else 0

    return Diag0xB8C8(
        log_time=log_time,
        version=version,
        companion=companion,
        record_descriptor=record_descriptor,
        trigger_config=trigger_config,
        payload_size=len(data),
        num_triggers=num_triggers,
    )
