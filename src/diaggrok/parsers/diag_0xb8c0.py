"""NR5G L1 Measurement Configuration (0xB8C0).

Active measurement set configuration. Variable-size records: 16B
(sentinel/empty), 100-732B (active config with per-cell entries).

Header (16 bytes) — offsets measured corpus-wide, version-aware:
    [0]     u8   version (0x08 SDX55/SDX65 majority; 0x07 SDX62 minority)
    [1]     u8   0x00 (invariant, both versions)
    [2]     u8   companion byte — 0x02 on v0x07 (SDX62), 0x00 on v0x08
    [3]     u8   0x00 (invariant, both versions)
    [4:8]   u32  record_descriptor: low byte [4]=0xFC marker (invariant,
                 both versions); [5:7] u16 = a content descriptor that
                 tracks the size class (e.g. v0x07: 184@372B, 96@196B);
                 [7]=0x00.
    [8:12]  u32  descriptor_word — not a free bitmask. High u16 = 0x0010
                 (=16 = header length) invariant across both versions
                 (653,328/653,329 v0x08 records; the 1 exception is an HDLC
                 misframe, see below). Low u16 is a small enum:
                   v0x07 (SDX62): 0x0C02 main body (3002) · 0x2C01 sub-format
                                  (55, echoes [12:16] id into the body; mostly
                                  size 516) · 0x04FE the 16B sentinel (189).
                   v0x08 (SDX55/SDX65): shares v0x07's main+sentinel enum —
                                  0x0C02 main body (618,765 = 94.7%) · 0x04FE
                                  the 16B sentinel (28,773 = 4.4%) · plus its
                                  own minority body sub-formats 0x2801 (4,992),
                                  0x4801 (786), 0x3007 (10), 0x8801 (2).
                                  Corpus-wide over all 653,329 v0x08 records
                                  (F3-VERDICT v0x08: GROUND, see below).
                                  The dominant v0x08 form is 0x0C02, same as
                                  v0x07 (a single 0x2801 record is not
                                  representative) — the real version
                                  discriminator is [2] (0x00 v0x08 / 0x02
                                  v0x07), not [8:12].
    [12:16] u32  record_id — for the 16B sentinel equals [8:12]
                 (0x001004FE); in the v0x07 0x2C01 sub-format this id is
                 echoed inside the body (a per-config identifier).

Body holds per-cell / per-beam configuration blocks. Their internal
layout is not field-decoded (surfaced raw via num_body_words); the
``num_cell_configs`` field is a size-derived CANDIDATE estimate
(extra // 40), not a decoded count — do not treat it as ground truth.

v0x07/v0x08 share the same size classes and the same main/sentinel
descriptor enum (0x0C02 / 0x04FE); they are told apart by [2] (0x02
v0x07 / 0x00 v0x08), and each carries its own minority body sub-formats
(v0x07: 0x2C01; v0x08: 0x2801/0x4801/…). A shared size does not imply a
shared format; each version is grounded on its own.

The B8C cluster (0xB8C0 config / 0xB8C8 trigger / 0xB8C9 results) are
related NR5G ML1 codes but, measured on v0x07 (SDX62), do not fire 1:1
synchronously — nearest-neighbour tick offsets run ~900-18000 ticks
(0/378 within 2 ticks). They share a subsystem, not a snapshot instant.
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


@dataclass
class Diag0xB8C0:
    """NR5G L1 Measurement Configuration (0xB8C0)."""

    log_time: int
    version: int
    record_descriptor: int
    meas_config_flags: int
    payload_size: int
    num_cell_configs: int
    num_body_words: int = 0  # count of non-zero u32 words in body
    content_descriptor: int = 0  # u16 [5:7] — exact raw read (size-class tracker)
    record_id: int = 0  # u32 [12:16] — exact raw read (per-config id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB8C0",
            "log_time": self.log_time,
            "version": self.version,
            "record_descriptor": self.record_descriptor,
            "meas_config_flags": self.meas_config_flags,
            "payload_size": self.payload_size,
            "num_cell_configs": self.num_cell_configs,
            "num_body_words": self.num_body_words,
            "content_descriptor": self.content_descriptor,
            "record_id": self.record_id,
        }


# ── Ground-truth recipe — WiGLE-indirect (rat-context) ───────────────────────
# 0xB8C0 is the NR5G L1 Measurement Configuration — the active measurement set
# (which NR cells/beams L1 is told to measure). WiGLE-indirect (rat-context):
# it bounds the NR neighbour set whose per-cell measurements (0xB8C8 trigger /
# 0xB8C9 results) feed WiGLE observations.
#
# F3-VERDICT v0x07: GROUND. RM520N-GL (SDX62) is the sole emitter of v0x07 in
# the corpus (3246 records / 5 captures; v0x08 is the SDX55/SDX65 majority on
# RM500Q/EM9190/RXM-G1/M2000). Grounding is structural + version-enumeration,
# corpus-wide over all 3246 v0x07 records:
#   • header invariants: [0]=0x07, [1]=0x00, [2]=0x02, [3]=0x00, [4]=0xFC,
#     [7]=0x00; [8:12] high-u16 = 0x0010 (=hdr len); [8:12] low-u16 enum
#     {0x0C02 main (3002), 0x2C01 sub-format (55), 0x04FE sentinel (189)}.
#   • single 16B sentinel form 07000200fc0c0000fe041000fe041000.
#   • the 0x2C01 sub-format is exactly the set whose [12:16] id is echoed in
#     the body (55/3057 populated) — a real discriminator, not noise.
# Oracles checked:
#   • F3: present and build-matched (67407 records) but silent on 0xB8C0's
#     config fields — the NR-meas F3 sites (rfmeas_mc.c, nrfw_meas.c,
#     rfmeas_mdsp.c) label RF-measurement execution (IRAT handles, script
#     sizes), never the ML1 measurement-set config this code snapshots. No 1:1
#     co-emission site → fields surfaced raw, not named.
#   • QCSuper / SCAT: no decode of 0xB8C0 — proprietary L1, not an RRC/NAS OTA
#     message; QCSuper emits only GSMTAP RRC/NAS.
#   • 0x60 events: present (~21-30 frames in F3-armed captures), not correlated.
#   • cluster co-emission with 0xB8C8/0xB8C9: not 1:1 synchronous on v0x07
#     (nearest-neighbour ~900-18000 ticks; 0/378 within 2 ticks).
# F3-VERDICT v0x08: GROUND. v0x08 is the SDX55/SDX65 majority (653,329 records
# / 134 captures — RM500Q, EM9190, RXM-G1, M2000, FN980, LV55, SIM8202).
# Grounding is structural + version-enumeration, corpus-wide over all 653,329
# v0x08 records:
#   • header invariants: [0]=0x08, [1]=0x00, [2]=0x00 (the version discriminator
#     vs v0x07's 0x02), [3]=0x00, [7]=0x00 — all 653,329/653,329.
#   • [4]=0xFC on 653,326/653,329 (3 HDLC-misframe records read 0xFD); [8:12]
#     high-u16 = 0x0010 (hdr len) on 653,328/653,329 (1 misframe reads 0xE515).
#     These ~4 sub-0.001% records are why [4] and high-u16 are not promoted to
#     registry field_invariants (a hard enum would reject real corpus traffic).
#   • [8:12] low-u16 enum {0x0C02 main (618,765=94.7%), 0x04FE sentinel
#     (28,773=4.4%), 0x2801 (4,992), 0x4801 (786), 0x3007 (10), 0x8801 (2)}.
#     v0x08 shares v0x07's 0x0C02 main + 0x04FE sentinel; its distinct sub-
#     formats are 0x2801/0x4801/0x3007/0x8801 (v0x07's is 0x2C01).
#   • single 16B sentinel form 08000000fc0c0000fe041000fe041000 (28,753),
#     differing from v0x07's only at [0] and [2].
#   • [5:7] content_descriptor tracks sub-format/size but not 1:1 with size
#     (e.g. size 212 carries cdesc {0x88,0x48}) — exposed raw, a content tag.
#   • record_id [12:16] echoed into body only 46/624,576 populated (rare on
#     v0x08; the 0x2C01 body-echo is a v0x07 thing).
# Oracles checked:
#   • F3: present and build-matched on v0x08 captures (RXM-G1 100% resolved;
#     RM500Q nrfw_meas.c 12,077 prints + rfe_nr5g_* sites) but silent on
#     0xB8C0's config-set fields — the NR-meas F3 sites label serving PCI /
#     RF-measurement execution, never the ML1 measurement-set config this code
#     snapshots. No 1:1 co-emission site → fields surfaced raw, not named.
#   • QCSuper / SCAT: no decode of 0xB8C0 on a v0x08 capture either — SCAT does
#     not handle this code; QCSuper emits only GSMTAP RRC/NAS frames.
#   • content (RXM-G1 hardware run, partial): num_cell_configs varies
#     {0,3,4,6,7,9,13}, meas_config_flags {1049854,1051650} — a real populated
#     varying count, but a single serving cell can't pin count->cell-set; the
#     per-cell body decode stays open (partial) on both versions.

@register(
    0xB8C0,
    name="0xB8C0",
    description="NR5G L1 active measurement set configuration — variable-payload (16-732B), v=0x08 (SDX55/SDX65, GROUND) + v=0x07 (SDX62, GROUND)",
    version=7,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "From [4] the record is a chain of 0xFC containers (u32 header "
        "type:8|length:12, length incl. header; tiles all 44 sampled "
        "v0x07/v0x08 records); a container whose length overruns the payload "
        "(truncated record) returns None (registry WARN). "
        "v0x07 GROUND (SDX62): RM520N-GL is the sole v0x07 emitter — "
        "corpus-wide structural grounding over all 3246 v0x07 records / 5 "
        "captures. Header invariants [0]=0x07 [1]=00 [2]=02 [3]=00 [4]=0xFC "
        "[7]=00; [8:12] high-u16=0x0010 (hdr len), low-u16 enum {0x0C02 main, "
        "0x2C01 sub-format, 0x04FE sentinel}; [12:16] record_id echoed in body "
        "for the 0x2C01 sub-format. B8C cluster not 1:1 synchronous on v0x07. "
        "v0x08 GROUND (SDX55/SDX65): the majority version — corpus-wide "
        "structural grounding over all 653,329 v0x08 records / 134 captures "
        "(RM500Q, EM9190, RXM-G1, M2000, FN980, LV55, SIM8202). [2]=00 is the "
        "discriminator (vs v0x07's 02); v0x08 shares v0x07's 0x0C02 main + "
        "0x04FE sentinel enum (0x0C02 94.7%, 0x04FE 4.4%) and adds minority "
        "sub-formats 0x2801/0x4801/0x3007/0x8801. [4]=0xFC / high-u16 0x0010 "
        "hold on all but ~4 HDLC-misframe records (kept out of hard "
        "invariants). On both versions F3 is present and build-matched but "
        "silent on this code's config fields (it labels RF-meas execution, "
        "not the ML1 config set), and QCSuper/SCAT do not decode this "
        "proprietary L1 code; the per-cell body stays undecoded. Cross-modem "
        "fixtures from RM500Q (v0x08 main-0x0C02 + sentinel) and RM520N-GL "
        "(v0x07 populated + 16B sentinel)."
    ),
    source_url="",
    fields_identified=8,
    fields_parsed=8,
    issues=(),
    field_invariants={
        "version": {"enum": [0x07, 0x08]},
    },
    wigle_direct=False,
    wigle_roles=("rat-context",),
    # Ground-truth recipe: WiGLE-indirect rat-context validation for v0x07
    # (RM520N-GL SDX62). Offline recipe; not hardware-run.
)
def parse_0xb8c0(log_time: int, data: bytes) -> Diag0xB8C0 | None:
    if len(data) < 16:
        return None
    version = data[0]
    if version not in (0x07, 0x08):
        return None
    # From [4] the record is a chain of 0xFC containers, each opened by
    # a u32 header type:8 | length:12 (length INCLUDES the header — the same
    # element grammar as 0xB8C5/0xB8C8/0xB8C9; [5:7] content_descriptor is
    # the first container's length). The chain tiles every sampled record.
    # A container that declares more bytes than the record holds means the
    # record was truncated — fail loud (registry WARN) instead of handing
    # back a record. Bytes after the chain (or a non-0xFC word) are tolerated.
    off = 4
    while off + 4 <= len(data) and data[off] == 0xFC:
        clen = (unpack_from("<I", data, off)[0] >> 8) & 0xFFF
        if clen < 4:
            break
        if off + clen > len(data):
            return None
        off += clen
    record_descriptor = unpack_from("<I", data, 4)[0]
    meas_config_flags = unpack_from("<I", data, 8)[0]
    content_descriptor = unpack_from("<H", data, 5)[0]  # exact raw [5:7]
    record_id = unpack_from("<I", data, 12)[0]  # exact raw [12:16]

    # CANDIDATE estimate only (not a decoded count) — the per-cell block
    # layout is not field-decoded; see module docstring.
    extra = len(data) - 16
    num_cell_configs = max(0, extra // 40) if extra > 0 else 0

    # Count non-zero u32 words in the body for data richness signal
    num_body_words = 0
    for off in range(16, len(data) - 3, 4):
        if unpack_from("<I", data, off)[0] != 0:
            num_body_words += 1

    return Diag0xB8C0(
        log_time=log_time,
        version=version,
        record_descriptor=record_descriptor,
        meas_config_flags=meas_config_flags,
        payload_size=len(data),
        num_cell_configs=num_cell_configs,
        num_body_words=num_body_words,
        content_descriptor=content_descriptor,
        record_id=record_id,
    )
