"""0x1755 — LTE PHY measurement block, 4 chipset-keyed variants.

The code has four (size, version) forms, so a single fixed-size filter
(614 B) would reject ~20% of corpus records (the EG25-G/MDM9207 394B variant
alone is 14.4%).

Corpus walk (247 captures, 296,475 records) — 4 substantive (size, version)
profiles, one per major baseband generation:

  profile      | records  | share | chipset gen | example modems
  -------------+----------+-------+-------------+-----------------------
  614 / 0x04   | 235,996  | 79.6% | SDX55 + NR  | Inseego M2000, Telit FN980,
                                                  Sierra EM9190, Quectel RM500Q
  394 / 0x02   |  42,827  | 14.4% | MDM9207     | Quectel EG25-G
  390 / 0x01   |   5,926  |  2.0% | MDM9x30     | Sierra MC7455
  534 / 0x03   |   5,728  |  1.9% | MDM9x07     | Quectel EP06-A

Common header pattern across all 4: byte+1 = 0x01 (constant). Byte+0
encodes the chipset-gen-specific version. Past-the-header layouts differ
by generation; the MDM9x07/9x30 variants are smaller and likely simpler
than the SDX55 one.

One singleton outlier (600B/v=0x04, 1 record) excluded — likely a
truncated SDX55 record from a mid-capture interruption.

Body-field semantics per variant remain open. Cross-correlating byte+8
(consistently 0x05 across SDX55/MDM9207/MDM9x07 variants but 0x00 on
MDM9x30) with serving-cell EARFCN/PCI is a follow-up.

Body geometry — 390B / v=0x01 / MDM9x30 MC7455 (bounded 2,000-record
sample, 5 captures, MC7455-only):
  **390 = 5-byte header + 5 x 77-byte blocks.** Header [0:5]: only [2]
  varies (byte+0 version=0x01, byte+1=0x01 the cross-variant constant,
  [3]/[4] invariant). Each 77-byte block carries variable fields at
  block-relative offsets {0, 1, 2, 4, 25, 45} — consistent across all 5
  blocks; the rest of each block is invariant/reserved. Single-chipset
  so far (no second MDM9x30 modem to corroborate). The 5-block array shape
  echoes the header+N*block pattern of 0x1894 / 0x18F5 / 0x1C5F. Per-block
  field semantics (the {0,1,2,4,25,45} positions) still need serving-cell
  correlation.

- **614B / v0x04 geometry.**
  Per-offset invariance over 2000 RM500Q-AE 614B/v04 records: **554/614 bytes
  CONST (90%), 60 VAR** — and the body is the SAME 5-block-array family as the
  small variant above. Layout: `[0:32]` header (mixed const/var), then a
  **stride-121 array of 5 entries**, each a **98-byte fixed/mostly-zero block**
  (CONST runs at offsets 32/153/274/395/516) separated by a **23-byte variable
  field** (at 130/251/372/493). I.e. `32 + 5×98 + 4×23 = 614`. The 98B blocks are
  fixed-capacity sub-records, sparsely populated in this camped RF state (only the
  23B inter-block fields carry per-record data here). Per-entry field
  semantics still need serving-cell correlation. The 394B/534B variants have
  no geometry pass yet.

F3 grounding — per-version identity, from a co-temporal (±10..25 ms of the
code's own records) LTE-ML1/RF-LTE F3 cluster on each version's silicon:

  - **v0x01 (390B, MDM9x30)** — EM7455 all-diag+F3 capture, 309
    records @ ~500 ms. Co-temporal (±25 ms) F3: lte_ml1_sleepmgr_stm.c (1998),
    lte_ml1_rfmgr_stm.c (795), lte_ml1_rfmgr.c (507), lte_ml1_mdb.c (495),
    lte_ml1_md.c (473), lte_ml1_sm_idle.c (435), lte_mac_dl.c (538),
    rflte_mc_rx_config.c (142). GROUND (identity = LTE PHY/ML1).
  - **v0x02 (394B, MDM9207)** — EG25-G F3 capture,
    1487 records @ ~197 ms. Co-temporal (±10 ms) LTE-ML1 *measurement* prints:
    lte_ml1_mdb_idle.c "apply rsrp offset flag …" (43), lte_ml1_md.c "Ngbr srch
    req (earfcn …)" (16) — names the LTE-PHY *measurement* activity outright.
    GROUND (identity = LTE PHY measurement).
  - **v0x03 (534B, MDM9x07)** — F3 **ABSENT / N/A**: all 4 EP06-A captures
    carrying 0x1755 v0x03 (and every EP06-A capture in the corpus) have zero
    0x79/0x99/0x98 F3, so in-capture F3 grounding is not possible from the
    current corpus.
  - **v0x04 (614B, SDX55+)** — RM520N-GL SDX62 LTE-VoLTE capture, 1392
    records @ ~190 ms. Co-temporal (±25 ms) RF-LTE/NR-modem PHY: rflm_qlnk_
    policy_mgmt.c (31543), rflm_sqp.c (15754), rflm_qlnk_thread.cpp, plus
    lte_ml1_rfmgr.c / lte_rrc_stm.c (0x79). Corroborated by RM500Q
    (rflte_*/lte_LL1_*), RM520N-GL (lte_ml1_dlm_ard_new.c/lte_ml1_rfmgr.c) and
    SDX62 band 12 (rflte_msm.c) captures. GROUND.

Body-field (byte-offset) semantics remain open per variant — identity is
grounded, but no 0x1755 body byte is yet matched 1:1 to an F3-printed value.

Log name: LOG_EVENT_DS_HPLMN_TIMER_EXPIRED
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from diaggrok.registry import register

_1755_VARIANTS: dict[tuple[int, int], str] = {
    (614, 0x04): "lte_phy_614_v04",   # SDX55+ — M2000 / FN980 / EM9190 / RM500Q
    (394, 0x02): "lte_phy_394_v02",   # MDM9207 — Quectel EG25-G
    (390, 0x01): "lte_phy_390_v01",   # MDM9x30 — Sierra MC7455
    (534, 0x03): "lte_phy_534_v03",   # MDM9x07 — Quectel EP06-A
}


@dataclass
class Diag0x1755:
    """LTE PHY measurement (0x1755) — 4 chipset-keyed (size, version) variants.

    Body-field semantics per variant are open.
    """
    log_time: int
    version: int
    variant: str
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1755',
            'log_time': self.log_time,
            'version': self.version,
            'variant': self.variant,
            'payload_size': self.payload_size,
        }


# Ground-truth recipe — keyed to the Foxconn T99W640 (SDX72). The body fields
# (per-variant) remain open; this recipe confirms the SDX55+ 614/v04 variant on
# SDX72 hardware and leaves the body semantics to a body-decode pass.

@register(
    0x1755,
    name="0x1755",
    description="LTE PHY measurement (0x1755) — 4 chipset-keyed variants spanning MDM9x30..SDX55+; header u32@4 = 1 kHz metronome tick",
    version=8,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    # METRONOME: the header field u32 @offset 4 is a
    # monotonic system tick, a clean linear function of the record ts64 — R²=1.0 with
    # Δts64/Δtick == 52428.8 on BOTH a Wistron LV55 (SDX55, n=37) and a Casa CFW-3212
    # (SDX62, n=1403) capture, in the shared 614B/v04 variant. 52428.8 ts64-units ==
    # exactly 1 ms (ts64 unit = 1/52428800 s), so it is a 1 kHz / 1 ms hardware clock
    # (same family as 0x1646). A u32 read at off=3 gives a ratio of 204.8 instead:
    # that is a one-byte misalignment shadow (÷256, 52428.8/256 == 204.8); the
    # aligned field is off=4. The same
    # 1 ms tick value is also mirrored at body offsets 130 and 493. Metronome only
    # (no wall/GPS-time mapping → not ts-anchor).
    timebase_roles=("metronome",),
    source_detail=(
        "Per-version F3 identity bound to co-temporal LTE-ML1/RF-LTE prints on "
        "each variant's own silicon — v0x01 GROUND (em7455 MDM9x30: lte_ml1_* + rflte_mc_rx_config), "
        "v0x02 GROUND (EG25-G MDM9207: lte_ml1_mdb_idle 'rsrp offset' + lte_ml1_md "
        "'Ngbr srch earfcn'), v0x04 GROUND (RM520N-GL SDX62: rflm_* PHY + lte_ml1_rfmgr/"
        "lte_rrc_stm, corroborated by RM500Q/SDX62 sites). "
        "v0x03 F3-ABSENT/N/A — no EP06-A/MDM9x07 capture in the corpus carries any F3. "
        "Identity (LTE PHY measurement) grounded; body-field byte-offset semantics "
        "remain open per variant. timebase_roles=(metronome,): the header u32 "
        "@offset 4 is monotonic and "
        "linear in the record ts64 — R²=1.0 on both LV55 SDX55 (n=37) and CFW-3212 "
        "SDX62 (n=1403) in the 614B/v04 variant, Δts64/Δtick == 52428.8 == exactly "
        "1 ms (ts64 unit 1/52428800 s), i.e. a 1 kHz system tick. A read at off=3 "
        "gives 204.8 (a one-byte misalignment shadow, ÷256); off=4 is the aligned "
        "field, also mirrored at body offsets "
        "130/493. Cross-chipset → usable as a metronome for cross-file alignment + "
        "ts64 gap detection; metronome only (no wall/GPS-time mapping). "
        "Cross-chipset corpus walk: 296,475 records / "
        "247 captures. 4 substantive (size, version) profiles, one per "
        "major baseband generation: 614/0x04 (SDX55+ — M2000/FN980/EM9190/RM500Q, "
        "79.6%), 394/0x02 (MDM9207 EG25-G, 14.4%), 390/0x01 (MDM9x30 "
        "MC7455, 2.0%), 534/0x03 (MDM9x07 EP06-A, 1.9%). "
        "byte+1=0x01 is a corpus-wide invariant across all variants."
    ),
    source_url="",
    fields_identified=3,
    fields_parsed=3,
    issues=(),
    field_invariants={
        "version": {"enum": [0x04, 0x02, 0x01, 0x03]},
        "payload_size": {"enum": [614, 394, 390, 534]},
    },
)
def parse_0x1755(log_time: int, data: bytes) -> Diag0x1755 | None:
    if len(data) < 1:
        return None
    key = (len(data), data[0])
    variant = _1755_VARIANTS.get(key)
    if variant is None:
        return None
    return Diag0x1755(
        log_time=log_time,
        version=data[0],
        variant=variant,
        payload_size=len(data),
    )
