"""LTE ML1 Neighbor Cell Measurement Response parser (0xB192).

0xB192 -- LTE ML1 Idle-Mode Neighbor Cell Measurement Request/Response
    Per-cell idle-mode neighbor measurements: EARFCN, PCI, RSRP, RSRQ Rx0/Rx1.
    Emitted during idle-mode cell search and reselection evaluation.

Payload structure (outer version 1, always 2 subpackets: request + response).
The subpacket `size` (u16 LE) is INCLUSIVE of the 4-byte subpacket header, so the
next subpacket begins at `offset + size`. Decode-complete map (#N, 2026-07-02,
verified across 55,521 corpus records / 7 QCA generations):

    [0]      u8   version (== 1; outer DIAG log version, L1-gated)
    [1]      u8   num_subpackets (== 2)
    [2:4]    u16  counter (per-capture constant config/instance marker, NOT SFN)

    Subpacket 0 (id=26) -- Request/Config, version-dispatched header:
        ver=2 (all modern): [0:4] u32 EARFCN(low18), [4:6] u16 num_cells|flag
                            (low5=count, bit5=meas-enable), [6:8] u16 reserved
        ver=1 (MC7700/MDM9200): [0:2] u16 EARFCN, [2:4] u16 flags
        Per-cell record (16 bytes): [0:4] u32 PCI(low9)+flags,
            [4:8] u32 timing0, [8:12] u32 timing1, [12:16] reserved.
        (Per-neighbour PCI byte-matches the response; timing0/1 are byte-
         identical to the response cell's +40/+44 pair.)

    Subpacket 1 (id=27) -- Response/Measurement, version-dispatched header:
        ver=4 & ver=56 (BYTE-IDENTICAL — 8-byte carrier header):
            [0:4] u32 EARFCN(low18, u32 so band-66 >65535 survives),
            [4:6] u16 num_cells, [6:8] u16 reserved
        ver=2 (MC7700/MDM9200 — 4-byte carrier header):
            [0:2] u16 EARFCN, [2:4] u16 num_cells
        Per-cell record (52 bytes, layout version-INDEPENDENT):
            [0:4]    u32  PCI (low 9 bits; upper bits 0 — no flags)
            [4:8]    u32  energy0  (per-Rx integrated energy, ~4-5e6)
            [8:12]   u32  energy1  (per-Rx integrated energy)
            [12:16]  u32  energy2  (integrated energy)
            [16:20]  u32  energy_wide0 (wide-scale accumulator, ~1.5e8)
            [20:24]  u32  energy_wide1 (wide-scale accumulator, ~1.9e8)
            [24:26]  u16  meas_index (small index/counter, 0..~1166)  <- the byte
                          the pre-2026-07-02 parser mis-decoded as RSRP (-raw/10)
            [26:28]  u16  reserved (0)
            [28:32]  u32  energy_filt (filtered energy, ~1.2e6)
            [32:36]  u32  reserved (0)
            [36:38]  u16  aux0 (semantics unresolved)
            [38:40]  u16  aux1 (semantics unresolved)
            [40:44]  u32  timing (== [44:48]; request-echoed timing/config)
            [44:48]  u32  timing (duplicate of [40:44])
            [48:52]  u32  reserved (0)

Reverse-engineered from corpus DLF/HDLC captures across MDM9200/9207/9230,
SDX20/50M/55/62, cross-validated against 0xB193 serving-cell encoding and
AT+QENG="neighbourcell" / QMI GetCellLocationInfo ground truth.

⚠️ There is NO calibrated dBm RSRP/RSRQ in this packet. The per-cell energy
words correlate with true RSRP *within* a single capture (r up to 0.85, time-
aligned) but carry NO capture-stable energy->dBm scale (the required slope is
~15, not the physical 1.0; the AGC-flattened energy varies <2x while true RSRP
swings 54 dB; the intercept drifts ~13 dB between captures). So entries.rsrp /
rsrq_* are None — see the #N discussion below and LteMl1NeighborCellEntry.

RSRP field semantics (#N — why entries.rsrp is REFUTED/PARTIAL everywhere):
    The per-cell rsrp `dBm = -raw/10.0` decode is WRONG, and not by a fixable
    fixed offset. The underlying LTE LL1 neighbour quantity is **SE / SNE linear
    energy** (signal energy / signal+noise energy raw integers — the firmware
    picks max(SE, SNE) per rx/tx), NOT dBm power. Quantitatively confirmed: the
    build-matched F3 (qdb GUID 404921d3) `lte_LL1_meas_ncell.c` NB_MEAS prints
    span max_SE 3,125..208,458,975 / max_SNE 2,330..131,592,553 over 992 lines —
    large, always-positive integers, exactly what *energy* (not dBm power) looks
    like. So the decoded -30..-63 dBm vs the true -97..-119 dBm "≈ constant
    ~-55 dB offset" seen across SDX55/SDX62/MDM9207/MDM9230 is the symptom of
    reading an energy word as dBm; a correct decode needs an energy→dBm
    reference conversion (log + per-band reference-power offset), NOT a tweak to
    -raw/10.0. See #N (LL1 energy semantics) and #N (the 0x187B sibling —
    same subsystem, same treatment).

    Bit-width proof (#N, 2026-06-16) — `entries.rsrp` is NOT the *raw* SE/SNE
    accumulator, and cannot be made to be: this field is a **u16** ([24:26],
    ≤ 65535), but the NB_MEAS raw energy spans up to max_SE 2.08e8 / max_SNE
    1.36e9 (~28–31 bits). A 16-bit field physically cannot hold a 31-bit value,
    so what 0xB192 stores is necessarily a firmware-*converted/compressed*
    representation of the energy (log-domain or reference-relative), never the
    raw word. So the energy reading is provenance — it explains the ~55 dB
    constant offset of the naïve -raw/10.0 decode — but the raw SE/SNE energy is
    UNRECOVERABLE from this narrow stored field. Grounding therefore requires the
    NB_MEAS F3 (the full-width energy oracle, lte_LL1_meas_ncell.c) plus a
    controlled varied-signal capture pairing this stored word with truth dBm to
    fit the firmware's energy→u16 conversion — not a re-interpretation of the
    stored word as raw energy. (0x187B's 12-bit RSRP bitfield fails the same
    test even harder.)

    Paired-truth fit RETRACTED (#N, 2026-06-18) — a 2026-06-17 pass reported
    `true_dBm ≈ 0.146·raw_u16 − 164` (R²≈0.94) from 6 (pci,earfcn) cells and
    called the scale "not locked, needs more RSRP levels." A **time-resolved**
    re-analysis of the SAME LV55 capture (`…211618Z-…-atjsonrpc`) RETRACTS that
    fit: it was a 2-point (2-EARFCN-cluster) artifact, not a per-cell law.
    Method: join EACH 0xB192 cell-entry to the nearest-in-time `$QCRSRP` poll by
    (pci,earfcn) — the `$QCRSRP` truth is embedded in this capture's F3 stream
    (dsatrsp.c) and **varies over time** — yielding 157 paired samples, 65
    distinct raw_u16, 40 distinct true dBm spanning −102..−119 (vs the prior 6
    static points). Result:
      * GLOBAL linear fit collapses to R²=0.39 once within-cluster scatter is
        admitted — the 0.94 was pure between-cluster leverage (2 means).
      * WITHIN the rich earfcn-66536 cluster (145 pairs): pearson(raw,true) =
        **0.008** (≈ zero); bucketed mean-true is FLAT (~−115.5 dB) across raw
        300→376. Tight time-matches (dt ≤ median, n=73): pearson 0.07.
      * Cleanest test — a SINGLE fixed cell pci=263/earfcn=66536 (n=117): raw
        varies 300..376 while its OWN true RSRP varies −118.8..−111.5, and
        pearson(raw,true) = **−0.020**. Same physical cell, real RSRP moving,
        stored field NOT tracking it.
    So the field at cell_offset+24 read as `−raw/10` (decodes −30..−37 dBm here,
    physically impossible vs true −115) does **not** track this neighbour's RSRP
    at all — refuting the "monotonic, scale-recoverable-with-more-levels" hope:
    the levels are now in hand and the correlation is zero. This re-points at the
    standing **suspected SDX per-cell layout/offset drift** (the entries.pci
    misalignment flagged on this same LV55/SDX55 + CFW-3212/SDX62 cells): +24 is
    likely NOT the RSRP slot on SDX silicon. Locking RSRP needs the correct
    per-cell offset table (cf. #N 0xB193 SDX offset work), not more captures.

    Offset-scan + energy-field location (#N, 2026-06-18) — the exhaustive
    per-offset scan the prior pass scoped ("needs the correct per-cell offset
    table") was run: for the fixed neighbour pci=263/earfcn=66536 (166 samples,
    true RSRP −118.8..−111.5), EVERY byte offset 0..50 of the 52-B cell record
    was decoded as u16 and correlated (per-cell-demeaned, tight-time-matched)
    against the co-temporal $QCRSRP truth. Findings:
      * **+24 confirmed NOT RSRP** by an independent method — within-cell-demeaned
        pearson(Δraw,Δtrue) = **−0.085** (all) / **+0.011** (tight). Zero.
      * **No offset recovers RSRP cleanly** — the best-tracking region is
        cell_offset **+8 / +12** at r≈0.40–0.44 (tight; *strengthens* as the
        time-match tightens — the signature of a real-but-weak co-temporal
        signal, vs +24 which stays flat). r≈0.44 explains <20% of variance — a
        lead, not a lock.
      * **+8 and +12 are two ~4×10⁶ u32 accumulators** (millions-range,
        110–116 distinct values across the 211 LV55 cells) of **linear-energy
        shape** that weakly-positively track RSRP (r≈0.41–0.44) exactly as a
        linear energy ∝ 10^(dBm/10) would. So an RSRP-tracking linear energy
        **lives at cell_offset +8/+12**, NOT at the +24 slot the parser
        mislabels as RSRP.
      * **But +8/+12 are NOT the NB_MEAS max_SE/max_SNE words** (#N,
        2026-06-18 follow-up) — tested directly against the SAME capture's
        co-temporal F3 NB_MEAS (856 `lte_LL1_meas_ncell.c` prints), two
        independent contrasts refute that specific identity:
          - **symmetry** — +8/+12 are EXACTLY EQUAL in **80.6%** of cells
            (min ratio 0.918, never >8% apart), i.e. a near-symmetric pair;
            NB_MEAS max_SE/max_SNE are **NEVER equal (0/856)** and median
            ratio 0.747 (asymmetric, range 0.367–1). A symmetric pair cannot
            be the SE/SNE decomposition.
          - **magnitude** — +8/+12 median **4,224,007** (range 3.7–5.1M);
            NB_MEAS max_SE median **118,179** (max 3.86M) on the same capture
            — +8/+12 are ~36× larger than the NB_MEAS SE median and their
            MINIMUM exceeds the NB_MEAS median. Different quantity.
        So +8/+12 are a **distinct, near-symmetric per-rx linear-energy
        accumulator** (likely the per-Rx-antenna |h|² energy *before* the
        SE/SNE max-pick reduction, or a different integration window) — the
        SE/SNE distinction the F3 NB_MEAS exposes is **not** what +8/+12
        represent. The prior pass's "the SE/SNE energy lives at +8/+12" is
        thereby refined: +8/+12 are *an* RSRP-tracking energy, but not the
        NB_MEAS SE/SNE pair specifically.
      * **Scale still unlockable on this capture** — true RSRP spans only 7.3 dB,
        so raw-vs-10·log10(energy) are locally indistinguishable (raw r=0.41 ≈
        log r=0.40 @+8) — the narrow-range-invariance trap. Locking energy→dBm
        needs a wider-RSRP-spread capture with co-temporal $QCRSRP. No re-key /
        no guessed decode landed (the +8/+12 energy is located, not scaled).

Reference: GitHub issue #N

Techplayon QXDM field reference (sources/web/2026-04-07_techplayon_qxdm-log-packets.wacz),
canonical names per docs/qualcomm/techplayon-field-validation.md (#N Track 1)
+ docs/qualcomm/techplayon-cross-refs.md (#N Track 2):
    0xB192 — LTE ML1 Neighbor Cell Meas Request/Response
        is_idle_mode, earfcn, duplex_mode, neighbor_pci, num_tx_antennas,
        ttl_ftl_enabled, rsrp_rx0_dbm, rsrp_rx1_dbm, rsrp_combined_dbm,
        rsrq_rx0_db, rsrq_rx1_db, rsrq_instantaneous_db,
        rssi_rx0_dbm, rssi_rx1_dbm

=== names-block:start (auto-generated by tools/inject_names_block_parsers.py) ===

Names by source (from sources/DIAG_LOG_INDEX.yaml):
    canonical: LOG_LTE_ML1_NEIGHBOR_CELL_MEAS_REQUEST_RESPONSE
        source: qxdm_itemtype_list_zukgit_2025_04_03 (authority: community)
    aliases: (none recorded)

Source-precedence (#N): vendor_official > observation >
community (specification) > community (reference).
=== names-block:end ===
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

LOG_LTE_ML1_NEIGHBOR_CELL_MEAS = 0xB192

# Ground-truth capture recipe (#N). ONE version: v=0x01.
#
# 0xB192 is the cleanest possible recipe target: its per-cell entries carry
# crisp 3GPP physical quantities (idle-mode neighbor PCI / EARFCN / RSRP / RSRQ)
# that a Quectel modem returns FIELD-BY-FIELD via AT+QENG="neighbourcell". The
# code is emitted by Quectel RM520N-GL / EG25-G / RM500Q (vendor AT applies),
# Telit FN980/LM960, and Sierra EM9291. The recommended validation target is the
# RM520N-GL because (a) it has the vendor QENG neighbour list and (b) the corpus
# already holds a diag+AT correlate capture for it
# (<redacted-pii>). WiGLE-direct
# validation of exactly these fields is tracked by #N.
#
# Honesty caveats baked into the field map:
#  * 0xB192 is IDLE-mode neighbor meas (cond:idle). The modem must be camped and
#    not in an active data bearer, or it emits the connected-mode siblings
#    (0xB195/0x18AB) instead.
#  * QENG="neighbourcell" reports ONE RSRQ per neighbor, not a per-Rx-antenna
#    split. So it grounds the combined RSRQ but CANNOT by itself validate the
#    rsrq_rx0 vs rsrq_rx1 antenna split — that needs a per-Rx source (QMI/SCAT)
#    and is left as a separate, weaker grounding (status=hypothesis, noted).
# Subpacket ids (walk-order is always request(26) then response(27), n=55521).
_REQUEST_SP_ID = 26
_RESPONSE_SP_ID = 27

# Response subpacket versions. Two layouts: the "modern" 8-byte carrier header
# (earfcn u32-low18 @0, num_cells u16 @4) and the MDM9200 4-byte header
# (earfcn u16 @0, num_cells u16 @2). Corpus-observed modern versions are 4 and 56
# — BYTE-IDENTICAL (verified across 9,147 cells / 9 modems), because the version
# byte tracks firmware build, not layout (an RM520N-GL on A01A08 emits ver=4, on
# A03A0x emits ver=56; same silicon). Only the Sierra MC7700 / MDM9200
# (Gobi-3000) uses the 4-byte header, at ver=2. Dispatch is therefore binary:
# ver=2 → 4-byte header; EVERYTHING ELSE → modern 8-byte header. The else branch
# is deliberate forward-compatibility: since versions track firmware and modern
# is the dominant layout, a future modern build emitting a new version number
# (e.g. ver=57) decodes correctly rather than being rejected. Decode-completeness
# RE 2026-07-02 (#N).
_RESP_VER_MDM9200 = (2,)        # the ONLY 4-byte-carrier-header response version

_CELL_RECORD_SIZE = 52          # per-cell response record stride (ALL versions)
_REQ_CELL_RECORD_SIZE = 16      # per-cell request record stride
_CARRIER_HEADER_MODERN = 8      # ver=4 / ver=56 response carrier header
_CARRIER_HEADER_MDM9200 = 4     # ver=2 response carrier header (earfcn u16 + num_cells u16)


@dataclass
class LteMl1NeighborRequestCell:
    """One per-neighbour entry from the request/config subpacket (id=26).

    RE'd 2026-07-02 (#N): the request subpacket — previously walked-and-
    skipped — carries, per neighbour, the SAME PCI as the response plus two
    ~200K 'timing/config' words that are byte-identical to the response cell's
    +40/+44 pair (request-side timing echoed into the response). Verified by an
    exact positional PCI match (sp26 pci == sp27 pci) across every multi-cell
    record, cross-modem.
    """
    pci: int
    timing0: int
    timing1: int

    def to_dict(self) -> dict[str, Any]:
        return {'pci': self.pci, 'timing0': self.timing0, 'timing1': self.timing1}


@dataclass
class LteMl1NeighborCellEntry:
    """A single idle-mode neighbour cell measurement (response subpacket id=27).

    Signal semantics (#N, re-confirmed adversarially 2026-07-02): the per-cell
    quantities are **AGC-flattened integrated-energy accumulators, NOT calibrated
    dBm**. `rsrp` / `rsrq_rx0` / `rsrq_rx1` are therefore ``None``:
      * within a single capture the energy words at +4/+8/+12/+16/+20 correlate
        with true QENG RSRP (Pearson r up to 0.85, time-aligned via anchors),
      * BUT no capture-stable energy->dBm law exists — the required slope is ~15
        (a real power->dBm law is slope 1.0; the energy varies <2x while RSRP
        swings 54 dB) and the intercept differs ~13 dB across captures.
    So a dBm value is NOT recoverable from this packet (would be plausible-but-
    wrong, #N). The raw energy/timing words ARE exposed as usable integers so
    the measurement data is 100% extracted; a consumer holding a per-band
    reference power can convert them. `pci` / `earfcn` are the genuinely-verified
    fields (multi-value QENG/QMI containment, cross-modem).
    """
    pci: int
    earfcn: int
    # API-compat signal fields — None: no calibrated dBm in the packet (#N).
    rsrp: float | None
    rsrq_rx0: float | None
    rsrq_rx1: float | None
    # Newly-RE'd raw per-cell measurement words (usable integers, #N):
    energy0: int         # +4  u32 per-Rx integrated energy (~4-5e6; 45067 floor when weak)
    energy1: int         # +8  u32 per-Rx integrated energy (~4-5e6)
    energy2: int         # +12 u32 integrated energy (~4-5e6)
    energy_wide0: int    # +16 u32 wide-scale energy accumulator (~1.5e8)
    energy_wide1: int    # +20 u32 wide-scale energy accumulator (~1.9e8)
    meas_index: int      # +24 u16 measurement index/counter (0..~1166; the byte
                         #        the pre-2026-07-02 parser mis-decoded as RSRP)
    energy_filt: int     # +28 u32 filtered energy (~1.2e6, low ~22 bits)
    aux0: int            # +36 u16 small field (semantics unresolved, ~42)
    aux1: int            # +38 u16 small field (semantics unresolved, ~45)
    timing: int          # +40 u32 request-echoed timing (+40 == +44 always)

    def to_dict(self) -> dict[str, Any]:
        return {
            'pci': self.pci,
            'earfcn': self.earfcn,
            'rsrp': self.rsrp,
            'rsrq_rx0': self.rsrq_rx0,
            'rsrq_rx1': self.rsrq_rx1,
            'energy0': self.energy0,
            'energy1': self.energy1,
            'energy2': self.energy2,
            'energy_wide0': self.energy_wide0,
            'energy_wide1': self.energy_wide1,
            'meas_index': self.meas_index,
            'energy_filt': self.energy_filt,
            'aux0': self.aux0,
            'aux1': self.aux1,
            'timing': self.timing,
        }


@dataclass
class Diag0xB192:
    """LTE ML1 Idle-Mode Neighbor Cell Measurement (0xB192).

    Full decode (#N, 2026-07-02): outer frame + BOTH subpackets. `counter` is
    the outer [2:4] word (constant per capture — a config/instance marker, not a
    rolling SFN). `request_cells` is the decoded request subpacket (id=26). The
    parser version-dispatches the response subpacket (id=27) across the three
    observed versions {2, 4, 56}.
    """
    log_time: int
    version: int
    sp_version: int          # response subpacket version (2 / 4 / 56)
    counter: int             # outer [2:4] config/instance marker
    earfcn: int
    num_cells: int
    entries: list[LteMl1NeighborCellEntry] = field(default_factory=list)
    request_cells: list[LteMl1NeighborRequestCell] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0xB192',
            'log_time': self.log_time,
            'version': self.version,
            'sp_version': self.sp_version,
            'counter': self.counter,
            'earfcn': self.earfcn,
            'num_cells': self.num_cells,
            'entries': [e.to_dict() for e in self.entries],
            'request_cells': [c.to_dict() for c in self.request_cells],
        }


@register(LOG_LTE_ML1_NEIGHBOR_CELL_MEAS,
    name="0xB192",
    description="Idle-mode neighbor cell meas 0xB192 — decode-complete: version-dispatched sp27 {2,4,56}, full 52B cell record (PCI/EARFCN + per-Rx energy words) + request sp26 + outer counter; rsrp/rsrq None (energy-not-dBm, #N)",
    version=23,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=("v14 (2026-06-19, #N <redacted-ref>, host <redacted-host>): 2nd-site "
                   "cross-corroboration of the EG25-G (MDM9207) v0x01 recipe on a "
                   "DIFFERENT physical unit at a DIFFERENT "
                   "carrier/band — Verizon B13 EARFCN 2050, serving PCI 221, LIMSRV "
                   "(SIM CME ERROR 13 on COPS=0). Own dual-mask DIAG+F3 capture, COPS "
                   "2->0->2 drive, 48 v0x01 records. entries.pci re-VERIFIED on a NEW "
                   "distinct neighbour value (CONST 220 == AT QENG intra neighbour "
                   "220, distinct from serving 221); entries.rsrp re-REFUTED (decoded "
                   "-48..-58 vs true QENG -117); entries.earfcn HELD PARTIAL — and F3 "
                   "lte_ml1_md.c:2753 'Ngbr srch req (earfcn 2050)' (11x, 2050 ONLY) "
                   "now EXPLAINS the tautology: the idle ML1 neighbour search is "
                   "scoped to the serving carrier, so the inter-freq cell QENG saw "
                   "(PCI 221 @ EARFCN 5230; F3 quectel_cell_atc.c lte_inter "
                   "cells_inst=1) never enters the 0xB192 stream without a true "
                   "reselection. No status flips; second-site agreement hardens the "
                   "recipe. "
                   "v13 (2026-06-19, #N/#N <redacted-ref>, host <redacted-host>): "
                   "RM500Q-AE WLSN v0x01 neighbour pci/earfcn RE-CONFIRMED on a "
                   "2nd owned 244.7s capture — decoded (earfcn,pci) 524/536 = "
                   "97.8% contained in same-capture QENG across 12+ cells / 7 "
                   "EARFCNs (incl. u32 66986), fresh 2332-print NB_MEAS F3 witness "
                   "(qdb 404921d3); rsrp energy-not-dBm refutation re-confirmed. "
                   "v12 (2026-06-18, #N <redacted-ref>, host <redacted-host>): added the "
                   "Quectel RM520N-GL R03A04 (01.203.01.203) per-firmware sibling — "
                   "cross-firmware confirmation of the R03A03_A0.303 branch on the "
                   "R03A04 side-grade. Own dual-mask DIAG+F3 idle capture, Verizon "
                   "B66: entries.earfcn {5230,975} and entries.pci {310,1,250} 100% "
                   "contained in the AT QENG=\"neighbourcell\" sets => VERIFIED; "
                   "entries.rsrp PARTIAL (same ~50 dB offset bug). "
                   "v10 (2026-06-14, #N <redacted-ref>, host <redacted-host>): added a "
                   "Sierra MC7411 (SDX50M / Snapdragon X20) v0x01 sibling — a 5th "
                   "chipset family. LIMSRV B66 EARFCN 66786, neighbours 471+322 "
                   "(322 transient). entries.pci VERIFIED (multi-value {471,322} ∈ "
                   "AT!LTEINFO IntraFreq), entries.earfcn VERIFIED (66786, u32), "
                   "num_cells VERIFIED (1↔2 tracks the transient 322), entries.rsrp "
                   "REFUTED (-43..-58 vs true -102..-115 — RSRP scale bug now on "
                   "SDX55/SDX62/MDM9207/MDM9230/SDX50M). "
                   "v9 (2026-06-14, #N <redacted-ref>, host <redacted-host>): "
                   "RE-VALIDATED the EG25-G (MDM9207) v0x01 recipe with a "
                   "SIM-present LIMSRV camp (T-Mobile B4 EARFCN 2300, serving PCI "
                   "236, stable intra neighbour PCI 471). entries.pci → VERIFIED "
                   "(CONST 471 == QENG neighbour 471, 86/86; resolves the prior "
                   "SIM-less run's 0%% overlap), entries.rsrp → REFUTED (decoded "
                   "-44..-60 dBm vs true QENG -96..-106; non-constant ~46-52 dB "
                   "error — confirms the per-cell RSRP scale bug on a THIRD chipset "
                   "family after the RM500Q-AE SDX55 refutation). F3 (0x79 "
                   "plaintext, no MDM9207 qdb) confirms the LTE ML1 neighbour-meas "
                   "subsystem (lte_ml1_md.c Ngbr srch, quectel_cell_atc LIMSRV) and "
                   "an 'apply rsrp offset' path. "
                   "v8 (2026-06-12, #N <redacted-ref>, host t480, RM500Q-AE "
                   "round): added a Quectel RM500Q-AE (Qualcomm SDX55) v0x01 "
                   "sibling — HW run in LTE LIMSRV on AT&T B66 with a RICH "
                   "multi-neighbour set (187 records, num_cells 1–4). "
                   "entries.pci + entries.earfcn = 341/343 (99.4%) contained in "
                   "AT QENG=\"neighbourcell\" bucketed by earfcn (25 PCIs over 7 "
                   "EARFCNs) → BOTH VERIFIED. This is the rich-neighbour SDX55 "
                   "datum the CFW-3212 (SDX62) + LV55 (SDX55) entries lacked: it "
                   "REFUTES the v6 'suspected SDX55 neighbour pci drift' (pci "
                   "decodes correctly given a readable set — the CFW-3212/LV55 "
                   "partials were sparse-readback, not a layout drift) while "
                   "CONFIRMING the per-cell rsrp bug (decoded -30..-63 vs true "
                   "-97..-119 → entries.rsrp REFUTED). F3 (qdb GUID 404921d3) "
                   "lte_LL1_meas_ncell.c:414 NB_MEAS witnesses the LTE LL1 "
                   "neighbour-meas subsystem. Fifth chipset instance; first SDX55 "
                   "with neighbour pci VERIFIED. "
                   "SDX20 DLF capture RE (LM960, multi-carrier wardrive). "
                   "v2 (2026-06-07, #N <redacted-ref>): HW run on RM520N-GL @ "
                   "A0.303 promoted entries.pci + entries.earfcn to VERIFIED "
                   "(100% containment vs AT QENG=\"neighbourcell\"); RSRP/RSRQ/"
                   "num_cells held at partial (RSRP scale off ~56 dB). "
                   "v3 (2026-06-10, #N <redacted-ref>): added EG25-G (MDM9207) "
                   "sibling recipe — HW run on EG25-G @ A0.301 in SIM-less "
                   "LIMSRV (COPS-reselection-stimulated idle meas, 36 records). "
                   "All fields held partial: earfcn decoded correctly (2050, "
                   "100% containment) but single-valued/tautological intra-freq; "
                   "per-cell pci/rsrp/rsrq ungrounded (sparse stationary AT "
                   "reference; RSRP scale consistent with the RM520N-GL offset, "
                   "not a new MDM9207 break). Confirmed 0xB195 stays silent "
                   "without a SIM. "
                   "v4 (2026-06-10, #N <redacted-ref>, anti-monopoly rotation "
                   "onto the EM7455): added a Sierra EM7455 (MDM9230, M.2 twin of "
                   "the MC7455) v0x01 sibling — HW run in limited-service idle (90 "
                   "records), grounded against AT!LTEINFO (Sierra has no QENG). "
                   "entries.pci VERIFIED by MULTI-VALUE containment: decoded "
                   "neighbour PCIs {471,307,237} == the AT!LTEINFO IntraFreq "
                   "neighbour PCIs (the independent variation the stationary EG25-G "
                   "run lacked). earfcn/rsrp/rsrq/num_cells held partial (intra-freq "
                   "tautology / scale unresolved across siblings). Third chipset "
                   "family for the recipe; first per-cell pci VERIFIED on a Sierra. "
                   "v5 (2026-06-10, #N <redacted-ref> run 2): EG25-G re-run with a "
                   "2× AT+COPS=2→0 reselection drive to try for inter-freq EARFCN "
                   "diversity — NO promotion. The SIM-less stationary EG25 emitted "
                   "only 8 intra-freq idle-meas records: earfcn still CONST 2050 "
                   "(single-value tautological), decoded pci {259,7,263} ∩ AT QENG "
                   "pci {1,250,259,310} = {259} (33%, weak). Reconfirms (2nd capture) "
                   "that a SIM-less stationary EG25 cannot produce the inter-freq "
                   "reselection that the multi-value earfcn/pci containment needs — "
                   "a camped SIM or physical movement is required (the EM7455 got "
                   "pci verified only because its limited-service camp surfaced a "
                   "rich intra-freq neighbour set). Not a refutation; the field "
                   "offsets remain VERIFIED on the RM520N-GL. All EG25 fields stay "
                   "partial. "
                   "v6 (2026-06-10, #N <redacted-ref> <redacted-ref>, LV55-focused "
                   "round): added the Wistron LV55 (Qualcomm SDX55) v0x01 sibling — "
                   "HW run cond:connected (42 records, Verizon B66/PCI 310). The "
                   "reference FW exposes no neighbour readback (no QENG, JSONRPC "
                   "serving-only), so per-cell pci/rsrp stay partial; entries.earfcn "
                   "66536 cross-corroborated (0xB0C0/0xB193). Surfaced a SUSPECTED "
                   "SDX55 layout drift (mirrors the #N 0xB193 SDX55 refutation): "
                   "the [8:12] serving-PCI read = 488 ≠ true 310, and neighbour rsrp "
                   "-30..-34.5 dBm is impossible vs serving -113 — flagged, not "
                   "refuted (no neighbour truth). Fourth chipset family."),
    source_url="https://github.com/lukejenkins",
    # Decode-complete field accounting (#N, 2026-07-02). Every byte of both
    # subpackets is decoded into a named field or an explicit reserved region —
    # no `raw: bytes` remains. Exposed named fields (17 identified / 15 parsed):
    #   Outer(4): version, num_subpackets(implicit via walk), counter, sp_version.
    #   Response carrier: earfcn, num_cells.
    #   Response per-cell(11): pci + energy0/energy1/energy2 + energy_wide0/
    #     energy_wide1 + meas_index + energy_filt + aux0 + aux1 + timing.
    #   Request per-cell: pci, timing0, timing1.
    # PARSED=15 fields carry a grounded semantic (structure, pci/earfcn VERIFIED,
    # the energy accumulators are energy-domain quantities #N). IDENTIFIED=17
    # counts the 2 aux fields whose semantic is not yet resolved. rsrp/rsrq are
    # deliberately None (no calibrated dBm in the packet — the -raw/10 & (raw-60)/2
    # decodes were plausible-but-wrong, #N/#N) so they are NOT counted as
    # parsed dBm quantities; the underlying data is extracted as energy words.
    fields_identified=17,
    fields_parsed=15,
    # Byte-0 is the Qualcomm DIAG outer log version, corpus-attested invariantly
    # 0x01 (n=55521). Gated below per "size invariance != format invariance". The
    # INNER response subpacket version (id=27, ver ∈ {2,4,56}) is a separate field
    # the parser dispatches on — do NOT conflate it with the outer version enum.
    field_invariants={"version": {"enum": [0x01]}},
    # #N is the diag-decode/wigle:direct tracker for THIS code's
    # PCI/EARFCN/RSRP/RSRQ validation (the recipe work lives here); #N is the
    # metadata-backfill tooling issue this parser was originally grouped under.
    # Was issues=() with #N only mentioned in the docstring — fixed so the
    # real tracker is discoverable from metadata (see the project-wide audit).
    issues=(),
    primary_issue=None,
    wigle_direct=True,
    wigle_roles=("signal", "pci-earfcn-bridge", "rat-context"),
)
def parse_0xb192(
    log_time: int, data: bytes
) -> Diag0xB192 | None:
    """Parse 0xB192 -- LTE ML1 Idle Neighbor Cell Measurement.

    Decode-complete (#N, 2026-07-02): outer frame + request subpacket (id=26)
    + response subpacket (id=27), version-dispatched across the three observed
    response versions {2, 4, 56}. Every byte is decoded into a named field.
    Per-cell signal quantities are exposed as raw integrated-energy words (the
    packet carries no calibrated dBm — see LteMl1NeighborCellEntry / #N).

    Returns None if payload is malformed or the outer version is not 0x01.
    """
    if len(data) < 8:
        return None

    version = data[0]
    # Layer-1 version gate (corpus byte-0 invariantly 0x01, n=55521).
    if version != 0x01:
        return None
    num_subpackets = data[1]
    counter = unpack_from('<H', data, 2)[0]

    if num_subpackets < 1:
        return None

    # Walk subpackets. sp_size is INCLUSIVE of the 4-byte subpacket header, so
    # the next subpacket begins at offset + sp_size. Collect request (id=26) and
    # response (id=27); the walk order is always (26, 27).
    request_sp: bytes | None = None
    request_ver = 0
    response_sp: bytes | None = None
    response_ver = 0
    offset = 4  # skip version(1) + num_sp(1) + counter(2)

    for _ in range(num_subpackets):
        if offset + 4 > len(data):
            break
        sp_id = data[offset]
        sp_ver = data[offset + 1]
        sp_size = unpack_from('<H', data, offset + 2)[0]
        if sp_size < 4 or offset + sp_size > len(data):
            break
        body = data[offset + 4:offset + sp_size]
        if sp_id == _RESPONSE_SP_ID:
            response_sp, response_ver = body, sp_ver
        elif sp_id == _REQUEST_SP_ID:
            request_sp, request_ver = body, sp_ver
        offset += sp_size

    if response_sp is None:
        return None

    request_cells = (
        _parse_request_subpacket(request_sp, request_ver)
        if request_sp is not None else []
    )
    return _parse_response_subpacket(
        log_time, version, counter, response_ver, response_sp, request_cells
    )


def _carrier_header_len(sp_version: int) -> int:
    """Response carrier-header size: 8 B for ver=4/56, 4 B for the MDM9200 ver=2."""
    return (_CARRIER_HEADER_MDM9200 if sp_version in _RESP_VER_MDM9200
            else _CARRIER_HEADER_MODERN)


def _parse_request_subpacket(
    sp: bytes, sp_version: int
) -> list[LteMl1NeighborRequestCell]:
    """Decode the request/config subpacket (id=26).

    Header: 8 B for ver=2 (earfcn u32-low18 @0, num_cells|flag u16 @4, reserved
    u16 @6); 4 B for the MDM9200 ver=1 (earfcn u16 @0, flags u16 @2). Per-cell
    record (16 B): pci low-9 + flags (u32 @0), timing0 (u32 @4), timing1
    (u32 @8), reserved (u32 @12). Best-effort — never fails the whole parse.
    """
    # NB: the request (id=26) and response (id=27) number their versions
    # independently. The 4-byte-header MDM9200 variant is request ver=1 /
    # response ver=2 — so the small-header case is sp_version==1 HERE, but
    # sp_version==2 in the response parser. Not a typo.
    hdr = _CARRIER_HEADER_MDM9200 if sp_version in (1,) else _CARRIER_HEADER_MODERN
    cells: list[LteMl1NeighborRequestCell] = []
    if len(sp) < hdr:
        return cells
    n = (len(sp) - hdr) // _REQ_CELL_RECORD_SIZE
    for i in range(n):
        co = hdr + i * _REQ_CELL_RECORD_SIZE
        if co + _REQ_CELL_RECORD_SIZE > len(sp):
            break
        pci = unpack_from('<I', sp, co)[0] & 0x1FF
        cells.append(LteMl1NeighborRequestCell(
            pci=pci,
            timing0=unpack_from('<I', sp, co + 4)[0],
            timing1=unpack_from('<I', sp, co + 8)[0],
        ))
    return cells


def _parse_response_subpacket(
    log_time: int, version: int, counter: int, sp_version: int,
    sp: bytes, request_cells: list[LteMl1NeighborRequestCell],
) -> Diag0xB192 | None:
    """Parse the response subpacket data (id=27), version-dispatched.

    ver=4 / ver=56 (byte-identical): 8-byte carrier header
        (earfcn u32-low18 @0, num_cells u16 @4, reserved u16 @6).
    ver=2 (MC7700 / MDM9200): 4-byte carrier header
        (earfcn u16 @0, num_cells u16 @2).
    Both use a 52-byte per-cell record with the same field layout.
    """
    hdr = _carrier_header_len(sp_version)
    if len(sp) < hdr:
        return None

    if sp_version in _RESP_VER_MDM9200:
        earfcn = unpack_from('<H', sp, 0)[0]        # u16, structurally <= 65535
        num_cells = unpack_from('<H', sp, 2)[0]
    else:
        earfcn = unpack_from('<I', sp, 0)[0] & 0x3FFFF   # 18-bit, <= 262143
        num_cells = unpack_from('<H', sp, 4)[0]
    # (No earfcn range gate: both reads are structurally bounded to a valid
    # 18-bit EARFCN space, so a `> 262143` check would be dead code.)

    # The request subpacket describes the same neighbour set as the response, so
    # trim any length-derived over-count to num_cells to preserve the documented
    # 1:1 request<->response correspondence even if the request body was padded.
    request_cells = request_cells[:num_cells]

    entries: list[LteMl1NeighborCellEntry] = []
    for i in range(num_cells):
        co = hdr + i * _CELL_RECORD_SIZE
        if co + _CELL_RECORD_SIZE > len(sp):
            break

        pci = unpack_from('<I', sp, co)[0] & 0x1FF
        entries.append(LteMl1NeighborCellEntry(
            pci=pci,
            earfcn=earfcn,
            # No calibrated dBm in the packet (#N) — energy exposed raw below.
            rsrp=None,
            rsrq_rx0=None,
            rsrq_rx1=None,
            energy0=unpack_from('<I', sp, co + 4)[0],
            energy1=unpack_from('<I', sp, co + 8)[0],
            energy2=unpack_from('<I', sp, co + 12)[0],
            energy_wide0=unpack_from('<I', sp, co + 16)[0],
            energy_wide1=unpack_from('<I', sp, co + 20)[0],
            meas_index=unpack_from('<H', sp, co + 24)[0],
            energy_filt=unpack_from('<I', sp, co + 28)[0],
            aux0=unpack_from('<H', sp, co + 36)[0],
            aux1=unpack_from('<H', sp, co + 38)[0],
            timing=unpack_from('<I', sp, co + 40)[0],
        ))

    return Diag0xB192(
        log_time=log_time,
        version=version,
        sp_version=sp_version,
        counter=counter,
        earfcn=earfcn,
        num_cells=num_cells,
        entries=entries,
        request_cells=request_cells,
    )
