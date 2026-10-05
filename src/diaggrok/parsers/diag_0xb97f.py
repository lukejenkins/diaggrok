"""NR5G ML1 Measurement Database Update parser (0xB97F).

Periodic snapshot of NR cell measurements. Each record is a **nested,
multi-component-carrier** report: a small record header, then one block per
active component carrier (CC), each carrying serving-cell aggregate
measurements plus a list of per-cell (serving + neighbour) measurements with
PCI, RSRP, and RSRQ.

One unified layout decodes all four observed chipset-generation versions
(u16@0 is the version). The config word's low byte is the number of component
carriers (num_CC): ``0x14xx`` is ``flags | num_CC``. It is not a fixed
structural constant; treating ``config == 0x1401`` as an invariant would reject
every multi-CC record, including the whole SDX65/SDX72 corpus.

Nested layout (reverse-engineered from the corpus, verified by exact-length
consumption across 22k+ records):

    Record header (REC_HDR bytes):
        u16@0   version              (0x00 / 0x07 / 0x09 / 0x0A)
        u16@2   sub_version          (2, or 3 for v0x00)
        u32@?   counter              (present on v9/v0A/v0 at @4; absent on v7)
        u32@cfg config               (bits [7:0] == num_CC;
                                      bits [15:8] == ssb_periodicity_ms)
        u32@?   frame_number
        i32@?   timing_offset

    Per-CC block, repeated num_CC times:
        CC identity (12 B):
            u32@0   nr_arfcn
            u8      num_cells         (@+4 on v7, @+5 on v9/v0A/v0)
            u16@6   serving_pci       (0xFFFF == no-serving sentinel)
            u32@8   flags             (serving SSB index nibble; 0xF = NA. The
                                       bit position is version-dependent:
                                       bits[3:0] on v7/v9, bits[11:8] on both
                                       SDX72 versions v0 and v0A — _SSB_FLAG_SHIFT)
        CC meas-header (CC_MEAS B: 20 for v7/v9/v0A, 28 for v0):
            i32@0   serving_rsrp      (/128 dBm; a CC-level aggregate that is
                                       frequently 0/unpopulated. The
                                       authoritative serving RSRP is the cell
                                       block whose pci == serving_pci, matched
                                       by PCI, not by position: the serving cell
                                       is not always cells[0])
            i32@4   serving_rsrp_b    (/128 dBm — a second RSRP, not an RSRQ;
                                       SCAT prints the pair as "RSRP: a/b")
            v0 only (cc_meas 28): SCAT prints a four-value RSRP quad here —
            i32@8   serving_rsrp_c    | (/128 dBm) 3rd/4th of the quad; 0 across
            i32@12  serving_rsrp_d    | the corpus (name grounded, value unexercised)
            u16@rx  rx_beam_a         | rx = 8 on v7/v9/v0A, 16 on v0 (after c/d).
            u16@rx+2 rx_beam_b        | 0xFFFF == NA. Overlays `meas_tail`.
            …fill (ff ff 00 00 ff ff ff ff)
        Cells (CELL B for a one-beam cell: 60 for v7/v9, 100 for v0A/v0;
               a cell with num_beams=N>1 is CELL + 84*(N-1) B on v0):
            u16@0   pci
            u16@2   pbch_sfn          (0..1023 — not an SSB index; see below)
            u32@4   num_beams
            i32@8   rsrp              (/128 dBm)   ← the ground-truthed field
            i32@12  rsrq              (/128 dB)
            (is_serving is derived, not on the wire: pci == CC.serving_pci)
            beam block @16 — named (Nr5gBeam), two layouts (_BEAM_LAYOUTS).
            v7/v9 (44-B beam) and v0 (84-B beam) are grounded against SCAT;
            v0x0A also uses the 84-B v0_84 layout, grounded by in-capture
            cross-check because SCAT cannot decode v0x0A:
              44-B beam (v7/v9, 60-B cell):     84-B beam (v0 + v0A, 100-B cell):
                u32@16 ssb_index                  u16@16 ssb_index (hi u16 = 1)
                u32@20 beam_id_a                   i32@20 beam_id_a
                u32@24 beam_id_b                   i32@24 beam_id_b
                i32@28 word3_raw (un-named)        i32@28 word3_raw (un-named)
                i32@32 word4_raw (un-named)        i32@32 word4_raw (un-named)
                i32@36 rsrp_a                       i32@36 rsrp_a
                i32@40 rsrp_b                       i32@40 rsrp_b
                i32@44 filtered_rsrp_nr2nr          i32@44 rsrq_a   ← v0_84 only
                i32@48 filtered_rsrq_nr2nr          i32@48 rsrq_b   ← v0_84 only
                i32@52 filtered_rsrp_l2nr          i32@52..80 (8×i32) all-zero gap
                i32@56 filtered_rsrq_l2nr             (un-named, in beam_words)
                                                   i32@68 filtered_rsrp_nr2nr
                                                   i32@72 filtered_rsrq_nr2nr
                                                   i32@76 filtered_rsrp_l2nr
                                                   i32@80 filtered_rsrq_l2nr
            (44-B beam: filtered fields duplicate the cell rsrp/rsrq @+8/+12 when
             num_beams==1; L2Nr pair 0/0 on every SA-mode record. The "no
             measurement" sentinel is −140.0 (v7) / −156.0 (v9/v0). The v0 84-B
             beam adds a per-beam RSRQ pair (rsrq_a/b) the 44-B beam has no
             equivalent of.)

``pbch_sfn`` is not an SSB index: it spans 0..1023 and advances +16 per record
on a stationary serving cell; the SSB index is the first word of the beam block
(@cell+16). ``serving_rsrp_b`` is an RSRP word, not an RSRQ, and carries values
in the RSRP band. Both, and every named beam field, agree 100 % with SCAT's
printed decode of the same records on every mapped field: 301 packets / 757
cells / 3 vendors on v0x09 and 500 packets / 1514 cells / 4 vendors on v0x07.

0xB97F carries no SINR on any version. SCAT's complete decode has no such
field, and 0 of 774,935 F3 records on the reference capture mention one; NR
SS-SINR has to come from another log code.

RSRP scale is ``i32@cell+8 / 128`` for every version — hardware-ground-truthed
on the RM520N-GL (v9, serving −98 dBm across AT QENG, QMI GetCellLocationInfo,
and firmware F3) and confirmed by a 100 % in-band fraction on the v7 corpus
(3196 serving cells all land in [−140, −83] dBm). Reading v7 as
``i16@cell+12 / 16`` instead produces impossible values down to −344 dBm on
10 % of records; the tests carry an ``i16/16`` regression guard.

Truncation rule: some records in F3-dual-mask / VoNR captures end with a cell
that carries only 16 bytes. It is decoded as a zero-beam cell — num_beams=0,
rsrp=rsrq=0, just the 16-byte fixed prefix and no beam block — after which the
walk closes exactly (both v9 fixtures that exhibit it). A record whose declared
CCs / cells genuinely overrun the payload returns None, so the registry WARNs
and tallies it instead of a partial record passing as complete.
``trailing_bytes`` reports only non-truncation slack — bytes left after every
declared CC/cell was consumed (e.g. the 84 zero bytes of an
allocated-but-unpopulated v0 beam slot). On v0x00, slack that is not a whole
number of 84-byte beam slots is itself treated as truncation (None).

Per-version parameters:

    ver   chipset            rec_hdr  config@  num_cells@  cc_meas  cell  sub_ver
    0x07  SDX55              16       4        id+4        20       60    2
    0x09  SDX62 (RM520N-GL)  20       8        id+5        20       60    2
    0x0A  SDX72 (T99W640)    20       8        id+5        20       100   2
    0x00  SDX72 (RG650V-NA)  20       8        id+5        28       100   3

v0x00 comes from a donated RG650V-NA (SDX72) capture. Its sub_version=3
CC-meas-header carries two extra measurement words before the fill, and its
100-byte cells hold a richer 84-byte beam tail.

v0x00 84-byte beam: grounded against SCAT, which decodes this SDX72 capture in
full; it is not a transfer of the 44-byte v9 layout. A field-by-field
comparison with SCAT's printed decode — anchored on the excluded per-cell (PCI,
RSRP, RSRQ) tuple over 498 cells / 24 packets — agrees at 100 % on every field
bar one anchor collision. The 84-byte beam is not the 44-byte beam padded: SCAT
prints an extra per-beam ``RSRQ: a/b`` pair (``rsrq_a``/``rsrq_b``
@beam+28/+32) that the v9 beam lacks, then a 32-byte all-zero gap
(@beam+36..+64, 0/21616 non-zero corpus-wide — un-named, left in
``beam_words``), then the filtered pairs at +68/+72/+76/+80. ``ssb_index`` is
the low u16 @beam+0 (its high u16 is a constant 1). Three further
v0-specific points:
  1. ``serving_ssb_index`` is flags bits[11:8] on v0, not bits[3:0] (SCAT
     agrees 48/48 for >>8, 0/48 for &0xF). See ``_SSB_FLAG_SHIFT``.
  2. ``serving_rsrp_c``/``serving_rsrp_d`` (CC meas-header m+8/m+12) are two
     more serving RSRP words — SCAT prints the v0 CC RSRP as a four-value quad
     where v7/v9 print two. 0 across the corpus (name grounded, value
     unexercised).
  3. ``rx_beam_a``/``rx_beam_b`` on v0 are at m+16 (after the c/d quad), not m+8.
No live AT/QMI ground truth exists for this unit, but SCAT is independent of
the parser and is the same class of ground truth used for v0x09/v0x07.

v0x0A (T99W640, SDX72): same silicon as v0x00 but a different firmware
generation (sub_version=2 vs 3, cc_meas=20 vs 28 — a 2-value serving-RSRP pair,
not v0's 4-value quad: cc_meas m+8/m+12 hold the 0xFFFFFFFF/0xFFFF sentinel, so
there is no serving_rsrp_c/d and rx_beam stays at m+8). Its 84-byte beam uses
the same ``v0_84`` layout as v0x00, established on v0x0A's own records rather
than assumed from the shared chipset. SCAT recognises the packet as NR ML1 Meas
DB Update "version 2.10" but has no layout for it and prints only the raw body
hexdump, and F3 is absent on every v0x0A capture (the T99W640 emits only 0x98
multi-radio wrappers, 0 decodable inner F3). The grounding is an in-capture
cross-check over all 509 v0x0A records / 692 cells:
  1. The filtered Nr2Nr pair @beam+68/+72 equals the cell rsrp/rsrq exactly on
     692/692 single-beam cells — the "filtered duplicates the cell measurement
     when num_beams==1" invariant, which ties the pair to the /128
     hardware-ground-truthed cell RSRP. Exact equality only holds at +68/+72
     (not the v9_44 +44/+48 position), which pins the whole 84-B origin.
  2. ``serving_ssb_index`` is flags bits[11:8], not bits[3:0] — bits[3:0] is a
     constant 0 on 443/443 serving CC0 records while bits[11:8] varies 0/1/2
     and equals the serving cell's beam ssb_index (low u16 @beam+0) on 507/507
     CC0 cells (0xF=NA on 112 secondary CCs -> None). Reading bits[3:0] would
     return 0 for flags 0x200 where the true index is 2.
  3. The 32-byte all-zero gap @beam+36..+64 holds on 5536/5536 words; exact
     consumption is 509/509 records. beam_id_a/b (0 corpus-wide), word3/word4
     (raw) and the L2Nr filtered pair (0/0, SA mode) carry the same caution as
     on v0.

v0x0A firmware corroboration. The T99W640 baseband build that emits the v0x0A
captures independently supports the field semantics above:
  * The emit-side module is ``nr5g_ml1_mdb.c`` (NR5G ML1 *Measurement
    DataBase*), per that build's QShrink4 message database. On this build
    ``srchmeas.c`` is the WCDMA/3G searcher (psc/aset/cpich/SIB11), not the NR
    measurement database.
  * ``nr5g_ml1_mdb.c`` prints ``PCC serving SSB serv Rx beam RSSI (%d, %d)``
    (a per-beam Rx-beam RSSI pair → the beam ``rsrp_a``/``rsrp_b`` pair) and
    ``L3_filtered_rx23_rsrp`` (→ ``filtered_rsrp_*``), plus MDB beam-reporting
    indications — the same field semantics on the silicon that emits v0x0A.
  * Byte offsets cannot be read straight off the code: the image is a
    QShrink4, table-driven-logging build in which F3 strings are decoupled from
    code (0 code/data refs), and log code 0xB97F never appears as an inline
    ``log_alloc`` immediate in 2.47 M disassembled instructions. A static read
    of the packer's offsets would need a full decompile of the MDB region, so
    the in-capture cross-check remains the offset oracle for v0x0A.

Multi-beam cells: the cell stride is not fixed (see ``_BEAM_EXTRA``). On v0,
a cell with ``num_beams=2`` is 84 bytes longer, and treating the stride as
fixed misaligns every later cell starting inside CC0; CC1 then reads 84 bytes
early, so its ``nr_arfcn`` and ``num_cells`` look like garbage. Exact-length
consumption across all 88 v0 records identifies the stride. Ground truth for
this unit is absent, so the per-beam extension's *contents* stay un-named;
what is grounded is its *size*.

F3 corroboration on v0x07 (SDX55). Across every F3-bearing v0x07 capture (66;
48 joined to records), the ``nrfw_iu_cfg.c`` print "cmd id = %d, sfn = %u"
matches the nearest preceding record's serving cell (``pci == serving_pci``)
``pbch_sfn``, advanced by the print lag (1 frame / 10 ms), within 2 frames on
32,513 prints, with 36 outside (residual mode 1 / 0 frames; chance 5/1024).
``quectel_led_modem.c`` serving NR RSRP (0.1 dBm) vs ``cells[].rsrp``: 848
within 2 dB, 15 outside. This grounds ``serving_pci``, ``pbch_sfn`` and
``rsrp`` on v0x07's own SDX55 records.

Log name: LOG_NR5G_ML1_SEARCHER_MEASUREMENT_DATABASE_UPDATE_EXT
Also known as: NR5G ML1 Searcher Measurement Database Update Ext
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Optional

from diaggrok.codes import LOG_NR5G_ML1_MEAS_DB_UPDATE
from diaggrok.registry import register


# --- Per-version structural parameters -------------------------------------
# (rec_hdr, config_offset, num_cells_offset_within_CC_identity, cc_meas_size,
#  cell_size, sub_version)
_V = {
    0x00: (20, 8, 5, 28, 100, 3),   # SDX72 RG650V-NA
    0x07: (16, 4, 4, 20, 60, 2),    # SDX55 RM500Q-AE
    0x09: (20, 8, 5, 20, 60, 2),    # SDX62 RM520N-GL
    0x0A: (20, 8, 5, 20, 100, 2),   # SDX72 T99W640
}

# --- Per-extra-beam cell extension -----------------------------------------
#
# ``cell_size`` above is the size of a cell reporting ONE beam. A cell whose
# ``num_beams`` (u32 @cell+4) is N > 1 carries N-1 additional beam blocks of
# ``_BEAM_EXTRA[version]`` bytes each, so its true stride is
# ``cell_size + extra * (num_beams - 1)``.
#
# With a fixed stride, a single num_beams=2 cell on the v0 RG650V-NA corpus
# shifts every later cell in the record by 84 bytes — including the whole of
# CC1, which then reads a nonsense nr_arfcn and num_cells=0 and leaves ~1.2 kB
# unconsumed. The symptom looks like a secondary-CC misalignment; the cause is
# one cell earlier and unrelated to CC boundaries.
#
# Grounded on all 88 v0 records in the RG650V-NA corpus (fixed stride -> this
# table):
#   * exact-consumption   78/88 -> 87/88 (the 88th leaves 84 ZERO bytes — the
#                         same quantum, an allocated-but-unpopulated slot)
#   * cells recovered     1690 -> 1798 (+108)
#   * RSRP out of the [-140, -30] band   67 -> 0
# and the recovered cells' PCIs match the neighbour set the ADJACENT snapshots
# report on the same camp, which is the corroboration that makes this a decode
# rather than a curve-fit.
#
# 0 for v7/v9/v0A is an observation, not knowledge. Corpus sweep: every
# 0xB97F-bearing RG650V-NA and T99W640 capture exhaustively, plus a 30-capture
# stratified sample elsewhere.
#
#   version  records  cells   num_beams>1  exact consumption
#   v0x00         88   1798   9 cells      87/88   ( 98.9%)  <- the known case
#   v0x07       5000  13160   none         5000/5000 (100%)
#   v0x09       2500   9304   none         2500/2500 (100%)
#   v0x0A        504    687   none          504/504  (100%)
#
# 8,004 non-v0 records / 23,151 cells, zero multi-beam, and exact consumption
# everywhere. v0x0A carries the most risk of the three zeros: it is SDX72, the
# same chipset generation as v0x00 — the only version where num_beams>1 has
# been seen — and it has 504 records behind it.
#
# Exact consumption is the detector: a wrong _BEAM_EXTRA shows up as leftover
# slack (a fixed stride leaves v0 at 78/88 with ~1.2 kB unconsumed). 100% on
# all three zeros means there is no silent misparse in the corpus today. If a
# v7/v9/v0A capture ever reports num_beams>1 and stops consuming exactly, this
# is the table to revisit — the defect will look identical.
#
# Nothing observed can distinguish "no extension on those versions" from
# "extension never exercised there". The corpus makes the second explanation
# less likely; it does not rule it out.
_BEAM_EXTRA = {
    0x00: 84,
    0x07: 0,
    0x09: 0,
    0x0A: 0,
}
_B97F_VERSIONS_OBSERVED = (0x00, 0x07, 0x09, 0x0A)

CC_ID_SIZE = 12
_CELL_PREFIX = 16      # pci u16, pbch_sfn u16, num_beams u32, rsrp i32, rsrq i32
RSRP_SCALE = 128.0     # i32@cell+8 / 128 = dBm (ground-truthed on RM520N-GL v9)
RSRQ_SCALE = 128.0     # i32@cell+12 / 128 = dB
_NO_SERVING = 0xFFFF   # serving_pci sentinel

# Plausible physical-quantity bands; values outside → None (kept as *_raw).
# RSRP low bound is EXCLUSIVE (-140 < val) so the firmware "no measurement"
# sentinels — v7 0xFFFFBA00 (=-140.0 exactly) and v9/v0A 0xFFFFB2xx (<=-156) —
# resolve to None instead of being reported as a real floor reading. Real
# serving/neighbour RSRP always sits strictly above the -140 dBm floor.
_RSRP_LO, _RSRP_HI = -140.0, -30.0
_RSRQ_LO, _RSRQ_HI = -43.0, 3.0


def _scale_rsrp(raw: int) -> Optional[float]:
    """i32 raw RSRP → dBm / 128, or None if at/below the -140 floor sentinel."""
    val = raw / RSRP_SCALE
    return val if _RSRP_LO < val <= _RSRP_HI else None


# --- Ground truth ----------------------------------------------------------
# v7 (SDX55): RSRP scale is i32@cell+8 / 128 (not i16@+12 / 16).
# v9 (SDX62 RM520N-GL): hardware-validated (serving −98 dBm, 4 sources).

# --- Dataclasses -----------------------------------------------------------
@dataclass
class Nr5gBeam:
    """One SSB beam's measurement block (the 44-B tail of a 60-B cell).

    Field names here are grounded against SCAT, not inferred: every one matches
    SCAT's printed decode of the same records — 301 packets / 757 cells
    across three vendors on v0x09 (RM520N-GL, EM9291, CFW-3212) and 500 packets
    / 1514 cells across four more on v0x07 (RM500Q-AE, FT980m, RM500Q,
    SIM8202G-M2), at 100 % agreement on every field below. SCAT's own line is::

        Beam 0: SSB[1] Beam ID: 0/0, RSRP: -113.88/-156.00,
                Filtered RSRP/RSRQ (Nr2Nr): -113.80/-16.79,
                Filtered RSRP/RSRQ (L2Nr): 0.00/0.00

    Populated on the 60-byte-cell versions (v0x07 / v0x09, 44-B beam) and on
    both 100-byte-cell SDX72 versions (v0x00 + v0x0A, 84-B beam). The 84-B beam
    is not a structural transfer of the 44-B one: it adds a per-beam
    ``RSRQ: a/b`` pair the v9 beam lacks, and the filtered pair moves from
    +44/+48 to +68/+72 with a 32-B all-zero gap between (see _BEAM_LAYOUTS).
    v0x00 is grounded against SCAT. v0x0A (T99W640 SDX72) shares the same
    ``v0_84`` layout, grounded by in-capture cross-check since SCAT cannot
    decode v0x0A — the filtered Nr2Nr pair @beam+68/+72 equals the cell
    rsrp/rsrq exactly on 692/692 single-beam cells, pinning both the pair
    position and the beam origin. That layout is established on v0x0A's own
    records, not assumed from the shared chipset: v0x0A is a different firmware
    generation (cc_meas 20, not v0's 28).
    """
    ssb_index: int            # @cell+16 u32 — the SSB index (SCAT "SSB[n]").
                              # Not to be confused with the u16 @cell+2, which is
                              # `pbch_sfn`.
    beam_id_a: int            # @cell+20 u32 — SCAT "Beam ID: a/b", first value
    beam_id_b: int            # @cell+24 u32 — SCAT "Beam ID: a/b", second value
                              # Both are 0 in every corpus record (2271 cells,
                              # 7 vendors). SCAT names them, but nothing has
                              # exercised them — so the name is grounded and
                              # the semantic is not. Same caution as _BEAM_EXTRA.
    word3_raw: int            # @cell+28 i32 — un-named. SCAT prints nothing
    word4_raw: int            # @cell+32 i32 — for this pair, and F3 is silent on
                              # it, so it stays raw. Live (271/306 distinct values
                              # over 1724 cells), high-magnitude, and not plausible
                              # as /128 dBm, a f32, or a u64 tick — genuinely
                              # unknown.
    rsrp_a: Optional[float]   # @cell+36 i32/128 dBm — SCAT beam "RSRP: a/b"
    rsrp_a_raw: int
    rsrp_b: Optional[float]   # @cell+40 i32/128 dBm — SCAT beam "RSRP: a/b"
    rsrp_b_raw: int           # (carries the -156.00 / -150.00 no-measurement
                              # sentinels, which _scale_rsrp resolves to None)
    # Filtered pairs. Offsets are layout-dependent (see _BEAM_LAYOUTS): on the
    # 44-B v9 beam they sit at +44/+48/+52/+56; the 84-B v0 beam has the
    # per-beam RSRQ pair (rsrq_a/b, below) plus a 32-B all-zero gap first, so
    # they move to +68/+72/+76/+80. The field meaning is identical either way.
    filtered_rsrp_nr2nr: Optional[float]   # i32/128 dBm — SCAT "Filtered RSRP (Nr2Nr)"
    filtered_rsrp_nr2nr_raw: int
    filtered_rsrq_nr2nr: Optional[float]   # i32/128 dB  — SCAT "Filtered RSRQ (Nr2Nr)"
    filtered_rsrq_nr2nr_raw: int
    filtered_rsrp_l2nr: Optional[float]    # i32/128 dBm — the LTE-to-NR filtered
    filtered_rsrp_l2nr_raw: int            # pair; 0.00/0.00 in every SA-mode record
    filtered_rsrq_l2nr: Optional[float]    # i32/128 dB  — in the corpus (name
    filtered_rsrq_l2nr_raw: int            # grounded, not semantic)
    # --- v0 (84-B beam) only: per-beam RSRQ pair (@beam+28/+32). The 44-B v9 beam
    # has no such field — SCAT prints "RSRQ: a/b" on the v0 beam line and nothing
    # there on v9. Grounded on the RG650V-NA SDX72 corpus: 497/498 cells match
    # SCAT, the 1 miss an anchor collision.
    # None on the 44-B v9 beam. Defaulted so they follow the non-default fields. ---
    rsrq_a: Optional[float] = None   # i32/128 dB — SCAT beam "RSRQ: a/b" (first)
    rsrq_a_raw: Optional[int] = None
    rsrq_b: Optional[float] = None   # i32/128 dB — SCAT beam "RSRQ: a/b" (second)
    rsrq_b_raw: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            'ssb_index': self.ssb_index,
            'beam_id_a': self.beam_id_a,
            'beam_id_b': self.beam_id_b,
            'word3_raw': self.word3_raw,
            'word4_raw': self.word4_raw,
            'rsrp_a': self.rsrp_a,
            'rsrp_a_raw': self.rsrp_a_raw,
            'rsrp_b': self.rsrp_b,
            'rsrp_b_raw': self.rsrp_b_raw,
            'rsrq_a': self.rsrq_a,
            'rsrq_a_raw': self.rsrq_a_raw,
            'rsrq_b': self.rsrq_b,
            'rsrq_b_raw': self.rsrq_b_raw,
            'filtered_rsrp_nr2nr': self.filtered_rsrp_nr2nr,
            'filtered_rsrp_nr2nr_raw': self.filtered_rsrp_nr2nr_raw,
            'filtered_rsrq_nr2nr': self.filtered_rsrq_nr2nr,
            'filtered_rsrq_nr2nr_raw': self.filtered_rsrq_nr2nr_raw,
            'filtered_rsrp_l2nr': self.filtered_rsrp_l2nr,
            'filtered_rsrp_l2nr_raw': self.filtered_rsrp_l2nr_raw,
            'filtered_rsrq_l2nr': self.filtered_rsrq_l2nr,
            'filtered_rsrq_l2nr_raw': self.filtered_rsrq_l2nr_raw,
        }


@dataclass
class Nr5gCellMeasurement:
    """One measured NR cell (serving or neighbour)."""
    pci: int
    pbch_sfn: int             # u16 @+2 — the cell's PBCH system frame number
                              # (0..1023). Not an SSB index: the SSB index
                              # lives at +16 (see Nr5gBeam.ssb_index); this field
                              # advances +16 per record on a stationary serving
                              # cell, which no SSB index does. Matches SCAT on
                              # 2271 cells / 7 vendors across v0x07 and v0x09, and
                              # corroborated in-capture by the RM520N-GL's own F3
                              # (`nrfw_iu_cfg.c:5846 "sfn = %u"`).
    num_beams: int
    rsrp: Optional[float]    # dBm (i32@cell+8 / 128), None if out-of-band/sentinel
    rsrp_raw: int            # raw i32@cell+8
    rsrq: Optional[float]    # dB  (i32@cell+12 / 128), None if out-of-band
    rsrq_raw: int            # raw i32@cell+12
    beam_words: list[int] = field(default_factory=list)  # per-beam tail, wire-typed i32s
                              # Retained alongside `beams`: it spans the whole tail,
                              # including any multi-beam extension the named decode
                              # does not cover, and the multi-beam stride check reads
                              # its length (a num_beams=2 v0 cell is 84 B / 21 words
                              # longer).
    beams: list[Nr5gBeam] = field(default_factory=list)   # named per-beam blocks
                              # (first beam only; empty for a zero-beam cell)
    is_serving: bool = False  # this cell's pci == its CC's serving_pci (matched by
                              # PCI, not position); False when the CC has no serving
                              # (serving_pci == 0xFFFF). Set by parse_0xb97f after the
                              # CC's serving_pci is known - the reliable
                              # serving-vs-neighbour flag.

    def to_dict(self) -> dict:
        return {
            'pci': self.pci,
            'pbch_sfn': self.pbch_sfn,
            'num_beams': self.num_beams,
            'rsrp': self.rsrp,
            'rsrp_raw': self.rsrp_raw,
            'rsrq': self.rsrq,
            'rsrq_raw': self.rsrq_raw,
            'beam_words': self.beam_words,
            'beams': [b.to_dict() for b in self.beams],
            'is_serving': self.is_serving,
        }


@dataclass
class Nr5gComponentCarrier:
    """One component carrier's measurement block."""
    nr_arfcn: int
    serving_pci: int          # 0xFFFF == no-serving sentinel (kept raw)
    num_cells: int            # declared cell count for this CC
    num_cells_companion: int  # RAW: the CC-identity byte the [4:6] pair holds
                              # alongside num_cells (byte@5 on v7, byte@4 on
                              # v9/v0A/v0 — the offset num_cells does NOT occupy).
                              # F3-silent, and VERSION-DEPENDENT, so it stays raw
                              # and un-named. Measured on CC0 over whole captures:
                              # v0x07 (EM9190 + RM500Q-AE, SDX55): equals the
                              # serving cell's array index on 6075/6075 records
                              # (six distinct values 0..5, two vendors), and 0xFF
                              # on 33/33 no-serving CCs. v0x09 (RM520N-GL, SDX62):
                              # only two values, 0 (3634) and 0xFF (935), while the
                              # serving index spans 0..3 (58 counterexamples) — a
                              # presence flag, not an index. v0x00: not an index
                              # either. v0x0A (T99W640): undecidable — 315/315
                              # comp==0 and index==0, but 311 of 315 records carry
                              # one cell, so the match is not evidence. The 0xFF
                              # "no serving" value (mirroring the PCI sentinel) is
                              # the version-invariant half: exact on v7 (33/33) and
                              # v9 (935/935). Naming it after the v7 semantic would
                              # mislabel every v9 record.
    flags: int
    serving_ssb_index: Optional[int]  # the serving cell's SSB index; 0xF is the NA
                              # sentinel and yields None. SCAT prints it as "/SSB: n"
                              # beside SCell PCI. The bit position is version-
                              # dependent: flags bits[3:0] on v0x07/v0x09
                              # (801/801 CC blocks / 7 vendors match SCAT),
                              # but flags bits[11:8] on both SDX72 versions v0x00
                              # and v0x0A. v0x00: SCAT agrees with the >>8 rule
                              # 48/48 and with &0xF 0/48. v0x0A: in-capture
                              # cross-check — bits[3:0] is a constant 0 on 443/443
                              # serving CC0 records while bits[11:8] varies 0/1/2
                              # and equals the serving cell's beam ssb_index on
                              # 507/507 CC0 cells (0xF=NA on 112 secondary CCs).
                              # The name is version-invariant; the bit position is
                              # not, and reading bits[3:0] on the SDX72 versions is
                              # wrong on 100 % of serving records. See
                              # _SSB_FLAG_SHIFT.
    serving_rsrp: Optional[float]   # CC meas-header i32@0 / 128 dBm, None if 0/out-of-band
    serving_rsrp_b: Optional[float]  # CC meas-header i32@4 / 128 — a second RSRP,
                              # not an RSRQ. SCAT prints the pair as one field
                              # ("RSRP: a/b") and the values live in the RSRP band
                              # (-107..-80 dBm measured); an RSRQ plausibility gate
                              # [-43, 3] would reject every value. Matches SCAT on
                              # 801/801 CC blocks, v0x07 + v0x09.
                              # Carries the -150.00 no-measurement sentinel.
    serving_rsrp_raw: int
    serving_rsrp_b_raw: int
    meas_tail: bytes = b''    # RAW: the rest of the CC meas header past the
                              # serving RSRP pair. 12 B on v7/v9/v0A (cc_meas 20),
                              # 20 B on v0 (cc_meas 28). Surfaced un-named because
                              # no source labels it: F3 confirms the NR5G-ML1
                              # searcher/meas subsystem (srchmeas.c reset_meas_db,
                              # nr5g_ml1_rfmgr_trm_if.c) but labels no field here.
                              # On the T99W640 SDX72 build the NR5G meas-DB
                              # emit-side file is `nr5g_ml1_mdb.c`, and `srchmeas.c`
                              # is the WCDMA/3G searcher; the firmware is still
                              # field-silent here either way.
                              # Byte-invariant on every correctly-aligned CC block
                              # across all four chipset generations (13,657/13,666
                              # blocks over a 13,433-record validation) —
                              # `ff ff ff ff | ff ff 00 00 | ff ff ff ff`
                              # (v0 prepends 8 zero bytes) — an unpopulated
                              # sentinel slot whose shape mirrors the CC identity's
                              # own 0xFFFF no-serving sentinel. The 9 exceptions are
                              # v0 secondary CCs read at the wrong offset when the
                              # multi-beam stride (_BEAM_EXTRA) is not applied;
                              # with it they carry the same sentinel, and v0 CC0 is
                              # 88/88 sentinel. Exposed anyway rather than dropped:
                              # an always-empty slot can turn live on other silicon
                              # (0x158C's `reserved2` is zero on modern silicon but
                              # four live u32 on MC7455), and retaining the bytes
                              # costs nothing.
                              # Its first four bytes on cc_meas 20 are named — see
                              # rx_beam_a/rx_beam_b below. The remaining 8 B
                              # (v7/v9/v0A) stay raw and un-named.
    rx_beam_a: Optional[int] = None   # u16 — SCAT prints the pair as "RX beam: x/y",
    rx_beam_b: Optional[int] = None   # with 0xFFFF rendered "NA". The offset is
                              # version-dependent: meas_tail[0:4] (m+8) on v7/v9/v0A
                              # (cc_meas 20), meas_tail[8:12] (m+16) on v0 (cc_meas 28,
                              # where serving_rsrp_c/d occupy m+8/m+12 first). Matches
                              # SCAT on 801/801 CC blocks v0x07+v0x09 / 7 vendors and
                              # 48/48 layers on v0. Every corpus sample is the NA
                              # sentinel, so both are None on every record in the
                              # corpus: SCAT grounds the name and the sentinel,
                              # never a populated value.
    # --- v0 (cc_meas 28) only: two more serving RSRP words. SCAT prints the v0
    # CC-level RSRP as a four-value quad ("RSRP: a/b/c/d") where v7/v9 print two
    # ("a/b"); c/d are these. m+8/m+12, i32/128 dBm. Matches the SCAT quad on
    # 48/48 v0 layers — but 0 on all 264 corpus CC blocks, so the name and
    # position are grounded while the value is unexercised (the same caution as
    # rx_beam / beam_id). None on v7/v9/v0A. ---
    serving_rsrp_c: Optional[float] = None   # m+8  i32/128 dBm — SCAT RSRP quad 3rd
    serving_rsrp_c_raw: Optional[int] = None
    serving_rsrp_d: Optional[float] = None   # m+12 i32/128 dBm — SCAT RSRP quad 4th
    serving_rsrp_d_raw: Optional[int] = None
    cells: list[Nr5gCellMeasurement] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            'nr_arfcn': self.nr_arfcn,
            'serving_pci': self.serving_pci,
            'num_cells': self.num_cells,
            'num_cells_companion': self.num_cells_companion,
            'flags': self.flags,
            'serving_ssb_index': self.serving_ssb_index,
            'serving_rsrp': self.serving_rsrp,
            'serving_rsrp_b': self.serving_rsrp_b,
            'serving_rsrp_raw': self.serving_rsrp_raw,
            'serving_rsrp_b_raw': self.serving_rsrp_b_raw,
            # .hex() per the 0x1c8f `name_buffer_residue` precedent — raw bytes
            # cross a JSON boundary as hex, never as a lossy decode.
            'meas_tail': self.meas_tail.hex(),
            'rx_beam_a': self.rx_beam_a,
            'rx_beam_b': self.rx_beam_b,
            'serving_rsrp_c': self.serving_rsrp_c,
            'serving_rsrp_c_raw': self.serving_rsrp_c_raw,
            'serving_rsrp_d': self.serving_rsrp_d,
            'serving_rsrp_d_raw': self.serving_rsrp_d_raw,
            'cells': [c.to_dict() for c in self.cells],
        }


@dataclass
class Diag0xB97F:
    """Parsed 0xB97F NR5G ML1 measurement database update (all versions)."""
    log_time: int
    version: int
    sub_version: int
    counter: int
    config_word: int
    num_cc: int
    frame_number: int
    timing_offset: int
    carriers: list[Nr5gComponentCarrier] = field(default_factory=list)
    trailing_bytes: int = 0     # >0 iff bytes remain after every declared CC/cell (slack; truncation -> None)

    @property
    def ssb_periodicity_ms(self) -> int:
        """SSB burst periodicity in ms — ``config_word`` bits [15:8].

        The config word's low byte is ``num_cc``; the byte above it is the SSB
        periodicity: ``config_word == 0x1402`` is ``num_cc=2, period=20 ms``,
        which is the standard NR SSB burst period. Matches SCAT on 801/801
        records across v0x07 + v0x09 / 7 vendors (SCAT's "ssb_periocity: N").
        """
        return (self.config_word >> 8) & 0xFF

    # --- Backward-compat top-level view (CC0) ------------------------------
    @property
    def _cc0(self) -> Optional[Nr5gComponentCarrier]:
        return self.carriers[0] if self.carriers else None

    @property
    def nr_arfcn(self) -> int:
        return self._cc0.nr_arfcn if self._cc0 else 0

    @property
    def serving_pci(self) -> int:
        return self._cc0.serving_pci if self._cc0 else 0

    @property
    def num_cells(self) -> int:
        return self._cc0.num_cells if self._cc0 else 0

    @property
    def num_cells_companion(self) -> int:
        return self._cc0.num_cells_companion if self._cc0 else 0

    @property
    def meas_tail(self) -> bytes:
        """CC0's meas-header tail (see ``Nr5gComponentCarrier.meas_tail``).

        Mirrors the other CC0 backward-compat properties so the region can enter
        the diagspec 3-way diff as a flat RAW_FIELD (nested per-CC values cannot;
        the harness diffs flat getattr scalars, and the full nested walk is pinned
        by the per-CC/per-cell cross-check test instead).
        """
        return self._cc0.meas_tail if self._cc0 else b''

    @property
    def entries(self) -> list[Nr5gCellMeasurement]:
        return self._cc0.cells if self._cc0 else []

    def to_dict(self) -> dict:
        return {
            'type': 'Diag0xB97F',
            'log_time': self.log_time,
            'version': self.version,
            'sub_version': self.sub_version,
            'counter': self.counter,
            'config_word': self.config_word,
            'num_cc': self.num_cc,
            'ssb_periodicity_ms': self.ssb_periodicity_ms,
            'frame_number': self.frame_number,
            'timing_offset': self.timing_offset,
            'carriers': [cc.to_dict() for cc in self.carriers],
            'trailing_bytes': self.trailing_bytes,
            # Backward-compat top-level aliases (CC0 view):
            'nr_arfcn': self.nr_arfcn,
            'earfcn': self.nr_arfcn,   # cross-code alias
            'serving_pci': self.serving_pci,
            'num_cells': self.num_cells,
            'num_cells_companion': self.num_cells_companion,
            'meas_tail': self.meas_tail.hex(),
            'entries': [e.to_dict() for e in self.entries],
        }


def _scale(raw: int, lo: float, hi: float, div: float) -> Optional[float]:
    """i32 raw → physical value / div, or None if outside the plausible band."""
    val = raw / div
    return val if lo <= val <= hi else None


#: Per-beam field offsets RELATIVE TO the beam start (== cell + 16), keyed by a
#: layout name:
#:
#:   * ``"v9_44"`` — the 44-byte beam of a 60-byte cell (v0x07 / v0x09). SCAT
#:     line: ``SSB[n] Beam ID: a/b, RSRP: a/b, Filtered .../(Nr2Nr)/(L2Nr)``.
#:     No per-beam RSRQ pair. ``ssb_index`` is the full i32 @+0.
#:     Matches SCAT field-by-field: 301 packets/757 cells v9 + 500/1514 v7 at
#:     100 %.
#:   * ``"v0_84"`` — the 84-byte beam of a 100-byte cell, on both SDX72 versions
#:     v0x00 (RG650V-NA) and v0x0A (T99W640). A per-beam ``RSRQ: a/b`` follows
#:     ``RSRP: a/b`` (@+28/+32), then a 32-byte all-zero gap (+36..+64, un-named)
#:     before the filtered pairs, which therefore move to +68/+72/+76/+80.
#:     ``ssb_index`` is the low u16 @+0 (the high u16 is a constant 1, un-named).
#:     v0x00 matches SCAT on 497/498 cells (1 miss = anchor collision). v0x0A is
#:     grounded by in-capture cross-check — the filtered Nr2Nr pair @+68/+72
#:     equals the cell rsrp/rsrq exactly on 692/692 v0x0A cells (pinning the pair
#:     at +68/+72 and the beam origin), the gap is all-zero on 5536/5536 words,
#:     and the beam ssb_index @+0 equals flags bits[11:8] on 507/507 serving CC0
#:     cells.
#:
#: SCAT decodes v0x00 but not v0x0A (it hexdumps version "2.10"), so v0x0A's
#: v0_84 entry rests on the in-capture cross-check above, not a SCAT comparison
#: and not a structural transfer from the shared chipset — v0x0A is a different
#: firmware generation (cc_meas 20 vs v0's 28) and is grounded on its own 509
#: records.
_BEAM_LAYOUTS = {
    # off:  ssb bid_a bid_b w3  w4  rp_a rp_b rq_a rq_b f_rp_n f_rq_n f_rp_l f_rq_l
    "v9_44": dict(ssb_u16=False, ssb=0, bid_a=4, bid_b=8, w3=12, w4=16,
                  rp_a=20, rp_b=24, rq_a=None, rq_b=None,
                  f_rp_n=28, f_rq_n=32, f_rp_l=36, f_rq_l=40),
    "v0_84": dict(ssb_u16=True, ssb=0, bid_a=4, bid_b=8, w3=12, w4=16,
                  rp_a=20, rp_b=24, rq_a=28, rq_b=32,
                  f_rp_n=68, f_rq_n=72, f_rp_l=76, f_rq_l=80),
}

#: version → beam layout name. v0x0A (T99W640 SDX72, 100-B cell) shares v0's
#: 84-byte ``v0_84`` layout, established by in-capture cross-checks on v0x0A's
#: own 509 records rather than by transfer from v0: (a) the filtered Nr2Nr pair
#: @beam+68/+72 equals the cell rsrp/rsrq exactly on 692/692 single-beam cells
#: (the "filtered duplicates the cell measurement when num_beams==1" invariant,
#: tying the pair to the /128 hardware-ground-truthed cell RSRP — which pins the
#: pair at +68/+72, not the v9_44 +44/+48 position), (b) the beam ssb_index (low
#: u16 @+0) equals flags bits[11:8] on 507/507 serving CC0 cells, (c) the 32-byte
#: gap @beam+36..+64 is all-zero on 5536/5536 words. SCAT recognises v0x0A
#: (version "2.10") but has no decoder for it and only hexdumps the body.
#: beam_id_a/b (0 corpus-wide), word3/word4 (raw, un-named) and the L2Nr
#: filtered pair (0/0 in SA mode) match v0's same-named fields and carry the
#: same caution (name/position grounded, semantic unexercised).
_VERSION_BEAM_LAYOUT = {0x07: "v9_44", 0x09: "v9_44", 0x00: "v0_84", 0x0A: "v0_84"}

#: version → the flags bit shift for the serving cell's SSB index. bits[3:0] on
#: v7/v9; bits[11:8] on both SDX72 versions v0x00 and v0x0A. v0x00 matches SCAT
#: 48/48 (bits[3:0] matched 0/48); v0x0A by in-capture cross-check — bits[3:0]
#: is a constant 0 on 443/443 serving CC0 records while bits[11:8] varies 0/1/2
#: and equals the serving cell's beam ssb_index on 507/507 CC0 cells (0xF=NA
#: sentinel on 112 secondary CCs, -> None). A shift of 0 on v0x0A would be wrong
#: on 100% of serving records (flags 0x200 -> 0, truth 2).
#: Version-dependent bit position, invariant name.
_SSB_FLAG_SHIFT = {0x07: 0, 0x09: 0, 0x0A: 8, 0x00: 8}


def _decode_beam(data: bytes, off: int, layout: str) -> Nr5gBeam:
    """Decode the per-beam block at ``off`` (== cell start + 16) per ``layout``."""
    L = _BEAM_LAYOUTS[layout]

    def i32(o: int) -> int:
        return unpack_from('<i', data, off + o)[0]

    ssb = (unpack_from('<H', data, off + L['ssb'])[0]
           if L['ssb_u16'] else i32(L['ssb']))
    rq_a = i32(L['rq_a']) if L['rq_a'] is not None else None
    rq_b = i32(L['rq_b']) if L['rq_b'] is not None else None
    return Nr5gBeam(
        ssb_index=ssb,
        beam_id_a=i32(L['bid_a']),
        beam_id_b=i32(L['bid_b']),
        word3_raw=i32(L['w3']),
        word4_raw=i32(L['w4']),
        rsrp_a=_scale_rsrp(i32(L['rp_a'])), rsrp_a_raw=i32(L['rp_a']),
        rsrp_b=_scale_rsrp(i32(L['rp_b'])), rsrp_b_raw=i32(L['rp_b']),
        filtered_rsrp_nr2nr=_scale_rsrp(i32(L['f_rp_n'])),
        filtered_rsrp_nr2nr_raw=i32(L['f_rp_n']),
        filtered_rsrq_nr2nr=_scale(i32(L['f_rq_n']), _RSRQ_LO, _RSRQ_HI, RSRQ_SCALE),
        filtered_rsrq_nr2nr_raw=i32(L['f_rq_n']),
        filtered_rsrp_l2nr=_scale_rsrp(i32(L['f_rp_l'])),
        filtered_rsrp_l2nr_raw=i32(L['f_rp_l']),
        filtered_rsrq_l2nr=_scale(i32(L['f_rq_l']), _RSRQ_LO, _RSRQ_HI, RSRQ_SCALE),
        filtered_rsrq_l2nr_raw=i32(L['f_rq_l']),
        rsrq_a=(_scale(rq_a, _RSRQ_LO, _RSRQ_HI, RSRQ_SCALE) if rq_a is not None else None),
        rsrq_a_raw=rq_a,
        rsrq_b=(_scale(rq_b, _RSRQ_LO, _RSRQ_HI, RSRQ_SCALE) if rq_b is not None else None),
        rsrq_b_raw=rq_b,
    )


def _decode_cell(data: bytes, off: int, cell_size: int,
                 beam_layout: Optional[str]) -> Nr5gCellMeasurement:
    rsrp_raw = unpack_from('<i', data, off + 8)[0]
    rsrq_raw = unpack_from('<i', data, off + 12)[0]
    # Per-beam tail: remaining bytes past the fixed +16 prefix, surfaced as
    # wire-typed i32 words. Retained even where `beams` names them (see the
    # Nr5gCellMeasurement.beam_words note) — it spans the WHOLE tail including
    # any multi-beam extension, which the named decode deliberately does not.
    beam_words = [
        unpack_from('<i', data, off + o)[0]
        for o in range(16, cell_size - 3, 4)
    ]
    # ``beam_layout`` names the grounded layout for THIS version's first beam
    # block (all four versions are grounded — None for a zero-beam cell or a future version).
    # Only the first beam is named; a multi-beam extension (v0 only) is left in
    # beam_words.
    beams = ([_decode_beam(data, off + 16, beam_layout)]
             if beam_layout is not None else [])
    return Nr5gCellMeasurement(
        pci=unpack_from('<H', data, off)[0],
        pbch_sfn=unpack_from('<H', data, off + 2)[0],
        num_beams=unpack_from('<I', data, off + 4)[0],
        rsrp=_scale_rsrp(rsrp_raw),
        rsrp_raw=rsrp_raw,
        rsrq=_scale(rsrq_raw, _RSRQ_LO, _RSRQ_HI, RSRQ_SCALE),
        rsrq_raw=rsrq_raw,
        beam_words=beam_words,
        beams=beams,
    )


def parse_0xb97f(log_time: int, data: bytes) -> Optional[Diag0xB97F]:
    """Parse a 0xB97F NR5G ML1 Measurement Database Update (all versions).

    Returns None if the payload is too short, carries a u16@0 version
    outside the observed enum, or is TRUNCATED — i.e. a declared CC
    (num_cc) or cell (num_cells x stride, incl. any multi-beam extension)
    runs past the end of the payload, so the registry WARNs instead of a
    partial decode passing as complete. Bytes left
    over after every declared CC/cell is consumed (non-truncation slack) are
    still recorded in ``trailing_bytes``.
    """
    if len(data) < 4:
        return None
    version = unpack_from('<H', data, 0)[0]
    # Layer-1 version gate: reject any u16@0 outside the
    # observed enum so a future chipset-gen layout returns None instead of
    # being silently mis-parsed.
    if version not in _V:
        return None

    rec_hdr, cfg_off, nc_off, cc_meas, cell_size, _sub = _V[version]
    beam_extra = _BEAM_EXTRA[version]
    beam_layout = _VERSION_BEAM_LAYOUT.get(version)   # None only for a future version
    ssb_shift = _SSB_FLAG_SHIFT[version]              # bit position of serving SSB idx
    if len(data) < rec_hdr + CC_ID_SIZE + cc_meas:
        return None

    sub_version = unpack_from('<H', data, 2)[0]
    config_word = unpack_from('<I', data, cfg_off)[0]
    num_cc = config_word & 0xFF
    if not (1 <= num_cc <= 12):
        return None

    # v7 has no dedicated counter word (config sits at @4); v9/v0A/v0 do (@4).
    counter = unpack_from('<I', data, 4)[0] if version != 0x07 else 0
    frame_number = unpack_from('<I', data, cfg_off + 4)[0]
    timing_offset = unpack_from('<i', data, cfg_off + 8)[0]

    carriers: list[Nr5gComponentCarrier] = []
    trailing = 0
    pos = rec_hdr
    for _cc in range(num_cc):
        if pos + CC_ID_SIZE + cc_meas > len(data):
            return None  # declared CC overruns the payload (truncated)
        nr_arfcn = unpack_from('<I', data, pos)[0]
        declared_cells = data[pos + nc_off]
        # The other byte of the [4:6] identity pair — the offset num_cells does
        # NOT occupy (byte@5 on v7, byte@4 on v9/v0A/v0). Live (0xFF on no-serving
        # CCs), version-dependent semantics; surfaced RAW.
        companion = data[pos + (5 if nc_off == 4 else 4)]
        serving_pci = unpack_from('<H', data, pos + 6)[0]
        flags = unpack_from('<I', data, pos + 8)[0]
        m = pos + CC_ID_SIZE
        s_rsrp_raw = unpack_from('<i', data, m)[0]
        s_rsrp_b_raw = unpack_from('<i', data, m + 4)[0]
        # The rest of the CC meas header. Kept raw; see the
        # Nr5gComponentCarrier.meas_tail note for why it is un-named.
        meas_tail = bytes(data[m + 8:m + cc_meas])
        # RX-beam pair + (v0 only) two more serving RSRP words. The RX-beam pair's
        # OFFSET is version-dependent because v0's 28-byte header carries a FOUR-
        # value serving RSRP quad (SCAT "RSRP: a/b/c/d") where v7/v9/v0A carry two
        # ("a/b"): on cc_meas 20 the pair is at m+8 (meas_tail[0:4]); on cc_meas 28
        # serving_rsrp_c/d occupy m+8/m+12 and the pair moves to m+16.
        # SCAT agrees on 48/48 v0 layers for both the RX-beam offset (all NA)
        # and the c/d position (all 0). Reading the pair at m+8 on
        # v0 would invent two RX-beam indices out of the zero c/d words.
        rx_a = rx_b = None
        s_rsrp_c_raw = s_rsrp_d_raw = None
        if cc_meas == 28:                      # v0x00 (SDX72 RG650V-NA)
            s_rsrp_c_raw = unpack_from('<i', data, m + 8)[0]
            s_rsrp_d_raw = unpack_from('<i', data, m + 12)[0]
            _a, _b = unpack_from('<HH', data, m + 16)
            rx_a = None if _a == 0xFFFF else _a
            rx_b = None if _b == 0xFFFF else _b
        elif cc_meas == 20 and len(meas_tail) >= 4:
            _a, _b = unpack_from('<HH', meas_tail, 0)
            rx_a = None if _a == 0xFFFF else _a
            rx_b = None if _b == 0xFFFF else _b
        pos = m + cc_meas

        cells: list[Nr5gCellMeasurement] = []
        for _ci in range(declared_cells):
            if pos + _CELL_PREFIX > len(data):
                # Not even the fixed cell prefix fits: truncated. Fail loudly
                # (registry WARN) rather than silently returning the
                # complete prefix as if it were the whole record.
                return None
            # Multi-beam cells are LONGER. num_beams is read before the
            # decode so the stride is known; the extension is beyond the fixed
            # +16 prefix every named field lives in, so _decode_cell's view of
            # the cell is unchanged apart from a longer beam_words tail.
            n_beams = unpack_from('<I', data, pos + 4)[0]
            if n_beams == 0:
                # Zero-beam cell: only the fixed 16-byte prefix
                # (pci/pbch_sfn/num_beams/rsrp/rsrq) is present — no beam block.
                # Seen as a short final cell in F3-dual-mask/VoNR captures: on
                # both v9 fixtures that exhibit it the 16-byte tail has
                # num_beams=0 and rsrp=rsrq=0, and the walk
                # then closes EXACTLY on the record; no beam-bearing cell in the
                # sampled corpus has num_beams=0.
                cells.append(_decode_cell(data, pos, _CELL_PREFIX, None))
                pos += _CELL_PREFIX
                continue
            stride = cell_size + beam_extra * max(0, n_beams - 1)
            if pos + stride > len(data):
                # A beam-bearing cell (incl. a multi-beam extension) that runs
                # past the buffer: truncated — None.
                return None
            cells.append(_decode_cell(data, pos, stride, beam_layout))
            pos += stride

        # Reliable serving-vs-neighbour flag: a cell is the serving cell iff its
        # PCI equals this CC's serving_pci (matched by PCI, NOT position - the
        # serving cell is not always cells[0]). 0xFFFF == no-serving → all
        # neighbours. All cells in a CC share nr_arfcn, so PCI is unambiguous here.
        if serving_pci != _NO_SERVING:
            for c in cells:
                if c.pci == serving_pci:
                    c.is_serving = True

        carriers.append(Nr5gComponentCarrier(
            nr_arfcn=nr_arfcn,
            serving_pci=serving_pci,
            num_cells=declared_cells,
            num_cells_companion=companion,
            flags=flags,
            serving_ssb_index=(None if ((flags >> ssb_shift) & 0xF) == 0xF
                               else ((flags >> ssb_shift) & 0xF)),
            serving_rsrp=(_scale_rsrp(s_rsrp_raw) if s_rsrp_raw != 0 else None),
            serving_rsrp_b=(_scale_rsrp(s_rsrp_b_raw) if s_rsrp_b_raw != 0 else None),
            serving_rsrp_raw=s_rsrp_raw,
            serving_rsrp_b_raw=s_rsrp_b_raw,
            meas_tail=meas_tail,
            rx_beam_a=rx_a,
            rx_beam_b=rx_b,
            serving_rsrp_c=(_scale_rsrp(s_rsrp_c_raw)
                            if s_rsrp_c_raw not in (None, 0) else None),
            serving_rsrp_c_raw=s_rsrp_c_raw,
            serving_rsrp_d=(_scale_rsrp(s_rsrp_d_raw)
                            if s_rsrp_d_raw not in (None, 0) else None),
            serving_rsrp_d_raw=s_rsrp_d_raw,
            cells=cells,
        ))

    # Any bytes not consumed by whole CCs/cells (non-truncation slack)
    # surface as trailing so nothing is silently dropped.
    if pos != len(data):
        trailing = len(data) - pos
        # On a multi-beam version (v0x00) the only attested slack is a whole
        # allocated-but-unpopulated beam slot (84 zero bytes, 1/88 corpus
        # records — see _BEAM_EXTRA). Slack that is not a whole number of
        # beam slots there is a cut-off slot, i.e. truncation.
        if beam_extra and trailing % beam_extra:
            return None

    return Diag0xB97F(
        log_time=log_time,
        version=version,
        sub_version=sub_version,
        counter=counter,
        config_word=config_word,
        num_cc=num_cc,
        frame_number=frame_number,
        timing_offset=timing_offset,
        carriers=carriers,
        trailing_bytes=trailing,
    )


register(
    LOG_NR5G_ML1_MEAS_DB_UPDATE,
    name="0xB97F",
    wigle_direct=True,
    wigle_roles=("signal", "pci-earfcn-bridge", "rat-context"),
    issues=(),
    primary_issue=None,
    description="Nested per-CC NR5G measurement DB: per-cell PCI/PBCH-SFN/RSRP/RSRQ + named per-beam block for serving + neighbour cells across component carriers",
    version=16,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Full nested decode of all four observed versions (v0x07 SDX55, v0x09 "
        "SDX62, v0x0A and v0x00 SDX72): record header, per-CC identity + "
        "meas-header (num_CC is the config word's low byte, SSB periodicity the "
        "byte above it), per-cell PCI / PBCH SFN / num_beams / RSRP / RSRQ, and a "
        "named per-beam block. Layout verified by exact-length consumption across "
        "22k+ records; multi-beam cells on v0x00 are 84 B longer per extra beam "
        "(_BEAM_EXTRA), which brings v0x00 exact consumption to 87/88 (the 88th "
        "ends in one all-zero 84-B slot). "
        "RSRP scale i32/128 dBm is hardware-ground-truthed on the RM520N-GL "
        "(serving -98 dBm across AT+QENG, QMI and F3), 100% in-band over 3196 v7 "
        "serving cells, and neighbour RSRP matches AT+QSCAN SS-RSRP across 70 "
        "observations / 7 cells over a 24 dB span (mean delta +0.34 dB, stdev "
        "1.57), so per-cell RSRP is absolute per-cell dBm, not a CC aggregate. "
        "Field names on v0x07/v0x09 match SCAT's printed decode at 100% on every "
        "mapped field (301 packets / 757 cells / 3 vendors on v0x09, 500 packets "
        "/ 1514 cells / 4 vendors on v0x07); v0x00's 84-B beam, 4-value serving "
        "RSRP quad and bits[11:8] serving SSB index match SCAT on 497/498 cells "
        "and 48/48 layers. SCAT cannot decode v0x0A, and its captures carry no "
        "decodable F3, so v0x0A is grounded by in-capture cross-check on its own "
        "509 records / 692 cells: the filtered Nr2Nr pair equals the cell "
        "rsrp/rsrq exactly on 692/692 single-beam cells (pinning the v0_84 "
        "layout), and flags bits[11:8] equal the serving beam's ssb_index on "
        "507/507 CC0 cells. F3 corroborates pbch_sfn and serving RSRP in-capture "
        "on the RM520N-GL (v0x09) and across 66 SDX55 (v0x07) captures. "
        "0xB97F carries no SINR on any version: SCAT's complete decode has no "
        "such field and 0/774,935 F3 records in the reference capture mention it. "
        "Known gaps: beam word3/word4 and the remaining meas_tail bytes are "
        "un-named (no source labels them); beam_id_a/b, rx_beam_a/b, "
        "serving_rsrp_c/d and the L2Nr filtered pair are name-grounded but 0 or "
        "NA across the corpus; num_cells_companion is version-dependent (serving "
        "cell array index on v0x07, presence flag on v0x09) and stays raw; "
        "_BEAM_EXTRA is 0 for v0x07/v0x09/v0x0A by observation only. Truncated "
        "records return None; a 16-byte final cell is decoded as a zero-beam cell."
    ),
    source_url="",
    # Fields cover the record header, per-CC identity and meas-header, per-cell
    # fields, and the named per-beam block (Nr5gBeam), which is named on all four
    # versions — v7/v9/v0 against SCAT, v0A by in-capture cross-check.
    # beam_words is retained as the raw surface and the multi-beam stride
    # detector.
    fields_identified=35,
    fields_parsed=34,
    field_invariants={
        "version": {"enum": [0x00, 0x07, 0x09, 0x0A]},
    },
)(parse_0xb97f)
