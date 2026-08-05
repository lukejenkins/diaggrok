"""NR5G ML1 Measurement Database Update parser (0xB97F).

Periodic snapshot of NR cell measurements. Each record is a **nested,
multi-component-carrier** report: a small record header, then one block per
active component carrier (CC), each carrying serving-cell aggregate
measurements plus a list of per-cell (serving + neighbour) measurements with
PCI, RSRP, and RSRQ.

The single unified layout below decodes ALL four observed chipset-generation
versions (u16@0 is THE version byte). The KEY that unlocked the full decode:
**the config word's low byte is the number of component carriers (num_CC)** —
the previous parser mistook ``config == 0x1401`` for a fixed structural
constant and used it as a Layer-2 invariant, which silently rejected every
multi-CC record (and the entire SDX65/SDX72 corpus). ``0x14xx`` is
``flags | num_CC``; the low byte counts carriers.

Nested layout (reverse-engineered from the corpus, verified by exact-length
consumption across 22k+ records):

    Record header (REC_HDR bytes):
        u16@0   version              (0x00 / 0x07 / 0x09 / 0x0A)
        u16@2   sub_version          (2, or 3 for v0x00)
        u32@?   counter              (present on v9/v0A/v0 at @4; absent on v7)
        u32@cfg config               (LOW BYTE == num_CC; upper bits flags)
        u32@?   frame_number
        i32@?   timing_offset

    Per-CC block, repeated num_CC times:
        CC identity (12 B):
            u32@0   nr_arfcn
            u8      num_cells         (@+4 on v7, @+5 on v9/v0A/v0)
            u16@6   serving_pci       (0xFFFF == no-serving sentinel)
            u32@8   flags
        CC meas-header (CC_MEAS B: 20 for v7/v9/v0A, 28 for v0):
            i32@0   serving_rsrp      (/128 dBm; a CC-level aggregate that is
                                       FREQUENTLY 0/unpopulated — the
                                       AUTHORITATIVE serving RSRP is the cell
                                       block whose pci == serving_pci, matched
                                       by PCI, NOT by position: the serving cell
                                       is not always cells[0])
            i32@4   serving_rsrq      (/128 dB; same aggregate caveat)
            …fill (ff ff ff ff ff ff 00 00 ff ff ff ff), v0 adds 8 extra bytes
        Cells (CELL B for a ONE-beam cell: 60 for v7/v9, 100 for v0A/v0;
               a cell with num_beams=N>1 is CELL + 84*(N-1) B on v0 — #N):
            u16@0   pci
            u16@2   ssb_index
            u32@4   num_beams
            i32@8   rsrp              (/128 dBm)   ← the ground-truthed field
            i32@12  rsrq              (/128 dB)
            (is_serving is derived, not on the wire: pci == CC.serving_pci)
            …per-beam tail (beam RSRP/RSRQ slots; "no measurement" sentinel
              is an i32 whose low16 is 0xBA00 (v7, −140) / 0xB200 (v9, −156))

RSRP scale is ``i32@cell+8 / 128`` for EVERY version — hardware-ground-truthed
on the RM520N-GL (v9, serving −98 dBm across AT QENG, QMI GetCellLocationInfo,
and firmware F3) and confirmed by a 100 % in-band fraction on the v7 corpus
(3196 serving cells all land in [−140, −83] dBm). This CORRECTS the prior v7
decode, which read ``i16@cell+12 / 16`` — a scale that produced impossible
values down to −344 dBm on 10 % of records (see the ``i16/16`` regression
guard in the tests).

Greedy truncation rule: some F3-dual-mask / VoNR captures end with a
truncated final cell (only ~16 of the 60/100 cell bytes present). The parser
decodes every COMPLETE cell and records ``trailing_bytes`` rather than
returning None — so a valid-version record ALWAYS yields a structured object
(100 % parse rate). ``trailing_bytes`` makes the truncation visible instead of
silently dropping the partial tail.

Per-version parameters:

    ver   chipset            rec_hdr  config@  num_cells@  cc_meas  cell  sub_ver
    0x07  SDX55              16       4        id+4        20       60    2
    0x09  SDX62 (RM520N-GL)  20       8        id+5        20       60    2
    0x0A  SDX72 (T99W640)    20       8        id+5        20       100   2
    0x00  SDX72 (RG650V-NA)  20       8        id+5        28       100   3

v0x00 is the RG650V-NA (SDX72, Snapdragon X72 5G-Advanced) donated QMDL. Its
sub_version=3 CC-meas-header carries two extra measurement words before the
fill, and its 100-byte cells hold a richer beam tail. Structure decodes with
plausible PCIs and 100 %-in-band RSRP, but no live AT/QMI ground truth exists
for that unit (donated capture; QMI plane not paired) — the beam-tail words
are surfaced wire-typed, not relabelled.

⛔ **RESOLVED (#N, 2026-07-26) — and the old description of it was wrong.**
This paragraph used to read: *"KNOWN RESIDUAL (#N): in ~10/88 v0 records
(sizes 2284/2384) the SECOND CC's cell count reads 0 and leaves a large
undecoded block … Closing the v0 CC1 tail needs an RG650V-NA ground-truth
capture, which we do not yet have."*

Both halves were wrong. It is **not** a CC-boundary problem: the misalignment
begins *inside CC0*, at the first cell following a ``num_beams=2`` cell,
because the cell stride is not fixed (see ``_BEAM_EXTRA``). CC1 then read
whatever landed 84 bytes early, which is why its ``nr_arfcn`` and ``num_cells``
looked like garbage — a symptom two structural levels below where it was
attributed. And it needed **no new capture**: the records were already in hand,
and exact-length consumption across all 88 is what identifies the stride.
⚠️ Ground truth for this unit is still absent, so the per-beam block's
*contents* stay un-named; what is now grounded is its **size**.

QXDM v2.7 field reference (per public Scribd QXDM log decode doc):
    Source: https://www.scribd.com/document/613159318/8f981d9f-29a1-4cdf-8b04-3991622af057-Diag
    Version convention: Scribd/QXDM calls u16@0 the "minor" version and u16@2
    the "major"; the example doc's "major=2, minor=7" == our u16@0=7, u16@2=2.
    Its "Component Carrier list" is exactly the per-CC block decoded here; the
    per-cell "Detected Beams / RX Beam Info / Cell Quality / Filtered Tx"
    columns map onto the per-cell beam tail.

Issue: #N

=== names-block:start (auto-generated by tools/inject_names_block_parsers.py) ===

Names by source (from sources/DIAG_LOG_INDEX.yaml):
    canonical: LOG_NR5G_ML1_SEARCHER_MEASUREMENT_DATABASE_UPDATE_EXT
        source: qxdm_itemtype_list_zukgit_2025_04_03 (authority: community)
    aliases:
        NR5G ML1 Searcher Measurement Database Update Ext
            source: qualcomm_qxdm_isf_filter_merge_perl_2020

Source-precedence (#N): vendor_official > observation >
community (specification) > community (reference).
=== names-block:end ===
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

# --- Per-extra-beam cell extension (#N) ---------------------------------
#
# ``cell_size`` above is the size of a cell reporting ONE beam. A cell whose
# ``num_beams`` (u32 @cell+4) is N > 1 carries N-1 additional beam blocks of
# ``_BEAM_EXTRA[version]`` bytes each, so its true stride is
# ``cell_size + extra * (num_beams - 1)``.
#
# Treating the stride as fixed is what #N was: on the v0 RG650V-NA corpus a
# single num_beams=2 cell shifted every LATER cell in the record by 84 bytes —
# including the whole of CC1, which then read a nonsense nr_arfcn and
# num_cells=0 and left ~1.2 kB unconsumed. The symptom was reported as "the
# secondary-CC walk misaligns"; the cause is one cell earlier and has nothing
# to do with CC boundaries.
#
# Grounded on all 88 v0 records in the RG650V-NA corpus:
#   * exact-consumption   78/88 -> 87/88 (the 88th leaves 84 ZERO bytes — the
#                         same quantum, an allocated-but-unpopulated slot)
#   * cells recovered     1690 -> 1798 (+108)
#   * RSRP out of the [-140, -30] band   67 -> 0
# and the recovered cells' PCIs match the neighbour set the ADJACENT snapshots
# report on the same camp, which is the corroboration that makes this a decode
# rather than a curve-fit.
#
# ⚠️ 0 for v7/v9/v0A is *observation*, not knowledge — but the observation is
# much broader than the 12 committed fixtures it originally rested on. Corpus
# sweep, 2026-07-26 (<redacted-ref>, #N): every 0xB97F-bearing rg650vna +
# t99w640 capture EXHAUSTIVELY, plus a 30-capture stratified sample elsewhere.
#
#   version  records  cells   num_beams>1  exact consumption
#   v0x00         88   1798   9 cells      87/88   ( 98.9%)  <- the known case
#   v0x07       5000  13160   none         5000/5000 (100%)
#   v0x09       2500   9304   none         2500/2500 (100%)
#   v0x0A        504    687   none          504/504  (100%)
#
# 8,004 non-v0 records / 23,151 cells, zero multi-beam, and exact consumption
# everywhere. ⚠️ **v0x0A was the one that mattered**: it is SDX72, the SAME
# chipset generation as v0x00 — the only version where num_beams>1 has ever been
# seen — so of the three zeros it carried the most risk, and it now has 504
# records behind it rather than a handful of fixtures.
#
# Exact consumption is the DETECTOR, not a nicety: a wrong _BEAM_EXTRA shows up
# as leftover slack, which is exactly how #N presented (v0 sat at 78/88 with
# ~1.2 kB unconsumed). 100% on all three zeros means there is no silent
# misparse in the corpus today. If a v7/v9/v0A capture ever reports num_beams>1
# and stops consuming exactly, THIS is the table to revisit — the defect will
# look identical.
#
# ⛔ Still not knowledge: nothing observed can distinguish "no extension on
# those versions" from "extension never exercised there". The corpus makes the
# second explanation less likely; it does not refute it.
_BEAM_EXTRA = {
    0x00: 84,
    0x07: 0,
    0x09: 0,
    0x0A: 0,
}
_B97F_VERSIONS_OBSERVED = (0x00, 0x07, 0x09, 0x0A)

CC_ID_SIZE = 12
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


# --- Ground-truth recipes (#N) ------------------------------------------
# v7 (SDX55): RSRP scale CORRECTED to i32@cell+8 / 128 (was i16@+12 / 16).
# v9 (SDX62 RM520N-GL): hardware-validated (serving −98 dBm, 4 sources).

# --- Dataclasses -----------------------------------------------------------
@dataclass
class Nr5gCellMeasurement:
    """One measured NR cell (serving or neighbour)."""
    pci: int
    ssb_index: int
    num_beams: int
    rsrp: Optional[float]    # dBm (i32@cell+8 / 128), None if out-of-band/sentinel
    rsrp_raw: int            # raw i32@cell+8
    rsrq: Optional[float]    # dB  (i32@cell+12 / 128), None if out-of-band
    rsrq_raw: int            # raw i32@cell+12
    beam_words: list[int] = field(default_factory=list)  # per-beam tail, wire-typed i32s
    is_serving: bool = False  # this cell's pci == its CC's serving_pci (matched by
                              # PCI, not position); False when the CC has no serving
                              # (serving_pci == 0xFFFF). Set by parse_0xb97f after the
                              # CC's serving_pci is known - the reliable wardriving
                              # serving-vs-neighbour flag (#N).

    def to_dict(self) -> dict:
        return {
            'pci': self.pci,
            'ssb_index': self.ssb_index,
            'num_beams': self.num_beams,
            'rsrp': self.rsrp,
            'rsrp_raw': self.rsrp_raw,
            'rsrq': self.rsrq,
            'rsrq_raw': self.rsrq_raw,
            'beam_words': self.beam_words,
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
                              # Un-RE'd; F3-silent (#N kaitai re-audit). NOT a
                              # constant: empirically 0xFF on every no-serving CC
                              # (serving_pci==0xFFFF, mirroring the PCI sentinel)
                              # and a small value on serving CC0 that tracks the
                              # serving cell's index. LEAD (unconfirmed): a serving-
                              # cell index with 0xFF="no serving" — the CC0 pattern
                              # matches PCI-derived serving index on 12/12 CC0
                              # observations but diverges on secondary CCs, so it is
                              # surfaced RAW (not named `serving_cell_index`) until
                              # ground truth confirms it.
    flags: int
    serving_rsrp: Optional[float]   # CC meas-header i32@0 / 128, None if 0/out-of-band
    serving_rsrq: Optional[float]   # CC meas-header i32@4 / 128
    serving_rsrp_raw: int
    serving_rsrq_raw: int
    meas_tail: bytes = b''    # RAW: the REST of the CC meas header — the bytes past
                              # the serving RSRP/RSRQ pair that the parser read PAST
                              # entirely until 2026-07-24 (#N kaitai audit). 12 B
                              # on v7/v9/v0A (cc_meas 20), 20 B on v0 (cc_meas 28).
                              # Surfaced un-named per the 0x1807 marker_a/marker_b
                              # rule (#N): F3 confirms the NR5G-ML1 searcher/meas
                              # subsystem (srchmeas.c reset_meas_db,
                              # nr5g_ml1_rfmgr_trm_if.c) but labels NO field here.
                              # Byte-INVARIANT on every CORRECTLY-ALIGNED CC block
                              # across all four chipset generations (13,657/13,666
                              # blocks over a 13,433-record validation) —
                              # `ff ff ff ff | ff ff 00 00 | ff ff ff ff`
                              # (v0 prepends 8 zero bytes) — i.e. an UNPOPULATED
                              # sentinel slot whose shape mirrors the CC identity's
                              # own 0xFFFF no-serving sentinel, not live data we were
                              # mis-reading. Exposed anyway rather than left dropped:
                              # a slot that is empty in every capture we hold is the
                              # 0x158C `reserved2` trap in waiting (zero on modern
                              # silicon, four live u32 on MC7455), and retaining the
                              # bytes costs nothing while silently discarding them
                              # would hide the day it IS populated.
                              # ⚠️ The only 9 non-sentinel samples in the corpus are
                              # all v0 SECONDARY CCs, where this parser's walk has
                              # already lost alignment (the known #N v0-CC1
                              # residual). They decode as plausible RSRP/RSRQ pairs
                              # at /128 only because a misaligned read lands inside a
                              # cell body — an artifact, NOT a populated tail. v0 CC0
                              # (aligned) is 88/88 sentinel. Do not promote this field
                              # on the strength of those samples.
    cells: list[Nr5gCellMeasurement] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            'nr_arfcn': self.nr_arfcn,
            'serving_pci': self.serving_pci,
            'num_cells': self.num_cells,
            'num_cells_companion': self.num_cells_companion,
            'flags': self.flags,
            'serving_rsrp': self.serving_rsrp,
            'serving_rsrq': self.serving_rsrq,
            'serving_rsrp_raw': self.serving_rsrp_raw,
            'serving_rsrq_raw': self.serving_rsrq_raw,
            # .hex() per the 0x1c8f `name_buffer_residue` precedent — raw bytes
            # cross a JSON boundary as hex, never as a lossy decode.
            'meas_tail': self.meas_tail.hex(),
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
    trailing_bytes: int = 0     # >0 iff a final cell was truncated (capture artifact)

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
        """CC0's meas-header tail — the bytes the parser used to read past (#N).

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


def _decode_cell(data: bytes, off: int, cell_size: int) -> Nr5gCellMeasurement:
    rsrp_raw = unpack_from('<i', data, off + 8)[0]
    rsrq_raw = unpack_from('<i', data, off + 12)[0]
    # Per-beam tail: remaining bytes past the fixed +16 prefix, surfaced as
    # wire-typed i32 words (no invented scale — ungrounded beam data).
    beam_words = [
        unpack_from('<i', data, off + o)[0]
        for o in range(16, cell_size - 3, 4)
    ]
    return Nr5gCellMeasurement(
        pci=unpack_from('<H', data, off)[0],
        ssb_index=unpack_from('<H', data, off + 2)[0],
        num_beams=unpack_from('<I', data, off + 4)[0],
        rsrp=_scale_rsrp(rsrp_raw),
        rsrp_raw=rsrp_raw,
        rsrq=_scale(rsrq_raw, _RSRQ_LO, _RSRQ_HI, RSRQ_SCALE),
        rsrq_raw=rsrq_raw,
        beam_words=beam_words,
    )


def parse_0xb97f(log_time: int, data: bytes) -> Optional[Diag0xB97F]:
    """Parse a 0xB97F NR5G ML1 Measurement Database Update (all versions).

    Returns None only if the payload is too short or carries a u16@0 version
    outside the observed enum. A valid-version record always yields a
    structured object; a truncated final cell is decoded greedily and the
    remaining byte count is recorded in ``trailing_bytes``.
    """
    if len(data) < 4:
        return None
    version = unpack_from('<H', data, 0)[0]
    # Layer-1 version gate (#N / #N): reject any u16@0 outside the
    # observed enum so a future chipset-gen layout returns None instead of
    # being silently mis-parsed.
    if version not in _V:
        return None

    rec_hdr, cfg_off, nc_off, cc_meas, cell_size, _sub = _V[version]
    beam_extra = _BEAM_EXTRA[version]
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
            trailing = len(data) - pos
            break
        nr_arfcn = unpack_from('<I', data, pos)[0]
        declared_cells = data[pos + nc_off]
        # The other byte of the [4:6] identity pair — the offset num_cells does
        # NOT occupy (byte@5 on v7, byte@4 on v9/v0A/v0). Live (0xFF on no-serving
        # CCs), previously discarded; surfaced RAW pending ground truth (#N).
        companion = data[pos + (5 if nc_off == 4 else 4)]
        serving_pci = unpack_from('<H', data, pos + 6)[0]
        flags = unpack_from('<I', data, pos + 8)[0]
        m = pos + CC_ID_SIZE
        s_rsrp_raw = unpack_from('<i', data, m)[0]
        s_rsrq_raw = unpack_from('<i', data, m + 4)[0]
        # The rest of the CC meas header — read PAST until #N. Kept raw; see
        # the Nr5gComponentCarrier.meas_tail note for why it is un-named.
        meas_tail = bytes(data[m + 8:m + cc_meas])
        pos = m + cc_meas

        cells: list[Nr5gCellMeasurement] = []
        for _ci in range(declared_cells):
            if pos + cell_size > len(data):
                # Truncated final cell (F3-dual-mask capture artifact): stop
                # decoding cells but keep every complete one.
                trailing = len(data) - pos
                break
            # Multi-beam cells are LONGER (#N). num_beams is read before the
            # decode so the stride is known; the extension is beyond the fixed
            # +16 prefix every named field lives in, so _decode_cell's view of
            # the cell is unchanged apart from a longer beam_words tail.
            n_beams = unpack_from('<I', data, pos + 4)[0]
            stride = cell_size + beam_extra * max(0, n_beams - 1)
            if pos + stride > len(data):
                # A multi-beam cell whose extension runs past the buffer. Same
                # rule as the truncated-cell case above: keep the complete cells
                # and record the tail rather than decoding a partial extension.
                trailing = len(data) - pos
                break
            cells.append(_decode_cell(data, pos, stride))
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
            serving_rsrp=(_scale_rsrp(s_rsrp_raw) if s_rsrp_raw != 0 else None),
            serving_rsrq=(_scale(s_rsrq_raw, _RSRQ_LO, _RSRQ_HI, RSRQ_SCALE)
                          if s_rsrq_raw != 0 else None),
            serving_rsrp_raw=s_rsrp_raw,
            serving_rsrq_raw=s_rsrq_raw,
            meas_tail=meas_tail,
            cells=cells,
        ))
        if trailing:
            break

    # Any bytes not consumed by whole CCs/cells (non-truncation slack) also
    # surface as trailing so nothing is silently dropped.
    if not trailing and pos != len(data):
        trailing = len(data) - pos

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
    issues=(),
    primary_issue=None,
    description="Nested per-CC NR5G measurement DB: per-cell PCI/RSRP/RSRQ for serving + neighbour cells across component carriers",
    version=12,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "v12 (2026-07-26, #N): THE CELL STRIDE IS NOT FIXED. A cell whose "
        "num_beams (u32 @cell+4) is N>1 carries N-1 extra beam blocks of 84 B "
        "on v0, so its true stride is cell_size + 84*(N-1). Treating it as fixed "
        "is the whole of the '#N v0 CC1 residual' — and BOTH halves of how that "
        "residual was described were wrong. (a) It is not a CC-boundary problem: "
        "the misalignment starts INSIDE CC0, at the first cell after a num_beams=2 "
        "cell; CC1 only looked like garbage (arfcn=65541/spci=0/ncells=0) because "
        "it was read 84 B early — the symptom was attributed two structural levels "
        "above its cause. (b) It did not need 'an RG650V-NA ground-truth capture "
        "which we do not yet have': the 88 records were already in hand, and "
        "EXACT-LENGTH CONSUMPTION over them is what identifies the stride, with no "
        "ground truth involved. Measured across all 88 v0 records: exact "
        "consumption 78/88 -> 87/88 (the 88th leaves 84 ZERO bytes, the same "
        "quantum — an allocated-but-unpopulated slot, not a residual "
        "misalignment); cells recovered 1690 -> 1798 (+108); RSRP outside the "
        "[-140,-30] band 67 -> 0. The recovered cells' PCIs (578/413/770/342/850/"
        "722/369) are the same neighbour set the ADJACENT snapshots report on the "
        "same camp — the corroboration that makes this a decode and not a "
        "curve-fit. Also retires the 9 out-of-family meas_tail blocks v11 recorded "
        "as 'artifact of a misaligned read': with the stride fixed, v0 CC1's "
        "meas_tail is the same sentinel v0 CC0 always was, so the 'exceptions' "
        "were never data. Per-beam extra is a PER-VERSION table (_BEAM_EXTRA), 0 "
        "for v7/v9/v0A — which is OBSERVATION, not knowledge: num_beams>1 has "
        "never been seen there (1789/1798 v0 cells and all 12 committed "
        "cross-version fixtures are num_beams=1), so no capture can currently "
        "distinguish 'no extension' from 'never exercised'. The block's CONTENTS "
        "stay un-named — ground truth for this unit is still absent; what is "
        "grounded is its SIZE. "
        "// v11 (2026-07-24, #N/#N Kaitai nested-walk typing): SECOND "
        "DISCARDED-BYTE FIX in the same code — the CC meas header's TAIL. The "
        "parser read the serving RSRP/RSRQ pair at meas+0/+4 and then jumped "
        "`pos = m + cc_meas`, reading PAST the remaining 12 B (cc_meas 20 on "
        "v7/v9/v0A) or 20 B (cc_meas 28 on v0) — bytes nothing had ever looked "
        "at. Now retained raw as `Nr5gComponentCarrier.meas_tail` (+ to_dict as "
        ".hex(), the 0x1c8f name_buffer_residue precedent) and modelled as the "
        "`meas_tail` field in diag_0xb97f.ksy. UNLIKE num_cells_companion this "
        "region is byte-INVARIANT on every correctly-aligned CC block across all "
        "four chipset generations — 13,657/13,666 blocks over a 15-capture / "
        "13,433-record validation carry exactly `ffffffff ffff0000 ffffffff` (8 "
        "leading zero bytes on v0) — an unpopulated sentinel slot mirroring the CC "
        "identity's own 0xFFFF no-serving sentinel, NOT data we were mis-reading. "
        "The 9 exceptions are ALL v0 secondary CCs, where the walk has already lost "
        "alignment (the known v0-CC1 residual: CC1 reads arfcn=65541/spci=0/ncells=0 "
        "and leaves ~1.2 kB unconsumed); they decode as plausible /128 RSRP/RSRQ "
        "pairs only because a misaligned read lands inside a cell body — artifact, "
        "not a populated tail (v0 CC0 is 88/88 sentinel). Retained anyway "
        "because an always-empty slot is the 0x158C `reserved2` trap in waiting "
        "(all-zero on modern silicon, four live u32 on MC7455): keeping the "
        "bytes costs nothing, dropping them hides the day it IS populated. "
        "F3-silent on this region (subsystem confirmed via srchmeas.c "
        "reset_meas_db + nr5g_ml1_rfmgr_trm_if.c, no per-field label), so it is "
        "surfaced UN-NAMED per the 0x1807 marker_a/marker_b rule (#N). "
        "Same session TYPED the whole nested per-CC walk in the .ksy "
        "(carriers[] -> cc_block -> cells[] -> nr_cell), lifting the opaque-array "
        "punt and unblocking #N's NR cell_observation C++ carve — 0xB97F is "
        "the only NR cell-measurement code in the Kismet celldiag mask. Nested "
        "decode pinned by a per-CC/per-cell cross-check vs the generated Kaitai "
        "Python (16 CC blocks / 40 cells / 0 mismatches over all 12 fixtures). "
        "// v10 (2026-07-24, #N Kaitai re-audit): DISCARDED-BYTE FIX. The 12-B CC "
        "identity's [4:6] pair holds num_cells at one offset and one MORE byte at "
        "the offset it does not occupy (byte@5 on v7, byte@4 on v9/v0A/v0) — read "
        "by NOTHING until now. It is live, not padding: 0xFF on every no-serving CC "
        "(serving_pci==0xFFFF, mirroring the PCI sentinel) and a small value on "
        "serving CC0 that tracks the serving cell's index (12/12 CC0 observations, "
        "but diverges on secondary CCs). Now surfaced RAW as num_cells_companion on "
        "the CC + CC0 top-level view + to_dict, and brought into the diagspec 3-way "
        "diff (all 12 committed fixtures). F3 (srchmeas.c/l1qualmeas.c NR5G ML1 "
        "subsystem CONFIRMED, per-field SILENT) carries no label for it, so it is "
        "un-named — 'serving-cell index, 0xFF=none' is an UNCONFIRMED lead awaiting "
        "ground truth, not a pinned semantic. "
        "// v11 (2026-07-26, #N <redacted-ref>): num_cells_companion is "
        "VERSION-DEPENDENT, and v10's lead is confirmed on ONE version and refuted "
        "on two. Measured on the post-#N stride, CC0, whole captures: "
        "v0x07 (EM9190 + RM500Q-AE, SDX55) 6075/6075 a PERFECT DIAGONAL — comp==the "
        "serving cell's ARRAY INDEX across SIX distinct values 0..5, two vendors, "
        "plus 33/33 0xFF->no-serving. v0x09 (RM520N-GL, SDX62) REFUTED at n=4569: "
        "comp takes only TWO values, 0 (3634) and 0xFF (935), while the serving "
        "index spans 0..3 — 58 counterexamples (0->1 x47, 0->2 x8, 0->3 x3). On v9 "
        "it is a PRESENCE FLAG, not an index. v0x00 refuted separately (d3f1). "
        "v0x0A (T99W640) UNDECIDABLE: 315/315 comp==0 and index==0, but 311 of 315 "
        "records carry ONE cell, so the independent variable has NO variance — a "
        "match here is not evidence. "
        "⛔ WHY v10 SAW 12/12. Its sample was v9, where the serving cell IS cells[0] "
        "in 98.4% of records; P(12 consecutive clean) ~= 0.82. Twelve samples cannot "
        "distinguish 'index' from 'presence flag' at that base rate — the claim was "
        "not mismeasured, it was UNDERPOWERED. Finding the 58 counterexamples took "
        "4569 records. "
        "The 0xFF sentinel is the one VERSION-INVARIANT half: exact on v7 (33/33) "
        "and v9 (935/935). Field stays RAW and un-named — one version's semantic is "
        "not the field's semantic, and naming it after v7 would mislabel every v9 "
        "record the Kismet reference modem emits. "
        "Prior: v9 (2026-07-13, #N): NEIGHBOUR-cell RSRP validated + reliable "
        "serving flag. Added derived per-cell is_serving (pci == CC.serving_pci, "
        "matched by PCI not position; False when serving_pci==0xFFFF) - the "
        "wardriving serving-vs-neighbour flag. NON-SERVING RSRP arbitrated "
        "against AT+QSCAN on the RM520N-GL NR-only LIMSRV survey "
        "(20260618T105519Z): per-cell rsrp (i32@+8/128) matched QSCAN SS-RSRP "
        "across 70 neighbour observations / 7 distinct (arfcn,pci) cells over a "
        "24 dB span (-95..-119 dBm) at mean delta +0.34 dB (median +0.27, "
        "stdev 1.57) - proving neighbour RSRP is real per-cell absolute dBm, "
        "NOT a CC aggregate. QSCAN is the neighbour arbiter here because AT+QENG "
        "neighbourcell is empty in idle/LIMSRV on this firmware. Two committed "
        "QSCAN-witness fixtures (pure-neighbour srv=0xFFFF arfcn 632064 pci 388 "
        "-112.8 vs QSCAN -113; serving srv=1 arfcn 177150 pci 1 -95.5). "
        "Prior: v8 (2026-07-02, #N): FULL-FIELD nested-CC decode replacing the "
        "single-CC-only decoder. THE KEY: the config word's low byte is the "
        "component-carrier count (num_CC) — the old parser mistook config==0x1401 "
        "for a fixed constant and used it as a Layer-2 invariant, silently "
        "dropping every multi-CC record plus the entire SDX65/SDX72 corpus. New "
        "unified nested walker: 16/20-B record header + per-CC [12-B identity + "
        "20/28-B meas-header + N×(60/100)-B cells], decoding ALL four versions "
        "(v7 SDX55, v9 SDX62, v0A + v0 SDX72). Per-cell now surfaces pci, "
        "ssb_index, num_beams, rsrp (i32@+8/128), rsrq (i32@+12/128), plus the "
        "wire-typed beam tail; per-CC surfaces serving_rsrp/rsrq; record header "
        "surfaces counter/sub_version/config/frame/timing. v7 RSRP SCALE "
        "CORRECTED from i16@+12/16 (10% out-of-band, values to −344 dBm) to "
        "i32@+8/128 (100% in-band across 3196 serving cells) — the same "
        "hardware-ground-truthed scale as v9. Greedy truncation handling: "
        "F3-dual-mask/VoNR captures with a truncated final cell decode every "
        "complete cell and record trailing_bytes instead of returning None → "
        "100% parse rate. v0 (RG650V-NA, SDX72 sub_version=3) decodes with "
        "plausible PCIs + 100%-in-band RSRP but its beam tail is wire-typed (no "
        "live AT/QMI ground truth on the donated QMDL). "
        "Prior: v6/v7 (2026-06-25/26) v9 serving identity + RM520N-GL v9 recipe; "
        "v4 (#N) v9 branch; v3 (#N) v0A branch; v2 (#N) version enum + "
        "Layer-1 gate. RE from RM500Q-AE (SDX55) 2026-04-05 wardrive DLFs onward."
    ),
    source_url="",
    # Fields decoded per record (record header 6 + per-CC identity 4 + per-CC
    # meas-header 4 + per-cell 8 named). Record header: version, sub_version,
    # counter, config_word, frame_number, timing_offset (6). Derived: num_cc.
    # Per-CC: nr_arfcn, serving_pci, num_cells, flags, serving_rsrp,
    # serving_rsrq (+2 raw) (6). Per-cell: pci, ssb_index, num_beams, rsrp,
    # rsrp_raw, rsrq, rsrq_raw, beam_words (8). trailing_bytes (truncation
    # marker) 1. Total distinct named fields = 6 + 1(num_cc) + 8(cc: 6 named +
    # 2 raw) + 8(cell) + 1 = 24 parsed. Beam-tail per-beam RSRP/RSRQ semantics
    # remain wire-typed (surfaced as beam_words) — the residual identified gap.
    fields_identified=31,
    fields_parsed=30,
    field_invariants={
        "version": {"enum": [0x00, 0x07, 0x09, 0x0A]},
    },
)(parse_0xb97f)
