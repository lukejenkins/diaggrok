"""0x4177 — WCDMA Step-1 search (LOG_WCDMA_STEP_1_EDITION_2) on v=0x01; historically
"LTE PHY" on v=0x05/0x07/0x08/0x0b. 5 chipset-keyed versions, stride-family encoding.

**v=0x01 (MDM9625, Foxconn T77W595 / HP X5) is F3-grounded as the WCDMA
Step-1 (P-SCH slot-sync) searcher's peak list — the canonical name is right.**
See "v=0x01" below; it re-opens the LTE attribution of the other versions.

Corpus: 194,395 records / 44 captures. Unlike codes where each version maps
1:1 to a payload size, 0x4177 is a **stride-family** code: each version has
a fixed base header size and a fixed per-cell stride, with the payload size
varying by the number of inline cell entries:

  ver  | base | stride | sizes observed (records)             | chipset
  -----+------+--------+--------------------------------------+----------------
  0x05 |  29B |   6B   | 29 (4,530 — all MC7455); 35, 41, 47, | MDM9x30
        |      |        | 125 (11 of 283 on the AirCard 791L)  | Sierra MC7455
        |      |        |                                      | (0 cells) +
        |      |        |                                      | MDM9x35 791L
  0x07 |  34B |   7B   | 34, 41, 48, 55, 62, 69, 76, 83, 90,  | MDM9207 +
        |      |        | 97, 146 (top: 34B@89%)               | MDM9x07 —
        |      |        |                                      | Quectel EG25-G,
        |      |        |                                      | EG95-NA
  0x08 |  42B |   7B   | 42..154 in 7B steps (top: 42B@99.0%) | SDX20 LM960 +
        |      |        |                                      | MDM9250 MC7411
  0x0b |  25B |   5B   | 25..185 in 5B steps (top: 25B@82%)   | SDX55 — Telit
        |      |        |                                      | FN980m, Sierra
        |      |        |                                      | EM9190

Per-cell stride structure (v=0x05 6B, v=0x07 7B, v=0x08 7B, v=0x0b 5B) —
the same on every version, and the same shape as v=0x01's Step-1 peak
(corpus-verified over 241 captures and 518,097 records):

    [+0..+1]  u16 LE — wide-cardinality identifier (``cell_id``). NOT a PCI
                       on any version (see below); < 20480 corpus-wide.
    [+2..+3]  u16 LE — signal-quality / energy word. Cells in a record are
                       SORTED DESCENDING by it. **u16, not u8 (v9):** [+3] is
                       1 or 2 on 29 v=0x07 and 174 v=0x0b corpus elements, and
                       the u16 reading is the better-sorted one (v0x07
                       1,037 vs 1,028 / 1,140 multi-cell records; v0x0b 5,089
                       vs 5,045 / 5,825). Chipset-specific encoding; the dBm
                       scale is ungrounded.
    [+4]      u8     — enum-2 flag (0x00 / 0x01) on EVERY version. On v=0x08
                       it is 1 on 5,863 / 15,193 corpus elements; <= v8 read
                       [+3..+6] there as "4 bytes of zero padding" and
                       discarded it.
    [+5]      v=0x05 zero pad; [+5..+6] v=0x07/0x08 zero pad (CONST 0x00).

Header skeleton (v9 surfaces it raw; F3 names none of these bytes on
v=0x05/0x07/0x08/0x0b — offsets in ``_HDR``): lead bytes, ``hdr_s16`` (i16),
a constant run, a 7-byte ``hdr_var_raw`` (v05/v07/v08), ``hdr_word`` (u16, in
the slot v=0x01 calls ``freq_word``), ``00 00``, the segment ``2d 20 00 XX
00`` (XX 0x60 on v05/v08, 0x47 on v07/v0b), and ``hdr_count`` (u16): the
elements FOUND, == n_cells or greater when the 16-entry cap clips (v0x0b:
== n_cells on every record, up to 32). v07/v08/v0b end in a short tail
(``00 00 68 01`` / ``68 01`` constants, ``ff``x6 on v08) carrying one
version-only u16 on v08 ([34:36]) and two on v0b ([8:10], [23:25]). Every
constant holds on 100% of its version's corpus records (``hdr_const_ok``).

v=0x07 was validated over 1,800 EG25-G + EG95-NA records (212 with cells /
518 cells).

F3 attribution, per version
---------------------------

  v=0x07 (MDM9207 EG25-G, one F3 capture, 1,406 records / 895
    cell-entries): LTE ML1/PHY attribution grounded on 26,368 co-present
    LTE-ML1 ``0x79`` plaintext F3 prints (lte_ml1_dlm_stm cell-switching,
    lte_ml1_bplmn_int cell-measurement, lte_ml1_rfmgr RF tune; zero
    GNSS/NR). cell_id is not a PCI: 26/895 = 2.9% in PCI range 0-503, while
    F3 lte_ml1_bplmn_int.c:1485 prints the true measured cells as
    (EARFCN,PCI) — (975,<pci>)(2050,<pci>)(2175,<pci>)(2300,<pci>)(5035,<pci>)
    (900,<pci>)… all PCIs in-range. A field/F3 correlation search (widths
    1,2,4 + f32) finds 0 hypotheses: no body offset echoes the F3
    EARFCN/PCI; header stays raw.
  v=0x0b (SDX55/SDX55M/SDX62 — RM520N with resolved F3, EM9190, SIM8202,
    RM500Q): LTE ML1/LL1 neighbour-cell-measurement attribution (EM9190
    lte_LL1_meas_ncell.c:414/420 NB_MEAS energies max_SNE/max_SE; the
    firmware's own neighbour quantities are ENERGIES, not PCI/dBm).
    cell_id is not a PCI at corpus scale, cross-chipset: 47/3,205 = 1.47%
    in 0-503 (RM520N 0%, EM9190 1.6%, SIM8202 1.2%, RM500Q 4.0%). The
    correlation search on RM520N finds 0 hypotheses. signal_quality is
    descending-sorted in 239/281 = 85% of multi-cell records.
  v=0x08 (SDX20 LM960 + MDM9250 MC7411 — 230,600 records): LTE-ML1
    idle/serving-measurement attribution. On an LM960 F3 capture (2,421
    v0x08 records; 1.40M F3 prints) the co-present LTE F3 is dominated by
    idle-measurement sites — ``lte_ml1_common_rssi_ind.c`` (serving
    RSSI/RSRP/RSRQ), ``lte_ml1_sm_idle_lte.c:983`` ("Scheduler scell earfcn:
    66786 pci: <pci>"), ``lte_ml1_mdb_idle.c:13498`` ("Current cell value: PCI
    ID <pci>"), ``lte_ml1_bplmn_intf.c``; zero NR. cell_id is not a PCI,
    cross-chipset: LM960 0/45 in 0–503 on the serving-PCI anchor (values
    cluster 17,836–18,412), LM960 2/31 on a second drive anchor,
    MC7411 (MDM9250) 0/1 (17,944); no v0x08 cell_id ever equals the
    F3/0xB193-anchored serving or neighbour PCI. Records are overwhelmingly
    header-only (n_cells=0), consistent with a per-TTI scheduling/PHY status
    record (possibly PDCCH/DCI grants) rather than a neighbour list. The
    correlation search (--min-distinct 6 on the lte_ml1 measurement
    subsystem) finds 0 hypotheses; a direct byte scan finds the F3 EARFCN
    66786 at NO offset and the PCI only at uniform-random offsets
    (+19/+34, card=256) by chance — header stays raw.
  v=0x05 (MDM9x30 Sierra MC7455, fixed 29B, 4,530 records / 15
    captures): no F3 available — all 15 MC7455 captures are LOG-only masks
    (0/15 carry any 0x79/0x99/0x98/0x92 F3 frame, 0/15 a 0x60 event), and
    QCSuper/SCAT do not decode 0x4177. Attribution rests on the in-capture
    LOG-code family: v0x05 co-occurs with a dense LTE-ML1 measurement set —
    0xB193 (serving/measured cells: 5 distinct PCIs, EARFCN
    8665/2050/5230), 0xB126, 0xB192 (neighbour meas), 0xB0C0 (LTE RRC
    OTA), 0xB180/0xB181 (RRC serving config) — placing v0x05 in the same
    LTE-ML1 idle/serving-measurement family as v0x07/v0x08/v0x0b. v0x05 has
    NO in-record cell list; the 29-byte header does not echo the
    co-captured 0xB193 PCI or EARFCN at any consistent offset (best hit
    ≤4/1,211 records = coincidental) — header stays raw. Structural note:
    the 29B v0x05 header shares the family framing skeleton with the 42B
    v0x08 header (``01 01 … fe/ff 00 02 00 02 00 02`` preamble, a
    ``2d 20 00 60 00`` trailer segment).

v=0x01 — WCDMA Step-1 peaks (24B header + 5B per peak, 16-peak log cap)
-----------------------------------------------------------------------

1,617 records / 4 captures (SIM power cycle, COPS dereg, manual PLMN scan,
uimcycle-attach), build ``T77W595.F0.0.0.6.5.VZ.017``; sizes 24 + 5n, n=0..16::

    [0:2]   01 00                    version + const (1,617/1,617)
    [2:4]   i16 LE  hdr_i16_at2      unnamed, -426..-19
    [4:11]  00 02 00 fe 00 02 00     const (1,617/1,617; 0x4179 v=0x01 [3:10])
    [11:13] u16 LE  freq_word_prev   0 (818) or == freq_word (799) — records pair
    [13:15] u16 LE  freq_word        carrier DL frequency, ~131.43 kHz/LSB
    [15:22] 00 00 2d 20 00 60 00     const (the family "2d 20 00 60 00" segment)
    [22:24] u16 LE  num_peaks        peaks FOUND; logged = min(num_peaks, 16)
    n x 5B: u16 peak_pos_cx8 (slot-relative, < 20480) | u16 peak_energy
            (descending) | u8 flag (0/1)

Grounding (legacy ``0x92`` INDEX-bound @1.0 + plaintext ``0x79``):

* ``srchsched.c:3412`` (WCDMA searcher scheduler, argc 3) fires at the
  record's DIAG tick with arg0 == ``num_peaks`` on **1,548/1,561** records
  (cops-dereg 592/592, PLMN scan 956/969). The 13 others are all F3 < record
  (29 vs 32, 1 vs 2, 2 vs 3) — never greater — consistent with a count
  printed after a pruning pass; not grounded. The MDM9207 EG25-G STRING DB
  names the corresponding print ``srchsched.c:3460 "STEP1_PROC: Number of
  Step1 peaks:%d, Primary cnt:%d,Sec cnt:%d"`` (same argc and arg shape;
  48-line cross-build offset > ALIGN_MAX_DISTANCE, so a CANDIDATE label).
* ``wsrch.c:13712`` fires only on capped records with ``[found, logged]`` =
  ``[num_peaks, 16]``: **44/44** (``[32, 16]``) — the 16-peak log cap.
* Cross-code (independent of the count): every 0x4179 v=0x01 PN-search task
  print ``wsrch.c:12067`` carries a 768-cx8 search window; its upper edge mod
  one slot (20480 cx8) lies within ±4 cx8 of a logged peak of the preceding
  0x4177 v=0x01 record on **846/924** prints (random-position null 2/924; 46
  of the 78 misses follow a capped record whose other peaks are unlogged).
  The searcher places its PN windows on these positions: they are Step-1
  slot-boundary hypotheses, not cell identities.
* ``freq_word``: 789/841 distinct (freq_word, last ``TUNE_TO_CHAN prim_freq``
  UARFCN) pairs fit DL frequency = freq_word × 131.43 kHz within 0.5 MHz
  (bands I/II/IV/V/VIII incl. additional channels; median residual 35 kHz,
  i.e. quantisation). The scale is a measured fit, so the word stays raw.

All 1,561 F3-co-captured records and all 1,617 v=0x01 records are energy-
sorted (u16 energy — 32 peaks exceed 255, so [+3] is not a pad) with every
position < 20480.

**This re-opens the LTE attribution of v=0x05/0x07/0x08/0x0b (not
re-verdicted).** A whole-corpus walk (218 captures, 489,042
records) finds the per-cell ``cell_id`` u16 below 20480 on EVERY element of
every version — v=0x0b 92,841/92,841, v=0x08 14,206/14,206, v=0x07
4,593/4,593 — with the per-version maximum exactly 20,476: the Step-1
slot-position range, not an identifier. v=0x0b also carries an in-header
count ([19] == n_cells on 20,339/20,339 element-bearing records). The
"cell_id is not a PCI" refutations above stand (uniform 0..20479 predicts the
measured ~1.5-2.9 % in-PCI-range rate), but the names ``cell_id`` /
``signal_quality`` are kept until a same-silicon Step-1 F3 witness exists
for those versions.

Stride invariance was verified at corpus scale: 0/194,395 records
violate `(size - base) % stride == 0` for their version. The parser
rejects records that fail this check.

Sizes that never appeared in the corpus (e.g. v=0x07 at 104B, v=0x0b at
125B) are **not** rejected by the parser — the stride math accepts them —
but they're not declared in `field_invariants`.

The name table's ``LOG_WCDMA_STEP_1_EDITION_2`` does not fit: the record is
an LTE PHY per-cell / scheduling code on every version.

Log name: LOG_WCDMA_STEP_1_EDITION_2
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


# Per-version (base_size, stride).
_4177_VERSION_PROFILE: dict[int, tuple[int, int]] = {
    0x01: (24, 5),  # MDM9625 Foxconn T77W595 — WCDMA Step-1 peaks, 5B per peak
    0x05: (29, 6),  # MDM9x30 MC7455 (always 0 cells) + MDM9x35 AirCard 791L — 6B per cell
    0x07: (34, 7),  # MDM9207+MDM9x07 Quectel EG25-G/EG95-NA — 7B per cell
    0x08: (42, 7),  # SDX20 LM960 + MDM9250 MC7411 — 7B per cell
    0x0b: (25, 5),  # SDX55 Telit FN980m + Sierra EM9190 — 5B per cell
}


@dataclass(frozen=True)
class _HdrLayout:
    """Header offsets of one non-v01 version (see "Header skeleton" above)."""
    s16: int                              # i16 hdr_s16
    var: int | None                       # 7 B hdr_var_raw (v05/v07/v08)
    word: int                             # u16 hdr_word
    count: int                            # u16 hdr_count
    extra: tuple[tuple[str, int], ...]    # version-only u16 words (attr, offset)
    consts: tuple[tuple[int, bytes], ...]  # (offset, expected bytes)


_SEG_60 = bytes.fromhex("2d20006000")
_SEG_47 = bytes.fromhex("2d20004700")
_RUN_6 = bytes.fromhex("000200020002")
_HDR: dict[int, _HdrLayout] = {
    0x05: _HdrLayout(3, 11, 18, 27, (),
                     ((1, b"\x01\x01"), (5, _RUN_6), (20, b"\x00\x00"), (22, _SEG_60))),
    0x07: _HdrLayout(4, 12, 19, 28, (),
                     ((1, b"\x01\x01\x01"), (6, _RUN_6), (21, b"\x00\x00"), (23, _SEG_47),
                      (30, bytes.fromhex("00006801")))),
    0x08: _HdrLayout(4, 12, 19, 28, (("hdr_u16_at34", 34),),
                     ((1, b"\x00\x01\x01"), (6, _RUN_6), (21, b"\x00\x00"), (23, _SEG_60),
                      (30, bytes.fromhex("00006801")), (36, b"\xff" * 6))),
    0x0b: _HdrLayout(3, None, 10, 19, (("hdr_u16_at8", 8), ("hdr_u16_at23", 23)),
                     ((1, b"\x01\x01"), (5, b"\x00\x02\x00"), (12, b"\x00\x00"),
                      (14, _SEG_47), (21, b"\x68\x01"))),
}


@dataclass
class Diag0x4177Cell:
    """One per-cell record from a 0x4177 in-record cell list.

    Fields (see the module docstring), the same on every version:
      [+0..+1] u16 LE — wide-cardinality identifier, varies per cell. NOT a
                        PCI (F3-checked on every cell-bearing version); < 20480
                        corpus-wide (the Step-1 slot range, see v=0x01).
      [+2..+3] u16 LE — signal-quality / energy word. Cells in a single
                        record are sorted DESCENDING by it. u16, not u8 (v9):
                        [+3] is non-zero on 29 v=0x07 and 174 v=0x0b corpus
                        elements, which the old u8 read truncated. Chipset-
                        specific encoding; no dBm conversion is grounded.
      [+4]     u8     — enum-2 flag (0x00 / 0x01). Also on v=0x08 (v9): 1 on
                        5,863 / 15,193 corpus elements, where <= v8 treated
                        [+3..+6] as zero padding.
      [+5]     (v=0x05) / [+5..+6] (v=0x07/0x08): zero pad (CONST 0x00).
    """
    cell_id: int  # u16 LE — identifier, NOT a PCI
    signal_quality: int  # u16 LE — energy-like, descending, chipset-specific encoding
    flag: int | None  # u8 enum-2 flag (every version since v9)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'cell_id': self.cell_id,
            'signal_quality': self.signal_quality,
        }
        if self.flag is not None:
            d['flag'] = self.flag
        return d


#: v=0x01: the firmware logs at most 16 Step-1 peaks (header count up to 32).
_V01_PEAK_CAP = 16
#: One WCDMA slot in chip x8 units (2560 chips x 8); Step-1 positions are
#: slot-relative, so every v=0x01 position is < this.
STEP1_SLOT_CX8 = 2560 * 8
_V01_HDR_CONST_A = bytes.fromhex("000200fe000200")                    # [4:11]
_V01_HDR_CONST_B = bytes.fromhex("00002d20006000")                    # [15:22]


@dataclass
class Diag0x4177Step1Peak:
    """One v=0x01 WCDMA Step-1 (P-SCH slot-sync) peak, 5 bytes.

      [+0..+1] u16 LE  peak_pos_cx8 — slot-relative position, chip x8
                       (0..20479). 846/924 PN-search windows (0x4179 v0x01,
                       wsrch.c:12067 arg7) start on one of these, mod 20480.
      [+2..+3] u16 LE  peak_energy — energy-sorted descending (1,561/1,561
                       records; u16, not u8: 32 peaks exceed 255).
      [+4]     u8      flag — 0/1, unnamed.
    """
    peak_pos_cx8: int
    peak_energy: int
    flag: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'peak_pos_cx8': self.peak_pos_cx8,
            'peak_energy': self.peak_energy,
            'flag': self.flag,
        }


@dataclass
class Diag0x4177:
    """LTE PHY 0x4177 — 4 chipset-keyed versions, stride-family encoding.

    Header fields are surfaced raw (``hdr_*``, v9). Cell-stride fields are
    emitted for v=0x05 (6B), v=0x07 (7B), v=0x08 (7B) and v=0x0b (5B).
    """
    log_time: int
    version: int
    variant: str
    payload_size: int
    n_cells: int
    cells: list[Diag0x4177Cell] = field(default_factory=list)
    # v=0x01 only (WCDMA Step-1 search, F3-grounded) — None/empty otherwise.
    num_peaks: int | None = None          # u16 @[22:24]: peaks FOUND (F3 count)
    peaks_capped: bool | None = None      # num_peaks > logged (16-peak cap)
    freq_word: int | None = None          # u16 @[13:15], ~131.43 kHz/LSB, raw
    freq_word_prev: int | None = None     # u16 @[11:13]: 0, or == freq_word
    hdr_i16_at2: int | None = None        # i16 @[2:4], unnamed (-426..-19)
    hdr_const_ok: bool | None = None      # v01 [0:2],[4:11],[15:22],[23]; others _HDR consts
    peaks: list[Diag0x4177Step1Peak] = field(default_factory=list)
    # v=0x05/0x07/0x08/0x0b header, raw (v9; F3 names none of it on these
    # versions — offsets per _HDR). None on v=0x01.
    hdr_s16: int | None = None            # i16 after the lead bytes (v01's hdr_i16_at2)
    hdr_word: int | None = None           # u16 before 00 00 + segment (v01's freq_word slot)
    hdr_count: int | None = None          # u16 elements FOUND (== n_cells, or > when capped)
    hdr_var_raw: bytes | None = None      # 7 B variable run (v05/v07/v08)
    hdr_u16_at8: int | None = None        # v0b only
    hdr_u16_at23: int | None = None       # v0b only
    hdr_u16_at34: int | None = None       # v08 only

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'type': 'Diag0x4177',
            'log_time': self.log_time,
            'version': self.version,
            'variant': self.variant,
            'payload_size': self.payload_size,
            'n_cells': self.n_cells,
        }
        if self.cells:
            d['cells'] = [c.to_dict() for c in self.cells]
        if self.version == 0x01:
            d['num_peaks'] = self.num_peaks
            d['peaks_capped'] = self.peaks_capped
            d['freq_word'] = self.freq_word
            d['freq_word_prev'] = self.freq_word_prev
            d['hdr_i16_at2'] = self.hdr_i16_at2
            d['hdr_const_ok'] = self.hdr_const_ok
            d['peaks'] = [p.to_dict() for p in self.peaks]
        elif self.version in _HDR:
            d['hdr_s16'] = self.hdr_s16
            d['hdr_word'] = self.hdr_word
            d['hdr_count'] = self.hdr_count
            d['hdr_const_ok'] = self.hdr_const_ok
            if self.hdr_var_raw is not None:
                d['hdr_var_raw'] = self.hdr_var_raw.hex()
            for name, _ in _HDR[self.version].extra:
                d[name] = getattr(self, name)
        return d


# Ground-truth recipe. v=0x08 (42B base + 7B/cell) is the MC7411 / LM960
# profile. The name table's LOG_WCDMA_STEP_1_EDITION_2 is almost certainly a
# mis-attribution — the record is an LTE PHY per-cell/scheduling code, and
# observation outranks that name. v=0x08 records may be PDCCH/DCI scheduling
# grants rather than idle-mode neighbour-cell measurements, so this recipe
# is ALSO the experiment that disambiguates the two readings.

@register(
    0x4177,
    name="0x4177",
    wigle_direct=True,
    wigle_roles=("identity",),
    description="0x4177 — v=0x01 (MDM9625 T77W595) is the WCDMA Step-1 searcher peak list (LOG_WCDMA_STEP_1_EDITION_2), F3-grounded: srchsched.c:3412 peak count == num_peaks 1,548/1,561, wsrch.c:13712 16-peak cap 44/44, 0x4179 PN windows sit on its slot positions 846/924. Historically LTE PHY (0x4177) — 4 chipset-keyed versions with per-version stride families; v=0x07/0x08/0x0b cell decode; cell_id is not a PCI on EG25-G (v0x07 MDM9207), LM960 (v0x08 SDX20), MC7411 (v0x08 MDM9250) or the SDX55/62 corpus (v0x0b); v0x07/v0x08/v0x0b LTE-ML1/LL1 attribution F3-grounded, v0x05 attributed by LTE-ML1 log-code co-presence (no F3 in its captures)",
    version=9,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Cross-chipset corpus: 194,395 records / 44 captures. 4 versions with "
        "chipset-keyed semantics: v=0x08 (SDX20 LM960 + MDM9250 MC7411, 94.3%, "
        "42B base + 7B stride), v=0x05 (MDM9x30 MC7455, 2.9%, 29B fixed), "
        "v=0x07 (MDM9207 EG25-G + MDM9x07, 1.4%, 34B base + 7B stride), v=0x0b "
        "(SDX55 FN980m + EM9190, 1.3%, 25B base + 5B stride). Stride invariance "
        "verified at corpus scale (0 violations). Per-cell layout (cell_id u16 "
        "+ descending-sorted signal_quality u8 + [+4] enum-2 flag on v0x07/v0x0b) "
        "validated on every cell-bearing version. cell_id is NOT a PCI on any "
        "version: v0x07 26/895 in 0-503 vs F3 lte_ml1_bplmn_int.c (EARFCN,PCI) "
        "prints; v0x0b 47/3,205 cross-chipset; v0x08 LM960 0/45 (serving-PCI "
        "anchor) + 2/31 (second anchor) + MC7411 0/1. F3 attribution: v0x07 LTE "
        "ML1/PHY (26,368 co-present lte_ml1 0x79 prints); v0x0b LTE ML1/LL1 "
        "neighbour measurement (lte_LL1_meas_ncell.c NB_MEAS energies); v0x08 "
        "LTE-ML1 idle/serving measurement (lte_ml1_common_rssi_ind.c / "
        "lte_ml1_sm_idle_lte.c:983 'scell earfcn 66786 pci <pci>' / "
        "lte_ml1_mdb_idle.c:13498, zero NR). v0x05 (MC7455, 4,530 records) has "
        "no F3 in any capture; attributed to the same LTE-ML1 family by "
        "co-present 0xB193 / 0xB126 / 0xB192 / 0xB0C0. No header offset echoes "
        "the F3- or 0xB193-printed EARFCN/PCI on any version, so headers stay "
        "raw; the signal_quality dBm scale is ungrounded. v=0x01 (MDM9625 "
        "Foxconn T77W595, 1,617 records / 4 captures): 24B header + 5B/peak "
        "(u16 peak_pos_cx8 < 20480, u16 energy descending, u8 flag), "
        "num_peaks u16@22 == legacy srchsched.c:3412 arg0 on 1,548/1,561, "
        "16-peak cap == wsrch.c:13712 [found, logged] 44/44; 0x4179 v0x01 "
        "wsrch.c:12067 window edges mod 20480 hit a logged peak 846/924 "
        "(null 2/924) — WCDMA Step-1 slot-sync peaks, as the name says."
    ),
    source_url="",
    fields_identified=20,
    fields_parsed=20,
    issues=(),
    primary_issue=None,
    field_invariants={
        "version": {"enum": [0x01, 0x05, 0x07, 0x08, 0x0b]},
    },
)
def parse_0x4177(log_time: int, data: bytes) -> Diag0x4177 | None:
    if len(data) < 1:
        return None
    version = data[0]
    profile = _4177_VERSION_PROFILE.get(version)
    if profile is None:
        return None
    base, stride = profile
    size = len(data)
    if size < base:
        return None
    delta = size - base
    if delta % stride != 0:
        return None
    n_cells = delta // stride
    if version == 0x01:
        peaks = [
            Diag0x4177Step1Peak(
                peak_pos_cx8=unpack_from('<H', data, base + i * stride)[0],
                peak_energy=unpack_from('<H', data, base + i * stride + 2)[0],
                flag=data[base + i * stride + 4],
            )
            for i in range(n_cells)
        ]
        num_peaks = unpack_from('<H', data, 22)[0]
        return Diag0x4177(
            log_time=log_time,
            version=version,
            variant=f"wcdma_step1_4177_v01_{size}B",
            payload_size=size,
            n_cells=n_cells,
            num_peaks=num_peaks,
            peaks_capped=num_peaks > n_cells,
            freq_word=unpack_from('<H', data, 13)[0],
            freq_word_prev=unpack_from('<H', data, 11)[0],
            hdr_i16_at2=unpack_from('<h', data, 2)[0],
            hdr_const_ok=(data[1] == 0 and data[4:11] == _V01_HDR_CONST_A
                          and data[15:22] == _V01_HDR_CONST_B and data[23] == 0),
            peaks=peaks,
        )
    # v=0x05/0x07/0x08/0x0b: every element is u16 cell_id | u16 signal_quality
    # | u8 flag | zero pad (v05 1 B, v07/v08 2 B, v0b none) — corpus-verified
    # (whole-corpus walk, 518,097 records). v05 has elements only on MDM9x35.
    cells = [
        Diag0x4177Cell(
            cell_id=unpack_from('<H', data, off)[0],
            signal_quality=unpack_from('<H', data, off + 2)[0],
            flag=data[off + 4],
        )
        for off in range(base, size, stride)
    ]
    hdr = _HDR[version]
    return Diag0x4177(
        log_time=log_time,
        version=version,
        variant=f"lte_phy_4177_v{version:02x}_{size}B",
        payload_size=size,
        n_cells=n_cells,
        cells=cells,
        hdr_s16=unpack_from('<h', data, hdr.s16)[0],
        hdr_word=unpack_from('<H', data, hdr.word)[0],
        hdr_count=unpack_from('<H', data, hdr.count)[0],
        hdr_var_raw=None if hdr.var is None else bytes(data[hdr.var:hdr.var + 7]),
        hdr_const_ok=all(data[o:o + len(c)] == c for o, c in hdr.consts),
        **{name: unpack_from('<H', data, off)[0] for name, off in hdr.extra},
    )
