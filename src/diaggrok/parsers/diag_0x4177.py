"""0x4177 — LTE PHY, 4 chipset-keyed versions, stride-family encoding.

Corpus: 194,395 records / 44 captures. Unlike codes where each version maps
1:1 to a payload size, 0x4177 is a **stride-family** code: each version has
a fixed base header size and a fixed per-cell stride, with the payload size
varying by the number of inline cell entries:

  ver  | base | stride | sizes observed (records)             | chipset
  -----+------+--------+--------------------------------------+----------------
  0x05 |  29B |   0    | 29 (5,724 — 100%)                    | MDM9x30
                                                                 Sierra MC7455
                                                                 fixed 29B, no
                                                                 in-record list
  0x07 |  34B |   7B   | 34, 41, 48, 55, 62, 69, 76, 83, 90,  | MDM9207 +
        |      |        | 97, 146 (top: 34B@89%)               | MDM9x07 —
        |      |        |                                      | Quectel EG25-G,
        |      |        |                                      | EG95-NA
  0x08 |  42B |   7B   | 42..154 in 7B steps (top: 42B@99.0%) | SDX20 LM960 +
        |      |        |                                      | MDM9x40 MC7411
  0x0b |  25B |   5B   | 25..185 in 5B steps (top: 25B@82%)   | SDX55 — Telit
        |      |        |                                      | FN980m, Sierra
        |      |        |                                      | EM9190

Per-cell stride structure (v=0x08 7B, v=0x0b 5B, v=0x07 7B):

    [+0..+1]  u16 LE — wide-cardinality identifier (``cell_id``). NOT a PCI
                       on any version (see below); semantics unnamed.
    [+2]      u8     — narrow-range signal-quality byte (0x48..0x5e on
                       SDX55, 0x61..0x65 on SDX20 single-cell). Cells in a
                       record are SORTED DESCENDING by this byte (e.g. a
                       32-cell SDX55 record: 0x5e → 0x4d monotonic; v=0x07
                       60/61 multi-cell records). A measurement with a
                       chipset-specific encoding; the dBm scale is
                       ungrounded.
  v=0x08-only:
    [+3..+6]  4 bytes of zero padding (CONST 0x00 across all observed cells)
  v=0x0b and v=0x07:
    [+3]      u8 zero pad (CONST 0x00)
    [+4]      enum-2 single-bit flag (0x00 / 0x01, ~50/50; 56.9 / 43.1 on
              v=0x07)
  v=0x07-only:
    [+5..+6]  u8 zero pad (CONST 0x00)

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
    (EARFCN,PCI) — (975,221)(2050,221)(2175,187)(2300,242)(5035,144)
    (900,182)… all PCIs in-range. A field/F3 correlation search (widths
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
  v=0x08 (SDX20 LM960 + MDM9x40 MC7411 — 230,600 records): LTE-ML1
    idle/serving-measurement attribution. On an LM960 F3 capture (2,421
    v0x08 records; 1.40M F3 prints) the co-present LTE F3 is dominated by
    idle-measurement sites — ``lte_ml1_common_rssi_ind.c`` (serving
    RSSI/RSRP/RSRQ), ``lte_ml1_sm_idle_lte.c:983`` ("Scheduler scell earfcn:
    66786 pci: 242"), ``lte_ml1_mdb_idle.c:13498`` ("Current cell value: PCI
    ID 242"), ``lte_ml1_bplmn_intf.c``; zero NR. cell_id is not a PCI,
    cross-chipset: LM960 0/45 in 0–503 on the PCI-242 anchor (values
    cluster 17,836–18,412), LM960 2/31 on a second (PCI-158) drive anchor,
    MC7411 (SDX50M) 0/1 (17,944); no v0x08 cell_id ever equals the
    F3/0xB193-anchored serving or neighbour PCI. Records are overwhelmingly
    header-only (n_cells=0), consistent with a per-TTI scheduling/PHY status
    record (possibly PDCCH/DCI grants) rather than a neighbour list. The
    correlation search (--min-distinct 6 on the lte_ml1 measurement
    subsystem) finds 0 hypotheses; a direct byte scan finds the F3 EARFCN
    66786 at NO offset and PCI 242 only at uniform-random offsets
    (+19/+34, card=256) by chance — header stays raw.
  v=0x05 (MDM9x30 Sierra MC7455, fixed 29B, 4,530 records / 15
    captures): no F3 available — all 15 MC7455 captures are LOG-only masks
    (0/15 carry any 0x79/0x99/0x98/0x92 F3 frame, 0/15 a 0x60 event), and
    QCSuper/SCAT do not decode 0x4177. Attribution rests on the in-capture
    LOG-code family: v0x05 co-occurs with a dense LTE-ML1 measurement set —
    0xB193 (serving/measured cells: PCI 109/196/250/310/410, EARFCN
    8665/2050/5230), 0xB126, 0xB192 (neighbour meas), 0xB0C0 (LTE RRC
    OTA), 0xB180/0xB181 (RRC serving config) — placing v0x05 in the same
    LTE-ML1 idle/serving-measurement family as v0x07/v0x08/v0x0b. v0x05 has
    NO in-record cell list; the 29-byte header does not echo the
    co-captured 0xB193 PCI or EARFCN at any consistent offset (best hit
    ≤4/1,211 records = coincidental) — header stays raw. Structural note:
    the 29B v0x05 header shares the family framing skeleton with the 42B
    v0x08 header (``01 01 … fe/ff 00 02 00 02 00 02`` preamble, a
    ``2d 20 00 60 00`` trailer segment).

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


# Per-version (base_size, stride). stride==0 means "fixed base, no cells".
_4177_VERSION_PROFILE: dict[int, tuple[int, int]] = {
    0x05: (29, 0),  # MDM9x30 Sierra MC7455 — fixed 29B
    0x07: (34, 7),  # MDM9207+MDM9x07 Quectel EG25-G/EG95-NA — 7B per cell
    0x08: (42, 7),  # SDX20 LM960 + MDM9x40 MC7411 — 7B per cell
    0x0b: (25, 5),  # SDX55 Telit FN980m + Sierra EM9190 — 5B per cell
}


@dataclass
class Diag0x4177Cell:
    """One per-cell record from a 0x4177 in-record cell list.

    Fields (see the module docstring):
      [+0..+1] u16 LE — wide-cardinality identifier, varies per cell. NOT a
                        PCI (F3-checked on every cell-bearing version).
      [+2]     u8     — narrow-range signal-quality byte. Cells in a
                        single record are sorted DESCENDING by this byte
                        (verified on 32-cell SDX55 records: 0x5e → 0x4d
                        monotonic). Chipset-specific encoding; DO NOT trust
                        a dBm conversion until reference-validated.
      [+3] (v=0x07/0x0b) u8 zero pad (CONST 0x00 in corpus)
      [+4] (v=0x07/0x0b) u8 enum-2 flag (0x00 / 0x01, ~50/50 distribution)
      [+3..+6] (v=0x08 only) 4 bytes of zero padding (CONST 0x00)
    """
    cell_id: int  # u16 LE — identifier, NOT a PCI
    signal_quality: int  # u8 — measurement, chipset-specific encoding
    flag: int | None  # v=0x07/0x0b: enum-2 single-bit flag

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'cell_id': self.cell_id,
            'signal_quality': self.signal_quality,
        }
        if self.flag is not None:
            d['flag'] = self.flag
        return d


@dataclass
class Diag0x4177:
    """LTE PHY 0x4177 — 4 chipset-keyed versions, stride-family encoding.

    Header fields within `base` are not decoded. Cell-stride fields
    are emitted for v=0x07 (7B stride), v=0x08 (7B stride)
    and v=0x0b (5B stride) — the three versions whose per-cell layout is
    corpus-validated. v=0x05 is fixed-29B with no cell list.
    """
    log_time: int
    version: int
    variant: str
    payload_size: int
    n_cells: int
    cells: list[Diag0x4177Cell] = field(default_factory=list)

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
    description="LTE PHY (0x4177) — 4 chipset-keyed versions with per-version stride families; v=0x07/0x08/0x0b cell decode; cell_id is not a PCI on EG25-G (v0x07 MDM9207), LM960 (v0x08 SDX20), MC7411 (v0x08 SDX50M) or the SDX55/62 corpus (v0x0b); v0x07/v0x08/v0x0b LTE-ML1/LL1 attribution F3-grounded, v0x05 attributed by LTE-ML1 log-code co-presence (no F3 in its captures)",
    version=7,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Cross-chipset corpus: 194,395 records / 44 captures. 4 versions with "
        "chipset-keyed semantics: v=0x08 (SDX20 LM960 + MDM9x40 MC7411, 94.3%, "
        "42B base + 7B stride), v=0x05 (MDM9x30 MC7455, 2.9%, 29B fixed), "
        "v=0x07 (MDM9207 EG25-G + MDM9x07, 1.4%, 34B base + 7B stride), v=0x0b "
        "(SDX55 FN980m + EM9190, 1.3%, 25B base + 5B stride). Stride invariance "
        "verified at corpus scale (0 violations). Per-cell layout (cell_id u16 "
        "+ descending-sorted signal_quality u8 + [+4] enum-2 flag on v0x07/v0x0b) "
        "validated on every cell-bearing version. cell_id is NOT a PCI on any "
        "version: v0x07 26/895 in 0-503 vs F3 lte_ml1_bplmn_int.c (EARFCN,PCI) "
        "prints; v0x0b 47/3,205 cross-chipset; v0x08 LM960 0/45 (PCI-242 "
        "anchor) + 2/31 (PCI-158) + MC7411 0/1. F3 attribution: v0x07 LTE "
        "ML1/PHY (26,368 co-present lte_ml1 0x79 prints); v0x0b LTE ML1/LL1 "
        "neighbour measurement (lte_LL1_meas_ncell.c NB_MEAS energies); v0x08 "
        "LTE-ML1 idle/serving measurement (lte_ml1_common_rssi_ind.c / "
        "lte_ml1_sm_idle_lte.c:983 'scell earfcn 66786 pci 242' / "
        "lte_ml1_mdb_idle.c:13498, zero NR). v0x05 (MC7455, 4,530 records) has "
        "no F3 in any capture; attributed to the same LTE-ML1 family by "
        "co-present 0xB193 / 0xB126 / 0xB192 / 0xB0C0. No header offset echoes "
        "the F3- or 0xB193-printed EARFCN/PCI on any version, so headers stay "
        "raw; the signal_quality dBm scale is ungrounded."
    ),
    source_url="",
    fields_identified=7,
    fields_parsed=7,
    issues=(),
    primary_issue=None,
    field_invariants={
        "version": {"enum": [0x05, 0x07, 0x08, 0x0b]},
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
    if stride == 0:
        if size != base:
            return None
        n_cells = 0
        cells: list[Diag0x4177Cell] = []
    else:
        delta = size - base
        if delta % stride != 0:
            return None
        n_cells = delta // stride
        cells = []
        # Per-cell stride decode for the three versions whose per-cell
        # layout is corpus-validated: v=0x08, v=0x0b, and v=0x07 (1,800
        # records / 212 with cells / 518 cells across EG25-G + EG95-NA,
        # signal_quality descending-sorted 60/61 multi-cell records, [+4]
        # enum-2 flag).
        # v=0x05 is fixed-29B with no in-record cell list.
        if n_cells > 0 and version in (0x07, 0x08, 0x0b):
            for i in range(n_cells):
                off = base + i * stride
                cell_id = unpack_from('<H', data, off)[0]
                signal_quality = data[off + 2]
                # v=0x07 (7B stride) and v=0x0b (5B stride) both carry an
                # enum-2 flag at [+4]; v=0x08 has 4 zero-pad bytes there.
                flag = data[off + 4] if version in (0x07, 0x0b) else None
                cells.append(Diag0x4177Cell(
                    cell_id=cell_id,
                    signal_quality=signal_quality,
                    flag=flag,
                ))
    return Diag0x4177(
        log_time=log_time,
        version=version,
        variant=f"lte_phy_4177_v{version:02x}_{size}B",
        payload_size=size,
        n_cells=n_cells,
        cells=cells,
    )
