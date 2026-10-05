"""0xB196 — LTE ML1 cell-measurement results (legacy `LteMl1B196`); cross-version v3.

The log name is **LOG_LTE_ML1_CELL_MEASUREMENT_RESULTS** — i.e. the body is a
per-cell LTE ML1 measurement array, one entry per measured cell on the
record's frequency layer.

## Structure (cross-version)

    4B header
      byte0  version       0x02 (mc7700) | 0x03 (eg25g) | 0x20 (mc7411) |
                           0x29 (rm520ngl, fn980m)
      byte1  num_cells     count of populated cell entries (see below)
      byte2  reserved      0x00
      byte3  reserved      0x00
    cell array: num_slots = (len - 4) / cell_size entries of cell_size bytes,
      the first `num_cells` populated, any remaining slots zero-padded.
      cell[0:4] = EARFCN of that cell (cell0's EARFCN == the record-level
      earfcn@4 used for DIAG×AT EARFCN attribution).

`cell_size` is **version-dependent**:

    version  cell_size  attested on
    0x02     36 B       mc7700 (Sierra SWI9200X MDM9200) — u16 earfcn + u16 pci
    0x03     40 B       eg25g (Quectel MDM9207), LM960, EG18
    0x29     40 B       rm520ngl (SDX62), fn980m (Telit SDX55)
    0x20     44 B       mc7411 (Sierra SWI9X50C SDX55)

`byte1 == (count of cell slots with nonzero EARFCN)` holds 100% across
fn980m (1408/1408), eg25g (909/909) and mc7411 (486/486) — so num_cells is
a hard semantic, not a heuristic. Note num_slots ≥ num_cells: e.g. an 84B
fn980m record carries num_cells=1 but 2×40B slots (1 real + 1 zero-pad).

## v0x02 — older MDM9200 / Sierra MC7700 packing (u16 identity, 36-byte cell)

**v0x02 is silicon-locked to the Sierra MC7700 on SWI9200X (MDM9200-era)
firmware** — 655 records across 8 captures (3 firmware builds, 2 units).
Like its EARFCN-attribution siblings **0xB180 v0x04** and **0xB17F v0x03**,
it carries a **u16 EARFCN** where the modern versions use a u32. A u32 read
pulls the next field into the high bytes and yields a constant 8-digit garbage
channel (31000703 == u16 2175 | 473<<16) on every MC7700 record.

The record sizes are exactly 4 + N×36 (40/76/112 B = 1/2/3 cells, 574/80/1
records), and each 36-byte cell is `u16 earfcn, u16 pci` followed by the same
measurement block as the 40-byte layout — every offset 4 bytes lower, because
the identity is two u16s instead of two u32s. That is exactly how 0xB17F v0x03
relates to 0xB17F v0x05. The second u16 (473 in the 31000703 value above) is
the PCI. Grounded bit-exact against the co-emitted 0xB17F v0x03 record of the
same (earfcn, pci): rsrp / rsrq / rssi 468/468 (100%) over the MC7700 corpus.

**F3-VERDICT v0x02: GROUND** — the u16@4 EARFCN == the **0xB0C0** (LTE RRC
Serving Cell Info, itself v0x02-grounded on MC7700) serving EARFCN in
**8/8 shared MC7700 captures** (2175 across all 655 records). The MDM9200 part
predates the QSH/QSR4 F3 plane, so there is no in-capture F3 for v0x02; the
0xB0C0 in-capture cross-check stands in its place, as it does for 0xB180 v0x04.

**Unaligned records return None** (registry WARN) rather than guessing a
stride — a wrong cell_size would mis-slice every field. Every attested record
of every version is 4 + k × its cell stride (v0x02 40/76/112, v0x03 44..244,
v0x20 48..224, v0x29 44..364 B), so an off-stride length is a truncated record.
The per-cell inner tuple (9×u32 for 36B, 10×u32 for 40B, 11×u32 for 44B) is
still surfaced raw as `u32` next to the named fields. **PCI is named on all
structured layouts**: u32[1] & 0x1FF on the 40-byte (v0x03/v0x29) and 44-byte
(v0x20) strides, u16@2 & 0x1FF on the 36-byte v0x02 stride.
- v0x03/v0x29: AT-verified on RM520N-GL (250/310 == QENG neighbourcell PCIs @
  EARFCN 66536).
- v0x20: **F3-VERDICT v0x20: GROUND**. On the Sierra mc7411/em7511 (SWI9X50C
  SDX55) 44-byte cell, u32[1] is the full PCI (upper bits 0 across 787/787
  corpus cells). Cross-confirmed three ways on an MC7411 F3+AT+QMI capture
  (EARFCN 66786 T-Mobile B66, 379 v0x20 records): serving cells[0]=(66786,236)
  == the 0xB0C0 serving cell (236, 100/100); neighbour cells[1]=(66786,471) ==
  0xB192 neighbour meas; 3rd cell (66786,322) == 0xB192; and the ML1 F3 plane
  labels every pair — `lte_ml1_dlm_rx_cfg.c:20561` "Doppler: Update cell=236,
  freq=66786", `lte_ml1_mdb.c:6246` "earfcn 66786 pci 471", `lte_ml1_md.c:1346`
  "EUTRA Ngbr Srch new cell (66786,322) ... num_cells 3" (the last also grounds
  the num_cells==3 semantic on the 136-byte record). The F3 format strings were
  resolved from one of 3 indistinguishable candidate message databases, but the
  (EARFCN,PCI) *values* are wire-sourced u32 args, independent of the
  format-string source, and they agree bit-for-bit with the two LOG-packet
  cross-checks.

## Per-cell measurement block — all versions

Offsets below are for the 40/44-byte layouts; on v0x02 subtract 4. Every
field is an x16 fixed-point value (the 0xB17F / 0xB193 idiom):

    cell+12  bits 0..11   rsrp_rx0_dbm = raw/16 - 180   (LL RSRP, Rx chain 0)
    cell+16  bits 0..11   rsrp_rx1_dbm = raw/16 - 180   (LL RSRP, Rx chain 1)
    cell+20  bits 0..11   rsrp_dbm     = raw/16 - 180   (instantaneous RSRP)
    cell+28  bits 20..29  rsrq_db      = raw/16 -  30   (instantaneous RSRQ)
    cell+36  bits 0..11   rssi_dbm     = raw/16 - 110

The 12-bit RSRP words carry the value twice (bits 12..23 repeat bits 0..11);
the RSRQ words are three 10-bit fields. A field is None when it holds a
"not measured" fill (a detected-but-unmeasured neighbour carries rsrp 0x1E0,
rx0/rx1 0x960, rsrq 0x1E0, rssi 0x640; v0x02 blanks a single antenna with 0)
or an RSRP outside the TS 36.133 extended range — <1% of corpus cells.
Three independent cross-checks:

1. **0xB17F, bit-exact, every version.** The co-emitted 0xB17F record of the
   same (earfcn, pci) holds the same values: cell+20 == 0xB17F u32@12 as a
   whole 32-bit word, rsrq == 0xB17F u32@20 bits 0..9, rssi == 0xB17F rssi.
   Measured at ~100% on 30+ captures: v0x02 MC7700, v0x03 LM960/EG25-G/EG18,
   v0x20 MC7411/EM7511/EM120R/EM160R, v0x29 FN980/RM500Q/RM520N/SIM8202G/
   EM9190/EM9291. The 0xB17F `rsrq` decode reads bits 20..29, which differ
   from bits 0..9 on two-filter chipsets (FN980, SIM8202G), so compare
   against the low field.
2. **F3, bit-exact (v0x03).** An EG18-NA cold-GNSS-start capture (406 records):
   `lte_ml1_md.c:6171 "Serving Cell Meas: (66786, 236) LL RSRP (used=rx1
   rx0 %d.%04d rx1 %d.%04d)"` == rsrp_rx0 / rsrp_rx1 within 1/16 dB on
   406/406; `lte_ml1_mdb_idle.c:7033 rsrp_inst` == rsrp_dbm and
   `:7054 rsrq_inst` == rsrq_db, 406/406. F3 `%d.%04d` drops the sign of
   the fraction: the value is int - frac/1e4 for negative ints (the raw
   `filt_coeff*rsrp_inst` Q7 product in `:6627` confirms it).
3. **F3 per antenna (v0x20) + AT per antenna (v0x29).** On the MC7411 capture,
   `lte_ml1_common_rssi_ind.c:1510` per-Rx prints put Rx1 26 dB below Rx0;
   rsrp_rx1 matches the Rx1 print (MAE 0.31 dB) and is 25.9 dB from the
   serving value. An RM520N-GL drive (979 records): rsrp_rx1 ≈ AT +QRSRP rx1
   (bias +0.36), rsrp_rx0 ≈ rx0, rsrp_dbm ≈ +QENG serving AND neighbour RSRP
   (540 neighbour joins).

Not named (left raw in `u32`): cell+8; cell+12/+16 bits 12..23; cell+24 and
the other cell+28 subfields (a second RSRQ — F3 Rx1 RSRQ on MC7411, but
inconsistent against AT +QRSRQ on two RM520N drives, so CANDIDATE only);
cell+32 (two 11-bit RSSI-scale fields); and the v0x20 trailing cell+40 word,
mostly the 18-bit all-ones 0x3FFFF sentinel. The post-filter
`rsrp avg`/`rsrq avg` of the idle S-criterion are not carried here.

### earfcn contract
`to_dict()` emits `earfcn` (= cell0's EARFCN = u32@4) for every returned
record, so record-level EARFCN-attribution consumers keep working.

Log name: LTE ML1 Measuring Cell Result
Also known as: LOG_LTE_ML1_CELL_MEASUREMENT_RESULTS
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

_HEADER_SIZE = 4
# Version -> per-cell tuple size (bytes). Only ground-truthed versions listed;
# an unaligned record returns None.
_CELL_SIZE_BY_VERSION = {
    0x02: 36,
    0x03: 40,
    0x20: 44,
    0x29: 40,
}

# v0x02 is the older MDM9200 / Sierra MC7700 (SWI9200X) packing, which — like
# its EARFCN-attribution siblings 0xB180 v0x04 and 0xB17F v0x03 — carries a
# **u16 EARFCN** where the modern-silicon versions use a u32. Reading the u32
# pulls the following field into the high bytes and yields a constant 8-digit
# garbage channel number (31000703 == 0x01D9087F, i.e. u16 0x087F=2175 with the
# PCI 0x01D9=473 in the top half) on every MC7700 record. GROUND: the u16 EARFCN
# == the 0xB0C0 (LTE RRC Serving Cell Info, itself v0x02-grounded on MC7700)
# serving EARFCN in 100% of the 8 shared MC7700 captures (2175 across 655
# records, 3 firmwares / 2 units). There is no F3 plane on MDM9200 (it predates
# QSH/QSR4). The 36-byte cell (u16 earfcn, u16 pci, then the 40-byte layout's
# measurement block 4 bytes lower) matches 0xB17F v0x03 bit-exact.
_MDM9200_V2_VERSION = 0x02

# Per-cell measurement block, as offsets into the 40/44-byte cell. The 36-byte
# v0x02 cell carries the same block 4 bytes lower (_MDM9200_V2_MEAS_SHIFT).
# All x16 fixed-point; see the module docstring for the three oracles.
_RSRP_RX0_OFF = 12   # bits 0..11, raw/16 - 180 dBm (F3 "LL RSRP rx0")
_RSRP_RX1_OFF = 16   # bits 0..11, raw/16 - 180 dBm (F3 "LL RSRP rx1")
_RSRP_OFF = 20       # bits 0..11, raw/16 - 180 dBm (F3 rsrp_inst; == 0xB17F u32@12)
_RSRQ_OFF = 28       # bits 20..29, raw/16 - 30 dB  (F3 rsrq_inst)
_RSSI_OFF = 36       # bits 0..11, raw/16 - 110 dBm (== 0xB17F rssi)
_MDM9200_V2_MEAS_SHIFT = -4

# "Not measured" fills (corpus census, <1% of cells). A cell the
# firmware has detected but not yet measured carries a fixed pattern — rsrp
# 0x1E0 (-150), rsrp_rx0/rx1 0x960 (-30), rsrq 0x1E0 (0 dB), rssi 0x640
# (-10) — or all-0x960; v0x02 also blanks single antennas with raw 0/11. Such
# values are emitted as None rather than as impossible dBm. RSRP outside the
# TS 36.133 extended reporting range (-156..-31 dBm) is treated the same way.
_RSRP_RAW_MIN = (-156 + 180) * 16   # 384
_RSRP_RAW_MAX = (-31 + 180) * 16    # 2384
_RSRP_FILL = 0x1E0
_RSRQ_FILL = 0x1E0
_RSSI_FILL = 0x640


def _rsrp(raw: int) -> float | None:
    if raw == _RSRP_FILL or not _RSRP_RAW_MIN <= raw <= _RSRP_RAW_MAX:
        return None
    return raw / 16 - 180


def _measurements(cell: bytes, shift: int) -> dict[str, float | None]:
    """Decode the named per-cell measurement fields."""
    def word(off: int) -> int:
        return unpack_from('<I', cell, off + shift)[0]

    rsrq_raw = (word(_RSRQ_OFF) >> 20) & 0x3FF
    rssi_raw = word(_RSSI_OFF) & 0xFFF
    return {
        "rsrp_rx0_dbm": _rsrp(word(_RSRP_RX0_OFF) & 0xFFF),
        "rsrp_rx1_dbm": _rsrp(word(_RSRP_RX1_OFF) & 0xFFF),
        "rsrp_dbm": _rsrp(word(_RSRP_OFF) & 0xFFF),
        "rsrq_db": None if rsrq_raw == _RSRQ_FILL else rsrq_raw / 16 - 30,
        "rssi_dbm": None if rssi_raw == _RSSI_FILL else rssi_raw / 16 - 110,
    }


@dataclass
class Diag0xB196:
    """0xB196 — LTE ML1 cell-measurement results (legacy `LteMl1B196`).

    `earfcn` is cell0's EARFCN (u32@4; u16@4 on v0x02), preserved as the
    record-level attribution field. When `structured` is True, `cells`
    holds one dict per populated cell: ``{"earfcn", "pci", "rsrp_rx0_dbm",
    "rsrp_rx1_dbm", "rsrp_dbm", "rsrq_db", "rssi_dbm", "u32"}``. ``pci`` is
    the per-cell physical cell id (AT-verified on RM520N-GL v0x29,
    F3+0xB0C0+0xB192-grounded on mc7411 v0x20). The measurement fields are
    grounded on every version (see the module docstring);
    ``u32`` keeps the whole raw cell tuple for the still-unnamed words.
    """
    log_time: int
    version: int
    earfcn: int
    num_cells: int | None
    num_slots: int | None
    cell_size: int | None
    structured: bool
    cells: list[dict[str, Any]]
    payload_size: int
    body_raw: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB196",
            "log_time": self.log_time,
            "version": self.version,
            "earfcn": self.earfcn,
            "num_cells": self.num_cells,
            "num_slots": self.num_slots,
            "cell_size": self.cell_size,
            "structured": self.structured,
            "cells": self.cells,
            "payload_size": self.payload_size,
            "body_raw": self.body_raw,
        }


# ── Ground-truth recipe ───────────────────────────────────────────────────
# Recipe for the Telit LM960 (SDX20), which emits 0xB196 at **v0x03**
# (byte0==0x03 across 59 LM960 captures, sizes 84B == 2×40+4 and 44B == 1×40+4,
# both on the v0x03 40-byte cell stride first established on the EG25-G).
#
# Grounding uses Telit AT (there is no QENG on Telit): AT#RFSTS gives the LTE
# serving EARFCN/RSRP/RSRQ; AT#MONI / AT#MONI=0 give the serving + neighbour
# cell rows (EARFCN, PCI); AT#SERVINFO the serving-cell summary.
#
# Hardware-validated on an LM960 (SDX20). Without a SIM the L1 camps
# limited-service on T-Mobile B66 (EARFCN 66786) and still emits 0xB196 (223
# records in a 150 s paired DIAG + 1 Hz AT capture). Findings:
#   - earfcn (record/cell0) = 66786 == AT#RFSTS/#MONI/#SERVINFO serving EARFCN
#     (100% identity, 223/223) -> VERIFIED.
#   - cells.earfcn = 66786 on both populated slots == serving EARFCN -> VERIFIED
#     (per-cell EARFCN decode exact; single-EARFCN capture so it confirms the
#     decode but not multi-EARFCN neighbour discrimination).
#   - num_cells = CONST 2, but AT#MONI reported only the single serving cell in
#     limited service (no neighbours without a SIM) -> PARTIAL (2-vs-1
#     discrepancy; a multi-cell SIM-camped drive is needed).
#   - the measurement words could not be checked in a stationary single-cell
#     window (no signal variation) -> PARTIAL on this modem; they are grounded
#     on other modems (module docstring).

# The versions this parser implements = the corpus-attested byte-0 set
# (attested byte0 at sizes>4: {'0x02': 694, '0x03': 52416, '0x20': 12716,
# '0x29': 145740}). Any other version returns None so the registry dispatch
# WARN fires instead of a silent record.
_VERSIONS_B196_4918: tuple[int, ...] = (0x02, 0x03, 0x20, 0x29)


@register(
    0xB196,
    name="0xB196",
    wigle_direct=False,
    wigle_roles=("pci-earfcn-bridge",),
    description=(
        "0xB196 -- LTE ML1 cell-measurement results (LOG_LTE_ML1_CELL_MEASUREMENT_RESULTS); "
        "4B header (byte1=num_cells) + version-sized per-cell array (36/40/44 B); "
        "earfcn=cell0 EARFCN; per-cell earfcn, pci and rsrp_rx0/rsrp_rx1/rsrp/rsrq/rssi "
        "on all versions (v0x02 MDM9200 u16 identity; v0x03/v0x29 40 B; v0x20 44 B)"
    ),
    version=16,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "4B header (byte0=version, byte1=num_cells, bytes2-3=0) + num_slots="
        "(len-4)/cell_size cell entries, first num_cells populated, rest zero-padded. "
        "cell_size by version: {0x02:36 (MDM9200, u16 earfcn + u16 pci), 0x03:40, "
        "0x29:40 (SDX5x/SDX62), 0x20:44 (Sierra SWI9X50C SDX55)}. byte1==populated-"
        "cell-count holds 100% across fn980m/eg25g/mc7411. cell0 EARFCN == record "
        "earfcn@4; a Layer-2 earfcn range invariant (0, 262143) (18-bit field width) "
        "guards against a garbage channel. A record that is shorter than 4 + byte1 x "
        "stride, or not a whole number of cells, returns None (registry WARN). "
        "Per-cell PCI = u32[1] & 0x1FF on the 40/44 B layouts: AT-verified on an "
        "RM520N-GL v0x29 paired DIAG+AT capture (EARFCN-66536 cells decode pci 250 "
        "and 310 == AT+QENG neighbourcell PCIs, with 5230 B13 serving + 66536 B66 "
        "inter-freq) and F3-grounded on v0x20 (MC7411: cells[0]=(66786,236)==0xB0C0 "
        "serving, cells[1]=(66786,471) and (66786,322)==0xB192, ML1 F3 sites "
        "lte_ml1_dlm_rx_cfg.c:20561 / lte_ml1_mdb.c:6246 / lte_ml1_md.c:1346 label "
        "all three). v0x02 u16@4 EARFCN == 0xB0C0 serving EARFCN in 8/8 MC7700 "
        "captures. Measurement block rsrp_rx0 (cell+12 b0..11), rsrp_rx1 (cell+16), "
        "rsrp (cell+20; == 0xB17F u32@12 whole-word), rsrq (cell+28 b20..29), rssi "
        "(cell+36), x16 fixed point (-180/-30/-110 offsets): 0xB17F bit-exact on "
        "every version, F3-exact on EG18-NA v0x03, per-antenna confirmed by F3 "
        "(MC7411 v0x20) and AT +QRSRP (RM520N-GL v0x29)."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=9,
    fields_parsed=11,
    field_invariants={"version": {"enum": [0x02, 0x03, 0x20, 0x29]}, "earfcn": {"range": (0, 262143)}},
)
def parse_0xb196(log_time: int, data: bytes) -> Diag0xB196 | None:
    if not data or data[0] not in _VERSIONS_B196_4918:  # loud version gate
        return None
    if len(data) < 1:
        return None
    version = data[0]
    cell_size = _CELL_SIZE_BY_VERSION.get(version)
    # Truncation gate: byte1 is the populated-cell count, so the record must
    # hold the 4 B header + byte1 x cell stride. A record shorter than that lost
    # bytes — decline it (registry WARN) rather than hand back a cell array
    # missing its tail. Every version accepted by the version gate above has a
    # known cell stride (incl. v0x02 = 36 B).
    if len(data) < _HEADER_SIZE or (
        cell_size is not None and len(data) < _HEADER_SIZE + data[1] * cell_size
    ):
        return None
    # Stride gate: the body may carry zero-pad slots past byte1 (a 244 B v0x29
    # is 6 slots with byte1 5), so the floor above cannot see a byte lost from
    # one. Every attested record is 4 + k x stride; anything else is truncated
    # (registry WARN).
    if cell_size is None or (len(data) - _HEADER_SIZE) % cell_size != 0:
        return None

    num_cells = data[1]
    num_slots = (len(data) - _HEADER_SIZE) // cell_size
    n_u32 = cell_size // 4
    v2 = version == _MDM9200_V2_VERSION
    shift = _MDM9200_V2_MEAS_SHIFT if v2 else 0
    cells: list[dict[str, Any]] = []
    for s in range(num_slots):
        off = _HEADER_SIZE + s * cell_size
        raw = data[off:off + cell_size]
        words = unpack_from(f'<{n_u32}I', raw)
        if v2:
            # 36-byte MDM9200 cell: u16 earfcn, u16 pci.
            cell_earfcn, pci_word = unpack_from('<HH', raw)
        else:
            cell_earfcn, pci_word = words[0], words[1]
        if cell_earfcn == 0:  # zero-pad slot beyond num_cells
            continue
        cell: dict[str, Any] = {"earfcn": cell_earfcn}
        # Per-cell PCI lives in the low 9 bits of u32[1] on BOTH the 40-byte
        # (v0x03 / v0x29) and the 44-byte (v0x20) cell layouts, and of the u16
        # at cell+2 on the 36-byte v0x02 layout.
        #   - v0x03 / v0x29: AT-verified on RM520N-GL — (u32[1] & 0x1FF)
        #     == the AT+QENG="neighbourcell" PCI for the same EARFCN (250 and 310
        #     @ EARFCN 66536). Upper bits are const 0x600 on v0x29, 0 on v0x03.
        #   - v0x20 (Sierra mc7411/em7511 SWI9X50C SDX55): GROUND (F3-VERDICT
        #     v0x20). u32[1] is the full PCI — upper bits are 0 for every corpus
        #     cell (u32[1]>>9 == 0 across 787/787), so the mask is a no-op
        #     guard, not a strip. Cross-confirmed three ways on an MC7411
        #     F3+AT+QMI capture: serving cells[0]=(66786,236) == 0xB0C0
        #     serving; neighbour cells[1]=(66786,471) == 0xB192 neighbour meas;
        #     3rd cell (66786,322) == 0xB192; and the ML1 F3 plane labels all
        #     three — lte_ml1_dlm_rx_cfg.c:20561 "cell=236 freq=66786",
        #     lte_ml1_mdb.c:6246 "earfcn 66786 pci 471",
        #     lte_ml1_md.c:1346 "EUTRA Ngbr Srch new cell (66786,322) num_cells 3".
        #   - v0x02: the u16 that a u32 EARFCN read would pull into its high
        #     half (473 in the 31000703 value); (earfcn, pci) keys the
        #     co-emitted 0xB17F v0x03 record 468/468.
        # The upper bits are treated as a separate field and masked off.
        cell["pci"] = pci_word & 0x1FF
        cell.update(_measurements(raw, shift))
        cell["u32"] = list(words)
        cells.append(cell)

    if cells:
        earfcn = cells[0]["earfcn"]
    elif v2:
        earfcn = unpack_from('<H', data, 4)[0] if len(data) >= 6 else 0
    else:
        earfcn = unpack_from('<I', data, 4)[0] if len(data) >= 8 else 0
    return Diag0xB196(
        log_time=log_time,
        version=version,
        earfcn=earfcn,
        num_cells=num_cells,
        num_slots=num_slots,
        cell_size=cell_size,
        structured=True,
        cells=cells,
        payload_size=len(data),
        body_raw=data[1:],
    )
