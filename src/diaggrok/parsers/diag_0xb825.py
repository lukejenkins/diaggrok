"""0xB825 — LOG_NR5G_RRC_CONFIGURATION_INFO (NR5G RRC configuration snapshot).

One cell-list grammar for every version, at a per-version base offset
(`_B825_LAYOUTS`), with a closed length budget; every cell typed, each version
grounded on its own. Bytes nothing labels (per-cell trailer, 18 B blocks) stay
raw in `body_raw`.

**Unified grammar — all six versions.**

    version  major  counts (bands, cells, blocks)  list  detail  SSB slot
    v0x00    0x02   @58 @59 @60                    @61   22 B    yes
    v0x08    0x00   @58 @59 @60                    @61   18 B    NO
    v0x0a    0x00   @58 @59 @60                    @61   22 B    yes
    v0x03    0x03   @66 @68 @70                    @71   23 B    yes
    v0x04    0x03   @67 @69 @71                    @72   23 B    yes
    v0x06    0x03   @67 @69 @71                    @72   25 B    yes

    list entry (4 B):  band u16 | u8 raw (0x01; 0x03 on a v0x06 2-cell band) | pcell-flag
    detail entry:      +0 serv_cell_index u8 | +1 pci u16 | +3 carrier DL u32 |
                       +7 carrier UL u32 (0 SDX55/SDX72, 0x3333 SDX6x = absent) |
                       +11 SSB u32 | +15 band u16 (v0x08: band u16 @+11, no SSB) |
                       per-cell trailer raw
    then n_blocks x 18 B, raw.

    len == list + 4*n_bands + detail*n_cells + 18*n_blocks   (closed budget)

A first band-list entry followed by the detail's serv_cell_index byte reads as
``<band> 00 01 01 00`` — e.g. ``29 00 01 01 00`` for n41 — which is easy to
mistake for a fixed "serving block" tag + sub-marker.

Corpus (1,331 records / 98 captures): the budget closes on **1,330/1,330** real
records across 24 (version, length, counts) profiles — v0x00 61/87/105, v0x03
116, v0x04 72/99/117/126/144/153/180/198, v0x06 72/101/119/180/213, v0x08
79/101/137/155, v0x0a 105 — plus three enumerated SDX55 fixed-capacity profiles
(`_B825_STALE_SLOT_PROFILES`: M2000 v0x0a 105 B non-camped + 65 B idle, FT980m
v0x00 65 B idle) where the firmware keeps a one-band/one-cell slot with zero
counts. The only rejected record is the v0x28 misframe phantom. Every detail
band is in its band list; every PCI <= 1007.

**Loud-drop contract.** Unhandled versions and lengths are logged loudly, never
silently dropped. A record returns None — firing the registry WARN and tally —
when its byte-0 is unattested, its major is not that version's, its length does
not close the budget (and is not an enumerated profile), or a detail entry is
not a plausible cell. Such a record is never returned as an untyped shell that
would be indistinguishable from an idle camp.

**Carrier-centre rule (GROUND).** The DL/UL pair is the RF carrier centre
(PointA + carrierBandwidth/2) whenever the UL slot is populated. With UL absent,
the FIRST entry's DL is a near-SSB RF tune (SSB −78…+138 on 504/504 such
entries, never a known centre — pre-dedicated-config) and stays untyped; a
LATER entry (DL-only SCell) carries its true centre (195/195 equal a centre
grounded on a UL-present entry). Every typed UL pair has its band's exact 3GPP
duplex gap (n5 45, n25 80, n66 400, n71 −46 MHz; n41/n77 TDD 0) — 386/386.

**Header (all versions), 4 bytes:**

    [0]  u8  version  release MINOR (byte-0); dominant 0x04 (89.5% of corpus,
                      SDX6x), then 0x00 (6.6%, SDX55/EM9190), 0x0a, 0x08, 0x06.
                      byte1 == 0x00 for every real version (it is the high byte
                      of the u16 release-minor) — a record whose byte1 != 0x00 is
                      an HDLC misframe, not a version (see the v0x28 phantom note
                      at `_B825_VERSIONS_OBSERVED`).
    [2]  u8  major    release MAJOR (byte-2): 0x03 on SDX6x, 0x02 on the SDX55
                      v0x00 emission, 0x00 on v0x08/v0x0a. byte3 == 0x00. This is
                      the same (rel_maj=u16@2, rel_min=u16@0) version tuple the
                      sibling 0xB823 parser documents; 0xB825 keys on the minor
                      (byte-0), which disambiguates the observed forms.

This is a variable-length, conditionally-populated record: an idle NR camp
emits a near-empty short frame (zero counts) and an active NR5G configuration
fills in the cell list.

**v0x04 / v0x06 ``nci`` @[4:8].** The [4:8] cell-identity word is the NR Cell
Identity: it equals the co-captured sibling 0xB823's ``nci`` for the same cells
(0xca74b017 @ pci293, 0xca74b003 @ pci515, 0x87eac028 on two RM520N-GL
captures; 0xB823's nci is AT+QENG / SCAT SIB1 / QMI verified). Zero on idle
camps (→ None). On v0x06 (T99W640) every nci equals a co-captured 0xB823.nci
across all 3 captures (full word, or gNB-ID where the two codes sampled
different sectors). The [8:12] upper-NCGI word has a constant 0x0130 high half
(the same marker sibling 0xB821/0xB823 carry) but a cell-varying low half
(0x0621 vs 0x1840), so it stays raw. `data_density` (nonzero fraction of the
body) is exposed as a cheap idle-vs-active discriminator.

**F3-VERDICT v0x04 — NCI GROUND (four independent sources).** On an RM520N-GL
capture with 100%-resolved F3: (1) 0xB825 v0x04 emits ``nci=0xc594112f`` (8
records, the dominant serving camp) and ``nci=0x85e8803a`` (1 record); (2) the
co-captured 0xB823 maps those same nci words to ``pci 260`` and ``pci 746``;
(3) QCSuper's NR-RRC decode of the capture reports ``physCellId: 260`` (and 515)
as NR serving/measured cells; and (4) F3 prints, co-temporal with the
``nci=0xc594112f`` records, ``tm_cm_iface_nonship.c:293 5G-NR CID Update:
TAC=45 Freq=501390 PSC=260`` — and that record's own cell list carries 501390,
the identical serving frequency. The CM layer reports the NR cell id itself as
the ``CID=0xFFFFFFFF`` sentinel, so F3 never prints the NCI integer.

**F3-VERDICT v0x04 — cell list GROUND: band + pci + SSB NR-ARFCN +
carrier-centre DL/UL.** 1,181 v0x04 records / 98 captures (RM520N-GL, EM9291,
T99W373, CFW-3212 …); 411 idle (0 cells), 770 populated, and the cell-list
grammar fits **770/770** — detail band == flagged list band, SSB inside that
band's NR-ARFCN range (n5/n25/n41/n66/n71/n77), PCI <= 1007. Sources, on
records with live alternatives to pick from:
(1) **F3** `gts.c:2768 "Proc NR5G … PCI <pci> <ssb>"` names this record's exact
    (pci, SSB) on **58/58** records of two 100%-resolved RM520N-GL captures (one
    hops n41 260/501390 → n71 515/125530 → n25 293/387170 → n77 746/647328). 48
    match the last print; the other 10 are leading edges (the config is logged
    just before the PHY's first print for the new cell, and the next print
    matches, 10/10). `tm_cm_iface_nonship.c:293 "5G-NR CID Update: Freq= PSC="`
    agrees wherever it is current.
(2) **F3 RF driver** `rfdevice_asm_common.cpp "mode=19 … freq_khz="` tunes the
    record's DL carrier within ±5 s on 54/58, and the UL carrier (TX: n71 678000
    kHz = 135600, n25 1857500 kHz = 371500) on 18/22, fixing the DL/UL order.
(3) **QCSuper** NR-RRC decodes the PCI-260 cell's ServingCellConfigCommon:
    absoluteFrequencySSB 501390, absoluteFrequencyPointA 499374,
    carrierBandwidth 273 @ 30 kHz, offsetToCarrier 0 → centre = 499374 +
    273·12/2·6 = **509202** == carrier_arfcn_dl, independently computed.
    Second detail entries (191 SCells, UL absent): DL == QCSuper centre 16/16
    joinable, == a UL-present-grounded centre 191/191.
(4) **3GPP duplex** — every UL-present pair has its band's exact duplex gap.
(5) **Cross-code** 0xB823 — on 58 captures that carry it, the (pci, SSB) pair is
    one 0xB823 also reports on 741/748; this record's own nci maps (via 0xB823) to
    the same (pci, SSB) on 700 — every single-cell record. On two-cell 180 B
    records the [4:8] nci leads/lags the list on 29/182 (4 point at entry 2, 25
    at a third cell), so the typed PCell is the list's first entry, not the nci.
The count at @71 is the 18 B block count (the idle 126 B frame is 72 + 3·18).
Still untyped: the near-SSB @+3 value when UL is absent (RF-tuned per F3, e.g.
501354 = SSB−36, but nothing names it — not the carrier centre, per (3)), the
per-cell trailer and the 18 B blocks.

**F3-VERDICT v0x03 — band + PCI + SSB NR-ARFCN + carrier-centre NR-ARFCN GROUND
(F3 + 0x60 + cross-code + SCAT, all discriminating).** v0x03 is an older
RM520N-GL firmware train's minor (SDX6x, major 0x03); the corpus holds exactly
one record (116 B, a QSH throughput capture with no co-emitted 0xB823). It is
the v0x04 grammar one byte earlier (budget 71+4+23+18 = 116): band n41, detail
serv_cell_index 0x07 (CANDIDATE: EN-DC SCG cell), PCI 596, carrier-centre DL/UL
509202/509202 (TDD n41), SSB 501390. Bytes [36:48] include ``42 00 42 00``
(66, 66) — the co-captured LTE anchor is EARFCN 66786 = B66, so an EN-DC
anchor-band pair is a CANDIDATE only (n=1), not typed.

A single record grounds because the UE hops between two n41 carriers on PCI
596 — SSB 521310 / carrier 528144 and SSB 501390 / carrier 509202 — so every
source had a live alternative and each picks the pair this record carries:
(1) **F3** (100% resolved) `gts.c:2769 "Proc NR5G … PCI 596 501390"` 113 ms
before the record, `… PCI 596 521310` on the segments either side; (2) **F3 RF
driver** `rfdevice_xsw_common.cpp:1644 "band=20 … freq_khz=2546010"` (== 509202
x 5 kHz) throughout the 501390 segment, `freq_khz=2640720` (== 528144 x 5 kHz)
on the 521310 segments; (3) **0x60** `EVENT_NR5G_RRC_NEW_CELL_IND_V2` payload
`8ea60700 5402 …` = (501390, 596) at -1.25 s, with `NR5G_RRC_HO_STARTED_V2` /
`HO_SUCCESS` carrying (596, 501390); (4) **cross-code** — the co-emitted 0xB821
header reads pci 596 / arfcn 501390, RRC-RECONF-COMPLETE, 0.33 ms after the
record, and QCSuper independently decodes that same nested NR
rrcReconfigurationComplete; (5) **SCAT** NR-ML1 `NR-ARFCN: 501390, SCell PCI:
596`, byte-joined (PBCH SFN 1002, RSRP -106.44, RSRQ -14.85) to the 0xB97F
record 0.41 s before. So this record is the RRC configuration snapshot logged
at the SCG reconfiguration onto the 501390 carrier.

**F3-VERDICT v0x06 — carrier centre + multi-cell GROUND (T99W640).** The
single-cell block is the v0x04 grammar with a 25 B detail; a band-list entry
`29 00 03 01` is 1 band with 2 cells. **SCAT** NR-RRC SCell Info on the
T99W640's own captures gives PointA + bandwidth for every carrier this version
emits: `501390/499374, 100 MHz` → 273 PRB → 509202; `521310/519324, 90 MHz` →
245 PRB → 528144; n25 `387170/370078, 15 MHz` → UL 370078 + 79·18 = 371500, DL
= UL + 80 MHz = 387500 — each equal to the v0x06 carrier pair; the n71 SCell's
126400 equals the QCSuper-grounded M2000 centre for the same cell. PCI / SSB
pairs equal the co-captured 0xB823's — (260,501390), (455,387170),
(596,501390), (596,521310) — and QCSuper's NR-RRC reports the same SSB
NR-ARFCNs. The 180 B (1 band / 2 cells) and 213 B (3 bands / 3 cells) frames
are typed: 16 cells, 0 out-of-range.

**F3-VERDICT v0x00 — grammar + PCI + SSB + band + carrier rule GROUND
(EM9190, FT980m).** F3 is silent on the EM9190 (only 0x98-wrapped multi-radio
F3, no resolvable 0x79/0x99 and no 0x60 cell events), so non-F3 sources
converge: (1) cross-code — on an EM9190 drive capture the 6 v0x00 records'
PCIs {69,76,240,240,487,557} equal the co-temporal 0xB823.pci 6/6, and their
SSB NR-ARFCN equals 0xB823.nr_arfcn 6/6 (521310 / 501390); (2) SCAT NR-ML1 on
the same capture reports the serving SCell PCI set {69,76,240,487,557,596}, and
on a second EM9190 capture the exact (NR-ARFCN, PCI) pairings this record emits
— `521310/265`, `521310/69`, `647328/746`, `647328/310`, `125530/550`; (3) the
list band (0x29=41/n41, 0x47=71/n71, 0x4D=77/n77) agrees with the SSB
NR-ARFCN's band range and SCAT's own `Band:` field across 3 EM9190 captures.
Across 5 EM9190 sessions (~40 active records) the PCI is always valid. The
EM9190 records are all UL-absent (UL slot 0), first-entry DL = SSB
−78/−36/−30/+14 → correctly untyped. A second SDX55 module also emits v0x00 —
Telit **FT980m** (Verizon mmWave camp): its 105 B record closes the budget
(1/1/1) with an n77 EN-DC SCG cell (idx 7, PCI 236, SSB 653952) whose carrier
655320/655320 == QCSuper PointA + carrierBandwidth/2 **1/1**; its 65 B idle
frame is the enumerated stale-slot profile.

**F3-VERDICT v0x08 — PCI GROUND, carrier centre DL/UL GROUND (SDX55-family:
Compal RXM-G1 / Quectel RM500Q-AE / Wistron LV55).** The v0x08 detail entry
has no SSB slot (18 B: idx/pci/DL/UL/band + trailer), so ``arfcn_dl`` is None
on v0x08. ``pci`` is verified by SCAT NR-ML1 (`SCell PCI: 596`) on an RXM-G1
capture and by `AT+QENG="servingcell"` (`PCI 596`) on a co-located RM500Q-AE
capture; across all 20 active v0x08 records (5 captures / 3 modules) the field
reads only valid PCIs {240, 310, 596, 754}. The DL/UL pair is the carrier
centre: QCSuper PointA + carrierBandwidth/2 == both on **7/7** joinable records
(528144), plus exact duplex on all 24 typed pairs (n41 TDD, n66 400 MHz, n71
−46 MHz). v0x08 carries no NCI at [4:8]: the QENG NCI ``0x1C6897138`` seen on
the RM500Q-AE camp appears nowhere in its v0x08 records.

**F3-VERDICT v0x0a — PCI + SSB + band + carrier centre GROUND (Inseego
M2000).** v0x0a is a minority version confined to the SDX55 Inseego M2000 (26
records / 4 captures, header `0a 00 00 00`). F3 is silent (no F3 frames and no
0x60 events in the capture). QCSuper's NR-RRC decode reports the exact
per-record `(physCellId, absoluteFrequencySSB)` pairings this record emits —
`(596, 501390)` and `(596, 521310)` on n41, `(389, 125530)` on n71 — and
PointA + carrierBandwidth/2 == carrier_arfcn_dl AND carrier_arfcn_ul on
**12/12** joinable records (n41 PointA 519324 + 245 PRB @30 kHz → 528144; n71
FDD 126400/135600, −46 MHz). The 12 non-camped 105 B frames are the zero-count
stale-slot profile.

The full set of corpus byte-0 versions is enum-gated so no real record is
silently dropped, while the per-cell trailer and blocks stay raw and preserved.

Log name: LOG_NR5G_RRC_CONFIGURATION_INFO
Also known as: NR5G RRC Configuration Info
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

# Every byte-0 (release MINOR) value observed in the corpus. Gating on the
# COMPLETE set means structural framing accepts 100% of real 0xB825 records
# while keeping the parser honest about the version space. A byte-0 OUTSIDE
# this set is NOT silently dropped: `parse_0xb825` returns None and the registry
# `parse()` wrapper emits a rate-limited WARN + tallies it, so a genuinely-new
# version surfaces loudly in a corpus walk. A version listed here is confirmed
# real and framed structurally.
#
# 0x03: a lone real record from RM520N-GL on an older firmware train — same
# SDX6x major (0x03) as the dominant v0x04, one minor lower. Header
# `03 00 03 00`, idle NCI, n41 cell list (509202/501390). A singleton size class
# can look like damage, but its cell is F3-grounded (F3-VERDICT v0x03 in the
# module docstring), which settles "real, not misframe".
#
# 0x28 is NOT a version: F3-VERDICT v0x28 = PHANTOM (HDLC misframe). Its sole
# record — 750 B in an LV55 SIM-power-cycle capture — has header `28 b8 ee 02`:
# byte1 == 0xb8 (every real version has byte1 == 0x00), and byte0:byte1 == 0xB828
# is a neighbouring NR5G log code. The same capture also carries a lone 945 B
# "0xB827 v0xf7" pseudo-record — a cluster of oversized garbage-version singletons
# in one framing-hostile SIM-power-cycle stream region: the fingerprint of a
# deframer over-reading a length past an HDLC boundary and swallowing the next
# frame's log-code header into the body. LV55's real 0xB825 is v0x08 @101 B (a
# sibling COPS-dereg capture). The record hits the loud unknown-version WARN
# path, which is correct for a misframe.
_B825_VERSIONS_OBSERVED = frozenset({0x00, 0x03, 0x04, 0x06, 0x08, 0x0A})
_B825_MIN_SIZE = 4  # 4-byte version header

# Unified cell-list grammar — every version is ONE grammar at a per-version
# base offset:
#
#     [nb_off]   u8  n_bands   — band-list entries
#     [nc_off]   u8  n_cells   — cell DETAIL entries
#     [nk_off]   u8  n_blocks  — trailing fixed 18 B blocks (raw)
#     [list_off] n_bands  x 4 B  `band u16 | u8 (raw) | pcell-flag u8`
#                n_cells  x detail_len B
#                    +0  u8   serv_cell_index
#                    +1  u16  pci
#                    +3  u32  carrier-centre NR-ARFCN DL
#                    +7  u32  carrier-centre NR-ARFCN UL (0 / 0x3333 = absent)
#                    +11 u32  SSB NR-ARFCN          (absent on v0x08)
#                    +15 u16  band                  (+11 on v0x08)
#                    ...      per-cell trailer, raw
#                n_blocks x 18 B (raw)
#
# and the record length MUST equal list_off + 4*n_bands + detail_len*n_cells +
# 18*n_blocks. That closed length budget is the loud-drop gate: a record of a
# known version whose (major, length, counts) do not satisfy it is an
# unobserved layout, so parse_0xb825 returns None and the registry fires its
# WARN and tally — never a silent half-decoded record.
#
# version: (major, nb_off, nc_off, nk_off, list_off, detail_len, has_ssb)
_B825_LAYOUTS: dict[int, tuple[int, int, int, int, int, int, bool]] = {
    0x00: (0x02, 58, 59, 60, 61, 22, True),   # SDX55 / Sierra EM9190
    0x03: (0x03, 66, 68, 70, 71, 23, True),   # SDX6x / RM520N-GL (older firmware)
    0x04: (0x03, 67, 69, 71, 72, 23, True),   # SDX6x / RM520N-GL, EM9291 …
    0x06: (0x03, 67, 69, 71, 72, 25, True),   # SDX72 / Foxconn T99W640
    0x08: (0x00, 58, 59, 60, 61, 18, False),  # SDX55 / RXM-G1, RM500Q-AE, LV55
    0x0A: (0x00, 58, 59, 60, 61, 22, True),   # SDX55 / Inseego M2000
}
_B825_BLOCK_LEN = 18
_B825_UL_ABSENT = frozenset({0x0000, 0x3333})  # 0: SDX55/SDX72, 0x3333: SDX6x

# Fixed-capacity SDX55 frames whose count bytes do NOT account for every byte:
# the firmware keeps its one-band (/one-cell) slot even when the counts are zero,
# filled with stale or zeroed bytes — so the COUNTS decide what is a cell, never
# the bytes present. Each entry is (version, length, n_bands, n_cells, n_blocks).
# Enumerated exactly (no ranges) so any other mismatch still drops loudly. All
# attested in the corpus walk (1,331 records / 98 captures):
_B825_STALE_SLOT_PROFILES: frozenset[tuple[int, int, int, int, int]] = frozenset({
    (0x0A, 105, 0, 0, 1),  # M2000 non-camped: 26 B stale list+detail slot (12 rec)
    (0x0A, 65, 0, 0, 0),   # M2000 idle: 4 B zero list slot (1 rec)
    (0x00, 65, 0, 0, 0),   # FT980m idle: 4 B zero list slot, same shape (1 rec)
})


# Per-version offsets (v0x04/v0x06 nci @[4:8]; every version's cell list) come
# from _B825_LAYOUTS above. Plausibility bounds for a decoded cell:
_NR_PCI_MAX = 1007  # NR physical-cell-id range 0..1007
_NR_BAND_MAX = 261  # highest assigned NR band number (n261 mmWave)
_B825_NCI_VERSIONS = frozenset({0x04, 0x06})  # nci @[4:8], 0xB823 cross-code lock


@dataclass
class Diag0xB825:
    """0xB825 — LOG_NR5G_RRC_CONFIGURATION_INFO: version header + cell list."""
    log_time: int
    version: int        # byte-0, release minor (chipset-family selector)
    major: int          # byte-2, release major (0x03 SDX6x/SDX72, 0x02 / 0x00 SDX55)
    data_density: float  # nonzero fraction of body — idle (~0) vs active config
    payload_size: int
    body_raw: bytes     # data[4:] preserved raw (per-cell trailers, 18 B blocks)
    # NR Cell Identity — [4:8] u32le, == sibling 0xB823.nci (verified). v0x04
    # and v0x06 only; None on other versions / idle (zero) camps.
    nci: int | None = None
    # Cell-list counts (unified grammar). 0/0 on an idle frame.
    band_count: int | None = None
    cell_count: int | None = None
    block_count: int | None = None
    # Every detail entry, in emission order: serv_cell_index, pci, band, arfcn_dl
    # (SSB; absent on v0x08), carrier_arfcn_dl/ul (RF carrier centre; see
    # _cell_dict for when each is typed).
    cells: list[dict[str, int]] | None = None
    # The FIRST detail entry (PCell / SCG SpCell), flattened for back-compat.
    serv_cell_index: int | None = None
    pci: int | None = None
    band: int | None = None
    arfcn_dl: int | None = None          # serving SSB NR-ARFCN (None on v0x08)
    carrier_arfcn_dl: int | None = None  # RF carrier-centre NR-ARFCN DL
    carrier_arfcn_ul: int | None = None  # RF carrier-centre NR-ARFCN UL

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": "Diag0xB825",
            "log_time": self.log_time,
            "version": self.version,
            "major": self.major,
            "data_density": self.data_density,
            "payload_size": self.payload_size,
            "body_raw": self.body_raw,
        }
        if self.nci is not None:
            d["nci"] = self.nci
            d["nci_hex"] = f"0x{self.nci:08X}"
        for k in ("band_count", "cell_count", "block_count", "serv_cell_index",
                  "pci", "band", "arfcn_dl", "carrier_arfcn_dl", "carrier_arfcn_ul"):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        if self.cells:
            d["cells"] = self.cells
        return d


def _cell_dict(data: bytes, d: int, has_ssb: bool, first: bool) -> dict[str, int] | None:
    """Decode one detail entry at offset ``d``; None if it is not a plausible cell.

    Carrier-centre typing (GROUND: QCSuper/SCAT PointA + carrierBandwidth/2 on
    v0x04/v0x06/v0x08/v0x0a, F3 RF freq_khz on v0x03/v0x04, exact 3GPP duplex on
    every UL pair): the DL/UL pair is typed whenever the UL slot is populated. With
    the UL slot absent (0 / 0x3333) the FIRST entry's DL is a near-SSB RF tune
    (SSB-36 / -78 / +14 …, no dedicated config yet — v0x00 EM9190 and v0x04
    pre-config frames), so it stays untyped; a LATER entry (an SCell, DL-only) still
    carries its true carrier centre (QCSuper 16/16 on v0x04, SCAT on v0x06).
    """
    pci = unpack_from("<H", data, d + 1)[0]
    band = unpack_from("<H", data, d + (15 if has_ssb else 11))[0]
    if pci > _NR_PCI_MAX or not 1 <= band <= _NR_BAND_MAX:
        return None
    cell = {"serv_cell_index": data[d], "pci": pci, "band": band}
    if has_ssb:
        cell["arfcn_dl"] = unpack_from("<I", data, d + 11)[0]
    dl, ul = unpack_from("<II", data, d + 3)
    if ul not in _B825_UL_ABSENT:
        cell["carrier_arfcn_dl"] = dl
        cell["carrier_arfcn_ul"] = ul
    elif not first:
        cell["carrier_arfcn_dl"] = dl
    return cell


@register(
    0xB825,
    name="0xB825",
    wigle_direct=True,
    wigle_roles=("identity",),
    description=(
        "0xB825 — LOG_NR5G_RRC_CONFIGURATION_INFO: one cell-list grammar for every "
        "version (v0x00/v0x03/v0x04/v0x06/v0x08/v0x0a) at a per-version base offset "
        "— band/cell/block counts, band list, and per-cell detail entries "
        "{serv_cell_index, pci, carrier-centre DL/UL NR-ARFCN, SSB NR-ARFCN (not on "
        "v0x08), band} typed for EVERY cell (cells[]; first entry flattened). "
        "Closed length budget: an unknown version, wrong major, or a length/count "
        "combination outside the grammar returns None (registry WARN + tally). "
        "v0x04/v0x06 nci @[4:8] (cross-code 0xB823). Grounded per version: F3 gts.c "
        "+ F3 RF freq_khz (v0x03/v0x04), qcsuper PointA+carrierBandwidth (v0x04/"
        "v0x08/v0x0a), SCAT NR-RRC SCell Info PointA+BW (v0x06), SCAT NR-ML1 + "
        "0xB823 (v0x00), exact 3GPP duplex on every UL pair; per-cell trailer and "
        "18 B blocks raw"
    ),
    version=14,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "One cell-list grammar for all six versions — counts (bands, cells, "
        "blocks) @58/59/60 (v0x00/v0x08/v0x0a), @66/68/70 (v0x03), @67/69/71 "
        "(v0x04/v0x06); band list; detail entries of 22/18/22 B (SDX55; v0x08 "
        "has no SSB slot) and 23/23/25 B (v0x03/v0x04/v0x06); 18 B trailing "
        "blocks. The record length must close the budget exactly (or be an "
        "enumerated SDX55 fixed-capacity profile) — otherwise None, so an "
        "unseen layout fires the registry WARN instead of decoding as an "
        "untyped shell; 1,330/1,330 real records over 98 captures close. Every "
        "detail entry is typed (cells[]). Per-version grounding: v0x04 nci @[4:8] "
        "== co-captured 0xB823.nci (itself AT+QENG / SCAT SIB1 / QMI verified), "
        "locked by QCSuper physCellId 260 and F3 '5G-NR CID Update: Freq=501390 "
        "PSC=260'; v0x06 nci the same cross-code lock on all 3 T99W640 captures; "
        "v0x04 cell list 770/770, F3 gts.c:2768 'Proc NR5G … PCI p ssb' 58/58, F3 "
        "RF freq_khz DL 54/58 and UL 18/22, QCSuper PointA 499374 + 273 PRB @30 "
        "kHz -> centre 509202 == carrier_arfcn_dl, 0xB823 pair agreement 741/748; "
        "v0x03 (single record) F3 gts.c + F3 RF freq_khz + 0x60 NEW_CELL_IND + "
        "co-emitted 0xB821 + SCAT NR-ML1, all on (596, 501390, carrier 509202); "
        "v0x06 SCAT NR-RRC SCell Info PointA+BW (509202, 528144, n25 UL 371500) "
        "and 0xB823 (pci, SSB) pairs; v0x00 cross-code 0xB823 6/6 and SCAT NR-ML1 "
        "exact (NR-ARFCN, PCI) pairs on EM9190, FT980m carrier == QCSuper 1/1; "
        "v0x08 PCI by SCAT NR-ML1 and AT+QENG (596), carrier == QCSuper 7/7; "
        "v0x0a QCSuper (physCellId, absoluteFrequencySSB) pairs and carrier 12/12. "
        "Exact 3GPP duplex on every UL pair (386/386). UL-absent sentinel is 0 on "
        "SDX55/SDX72, 0x3333 on SDX6x; with UL absent the first entry's DL is a "
        "near-SSB RF tune and stays untyped. Per-cell trailer and 18 B blocks "
        "stay raw."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=14,
    fields_parsed=14,
    field_invariants={
        # byte-0 release minor; full corpus set.
        "version": {"enum": sorted(_B825_VERSIONS_OBSERVED)},
    },
)
def parse_0xb825(log_time: int, data: bytes) -> Diag0xB825 | None:
    # Loud-drop contract: never silently drop a version or a length. Every
    # `return None` below fires the registry's rate-limited WARN and tally:
    #   * byte-0 outside the attested set (incl. the v0x28 misframe phantom);
    #   * byte-2 major not the one that version ships with;
    #   * a length that does not close the cell-list budget (and is not an
    #     enumerated fixed-capacity profile);
    #   * a detail entry that is not a plausible cell, or whose band is not in the
    #     band list — i.e. the grammar does not fit, so the parser refuses to guess.
    if len(data) < _B825_MIN_SIZE:
        return None
    version = data[0]
    if version not in _B825_VERSIONS_OBSERVED:
        return None
    major = data[2]
    major_want, nb_off, nc_off, nk_off, list_off, detail_len, has_ssb = (
        _B825_LAYOUTS[version]
    )
    if major != major_want or len(data) < list_off:
        return None
    n_bands, n_cells, n_blocks = data[nb_off], data[nc_off], data[nk_off]
    budget = list_off + 4 * n_bands + detail_len * n_cells + _B825_BLOCK_LEN * n_blocks
    if budget != len(data) and (
        (version, len(data), n_bands, n_cells, n_blocks) not in _B825_STALE_SLOT_PROFILES
    ):
        return None

    band_list = {
        unpack_from("<H", data, list_off + 4 * i)[0] for i in range(n_bands)
    }
    detail_off = list_off + 4 * n_bands
    cells: list[dict[str, int]] = []
    for j in range(n_cells):
        cell = _cell_dict(data, detail_off + detail_len * j, has_ssb, first=(j == 0))
        if cell is None or cell["band"] not in band_list:
            return None
        cells.append(cell)

    body = data[4:]
    nonzero = sum(1 for b in body if b != 0)
    density = round(nonzero / len(body), 2) if body else 0.0
    nci: int | None = None
    if version in _B825_NCI_VERSIONS:
        nci = unpack_from("<I", data, 4)[0] or None

    first = cells[0] if cells else {}
    return Diag0xB825(
        log_time=log_time,
        version=version,
        major=major,
        data_density=density,
        payload_size=len(data),
        body_raw=body,
        nci=nci,
        band_count=n_bands,
        cell_count=n_cells,
        block_count=n_blocks,
        cells=cells or None,
        serv_cell_index=first.get("serv_cell_index"),
        pci=first.get("pci"),
        band=first.get("band"),
        arfcn_dl=first.get("arfcn_dl"),
        carrier_arfcn_dl=first.get("carrier_arfcn_dl"),
        carrier_arfcn_ul=first.get("carrier_arfcn_ul"),
    )
