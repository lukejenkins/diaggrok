"""0xB176 — LTE ML1 initial-acquisition results (cell search + PBCH decode).

Legacy registry mislabel `LtePdcpB176`. The log names listed below carry
both `…CELL_SELECT_RESELECTS_CHECK_PROCEDURE` and
`…INITIAL_ACQUISITION_RESULTS`; the decoded body is the latter:
one record per ML1 acquisition attempt on one EARFCN, emitted on the same diag
tick as the firmware's `lte_ml1_md.c` `PBCH decode resp` print.

Layout. Little-endian. The same three lists on
every version; only the packing of the 16 B header differs.

    header (16 B)
      [0]      version            0x03 / 0x10 / 0x20
      [1:4]    zero
      [4:8]    earfcn             u32 (F3-grounded on all 3 versions)
      [8:12]   header word        band / duplex / result bits, see below
      [12:16]  count word         list counts, see below
    black_cell_pcis  n_black x u32  PCIs excluded from this attempt
    cells            n_cell  x 16 B detected cells, strongest first
      +0 u32  search_word   bits 0-7 always 0xFF, bits 8-14 shared by every
                            cell in a record, bit 15 varies; bits 16-31
                            `timing_raw` (CANDIDATE: PSS timing position)
      +4 u16  bits 0-8 pci, bit 9 `cp_flag` (CANDIDATE, see below),
              bits 10-15 zero in the corpus
      +6 s16  freq_offset_raw   (CANDIDATE; one value shared by the record's
                                cells in 1890/1897)
      +8 u32  zero
      +12 u32 energy            (CANDIDATE: detection energy; descending
                                across a record's cells in 1895/1897)
    pbch             n_pbch  x 12 B PBCH decode results
      +0 u32  search_word   equals the decoded cell's `search_word` (252/252),
                            but two cells can share one: join on `pci`
      +4 u32  mib           the 24-bit TS 36.331 MIB, MSB-aligned (bits 8-31)
      +8 s16  freq_err
      +10 u16 bits 0-8 pci, bits 9-14 `info_raw`, bit 15 `crc_pass`

    header word, v0x10 / v0x20          header word, v0x03
      bits 0-7   band_index (band-1)      bits 0-5  band_index (6 bits; bands
      bit 8      tdd                                65+ wrap, e.g. B66 -> 1)
      bit 9      acq_failed               bit 6     tdd
      bits 10-31 raw (0x0A1021 const)     bit 7     acq_failed
                                          bits 8-27 raw (0x0A1021 const)
                                          bits 28-31 n_black
    count word, v0x10 / v0x20           count word, v0x03
      bits 0-2  n_black                   bits 0-2  n_pbch
      bits 3-5  n_pbch                    bits 3-7  n_cell
      bits 6-10 n_cell

Size = 16 + 4*n_black + 16*n_cell + 12*n_pbch held on 1897/1897 records from 5
captures (3 versions, 5 chipsets). A record SHORTER than that (or than the
16 B header) is truncated and returns None. A longer record keeps
its header fields, gets empty lists and `layout_ok=False`. That flag is not
pinned as an invariant.

Grounding. Each record is joined to the `lte_ml1_*` F3 prints of its own
acquisition attempt; the baseline figures join the attempt before it
instead.
  * v0x10, EG25-G MDM9207 (383 records): band = `LTE_CPHY_ACQ_REQ … Band`
    383/383; n_black = `# black_cells` 383/383 (baseline 0/14), the list
    growing by the PCI acquired on the previous attempt; every `Acq_cnf
    values: Cell id` is in cells[].pci 27/27 (baseline 4/24). PBCH vs `PBCH
    decode resp: MIB cell (earfcn,pci), BW # ant pHICH res|dur sfn … freq
    err`, on the same tick: BW 16/16, PHICH 16/16, sfn (8 MIB MSBs x4)
    15/16, freq_err (signed) 15/16. The miss is off on both sfn and
    freq_err, so a different decode attempt.
  * v0x03, MC7411 MDM9x50 (604 records): band 604/604; n_black 604/604
    (baseline 2/48); n_cell = `Init Acq Cnf; earfcn num cells` 601/604
    (baseline 10/48); acq_failed = `LTE_CPHY_ACQ_CNF Status` != 0 572/572
    (baseline 4/17); Cell id in cells[].pci 96/99; PBCH BW 49/49, PHICH
    49/49, sfn 48/49, freq_err 48/49.
  * v0x20, RM520N-GL SDX62 CFUN band-lock sweep: band_index = commanded
    band - 1 on 3929/3929 records over 7 bands, the firmware's own 0-based
    number (`srchfs.c FFT_debug band 70` = B71). In the 4 legs that
    camp, the PBCH-passing cell and its dl_bandwidth_prb equal the AT+QENG
    serving PCI and DL bandwidth 4/4. No v0x20 capture with resolvable F3
    had the LML1 F3 client armed, so the PBCH-print join is v0x10 and
    v0x03 only.
  * Not `# ant`: F3 printed 4 antennas while `info_raw` ranged 1-6.

`band` is band_index+1. On v0x03 the index is 6 bits, and a 65+ band wraps
(B66 -> 1, B71 -> 6). An EARFCN of 65536 or more is always band 65+, so the
parser adds 64 back there: 100% agreement with the EARFCN on the sample.

`acq_failed`: 1 on 1710/1711 records with no passing PBCH entry, 0 on
152/192 records with one. `cp_flag`: 18 of 416 cells, all at noise-floor
energy (median 670 vs 1503), none PBCH-passing; the Techplayon field list
names a CP per search result, so extended-CP hypothesis is the candidate.

The MIB tail (bits 8-17) is `sib1_br_raw`: schedulingInfoSIB1-BR-r13 (5 bits)
+ systemInfoUnchanged-BR-r15 + spare. Non-zero on LTE-M carriers.

Log name: LOG_CELL_SELECT_RESELECTS_CHECK_PROCEDURE
Also known as: LOG_LTE_ML1_CELL_SELECT_RESELECTS_CHECK_PROCEDURE, LOG_LTE_ML1_INITIAL_ACQUISITION_RESULTS, LOG_LTE_INITIAL_ACQUISITION_RESULTS, LTE Initial Acquisition Results
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

# byte-0 version/sub-layout discriminator: every value observed
# at size>4 in the corpus: 0x03, 0x10, 0x20.
_B176_VERSIONS_OBSERVED = (0x03, 0x10, 0x20)

_HDR_LEN = 16
_CELL_LEN = 16
_PBCH_LEN = 12

# MIB dl-Bandwidth enum (TS 36.331) -> resource blocks.
_DL_BANDWIDTH_PRB = (6, 15, 25, 50, 75, 100)


@dataclass
class B176Cell:
    """One detected cell (16 B)."""
    search_word: int
    pci: int
    cp_flag: int
    freq_offset_raw: int
    energy: int

    @property
    def timing_raw(self) -> int:
        return self.search_word >> 16

    def to_dict(self) -> dict[str, Any]:
        return {
            "pci": self.pci,
            "cp_flag": self.cp_flag,
            "timing_raw": self.timing_raw,
            "search_word": self.search_word,
            "freq_offset_raw": self.freq_offset_raw,
            "energy": self.energy,
        }


@dataclass
class B176Pbch:
    """One PBCH decode result (12 B), keyed to a cell by `search_word`."""
    search_word: int
    mib: int
    freq_err: int
    pci: int
    info_raw: int
    crc_pass: bool

    @property
    def dl_bandwidth(self) -> int:
        return self.mib >> 29

    @property
    def dl_bandwidth_prb(self) -> int | None:
        bw = self.dl_bandwidth
        return _DL_BANDWIDTH_PRB[bw] if bw < len(_DL_BANDWIDTH_PRB) else None

    @property
    def phich_duration(self) -> int:
        return (self.mib >> 28) & 1

    @property
    def phich_resource(self) -> int:
        return (self.mib >> 26) & 3

    @property
    def sfn(self) -> int:
        # The MIB carries the 8 MSBs of the 10-bit SFN; F3 prints them x4.
        return ((self.mib >> 18) & 0xFF) << 2

    @property
    def sib1_br_raw(self) -> int:
        return (self.mib >> 8) & 0x3FF

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "pci": self.pci,
            "crc_pass": self.crc_pass,
            "info_raw": self.info_raw,
            "search_word": self.search_word,
            "freq_err": self.freq_err,
            "mib": self.mib,
        }
        if self.crc_pass:
            d.update(
                dl_bandwidth=self.dl_bandwidth,
                dl_bandwidth_prb=self.dl_bandwidth_prb,
                phich_duration=self.phich_duration,
                phich_resource=self.phich_resource,
                sfn=self.sfn,
                sib1_br_raw=self.sib1_br_raw,
            )
        return d


@dataclass
class Diag0xB176:
    """0xB176: one ML1 acquisition attempt on `earfcn` (layout in module doc).

    `earfcn` is the u32-LE at byte-offset 4. For payloads < 8B the
    byte-1 fallback applies; for < 2B the slot is 0, the `_simple_parser`
    factory contract. A payload shorter than the 16 B header, or than the
    lists the count word declares, returns None; `layout_ok` is
    False (lists empty) when the payload is longer than the count word implies.
    """
    log_time: int
    version: int
    earfcn: int
    data_density: float
    payload_size: int
    body_raw: bytes
    band_index: int | None = None
    band: int | None = None
    duplex: str | None = None
    acq_failed: bool | None = None
    header_raw: int | None = None
    n_black: int | None = None
    n_cell: int | None = None
    n_pbch: int | None = None
    layout_ok: bool | None = None
    black_cell_pcis: list[int] = field(default_factory=list)
    cells: list[B176Cell] = field(default_factory=list)
    pbch: list[B176Pbch] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB176",
            "log_time": self.log_time,
            "version": self.version,
            "earfcn": self.earfcn,
            "band_index": self.band_index,
            "band": self.band,
            "duplex": self.duplex,
            "acq_failed": self.acq_failed,
            "header_raw": self.header_raw,
            "n_black": self.n_black,
            "n_cell": self.n_cell,
            "n_pbch": self.n_pbch,
            "layout_ok": self.layout_ok,
            "black_cell_pcis": list(self.black_cell_pcis),
            "cells": [c.to_dict() for c in self.cells],
            "pbch": [p.to_dict() for p in self.pbch],
            "data_density": self.data_density,
            "payload_size": self.payload_size,
            "body_raw": self.body_raw,
        }


# ──────────────────────────────────────────────────────────────────────────
# Emission: on an RRC-Connected EM7565 a COPS=2/COPS=0 rescan emits v0x03
# records whose earfcn set is a superset of the camped cell; earfcn is
# verified by containment of the AT-confirmed serving EARFCN.
# ──────────────────────────────────────────────────────────────────────────

@register(
    0xB176,
    name="0xB176",
    wigle_direct=False,
    wigle_roles=("pci-earfcn-bridge",),
    description=(
        "0xB176 — LTE ML1 initial-acquisition results: earfcn, band, duplex, "
        "acq result, black-cell PCIs, detected cells (pci/energy), PBCH "
        "decodes (MIB bandwidth/PHICH/SFN, freq err, CRC)"
    ),
    version=11,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Body decoded on all three versions (byte 0 = 0x03 / 0x10 / 0x20, the "
        "sub-layout discriminator). The 16 B header carries earfcn (u32@4), "
        "band_index/tdd/acq_failed (header word) and n_black/n_cell/n_pbch (count "
        "word, packed differently on v0x03), followed by n_black u32 black-cell "
        "PCIs, n_cell 16 B detected cells and n_pbch 12 B PBCH decodes whose "
        "middle u32 is the MSB-aligned 24-bit MIB. Size formula 1897/1897 across "
        "5 captures (3 versions, 5 chipsets). earfcn is F3-grounded on every "
        "version against the firmware's own EARFCN prints: v0x03 (LM960A18 SDX20) "
        "13/13 decoded EARFCNs are members of the `lte_rrc_csp.c` acq-DB set; "
        "v0x10 (EG25-G MDM9207) an exact value+timestamp match bracketed by "
        "`lte_rrc_csp.c` 'Acq requested on earfcn 2300' / 'Adding cell to Acq DB "
        "EARFCN:2300' prints; v0x20 (RM520N-GL SDX62 CFUN band-lock sweep) "
        "973/986 Band-71 records inside the `srchfs.c` 'FFT_debug band 70 start "
        "earfcn 68586 end earfcn 68935' scan window and all 1688 Band-5 records "
        "inside [2400,2649]. It is also AT-grounded by containment of the AT+QENG "
        "serving EARFCN on EM7565 (v0x03), EG25-G (v0x10, a 362-record COPS "
        "full-scan sweep) and RM520N-GL (v0x20). Header and list fields are "
        "F3-joined to `lte_ml1_md.c` PBCH decode resp / `lte_ml1_mgr_stm.c` "
        "LTE_CPHY_ACQ_REQ / `lte_ml1_sm_main.c` Acq_cnf prints on v0x10 and "
        "v0x03. Corpus walk (21,979 records / 113 captures): max earfcn 68,911 "
        "(Band 71), none over the 18-bit EARFCN width; earfcn=0 search-mode "
        "records are valid. Truncated payloads return None (registry warning); "
        "a payload longer than the counts imply returns layout_ok=False with "
        "empty lists. QCSuper and SCAT output carries no LTE EARFCN for the "
        "band-sweep captures (the sweep never camps)."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=22,
    fields_parsed=22,
    field_invariants={
        "version": {"enum": list(_B176_VERSIONS_OBSERVED)},
        "earfcn": {"range": (0, 262143)},
    },
)
def parse_0xb176(log_time: int, data: bytes) -> Diag0xB176 | None:
    if len(data) < 1:
        return None
    version = data[0]
    # Layer-1 byte-0 version gate.
    if version not in _B176_VERSIONS_OBSERVED:
        return None
    if len(data) >= 8:
        earfcn = unpack_from('<I', data, 4)[0]
    elif len(data) >= 2:
        earfcn = data[1]
    else:
        earfcn = 0
    if len(data) > 2:
        nonzero = sum(1 for b in data[2:] if b != 0)
        total = max(len(data) - 2, 1)
        density = round(nonzero / total, 2)
    else:
        density = 0.0
    rec = Diag0xB176(
        log_time=log_time,
        version=version,
        earfcn=earfcn,
        data_density=density,
        payload_size=len(data),
        body_raw=data[1:],
    )
    if len(data) < _HDR_LEN:
        # Shorter than the 16 B header -> truncated.
        return None

    hdr, counts = unpack_from('<II', data, 8)
    if version == 0x03:
        band_index = hdr & 0x3F
        tdd = (hdr >> 6) & 1
        acq_failed = (hdr >> 7) & 1
        header_raw = (hdr >> 8) & 0xFFFFF
        n_black = hdr >> 28
        n_pbch = counts & 0x7
        n_cell = (counts >> 3) & 0x1F
        # 6-bit band index: bands 65+ wrap; their EARFCNs are all >= 65536.
        band = band_index + 1 + (64 if earfcn >= 65536 else 0)
    else:
        band_index = hdr & 0xFF
        tdd = (hdr >> 8) & 1
        acq_failed = (hdr >> 9) & 1
        header_raw = hdr >> 10
        n_black = counts & 0x7
        n_pbch = (counts >> 3) & 0x7
        n_cell = (counts >> 6) & 0x1F
        band = band_index + 1
    rec.band_index = band_index
    rec.band = band
    rec.duplex = "TDD" if tdd else "FDD"
    rec.acq_failed = bool(acq_failed)
    rec.header_raw = header_raw
    rec.n_black, rec.n_cell, rec.n_pbch = n_black, n_cell, n_pbch

    want = _HDR_LEN + 4 * n_black + _CELL_LEN * n_cell + _PBCH_LEN * n_pbch
    if want > len(data):
        # The count word declares more lists than the payload holds ->
        # truncated; return None (registry warning).
        return None
    rec.layout_ok = want == len(data)
    if not rec.layout_ok:
        return rec

    off = _HDR_LEN
    rec.black_cell_pcis = list(unpack_from(f'<{n_black}I', data, off))
    off += 4 * n_black
    for _ in range(n_cell):
        sw, pw, fo, _zero, energy = unpack_from('<IHhII', data, off)
        rec.cells.append(B176Cell(
            search_word=sw, pci=pw & 0x1FF, cp_flag=(pw >> 9) & 1,
            freq_offset_raw=fo, energy=energy))
        off += _CELL_LEN
    for _ in range(n_pbch):
        sw, mib, ferr, pw = unpack_from('<IIhH', data, off)
        rec.pbch.append(B176Pbch(
            search_word=sw, mib=mib, freq_err=ferr, pci=pw & 0x1FF,
            info_raw=(pw >> 9) & 0x3F, crc_pass=bool(pw >> 15)))
        off += _PBCH_LEN
    return rec
