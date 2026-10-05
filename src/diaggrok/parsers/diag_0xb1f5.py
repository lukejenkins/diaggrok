"""LTE ML1 IRAT NR measurement results — per-frequency NR neighbour cells.

SUBJECT MATTER: the LTE anchor's measurements of NR (5G) cells for E-UTRA→NR
reselection and EN-DC B1 reporting. Canonical name
``LOG_LTE_ML1_IRAT_NR_MEAS_RESULTS``. Each record lists NR
frequencies (NR-ARFCN) and, per frequency, the measured cells (PCI) with
SS-RSRP / SS-RSRQ at cell level and per SSB beam. In idle mode the records come
in bursts once per paging cycle: every 1.28 s on the M2000 and EM9190
captures, whose SIB2 ``defaultPagingCycle`` is rf128.

Layouts
-------
All records carry version byte 0x01. **Byte 5 is a minor version that selects
the layout**, so the version byte alone is not enough (a shared version does
not imply a shared format):

Common header (8 B)::

    +0  u8   version          0x01
    +1  u8   hdr_byte1        0x01 on every record (raw)
    +2  u16  hdr_word2        raw; 0 or 1 on most builds, varies on T99W373
    +4  u8   hdr_byte4        0x3B on every record (raw)
    +5  u8   minor_version    0x30 | 0x33 | 0x34
    +6  u16  body_len         == payload length - 4 (enforced)

``minor_version`` 0x30 — **fixed 1,840 B** (SDX55 generation)::

    +8   u32  hdr_word8 (raw)   +12 u8 hdr_byte12 (raw, 0/1)
    +13  u8   num_freqs (0..4)  +14 u16 hdr_word14 (raw)
    +16  4 x 456 B freq slot:
         +0 u32 nr_arfcn  +4 u32 word_a  +8 u32 word_b  +12 u32 word_c
         +16 u32 num_cells (0..4)
         +20 4 x 108 B cell slot:
             +0 u16 pci  +2 u8 num_beams (0..8, 1..5 seen)  +3 u8 cell_byte3
             +4 i32 rsrp (1/128 dBm)  +8 i32 rsrq (1/128 dB)
             +12 8 x 12 B beam: u32 ssb_index, i32 rsrp, i32 rsrq
         +452 u32 meas_word
    Unused freq / cell / beam slots are zero.

``minor_version`` 0x33 / 0x34 — **variable** (SDX62 / SDX65 generation)::

    +8   9 B hdr_pad (zero, except byte 16 = 1 on 16 records)
    +17  u8  num_freqs          +18 u8 num_list_arfcns
    +19  u8  hdr_byte19 (raw)   +20 u32 x num_list_arfcns: list_arfcns
    then num_freqs contiguous blocks:
         u32 nr_arfcn, u32 word_a, u32 word_b, u32 num_cells, u32 meas_word
         num_cells x (20 + 16 * num_beams) B cell:
             u16 pci, u8 num_beams, u8 cell_byte3, u32 cell_flags (0x21),
             i32 rsrp (1/128 dBm), i32 rsrq (1/128 dB), i32 sinr (1/65536 dB)
             num_beams x 16 B beam: u32 ssb_index, i32 rsrp, i32 rsrq, i32 sinr
    then a zero tail: 4 * num_freqs B on minor 0x34; on minor 0x33 32 / 12 /
    16 B for 1 / 2 / 3 freqs (20 records, no rule found).

GROUND v0x01
------------
Corpus: 6,876 records / 77 captures, all v0x01, all parse with 0 invariant
violations (minor 0x30: 4,306; 0x33: 20; 0x34: 2,550). Minor 0x30 on EM9190,
RM500Q, M2000, RXM-G1, SIM8202G-M2, FN980, LV55, FT980m; 0x34 on EM9291,
RM520N (newer firmware), T99W373; 0x33 on M3100 and RM520N (older firmware).

Reference decode (QCSuper on the co-emitted LTE RRC ``0xB0C0``), per capture:

* **NR-ARFCN.** Every ``nr_arfcn`` and ``list_arfcns`` value appears in the same
  capture's RRC ``carrierFreq-r15`` (SIB24 ``carrierFreqListNR-r15`` or
  ``measObjectNR-r15``): 57 of 57 captures that carry one, 0 misses, all three
  minors (17 others have no ``carrierFreq-r15`` on the wire; 2 could not be
  decoded). The ML1 list can be a subset of SIB24 (n71 / n25 dropped on an
  RM520N; its F3 prints ``Prune L2NR FR1 IDLE meas`` at that step).
* **PCI + cell RSRP / RSRQ.** Each NR neighbour in an LTE ``MeasurementReport``
  (``measResultNeighCellListNR-r15``) joined to the latest earlier 0xB1F5
  record carrying that PCI: cell ``rsrp / 128`` is in the reported SS-RSRP
  bin on 35 / 36 and ``rsrq / 128`` in the SS-RSRQ bin on 34 / 36, across all
  three minors (M2000, FT980m: 0x30; M3100: 0x33; RM520N: 0x34). Every join
  0-40 ms apart hits the bin; the 3 misses are 120-140 ms apart and within
  0.5 dB (the value moved).
* **F3: present, silent.** The build-matched RM520N F3 message database has
  no LTE ML1 site that prints a per-cell NR RSRP / PCI; its NR prints are
  RRC-side (``lte_rrc_meas_idle.c``). A source-restricted extract of an
  RM520N-GL NR capture (lte_ml1 + lte_rrc_meas_idle + lte_rrc_irat_to_nr5g,
  963 prints) holds only ML1 state-machine prints.
* **``0x60``: present, silent.** Present in 14 of 76 bearing captures. No event
  carries an NR neighbour PCI or RSRP (T99W373 / EM9190 census:
  ``EVENT_LTE_ML1_SEARCH_IDLE``, ``EVENT_LTE_RRC_PAGING_DRX_CYCLE`` and RRC
  state events only).

Corroborated, not externally grounded:

* ``ssb_index``: 0..5, one beam per cell on 99.9 % of cells (up to 5). Cells
  seen by several modem families report the same modal index: 23 cells with a
  non-zero index agree across families (e.g. PCI 596 on 521310 -> 2 on 8
  families; PCI 266 on 632064 -> 4 on EM9190, EM9291, FN980, RM520N), 3 differ.
  A per-cell beam property that independent chipsets reproduce. No reference
  decoder reports it, so the name stays a strong CANDIDATE.
* The cell value equals beam 0 on 95 % of cells: the cell value is likely
  L3-filtered, the beam value the latest sample.

Not externally grounded, CANDIDATE or raw:

* ``sinr`` (variable layout only): 1/65536 dB fits (always a 0.5 dB step), but
  no reference decoder reports SS-SINR.
* ``meas_word``: non-zero on exactly one frequency in 6,855 of 6,876 records
  (0 in 20, 2 in 1), rotating between frequencies record to record. It marks
  the frequency measured in that occasion. Every value is 19,200 * k +/- 1
  (k = 3, 4, 5, 6, 8, 21), consistent with a duration in 19.2 MHz ticks
  (3..21 ms). A hypothesis, so unnamed.
* **Floor sentinel.** 4 zero-beam cells (minor 0x34) carry raw
  ``(rsrp, rsrq, sinr) == (-156, -43, -23)``, the 3GPP SS-RSRP / SS-RSRQ /
  SS-SINR floors as unscaled dB. The parser flags them ``floor_sentinel``.
* ``word_a`` (0), ``word_b`` (per-frequency constant within a capture),
  ``word_c`` (0), ``cell_flags`` (0x21), the header raw bytes.

``config_word`` (u32@4, an older structural name) and ``body_raw`` remain
available.

Log name: LOG_LTE_ML1_IRAT_NR_MEAS_RESULTS
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

_VERSION = 0x01
_MINOR_FIXED = 0x30
_MINOR_VARIABLE = (0x33, 0x34)
_MINORS = (_MINOR_FIXED,) + _MINOR_VARIABLE

# minor 0x30 fixed-slot geometry.
_FIXED_SIZE = 1840
_FIXED_HDR = 16
_FIXED_FREQ_SLOTS = 4
_FIXED_FREQ_SLOT = 456
_FIXED_CELL_SLOTS = 4
_FIXED_CELL_SLOT = 108
_FIXED_BEAM_SLOTS = 8
_FIXED_BEAM_SLOT = 12
_FIXED_MEAS_WORD_OFF = 452

# minor 0x33 / 0x34 variable geometry.
_VAR_HDR = 20
_VAR_FREQ_HDR = 20
_VAR_CELL_HDR = 20
_VAR_BEAM = 16
_VAR_TAIL_PER_FREQ = 4
_VAR33_TAIL_MAX = 32

_RSRP_SCALE = 128.0      # 1/128 dBm (RRC-grounded)
_RSRQ_SCALE = 128.0      # 1/128 dB (RRC-grounded)
_SINR_SCALE = 65536.0    # 1/65536 dB (CANDIDATE)
# A zero-beam cell may carry the 3GPP SS-RSRP / SS-RSRQ / SS-SINR floors as
# UNSCALED dB: "detected, not measured". Scaling them gives nonsense.
_FLOOR_SENTINEL = (-156, -43, -23)


@dataclass
class B1F5Beam:
    ssb_index: int
    rsrp_raw: int
    rsrq_raw: int
    sinr_raw: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "ssb_index": self.ssb_index,
            "rsrp_dbm": self.rsrp_raw / _RSRP_SCALE,
            "rsrq_db": self.rsrq_raw / _RSRQ_SCALE,
        }
        if self.sinr_raw is not None:
            d["sinr_db"] = self.sinr_raw / _SINR_SCALE
        return d


@dataclass
class B1F5Cell:
    pci: int
    num_beams: int
    cell_byte3: int
    rsrp_raw: int
    rsrq_raw: int
    sinr_raw: int | None = None
    cell_flags: int | None = None
    beams: list[B1F5Beam] = field(default_factory=list)

    @property
    def floor_sentinel(self) -> bool:
        """True when the cell carries the unscaled 3GPP floors (not measured)."""
        return (self.rsrp_raw, self.rsrq_raw, self.sinr_raw) == _FLOOR_SENTINEL

    @property
    def rsrp_dbm(self) -> float:
        return self.rsrp_raw / _RSRP_SCALE

    @property
    def rsrq_db(self) -> float:
        return self.rsrq_raw / _RSRQ_SCALE

    @property
    def sinr_db(self) -> float | None:
        return None if self.sinr_raw is None else self.sinr_raw / _SINR_SCALE

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "pci": self.pci,
            "num_beams": self.num_beams,
            "cell_byte3": self.cell_byte3,
            "rsrp_dbm": self.rsrp_dbm,
            "rsrq_db": self.rsrq_db,
        }
        if self.sinr_raw is not None:
            d["sinr_db"] = self.sinr_db
        if self.cell_flags is not None:
            d["cell_flags"] = self.cell_flags
        if self.floor_sentinel:
            d["floor_sentinel"] = True
        d["beams"] = [b.to_dict() for b in self.beams]
        return d


@dataclass
class B1F5Freq:
    nr_arfcn: int
    word_a: int
    word_b: int
    word_c: int | None
    num_cells: int
    meas_word: int
    cells: list[B1F5Cell] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "nr_arfcn": self.nr_arfcn,
            "word_a": self.word_a,
            "word_b": self.word_b,
        }
        if self.word_c is not None:
            d["word_c"] = self.word_c
        d["num_cells"] = self.num_cells
        d["meas_word"] = self.meas_word
        d["cells"] = [c.to_dict() for c in self.cells]
        return d


@dataclass
class Diag0xB1F5:
    """LTE ML1 IRAT NR measurement results."""

    log_time: int
    version: int
    hdr_byte1: int
    hdr_word2: int
    hdr_byte4: int
    minor_version: int
    body_len: int
    layout: str
    num_freqs: int
    list_arfcns: tuple[int, ...]
    freqs: list[B1F5Freq]
    hdr_raw: bytes
    tail_raw: bytes
    body_raw: bytes
    payload_size: int

    @property
    def config_word(self) -> int:
        """Legacy name for u32@4 (hdr_byte4 | minor_version << 8 | body_len << 16)."""
        return self.hdr_byte4 | (self.minor_version << 8) | (self.body_len << 16)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB1F5",
            "log_time": self.log_time,
            "version": self.version,
            "hdr_byte1": self.hdr_byte1,
            "hdr_word2": self.hdr_word2,
            "hdr_byte4": self.hdr_byte4,
            "minor_version": self.minor_version,
            "body_len": self.body_len,
            "layout": self.layout,
            "num_freqs": self.num_freqs,
            "list_arfcns": list(self.list_arfcns),
            "freqs": [f.to_dict() for f in self.freqs],
            "hdr_raw": self.hdr_raw.hex(),
            "tail_raw": self.tail_raw.hex(),
            "config_word": self.config_word,
            "payload_size": self.payload_size,
        }


def _parse_fixed(data: bytes) -> tuple[int, list[B1F5Freq]] | None:
    if len(data) != _FIXED_SIZE:
        return None
    num_freqs = data[13]
    if num_freqs > _FIXED_FREQ_SLOTS:
        return None
    freqs: list[B1F5Freq] = []
    for i in range(num_freqs):
        base = _FIXED_HDR + _FIXED_FREQ_SLOT * i
        arfcn, word_a, word_b, word_c, num_cells = unpack_from("<5I", data, base)
        if num_cells > _FIXED_CELL_SLOTS:
            return None
        (meas_word,) = unpack_from("<I", data, base + _FIXED_MEAS_WORD_OFF)
        cells: list[B1F5Cell] = []
        for j in range(num_cells):
            cb = base + 20 + _FIXED_CELL_SLOT * j
            pci, num_beams, byte3 = unpack_from("<HBB", data, cb)
            if num_beams > _FIXED_BEAM_SLOTS:
                return None
            rsrp, rsrq = unpack_from("<ii", data, cb + 4)
            beams = []
            for k in range(num_beams):
                ssb, brsrp, brsrq = unpack_from("<Iii", data, cb + 12 + _FIXED_BEAM_SLOT * k)
                beams.append(B1F5Beam(ssb, brsrp, brsrq))
            cells.append(B1F5Cell(pci, num_beams, byte3, rsrp, rsrq, beams=beams))
        freqs.append(B1F5Freq(arfcn, word_a, word_b, word_c, num_cells, meas_word, cells))
    return num_freqs, freqs


def _parse_variable(data: bytes, minor: int) -> tuple[int, tuple[int, ...], list[B1F5Freq], bytes] | None:
    if len(data) < _VAR_HDR:
        return None
    num_freqs = data[17]
    num_list = data[18]
    off = _VAR_HDR + 4 * num_list
    if off > len(data):
        return None
    list_arfcns = unpack_from(f"<{num_list}I", data, _VAR_HDR)
    freqs: list[B1F5Freq] = []
    for _ in range(num_freqs):
        if off + _VAR_FREQ_HDR > len(data):
            return None
        arfcn, word_a, word_b, num_cells, meas_word = unpack_from("<5I", data, off)
        off += _VAR_FREQ_HDR
        cells: list[B1F5Cell] = []
        for _ in range(num_cells):
            if off + _VAR_CELL_HDR > len(data):
                return None
            pci, num_beams, byte3 = unpack_from("<HBB", data, off)
            flags, rsrp, rsrq, sinr = unpack_from("<Iiii", data, off + 4)
            off += _VAR_CELL_HDR
            if off + _VAR_BEAM * num_beams > len(data):
                return None
            beams = []
            for _ in range(num_beams):
                ssb, brsrp, brsrq, bsinr = unpack_from("<Iiii", data, off)
                beams.append(B1F5Beam(ssb, brsrp, brsrq, bsinr))
                off += _VAR_BEAM
            cells.append(B1F5Cell(pci, num_beams, byte3, rsrp, rsrq, sinr, flags, beams))
        freqs.append(B1F5Freq(arfcn, word_a, word_b, None, num_cells, meas_word, cells))
    tail = bytes(data[off:])
    # Fail loudly. minor 0x34: exactly a 4-B-per-freq tail. minor 0x33:
    # the tail is zero but its length (32 / 12 / 16 B for 1 / 2 / 3 freqs on the
    # 20 corpus records) follows no known rule, so accept a zero, 4-B-aligned tail
    # of at most _VAR33_TAIL_MAX bytes. A misframed parse leaves non-zero bytes.
    if minor == 0x34:
        if len(tail) != _VAR_TAIL_PER_FREQ * num_freqs:
            return None
    elif len(tail) % 4 or len(tail) > _VAR33_TAIL_MAX or any(tail):
        return None
    return num_freqs, tuple(list_arfcns), freqs, tail


@register(
    0xB1F5,
    name="0xB1F5",
    description=(
        "LTE ML1 IRAT NR measurement results — per-frequency NR neighbour "
        "cells (NR-ARFCN, PCI, SS-RSRP/RSRQ at cell and SSB-beam level). "
        "version=1; byte 5 minor selects the layout: 0x30 fixed 1840 B "
        "(4 freq x 4 cell x 8 beam slots), 0x33/0x34 variable. NR-ARFCN "
        "matches RRC SIB24/measObjectNR carrierFreq-r15 (57/57 captures); "
        "cell RSRP/RSRQ (1/128) match LTE MeasurementReport NR bins 35/36, "
        "34/36."
    ),
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "GROUND v0x01 against QCSuper's decode of the co-emitted LTE RRC "
        "0xB0C0. NR-ARFCN (freq blocks + ML1 list) is a subset of the "
        "capture's carrierFreq-r15 (SIB24 / measObjectNR) in 57/57 captures "
        "that carry one, all three minors. PCI + cell rsrp/128 and rsrq/128 "
        "fall in the measResultNeighCellListNR-r15 SS-RSRP / SS-RSRQ bins on "
        "35/36 and 34/36, all three minors (misses 120-140 ms apart, within "
        "0.5 dB). F3 silent: the build-matched RM520N F3 database has no ML1 "
        "per-cell NR print; 0x60 silent. ssb_index corroborated cross-device "
        "(23 cells agree across modem families, 3 differ). SINR scale, "
        "meas_word / word_a..c kept CANDIDATE / raw. 6,876 records / 77 "
        "captures parse, 0 invariant violations."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    # No NR global cell id: NR PCI + NR-ARFCN + SS-RSRP join to an identity
    # source (NR SIB1 / RRC) by PCI and ARFCN, and say which NR carriers exist.
    wigle_direct=False,
    wigle_roles=("pci-earfcn-bridge", "rat-context"),
    fields_identified=12,
    fields_parsed=30,
    field_invariants={
        "version": {"enum": [_VERSION]},
        "minor_version": {"enum": list(_MINORS)},
    },
)
def parse_0xb1f5(log_time: int, data: bytes) -> Diag0xB1F5 | None:
    if len(data) < 8 or data[0] != _VERSION:
        return None
    minor = data[5]
    if minor not in _MINORS:
        return None
    (hdr_word2,) = unpack_from("<H", data, 2)
    (body_len,) = unpack_from("<H", data, 6)
    if body_len != len(data) - 4:
        return None
    if minor == _MINOR_FIXED:
        fixed = _parse_fixed(data)
        if fixed is None:
            return None
        num_freqs, freqs = fixed
        layout, list_arfcns, hdr_end, tail = "fixed", (), _FIXED_HDR, b""
    else:
        var = _parse_variable(data, minor)
        if var is None:
            return None
        num_freqs, list_arfcns, freqs, tail = var
        layout, hdr_end = "variable", _VAR_HDR
    return Diag0xB1F5(
        log_time=log_time,
        version=data[0],
        hdr_byte1=data[1],
        hdr_word2=hdr_word2,
        hdr_byte4=data[4],
        minor_version=minor,
        body_len=body_len,
        layout=layout,
        num_freqs=num_freqs,
        list_arfcns=list_arfcns,
        freqs=freqs,
        hdr_raw=bytes(data[8:hdr_end]),
        tail_raw=tail,
        body_raw=bytes(data[1:]),
        payload_size=len(data),
    )
