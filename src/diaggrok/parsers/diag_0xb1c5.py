"""0xB1C5 — LTE ML1 NR Meas Results Enhanced — unified layered decode (v0x39, T99W640 SDX72).

One grammar decodes every record in the corpus (210/210, 8 captures): a
frequency list, then per-NR-layer blocks of per-cell SS-RSRP/RSRQ, F3-grounded.

Canonical log name ``LOG_LTE_ML1_NR_MEAS_RESULTS_ENHANCED`` — LTE ML1's report
of one **LTE→NR IRAT measurement occasion**: the NR-ARFCN layers LTE was told
to measure (SIB24 in idle, measConfig under EN-DC) and the NR cells found on
each.

Wire grammar (all integers little-endian; exact-length consumption verified on
**210/210** corpus records; there is no separate "Format A / Format B" — a
fixed-offset count at byte 80 is layer 2's ``num_cells`` only when layers 0
and 1 are empty)::

    u8      version            == 0x39
    u8[12]  reserved           all-zero corpus-wide
    u8      num_layers         layer blocks present          (1..4 observed)
    u8      num_freqs          entries in freq_list          (3 or 4 observed)
    u8      pad                0
    u32     freq_list[num_freqs]   NR-ARFCNs configured for measurement
    layer[num_layers]:                                         (20 B + cells)
        u32  nr_arfcn          == freq_list[i] (list order, 630/630)
        u32  reserved          0
        u32  layer_state       RAW: 1 (LTE idle), 2 (EN-DC), 6 (edge-case
                               captures); 0x170 whenever num_cells == 0
        u32  num_cells
        u32  meas_word         RAW; non-zero on EXACTLY ONE layer per record
                               (210/210) — see is_measured_layer
        cell[num_cells]:                                        (36 B)
            u16  pci           (< 1008, 441/441)
            u16  cell_flags    == 1 corpus-wide
            u32  marker        == 0x21 corpus-wide
            i32  rsrp          SS-RSRP, Q7 → /128 dBm
            i32  rsrq          SS-RSRQ, Q7 → /128 dB
            i32  sinr          CANDIDATE SS-SINR, Q16 → /65536 dB
            u32  cell_status   CANDIDATE: 2 = serving NR SCell (see below)
            i32  rsrp_b, rsrq_b, sinr_b   second measurement set; identical
                                          to the first in 441/441 cells
    u32     trailer[num_layers]   all-zero corpus-wide

**Grounding (F3-VERDICT v0x39):**

* **Emitter / procedure — F3 GROUND.** Every record is emitted 0.22–0.61 ms
  after ``nrfw_srch_post_proc.c:1385 "SRCH post-proc on nb_id 0, sample
  status: %d"`` — 93/93 in an LTE-idle camp capture (97 post-procs, 4
  unpaired), 7/8 in an EN-DC capture. The window is
  bracketed by ``lte_LL1_irat_logging "nb_non_intrusive_logging odrx irat"``
  and ``nrfw_rxfe_intf`` RF-group alloc/dealloc, i.e. one LTE-gap NR search.
  The camp capture's LTE side is ``IDLE_CAMPED``, so the code covers idle-mode
  reselection measurement, not only EN-DC reports.
* **F3 is silent on the per-cell values** — no site prints the Q7 levels (a
  value join over 2.5 M F3 records hit only coincidental TCXO args).
* **pci + nr_arfcn — GROUND (SCAT).** SCAT's NR RRC decode names the
  EN-DC SCell ``NR-ARFCN 501390, PCI 260`` in the EN-DC capture — this code's
  ``260@501390`` — and the survey's SCAT NR-MIB list carries ``756@174770``,
  ``596@501390``, ``455@387170``, ``591/389@125530``, every one a pair this
  code reports.
* **rsrp /128 dBm, rsrq /128 dB — GROUND (cross-log).** Matched by
  (PCI, NR-ARFCN) against the SCAT-grounded ``0xB97F`` cells in the same
  EN-DC capture: ΔRSRP −1.6..+2.5 dB (serving 260: +0.1..+1.1), ΔRSRQ ≤ 1.1 dB,
  23 pairs 1–3 s apart. A wrong scale would miss by tens of dB.
* **sinr — CANDIDATE.** No oracle carries it; Q16 is inferred from every value
  being a multiple of 0x8000 (0.5 dB) and the range −11.5..+23.5 dB.
* **cell_status — CANDIDATE.** 2 on the SCAT-confirmed SCell (260, 15/15)
  and on 596 in the bring-up capture (SCell there not independently
  confirmed); 0 on every LTE-idle cell; 0 vs 1 among EN-DC neighbours is not
  separable on the current corpus.
* **is_measured_layer (meas_word != 0) — CANDIDATE, strong.** The flagged
  layer's cells changed vs the previous record in 192/195 cases; unflagged
  layers stayed identical 25/34. The flag rotates 0,1,2,3,0,1,3… in the
  bring-up capture (round-robin gap scheduling). The raw value (0xE100,
  0x62700, 0x12C00) is unnamed.

Single chipset (SDX72, T99W640) and one version byte across the corpus;
a future firmware may ship a different layout under the same 0x39 — the
exact-length check rejects (returns None) rather than mis-parse.

Log name: LOG_LTE_ML1_NR_MEAS_RESULTS_ENHANCED
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_LTE_ML1_B1C5
from diaggrok.registry import register

_B1C5_VERSION = 0x39
_HDR = 16                # version + 12 reserved + num_layers + num_freqs + pad
_LAYER_HDR = 20
_CELL = 36
_MAX_FREQS = 32          # sanity bounds — far above anything observed (4)
_MAX_CELLS = 64


@dataclass
class B1C5Meas:
    """One SS-RSRP / SS-RSRQ / SINR triple (Q7, Q7, Q16)."""
    rsrp_raw: int
    rsrq_raw: int
    sinr_raw: int

    @property
    def rsrp_dbm(self) -> float:
        return self.rsrp_raw / 128

    @property
    def rsrq_db(self) -> float:
        return self.rsrq_raw / 128

    @property
    def sinr_db(self) -> float:
        return self.sinr_raw / 65536

    def to_dict(self) -> dict[str, Any]:
        return {
            'rsrp_dbm': self.rsrp_dbm,
            'rsrp_raw': self.rsrp_raw,
            'rsrq_db': self.rsrq_db,
            'rsrq_raw': self.rsrq_raw,
            'sinr_db': self.sinr_db,      # CANDIDATE (Q16 inferred)
            'sinr_raw': self.sinr_raw,
        }


@dataclass
class B1C5Cell:
    """One 36-byte NR cell entry."""
    pci: int
    cell_flags: int          # == 1 corpus-wide
    marker: int              # == 0x21 corpus-wide
    meas: B1C5Meas
    cell_status: int         # CANDIDATE: 2 = serving NR SCell
    meas_b: B1C5Meas         # == meas in every attested cell

    def to_dict(self) -> dict[str, Any]:
        return {
            'pci': self.pci,
            'cell_flags': self.cell_flags,
            'marker': self.marker,
            'meas': self.meas.to_dict(),
            'cell_status': self.cell_status,
            'meas_b': self.meas_b.to_dict(),
        }


@dataclass
class B1C5Layer:
    """One NR-ARFCN layer block: 20-byte header + num_cells cells."""
    nr_arfcn: int
    reserved: int
    layer_state: int         # RAW (1 idle / 2 EN-DC / 6; 0x170 when empty)
    num_cells: int
    meas_word: int           # RAW; non-zero on exactly one layer per record
    cells: list[B1C5Cell]

    @property
    def is_measured_layer(self) -> bool:
        """CANDIDATE: this layer was (re)measured in this occasion."""
        return self.meas_word != 0

    def to_dict(self) -> dict[str, Any]:
        return {
            'nr_arfcn': self.nr_arfcn,
            'reserved': self.reserved,
            'layer_state': self.layer_state,
            'num_cells': self.num_cells,
            'meas_word': self.meas_word,
            'is_measured_layer': self.is_measured_layer,
            'cells': [c.to_dict() for c in self.cells],
        }


@dataclass
class Diag0xB1C5:
    """0xB1C5 — LTE ML1 NR meas results enhanced (one IRAT meas occasion)."""
    log_time: int
    version: int             # byte[0] (== 0x39)
    reserved: bytes          # bytes 1..12, all-zero corpus-wide
    num_layers: int          # byte[13]
    num_freqs: int           # byte[14]
    pad: int                 # byte[15]
    freq_list: list[int]     # NR-ARFCNs
    layers: list[B1C5Layer]
    trailer: list[int]       # num_layers × u32, all-zero corpus-wide
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0xB1C5',
            'log_time': self.log_time,
            'version': self.version,
            'reserved': self.reserved.hex(),
            'num_layers': self.num_layers,
            'num_freqs': self.num_freqs,
            'pad': self.pad,
            'freq_list': list(self.freq_list),
            'layers': [lay.to_dict() for lay in self.layers],
            'trailer': list(self.trailer),
            'payload_size': self.payload_size,
        }


def _read_meas(data: bytes, off: int) -> B1C5Meas:
    rsrp, rsrq, sinr = unpack_from('<3i', data, off)
    return B1C5Meas(rsrp_raw=rsrp, rsrq_raw=rsrq, sinr_raw=sinr)


@register(
    LOG_LTE_ML1_B1C5, domain="lte-ml1",
    name="0xB1C5",
    description=(
        "LTE ML1 NR Meas Results Enhanced — one LTE→NR IRAT meas occasion: "
        "hdr (num_layers@13, num_freqs@14) + u32 NR-ARFCN freq_list + per-layer "
        "20B hdr {arfcn, state, num_cells, meas_word} + N×36B cells {pci, "
        "SS-RSRP/RSRQ Q7, SINR Q16 (candidate), status} + u32×num_layers "
        "trailer; 210/210 exact. F3 GROUND emitter (nrfw_srch_post_proc 1:1), "
        "pci/arfcn SCAT-GROUND, rsrp/rsrq cross-log GROUND vs 0xB97F"
    ),
    version=2,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Unified layered grammar: num_layers@13, num_freqs@14, freq_list, "
        "per-layer blocks, per-cell 36B; exact-length consumption 210/210 "
        "across 8 T99W640 (SDX72) captures. Emitter F3-grounded: 0xB1C5 "
        "follows nrfw_srch_post_proc.c:1385 by 0.22-0.61 ms, 93/93 in an "
        "LTE-idle camp capture and 7/8 in an EN-DC capture. PCI/NR-ARFCN "
        "match SCAT NR RRC SCell (260@501390) and SCAT NR-MIB pairs. "
        "RSRP/RSRQ /128 match SCAT-grounded 0xB97F cells by (PCI, ARFCN): "
        "ΔRSRP -1.6..+2.5 dB, ΔRSRQ <=1.1 dB over 23 pairs. SINR Q16, "
        "cell_status and is_measured_layer are candidates. Canonical name "
        "LOG_LTE_ML1_NR_MEAS_RESULTS_ENHANCED."
    ),
    issues=(),
    primary_issue=None,
    # Wire fields: hdr {version, reserved, num_layers, num_freqs, pad},
    # freq_list, layer {nr_arfcn, reserved, layer_state, num_cells, meas_word},
    # cell {pci, cell_flags, marker, rsrp, rsrq, sinr, cell_status, rsrp_b,
    # rsrq_b, sinr_b}, trailer — 22, every one exposed by to_dict().
    fields_identified=22,
    fields_parsed=22,
    field_invariants={"version": {"enum": [_B1C5_VERSION]}},
    # WiGLE: per-NR-cell SS-RSRP/RSRQ (cross-log GROUND
    # vs 0xB97F) is `signal`; pci + NR-ARFCN (SCAT-GROUND) need an NR SIB1
    # join for identity (`pci-earfcn-bridge`); an LTE→NR IRAT occasion is
    # `rat-context`. Same roles as its sibling 0xB97F.
    wigle_direct=True,
    wigle_roles=("signal", "pci-earfcn-bridge", "rat-context"),
)
def parse_0xb1c5(log_time: int, data: bytes) -> Diag0xB1C5 | None:
    if len(data) < _HDR:
        return None
    version = data[0]
    # Version gate — hard-reject unknown versions before decode.
    if version != _B1C5_VERSION:
        return None
    num_layers, num_freqs, pad = data[13], data[14], data[15]
    if num_freqs > _MAX_FREQS or num_layers > num_freqs:
        return None
    off = _HDR
    if off + 4 * num_freqs > len(data):
        return None
    freq_list = list(unpack_from(f'<{num_freqs}I', data, off))
    off += 4 * num_freqs

    layers: list[B1C5Layer] = []
    for _ in range(num_layers):
        if off + _LAYER_HDR > len(data):
            return None
        arfcn, reserved, state, num_cells, meas_word = unpack_from('<5I', data, off)
        off += _LAYER_HDR
        if num_cells > _MAX_CELLS or off + _CELL * num_cells > len(data):
            return None
        cells: list[B1C5Cell] = []
        for _ in range(num_cells):
            pci, flags, marker = unpack_from('<HHI', data, off)
            status = unpack_from('<I', data, off + 20)[0]
            cells.append(B1C5Cell(
                pci=pci, cell_flags=flags, marker=marker,
                meas=_read_meas(data, off + 8),
                cell_status=status,
                meas_b=_read_meas(data, off + 24),
            ))
            off += _CELL
        layers.append(B1C5Layer(
            nr_arfcn=arfcn, reserved=reserved, layer_state=state,
            num_cells=num_cells, meas_word=meas_word, cells=cells,
        ))

    # Exact-length check: the trailer is num_layers × u32 and nothing follows.
    # A record that does not consume exactly is a layout this grammar does not
    # know — reject rather than mis-parse.
    if off + 4 * num_layers != len(data):
        return None
    trailer = list(unpack_from(f'<{num_layers}I', data, off))

    return Diag0xB1C5(
        log_time=log_time,
        version=version,
        reserved=bytes(data[1:13]),
        num_layers=num_layers,
        num_freqs=num_freqs,
        pad=pad,
        freq_list=freq_list,
        layers=layers,
        trailer=trailer,
        payload_size=len(data),
    )
