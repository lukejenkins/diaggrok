"""LTE ML1 Connected-Mode Neighbor Cell Measurement parser (0xB195).

0xB195 -- LTE ML1 Connected-Mode Neighbor Cell Measurement Request/Response
    Per-cell connected-mode neighbor cell measurements while the UE is in
    RRC_CONNECTED. Emitted during the L1 measurement gap so the UE can
    measure neighbor cells without losing the serving link.

    The connected-mode variant is the primary source for handover-quality
    neighbor data during active data sessions — complements 0xB192 (idle
    mode) and 0xB193 (serving cell).

Payload structure (version 1, MDM9207 / SDX-class subpacket variant
v3 request + v4 response, 100 bytes total):

    [0]      u8   version (1)
    [1]      u8   num_subpackets (2)
    [2:4]    u16  measurement counter / SFN

    Subpacket 0 (id=30, ver=3, size=32) -- Request/Config:
        [0:4]    u32  EARFCN (low 18 bits)
        [4:8]    u32  config flags / cell count hint
        [8:12]   u32  serving PCI bitfield
        [12:16]  u32  scheduling/timing
        [16:20]  u32  rotation timing
        [20:24]  u32  rotation timing (mirror)
        [24:28]  u32  reserved (zeros)

    Subpacket 1 (id=31, ver=4, size=64) -- Response/Measurement:
        [0:4]    u32  EARFCN (low 18 bits)
        [4:6]    u16  num_cells_word: bits 0-6 = num_cells, bits 7-15 a
                      separate, unresolved field (zero on sp.v4; live on
                      sp.v40/56/57 — see "Layouts" below)
        [6:8]    u16  sf_counter (CANDIDATE): zero on sp.v4; live on
                      sp.v40 (max 639) and sp.v56/57 (0..5119, exactly the
                      SFN*10+subframe range); absent on sp.v3

        Per-cell record (52 bytes each — byte-identical to 0xB192):
            [0:4]    u32  PCI (low 9 bits); bits 9-31 exposed as pci_flags
                          (bit 25 set on ~46% of sp.v57 cells, never on
                          v3/v4/v40/v56; semantics unresolved — not intra/inter)
            [4:8]    u32  energy0  (per-Rx integrated energy ~4-5e6)
            [8:12]   u32  energy1  (per-Rx integrated energy; RSRP-tracking)
            [12:16]  u32  energy2  (integrated energy; RSRP-tracking)
            [16:20]  u32  energy_wide0 (wide-scale accumulator ~1.5e8)
            [20:24]  u32  energy_wide1 (wide-scale accumulator ~1.9e8)
            [24:26]  u16  meas_index (0..~1166 counter — not RSRP; a -raw/10
                          reading of it gives -32..-58 dBm, far from QENG truth)
            [28:32]  u32  energy_filt (filtered energy ~1.2e6)
            [36:38]  u16  aux0 (unresolved; not RSRQ Rx0)
            [38:40]  u16  aux1 (unresolved; not RSRQ Rx1)
            [40:44]  u32  timing (request-echoed; +40 == +44 always)

        No calibrated dBm exists in this packet: the energy words are
        AGC-flattened, so rsrp/rsrq_rx0/rsrq_rx1 are None. pci/earfcn are the
        verified fields.

Reverse-engineered from an EG25-G (MDM9607) DLF capture (46 records, all 100
bytes, all single-cell on EARFCN 5035 / PCI 404).

The per-cell record layout is byte-compatible with 0xB192's per-cell
record at the PCI/RSRP/RSRQ field offsets, so this parser shares the
extraction primitives with the idle-mode neighbor parser.

**Layouts (response subpacket version, the sp.vN layout axis).**
Five response versions share ONE 52-byte cell. Four of them share one 8-byte
carrier header; sp.v3 has a 4-byte one (earfcn u16 @0, num_cells u16 @2, the
shape 0xB192 ver=2 has on the MDM9200):

    sp.v3   MDM9625 (Foxconn T77W595)                          — request sp.v2
            (request header 8 B, not 12)
    sp.v4   MDM9207 / SDX24 / SDX55 (EG25-G, LM960, EM160R-GL) — request sp.v3
    sp.v40  SDX20 / SDX55 (LV55, RM500Q)                       — request sp.v40
    sp.v56  SDX55 (Inseego M3100)                              — request sp.v56
    sp.v57  SDX62 (RM520N-GL)                                  — request sp.v56

What was once read as "v40 puts num_cells elsewhere" (the old ``> 32 ->
body-size`` heuristic) is the num_cells_word bitfield: ``word & 0x7F`` equals
the body-derived cell count on 100% of records on all four layouts (v4 867, v40 213, v56 770, v57 2,843 records), and bits 7-15
carry a different, unresolved value. The request subpacket (id=30, 12-byte
header + 16 B/cell) echoes each response cell's PCI in order (853/853 v56,
4,590/4,590 v57, 1,372/1,372 v4, 331/331 v40). Padding at cell +26/+32/+48 is
zero and +40 == +44 on every cell of v4/v56/v57.

Identity grounding per layout (F3):
    sp.v3: every decoded (earfcn, pci) pair — 4 pairs, 67/67 entries — is
        named by the firmware's own cell-database print, 0x79 plaintext F3
        lte_ml1_cdb.c:1807 "CDB get status [ LTE: pci X fcn Y ]"
        (a T77W595 attach capture, 49 records).
    sp.v56: (earfcn, pci) ⊂ the RRC measObject carriers {975, 5230, 55342,
        55540, 66536} decoded by the qcsuper black-box oracle, and PCI 221 is
        the neighbour the UE names in its RRC MeasurementReports
        (an M3100 survey capture, 770 records).
    sp.v57: 4,566/4,590 entries (99.5%) contained in the co-captured
        AT+QENG neighbour/serving lists; the 24 misses are 3 transient weak
        cells (an RM520N-GL survey capture).
    F3: lte_LL1_meas_ncell.c NB_MEAS max_SE/max_SNE prints co-emit but do not
        byte-match any cell energy word (0/853 on v56) — the print is the
        per-search pick, upstream of the accumulators. No F3 site names a
        connected-mode neighbour PCI on these builds.

A public field reference (Techplayon) lists these field names for the log;
the energy-word decode above does not yet map onto them:
    0xB195 — LTE ML1 Connected Neighbor Meas Request/Response
        Request: earfcn, serving_cell_index, measurement_gap_period_ms,
            measurement_gap_mask, neighbor_pci, cyclic_prefix_type,
            frame_boundary_offset, cir_timing_adjustment_samples
        Response: rsrp_rx0_dbm, rsrp_rx1_dbm, rsrp_combined_dbm,
            rsrq_rx0_db, rsrq_rx1_db, rsrq_instantaneous_db,
            rssi_rx0_dbm, rssi_rx1_dbm

Log name: LOG_LTE_ML1_CONNECTED_MODE_NEIGHBOR_MEAS_REQ_RESP
Also known as: LOG_LTE_ML1_CONNECTED_NEIGHBOR_MEAS_REQUEST_RESPONSE
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_LTE_ML1_CONNECTED_NEIGHBOR_MEAS
from diaggrok.registry import register


_REQUEST_SP_ID = 30
_RESPONSE_SP_ID = 31
_RESPONSE_SP_VERSION = 4
_CELL_RECORD_SIZE = 52
_CARRIER_HEADER_SIZE = 8
# sp.v3 (MDM9625 / T77W595) uses the 4-byte carrier header 0xB192 ver=2 has on
# the MDM9200: earfcn u16 @0, num_cells u16 @2. The 52-byte cell is unchanged.
_RESPONSE_SP_VERSION_SHORT_HDR = 3
_CARRIER_HEADER_SIZE_SHORT = 4


@dataclass
class LteMl1ConnectedNeighborEntry:
    """A single connected-mode neighbour cell measurement (response sp id=31).

    Byte-identical per-cell layout to 0xB192's idle-mode ``LteMl1NeighborCellEntry``.
    All per-cell energy/timing words are exposed as raw integers, and the signal
    fields are ``None``.

    Signal semantics (shared with 0xB192's byte-identical cell): the per-cell
    quantities are **AGC-flattened integrated-energy accumulators, not
    calibrated dBm**, so ``rsrp`` / ``rsrq_rx0`` / ``rsrq_rx1`` are ``None`` — no
    capture-stable energy->dBm law exists. Cell offset +24 is ``meas_index`` (a
    0..~1166 counter), not RSRP: a -raw/10 reading of it gives -32..-58 dBm where
    QENG reports -104..-119. The raw words are exposed so the measurement data is
    fully extracted; a consumer holding a per-band reference power can convert
    them. ``pci`` / ``earfcn`` are the verified fields (multi-value QENG/QMI
    containment, cross-modem).
    """
    pci: int
    earfcn: int
    # API-compat signal fields — None: no calibrated dBm in the packet.
    rsrp: float | None
    rsrq_rx0: float | None
    rsrq_rx1: float | None
    # Raw per-cell measurement words (usable integers, byte-identical to 0xB192):
    energy0: int         # +4  u32 per-Rx integrated energy (~4-5e6)
    energy1: int         # +8  u32 per-Rx integrated energy (~4-5e6; RSRP-tracking)
    energy2: int         # +12 u32 integrated energy (~4-5e6; RSRP-tracking)
    energy_wide0: int    # +16 u32 wide-scale energy accumulator (~1.5e8)
    energy_wide1: int    # +20 u32 wide-scale energy accumulator (~1.9e8)
    meas_index: int      # +24 u16 measurement index/counter (0..~1166; not RSRP)
    energy_filt: int     # +28 u32 filtered energy (~1.2e6)
    aux0: int            # +36 u16 small field (semantics unresolved; not rsrq_rx0)
    aux1: int            # +38 u16 small field (semantics unresolved; not rsrq_rx1)
    timing: int          # +40 u32 request-echoed timing (+40 == +44 always)
    # +0 u32 bits 9-31 (the word PCI is masked from). Bit 25 (0x10000 here) is
    # set on ~46% of sp.v57 cells and never on v3/v4/v40/v56; unresolved.
    pci_flags: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            'pci': self.pci,
            'pci_flags': self.pci_flags,
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
class Diag0xB195:
    """LTE ML1 Connected-Mode Neighbor Cell Measurement (0xB195)."""
    log_time: int
    version: int
    earfcn: int
    num_cells: int
    entries: list[LteMl1ConnectedNeighborEntry] = field(default_factory=list)
    # Response (id=31) subpacket version — 4 (MDM9207) / 40 (SDX20/SDX55). It
    # moves num_cells, a layout axis; exposed so the sweep can split on it.
    sp_version: int | None = None
    # Carrier header +4 u16 in full: bits 0-6 are num_cells, bits 7-15 an
    # unresolved field (zero on sp.v4, live on v40/56/57).
    num_cells_word: int | None = None
    # Carrier header +6 u16. CANDIDATE subframe counter: 0 on sp.v4, live on
    # sp.v40 (max 639) and sp.v56/57 (0..5119, the SFN*10+subframe range); None
    # on sp.v3 (no such word). Not F3-labelled.
    sf_counter: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0xB195',
            'log_time': self.log_time,
            'version': self.version,
            'sp_version': self.sp_version,
            'earfcn': self.earfcn,
            'num_cells': self.num_cells,
            'num_cells_word': self.num_cells_word,
            'sf_counter': self.sf_counter,
            'entries': [e.to_dict() for e in self.entries],
        }


# Ground-truth recipe — EC25/EG25 family (MDM9607) LTE connected-mode neighbor
# measurement. The decoded per-cell PCI/EARFCN map 1:1 to Quectel
# AT+QENG="neighbourcell" columns; the QENG RSRP/RSRQ columns have no decoded
# counterpart (the energy words are not dBm). cond="connected": the connected-mode
# neighbor log only fires while the UE is RRC_CONNECTED (active data session),
# so the capture must drive a sustained download while polling QENG.

@register(LOG_LTE_ML1_CONNECTED_NEIGHBOR_MEAS, domain="lte-signal",
    name="0xB195",
    description="Connected-mode neighbor cell meas 0xB195 — version-dispatched response sp31 {4,40}, full 52B cell record shared with 0xB192 (PCI/EARFCN + per-Rx energy/timing words); rsrp/rsrq None (energy, not dBm)",
    version=8,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Layout from an EG25-G (MDM9607) DLF capture (46 records, 100B "
        "single-cell), validated by a corpus walk (9 captures, 202 records): "
        "outer version=0x01 on 100% of records, sizes 100B (1 cell, 35%), "
        "168B (2 cells, 29%), 236B (3 cells, 22%), 304B (4 cells, 11%), "
        "372B (5 cells, 2%) — +68B per added cell. num_cells is computed from "
        "body size on the v40 SP variant (LV55 SDX55). The 52B cell record is "
        "byte-identical to 0xB192's; PCI/EARFCN are verified by containment "
        "against QMI (LV55) and QENG (RM520N-GL) neighbour lists in their "
        "captures. The per-cell energy words are AGC-flattened accumulators, "
        "not dBm, so rsrp/rsrq are None and the raw words are exposed. "
        "Response layouts sp.v4/v40/v56/v57 share the header and cell "
        "(sp.v3, MDM9625, has a 4-byte header and the same cell); "
        "num_cells = carrier word & 0x7F on 100% of records of all four, "
        "and the request subpacket echoes every response PCI. sp.v56 "
        "identity grounded against the qcsuper RRC measObject/"
        "MeasurementReport set (M3100), sp.v57 against AT+QENG (99.5%, "
        "RM520N-GL), sp.v3 against F3 lte_ml1_cdb.c cell-database prints "
        "(67/67, T77W595)."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    # Header: version, earfcn, num_cells, sp_version, num_cells_word,
    # sf_counter (6) + per-cell pci, pci_flags + 11 raw energy/timing words
    # (13) = 19 parsed; +3 identified-but-None signal fields (rsrp, rsrq_rx0,
    # rsrq_rx1 — energy, not dBm) = 22 identified.
    fields_identified=22, fields_parsed=19,
    field_invariants={
        "version": {"enum": [0x01]},
        # Response subpacket version (layout axis): 3 = MDM9625 (4-byte
        # carrier header), 4 = MDM9207/SDX24/SDX55,
        # 40 = SDX20/SDX55, 56 = SDX55 (M3100), 57 = SDX62 (RM520N-GL). One
        # header + cell layout across all four. Pinned so an unseen one is
        # loud (the record is still returned).
        "sp_version": {"enum": [3, 4, 40, 56, 57]},
    },
    # F3-sweep layout axis: byte 0 is 0x01 on every record, the
    # response subpacket version picks the carrier header -> (0xB195, v0x01, sp.vN).
    layout_axes={"sp": "sp_version"},
    wigle_direct=True,
    wigle_roles=("signal", "pci-earfcn-bridge", "rat-context"),
)
def parse_0xb195(
    log_time: int, data: bytes
) -> Diag0xB195 | None:
    """Parse 0xB195 -- LTE ML1 Connected-Mode Neighbor Cell Measurement.

    Walks subpackets to find the response subpacket (id=31), extracts per-cell
    PCI, EARFCN, and the raw per-Rx energy/timing words (byte-identical to
    0xB192). The response versions 4/40/56/57 share one carrier header and
    one cell layout.

    Returns ``None`` for malformed payloads.
    """
    if len(data) < 8:
        return None

    version = data[0]
    if version != 1:
        return None
    num_subpackets = data[1]
    if num_subpackets < 1:
        return None

    # Walk subpackets to find the response subpacket (id=31)
    offset = 4  # skip outer header (version + num_sp + counter)

    for _ in range(num_subpackets):
        if offset + 4 > len(data):
            return None

        sp_id = data[offset]
        sp_ver = data[offset + 1]
        sp_size = unpack_from('<H', data, offset + 2)[0]

        if sp_size < 4 or offset + sp_size > len(data):
            return None

        if sp_id == _RESPONSE_SP_ID:
            sp_data = data[offset + 4:offset + sp_size]
            return _parse_response_subpacket(log_time, version, sp_data, sp_ver)

        offset += sp_size

    return None


def _parse_response_subpacket(
    log_time: int, version: int, sp: bytes, sp_ver: int = 4
) -> Diag0xB195 | None:
    """Parse the response subpacket data (id=31).

    One layout for sp versions 4/40/56/57: num_cells is the low 7 bits of the
    u16 at +4 (the high bits are a separate field), clamped to what the body
    holds.
    """
    if sp_ver == _RESPONSE_SP_VERSION_SHORT_HDR:
        hdr = _CARRIER_HEADER_SIZE_SHORT
        if len(sp) < hdr:
            return None
        earfcn, num_cells_word = unpack_from('<HH', sp, 0)
        sf_counter = None
    else:
        hdr = _CARRIER_HEADER_SIZE
        if len(sp) < hdr:
            return None
        earfcn = unpack_from('<I', sp, 0)[0] & 0x3FFFF
        num_cells_word = unpack_from('<H', sp, 4)[0]
        sf_counter = unpack_from('<H', sp, 6)[0]

    if earfcn > 262143:
        return None

    # Bits 0-6 are the cell count on every layout (== the body-derived count on
    # 100% of corpus records, v4/v40/v56/v57); bits 7-15 are another field.
    # Clamp to what the body actually holds so a short record cannot over-read.
    body_cells = (len(sp) - hdr) // _CELL_RECORD_SIZE
    num_cells = min(num_cells_word & 0x7F, body_cells)

    entries: list[LteMl1ConnectedNeighborEntry] = []

    for i in range(num_cells):
        cell_offset = hdr + i * _CELL_RECORD_SIZE
        if cell_offset + _CELL_RECORD_SIZE > len(sp):
            break

        co = cell_offset
        # pci: low 9 bits of the u32 at cell +0 (byte-identical to 0xB192).
        pci_word = unpack_from('<I', sp, co)[0]
        pci = pci_word & 0x1FF

        # rsrp / rsrq_rx0 / rsrq_rx1 are None: the per-cell words are
        # AGC-flattened linear-energy accumulators with no capture-stable
        # energy->dBm law, and +24 is meas_index (a counter), not RSRP (read as
        # RSRP it gives -32..-58 dBm vs QENG truth -104..-119). The raw
        # energy/timing words are exposed below so the measurement data is fully
        # extracted; a consumer holding a per-band reference power can convert them.
        # All offsets are byte-identical to 0xB192's response cell.
        entries.append(LteMl1ConnectedNeighborEntry(
            pci=pci, earfcn=earfcn,
            rsrp=None, rsrq_rx0=None, rsrq_rx1=None,
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
            pci_flags=pci_word >> 9,
        ))

    return Diag0xB195(
        log_time=log_time,
        version=version,
        earfcn=earfcn,
        num_cells=num_cells,
        entries=entries,
        sp_version=sp_ver,
        num_cells_word=num_cells_word,
        sf_counter=sf_counter,
    )
