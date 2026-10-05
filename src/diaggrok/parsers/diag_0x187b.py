"""LTE ML1 Neighbor Cell Measurements (0x187B).

28-byte records, version 2. Header layout (corpus-validated over 826,205
records / 172 captures):
[0]=version, [1:4]=seq_counter (24b LE), [4:8]=reserved, [9]=flags,
[10:12]=marker 0x200c, [12]=num_cells, [13:17]=bitpacked cell when
num_cells>0, [20:22]=sentinel 0xFEFF, [22:28]=reserved.

Per-cell bitpack: PCI(9b) | RSSI(11b) | RSRP(12b) in a u32 field.

**The inline cell bitpack is empty in practice.** Bytes [13:20] read zero on
every corpus record, including every num_cells=1 record, on stationary and
mobile (drive) captures alike. ``num_cells`` takes only {0, 1} and behaves as
a status flag, not a count; ``cells`` is therefore always empty on real
records. num_cells=1 announces an LTE-idle -> WCDMA IRAT search: the
co-emitted 0x4179 (~100 ms later) is the WCDMA PN search results log
(UARFCN + PSC + PN peaks), not an LTE neighbour carrier.

RSRP/RSSI field semantics: like the 0xB192 sibling, the RSRP/RSSI words
here are LTE LL1 neighbour quantities = **SE / SNE linear energy**, NOT dBm
power (F3 `lte_LL1_meas_ncell.c` NB_MEAS, max_SE up to 2.08e8 / max_SNE up
to 1.3e8 — large always-positive energy integers). The `RSRP = -180 +
raw*0.0625` dBm scale used by the cell filter below therefore decodes an
energy word and cannot be right without an energy→dBm reference conversion.
This is moot while the bitpack is empty.

Bit width: the RSRP word here is a **12-bit** bitfield (≤ 4095) and RSSI an
**11-bit** field (≤ 2047), but the NB_MEAS raw energy spans up to ~1.36e9
(~31 bits). These narrow fields physically cannot hold the raw SE/SNE
accumulator, so — exactly as for the 0xB192 u16 sibling — any value stored
here would be a firmware-converted/compressed form, never the raw energy
word. Grounding would need the full-width NB_MEAS F3 oracle + a populated,
varied-signal capture pairing the stored word with truth dBm.
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_LTE_ML1_NEIGHBOR_MEAS
from diaggrok.registry import register

# Ground-truth capture recipe. ONE version: v=0x02 (corpus-wide).
#
# 0x187B carries a DEFINED per-cell bitpack (PCI 9b | RSSI 11b | RSRP 12b in a
# u32) that a Quectel modem could ground field-by-field via the vendor
# neighbour list AT+QENG="neighbourcell". But the inline cell bitpack at
# offset 13 reads zero on every corpus record (see the module docstring), so
# the decode is currently unreachable: real records emit an empty `cells` list.
# The recipe is a falsifiable design with two hypotheses, tested against a
# paired QENG poll on the RM520N-GL (it has vendor QENG, is a corpus-attested
# v=0x02 emitter, and reports LTE neighbours when anchored on LTE):
#   (H1) does any firmware/condition populate the [13:20] cell bitpack at all?
#        If a populated record appears, ground its PCI/RSSI/RSRP against QENG.
#        A SIM8202 (SDX55) drive capture — 31,179 records with genuine
#        reselection — carries 32 num_cells=1 records, every one with
#        [13:20] all zero, so mobility alone does not populate it.
#   (H2) is `num_cells` a neighbour count or a status flag? Compare it to the
#        number of QENG neighbour rows captured at the same instant.
# Sibling idle-mode 0xB192 (already recipe'd) DOES decode populated idle
# neighbours — capture both in one session and use 0xB192 as the positive
# control for what QENG agreement should look like.
#
# Field-map honesty caveats:
#  * cond:idle — populated records (if they exist) require active reselection
#    evaluation (idle, camped, moving); a stationary strong-serving capture
#    emits only the empty num_cells=0 form (marker 0x0c20, >99.98%).
#  * RSRP is stored as rsrp_raw (dBm = -180 + raw*0.0625) — convert before
#    comparing to QENG's integer-dBm neighbour RSRP.
#  * RSSI is rssi_raw with no confirmed dBm scale; QENG neighbour rows carry no
#    per-neighbour RSSI column, so AT can only loosely bound it (weakest field).

# Constants for the cross-corpus marker + sentinel invariants.
#
# Marker @ [10:12] (u16 LE): bytes are `0x20 0x0c` → LE u16 = 0x0c20. The
# corpus also shows a minority at `0x21 0x4c` → LE u16 = 0x4c21 (~0.1% of
# records, co-occurs with non-zero flags_byte). The 0x4c high byte is
# cross-vendor (LM960, SIM8202G-M2 and FT980m captures); only its frequency is
# a minority. Both markers are real firmware-emitted values; the enum below
# accepts both.
_MARKER_DOMINANT = 0x0c20  # observed when num_cells == 0 (>99.98%)
_MARKER_NUMCELLS_SET = 0x0c21  # observed when num_cells == 1 (cross-vendor: lm960 + fn980m)
_MARKER_LM960 = 0x4c21  # 0x4c21 cross-vendor minority (lm960 + simcom_sim8202gm2 + ft980m); co-occurs with non-zero flags_byte. Const name kept for back-compat.
_OBSERVED_MARKERS = (_MARKER_DOMINANT, _MARKER_NUMCELLS_SET, _MARKER_LM960)
# Sentinel @ [20:22] (u16 LE): bytes are `0xFE 0xFF` → LE u16 = 0xFFFE.
# 100% invariant across the corpus.
_SENTINEL = 0xFFFE
# Fixed record size (826,205 corpus records, all 28 B). Shorter = truncated.
_RECORD_LEN = 28


@dataclass
class Diag0x187B:
    log_time: int
    version: int
    seq_counter: int  # 24-bit LE value at bytes [1:4]. Free-running hardware counter ticking at ~2.731 µs/tick (~366.3 kHz): ≈140,000 adjacent-delta samples × 6 chipsets (lm960/SDX20, fn980m/SDX55, rm500q/SDX55, simcom/SDM450, fn980/SDX55, mc7455/MDM9x07) all show p10..p90 d_log_time(µs)/d_seq_counter in [2.729, 2.732]. Wraps every ~45.83 s (2^24 × 2.731 µs). The rate is not a power of 2, so no integer right-shift of log_time matches it. Session-level absolute offsets vary (a linear fit across a multi-session capture has multi-billion-µs residuals), suggesting the counter resets on modem session boundaries rather than syncing to wall clock. Exact clock source unknown — 2.7307 µs doesn't match a clean 3GPP timer (LTE subframe / N, OFDM symbol / N); likely an internal ML1 measurement-cycle clock.
    flags_byte: int   # byte [9], near-const 0x00; LM960-only minorities up to 0x0c
    marker: int       # u16 LE @ [10:12]; observed: 0x0c20 (num_cells=0, 99.98%) + 0x0c21 (num_cells=1, cross-vendor) + 0x4c21 (cross-vendor minority: lm960 + simcom + ft980m).
    num_cells: int
    sentinel: int     # u16 LE @ [20:22]; 100% invariant 0xFFFE across the corpus
    cells: list[dict]  # each: {pci, rssi_raw, rsrp_raw}

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x187B',
            'log_time': self.log_time,
            'version': self.version,
            'seq_counter': self.seq_counter,
            'flags_byte': self.flags_byte,
            'marker': self.marker,
            'num_cells': self.num_cells,
            'sentinel': self.sentinel,
            'cells': self.cells,
        }


@register(LOG_LTE_ML1_NEIGHBOR_MEAS,
    name="0x187B",
    description="Neighbor cell PCI, RSSI, RSRP from 28-byte records with bitpacked fields",
    version=12,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE from SDX20 captures and an exhaustive corpus walk "
        "(826,205 records / 172 captures, 6+ chipsets). Single version v0x02: "
        "offset 0 is 100% 0x02. num_cells (byte 12) is only {0, 1} — a status "
        "flag, not a count — and the inline PCI(9)|RSSI(11)|RSRP(12) bitpack "
        "[13:19] reads 0x00 on every record including every num_cells=1 record "
        "(stationary and drive captures alike), so no cell measurement is "
        "carried inline. Invariants hold with 0 violations: version {0x02}; "
        "marker u16 within {0x0c20, 0x0c21, 0x4c21}; sentinel 0xFFFE. The "
        "subsystem is F3-named by plaintext lte_LL1_meas_ncell.c NB_MEAS (the "
        "LL1 neighbour-meas engine), but with an empty bitpack there is no "
        "value to validate. QCSuper does not decode 0x187B. num_cells=1 "
        "announces an LTE-idle -> WCDMA IRAT search: the co-emitted 0x4179 "
        "(+101,376 / +102,400 µs median lag, 57/57 paired) is F3-grounded as "
        "the WCDMA PN search results log (UARFCN/PSC/PN peaks), so this code "
        "carries rat-context and a one-shot timing anchor only. seq_counter is "
        "a free-running ~2.731 µs/tick (~366.3 kHz) 24-bit counter, consistent "
        "across 6 chipsets, that resets on session boundaries; 0x4179 does not "
        "carry it, so the 0x187B -> 0x4179 pairing is timing-only. A payload "
        "shorter than 28 B, or whose num_cells x 4 B bitpack overruns it, "
        "returns None."
    ),
    source_url="",
    # Corpus walk:
    # offset 0  = version (always 0x02)
    # offsets [1:4] = 24-bit LE seq_counter (uniform per-byte distribution)
    # offsets [4:8] = reserved zero (100% invariant)
    # offset 9 = flags_byte (99.8% 0x00, LM960-specific minorities to 0x0c)
    # offsets [10:12] = marker enum {0x0c20 (num_cells=0 99.98%), 0x0c21 (num_cells=1 cross-vendor), 0x4c21 (LM960 minority)}
    # offset 12 = num_cells
    # offsets [13:17] = bitpacked cell u32 when num_cells>0
    # offsets [20:22] = sentinel 0xFFFE LE (100% invariant)
    # offsets [22:28] = reserved zero (100% invariant)
    fields_identified=9,
    fields_parsed=9,
    wigle_direct=False,
    wigle_roles=("rat-context", "timing-anchor:one-shot"),
    supported_versions=[0x02],
    field_invariants={
        'version': {'enum': [0x02]},
        'marker': {'enum': list(_OBSERVED_MARKERS)},
        'sentinel': {'enum': [_SENTINEL]},
    },
    issues=(),
    primary_issue=None,
    # Bytes [13:20] are 100% zero across every num_cells>0 record in the
    # corpus. The inline PCI(9)|RSSI(11)|
    # RSRP(12) bitpack decode below at offset 13 returns zero in every case and
    # is currently unreachable as cell data. Kept defensively in case a future
    # firmware variant ships in-record cell data — but the "num_cells" byte
    # appears to be a status flag, not a count.
)
def parse_0x187b(log_time: int, data: bytes) -> Diag0x187B | None:
    """Parse 0x187B -- LTE ML1 Neighbor Cell Measurements.

    28-byte records, version 2. Header layout (corpus-validated):
    [0]=version, [1:4]=seq_counter (24b LE), [4:8]=reserved, [9]=flags,
    [10:12]=marker (0x0c20 / 0x4c21 LE), [12]=num_cells, [13:17]=bitpacked
    cell when num_cells>0, [20:22]=sentinel 0xFFFE LE, [22:28]=reserved.

    Per-cell bitpack: PCI(9b) | RSSI(11b) | RSRP(12b) in a u32 field.
    Returns None if payload is shorter than the fixed 28-byte record
    (truncated records decline loudly), version not 2, the cell bitpack for
    ``num_cells`` overruns the payload, or the sentinel byte pair doesn't
    match the corpus-invariant 0xFFFE (drift guard).
    """
    if len(data) < _RECORD_LEN:
        return None
    version = data[0]
    if version != 2:
        return None

    seq_counter = int.from_bytes(data[1:4], 'little')
    flags_byte = data[9]
    marker = unpack_from('<H', data, 10)[0]
    num_cells = data[12]
    sentinel = unpack_from('<H', data, 20)[0]
    if sentinel != _SENTINEL:
        return None
    cells: list[dict] = []

    cell_offset = 13
    for _ in range(num_cells):
        if cell_offset + 4 > len(data):
            return None  # num_cells overruns the record
        cell_u32 = unpack_from('<I', data, cell_offset)[0]
        if cell_u32 != 0:
            pci = cell_u32 & 0x1FF
            rssi_raw = (cell_u32 >> 9) & 0x7FF
            rsrp_raw = (cell_u32 >> 20) & 0xFFF
            if pci <= 503:
                rsrp_dbm = -180.0 + rsrp_raw * 0.0625
                if -140.0 <= rsrp_dbm <= -30.0:
                    cells.append({
                        'pci': pci,
                        'rssi_raw': rssi_raw,
                        'rsrp_raw': rsrp_raw,
                    })
        cell_offset += 4

    return Diag0x187B(
        log_time=log_time,
        version=version,
        seq_counter=seq_counter,
        flags_byte=flags_byte,
        marker=marker,
        num_cells=num_cells,
        sentinel=sentinel,
        cells=cells,
    )
