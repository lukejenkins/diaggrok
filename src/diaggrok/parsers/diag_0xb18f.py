"""0xB18F — LTE ML1 AdvRx IC cell list (LOG_LTE_ML1_ADVRX_IC_CELL_LIST).

All five corpus versions decode to the same fields (carrier, DL EARFCN,
serving + IC-neighbour cell PCI / RB / RSRP); each is grounded on its own
silicon.

Emitter: ``lte_ml1_sm_conn_advrx_stm.c`` "Unable to allocate log packet for
AdvRX IC list" — present in the SDX20 (:6728), MDM9x40 (:7155), SDX24
(:6908) and SDX55 (:6837) builds.

Cell entry (shared by every version; LE)
----------------------------------------
::

    +0   u16 raw_0
    +2   u16 pci
    +4   u16 dl_bw_rb       25 / 50 / 100 on measured cells; 0 = empty slot.
                            101 occurs only on neighbour slots, always with
                            num_rx_ant 0 (v0x30 2,638, v0x36 5,002 entries):
                            it is not an RB count and its meaning is unresolved.
    +6   u16 num_rx_ant_candidate   2 or 4 on measured cells (per-capture constant)
    +8   u16 rsrp_raw[3]    dBm = raw/16 - 180. raw 0x0960 (-30 dBm) and
                            0x01e0 (-150 dBm) are outside the physical RSRP
                            range and recur (3,223 / 71 on v0x36): rsrp_dbm
                            reports them as None.
    +14  ...                raw_14 (0x01e0 at +14 and 0xa0 at +18 on every
                            measured cell)

RSRP grounding: rsrp_raw[1] and [2] of the serving slot equal the co-captured
0xB193 serving-cell RSRP (same PCI + EARFCN, ±200 ms) with median error
0.00 dB — v0x30 LV55 68/68 within 2 dB, v0x36 RM520N-GL 604/669 and M3100
572/574. rsrp_raw[0] runs ~0.6 dB below them (a differently filtered value).
v0x20: all three are within 2 dB of F3 ``wb_stm.c:3235`` rx0 on 269/269.

Fixed-size versions (v0x20 / v0x23 / v0x28 / v0x30)
----------------------------------------------------
``head + 17 x 32 B cell slots + 2 B``. Slots 0 (serving) and 1 (first IC
neighbour) are decoded; they are the slots F3 grounds. Slots 2..16 keep the
same 32 B shape and sometimes hold a plausible cell (v0x23 93/913 records in
slot 2), but no field was found that says how many slots are current, and on
other records they hold a stale repeating fill (``f0 .. fb`` with a 10-byte
period on v0x28). They are returned as ``tail_raw`` with the 2 B trailer, not
decoded as cells.

======  =========================  ======  ===========  ==========  ======
ver     silicon (corpus)           size    dl_earfcn    cells at    head
======  =========================  ======  ===========  ==========  ======
0x20    Sierra SDX20 (EM7565/      580     u32@12       +34         34 B
        EM7511/MC7411)
0x23    Telit LM960A18 MDM9x40     588     u32@16       +42         42 B
0x28    Quectel EM120R-GL SDX24    572     u32@16       +26         26 B
0x30    SDX55 (LV55, RM500Q,       572     u32@16       +26         26 B
        T99W175, FN980, M2000)
======  =========================  ======  ===========  ==========  ======

``carrier_index`` = u8@1 on every version (0 = PCC; the corpus reaches 2 on
v0x28 and 4 on v0x30 / v0x36 under CA).

Grounding (carrier 0 = PCC, against the same DIAG stream):

* v0x20 — slot-0 PCI == F3 ``lte_ml1_sm_conn_wb_stm.c:3235`` "Serving Cell
  %d LL RSRP" 269/269 (EM7565). (pci,
  dl_earfcn, dl_bw_rb) == 0xB0C2 RRC serving cell 3672/3672 (u32@16 / u32@20
  match 0, so the EARFCN is u32@12).
* v0x23 — see below.
* v0x28 — (pci, dl_earfcn, dl_bw_rb) == 0xB0C2 109/109. F3
  ``lte_rrc_sib.c:517`` "Cell freq %d, Cell Id %d" and ``:3946``
  "cphy_sib_sched_req for phy_cell_id = %d freq = %d" each equal the
  (dl_earfcn, slot-0 pci) of a carrier of a record within 2 s, 17/17
  (EM120R-GL; carriers 5035/158, 2300/242, 900/182).
* v0x30 — (pci, dl_earfcn, dl_bw_rb) == 0xB0C2 1263/1263 (LV55).
* v0x36 — (pci, dl_earfcn, dl_bw_rb) == 0xB0C2 2127/2211; the other 84 report
  EARFCN 66536 while the RRC PCell is 5230, and do not match the next 0xB0C2
  either (unexplained).

v0x23 (588 B, Telit LM960A18 / MDM9x40) — F3-grounded
------------------------------------------------------
The tick that builds the list co-emits F3 ``advrx_stm.c:2632`` ("tao
cc_mask(...) before eval_t") on 603/603 records and ``:8122`` ("carrier %u
allocated %u max ic cells") on 600/603 within ±5 ms (an LM960A18 drive
capture). Head fields beyond the common ones::

    +16  u32  dl_earfcn        GROUND: carrier-0 (pci, dl_earfcn, dl_bw_rb) ==
                               0xB0C2 RRC serving cell 302/302 (drive capture)
    +40  u8   num_cell_slots   (== 2 on all 3,318 records measured)
    +41  u8   ic_cells_allocated  CANDIDATE: == F3 :8122 "allocated %u max ic
                               cells" 2,978/3,000 carrier-0 joins, incl. 8/8 of
                               the rare value 2 (byte +36, constant 1, is not it)

Slot-0 PCI == F3 wb_stm.c:3587 "Serving Cell %d" 2715/2715; slot-1 ==
F3 wb_stm.c:3611 "Neighbor Cell %d" 870/871, and advrx_stm.c:7668/3839/15714.

v0x36 (60 + 28 x n B: Quectel RM520N-GL SDX62, Inseego M3100, Sierra EM9291)
----------------------------------------------------------------------------
::

    +0   u8   version (0x36)
    +1   u8   carrier_index
    +4   u32  dl_earfcn
    +9   u8   num_neighbour_cells   n; the record holds 1 + n blocks
    +16  block[1 + n], 28 B each: u16 prefix_raw, then the cell entry above
         (26 B: pci at block+4)
    end-16  16 B tail_raw (fields not identified)

Every corpus size (60..228 step 28) equals 60 + 28 x u8@9.

Log name: LTE ML1 AdvRx IC Cell List
Also known as: LOG_LTE_ML1_ADVRX_IC_CELL_LIST
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


V23_VERSION = 0x23
_CELL_STRIDE = 32
_NUM_DECODED_SLOTS = 2   # serving + first IC neighbour (the F3-grounded slots)

# Fixed-size versions: version -> (dl_earfcn offset, first cell slot, size).
# Every record is head + 17 x 32 B slots + 2 B. No version carries a length
# field, so a record shorter than its size is declined (registry warning),
# never decoded; v0x30 also has rare longer records, which stay accepted.
_FIXED_LAYOUT = {
    0x20: (12, 34, 580),
    0x23: (16, 42, 588),
    0x28: (16, 26, 572),
    0x30: (16, 26, 572),
}
_V36_VERSION = 0x36
_V36_BASE_SIZE = 60
_V36_BLOCK_SIZE = 28
_V36_BLOCKS_OFF = 16
_V36_COUNT_OFF = 9
_V36_TAIL_SIZE = 16

# rsrp_raw values that decode outside the physical RSRP range (-30 / -150 dBm).
_RSRP_SENTINELS = frozenset({0x0960, 0x01E0})


def _min_size(version: int, data: bytes) -> int:
    if version == _V36_VERSION:
        if len(data) <= _V36_COUNT_OFF:
            return _V36_BASE_SIZE
        return _V36_BASE_SIZE + _V36_BLOCK_SIZE * data[_V36_COUNT_OFF]
    return _FIXED_LAYOUT[version][2]


def _rsrp_dbm(raw: int) -> float | None:
    if raw in _RSRP_SENTINELS:
        return None
    return raw / 16.0 - 180.0


def _decode_cell(data: bytes, off: int, end: int) -> dict[str, Any]:
    pci, bw, n_ant = unpack_from('<HHH', data, off + 2)
    rsrp_raw = list(unpack_from('<HHH', data, off + 8))
    return {
        "raw_0": unpack_from('<H', data, off)[0],
        "pci": pci,
        "dl_bw_rb": bw,
        "populated": bw != 0,
        "num_rx_ant_candidate": n_ant,
        "rsrp_raw": rsrp_raw,
        "rsrp_dbm": [_rsrp_dbm(r) for r in rsrp_raw],
        "raw_14": data[off + 14:end],
    }


@dataclass
class Diag0xB18F:
    """0xB18F — LTE ML1 AdvRx IC cell list (all corpus versions decoded)."""
    log_time: int
    version: int
    config_word: int
    data_density: float
    payload_size: int
    body_raw: bytes
    carrier_index: int | None = None
    dl_earfcn: int | None = None
    cells: list[dict[str, Any]] | None = None
    tail_raw: bytes | None = None
    # v0x23 only.
    ic_cells_allocated_candidate: int | None = None
    num_cell_slots: int | None = None
    # v0x36 only.
    num_neighbour_cells: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d = {
            "type": "Diag0xB18F",
            "log_time": self.log_time,
            "version": self.version,
            "config_word": self.config_word,
            "data_density": self.data_density,
            "payload_size": self.payload_size,
            "body_raw": self.body_raw,
            "carrier_index": self.carrier_index,
            "dl_earfcn": self.dl_earfcn,
            "cells": self.cells,
            "tail_raw": self.tail_raw,
        }
        if self.version == V23_VERSION:
            d["ic_cells_allocated_candidate"] = self.ic_cells_allocated_candidate
            d["num_cell_slots"] = self.num_cell_slots
        if self.version == _V36_VERSION:
            d["num_neighbour_cells"] = self.num_neighbour_cells
        return d


def _decode_fixed(version: int, data: bytes) -> dict[str, Any]:
    earfcn_off, cells_off, _ = _FIXED_LAYOUT[version]
    tail_off = cells_off + _NUM_DECODED_SLOTS * _CELL_STRIDE
    out: dict[str, Any] = {
        "carrier_index": data[1],
        "dl_earfcn": unpack_from('<I', data, earfcn_off)[0],
        "cells": [
            _decode_cell(data, o, o + _CELL_STRIDE)
            for o in range(cells_off, tail_off, _CELL_STRIDE)
        ],
        "tail_raw": data[tail_off:],
    }
    if version == V23_VERSION:
        out["num_cell_slots"] = data[40]
        out["ic_cells_allocated_candidate"] = data[41]
    return out


def _decode_v36(data: bytes) -> dict[str, Any]:
    n = data[_V36_COUNT_OFF]
    cells = []
    for i in range(1 + n):
        blk = _V36_BLOCKS_OFF + i * _V36_BLOCK_SIZE
        cell = _decode_cell(data, blk + 2, blk + _V36_BLOCK_SIZE)
        cell["prefix_raw"] = unpack_from('<H', data, blk)[0]
        cells.append(cell)
    return {
        "carrier_index": data[1],
        "dl_earfcn": unpack_from('<I', data, 4)[0],
        "num_neighbour_cells": n,
        "cells": cells,
        "tail_raw": data[_V36_BLOCKS_OFF + (1 + n) * _V36_BLOCK_SIZE:],
    }


# BYTE0-VERSION-ASSUMPTION: byte-0 is assumed to be the version field (the
# usual DIAG log convention). enum = every byte-0 value observed at size>4:
# 0x20, 0x30, 0x36, 0x23 (LM960, 7,433 records corpus-wide) and 0x28
# (EM120R-GL SDX24, 283 records). Each version has its own size and layout, and
# every one carries carrier/EARFCN/PCI at version-specific offsets that join
# the RRC serving cell exactly — consistent with byte 0 selecting the layout.
_B18F_VERSIONS_OBSERVED = (0x20, 0x23, 0x28, 0x30, 0x36)


@register(
    0xB18F,
    name="0xB18F",
    description="LTE ML1 AdvRx IC cell list: carrier, DL EARFCN, serving + IC-neighbour PCI/BW/RSRP (v0x20/0x23/0x28/0x30/0x36)",
    version=5,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail="All five versions (v0x20 580 B, v0x23 588 B, v0x28 572 B, v0x30 572 B, v0x36 60 + 28*n B) decode to the same field set. Carrier-0 (pci, dl_earfcn, dl_bw_rb) == 0xB0C2 RRC on v0x20 3672/3672, v0x23 302/302, v0x28 109/109, v0x30 1263/1263, v0x36 2127/2211; v0x20 slot-0 PCI == F3 lte_ml1_sm_conn_wb_stm.c:3235 269/269; v0x23 slot-0/slot-1 PCI == F3 wb_stm.c 'Serving Cell' 2715/2715 / 'Neighbor Cell' 870/871; v0x28 (earfcn, pci) == F3 lte_rrc_sib.c:517/:3946 17/17; rsrp_raw[1..2] == 0xB193 serving RSRP (median 0.00 dB) on v0x30/v0x36. Truncated payloads return None.",
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=10,
    fields_parsed=10,
    field_invariants={
        "version": {"enum": [0x20, 0x23, 0x28, 0x30, 0x36]},
    },
)
def parse_0xb18f(log_time: int, data: bytes) -> Diag0xB18F | None:
    if len(data) < 1:
        return None
    version = data[0]
    if version not in _B18F_VERSIONS_OBSERVED:
        return None
    if len(data) < _min_size(version, data):
        return None
    config_word = unpack_from('<I', data, 4)[0]
    nonzero = sum(1 for b in data[2:] if b != 0)
    density = round(nonzero / max(len(data) - 2, 1), 2)
    detail = _decode_v36(data) if version == _V36_VERSION else _decode_fixed(version, data)
    return Diag0xB18F(
        **detail,
        log_time=log_time,
        version=version,
        config_word=config_word,
        data_density=density,
        payload_size=len(data),
        body_raw=data[1:],
    )
