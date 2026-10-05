"""0x5071 — LOG_GSM_L1_SURROUND_CELL_BA_LIST: GSM neighbour (BA list) cells, ranked.

Layout (718/718 corpus records, 10 captures, EG25-G MDM9207 + EC25 +
MC7700 MDM9200):

    [0]              num_cells    u8 (0..6 observed)
    [1+12i:+2]       arfcn word   u16 LE: ARFCN in bits 0..11, band in bits 12..15
    [3+12i:+2]       rx_power     int16 LE, 1/16 dBm
    [5+12i]          bsic_known   u8, 0 or 1
    [6+12i]          bsic         u8, 6-bit BSIC (NCC<<3 | BCC); valid only
                                  when bsic_known == 1
    [7+12i:+4]       fn_offset    u32 LE (CANDIDATE, see below)
    [11+12i:+2]      qbit_offset  u16 LE (CANDIDATE, see below)

The record is exactly ``1 + 12 * num_cells`` bytes (718/718); anything else
is rejected. Entries are ranked strongest-first (679/718 records strictly
non-increasing in rx_power).

**Byte 0 is a cell COUNT, not a version** (``version_less=True``). Read as
a version it would look like an enum {0x01..0x06}, each value one list
length (13, 25, 37, 49, 61, 73 bytes); the count-0 form is the 1-byte
record. There is no config word.

Grounding (EG25-G on two firmware builds, EC25, MC7700):

* **F3 identity.** Each record is the log twin of the RR inter-task message
  ``gs1:IMsg: MPH_SURROUND_MEAS_IND`` (``rr_gprs_debug.c:3768``): 335/347
  records in the 4 F3-bearing captures sit within 1.12 ms of one (median
  0.011 ms), 1:1 with no message reused. The 12 others are runs of
  n = 3 → 4 → 5, about 78 ms apart, just before an IND, while the list fills
  during acquisition. 0x507B is emitted in the same tick.
* **num_cells.** Equals the count of ARFCNs in the list by construction (the
  size law). F3 ``NOTIFY MONSCAN BA LIST num_cells=%d`` is NOT a twin
  (sparse, hundreds of ms away, and prints 6 next to n = 3 records).
* **ARFCN / band.** 2213/2213 entries are in the network's own SI1/SI2/SI2bis
  ARFCN lists (0x512F decode) in the 4 captures that carry SI. All
  observed ARFCNs are PCS-1900 (512..810) with band 0xA, the same packed
  word as 0x5065 / 0x5066 / 0x507B.
* **rx_power.** Joined to the same-tick 0x507B record (whose 1/16 dBm scale
  is F3-pinned via 0x507A): 3367/3369 entries have the ARFCN there, mean
  difference +0.08 dB (median +0.06). 0x5071 is a smoothed value, so it is
  not bit-equal. Observed -108.0 to -55.2 dBm.
* **bsic_known / bsic.** Against the latest CRC-pass 0x5066 SCH decode on
  the same ARFCN in the same capture: 81/81 known BSICs match when that
  decode is ≤ 60 s old. In one EG25-G survey, SCH decodes
  683 → 21 and 637 → 42, and the next 0x5071 record, 0.5 s later, flips both
  entries to bsic_known = 1 with those BSICs. Every mismatch (73) is in the
  moving EC25 drive capture with an SCH decode ≥ 325 s old, i.e. another cell
  that reuses the ARFCN. With bsic_known = 0 the byte keeps a stale value,
  so ``bsic`` is ``None`` there and ``bsic_raw`` keeps the byte.
* **Black-box (SCAT).** SCAT decodes this code ("GSM Surround Cell BA").
  516 of its records align 1:1 with ours (it drops the rest). Count, ARFCN
  and band agree on 2361/2361 cells; its "BSIC: N/A" ⇔ bsic_known = 0 on
  2361/2361; on the 298 known cells BSIC and RX power agree 298/298. On
  unknown cells SCAT prints the stale BSIC byte in its RxPwr column, which
  is a SCAT output quirk, not a layout disagreement.
* ``0x60`` events: none in any capture that carries this code.

CANDIDATE ``fn_offset`` / ``qbit_offset``: not printed by F3 or SCAT. They
are bounded by GSM constants on 3369/3369 entries: fn_offset < 2715648
(the hyperframe) and qbit_offset < 5000 (quarter-bits per TDMA frame). The
non-zero pairs are (0, 2..56) and (2715647, 4994..4998), i.e. small signed
offsets written mod hyperframe. They read as the neighbour's frame timing
relative to the serving cell, but that meaning is unproven, so the raw
words are exposed and nothing is folded or renamed.

Log name: LOG_GSM_L1_SURROUND_CELL_BA_LIST
Also known as: LOG_GSM_SURROUND_CELL_BA_LIST
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

CELL_SIZE = 12


@dataclass
class GsmBaListCell:
    """One BA-list neighbour: ARFCN, band, RX power, BSIC, timing words."""
    arfcn: int
    band: int
    rx_power_raw: int
    rx_power_dbm: float
    bsic_known: int
    bsic: int | None
    bsic_raw: int
    fn_offset: int
    qbit_offset: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "arfcn": self.arfcn,
            "band": self.band,
            "rx_power_raw": self.rx_power_raw,
            "rx_power_dbm": self.rx_power_dbm,
            "bsic_known": self.bsic_known,
            "bsic": self.bsic,
            "bsic_raw": self.bsic_raw,
            "fn_offset": self.fn_offset,
            "qbit_offset": self.qbit_offset,
        }


@dataclass
class Diag0x5071:
    """0x5071 — GSM L1 surround-cell BA list."""
    log_time: int
    num_cells: int
    cells: list[GsmBaListCell] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x5071",
            "log_time": self.log_time,
            "num_cells": self.num_cells,
            "cells": [c.to_dict() for c in self.cells],
        }


@register(
    0x5071,
    name="0x5071",
    description="GSM L1 surround-cell BA list: count + {ARFCN, band, RX power "
                "(1/16 dBm), BSIC + known flag, FN/qbit offset words} per cell",
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE + F3 grounding on EG25-G MDM9207, EC25 and MC7700 "
        "MDM9200. Record is 1 + 12*num_cells bytes on 718/718 corpus records. "
        "Version-less: byte 0 is the cell count, not a version. "
        "Each record twins RR MPH_SURROUND_MEAS_IND (335/347 within 1.12 ms, 1:1); "
        "2213/2213 ARFCNs are in the network's SI BA lists (0x512F); power "
        "matches same-tick 0x507B (mean +0.08 dB); BSIC matches the 0x5066 SCH "
        "decode 81/81 when fresh; SCAT A/B 298/298 on known cells. FN/qbit "
        "offset words raw (CANDIDATE)."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=8,
    fields_parsed=8,
    version_less=True,
)
def parse_0x5071(log_time: int, data: bytes) -> Diag0x5071 | None:
    if not data:
        return None
    n = data[0]
    if len(data) != 1 + CELL_SIZE * n:
        return None
    cells = []
    for i in range(n):
        word, raw, known, bsic, fn_off, qbit_off = unpack_from(
            "<HhBBIH", data, 1 + CELL_SIZE * i)
        cells.append(GsmBaListCell(
            arfcn=word & 0x0FFF,
            band=word >> 12,
            rx_power_raw=raw,
            rx_power_dbm=raw / 16,
            bsic_known=known,
            bsic=bsic if known == 1 else None,
            bsic_raw=bsic,
            fn_offset=fn_off,
            qbit_offset=qbit_off,
        ))
    return Diag0x5071(log_time=log_time, num_cells=n, cells=cells)
