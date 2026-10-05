"""0x507B — LOG_GSM_L1_NEIGHBOR_CELL_AUXILIARY_MEASUREMENTS: GSM neighbour RX power list.

Layout (702/702 corpus records, 10 captures, EG25-G MDM9207 + EC25 +
MC7700 MDM9200):

    [0]        num_cells   u8 (0..6 observed)
    [1+4i:+2]  arfcn word  u16 LE: ARFCN in bits 0..11, band in bits 12..15
    [3+4i:+2]  rx_power    int16 LE, 1/16 dBm

The record is exactly ``1 + 4 * num_cells`` bytes (702/702); anything else
is rejected. The layout agrees with the open-source SRLabs diag-parser struct for
this code (``cell_count`` + ``{arfcn_and_band, rx_power}``), used here as
a reference for the 12/4 bit split only.

**Byte 0 is a cell COUNT, not a version** (``version_less=True``). Read as
a version it would look like an enum {0x01..0x06}, each value one list
length (5, 9, 13, 17, 21, 25 bytes); the count-0 form is the 1-byte
record. There is no config word.

Grounding (EG25-G F3 captures, an EC25 drive, an EG25-G survey):

* Each record is the log twin of the RR inter-task message
  ``gs1:IMsg: MPH_SURROUND_MEAS_IND`` (``rr_gprs_debug.c:3768``):
  305/305 records within 1.1 ms of one, in 3 F3-bearing captures.
* ARFCN: 2171/2171 entries are in the network's own SI1/SI2/SI2bis
  ARFCN lists (0x512F decode) in the 4 captures that carry SI, and the
  serving ARFCN named by F3 ``CXM DL ARFCN=685`` is never in the list
  while it serves. All observed ARFCNs are PCS-1900 (512..810).
* rx_power: same 1/16 dBm word as 0x507A, whose scale the F3 CXM DL
  dBm10 print pins (see diag_0x507a). Observed -108.0 to -53.2 dBm.
* band: 0xA on every entry (all PCS-1900). Exposed raw; the enum
  mapping for other bands is not observed.

QCSuper and SCAT do not decode this code.
``0x60`` events: none in any capture that carries this code.

Log name: LOG_GSM_L1_NEIGHBOR_CELL_AUXILIARY_MEASURMENTS
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

CELL_SIZE = 4


@dataclass
class GsmNcellAuxMeas:
    """One neighbour entry: ARFCN, band, RX power."""
    arfcn: int
    band: int
    rx_power_raw: int
    rx_power_dbm: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "arfcn": self.arfcn,
            "band": self.band,
            "rx_power_raw": self.rx_power_raw,
            "rx_power_dbm": self.rx_power_dbm,
        }


@dataclass
class Diag0x507B:
    """0x507B — GSM L1 neighbour-cell auxiliary measurements."""
    log_time: int
    num_cells: int
    cells: list[GsmNcellAuxMeas] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x507B",
            "log_time": self.log_time,
            "num_cells": self.num_cells,
            "cells": [c.to_dict() for c in self.cells],
        }


@register(
    0x507B,
    name="0x507B",
    description="GSM L1 neighbour-cell auxiliary measurements: count + "
                "{ARFCN, band, RX power (1/16 dBm)} per cell",
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE + F3 grounding on EG25-G MDM9207, EC25 and MC7700 "
        "MDM9200. Record is 1 + 4*num_cells bytes on 702/702 corpus records. "
        "Version-less: byte 0 is the cell count, not a version. "
        "Each record twins the RR message MPH_SURROUND_MEAS_IND (305/305 within "
        "1.1 ms); 2171/2171 ARFCNs are in the network's SI BA lists (0x512F); "
        "the F3-named serving ARFCN is never listed. Power shares 0x507A's "
        "F3-pinned 1/16 dBm scale. 12/4 ARFCN/band split agrees with the "
        "open-source SRLabs diag-parser struct."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=4,
    fields_parsed=4,
    version_less=True,
)
def parse_0x507b(log_time: int, data: bytes) -> Diag0x507B | None:
    if not data:
        return None
    n = data[0]
    if len(data) != 1 + CELL_SIZE * n:
        return None
    cells = []
    for i in range(n):
        word, raw = unpack_from("<Hh", data, 1 + CELL_SIZE * i)
        cells.append(GsmNcellAuxMeas(
            arfcn=word & 0x0FFF,
            band=word >> 12,
            rx_power_raw=raw,
            rx_power_dbm=raw / 16,
        ))
    return Diag0x507B(log_time=log_time, num_cells=n, cells=cells)
