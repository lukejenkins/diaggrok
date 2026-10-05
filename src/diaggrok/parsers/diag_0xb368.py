"""0xB368 — SDX72 NR5G/LTE serving-cell-identity + measurement record.

Observed on a T99W640 (Dell DW5934e, **SDX72**) during a DIAG-only
stationary cell-site survey, camped NR5G-SA on T-Mobile n41. Fixed 1768-byte payload; the first dword is the **4-byte
version** ``0x0000003B`` (byte-0 == 0x3B, bytes [1:4] == 0) — the 0xBxxx
outer-version convention, not a u8 version.

Header layout (first 28 bytes), grounded across all 6 corpus records
(a cell-site survey plus a bring-up capture on the same modem):

    [0:4]    u32le  version    == 0x0000003B (59) — byte-0 gate
    [4:8]    u32le  arfcn      channel number — NR-ARFCN when rat==2,
                               EARFCN when rat==1
    [8:12]   u32le  pci        physical cell id
    [12:16]  u32le  rat        RAT enum: 1 = LTE, 2 = NR5G
    [16:20]  u32le  band       band number (n<band> for NR, B<band> for LTE)
    [20:24]  u32le  word_14    {0,1} — 1 on both n41 records (candidate
                               serving-cell / FR flag, not asserted; n=6)
    [24:28]  u32le  word_18    free-running per-record counter/timestamp
    [28:1768] bytes body_raw   1740-byte body: structured front (abs 28:256)
                               + dense dynamic tail (abs ~348:1768), see below

### Cell-identity grounding

The header's ``arfcn``/``pci``/``rat``/``band`` fields are asserted on
three independent ground-truth legs (the 0xB368-bearing captures carry no
in-capture F3, so the grounding is cross-capture and cross-decoder):

1. **Internal arfcn↔band↔rat consistency, 6/6 records across BOTH RATs.**
   Every record's ``arfcn`` decodes to a frequency inside the band named
   by the separate ``band`` field, with ``rat`` selecting the numbering:

       arfcn   pci  rat  band   reads as
       501390  596   2    41    NR-ARFCN 501390 ∈ n41 (2496 MHz)  ×2
       521310  596   2    41    NR-ARFCN 521310 ∈ n41 (2606 MHz)
       387170  455   2    25    NR-ARFCN 387170 ∈ n25 (1936 MHz)  ×2
       5035    404   1    12    LTE EARFCN 5035 ∈ B12             ×1

   A timestamp cannot land inside the band a *different* field names in
   6/6 records; and ``rat==1`` occurs *exactly* on the LTE-EARFCN record.

2. **External QMI serving-cell match.** A later survey on the same modem
   and firmware build reports via QMI
   ``nas-get-cell-location-info`` a serving NR-ARFCN of **501390** on
   n41 — byte-identical to the ``arfcn`` of the serving-cell record.

3. **Independent SCAT decode of the same capture.** SCAT,
   reading the *standard* LTE/NR ML1 log codes (never the 0xB368 payload),
   reports exactly these cell triples in the bringup capture:
   PCI 596 / NR-ARFCN 501390 / Band 41, PCI 455 / NR-ARFCN 387170 /
   Band 25, PCI 404 / EARFCN 5035, NR-ARFCN 521310.

``rat`` is left **unpinned** (a legitimate RAT can take other values on a
future capture) — decoded, not gated. Only ``version``/``payload_size``
are field-invariant gates.

### Body structure

The 1740-byte body is NOT a clean tag-length-value stream — four candidate
TLV grammars (``total=lenbyte+2``, ``=lenbyte``, ``=2+4*lenbyte``,
``=2+2*lenbyte``) each fail to tile any of the 6 records. Per-offset
variance partitions it into a **structured front** ``body[0:~228]``
(abs 28:256; short const runs + 1-3 byte per-record fields; ``body[5]`` a
seq-low-byte paralleling ``word_18``) and a **dense dynamic tail**
``body[~320:1740]`` (per-capture content; grounding it needs a capture
with a driven workload and a parallel AT poll). The one recurring motif, an
8-byte ``04 02 | chan(u16le) | value(u32le)`` entry ×5/record, is constant
across all 6 records / 3 cells
(``(150,1200)(150,1800)(180,300)(180,360)(240,300)``) — a static
config/threshold table, NOT live per-cell measurements.

Per the log-code version policy this parser pins
``field_invariants={"version": {"enum": [0x3B]}}`` and enforces it at a
Layer-1 byte gate (byte-0), so a future firmware shipping a different
version dword in the same 1768-byte count is rejected rather than silently
mis-parsed.

F3-VERDICT 0xB368 v0x3b: INCONCLUSIVE.
Every F3-bearing capture (4 T99W640, 7 records, 28,878 prints within ±200 ms):
no print carries ``arfcn`` / ``pci`` / ``band`` above the shuffled baseline.
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

# Fixed 1768-byte payload; 4-byte version dword 0x0000003B (byte-0 == 0x3B).
_B368_SIZE = 1768
_B368_VERSION = 0x3B

# rat enum (grounded; see module docstring): 1 = LTE (arfcn is an EARFCN), 2 = NR5G (NR-ARFCN).
_RAT_NAMES = {1: "LTE", 2: "NR5G"}


@dataclass
class Diag0xB368:
    """0xB368 — SDX72 serving-cell-identity + measurement record (v=0x3B)."""
    log_time: int
    version: int
    arfcn: int         # u32le @4  — NR-ARFCN (rat==2) or EARFCN (rat==1)
    pci: int           # u32le @8  — physical cell id
    rat: int           # u32le @12 — RAT enum: 1=LTE, 2=NR5G
    band: int          # u32le @16 — band number (n<band> NR / B<band> LTE)
    word_14: int       # u32le @20 — {0,1}; 1 on n41 records (serving/FR? unasserted)
    word_18: int       # u32le @24 — free-running counter
    body_raw: bytes    # @28:1768 — structured front + dense dynamic tail, TBD
    payload_size: int

    @property
    def rat_name(self) -> str:
        return _RAT_NAMES.get(self.rat, f"rat{self.rat}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB368",
            "log_time": self.log_time,
            "version": self.version,
            "arfcn": self.arfcn,
            "pci": self.pci,
            "rat": self.rat,
            "rat_name": self.rat_name,
            "band": self.band,
            "word_14": self.word_14,
            "word_18": self.word_18,
            "body_raw": self.body_raw,
            "payload_size": self.payload_size,
        }


@register(
    0xB368,
    name="0xB368",
    wigle_direct=False,
    wigle_roles=("pci-earfcn-bridge", "rat-context"),
    description="0xB368 — SDX72 (T99W640) NR5G/LTE serving-cell record, fixed 1768 B, 4-byte version dword 0x3B. Header = cell identity {arfcn@4 (NR-ARFCN/EARFCN), pci@8, rat@12 (1=LTE/2=NR5G), band@16} grounded 6/6 via arfcn<->band<->rat internal consistency + QMI serving-cell match (NR-ARFCN 501390 n41) + independent SCAT ML1 decode. Body = structured front (abs 28:256) with 5 constant '04 02|chan|val' entries (static table) + dense dynamic tail (abs ~348:1768, needs workload+AT). No generic TLV grammar tiles it.",
    version=4,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail="Clean-room reverse engineering from a T99W640 (SDX72) cell-site survey plus a bring-up capture: 6 records (1768 B fixed; 4-byte version dword 0x0000003B). Header cell-identity fields are asserted: arfcn@4 = NR-ARFCN (rat==2) / EARFCN (rat==1); pci@8; rat@12 = 1 LTE / 2 NR5G; band@16. The 0xB368-bearing captures carry no in-capture F3, so grounding rests on 3 independent legs: (1) arfcn->band internal consistency 6/6 across both RATs (501390/521310->n41, 387170->n25, EARFCN 5035->B12, with rat==1 exactly on the LTE record); (2) a QMI nas-get-cell-location serving NR-ARFCN 501390 n41 from a later survey on the same modem and build; (3) SCAT's ML1 decode of the bring-up capture reproducing PCI 596/455/404, NR-ARFCN 501390/387170/521310, EARFCN 5035, Band 41/25. rat is decoded, not gated. No generic TLV grammar tiles the 1740-byte body; it splits into a structured front (abs 28:256) and a dense dynamic tail (abs ~348:1768, needs a driven-workload capture with an AT poll); the 8B '04 02|chan(u16)|val(u32)' entry x5/record is constant across all 6 records/3 cells, i.e. a static table, not measurements.",
    source_url="",
    issues=(),
    primary_issue=None,
    # version, arfcn, pci, rat, band, word_14, word_18, body_raw — 8 fields
    # covering all 1768 bytes; the 4 cell-identity fields are semantically
    # grounded (arfcn/pci/rat/band), word_14/word_18 wire-typed, body_raw
    # a known-size opaque region (dynamic tail not yet semantically decoded).
    fields_identified=8,
    fields_parsed=8,
    field_invariants={
        "version": {"enum": [_B368_VERSION]},
        "payload_size": {"enum": [_B368_SIZE]},
    },
)
def parse_0xb368(log_time: int, data: bytes) -> Diag0xB368 | None:
    if len(data) != _B368_SIZE:
        return None
    # Layer-1 version gate (version byte first): byte-0 of the
    # 4-byte version dword. The upper 3 bytes are 0 in the corpus.
    if data[0] != _B368_VERSION:
        return None
    return Diag0xB368(
        log_time=log_time,
        version=unpack_from("<I", data, 0)[0],
        arfcn=unpack_from("<I", data, 4)[0],
        pci=unpack_from("<I", data, 8)[0],
        rat=unpack_from("<I", data, 12)[0],
        band=unpack_from("<I", data, 16)[0],
        word_14=unpack_from("<I", data, 20)[0],
        word_18=unpack_from("<I", data, 24)[0],
        body_raw=data[28:1768],
        payload_size=len(data),
    )
