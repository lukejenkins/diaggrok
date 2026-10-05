"""0xB180 — LTE ML1 Neighbor Measurements packet (legacy mislabel `LtePdcpB180`).

A fixed header carrying the measured-carrier EARFCN, followed by a
variable-length array of fixed-stride per-neighbour measurement blocks.

### Naming

The legacy `LtePdcpB180` label was a band-wide guess from an early bulk
stub import ("LTE MAC/RLC/PDCP"). The canonical log name (listed below) is
**`LOG_LTE_ML1_NEIGHBOR_MEASUREMENTS_PACKET`** — an LTE **ML1** (layer-1
measurement) record, *not* a PDCP cipher log. The decoded structure (fixed
header + fixed-stride per-neighbour-cell entry array) matches the
ML1-neighbour-measurement name.

### Record structure (version 5; verified cross-vendor, cross-corpus)

A 12-byte header followed by `N` fixed 32-byte measurement blocks:

```
offset  0 : u32 LE  0x00000105   header tag (version=0x05, const 0x01)  — corpus-invariant
offset  4 : u32 LE  earfcn       MEASURED-carrier EARFCN of this record's neighbours (see below)
offset  8 : u8       cell_count_field = (8 + 64*N) & 0xFF
offset  9 : u8[3]    reserved (zero)
offset 12 : N x 32B  per-NEIGHBOUR blocks (pci/rssi/rsrp/rsrq/ttl — F3-GROUNDED, see below)
```

`N = (payload_size - 12) // 32`. Observed size classes 44/76/108/140/172/204 B
(N = 1..6). The `cell_count_field` at offset 8 is a redundant/derived count — it
packs `N` in bits [7:6] (so it wraps modulo 4: N=1->72, 2->136, 3->200, 4->8)
with a constant `0x08` low field. The **authoritative** block count is
`(payload_size - 12) // 32`; `cell_count_field` is surfaced raw for verification
only. `num_cells`/`cells` are the mechanical block count/slices; `neighbors` is
their F3-grounded decode, with unpopulated padding slots flagged
`populated=False`.

### Record structure (version 4 — older MDM9200 / Sierra MC7700 packing)

**v0x04 is a structurally distinct layout, seen only on the Sierra MC7700
(SWI9200X, MDM9200-era firmware)** — 276 records across 9 captures, three
firmware builds; no other modem in the corpus emits it. Like the sibling 0xB17F
v0x03, it uses **16-bit identity fields where v0x05 uses 32-bit**, with an
8-byte header and a 28-byte (not 32-byte) block stride:

```
offset  0 : u32 LE  0x00000004   header tag (version=0x04; bytes 1..3 = 0)
offset  4 : u16 LE  earfcn       serving-frequency EARFCN (grounded below) — NOT the u32 v0x05 uses
offset  6 : u8       cell_count_field (raw; hi bits[7:6] track the neighbour count, low nibble a flag)
offset  7 : u8       reserved — 0x00 on 276/276 records
offset  8 : N x 28B  fixed-stride measurement blocks (trailing blocks may be zero-padding)
```

`N = (payload_size - 8) // 28`. Observed size classes 36/64/92/120 B (N = 1..4);
the 92/120 B records carry a single populated block plus zero-padding, so
`num_cells` (size-derived) over-counts real neighbours — a *mechanical* slice
count, exactly as for v0x05. Each 28-byte block ends in a duplicated 4-byte word
(`ff??????  ff??????`), the same signature v0x05 shows in its 32-byte blocks —
that pair is w5 == w6 (per-antenna ttl_ref_time), see below; v0x04 blocks share
the v0x05 word layout minus w7 (structural transfer).

Reading `earfcn` as v0x05's `u32@4` on a v0x04 frame yields a 7-digit garbage
channel number (e.g. 4,720,892 / 8,915,196) on all 276 v0x04 records, so every
field is version-gated.

#### v0x04 grounding: in-capture 0xB0C0 (no F3 plane on MDM9200)

The MC7700 / SWI9200X predates the QSH / QSR4 F3 plane, so no F3 oracle exists
for v0x04. The EARFCN is instead grounded on the **co-temporal 0xB0C0 (LTE RRC
Serving Cell Info)** record: across all 7 v0x04 captures that also carry 0xB0C0,
the 0xB180 v0x04 `u16@4` EARFCN equals the 0xB0C0 serving EARFCN in **100 %** of
captures — 2175 in five captures, 2300 in one. On the 2300 capture the sibling
0xB17F v0x03 decode gives cell `(2300, 236)` (earfcn 2300 == AT!GSTATUS), and
0xB0C0's own `pci=236` agrees. QCSuper produces only a header-only pcap (0xB180
is not in its GSMTAP export set), and SCAT does not decode this code.

### Neighbour blocks — F3-GROUNDED on v0x05

Each block is one *neighbour* cell (the serving cell is never in it),
bit-packed in u32 words:

```
w0[0:9]   pci                       w0[9:20]  rssi  /16-110 dBm   w0[20:32] rsrp /16-180 dBm
w1[0:12]  == rsrp (copy)            w1[12:24] rsrp_alt_raw (CANDIDATE)   w2[0:12] == rsrp_alt
w2[12:22] rsrq /16-30 dB            w2[22:32] == rsrq (copy)
w3[0:10]  rsrq_alt_raw (CANDIDATE)  w3[10:20] == rsrq_alt        w3[20:32] RAW
w4        reserved (0)              w5[11:30] ttl_ref_time_ant0   w6[11:30] ttl_ref_time_ant1
w5/w6 [0:11]=0x7FF, [30:32] RAW flag bits;  w7 (v0x05 only) RAW trailer
```

**Oracle — F3 co-emission, 1:1, same diag tick.** `lte_ml1_md.c` prints, per
neighbour per measurement, `Ngbr Cell %d LL RSRP (used=%d rx0 rx1) RSRQ (used=rx%d
rx0)` + `Ngbr Cell %d LL RSRQ (rx1) RSSI (comb rx0 rx1)` at the *same* diag
timestamp as the 0xB180 record; `Ngbr meas req (earfcn,pci) … ttl_ref_time ant0 ant1`
precedes it. Matched by format string (line numbers move across builds):

| capture (chipset) | blocks | pci | rsrp(used) | rsrq(used) | rssi(comb) |
|---|---|---|---|---|---|
| MC7411 (SDX20, Sierra) | 203 | 203 | 203 (≤0.03 dB) | 203 | 203 |
| LM960 drive capture (SDX20, Telit) | 287 | 287 | 287 | 287 | 287 |
| T77W968 (SDX55, Foxconn) | 48 | 48 | 48 | 48 | 48 |

`rsrp`/`rsrq` follow the F3 `used=` chain (a `used=1` block carries rx1's value).
`ttl_ref_time_ant0` == F3 on 203/203 MC7411 blocks (19-bit; bits 30..31 are a
separate flag). Pair-B (`rsrp_alt_raw` / `rsrq_alt_raw`) is on the same scale and
equals pair-A on ~93 % of blocks but drifts ≤~1 dB on the rest with no F3 print
matching it (likely a filtered value) → CANDIDATE, surfaced raw.
Corpus: 31,946 populated v0x05 blocks / 20 modem families — pci ≤ 503 on 100 %,
rsrp ∈ [-144,-40] on 31,945, rssi plausible on 31,945, rsrq ∈ (-30,0] on 31,903.
In-capture `0x60` events: absent on the F3 capture. QCSuper exports no
ML1-neighbour packet and SCAT does not decode this code.

**v0x04 (MC7700, 28 B = words 0..6, no w7):** pci / rsrp / rsrq / ttl fields and the
pair-copy invariants transfer *structurally* (no F3 plane on MDM9200), but
w0[9:20] sits at a constant 0x640 — not RSSI-shaped — so v0x04 surfaces it as
`w0_mid_raw`, not `rssi_dbm`. v0x04 block names are a structural transfer.

Because the blocks are neighbours, no single offset carries the serving PCI
(e.g. 236) alongside a neighbour PCI (e.g. 471). The apparent "block-type tag"
`byte[0] ∈ {0xD7, 0x42}` is the low byte of the neighbour PCIs **471 = 0x1D7**
and **322 = 0x142** (and the order swaps between records), and the duplicated
word-pair `[20:24] == [24:28]` is w5 == w6, the per-antenna ttl_ref_time pair.

### Header EARFCN is the MEASURED carrier, not the serving one

In idle-mode intra-frequency samples the measured and serving EARFCNs
coincide, but they need not: on an LM960 per-channel survey the header hops
2300 → 900 → 66911 within ~1 s — no serving cell changes that fast — and
**30/30** F3-joined blocks (9/9 distinct `(earfcn, pci)` pairs, six EARFCNs)
carry the same EARFCN in the co-temporal `Ngbr meas req (earfcn,pci)` print,
with 29/30 same-tick `Ngbr Cell %d LL RSRP` positive controls matching ≤0.07 dB.
PCI 221 appears on both 975 and 2050 (co-sited) and each block is attributed to
the right carrier. So `(pci, header earfcn)` is the correct neighbour identity
key (`wigle_direct=True`).

### EARFCN attribution

The u32 at byte-offset 4 was first identified as the **EARFCN** by DIAG×AT
correlation on an LM960A18 (SDX20, 180/185 = 97.3%) and re-validated
cross-modem (Sierra MC7411/EM7511 + Telit LM960). `to_dict()` emits an
`earfcn` key (never `config_word`).

Log name: LOG_LTE_ML1_NEIGHBOR_MEASUREMENTS_PACKET
Also known as: LOG_LTE_ML1_NEIGHBOR_MEASUREMENTS
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

# Structural constants for the version-5 neighbor-measurement array form.
_HEADER_LEN = 12
_ENTRY_STRIDE = 32
_STRUCT_VERSION = 0x05
# v0x04 — older MDM9200 / Sierra MC7700 packing: 8B header + 28B block stride,
# and a u16 EARFCN where v0x05 uses u32 (sibling-consistent with 0xB17F v0x03).
_HEADER_LEN_V4 = 8
_ENTRY_STRIDE_V4 = 28
_STRUCT_VERSION_V4 = 0x04


def _bits(word: int, lo: int, width: int) -> int:
    return (word >> lo) & ((1 << width) - 1)


def _decode_block(block: bytes, version: int) -> dict[str, Any]:
    """Decode one neighbour block (F3-grounded, see module docstring).

    Shared word layout (v0x05 32 B = 8 u32 words; v0x04 28 B = words 0..6):
      w0[0:9]   pci                  GROUND (F3 ``Ngbr Cell %d``)
      w0[9:20]  rssi  /16 - 110 dBm  GROUND on v0x05 (F3 ``RSSI comb``); RAW on v0x04
      w0[20:32] rsrp  /16 - 180 dBm  GROUND (F3 ``LL RSRP`` of the *used* rx chain); == w1[0:12]
      w1[12:24] rsrp_alt_raw         CANDIDATE (same scale, ≤~1 dB off; no F3 match) == w2[0:12]
      w2[12:22] rsrq  /16 - 30 dB    GROUND (F3 ``LL RSRQ`` of the *used* rx chain); == w2[22:32]
      w3[0:10]  rsrq_alt_raw         CANDIDATE (same scale; no F3 match) == w3[10:20]
      w3[20:32] w3_hi_raw            RAW (tracks RSRQ on an integer scale; unnamed)
      w4        reserved (0 on 99.5% of corpus blocks)
      w5[11:30] ttl_ref_time_ant0    GROUND (F3 ``Ngbr meas req … ttl_ref_time ant0``)
      w6[11:30] ttl_ref_time_ant1    GROUND (F3 ``… ant1``)
      w5/w6[0:11], [30:32]           RAW (0x7FF / 2-bit flag)
      w7 (v0x05 only)                RAW trailer (low byte 0x45/0xC5; upper bytes unstable)
    An all-zero leading 24 bytes marks an unpopulated (padding) slot -> ``populated=False``.
    """
    n = len(block) // 4
    w = unpack_from("<%dI" % n, block, 0)
    populated = any(block[:24])
    out: dict[str, Any] = {"populated": populated}
    if not populated:
        return out
    out.update(
        pci=_bits(w[0], 0, 9),
        rsrp_dbm=_bits(w[0], 20, 12) / 16 - 180,
        rsrq_db=_bits(w[2], 12, 10) / 16 - 30,
        rsrp_alt_raw=_bits(w[1], 12, 12),
        rsrq_alt_raw=_bits(w[3], 0, 10),
        w3_hi_raw=_bits(w[3], 20, 12),
        ttl_ref_time_ant0=_bits(w[5], 11, 19),
        ttl_ref_time_ant1=_bits(w[6], 11, 19),
        w5_flags_raw=(_bits(w[5], 0, 11), _bits(w[5], 30, 2)),
        w6_flags_raw=(_bits(w[6], 0, 11), _bits(w[6], 30, 2)),
    )
    if version == _STRUCT_VERSION:
        out["rssi_dbm"] = _bits(w[0], 9, 11) / 16 - 110
        out["w7_raw"] = w[7]
    else:  # v0x04: bits 9..19 sit at a constant 0x640 on MC7700 — not RSSI-shaped
        out["w0_mid_raw"] = _bits(w[0], 9, 11)
    return out


@dataclass
class Diag0xB180:
    """0xB180 — LTE ML1 Neighbor Measurements packet.

    `earfcn` is the u32-LE at byte-offset 4 (u16 on v0x04; DIAG×AT-validated).

    For version-5 records sized `12 + 32*N`, the body is split into `N`
    fixed 32-byte measurement blocks (`cells`); `num_cells` is the
    authoritative block count `(payload_size - 12) // 32`. `neighbors` is the
    per-block decode — one F3-grounded NEIGHBOUR cell per block, all on the
    header `earfcn` (the measured carrier); padding slots are
    `populated=False`. A short or non-aligned payload — or a v0x05 one whose
    byte-8 bits [7:6] disagree with N mod 4 — is truncated, so the parser
    returns None.
    """
    log_time: int
    version: int
    earfcn: int
    num_cells: int
    cell_count_field: int
    cells: list[bytes]
    neighbors: list[dict[str, Any]]
    data_density: float
    payload_size: int
    body_raw: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB180",
            "log_time": self.log_time,
            "version": self.version,
            "earfcn": self.earfcn,
            "num_cells": self.num_cells,
            "cell_count_field": self.cell_count_field,
            "cells": self.cells,
            "neighbors": self.neighbors,
            "data_density": self.data_density,
            "payload_size": self.payload_size,
            "body_raw": self.body_raw,
        }


# Emission hardware-validated on a connected EG25-G.

@register(
    0xB180,
    name="0xB180",
    # WiGLE-direct: per-neighbour rsrp/rssi are F3-grounded, i.e. a WiGLE
    # `signal` (RSSI column); identity joins via (pci, header earfcn) ->
    # 0xB0C0 SIB1 exactly like siblings 0xB192/0xB195 (v0x05 only).
    wigle_direct=True,
    wigle_roles=("signal", "pci-earfcn-bridge", "rat-context"),
    description="0xB180 — LTE ML1 Neighbor Measurements packet (per-neighbour pci/rsrp/rsrq/rssi blocks, F3-grounded; v0x05: 12B header + N×32B blocks; v0x04: 8B header + N×28B blocks, MDM9200 u16 earfcn)",
    version=8,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Two layouts keyed on byte 0. v0x05: 12B header (u32@4 earfcn, first "
        "attributed by LM960A18 DIAG×AT correlation, 180/185) + N×32B blocks. "
        "v0x04 (older MDM9200 / Sierra MC7700 packing, exclusively MC7700 / "
        "SWI9200X, 276 records / 9 captures): 8B header with a u16@4 EARFCN + "
        "N×28B blocks. Each block is one NEIGHBOUR cell: pci w0[0:9], rssi "
        "w0[9:20]/16-110, rsrp w0[20:32]/16-180, rsrq w2[12:22]/16-30, "
        "ttl_ref_time w5/w6[11:30]; on v0x05 these are F3-grounded 1:1 on the "
        "same diag tick against lte_ml1_md.c 'Ngbr Cell' prints on MC7411 "
        "(203/203), LM960 (287/287) and T77W968 SDX55 (48/48). The header "
        "EARFCN is the measured carrier: on an LM960 per-channel survey 30/30 "
        "F3-joined blocks carry the EARFCN of the co-temporal 'Ngbr meas req "
        "(earfcn,pci)' print. v0x04 has no F3 plane (pre-QSH), so its EARFCN is "
        "grounded on the co-temporal 0xB0C0 serving-cell record: u16@4 == the "
        "0xB0C0 serving EARFCN in 100% of the 7 shared captures (2175 x5, 2300 "
        "x1), consistent with the sibling 0xB17F v0x03 decode (2300 == "
        "AT!GSTATUS); v0x04 block fields are a structural transfer. QCSuper "
        "produces a header-only pcap for this code (not in its export set) and "
        "SCAT does not decode it. Payloads that are not exactly header + N whole "
        "blocks, or whose v0x05 byte-8 bits [7:6] disagree with N mod 4, return "
        "None (registry warning)."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=11,
    fields_parsed=11,
    # byte-0 is the version (low byte of the u32 header tag 0x0000VVVV).
    # Corpus byte-0 at size>4 = {0x04, 0x05}; v0x05 decodes as the 12B header
    # + N×32B cell array, v0x04 as the 8B header + N×28B array with a u16@4
    # earfcn. Both gated below.
    field_invariants={"version": {"enum": [0x04, 0x05]}},
)
def parse_0xb180(log_time: int, data: bytes) -> Diag0xB180 | None:
    if len(data) < 1:
        return None
    version = data[0]
    if version not in (0x04, 0x05):
        return None

    # The payload must be exactly header + N whole
    # blocks (v0x05 12 + 32*N, v0x04 8 + 28*N). The block count has no explicit
    # length field, so a short or non-aligned payload is truncated (the last
    # block would be cut) — return None (registry warning) instead of a stub
    # record with num_cells=0. v0x05 additionally packs N mod 4 in bits [7:6]
    # of byte 8; a disagreement means whole blocks are missing -> None.
    if version == _STRUCT_VERSION:
        hdr_len, stride = _HEADER_LEN, _ENTRY_STRIDE
    else:
        hdr_len, stride = _HEADER_LEN_V4, _ENTRY_STRIDE_V4
    if len(data) < hdr_len or (len(data) - hdr_len) % stride:
        return None
    num_cells = (len(data) - hdr_len) // stride
    if version == _STRUCT_VERSION and (data[8] >> 6) != num_cells % 4:
        return None

    # EARFCN — version-specific width. v0x05 (modern silicon) reads the
    # DIAG×AT-validated u32@4; v0x04 (older MDM9200 / Sierra MC7700 packing)
    # reads a u16@4. Applying v0x05's u32@4 to a v0x04 frame yields a 7-digit
    # garbage channel number on all 276 v0x04 corpus records (cf. the sibling
    # 0xB17F v0x03 layout).
    if version == _STRUCT_VERSION_V4:
        earfcn = unpack_from('<H', data, 4)[0]
    else:
        earfcn = unpack_from('<I', data, 4)[0]

    nonzero = sum(1 for b in data[2:] if b != 0)
    density = round(nonzero / max(len(data) - 2, 1), 2)

    # Structural decode. v0x05: 12B header + N×32B blocks. v0x04: 8B header
    # + N×28B blocks. `cell_count_field` is the redundant/derived
    # count byte, surfaced RAW for verification only — at offset 8 for v0x05,
    # offset 6 for v0x04's shorter header. The authoritative block count is
    # size-derived (a MECHANICAL slice count — for v0x04 the 92/120 B records
    # zero-pad, so it can over-count real neighbours; see docstring).
    cell_count_field = data[8] if version == _STRUCT_VERSION else data[6]
    cells: list[bytes] = [
        data[hdr_len + stride * k : hdr_len + stride * (k + 1)]
        for k in range(num_cells)
    ]

    neighbors = [_decode_block(c, version) for c in cells]

    return Diag0xB180(
        log_time=log_time,
        version=version,
        earfcn=earfcn,
        num_cells=num_cells,
        cell_count_field=cell_count_field,
        cells=cells,
        neighbors=neighbors,
        data_density=density,
        payload_size=len(data),
        body_raw=data[1:],
    )
