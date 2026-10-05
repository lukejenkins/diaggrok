"""0xB17C — LTE ML1 Paging DRX info (per-cell paging-occasion config; legacy `LtePdcpB17C`).

**This is the ML1 paging-DRX record, not a neighbor-measurement packet.** The whole 20 B record is the binary twin of
the firmware F3 print ``lte_ml1_common_paging_drx.c``::

    Paging DRX info: cell (%d,%d) cycle %d Nb %d UE id %d cycle idx %d
    Paging Config: cycle %d Nb %d UEid %d T %d N %d Ns %d i_s %d sfn_off %d subfn_off %d

i.e. the 3GPP TS 36.304 §7.1 paging-occasion computation for one camped cell
(the alias ``LOG_LTE_ML1_PAGING_DRX_REQUEST`` from a newer item-type list
fits the content; the canonical "Neighbor Measurements Log Packet" name
does not). Layout::

    0  u8   version (0x02)          1..3 reserved (0 on every corpus record)
    4  u32  earfcn                  F3 `cell (EARFCN, …)`
    8  u16  pci                     F3 `cell (…, PCI)`
    10 u8   paging_cycle_idx        F3 `cycle idx`; T = 32 << idx radio frames
    11 u8   nb_idx                  F3 `Nb`; SIB2 nB enum {4T,2T,T,T/2,…,T/32}
    12 u16  ue_id                   F3 `UE id`; = IMSI mod 1024 (10-bit)
    14 u16  paging_sfn_offset       F3 `sfn_off`; PF = SFN mod T
    16 u8   paging_subfn_offset     F3 `subfn_off`; PO subframe (FDD 9 / TDD 0 @ Ns=1)
    17..19 reserved (0 on every corpus record)

``ue_id`` is IMSI-derived and is decoded; fixtures carry synthetic values
only.

The u32 at byte-offset 4 was first identified as the **EARFCN** of the
record's cell by DIAG×AT correlation on an LM960A18. `to_dict()` emits it
under an `earfcn` key (never the generic `config_word`), so consumers
keyed on `earfcn` keep working.

Single observed size: 20 B (99.3% of records).

Log name: LOG_LTE_ML1_NEIGHBOR_MEASUREMENTS_LOG_PACKET
Also known as: LOG_LTE_NEIGHBOR_MEASUREMENTS_LOG_PACKET, LOG_LTE_ML1_PAGING_DRX_REQUEST
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

# byte-0 version discriminator — corpus shows a single value
# 0x02 across all 610 records (fixed size 20). Layer-1 gate rejects any other.
_B17C_VERSIONS_OBSERVED = (0x02,)

# The full paging-DRX layout needs the whole fixed 20 B record.
_B17C_RECORD_LEN = 20

# SIB2 PCCH-Config nB enum → nB as a multiple of T (TS 36.331 / 36.304 §7.1).
NB_ENUM = ("4T", "2T", "T", "T/2", "T/4", "T/8", "T/16", "T/32")


@dataclass
class Diag0xB17C:
    """0xB17C — LTE ML1 paging-DRX record (legacy `LtePdcpB17C`).

    Each fixed-20B record is the paging-occasion config for one camped cell
    (see the module docstring for the F3 twin and full layout):

    * `earfcn` — u32-LE at byte-offset 4. **F3-grounded**: a
      co-temporal T99W175 `0x79` plaintext print
      (`… EARFCN:66786 …`) matches u32@4=66786 in the same capture, so this
      is the cell EARFCN, not just an in-band statistical match. For payloads < 8B the byte-1 fallback
      applies; for < 2B the slot is 0 (matches the `_simple_parser` contract).
    * `pci` — u16-LE at byte-offset 8 = the cell's PhysCellID.
      **F3-grounded**: a T99W175 SIM power-cycle capture
      caught a serving→neighbor reselection; its two 0xB17C records carry
      u16@8=471 and u16@8=236, matching the firmware's co-temporal
      `PhyId:471` / `PhyId:236` (`PhyCellID=236`) F3 prints exactly. PhyId
      471=0x1d7 requires bit-0 of byte-9, so byte-9 holds the PCI 9th bit;
      byte-9 is `∈ {0x00,0x01}` across all 1,026 corpus records (9-bit field,
      u16@8 ≤ 511).
    * `paging_cycle_idx` / `paging_cycle_rf` / `nb_idx` / `nb` / `ue_id` /
      `paging_sfn_offset` / `paging_subfn_offset` — bytes 10..16, the
      TS 36.304 §7.1 PF/PO computation (F3 `Paging DRX info` /
      `Paging Config` grounded). A sub-20 B (truncated) frame returns None
      from the parser.
    """
    log_time: int
    version: int
    earfcn: int
    pci: int
    paging_cycle_idx: int | None
    paging_cycle_rf: int | None
    nb_idx: int | None
    nb: str | None
    ue_id: int | None
    paging_sfn_offset: int | None
    paging_subfn_offset: int | None
    data_density: float
    payload_size: int
    body_raw: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB17C",
            "log_time": self.log_time,
            "version": self.version,
            "earfcn": self.earfcn,
            "pci": self.pci,
            "paging_cycle_idx": self.paging_cycle_idx,
            "paging_cycle_rf": self.paging_cycle_rf,
            "nb_idx": self.nb_idx,
            "nb": self.nb,
            "ue_id": self.ue_id,
            "paging_sfn_offset": self.paging_sfn_offset,
            "paging_subfn_offset": self.paging_subfn_offset,
            "data_density": self.data_density,
            "payload_size": self.payload_size,
            "body_raw": self.body_raw,
        }


@register(
    0xB17C,
    name="0xB17C",
    wigle_direct=False,
    wigle_roles=("pci-earfcn-bridge",),
    description="0xB17C — LTE ML1 Paging DRX info (fixed 20B; F3-grounded earfcn@4, pci@8, paging cycle/nB/UE_ID/PF/PO @10..16; legacy mislabel LtePdcpB17C)",
    version=7,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Fixed 20 B record (byte 0 = 0x02 on all 610 records): the ML1 "
        "paging-DRX config, the binary twin of F3 "
        "`lte_ml1_common_paging_drx.c` `Paging DRX info: cell (earfcn,pci) "
        "cycle Nb UE id cycle idx` / `Paging Config: … sfn_off subfn_off` "
        "(LM960, EM7565, SIM7600NA). earfcn=u32@4, first attributed by "
        "LM960A18 DIAG×AT correlation, is confirmed by a co-temporal T99W175 "
        "`EARFCN:66786` F3 print. pci=u16@8 is the cell's PhysCellID: a "
        "serving→neighbor reselection in a T99W175 SIM power-cycle capture "
        "emitted two records with u16@8=471 and 236, matching the firmware's "
        "`PhyId:471`/`PhyId:236` prints; byte 9 ∈ {0x00,0x01} on all 1,026 "
        "corpus records (~185 captures / 56 models), so the field is 9 bits "
        "wide (3GPP PCI max is 503). Bytes 10..16: paging_cycle_idx u8@10 "
        "(T=32<<idx), nb_idx u8@11 (SIB2 nB enum), ue_id u16@12 (IMSI mod "
        "1024), paging_sfn_offset u16@14, paging_subfn_offset u8@16. "
        "Grounding: (a) every F3 (earfcn,pci) cell that also appears in "
        "0xB17C carries the same cycle idx/Nb; (b) the TS 36.304 §7.1 PF/PO "
        "recomputation from (T,nB,UE_ID) reproduces u16@14 and u8@16 on every "
        "corpus record; (c) bytes 1..3 and 17..19 are zero on every record. "
        "Max earfcn in the corpus is 68,911 (within the 18-bit width); "
        "earfcn=0 search-mode records are valid. Payloads shorter than 20 B "
        "return None (registry warning)."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=8,
    fields_parsed=8,
    field_invariants={
        "version": {"enum": list(_B17C_VERSIONS_OBSERVED)},
        "earfcn": {"range": (0, 262143)},
        "pci": {"range": (0, 511)},
        # 36.331 defaultPagingCycle ∈ {rf32,rf64,rf128,rf256}.
        "paging_cycle_idx": {"range": (0, 3)},
        "nb_idx": {"range": (0, 7)},
        # IMSI mod 1024 — 10-bit.
        "ue_id": {"range": (0, 1023)},
        # PF offset < T ≤ 256; PO subframe index.
        "paging_sfn_offset": {"range": (0, 255)},
        "paging_subfn_offset": {"range": (0, 9)},
    },
)
def parse_0xb17c(log_time: int, data: bytes) -> Diag0xB17C | None:
    if len(data) < 1:
        return None
    version = data[0]
    # Layer-1 byte-0 version gate.
    if version not in _B17C_VERSIONS_OBSERVED:
        return None
    # The record is a fixed 20 B layout; a shorter payload is truncated ->
    # None (registry warning), not a part-filled record.
    if len(data) < _B17C_RECORD_LEN:
        return None
    if len(data) >= 8:
        earfcn = unpack_from('<I', data, 4)[0]
    elif len(data) >= 2:
        earfcn = data[1]
    else:
        earfcn = 0
    # pci = u16-LE @8 (F3-grounded PhysCellID). Absent on any
    # sub-10B foreign frame → 0 (the version gate already rejects those,
    # but keep the slice defensive to match the earfcn fallback style).
    pci = unpack_from('<H', data, 8)[0] if len(data) >= 10 else 0
    # Bytes 10..16 = paging-DRX config (F3-grounded).
    cycle_idx = nb_idx = ue_id = sfn_off = subfn_off = None
    cycle_rf = None
    nb = None
    if len(data) >= _B17C_RECORD_LEN:
        cycle_idx, nb_idx, ue_id, sfn_off, subfn_off = unpack_from('<BBHHB', data, 10)
        cycle_rf = 32 << cycle_idx if cycle_idx <= 3 else None
        nb = NB_ENUM[nb_idx] if nb_idx < len(NB_ENUM) else None
    if len(data) > 2:
        nonzero = sum(1 for b in data[2:] if b != 0)
        total = max(len(data) - 2, 1)
        density = round(nonzero / total, 2)
    else:
        density = 0.0
    return Diag0xB17C(
        log_time=log_time,
        version=version,
        earfcn=earfcn,
        pci=pci,
        paging_cycle_idx=cycle_idx,
        paging_cycle_rf=cycle_rf,
        nb_idx=nb_idx,
        nb=nb,
        ue_id=ue_id,
        paging_sfn_offset=sfn_off,
        paging_subfn_offset=subfn_off,
        data_density=density,
        payload_size=len(data),
        body_raw=data[1:],
    )
