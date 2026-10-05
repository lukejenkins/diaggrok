"""0xB0C2 — LTE RRC Serving Cell Info (legacy `LteRrcB0C2`).

**Full-body decode, F3- and OTA-grounded.**
The fixed 29 B v0x03 record is the RRC layer's summary of the camped cell:
the MIB bandwidth, the SIB1 identity (cell identity, TAC, PLMN, band
indicator) and the serving EARFCN/PCI, emitted once per camp / reselection /
SIB1 change. Layout (little-endian, packed)::

    0  u8   version (0x03)
    1  u16  pci                 phys cell id, 0..503
    3  u32  dl_earfcn
    7  u32  ul_earfcn           = dl + 18000 (FDD B2/B4/B12/B14/B17),
                                  dl + 65536 (B66), = dl (TDD B48)
    11 u8   dl_bandwidth_rb     6/15/25/50/75/100 RB (MIB dl-Bandwidth)
    12 u8   ul_bandwidth_rb
    13 u32  cell_identity       SIB1 28-bit E-UTRAN cell identity (ECI);
                                  enb_id = ECI >> 8, local_cell_id = ECI & 0xFF
    17 u16  tac                 SIB1 trackingAreaCode
    19 u32  band                SIB1 freqBandIndicator — NOT derived from the
                                  EARFCN: a B12 EARFCN 5110 on an MFBI cell
                                  reports 17 (B17 ⊂ B12)
    23 u16  mcc                 decimal, e.g. 310
    25 u8   num_mnc_digits      2 or 3
    26 u16  mnc                 decimal; render zero-padded to num_mnc_digits
    28 u8   allowed_access      CANDIDATE — see below

Grounding (v0x03), all on captured records:

* **F3 (the firmware's own labels; ±5 s tick join, 142 records / 22
  F3-bearing captures, anchors fired on EG25-G, NL668, LM960A18 SDX20,
  MC7411, RM500Q/EM120 surveys)**:
  ``emm_rrc_handler.c`` "RRC_SERVICE_IND - TAC %u, Cell ID %u" → tac +
  cell_identity **23/23** (14 distinct cells); ``lte_rrc_csp.c`` "CSP:
  Cell Identity = %d" 22/23; "CSP: Camped PLMN = MCC:[…] MNC:[…]" → mcc +
  mnc + num_mnc_digits **40/40**; ``lte_rrc_sib.c`` "Cell freq %d, Cell Id
  %d" → dl_earfcn + pci 21/23 (14 distinct) and ``lte_rrc_csp.c`` get-SIBs
  cnf "[EARCN:%d, PCI:%d]" 9/9; ``lte_ml1_md.c`` "PBCH decode resp: MIB cell
  (%d,%d), BW %d" → dl_bandwidth_rb **18/18**; ``lte_rrc_llcdb.c``
  "CACCInfoList: freq; band; is_pcc? 1" → band 6/6. The few misses are the
  neighbouring cell printed inside the window during a reselection.
* **OTA oracle (SIB1/MIB from the black-box SCAT pcap, decoded by
  Wireshark's ASN.1 dissector, joined on EARFCN ±10 s; 142 records / 62
  captures / ~20 models from MDM9207 to SDX65)**: cell_identity == SIB1
  cellIdentity **141/142** (52 distinct; tshark renders the 28-bit BIT
  STRING left-aligned, i.e. ``<< 4``); tac **142/142**; (mcc, mnc,
  num_mnc_digits) ∈ SIB1 plmn-IdentityList **142/142**; band ∈ SIB1
  {freqBandIndicator ∪ multiBandInfoList} **142/142**, of which 13 are the
  MFBI alternate, not the primary (so ``band`` is the UE-*selected* band);
  dl_bandwidth_rb == MIB dl-Bandwidth **141/141**.
* **Structure** — UL−DL EARFCN offset is exactly the 3GPP duplex offset on
  every record (18000 / 65536 / 0); PCI < 504 everywhere.
* ``allowed_access`` is exposed raw: 0 (611) / 1 (737) / 2 (154) across
  all captures. It is NOT the F3 ``lte_rrc_csp.c`` "cell_access_status" (3
  on every joined record, where this byte read 0 or 2). 0 shows on
  FirstNet/AT&T B14 cells under a non-AT&T SIM and during a manual PLMN
  scan, so it plausibly says whether the camp is suitable. That is a
  CANDIDATE, not grounded.
* **All captures**: 1,502 records / 257 captures, all v0x03 / 29 B; dl/ul
  bandwidth ∈ {25, 50, 75, 100} RB; ECI top byte < 0x10 (28-bit); band top
  byte 0; num_mnc_digits 3 everywhere (US-only captures).

``cell_identity``/``tac``/PLMN are network-side identifiers (WiGLE's LTE cell
key), not subscriber PII, but a real (EARFCN, PCI, ECI, TAC) tuple can locate
a capture site, so fixtures sentinel the ECI and TAC.

Version enum: a black-box reference decoder also handles minor version
**2**, which is **not attested** in any capture (all 1,502 records are
v0x03 / 29 B). The enum stays {0x03}; a v0x02 record returns None (loud)
rather than being decoded on a guessed layout.

Log name: LOG_LTE_RRC_SERV_CELL_INFO_LOG_C
Also known as: LOG_LTE_RRC_SERVING_CELL_INFO, LOG_SERVING_CELL_INFO, LOG_LTE_RRC_SERVING_CELL_INFO_LOG_PKT, LTE RRC Serving Cell Info Log Pkt
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import Any

from diaggrok.registry import register


@dataclass
class Diag0xB0C2:
    """0xB0C2 — LTE RRC serving cell info (v0x03, 29 B)."""
    log_time: int
    version: int
    pci: int
    dl_earfcn: int
    ul_earfcn: int
    dl_bandwidth_rb: int
    ul_bandwidth_rb: int
    cell_identity: int
    tac: int
    band: int
    mcc: int
    num_mnc_digits: int
    mnc: int
    allowed_access: int

    @property
    def enb_id(self) -> int:
        return self.cell_identity >> 8

    @property
    def local_cell_id(self) -> int:
        return self.cell_identity & 0xFF

    @property
    def plmn(self) -> str:
        """``MCC-MNC`` with the MNC zero-padded to its signalled width."""
        return f"{self.mcc:03d}-{self.mnc:0{self.num_mnc_digits}d}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB0C2",
            "log_time": self.log_time,
            "version": self.version,
            "pci": self.pci,
            "dl_earfcn": self.dl_earfcn,
            "ul_earfcn": self.ul_earfcn,
            "dl_bandwidth_rb": self.dl_bandwidth_rb,
            "ul_bandwidth_rb": self.ul_bandwidth_rb,
            "cell_identity": self.cell_identity,
            "enb_id": self.enb_id,
            "local_cell_id": self.local_cell_id,
            "tac": self.tac,
            "band": self.band,
            "mcc": self.mcc,
            "num_mnc_digits": self.num_mnc_digits,
            "mnc": self.mnc,
            "plmn": self.plmn,
            "allowed_access": self.allowed_access,
        }


# Every captured record is v0x03 / 29 B. Size invariance
# != format invariance: another version at the same length is rejected, not
# decoded on the v0x03 layout.
_B0C2_VERSION_OBSERVED = 0x03
_B0C2_PAYLOAD_SIZE_OBSERVED = 29
_V3 = Struct("<BHIIBBIHIHBHB")
assert _V3.size == _B0C2_PAYLOAD_SIZE_OBSERVED


@register(
    0xB0C2,
    name="0xB0C2",
    domain="rrc",
    wigle_direct=True,
    wigle_roles=("identity", "pci-earfcn-bridge", "rat-context"),
    description="0xB0C2 — LTE RRC Serving Cell Info (fixed 29B v0x03; F3+SIB1-grounded pci, dl/ul earfcn, dl/ul bw, cell identity, tac, band, mcc/mnc)",
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Full 29B body reverse-engineered from captures and "
        "grounded per field against in-capture F3 (lte_rrc_sib.c / "
        "lte_rrc_csp.c / emm_rrc_handler.c / lte_ml1_md.c prints) and the "
        "SCAT-pcap SIB1/MIB OTA decode. Version and payload size are gated "
        "(v0x03, 29 B). allowed_access remains a CANDIDATE."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=13,
    fields_parsed=13,
    field_invariants={
        "version": {"enum": [_B0C2_VERSION_OBSERVED]},
        "pci": {"range": (0, 503)},
    },
)
def parse_0xb0c2(log_time: int, data: bytes) -> Diag0xB0C2 | None:
    if len(data) != _B0C2_PAYLOAD_SIZE_OBSERVED:
        return None
    if data[0] != _B0C2_VERSION_OBSERVED:
        return None
    (version, pci, dl_earfcn, ul_earfcn, dl_bw, ul_bw, cell_identity, tac,
     band, mcc, num_mnc_digits, mnc, allowed_access) = _V3.unpack(data)
    return Diag0xB0C2(
        log_time=log_time,
        version=version,
        pci=pci,
        dl_earfcn=dl_earfcn,
        ul_earfcn=ul_earfcn,
        dl_bandwidth_rb=dl_bw,
        ul_bandwidth_rb=ul_bw,
        cell_identity=cell_identity,
        tac=tac,
        band=band,
        mcc=mcc,
        num_mnc_digits=num_mnc_digits,
        mnc=mnc,
        allowed_access=allowed_access,
    )
