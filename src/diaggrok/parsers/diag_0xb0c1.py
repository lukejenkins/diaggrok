"""0xB0C1 — LTE RRC MIB Message (legacy `CodeB0C1`).

**Full-body decode, F3-, black-box- and OTA-grounded.** The fixed 11 B v0x02 record is the RRC layer's log of one
decoded Master Information Block (``LTE_CPHY_MIB_IND`` from ML1), for the
serving cell *and* for neighbours / CSP-scan candidates whose PBCH the UE
decodes. Layout (little-endian, packed)::

    0  u8   version (0x02)
    1  u16  pci                 phys cell id, 0..503
    3  u32  dl_earfcn
    7  u16  sfn                 full 10-bit system frame number at decode
                                  (MIB's 8 MSBs + the 2 LSBs from the PBCH
                                  repetition index), 0..1023
    9  u8   num_tx_antennas     PBCH antenna ports {1, 2, 4} (blind-detected
                                  from the PBCH CRC mask, not an ASN.1 field)
    10 u8   dl_bandwidth_rb     MIB dl-Bandwidth as a resource-block count
                                  {6, 15, 25, 50, 75, 100} — NOT the ASN.1
                                  enum index (n6..n100 = 0..5)

Grounding (v0x02), all on captured records:

* **F3 (the firmware's own labels; nearest-tick join, 5 captures on 4
  chipsets extracted, MIB sites armed on 2)**: ``lte_rrc_sib.c:17295`` "MIB
  received for phy_cell_id = %d & freq = %d at SFN %d" → pci + dl_earfcn +
  sfn **22/22 exact** (LM960A18 SDX20 18/18, EG18-NA 4/4), one print per
  record within ≤1001 ticks — i.e. 1:1 co-emission; this is the emitting
  site. ``lte_ml1_md.c:7678`` "PBCH decode resp: MIB cell (%d,%d), BW %d #
  ant %d … sfn %d" → dl_bandwidth_rb (as RB, "BW 100") + num_tx_antennas +
  sfn **18/18** on the same cell. ML1 prints more decode responses (32) than
  RRC logs records (18): the record is the RRC-consumed MIB, not every
  PBCH attempt. RM500Q (SDX55) and T99W640 (SDX72) captures carry F3 but
  those sites were not armed — silent, not contradicting.
* **Black-box oracle (SCAT, output-only)**: SCAT's own decode of this code
  ("LTE MIB Info: EARFCN, SFN, Bandwidth, TX antennas") agrees with this
  parser on **307/307** lines across 35 captures (13 sequence-identical; in
  the rest every SCAT line is one of ours — SCAT prints a subset). Includes
  45 ``num_tx_antennas = 1`` lines (MC74xx, EARFCN 8665, 25 RB) that F3 never
  covered.
* **OTA oracle (MIB BCCH-BCH from the SCAT pcap, Wireshark ASN.1)**: of 412
  records in the same 35 captures, **220** match (dl_earfcn,
  dl_bandwidth_rb, sfn >> 2 == systemFrameNumber) exactly and 12 more match
  within one 40 ms PBCH TTI; 0 disagree on bandwidth. The rest have no OTA
  MIB logged at that instant (0xB0C0 does not log every BCH PDU). All-zero
  BCH PDUs in the pcap (n6, SFN 0) are placeholders, not MIBs.
* **Internal**: dl_bandwidth_rb == 0xB0C2.dl_bandwidth_rb on every record
  whose (pci, dl_earfcn) is the serving cell (223/223); the other records
  are neighbour/scan MIBs, which 0xB0C2 never reports.
* **All captures (5,258 records / 281 captures)**: all v0x02 / 11
  B; sfn high byte 0..3; num_tx_antennas ∈ {4: 4,053, 2: 1,093, 1: 112};
  dl_bandwidth_rb ∈ {100, 50, 25, 75, 6, 15} — every value lies in its 3GPP
  domain, so those domains are pinned as invariants below.
* **Odd values, reported verbatim**: a 6 RB MIB on EARFCN 5110 (EM9291) is
  confirmed by the OTA pcap (n6, systemFrameNumber 0x09 = SFN 39 >> 2), so
  the air interface really delivered it. A 15 RB / 1-port MIB on EARFCN 9260,
  whose other MIBs are 50 RB / 4-port, has no oracle — plausibly a false-CRC
  PBCH decode. EARFCN 43690 (0xAAAA, PCI 411, 100 RB, 2 ports) recurs on
  EM9291 and SCAT decodes the same bytes, but no OTA MIB exists for it; it is
  unexplained, not a layout error.

Network-side identifiers only (no subscriber PII).

Version enum: a black-box reference decoder also handles minor versions
**1 and 17**, which are **not attested** in any capture (all 5,258 records
are v0x02 / 11 B). The enum stays {0x02}; any other version returns None
(loud) rather than being decoded on a guessed layout.

Log name: LOG_LTE_RRC_MIB_MESSAGE
Also known as: LOG_MIB_MESSAGE, LOG_LTE_RRC_MIB_MESSAGE_LOG_PACKET, LTE RRC MIB Message Log Packet
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import Any

from diaggrok.registry import register


@dataclass
class Diag0xB0C1:
    """0xB0C1 — LTE RRC MIB message (v0x02, 11 B)."""
    log_time: int
    version: int
    pci: int
    dl_earfcn: int
    sfn: int
    num_tx_antennas: int
    dl_bandwidth_rb: int

    @property
    def dl_bandwidth_mhz(self) -> float | None:
        """Channel bandwidth in MHz for the signalled RB count (None if the
        RB count is outside the 3GPP set — the registry invariant flags it)."""
        return _RB_TO_MHZ.get(self.dl_bandwidth_rb)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB0C1",
            "log_time": self.log_time,
            "version": self.version,
            "pci": self.pci,
            "dl_earfcn": self.dl_earfcn,
            "sfn": self.sfn,
            "num_tx_antennas": self.num_tx_antennas,
            "dl_bandwidth_rb": self.dl_bandwidth_rb,
            "dl_bandwidth_mhz": self.dl_bandwidth_mhz,
        }


# Every captured record is v0x02 / 11 B. Size invariance
# != format invariance: another version at the same length is rejected, not
# decoded on the v0x02 layout.
_B0C1_VERSION_OBSERVED = 0x02
_B0C1_PAYLOAD_SIZE_OBSERVED = 11
_V2 = Struct("<BHIHBB")
assert _V2.size == _B0C1_PAYLOAD_SIZE_OBSERVED

# 3GPP TS 36.331 MasterInformationBlock dl-Bandwidth, as RB → MHz.
_RB_TO_MHZ = {6: 1.4, 15: 3.0, 25: 5.0, 50: 10.0, 75: 15.0, 100: 20.0}


@register(
    0xB0C1,
    name="0xB0C1",
    domain="rrc",
    wigle_direct=False,
    wigle_roles=("pci-earfcn-bridge",),
    description="0xB0C1 — LTE RRC MIB Message (fixed 11B v0x02; F3+SCAT+OTA-grounded pci, dl_earfcn, sfn, num_tx_antennas, dl_bandwidth_rb)",
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Full 11B body reverse-engineered from captures and "
        "grounded per field against in-capture F3 (lte_rrc_sib.c 'MIB received' "
        "1:1 co-emission; lte_ml1_md.c 'PBCH decode resp'), SCAT's black-box "
        "decode of this code, and the SCAT-pcap MIB OTA decode. Version and "
        "payload size are gated (v0x02, 11 B)."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=6,
    fields_parsed=6,
    field_invariants={
        "version": {"enum": [_B0C1_VERSION_OBSERVED]},
        "pci": {"range": (0, 503)},
        "sfn": {"range": (0, 1023)},
        "num_tx_antennas": {"enum": [1, 2, 4]},
        "dl_bandwidth_rb": {"enum": sorted(_RB_TO_MHZ)},
    },
)
def parse_0xb0c1(log_time: int, data: bytes) -> Diag0xB0C1 | None:
    if len(data) != _B0C1_PAYLOAD_SIZE_OBSERVED:
        return None
    if data[0] != _B0C1_VERSION_OBSERVED:
        return None
    version, pci, dl_earfcn, sfn, num_tx_antennas, dl_bandwidth_rb = _V2.unpack(data)
    return Diag0xB0C1(
        log_time=log_time,
        version=version,
        pci=pci,
        dl_earfcn=dl_earfcn,
        sfn=sfn,
        num_tx_antennas=num_tx_antennas,
        dl_bandwidth_rb=dl_bandwidth_rb,
    )
