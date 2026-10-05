"""0xB197 — LTE ML1 Serving Cell Information (``LOG_LTE_ML1_SERVING_CELL_INFORMATION``).

All corpus records are **v=0x02 / 36 B** (7,470 records / 233 captures). The
serving-cell identity fields are exposed:

    offset 0 : u8    version            (corpus-invariant 0x02)
    offset 1 : u8    dl_bandwidth (RB)  {6,15,25,50,75,100} = 1.4/3/5/10/15/20 MHz;
                                        {0, 101} are the two "no-measurement" sentinels
    offset 4 : u32   earfcn             firmware-truncated to the low 16 bits
    offset 8 : u16   pci (low 9 bits)   + pci_word_hi (bits 9..15): two flag bits at
                                        u16 bit 9 & bit 14 (raw); not a populated/sentinel
                                        marker (see below)
    offset 20: 12 B  measurement region — all-zero exactly when byte 1 is a sentinel
    offset 34: u8    num_antennas       antenna count {1,2,(4)} — not the eNB Tx port
                                        count (see below); the value 3 coincides
                                        exactly with the byte-1 no-measurement sentinel

## The ``num_antennas`` field — SCAT grounded

Offset 34 is an **antenna count**, located by an A/B against the SCAT decoder
on a Sierra **EM9291** (SDX62) drive capture. SCAT renders 0xB197 as *"LTE ML1
Cell Info … Num antennas: N"*; a per-record composite-key join (``earfcn``/
``pci``/``dl_bandwidth``) against 265 corpus records matched byte-34 to SCAT's
``Num antennas`` on **237 / 237** records that SCAT rendered (28 SCAT-deduped
records had no join key), with **zero mismatches**:

- populated cells: byte-34 ∈ {1, 2} — 12× ``1``, 171× ``2`` — and the 1-vs-2
  split tracks SCAT per serving cell (e.g. B4 EARFCN 5230/PCI 303 → 1 antenna).
- the ``101`` no-measurement sentinel records: byte-34 == **3** on all 82, and 3
  never appears on a populated cell. LTE CRS antenna ports are {1, 2, 4}, so 3 is
  not a real port count — it is the antenna field's "no valid measurement"
  reading, coincident with the byte-1 sentinel and the zeroed measurement region.
  Corroborated on a *second* chipset: the T99W175 (SDX55) fixtures carry byte-34
  == 2 on populated cells and == 3 on the sentinel.

Exposed both ways (surface raw, decode conservatively): ``num_antennas_raw`` =
byte-34 verbatim; ``num_antennas`` = that value when it is a real CRS port count
{1, 2, 4}, else ``None`` — so the sentinel-coupled 3 can never be mistaken for a
genuine 3-antenna configuration (mirrors the ``dl_bandwidth`` sentinel→None
handling).

## ``num_antennas`` is not the eNB's Tx antenna-port count

On an SDX24 EM120R-GL survey (8 x 0xB197 v0x02) byte-34 reads **2** on both
serving carriers (5035/PCI 158 and 66786/PCI 242), while SCAT's **MIB** render of
the same capture reads **"TX antennas: 4"** on both carriers. A Tx-port count
cannot disagree with the MIB's. The same survey's QMI reports exactly **2 UE Rx
chains tuned**, so byte-34 fits the UE Rx-chain count (or an effective
min(Tx, Rx)); which one is not settled. The {1,2,4} / sentinel-3 -> None gate
applies either way. The same records' identity is grounded by F3
(``lte_rrc_sib.c:17725`` "phy_cell_id = 158 & freq = 5035",
``lte_rrc_plmn_search.c:8940`` "phy_cell_id=242 freq=66786"; 66786 & 0xFFFF ==
1250, see the truncation note below) and ``dl_bandwidth_rb`` 25 by
``lte_rrc_cap_ca_mgr.c:2533`` "cell_band: 12, cell_bw: 25 rb".

## F3 grounding

``earfcn`` and ``pci`` are grounded against the firmware's **own F3 prints** on a
Foxconn T99W175 (SDX55) RF-state capture (23 × 0xB197 records, F3 100%-resolved),
in addition to SCAT and ``AT#CSURV``:

- serving cell during the ``earfcn=800 / pci=148`` records ↔ F3
  ``tm_cm_iface_nonship.c:257`` *"LTE CID Update: TAC=39178 Freq=800 PSC=148"* and
  ``tm_umts_up_supl_no_ship.c:643`` *"PhyCellID=148 … Freq=800"* — an **exact**
  earfcn+pci match to the firmware's own serving-cell print.
- the sole ``byte-1 == 101`` record is the **only** one whose measurement region
  ``[20:32]`` is fully zeroed — corroborating that ``{0,101}`` are
  "no-measurement" sentinels, not RB counts.
- the bits above ``pci`` (``u16@8 >> 9``) are surfaced raw as ``pci_word_hi``
  (exposed, not named). They are **not** a populated/sentinel marker: the value
  33 on every populated record and 0 on the sentinel holds only on two
  low-variety captures (T99W175 ``{33 populated, 0 sentinel}``; EG25-G
  ``{33, 0}``). A SIM8202G-M2 (SDX55) drive capture carries
  ``pci_word_hi ∈ {0, 1, 32, 33}`` on populated records, and the value **flips
  between adjacent records of the same serving cell** (e.g. earfcn 56040/pci 412
  → both 1 and 0). Structurally it is **two independent flag bits**, at u16@8
  **bit 9** (``pci_word_hi`` bit 0, value 1) and **bit 14** (bit 5, value 32) —
  no other bit is ever set across the checked captures; T99W175/EG25-G simply
  always co-set both when populated. On SIM8202 bit 14 tracks a cell/carrier
  grouping (pci ~213–310 set it, pci ~405–412 clear it) — a lead, not
  F3-named. The meas-region-zeroed check and the byte-1/num_antennas sentinels
  are the reliable no-measurement signals.

## The earfcn truncation — a decoded caveat, not a parse guard

Offsets 6–7 are ``0x00`` in **all 7,470 corpus records**, including B66/B71 cells
whose true EARFCN exceeds 65535 (e.g. SCAT ``EARFCN 66786`` renders here as
``66786 & 0xFFFF == 1250``). The high 16 bits are gone before the record leaves
the modem, so ``earfcn`` below is the **low-16-truncated** value. It is exposed
(the low bits are still useful for cross-code correlation) but must not be trusted
as a usable absolute EARFCN on bands above ~65.

Version enum: SCAT handles a minor version 1 that the ``version`` enum (={0x02})
rejects. That version is **not attested in this corpus** (all 7,470 records are
v=0x02), so the enum is left strict rather than widened for a version only a
reference decoder knows.

Log name: LOG_LTE_ML1_SERVING_CELL_INFORMATION
Also known as: LTE ML1
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

_B197_VERSION_OBSERVED = 0x02
_B197_PAYLOAD_SIZE_OBSERVED = 36

# Canonical LTE DL bandwidths, expressed as their resource-block counts:
#   6 → 1.4 MHz, 15 → 3 MHz, 25 → 5 MHz, 50 → 10 MHz, 75 → 15 MHz, 100 → 20 MHz.
# byte 1 ∈ {0, 101} are the two "no-measurement" sentinels (0 on older chipsets,
# 101 == max-valid-RB + 1 on SDX55/SDX65-class NR parts) → decoded to None so a
# sentinel can never be mistaken for a bandwidth.
# Corroborated by SCAT, which labels byte-1
# "Bandwidth"/unit "PRBs", maps {25,50,100}→{5,10,20} MHz (this exact map), and
# passes the 101 sentinel through as raw "101 PRBs" — never a MHz value.
_VALID_DL_BANDWIDTH_RB = frozenset({6, 15, 25, 50, 75, 100})

# LTE CRS Tx antenna ports are {1, 2, 4} (36.211 §6.10). byte-34 == 3 is not a
# valid port count — it coincides exactly with the byte-1 no-measurement sentinel
# (82/82 sentinel records, 0 populated), so it is decoded to None like the
# dl_bandwidth sentinels rather than surfaced as a bogus 3-antenna config.
_VALID_ANTENNA_PORTS = frozenset({1, 2, 4})


@dataclass
class Diag0xB197:
    """0xB197 — LTE ML1 Serving Cell Information (v=0x02, 36 B)."""
    log_time: int
    version: int
    dl_bandwidth_rb: int | None
    dl_bandwidth_raw: int
    earfcn: int
    pci: int
    pci_word_hi: int
    num_antennas: int | None
    num_antennas_raw: int
    meas_region_zeroed: bool
    payload_size: int
    body_raw: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB197",
            "log_time": self.log_time,
            "version": self.version,
            "dl_bandwidth_rb": self.dl_bandwidth_rb,
            "dl_bandwidth_raw": self.dl_bandwidth_raw,
            "earfcn": self.earfcn,
            "pci": self.pci,
            "pci_word_hi": self.pci_word_hi,
            "num_antennas": self.num_antennas,
            "num_antennas_raw": self.num_antennas_raw,
            "meas_region_zeroed": self.meas_region_zeroed,
            "payload_size": self.payload_size,
            "body_raw": self.body_raw,
        }


@register(
    0xB197,
    name="0xB197",
    wigle_direct=False,
    wigle_roles=("pci-earfcn-bridge", "rat-context"),
    description="0xB197 — LTE ML1 Serving Cell Information (earfcn/pci/dl_bandwidth/num_antennas, F3+SCAT-grounded)",
    version=4,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "LTE ML1 Serving Cell Information. earfcn@4 (firmware-truncated to "
        "the low 16 bits) + pci@8&0x1FF F3-grounded on a T99W175 RF-state "
        "capture (tm_cm_iface_nonship.c 'Freq=800 PSC=148' ↔ decoded "
        "earfcn=800/pci=148); byte-1 dl_bandwidth {0,101}→None sentinels; "
        "num_antennas@34 SCAT-grounded on EM9291 (237/237 per-record match, "
        "{1,2,4}→value else None, 3⟺sentinel). v=0x02/36B on 7,470 records."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=5,
    fields_parsed=10,
    field_invariants={
        "version": {"enum": [_B197_VERSION_OBSERVED]},
        "payload_size": {"enum": [_B197_PAYLOAD_SIZE_OBSERVED]},
    },
)
def parse_0xb197(log_time: int, data: bytes) -> Diag0xB197 | None:
    if len(data) != _B197_PAYLOAD_SIZE_OBSERVED:
        return None
    version = data[0]
    if version != _B197_VERSION_OBSERVED:
        return None

    dl_bandwidth_raw = data[1]
    dl_bandwidth_rb = dl_bandwidth_raw if dl_bandwidth_raw in _VALID_DL_BANDWIDTH_RB else None

    earfcn = unpack_from('<I', data, 4)[0]  # low-16-truncated (bytes 6-7 == 0)
    pci_word = unpack_from('<H', data, 8)[0]
    pci = pci_word & 0x1FF
    pci_word_hi = pci_word >> 9

    num_antennas_raw = data[34]  # SCAT "Num antennas" (237/237 EM9291 match)
    num_antennas = num_antennas_raw if num_antennas_raw in _VALID_ANTENNA_PORTS else None

    meas_region_zeroed = not any(data[20:32])

    return Diag0xB197(
        log_time=log_time,
        version=version,
        dl_bandwidth_rb=dl_bandwidth_rb,
        dl_bandwidth_raw=dl_bandwidth_raw,
        earfcn=earfcn,
        pci=pci,
        pci_word_hi=pci_word_hi,
        num_antennas=num_antennas,
        num_antennas_raw=num_antennas_raw,
        meas_region_zeroed=meas_region_zeroed,
        payload_size=len(data),
        body_raw=data[1:],
    )
