"""0xB823 — LOG_NR5G_RRC_SERVING_CELL_INFO (NR5G RRC serving-cell snapshot).

Layout from a corpus body-walk: 326 records over 51 captures / 5 models (rm520,
em9291, em9190, rm500q, one unidentified drive). The versions are
distinguished by byte-0, with different field *presence* (not just offsets):

    byte-0   size   records
    0x04     38     127
    0x02     49     199

**Version 4 (38 bytes):**

    [0]      u8     version (4)
    [1:4]           reserved (0)
    [4:6]    u16le  pci          (physical cell id, 0..1007)
    [6:10]   u32le  nr_arfcn     (carrier / DL NR-ARFCN)
    [10:14]  u32le  nr_arfcn_2   (second frequency — UL or SSB ARFCN; the
                                  spacing from nr_arfcn varies across the
                                  corpus (~3 MHz .. ~400 MHz), so the exact
                                  DL/UL/SSB role is not pinned — value kept raw)
    [14:16]  u16le  dl_bandwidth (raw; {10,15,100} match NR channel BW in MHz)
    [16:18]  u16le  ul_bandwidth (symmetric with dl_bandwidth across corpus)
    [18:22]  u32le  nci          (NR Cell Identity low word)
    [22:26]  u32le  word_22      (0/1 across corpus — flag/count, left raw)
    [26:38]  bytes  tail_raw     (12-byte trailer — see below)

**Version 2 (49 bytes):** the same logical record with an NCGI block inserted
and a wider front header. v2 = v4 + 11 bytes:

    [0]      u8     version (2)
    [1:7]           sub-header (00 03 00 01 01 00 in-corpus — format markers)
    [7:9]    u16le  pci
    [9:13]   u32le  nci          (early copy — equals the late nci below)
    [13:17]  u32le  ncgi_marker  (NCGI/NCI upper dword — not a corpus constant.
                                  Observed values incl. 0x01300621 and
                                  0x01301840: the upper 16 bits (0x0130) are
                                  stable in-corpus, the lower 16 bits are
                                  cell-specific (part of the 36-bit NR Cell
                                  Identity, not a format marker). Records
                                  from one gNB share one value. Sibling 0xB821
                                  carries 0x0130 as the NCGI upper word; kept
                                  decoded + raw, unpinned.)
    [17:21]  u32le  nr_arfcn
    [21:25]  u32le  nr_arfcn_2
    [25:27]  u16le  dl_bandwidth
    [27:29]  u16le  ul_bandwidth
    [29:33]  u32le  nci          (canonical late copy — present in both versions)
    [33:37]  u32le  word_22      (the v2 analogue of v4's word_22)
    [37:49]  bytes  tail_raw     (identical 12-byte trailer shape as v4)

Cross-checks that anchor the layout: (1) the same physical cell (PCI 596) is
logged as v4 by RM500Q and v2 by EM9291 with byte-identical nr_arfcn /
nr_arfcn_2 / nci; (2) in every v2 record the early nci (@9) equals the late nci
(@29); (3) the per-version size gate ({v4:38, v2/v3:49}) rejects cross-version
residue. (The ncgi_marker upper-16 = 0x0130 is stable in-corpus but its lower-16
is cell-specific — see the field note above — so it is a weak hint, not a
layout-anchoring constant.)

**Version 3 (49 bytes) — SDX75 (Foxconn T99W640):** byte-for-byte the same
49 B layout as v2; only byte-0 (the release minor) differs (3 vs 2). The
modem reports its own chipset id as ``qcom-sdx75m``. One v3 record is
byte-identical to the in-corpus v2 EM9291 record except byte-0, and another
carries PCI 596 / NR-ARFCN 521310 / NCI 0xC6897138 — the exact T-Mobile n41
cell hardware-verified on the v4 path (RXM-G1). All hold the structural
invariants (early-nci == late-nci, sub-header ``00 03 00 01 01 00``); their
ncgi_marker == 0x01300621 because they are the same n41/gNB cell, not because
the field is a corpus constant (see field note above).

**Version-tuple note:** byte-0 is not the only version field. The record opens
with two little-endian 16-bit fields — ``u16@0`` = release MINOR (what this
module calls ``version``) and ``u16@2`` = release MAJOR. SCAT reads them as
``(rel_maj, rel_min) == (u16@2, u16@0)``. So v4 = SCAT (0,4), v2 = SCAT (3,2),
v3 = SCAT (3,3). This module keys on the minor (byte-0), which disambiguates
all observed layouts; if a future record ever shows a major-0 49 B form (a
hypothetical SCAT (0,2) colliding with v2's (3,2) on byte-0), the gate should
become a ``(major, minor)`` pair key.

**F3-VERDICT v0x02: GROUND (pci, nr_arfcn) — SDX62.** An RM520N-GL capture
with 100%-resolved F3 prints, co-temporal with **every** v0x02 record (Δ sub-ms
at 17.24 ns/tick), the CM-layer site ``tm_cm_iface_nonship.c:293  5G-NR CID
Update: … Freq=<nr_arfcn> PSC=<pci>`` for both cells in the capture::

    pci=260 nr_arfcn=501390  <->  "CID Update: TAC=45 Freq=501390 PSC=260 MCC=[3 1 0]"  (Δ~0.42 ms)
    pci=746 nr_arfcn=647328  <->  "CID Update: TAC=13 Freq=647328 PSC=746 MCC=[3 1 1]"  (Δ~0.98 ms)

The firmware's own ``Freq``/``PSC`` args match the v0x02 decode exactly.
Independently corroborated by QCSuper's NR-RRC ASN.1 decode of the same
capture, which reports serving ``physCellId 260`` (515/293 are
measurement-report neighbours). F3 contradicts no field. The CM layer reports
the NR cell id as the ``CID=0xFFFFFFFF`` sentinel (see the co-temporal
``tm_cm_iface_nonship.c:147 … CID=4294967295``), so F3 does not print the NCI
integer; ``nci`` is verified by AT/SCAT/QMI and the sibling 0xB825. A numeric
F3-correlation ranking on this capture surfaced only coincidental matches on
tail offsets, so the plaintext co-temporal text is the real witness.

**F3-VERDICT v0x04: GROUND (pci, nr_arfcn) — SDX55.** An RXM-G1 capture with
100%-resolved F3 prints, co-temporal with every v0x04 record (delta < 0.5 s;
158 prints bracket the 2 records), the NR5G ML1 site ``gts.c:2660``
(subsystem 85 = NR5G)::

    Proc NR5G. Sub %u Val %u %u BS %u TA %ld PCI %u %lu QT 0x%lx%08lx
    -> "Proc NR5G. Sub 0 Val 0 0 BS 0 TA 0 PCI 596 521310 QT 0x..."

The firmware's own ``PCI %u %lu`` args are ``596`` and ``521310`` — matching the
v0x04 decode ``pci=596`` / ``nr_arfcn=521310`` exactly. Independently
corroborated by QCSuper's NR-RRC ASN.1 decode of the same capture, which
reports serving ``physCellId 596`` (385/754 are measurement-report
neighbours). As on v0x02, F3 does not witness ``nci`` (the ML1/CM layers print
the CID sentinel, not the ``0xC6897138`` integer) — ``nci`` is verified by
AT/SCAT/QMI and the sibling 0xB825. The v0x04 F3 site is the ML1-layer
``gts.c``, distinct from the v0x02 CM-layer ``tm_cm_iface_nonship.c`` witness
above — same fields, different print sites on different silicon, which is why
each version is grounded on its own.

**F3-VERDICT v0x03: GROUND (pci, nr_arfcn, nr_arfcn_2=UL, dl/ul_bw, nci)
via SCAT + an AT survey; no F3 in the v0x03 captures.** The two available
v0x03 captures (SDX75 Foxconn T99W640 on T-Mobile — a cell-site survey and a
bring-up run) hold five v0x03 records over three distinct cells, every one on
gNB ncgi upper ``0x0130``. Two independent sources agree on every field:

* **SCAT NR-RRC ASN.1 SCell Info** decodes, from the survey capture, the
  serving cell's two aggregated n41 carriers::

      NR RRC SCell Info: NR-ARFCN 501390/499374  BW 100/100  Band 41  PCI 596  xCID 1c689712e
      NR RRC SCell Info: NR-ARFCN 521310/519324  BW  90/90   Band 41  PCI 596  xCID 1c6897138

  matching the v0x03 decode exactly — carrier[0] ↔ record {pci=596,
  nr_arfcn=501390, nr_arfcn_2=499374, dl/ul_bw=100, nci=0xC689712E} and
  carrier[1] ↔ {pci=596, nr_arfcn=521310, nr_arfcn_2=519324, dl/ul_bw=90,
  nci=0xC6897138}. SCAT's ``xCID`` low-32 == the decoded ``nci`` on both.
* **The AT cell-site survey** run alongside independently reports the same n41
  serving cell — ``pci=596``, two carriers ``nr_arfcn_dl/ul =
  501390/499374`` and ``521310/519324`` — matching pci / nr_arfcn (DL) /
  nr_arfcn_2 (UL) exactly.

Two consequences specific to v0x03:

* ``nr_arfcn_2`` is **the UL NR-ARFCN** — pinned by SCAT's SCell DL/UL pair
  and the AT survey's ``nr_arfcn_ul`` (exact on both carriers). The generic
  "role not pinned (DL/UL/SSB)" note applies to v0x02/v0x04, whose captures
  have no UL cross-check; on v0x03 it is UL. (The field is still decoded raw
  and named ``nr_arfcn_2``.)
* ``nci`` is **witnessed on v0x03** (SCAT ``xCID``), unlike v0x02/v0x04 where
  the CM/ML1 layers print the ``0xFFFFFFFF`` CID sentinel.

**F3 (0x79/0x99/0x92) is absent** in both v0x03 captures — they were
survey/bring-up runs with no QSH F3 maskset armed. The survey shows 40003
``0x98 DIAG_MULTI_RADIO`` frames, none wrapping F3 (0x79 / 0x99 / 0x92 counts
are all 0); the bring-up capture has no F3 at all. A future F3-armed T99W640
capture could pin the firmware print site (CM ``tm_cm_iface_nonship.c`` as on
v0x02, or ML1 ``gts.c`` as on v0x04), but the SCAT RRC ASN.1 decode already
grounds every field.

The 12-byte ``tail_raw`` (e.g. ``36 01 03 04 01 01 00 66 2d 00 29 00``) is
identical in shape across all versions; its sub-fields vary per cell but are
not confidently nameable without a reference decode, so it is left raw +
preserved. A shared size does not imply a shared format, so layout is
dispatched on byte-0 (the version) and size is gated to the per-version length
as corroboration.

Log name: LOG_NR5G_RRC_SERVING_CELL_INFO
Also known as: NR5G RRC Serving Cell Info
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any, Optional

from diaggrok.registry import register

# byte-0 (release MINOR; see version-tuple note below) → exact payload size
# observed in-corpus (used as a gate). v0x02 (SDX62/SDX65) and v0x03 (SDX75
# Foxconn T99W640) share the same 49 B layout — only the minor version byte differs.
_B823_SIZE_BY_VERSION = {0x04: 38, 0x02: 49, 0x03: 49}
# Not a corpus constant — this is the NCGI upper dword of the anchor fixture
# cells (PCI 596/455/260), which share one gNB. In the wider corpus
# ncgi_marker varies (e.g. 0x01301840 on PCI 746); only the upper 16 bits
# (0x0130, cf. 0xB821) are stable, the lower 16 are cell-specific. Kept as a
# named fixture value, not a pinned field_invariant.
_B823_NCGI_MARKER = 0x01300621
_B823_NCGI_UPPER16 = 0x0130      # stable upper half of ncgi_marker in-corpus

# --- Ground-truth recipe --------------------------------------------------
# v2 is the RM520N-GL (SDX62) emission: a corpus body-walk of RM520N-GL
# captures shows byte-0 == 0x02 (49 B) on every record (50/50 sampled).
# v4 (RM500Q SDX55) is the same logical record minus the NCGI block.

@dataclass
class Diag0xB823:
    """0xB823 — LOG_NR5G_RRC_SERVING_CELL_INFO."""
    log_time: int
    version: int
    pci: int
    nr_arfcn: int
    nr_arfcn_2: int            # second frequency (UL on v0x03; role not pinned on v0x02/v0x04)
    dl_bandwidth: int
    ul_bandwidth: int
    nci: int                   # NR Cell Identity low word (canonical late copy)
    tail_raw: bytes
    payload_size: int
    # v2/v3 only: NCGI upper dword (upper 16 bits 0x0130, lower 16 cell-specific). None on v4.
    ncgi_marker: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        d = {
            "type": "Diag0xB823",
            "log_time": self.log_time,
            "version": self.version,
            "pci": self.pci,
            "nr_arfcn": self.nr_arfcn,
            "nr_arfcn_2": self.nr_arfcn_2,
            "dl_bandwidth": self.dl_bandwidth,
            "ul_bandwidth": self.ul_bandwidth,
            "nci": self.nci,
            "tail_raw": self.tail_raw,
            "payload_size": self.payload_size,
        }
        if self.ncgi_marker is not None:
            d["ncgi_marker"] = self.ncgi_marker
        return d


@register(
    0xB823,
    name="0xB823",
    wigle_direct=True,
    wigle_roles=("identity", "pci-earfcn-bridge", "rat-context"),
    description="0xB823 — LOG_NR5G_RRC_SERVING_CELL_INFO {pci, nr_arfcn x2, bandwidth, nci, NCGI marker}",
    version=9,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail="LOG_NR5G_RRC_SERVING_CELL_INFO. Layout from a corpus body-walk (326 records / 51 captures / 5 models). Three minor-version layouts: v4=38B (SDX55), v2=49B (SDX62/SDX65), v3=49B (SDX75 T99W640 — same 49B layout as v2, only the minor byte differs). v2/v3 = v4 + early-NCI + NCGI upper dword (upper16 0x0130 stable, lower16 cell-specific; kept raw/unpinned) + wider front header. Decodes pci/nr_arfcn/nr_arfcn_2/dl_bw/ul_bw/nci per version. Anchored by PCI 596 logged as v4 (RM500Q) and v2 (EM9291) with identical nr_arfcn/nci, and v2/v3 early-nci==late-nci. Grounding per version: v0x02 pci/nr_arfcn/nci verified on an RM520N-GL Verizon n5-SA cell (pci=1/nr_arfcn=177150/nci=0x87EAC028) by exact equality across AT+QENG, SCAT RRC SIB1 NCGI 0x087EAC028 and QMI, nci cross-confirmed by co-captured 0xB825; v0x02 pci/nr_arfcn F3-grounded on tm_cm_iface_nonship.c:293 '5G-NR CID Update: Freq=<nr_arfcn> PSC=<pci>' for both cells of an RM520N-GL capture (260/501390, 746/647328), corroborated by QCSuper NR-RRC physCellId 260. v0x04 pci/nr_arfcn F3-grounded on an RXM-G1 capture's NR5G ML1 site gts.c:2660 'Proc NR5G ... PCI 596 521310', corroborated by QCSuper NR-RRC physCellId 596. On v0x02/v0x04 F3 prints only the CID sentinel, so nci rests on AT/SCAT/QMI + 0xB825. v0x03 grounded by SCAT NR-RRC SCell Info on both aggregated n41 carriers ('NR-ARFCN 501390/499374 BW 100/100 PCI 596 xCID 1c689712e', '521310/519324 BW 90/90 PCI 596 xCID 1c6897138'), matching pci/nr_arfcn/nr_arfcn_2/dl_bw/ul_bw/nci exactly (xCID low-32 == nci), plus an AT cell-site survey; nr_arfcn_2 is the UL ARFCN on v0x03. The v0x03 captures carry no F3. 12B tail kept raw.",
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=8,
    fields_parsed=8,
    field_invariants={
        # byte0 is the release MINOR (u16@0); see the version-tuple note in the
        # module docstring. v3 is the SDX75 (T99W640) minor.
        "version": {"enum": [0x02, 0x03, 0x04]},
    },
)
def parse_0xb823(log_time: int, data: bytes) -> Diag0xB823 | None:
    if len(data) < 1:
        return None
    version = data[0]
    expected_size = _B823_SIZE_BY_VERSION.get(version)
    if expected_size is None or len(data) != expected_size:
        return None

    if version == 0x04:
        pci = unpack_from('<H', data, 4)[0]
        nr_arfcn = unpack_from('<I', data, 6)[0]
        nr_arfcn_2 = unpack_from('<I', data, 10)[0]
        dl_bandwidth = unpack_from('<H', data, 14)[0]
        ul_bandwidth = unpack_from('<H', data, 16)[0]
        nci = unpack_from('<I', data, 18)[0]
        tail_raw = data[26:]
        ncgi_marker: Optional[int] = None
    else:  # version == 0x02 (SDX62/SDX65) or 0x03 (SDX75) — shared 49 B layout
        pci = unpack_from('<H', data, 7)[0]
        ncgi_marker = unpack_from('<I', data, 13)[0]
        nr_arfcn = unpack_from('<I', data, 17)[0]
        nr_arfcn_2 = unpack_from('<I', data, 21)[0]
        dl_bandwidth = unpack_from('<H', data, 25)[0]
        ul_bandwidth = unpack_from('<H', data, 27)[0]
        nci = unpack_from('<I', data, 29)[0]
        tail_raw = data[37:]

    return Diag0xB823(
        log_time=log_time,
        version=version,
        pci=pci,
        nr_arfcn=nr_arfcn,
        nr_arfcn_2=nr_arfcn_2,
        dl_bandwidth=dl_bandwidth,
        ul_bandwidth=ul_bandwidth,
        nci=nci,
        tail_raw=tail_raw,
        payload_size=len(data),
        ncgi_marker=ncgi_marker,
    )
