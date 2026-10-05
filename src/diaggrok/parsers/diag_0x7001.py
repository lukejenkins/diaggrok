"""LTE RRC event parser -- compact decoded-event format (0x7001).

Parses the compact RRC event records first seen on SDX20/LM960 (NOT full
ASN.1 RRC PDUs). ``0x7001`` (canonical ``LOG_UMTS_CALL_FLOW_ANALYSIS``) is a
firmware **decoded-event struct** — a fixed-layout binary record (10-260
bytes) with byte-aligned fields — not a container for a raw over-the-air
message.

F3 grounding (v0xa1): PLMN and TAC vs the firmware's prints
-----------------------------------------------------------
Every F3-bearing capture of v0xa1 was joined capture-wide (279 captures, 296
streams; 419,395 records; 1,244 FE08 records carrying ``tac_off96``). The
firmware prints PLMN and TAC at attach / cell read (``qpDcm.c``
``MCC : %d, MNC : %d``, ``mmgsdi_ss_event.c ... PLMN: 0x%x``, ``tle_log.c`` /
``tle_base.cpp MCC:%d,MNC:%d,TAC:%d``, ``tm_cm_iface_nonship.c TAC=%d``,
``dsatetsicall_ex.c lte_tac:%d``), not within milliseconds of each record,
so the join compares the per-capture value sets:

* ``mcc`` / ``mnc``: on **181/181** captures where both sides exist, the
  records' PLMN set equals the F3-printed PLMN set (0 disagreements).
* ``tac_off96``: on **102/135** captures where both sides exist, the record's
  TAC is printed verbatim by the firmware (6 distinct TACs). On the other 33
  the record's TAC is simply not printed (the TAC-pattern hits there are
  unrelated small values such as 2 / 45 / 990); no conflicting real-TAC print
  was found. Record values 4 / 768 there look like the ``byte[6] == 0x07``
  sibling event the PLMN gate already excludes.

A generic co-emission pass shows the records sit on tech/coex state updates
(``rr_gprs_debug.c``, ``coex_algos.c``, ``lmtsmgr_*``). Its "pci" value matches
are coincidental: ``byte[6]`` is the 2-valued subtype discriminator (below).

FE08 header, SDX20 vs SDX62
---------------------------
The compact-format FE08 (260-byte) record header is **byte-identical between
SDX20 (LM960) and SDX62 (RM520N-GL)**: ``a1 <seq> 01 01 08 fe ...`` with
``byte[6] ∈ {0x07, 0x0a}`` on both.

* **``byte[6]`` (decoded as ``pci``) is a 2-valued message-subtype
  discriminator, NOT a 9-bit physical cell id** — it can only ever be 7 or 10
  on the FE08 record, on every chipset.
* **The FE08 header carries no serving/measured PCI** — two independent lines
  of evidence:
  1. **Structural** (one large survey, 3,858 FE08 records over 1,878 scanned
     sites): ``byte[6]`` takes ONLY ``{7, 10}`` and ``earfcn@14`` only ~2
     dominant values (``1794`` + the ``0xFF00`` sentinel). A real 9-bit
     PCI / per-cell EARFCN would vary widely across 1,878 sites.
  2. **Cross-grounding** against the sibling ``0xB193`` (LTE ML1
     measurement) co-captured on an RM520N-GL: ``0xB193`` shows the modem
     measured **pci=221 only**, earfcn ∈ ``{66536, 55540, 55342, 5230, 975}``
     (bands 66/71/13), while the co-temporal ``0x7001`` FE08 records decode
     **pci=const 10** and ``earfcn@14`` ∉ that set (bands 2/3).
  pci/earfcn/band are retained for SDX20-class back-compat + the legacy WiGLE
  path only; they are NOT a usable cell identity.
* **``tac_off96`` (FE08 offset 96)** is the SIB1-read cell's broadcast TAC,
  verified against AT+QENG / QMI / F3 on RM520N-GL; it is valid regardless of
  camp state (see the ``tac_off96`` note in ``parse_0x7001``).
* **``seq`` (``byte[1]``)** is a per-record monotonic-wrapping log sequence
  counter (0..255), +1 (mod 256) on 99.9 % of consecutive records across an
  18,495-record RM520N-GL survey; a cadence break flags a dropped/gapped DIAG
  record (capture-integrity signal). Shared SDX20/SDX62.

There is no embedded ASN.1 RRC PDU
----------------------------------
0x7001 carries no ASN.1 PDU to decode; writing a TS 36.331 uPER decoder for
it would be pointless. Four independent lines of evidence (an RM520N-GL
capture):

1. **Reference decoders don't touch it.** QCSuper and SCAT — the open-source
   LTE RRC OTA decoders — have no handling for 0x7001; they decode the real
   LTE RRC OTA log ``0xB0C0`` only. (0xB0C0 is co-present in the same
   capture, 116 records — that is where the genuine ASN.1 RRC PDUs live.)
2. **TAC is byte-aligned at a fixed offset (96).** A uPER-packed SIB1
   ``trackingAreaCode`` BIT STRING would not land byte-aligned at a constant
   offset across records — a fixed struct does.
3. **EARFCN is byte-aligned at a fixed offset (82).** Cross-validated across two
   captures with different serving cells (1000 on one; 0 on the other where LTE
   is non-serving, with neighbour EARFCNs at @250). Bit-packed ASN.1 would not.
4. **No region has an RRC message-type prefix or uPER entropy signature.** The
   record is a struct of counters, a system-time stamp (@26-29), and
   cell-measurement descriptors (@79-86 / @247-254).

So a full decode of 0x7001 means decoding the STRUCT fields that exist. The
28-bit ``cellIdentity`` + SIB scheduling live only in ``0xB0C0`` (real
ASN.1), but the **broadcast PLMN (MCC/MNC) is a byte-aligned field of this
struct** — a plain 3-octet TBCD value, not uPER.

MCC/MNC (FE08 SIB1 subtype)
---------------------------
The **serving/broadcast PLMN sits byte-aligned at FE08 offset 15-17 as a
3GPP TS 24.008 TBCD triple**, decoded ONLY on the SIB1 event subtype
(``pkt_type==0xFE08 AND byte[6]==0x0A``). On the FE03 event the same bytes
are a constant-looking config region. Multi-source verified on a registered
RM520N-GL drive capture (Verizon):
  * **AT+COPS** ``"Verizon Wireless"`` / numeric ``31148`` (on-modem ground truth)
  * **SCAT** decoding the real RRC ``0xB0C0`` SIB1 → ``MCC: 311, MNC: 480``
  * **FE08 @15 bytes** ``13 01 84`` → TBCD MCC 311 / MNC 480 (60/64 FE08 records)
  * **firmware F3** ``mmgsdi_ss_event.c:1113 "PLMN: 0x130014"`` (the exact TBCD
    dword) + ``tle_base.cpp:104 "MCC:310, MNC:260, TAC:11544, ..."``
Cross-carrier corroboration from the committed fixtures (each PLMN coherent with
its independently-known TAC/band): rm520n & m2000 ``13 00 62`` → 310/260
T-Mobile; fn980 ``13 00 14`` → 310/410 AT&T; em9190 ``13 01 84`` → 311/480 Verizon.
The gate matters: on scan captures the SIBLING FE08 event (``byte[6]==0x07``,
info_id 0xCAC/0xDC4) puts non-PLMN bytes at offset 15 that would decode to bogus
operators (MCC 703/503) - hence the ``byte[6]==0x0A`` discriminator.

**Chipset scope - SDX55/SDX62 only; SDX20 does NOT carry the PLMN here.** The
offset-15 PLMN is an SDX55/SDX62-layout field. On **SDX20** (an LM960 capture
registered on T-Mobile B66) the FE08 SIB1 records (byte[6]==0x0A) hold
``ff ff ff``/``00 00 00`` at offset 15 and carry NO TBCD PLMN at any offset
(all-offset scan of 83 SIB1 records: zero US-MCC hits) - SDX20's leaner FE08
carries only the TAC (at offset 64, the same offset split as ``tac`` vs
``tac_off96``). The decode is SAFE on SDX20 (``_decode_tbcd_plmn`` rejects the
0xFF/0x00 region → mcc/mnc=None), it simply does not fire. So 0x7001 yields
MCC/MNC on SDX55/SDX62 modems (RM500Q, RM520N-GL, M2000, FN980, EM9190) but
NOT on SDX20 modems (LM960, EG18).

**Decodable content (SDX55/SDX62, verified against AT/QMI/SCAT/F3):**
* ``mcc`` + ``mnc`` (@15-17, FE08 SIB1 subtype) - broadcast PLMN.
* ``serving_earfcn`` (@82) + ``serving_band`` — the real serving LTE EARFCN on
  the FE03 serving-cell event (@82 == QMI serving EUTRA ARFCN 1000). The
  legacy ``earfcn`` (@14) is the wrong offset (constant 891).
* ``tac_off96`` (@96) - the FE08 SIB1 record carries the read cell's
  broadcast TAC, coherent with the co-located @15 PLMN.
* ``seq`` (@1), ``pkt_type`` (@4), event-subtype discriminator ``byte[6]``.

**Structurally absent from 0x7001 (do NOT expect to decode):** serving PCI
and the 28-bit global ``cellIdentity``. They appear NOWHERE in the 260-byte
record at any width or offset (no F3-printed CellId appears at any u32 offset
in the FE08 body). So 0x7001 yields MCC/MNC/TAC/EARFCN but NOT PCI/CellID -
use 0xB193 (PCI) / 0xB0C0 (cellIdentity) for those.

Licensing note: an ASN.1 decoder (for 0xB0C0, not here) must be written from
spec on ``uper.UperReader`` — pycrate (LGPL) is never imported into this
Apache-2.0 library and serves only as an external subprocess cross-check.

Log name: LOG_UMTS_CALL_FLOW_ANALYSIS
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_LTE_RRC_OTA_SDX20
from diaggrok.parsers.lte_tables import earfcn_to_band
from diaggrok.registry import register

# FE08 SIB1 event discriminator: the record's message-subtype byte (byte[6], the
# field historically decoded as `pci`) takes value 0x0A on the SIB1 event that
# carries the broadcast PLMN, and 0x07 on the other FE08 event (info_id
# 0xCAC/0xDC4) where offset-15 is NOT a PLMN. Gating on this value is what
# keeps the PLMN decode from emitting plausible-but-wrong operators (MCC
# 703/503) off the non-SIB1 records.
_FE08_SIB1_SUBTYPE = 0x0A
_PLMN_OFFSET = 15  # 3GPP TS 24.008 TBCD PLMN, 3 octets @ FE08 offset 15-17


def _decode_tbcd_plmn(b3: bytes) -> tuple[str, str] | None:
    """Decode 3 octets of 3GPP TS 24.008 TBCD PLMN -> (mcc, mnc) digit strings.

    Octet layout (little-endian nibbles):
        octet0: [MCC2 | MCC1]   octet1: [MNC3 | MCC3]   octet2: [MNC2 | MNC1]
    MNC3 == 0xF is the 2-digit-MNC filler. Returns None on any out-of-range
    nibble or a zero leading MCC digit (never a valid PLMN) so a non-SIB1 or
    padding region rejects rather than yields a garbage operator.
    """
    if len(b3) != 3:
        return None
    mcc1, mcc2 = b3[0] & 0xF, b3[0] >> 4
    mcc3, mnc3 = b3[1] & 0xF, b3[1] >> 4
    mnc1, mnc2 = b3[2] & 0xF, b3[2] >> 4
    if any(d > 9 for d in (mcc1, mcc2, mcc3, mnc1, mnc2)):
        return None
    if mcc1 == 0:  # a real MCC never has a leading zero digit
        return None
    mcc = f"{mcc1}{mcc2}{mcc3}"
    if mnc3 == 0xF:
        mnc = f"{mnc1}{mnc2}"
    elif mnc3 <= 9:
        mnc = f"{mnc1}{mnc2}{mnc3}"
    else:
        return None
    return mcc, mnc


@dataclass
class Diag0x7001:
    log_time: int
    version: int             # u8 @ 0 — log version; corpus-observed 0xA1 (parser accepts 0xA0-0xA5)
    seq: int                 # u8 @ 1 — per-record monotonic-wrapping sequence counter (0..255).
                             # Structurally attested: increments +1 (mod 256) on 99.9% of
                             # consecutive 0x7001 records (RM520N-GL SDX62, 18,495-record
                             # survey). A break in the +1 cadence flags a dropped/gapped
                             # DIAG record — useful for capture-integrity checks. Shared across
                             # SDX20 (LM960) and SDX62 (byte-identical FE08 header). NOT a
                             # semantic protocol field; a transport-layer log counter.
    pkt_type: int            # u16 @4 — event-class / record-type selector. 0xFE03 (serving-cell
                             # info event, dominant), 0xFE08 (SIB/TAC event), 0xFE04/05/1E, the
                             # 0x05xx-0x10xx short-event family, 0x8808 (SDX62 per-carrier list).
    info_id: int             # u16 @8 — call-flow event / message identifier (the semantic core of
                             # this LOG_UMTS_CALL_FLOW_ANALYSIS record). FE03 serving-cell events
                             # carry a constant 0x2944 (10564); FE08 SIB/TAC events vary
                             # (observed {0x01BC, 0x1664, 0x0CAC} on RM520N-GL). 0 when <10 bytes.
    timestamp: int           # u32 @26 — modem free-running tick counter. Verified monotonic with
                             # log_time (316/317 + 23/23 agreement on RM520N-GL FE03). A
                             # per-record capture-time anchor; 0 when <30 bytes.
    meas_earfcn: int         # u16 @250 — measured/reported cell EARFCN (cell-entry block B). On
                             # FE03 it tracks the reported cell (serving 1000 on one capture;
                             # neighbour set {1100,5110,1125,...} on another); 0/0xFFFF (→0)
                             # when absent. Distinct from serving_earfcn (@82, block A).
    meas_band: int           # band derived from meas_earfcn (0 when meas_earfcn is 0).
    earfcn: int              # LEGACY @14 read — not an EARFCN (constant 891 on SDX55/62); kept
                             # for back-compat + the legacy wigle path only.
    pci: int                 # LEGACY @6 read — not a PCI (constant 214 on FE03; subtype 7/10 on
                             # FE08). See docstring. PCI is NOT carried by this log code at
                             # all — use the sibling 0xB193.
    band: int                # band derived from the legacy `earfcn` — also not usable.
    serving_earfcn: int      # u16 @ 82 — the real serving LTE EARFCN, present on the FE03
                             # serving-cell-info event (0 on FE08 SIB/TAC events and when LTE
                             # is not the serving RAT). Verified on RM520N-GL SDX62: FE03 @82
                             # == QMI GetCellLocationInfo serving EUTRA ARFCN 1000 (314/318
                             # records); on a capture with LTE non-serving, @82=0 and the
                             # neighbour EARFCNs sit at @250. 0 → not present.
    serving_band: int        # band derived from serving_earfcn (0 when serving_earfcn is 0).
    tac: int | None          # 0xFE08 offset 64 (SDX20 layout); None otherwise
    tac_off96: int | None    # 0xFE08 offset 96 (SDX55/SDX62 layout); None when <98B or zero.
                             # The SIB1-READ CELL's BROADCAST TAC — valid independent of camp
                             # state and not chipset-specific (M2000 SDX55 attached corpus).
                             # Not "registration-gated / stale when unregistered": all three
                             # unregistered fixtures read carrier-COHERENT values alongside the
                             # co-decoded broadcast PLMN @15-17 — decisively the FN980 (CEREG
                             # 0,0) three-way agreement PLMN 310/410 (AT&T) + EARFCN 4864
                             # (AT&T B12) + tac_off96 39178. That same 39178 is F3-verified as
                             # a real TAC on RM500Q-AE and RM520N-GL.
                             # Consequence: this is the READ cell's broadcast TAC, which need
                             # not equal the SERVING TAC when the modem is camped elsewhere;
                             # consumers wanting the attached TAC must use NAS/CEREG.
    mcc: str | None          # SIB1 broadcast Mobile Country Code (3 digits, e.g. "311").
                             # 3GPP TS 24.008 TBCD PLMN @ FE08 offset 15-17, decoded ONLY on the
                             # SIB1 event subtype (pkt_type 0xFE08 AND byte6==0x0A).
                             # Multi-source verified on a registered RM520N-GL capture:
                             # AT+COPS "Verizon Wireless"/31148 == SCAT 0xB0C0 SIB1 (MCC
                             # 311/MNC 480) == FE08 @15 bytes 13 01 84 == firmware F3 print
                             # mmgsdi_ss_event.c:1113 "PLMN: 0x130014" / tle_base.cpp:104
                             # "MCC:310, MNC:260 ...". None when not a SIB1 event or PLMN absent.
    mnc: str | None          # SIB1 broadcast Mobile Network Code (2 or 3 digits, e.g. "480").
                             # Same source/gate as `mcc`. 2-digit when the TBCD MNC filler nibble
                             # is 0xF, else 3-digit. None when `mcc` is None.

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x7001',
            'log_time': self.log_time,
            'version': self.version,
            'seq': self.seq,
            'pkt_type': self.pkt_type,
            'info_id': self.info_id,
            'timestamp': self.timestamp,
            'meas_earfcn': self.meas_earfcn,
            'meas_band': self.meas_band,
            'earfcn': self.earfcn,
            'pci': self.pci,
            'band': self.band,
            'serving_earfcn': self.serving_earfcn,
            'serving_band': self.serving_band,
            'tac': self.tac,
            'tac_off96': self.tac_off96,
            'mcc': self.mcc,
            'mnc': self.mnc,
        }


# Ground-truth recipe. v=0xA1 is the only corpus-attested version byte;
# RM520N-GL SDX62 emits this code with mcc/mnc and tac_off96 populated on
# SIB1-bearing events (pkt_type 0xFE08) and serving_earfcn on FE03. Short
# event packet types return earfcn/band/tac=0/None by design, so the
# validator must filter to populated records. tac_off96 is the read cell's
# broadcast TAC, so compare it against the PLMN/EARFCN in the same record
# rather than assuming it equals the attached TAC.

@register(LOG_LTE_RRC_OTA_SDX20, domain="rrc",
    primary_issue=None,
    name="0x7001",
    description="Compact RRC decoded-event records (LOG_UMTS_CALL_FLOW_ANALYSIS struct, no embedded ASN.1). Decodes broadcast PLMN (mcc/mnc) + TAC from FE08 SIB1 events, plus serving/measured EARFCN. F3-grounded v0xa1: mcc/mnc == firmware PLMN prints on 181/181 captures, tac_off96 printed verbatim on 102/135. mcc/mnc multi-source verified (AT+COPS == SCAT 0xB0C0 SIB1 == FE08 bytes == firmware F3 'PLMN: 0x130014') on a registered RM520N-GL. tac_off96 is the SIB1-read cell's broadcast TAC, valid regardless of camp state. PCI + 28-bit cellIdentity are structurally absent (use 0xB193/0xB0C0).",
    version=23,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE across SDX20 (Telit LM960), SDX55 (Quectel RM500Q-AE, "
        "Sierra EM9190, Telit FN980, Inseego M2000, Compal RXM-G1, Wistron "
        "NeWeb LV55) and SDX62 (Quectel RM520N-GL, CFW-3212). byte[5] declares "
        "the body length (len == 6 + byte[5], 24/24 sampled records, 23 event "
        "types); truncated payloads return None (registry WARN). TAC sits at "
        "two on-wire offsets on the same 0xFE08 pkt_type: offset 64 on SDX20 "
        "(LM960: tac 11544 == AT#RFSTS TAC, while offset 96 misreads) and "
        "offset 96 on SDX55/SDX62 (tac_off96). tac_off96 verified on several "
        "devices: RM500Q-AE 39178 == AT+QENG == QMI == firmware cell-DB F3 "
        "(tm_cm_iface_nonship.c 'LTE CID Update: TAC=39178', tle_base.cpp "
        "'TAC:39178'); RXM-G1 11544 == NAS CEREG attach TAC; RM520N-GL 11544 "
        "== AT+QENG and F3 'TAC=11544'; M2000 SDX55 attached corpus 11544 == "
        "T-Mobile TAC. tac_off96 is the read cell's broadcast TAC and stays "
        "carrier-coherent with the same record's PLMN on unregistered captures "
        "(FN980 310/410 + B12 + 39178). The legacy pci/earfcn/band reads are "
        "not cell identity: across RM520N-GL, CFW-3212, RM500Q-AE, LV55, "
        "RXM-G1 and LM960 the FE03 scan-SIB values (e.g. pci 214 / earfcn 891 "
        "or 1147) never match the F3- or QMI-witnessed serving PCI/EARFCN. "
        "mcc/mnc (FE08 @15-17 TBCD, byte[6]==0x0A gate) and serving_earfcn "
        "(@82) are multi-source verified on RM520N-GL."
    ),
    source_url="https://github.com/lukejenkins",
    # pkt_type, earfcn, pci, band, tac, tac_off96 — named physical quantities
    # for the SDX20 compact format plus the SDX55/SDX62 offset-96 TAC-candidate.
    # Short RRC-event packet types return earfcn/band/tac/tac_off96=0/None by
    # design (those fields aren't present in the wire format for those types).
    fields_identified=16,  # incl. mcc/mnc @15-17 FE08 SIB1 TBCD PLMN
    fields_parsed=16,
    wigle_direct=True,
    wigle_roles=("identity", "pci-earfcn-bridge", "rat-context"),
    # Byte 0 is the log version. Across real records (LM960 SDX20 corpus,
    # 844,913 records) the version byte is uniformly 0xA1; declare the canonical enum at the single corpus-
    # attested value. The parser body keeps the permissive 0xA0-0xA5
    # accept-range (the expected format-variant span) so an as-yet-
    # unobserved variant is surfaced by the Layer-2 invariant check rather
    # than silently rejected at Layer-1.
    field_invariants={"version": {"enum": [0xA1]}},
)
def parse_0x7001(log_time: int, data: bytes) -> Diag0x7001 | None:
    """Parse 0x7001 -- LOG_UMTS_CALL_FLOW_ANALYSIS (decoded-event struct).

    NOT a raw OTA / ASN.1 container — see the module docstring.
    Handles variable-size records (10-260 bytes). Packet types (pkt_type @4):
    - 0xFE03: serving-cell info event (dominant, 260B) — serving_earfcn @82
    - 0xFE08: SIB/TAC event (260B) — tac/tac_off96
    - 0xFE04/FE05/FE1E, 0x9Cxx: other 260/162B full events
    - 0x05xx-0x10xx: short-event family (10-22B)
    - 0x8808 (SDX62-only, 142B): per-carrier/SCG state list; structural stub

    COMPLETE 260-byte FE03/FE08 BYTE MAP (RM520N-GL SDX62, every byte
    accounted for: named field, or reserved/constant w/ observed value):
      @0    u8   version (0xA1)
      @1    u8   seq — monotonic-wrapping log counter
      @2-3  u16  const 0x0101 — record marker
      @4-5  u16  pkt_type (event-class selector); byte[5] == len - 6 (the
                 body length), so it is a length+subtype pair
      @6    u8   pci (LEGACY name; subtype byte: 214 on FE03; 7/10 on FE08)
      @7    u8   const 0x00
      @8-9  u16  info_id — call-flow event/message id (FE03 0x2944; FE08 varies)
      @10-13     sub-id / flags — usually 0, occasionally populated (event-specific)
      @14-15 u16 earfcn (LEGACY name — constant 891; NOT the real EARFCN)
      @15-17 3B  (FE08 SIB1 subtype byte[6]==0x0A only) broadcast PLMN - 3GPP
                 TS 24.008 TBCD -> mcc/mnc (e.g. 13 01 84 = 311/480). On FE03 and
                 the byte[6]==0x07 FE08 sibling this region is NOT a PLMN.
      @16-25     (FE03) const config region (e.g. 0b00 0f00 0100 7f000000)
      @26-29 u32 timestamp — modem tick counter (verified monotonic w/ log_time)
      @30   u8   state flag (0/1/2)
      @31-33     const
      @34-86     cell-entry block A (present iff serving cell): @82 serving_earfcn,
                 @84 serving_band; @79-81/@85-86 per-cell descriptor bytes (config-
                 like constants, NOT live RSRP); @40-65 a
                 0xFF-filled reserved/invalid-slot run when the block is populated.
      @87-201    reserved / padding (constant 0x00 across the RM520N-GL corpus)
      @202-258   cell-entry block B (mirrors A): @250 meas_earfcn, @254 meas_band;
                 @247-249/@251-252 descriptor bytes; @208-233 0xFF reserved run.
      @96   u16  (FE08 only) tac_off96 — the SIB1-read cell's broadcast TAC
                 (overlaps block A's reserved region on FE03 where it is not a TAC)
      @64   u16  (FE08 SDX20-layout only) tac
    Bytes not listed are constant 0x00/0xFF padding in the observed corpus.

    TAC extraction has two layouts:
    - SDX20 compact (LM960): 0xFE08 TAC at offset 64 -> ``tac``
    - SDX55 + SDX62 (M2000 / RM520N / EM9190 / FN980): 0xFE08 TAC at
      offset 96 -> ``tac_off96``. It is the **broadcast TAC of the cell
      whose SIB1 this record reports**, and it is valid *regardless of
      camp state* — neither chipset-gated nor registration-gated
      (M2000 SDX55 attached → 11544 = T-Mobile TAC, matching SDX62
      RM520N attached).

    **tac_off96 is not stale when unregistered.** With ``mcc``/``mnc``
    (the SIB1 broadcast PLMN @15-17) decoded from the same record, the
    unregistered captures are checkable — and all three read
    carrier-coherent:

    ==========================  =========  ==========  ==============
    fixture (camp state)        PLMN @15   tac_off96   corroboration
    ==========================  =========  ==========  ==============
    FN980   (CEREG 0,0)         310/410    39178       EARFCN 4864 =
                                                       AT&T B12 → 3-way
    EM9190  (not attached)      311/480    3328        PLMN-coherent
    M2000   (CEREG 0,1)         310/260    11544       EARFCN 4865 =
                                                       T-Mobile B11
    ==========================  =========  ==========  ==============

    A stale internal value has no mechanism to come out carrier-coherent
    three times out of three. The decisive case is FN980: **unregistered**
    yet PLMN, band and TAC independently agree on AT&T.

    The same value on FN980 (39178 = 0x990A) is F3-verified as a real TAC
    on two other devices (RM500Q-AE, RM520N-GL); it cannot be both a stale
    sentinel and firmware-witnessed ground truth.

    **Consumer consequence.** Because this is the *read* cell's
    broadcast TAC, it need not equal the *serving* TAC when the modem is
    camped elsewhere or merely scanning. Code that needs the attached
    TAC must take it from NAS/CEREG, not from this field.

    Returns None if the version byte is not recognized, or if the payload is shorter than the declared ``6 + byte[5]`` length.
    """
    if len(data) < 6:
        return None
    if data[0] not in (0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5):
        return None
    # Declared length: byte[5] — the high byte of the legacy pkt_type
    # u16 — is the body length after the 6-byte header (len == 6 + byte[5] on
    # every sampled record: 10 B 0x0408 .. 260 B 0xFE08). A shorter payload is
    # truncated: return None (registry WARN) rather than silently defaulting
    # the tail fields. Longer payloads are tolerated.
    if len(data) < 6 + data[5]:
        return None
    seq = data[1]  # per-record monotonic-wrapping sequence counter
    pkt_type = unpack_from('<H', data, 4)[0]
    # pci = data[6] is the SDX20-origin read. On the FE08 record (shared SDX20/
    # SDX62 layout) byte[6] takes only {0x07, 0x0a} — it is a 2-valued message-
    # subtype discriminator, NOT a 9-bit physical cell id. Cross-grounded against
    # the co-captured 0xB193 (LTE ML1) measurement set: on an RM520N-GL capture
    # the modem measured pci=221 only, yet 0x7001 FE08 decodes pci=const 10; and
    # the FE08 earfcn@14 values (bands 2/3) match NONE of the 0xB193-observed
    # EARFCNs {66536,55540,55342,5230,975}. The serving PCI / cell identity is
    # NOT carried by 0x7001 at all — an exhaustive offset search finds QMI PCI
    # 221 / Global Cell ID 3359264 at NO offset or width. (It is NOT in an
    # embedded ASN.1 PDU either — 0x7001 carries no PDU; the real ASN.1 RRC
    # lives in 0xB0C0.) pci/earfcn/band are retained ONLY for SDX20-class back-compat
    # and the legacy wigle path. Use 0xB193 (PCI) / 0xB0C0 (cellId) instead.
    pci = data[6] if len(data) > 6 else 0

    # info_id @8 — the call-flow event/message identifier (the semantic core of a
    # LOG_UMTS_CALL_FLOW_ANALYSIS record). FE03=0x2944 const; FE08 varies.
    info_id = unpack_from('<H', data, 8)[0] if len(data) >= 10 else 0
    # timestamp @26 (u32) — modem free-running tick counter; verified monotonic
    # with log_time on RM520N-GL FE03. Per-record capture-time anchor.
    timestamp = unpack_from('<I', data, 26)[0] if len(data) >= 30 else 0

    tac: int | None = None
    tac_off96: int | None = None
    mcc: str | None = None
    mnc: str | None = None
    if pkt_type == 0xFE08:
        if len(data) >= 66:
            val = unpack_from('<H', data, 64)[0]
            if 0 < val < 0xFFFE:
                tac = val
        if len(data) >= 98:
            val = unpack_from('<H', data, 96)[0]
            if 0 < val < 0xFFFE:
                tac_off96 = val
        # SIB1 broadcast PLMN (MCC/MNC) @ offset 15-17, 3GPP TS 24.008 TBCD.
        # ONLY on the SIB1 event subtype (byte[6]/`pci` == 0x0A); the sibling
        # FE08 event (byte[6]==0x07, info_id 0xCAC/0xDC4) puts non-PLMN struct
        # bytes at offset 15 that would otherwise decode to a bogus operator
        # (MCC 703/503). Multi-source verified (AT+COPS == SCAT 0xB0C0 SIB1 ==
        # FE08 bytes == firmware F3 "PLMN: 0x130014").
        if pci == _FE08_SIB1_SUBTYPE and len(data) >= _PLMN_OFFSET + 3:
            decoded = _decode_tbcd_plmn(data[_PLMN_OFFSET:_PLMN_OFFSET + 3])
            if decoded is not None:
                mcc, mnc = decoded

    # Extract EARFCN from full records (need at least 16 bytes)
    earfcn = 0
    band = 0
    if len(data) >= 16:
        earfcn = unpack_from('<H', data, 14)[0]
        if 0 < earfcn < 70000 and pci <= 503:
            band = earfcn_to_band(earfcn)
        else:
            earfcn = 0

    # Real serving LTE EARFCN @ offset 82 (260-byte full records). Present on the
    # FE03 serving-cell-info event; 0 on FE08 SIB/TAC events and when LTE is not the
    # serving RAT. Verified on RM520N-GL SDX62 against QMI GetCellLocationInfo
    # (@82=1000=serving EUTRA ARFCN, 314/318 FE03 records).
    serving_earfcn = 0
    serving_band = 0
    if len(data) >= 84:
        val = unpack_from('<H', data, 82)[0]
        if 0 < val < 70000:
            serving_earfcn = val
            serving_band = earfcn_to_band(val)

    # Measured/reported cell EARFCN @250 (cell-entry block B). Tracks the reported
    # cell (serving when camped; neighbour when measured). 0xFFFF/0 → absent.
    meas_earfcn = 0
    meas_band = 0
    if len(data) >= 252:
        val = unpack_from('<H', data, 250)[0]
        if 0 < val < 70000:
            meas_earfcn = val
            meas_band = earfcn_to_band(val)

    return Diag0x7001(
        log_time=log_time,
        version=data[0],
        seq=seq,
        pkt_type=pkt_type,
        info_id=info_id,
        timestamp=timestamp,
        earfcn=earfcn,
        pci=pci,
        band=band,
        serving_earfcn=serving_earfcn,
        serving_band=serving_band,
        meas_earfcn=meas_earfcn,
        meas_band=meas_band,
        tac=tac,
        tac_off96=tac_off96,
        mcc=mcc,
        mnc=mnc,
    )
