"""LTE ML1 Serving Cell Measurement Response parser (0xB193).

0xB193 -- LTE ML1 Serving Cell Meas Response
    Per-cell serving cell measurements: EARFCN, PCI, RSRP, RSRQ.
    Emitted periodically when the log mask is subscribed.

First reverse-engineered from SDX20 (LM960) DLF captures against AT+CSQ
survey data; the other per-cell layouts are documented below.

Payload structure:
    [0]      u8   version — corpus-invariant 0x01 (359,915/359,915 records). An
                  INERT gate: it discriminates nothing.
    [1]      u8   num_subpackets (1 on every observed record)
    [2:4]    u16  counter — a per-capture config/instance marker, NOT an SFN
                  (it reads 44084 / 63629 on real records, 43-62x the max LTE
                  SFN of 1023)
    [4]      u8   subpacket_id (25)
    [5]      u8   *** subpacket_version — THE structural discriminator ***
    [6:8]    u16  subpacket_size (includes the 4-byte subpacket header). NB the
                  parser deliberately does NOT bound the body with it — the body
                  runs to end-of-payload and the per-cell stride is DERIVED from
                  that length, so honouring sp_size here would change the stride.

Subpacket data (payload offset 8):
    [0:4]    u32  EARFCN (low 18 bits) — verified on every version, and the ONLY
                  field ahead of every observed per-cell drift
    [4:6]    u16  num_cells        (v3/v18 instead pack the serving cell inline)
    [6:8]    u16  num_rx_antennas

THE PER-CELL LAYOUT IS KEYED ON subpacket_version, WHICH TRACKS THE CHIPSET.
Ten versions are corpus-observed (the share column is from a full walk of 807
captures / 482 with records / 359,915 records, before v40 appeared). There is
NO single per-cell layout — the table below is the map, and each version's
constants block carries its evidence:

    ver  share  silicon / modems              per-cell layout        signal
    ---  -----  ----------------------------  --------------------  --------------
    59   38.9%  SDX62 RM520N-GL, EM9291       PCI@cell+8 (bit15=srv) 12-bit @+44/+56
    36   28.9%  SDX20 LM960, EG18-NA          PCI@cell+0             RSRP x16 @+20,
                                                                    RSRQ x16 @+36
    35   17.6%  SDX50M MC7411, MDM9x50 EM75xx PCI@cell+0             REFUTED (F3 +7 dB)
    48    6.8%  SDX55 LV55, RM500Q, EM9190    PCI@cell+4 (12B hdr)   RSRP x16 @+28
    50    4.2%  SDX55 FN980, EM9190           v59 family             v59 scale ✓
    18    3.2%  MDM9207 EG25-G, MDM9230       serving INLINE @sp+4   not RE'd
    3     0.2%  MDM9200 MC7700                serving INLINE, 4B hdr not RE'd
    22    0.1%  EP06-A                        PCI@cell+0             not RE'd
    56   <0.1%  SDX62 RM520N-GL               v59 family             v59 scale ✓
    40   (893)  SDX24 EM120R-GL, EM160R-GL    PCI@cell+0, FIXED      RSRP x16 @+36,
                                              4x132 B cell array     RSRQ x16 @+48 b20

An UNKNOWN version emits the carrier header and ZERO entries — never another
version's offsets. Guessing fabricates a PCI and a dBm: v50 read under another
version's offsets decodes its antenna mask as "PCI 3" on all 15,145 records
("size invariance != format invariance", in its VERSION form).

RSRP/RSRQ ARE NOT DECODABLE ON EVERY VERSION, AND THAT IS DELIBERATE. Only v36,
v40, v48 and the v59 family (v50/v56/v59) carry a grounded dBm scale — all x16
fixed-point. On v3/v18/v22/v35 the signal fields are None because the candidate
field is REFUTED (it is wideband RSSI / a linear energy, not dBm) or ungrounded.
Emitting a plausible-but-wrong dBm is worse than emitting None: it flows into
wigle_direct as a measurement. Do NOT "restore" any of them without a
WIDE-RSRP-SWEEP (>=15-20 dB) capture with co-temporal truth — a stationary camp
cannot tell a real field from a constant look-alike (on v36, a single stationary
capture sat exactly where a wrong field crosses the truth line; see its
constants block). The bar v36 met: 45 dB of sweep, own-F3 pairing on the raw
tick, AND a truth-free TS 36.214 closure. Meeting two of the three is not
meeting it.

Per-cell stride: DERIVED as (len(body) - 8) / num_cells — the wire carries no
stride field (v48 uses its 12 B header instead of 8; v40 is a fixed array).

Techplayon's public log-packet field list names the 0xB193 fields:
    0xB193 — LTE ML1 Serving Cell Meas Response
        earfcn, pci, serving_cell_index, cell_timing_offset,
        rsrp_inst_rx0_dbm, rsrp_inst_rx1_dbm, rsrp_combined_dbm,
        rsrq_rx0_db, rsrq_rx1_db, rsrq_instantaneous_db,
        rssi_rx0_dbm, rssi_rx1_dbm, rssi_instantaneous_dbm,
        residual_freq_error_hz, ftl_snr_rx0_db, ftl_snr_rx1_db

Log name: LTE ML1 Serving Cell Meas Response
Also known as: LOG_LTE_ML1_SERVING_CELL_MEAS_RESPONSE
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_LTE_ML1_SERVING_CELL_MEAS_RSP
from diaggrok.registry import register


@dataclass
class LteMl1ServingCellMeasEntry:
    """A single per-cell measurement from 0xB193.

    ``pci``/``earfcn`` are the GROUNDED fields: they decode on every version the
    parser emits (each anchored against AT and/or a co-captured, independently
    verified DIAG code — 0xB116 config_word, 0xB0C0, 0xB192).

    ``rsrp``/``rsrq`` are ``None`` far more often than not, BY DESIGN. A dBm is
    emitted only where a scale is genuinely grounded:

      * v48 (SDX55)                — rsrp only (single-cell): x16 fixed-point,
                                     pinned against the modem's own F3 (resid
                                     0.14 dB).
                                     rsrq: candidates located, not locked.
      * v50 / v56 (the v59 family) — rsrp+rsrq: v59's bit-exact scale, matched to
                                     AT #RFSTS at every quantile (median delta
                                     -0.31 / -0.25 dB).
      * v59 (SDX62)                — rsrp+rsrq for the SERVING cell only
                                     (``serving_flag == 1``). Non-serving cells
                                     read ~3-8 dB low vs AT+QENG -> gated to
                                     None; their
                                     pci/earfcn identity IS still valid.
      * v36 (SDX20)                — rsrp+rsrq for SINGLE-cell records: x16
                                     fixed-point RSRP @cell+20 (raw/16-180) and
                                     RSRQ @cell+36 (raw/16-30), grounded on a
                                     45 dB wide-sweep drive capture. Own-F3
                                     tick-paired max err 0.032 dB; AT#LAPS median
                                     -0.31 / +0.05 dB; TS 36.214 identity closes
                                     onto the carriers' true N_RB.
      * v40 (SDX24)                — rsrp+rsrq for SINGLE-cell records: within
                                     1 LSB of the same-tick 0xB17F (551/551).
      * v3 / v18 / v22 / v35       — ALWAYS None. The candidate field is REFUTED
                                     (wideband RSSI / a linear energy, not dBm —
                                     v35 is +7.0 dB vs its own F3) or never RE'd.

    A None here means "we do not know", NOT "no signal". Do not substitute a
    default, and do not drop the observation — the pci/earfcn identity carries two
    of this code's three wigle_roles ("pci-earfcn-bridge", "rat-context") on its
    own. Emitting a plausible-but-wrong dBm is the failure mode this parser exists
    to avoid.
    """
    pci: int
    earfcn: int
    rsrp: float | None  # dBm; None unless a grounded scale exists (see the class docstring)
    rsrq: float | None  # dB (primary Rx); None unless grounded — v48 rsrq is NOT
    serving_flag: int | None = None  # 1 = PRIMARY CELL OF THIS CARRIER'S RECORD — *not* "the
                                     # globally serving cell". v59: bit15 of the PCI word. The
                                     # name is kept for consumer compatibility, but read it as
                                     # carrier-local: a carrier the UE is NOT camped on still sets
                                     # bit15 in its own record. On an RM520N-GL limited-service
                                     # capture, 262/262 records set bit15 across FIVE distinct
                                     # (earfcn, pci) — 5230/1, 66661/473, 5110/268, 5230/310,
                                     # 66986/473 — only one of which was the camped cell. That is
                                     # why the v59 non-serving signal gate also applies on carriers
                                     # the UE is not camped on.
                                     # v50/v56: derived (single-cell record). NB bit15 is NOT a
                                     # primary flag outside v59 — v50's serving cell has bit15=0.
    meas_type: str | None = None     # v59 family: RX-antenna mask -> "intra_2rx" (0x3) / "inter_4rx" (0xF)

    def to_dict(self) -> dict[str, Any]:
        return {
            'pci': self.pci,
            'earfcn': self.earfcn,
            'rsrp': self.rsrp,
            'rsrq': self.rsrq,
            'serving_flag': self.serving_flag,
            'meas_type': self.meas_type,
        }


@dataclass
class Diag0xB193:
    """LTE ML1 Serving Cell Measurement Response (0xB193)."""
    log_time: int
    version: int
    subpacket_version: int
    # Outer-frame [2:4] u16 per-capture config/instance marker (NOT an SFN — it
    # reads 44084 / 63629 on real records, 43-62x the max LTE SFN of 1023). An
    # UNCONDITIONAL layout field present on every subpacket version, so it is
    # diffed as a RAW_FIELD (unlike num_cells, which v18 synthesizes). Exposed
    # for parity with the same-family sibling 0xB192, which exposes the
    # identical outer counter.
    counter: int
    earfcn: int
    num_cells: int
    payload_size: int = 0
    entries: list[LteMl1ServingCellMeasEntry] = field(default_factory=list)
    # v48 (SDX55) record-level enrichment — populated ONLY on
    # subpacket_version 48, None everywhere else. Additive; NOT a RAW_FIELD (these
    # join the punted-enrichment tier alongside `entries`, so the 3-way diff is
    # untouched). See the _V48_VALID_RX_OFF / _V48_SFN_OFF constants block.
    valid_rx: int | None = None      # sp+6 u16: valid-Rx-antenna mask (0x3 = 2 Rx, 0xF = 4 Rx)
    sfn: int | None = None           # sp+16 bits0..9: LTE system frame number (0..1023)
    sub_fn: int | None = None        # sp+16 bits10..13: subframe number (0..9)

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0xB193',
            'log_time': self.log_time,
            'version': self.version,
            'subpacket_version': self.subpacket_version,
            'counter': self.counter,
            'earfcn': self.earfcn,
            'num_cells': self.num_cells,
            'payload_size': self.payload_size,
            'valid_rx': self.valid_rx,
            'sfn': self.sfn,
            'sub_fn': self.sub_fn,
            'entries': [e.to_dict() for e in self.entries],
        }


# Minimum payload: 2-byte outer header + 4-byte subpacket header + 8-byte
# subpacket data header = 14 bytes. Realistic payloads are 528 bytes.
_MIN_PAYLOAD = 14
# Offset of subpacket data within payload.
_SUBPACKET_DATA_OFFSET = 8
# The subpacket header (id u8, version u8, size u16) starts after the 4-byte
# outer header; its declared size spans header + data.
_SUBPACKET_HDR_OFFSET = 4
# Size of the per-carrier header within subpacket data (EARFCN + counts).
_CARRIER_HEADER_SIZE = 8
# ...EXCEPT on v48 (SDX55), the one version whose carrier header is 12 B.
# The cell array therefore starts at sp+12 there, and — critically — the DERIVED
# per-cell stride must divide the space AFTER that header: (len(sp) - 12) / n.
#
# WHY THIS IS ITS OWN CONSTANT AND NOT AN OFFSET FUDGE. Using the generic 8 for
# BOTH the stride divisor and the cell base on v48, and compensating by shifting
# the in-cell offsets (PCI +4, RSRP +28 over the 8 B base), gives the right
# answer at num_cells == 1 only: the two errors cancel EXACTLY (8+4 == 12+0;
# 8+28 == 12+24). At num_cells > 1 they do not cancel — the STRIDE is wrong, so
# cell[1..] land at wrong offsets. The per-cell size is a physical invariant of a
# version, and only the 12-base derivation holds it constant across the corpus:
#
#     num_cells   sp_len   (len-8)//n   (len-12)//n
#     1           152      144          140
#     2           292      142          140
#     3           432      141          140
#
# A cell that shrinks as cells are added is impossible. The 12-base derivation
# also TILES the buffer exactly at every observed n (12 + n*140 == sp_len for
# n=1/2/3), while the 8-base one is a byte short at n=3 (8 + 3*141 = 431 != 432,
# lost to floor division) — a geometry that does not tile is not the geometry.
# Secondary tell: on the multi-cell fixtures the 8-base walk reads PCI 0 for
# EVERY extra cell ([463, 0] / [463, 0, 0]) where the 12-base walk reads varied
# plausible values ([463, 172] / [463, 147, 172]).
#
# 46 corpus records (32 n=2 + 14 n=3, on LV55 / RM500Q / Inseego M2000) are
# multi-cell v48. Their RSRP slot is garbage under BOTH geometries (cell 0
# included) and would fail the -140..-30 plausibility filter, which `continue`s
# past the whole entry and discards the VERIFIED pci/earfcn with it — so the
# multi-cell signal gate in parse_0xb193 is what lets the identity survive.
_V48_CARRIER_HEADER_SIZE = 12
# Smallest sane DERIVED per-cell stride. The wire carries no stride field — it is
# floor((len(body) - 8) / num_cells) — so a garbage num_cells drives the stride
# toward 0, at which point every "cell" re-reads cell_offset 0 and the parser
# emits num_cells IDENTICAL duplicates. 4 B is the minimum that can hold the PCI
# u32 every layout starts from; anything smaller means num_cells is not a count.
_MIN_STRIDE = 4

# v59 (SDX62 RM520N-GL / RG520N) per-cell BITFIELD layout, RE'd from a
# 28,879-record capture by bit-slice correlation against time-aligned AT
# QENG/QRSRP/QRSRQ truth, cross-checked against the UE's own RRC
# MeasurementReport and a weak-signal F3 capture. Per-cell record (148 B stride
# from sp+8):
#   cell+0   u32  valid-RX-antenna bitmask (0x3 = 2-RX intra meas,
#                 0xF = 4-RX inter-freq gap meas)
#   cell+4   u8[4] antenna indices (ffff0100 on 2-RX, 03020100 on 4-RX)
#   cell+8   u32  bits 0..8 PCI, bit 15 = carrier-record PRIMARY flag
#                 (NOT "the globally serving cell"; see LteMl1ServingCellMeasEntry)
#   cell+28  u32  bits 0..11 rsrp_inst_rx0 (raw/16 - 180 dBm; carrier-level,
#                 repeated in every cell of the record on the 2-RX subtype)
#   cell+32  u32  bits 0..11 rsrp_inst_rx1 (raw/16 - 180 dBm; carrier-level)
#   cell+44  u32  bits 0..11 per-cell inst RSRP; bits 12..23 per-cell
#                 combined/filtered RSRP (raw/16 - 180 dBm)  <- entries.rsrp
#   cell+56  u32  bits 20..31 per-cell RSRQ (raw/16 - 30 dB) <- entries.rsrq
# Single-byte scales (rsrp byte@cell+59 = raw/2-99, rsrq byte@cell+26 = raw-37)
# fit strong-signal captures by coincidence and are ~24 dB off at true RSRP
# -117; the bitfields decode that weak-signal capture to -117.6 (F3 truth
# -117.1) and reproduce +QRSRP -117,-119 per-antenna exactly via
# cell+28/cell+32.
_V59_SUBPACKET = 59
_V59_RSRP_WORD_OFF = 44   # u32 whose bits 12..23 carry combined RSRP
_V59_RSRQ_WORD_OFF = 56   # u32 whose bits 20..31 carry RSRQ
_V59_MIN_CELL_RECORD = 60  # need the full u32 at cell+56

# v48 (SDX55: RM500Q-AE / LV55 / EM9190) — the 12 B carrier header (EARFCN u32
# @sp+0, num_cells u16 @sp+4, then 4 more bytes), so the per-cell array starts
# at sp+12. Reading PCI at the 8 B base's sp+8 decodes the 0xffff0100 carrier
# tail -> low9 256; sp+12 holds the true PCI. Validated on an RM500Q-AE LTE
# limited-service capture: decoded PCI {473,37,277} == AT+QENG="servingcell"
# <pcid> across reselections + co-captured verified 0xB116 config_word.
# RSRP is decoded (see the _V48_RSRP_OFF block): in-cell +24 is an x16
# fixed-point RSRP (-180 + raw/16) — the same idiom as v36/v59; raw values
# 473 ~1160 > 37 ~1106 > 277 ~1038 decode to -107/-110.5/-111 dBm. RSRQ stays
# None (its v59-analog candidates overlap the AT range but do not track — see
# the _V48_RSRP_OFF block).
#   F3 is not usable as an RSRP-scale oracle on SDX55, checked on TWO builds:
#   RM500Q-AE (the only candidate, quectel_led_modem.c, is an LED site, 9
#   fires/335 s; no LTE-ML1 measurement F3 print) and T99W175 (the only dBm-RSRP
#   F3 sites are RRC rrcnv.c:1456 / rrcdata.c:21476, all constant -100/-20 = an
#   NV default, RSRQ -20 being below the valid range; the dense rflte_mc_meas /
#   lte_LL1_meas_ncell sites carry RF-driver handles + linear SE/SNE energies,
#   not dBm). A ~3.5 dB "reads low" residual on the RM500Q is therefore
#   F3-unadjudicable; the dense per-measurement oracle there is QSH 0x9D.
_V48_SUBPACKET = 48
# Expressed over v48's TRUE 12 B carrier base (_V48_CARRIER_HEADER_SIZE), i.e.
# in-cell +0 == payload+20 for cell 0. Over the generic 8 B base it would read
# 4; the two forms are identical only at num_cells == 1 (see the
# _V48_CARRIER_HEADER_SIZE block).
_V48_PCI_OFF = 0

# v18 (MDM9207: EG25-G / EC25 family) — older small-regime carrier-header
# layout. Unlike v36/v48/v59 (which carry a num_cells count at sp+4 followed by
# per-cell records), v18 packs the serving cell INLINE in the carrier header and
# has NO num_cells field at sp+4 — reading sp+4 as a u16 count yields garbage
# (e.g. 0x1136 = 4406). The serving cell is: EARFCN @ sp+0 (u32, low 18 bits),
# serving PCI @ sp+4 (u32, low 9 bits). Validated on an EG25-G LTE
# limited-service capture: EARFCN 2050 + PCI 310 == AT+QENG="servingcell" AND
# the co-captured, already-verified 0xB116 serving-PCI field (310). The per-cell
# RSRP/RSRQ byte layout is NOT RE'd for v18, so v18 entries carry pci+earfcn
# with rsrp/rsrq=None. Only the serving cell has been observed; larger v18
# payloads (multi-cell) are not yet characterised.
#
# RSRP-field search: a scan of a 100 B v18 payload at every i8/i16/u16/i32
# offset against co-captured AT truth (QENG servingcell RSRP -100..-104, RSSI
# -67..-71, RSRQ -11..-13) cannot locate the field: the only fields whose value
# sits near the AT RSRP are CONSTANT across all 245 records (payload off=7 i16
# == -1024 == -102.4 dBm at a /10 scale; off=21 i8 == -105) and therefore do
# NOT track the AT's ~4 dB RSRP variation, while every field that DOES vary
# spans the full byte range (noise). A stable-RSRP capture cannot disambiguate
# the field even WITH AT truth; locating it needs a v18 capture with a WIDE
# serving-RSRP sweep (>=15-20 dB, e.g. a drive/attach) so the true field
# separates from the constant look-alikes. rsrp/rsrq stay None.
_V18_SUBPACKET = 18

# v3 (MDM9200: Sierra MC7700) — the SMALL 4-byte carrier header. Like v18 it
# packs the serving cell INLINE and has no num_cells, but its fields are u16,
# not u32: EARFCN @sp+0 (u16), serving PCI @sp+2 (u16). Reading the v18 8-byte
# header here yields u32@0 & 0x3FFFF = 67711 and u16@4 = 57473 as a "cell
# count". Same small-header regime as 0xB192's MDM9200 response ver=2.
#
# 67711 is NOT "true EARFCN + a band offset" (the band-66 u16-overflow pattern
# that is exactly why v35/36/48/50/59 + v18 read EARFCN as u32-low18 — band 66's
# 66536 does not fit in a u16). Here the true EARFCN is a u16 and the "extra"
# value is an ADJACENT FIELD leaking into a straddling u32 read, NOT an offset:
#   * 67711 - 2175 = 65536 = 2^16 EXACTLY. A real band offset adds the band's
#     frequency constant (band 66 = +66436, band 4 = +1950), never a clean 2^16.
#   * The straddling u32 is [earfcn u16 @sp0][pci u16 @sp2]; bit 16 of it is the
#     LOW BIT OF THE PCI. pci 473 is odd, so (473 & 1) << 16 = 65536 — that IS
#     the "+65536". A u32 earfcn would overlap the pci; it cannot, because the
#     pci at sp+2 (473) is independently anchored (0xB116 config_word).
#   * 67711 is not a valid EARFCN for ANY band (it lands in the gap above band-66
#     DL 67335); 2175 is cleanly band 4. And an MDM9200 part PREDATES band 66
#     entirely (tops out at band 17, ~5849 << 65535) — no v3 emitter can
#     legitimately need >16 bits, so u16 is both correct and sufficient.
#
# Triple-anchored on an MC7700 capture (31 v3 records, 84 B): decodes earfcn
# 2175 (valid band 4) + pci 473, and the SAME capture's co-captured,
# independently-verified codes agree on BOTH fields — 0xB116 config_word
# (verified==PCI) = 473, 0xB0C0 = (pci 473, earfcn 2175), and 0xB192's own
# MDM9200 4-byte-header path = earfcn 2175. Per-cell RSRP/RSRQ are not RE'd for
# v3 -> None.
_V3_SUBPACKET = 3
_CARRIER_HEADER_MDM9200 = 4

# v22 (Quectel EP06-A) — the v35/v36 carrier-header shape (EARFCN u32-low18
# @sp+0, num_cells u16 @sp+4, per-cell array @sp+8, PCI low-9 @cell+0). Identity
# fields anchored on a 22-record (496 B) capture: earfcn 2050 + pci 310 ==
# co-captured 0xB116 config_word 310 AND 0xB0C0 (pci 310, earfcn 2050). Its
# per-cell RSRP/RSRQ scale is NOT RE'd; a wrong-scale rsrp would fail the
# -140..-30 plausibility gate and `continue`, discarding the VERIFIED
# pci+earfcn with it (0 entries on all 523 corpus records). rsrp/rsrq -> None
# so the identity fields survive.
_V22_SUBPACKET = 22

# v35 (SDX50M Sierra MC7411 / MDM9x50 EM7565+EM7511 / SDX12 FM101-GL) — the v36
# carrier/PCI shape (PCI low-9 @cell+0, VERIFIED) but its per-cell RSRP is
# REFUTED. v35 is 17.6% of the corpus (63,319 records); decoding it with v36's
# old `-raw/10` offsets puts a wrong value into a wigle_direct "signal" field.
#
# Refuted by the firmware's own F3 on an EM7565 capture with 32,234 v35 records:
#   F3 qm_meas.c:938  "LTE rssi 61, rsrq -7, rsrp -87, sinr 214" (93 samples,
#   constant -87), corroborated by cmss.c:10151 (rsrp=-87) and atrf.c:2345
#   ("AT+CESQ input: RSRP: -86")  ->  `-raw/10` decodes median -80.0  =  +7.0 dB.
# NOT a calibration offset — the error differs per modem (MC7411 ~+30 dB vs
# AT!GSTATUS -100.1; EM7511 -69.2; EM7565 +7.0), i.e. it is the WRONG FIELD, the
# same "linear energy read as dBm" semantics as 0xB192's neighbour rsrp.
# An exhaustive offset scan (cell+0..200 x i8/i16/u16/i32 x 5 scales) for a field
# == the F3 truth found ZERO candidates, so the true field is not locatable from
# a zero-spread capture (the same trap as v18). rsrp/rsrq -> None; pci+earfcn
# keep.
_V35_SUBPACKET = 35

# v36 (SDX20: Telit LM960 / Quectel EG18-NA) — PCI @cell+0 VERIFIED.
#
# The u16 @cell+56 is NOT serving RSRP: read as `-raw/10` it decodes -61..-73 dBm
# = AT RSSI (-64..-71) while #RFSTS/#MONI report RSRP -100..-104, ~36 dB hot.
# Across three F3/AT-grounded points that decode is ANTI-CORRELATED with truth:
#     true -101  ->  decoded  -66     (B66)
#     true  -85  ->  decoded  -84.1   (B48)  <- the crossing
#     true  -74  ->  decoded -101.6   (B12)
# As truth RISES the decode FALLS — the signature of `-raw/10` negating a linear
# energy. -85 is simply where the two lines cross; a single stationary capture
# near -85 dBm reproduces the coincidence (-84.20 vs F3 -85), not the field.
# Likewise `(raw-60)/2` RSRQ decodes a CONSTANT -10.0 across 10,840 records
# while the LM960's own F3 logs rsrq -6/-7 (varying) — a stuck field.
#
# cell+56 is in fact RSSI on the raw/16 scale (below), and the real RSRP sits
# 36 bytes earlier. `-raw/10` at cell+56 read "~36 dB hot" and anti-correlated
# because it was negating a *wideband-power* field on the wrong scale.
#
# Grounding capture: LM960A18 drive, T-Mobile B66 EARFCN 66786 + B2 EARFCN 900,
# 16.2 min, 2,078 0xB193 records / 2,055 single-cell. RSRP sweeps -108..-63 dBm
# = **45 dB**, clearing the >=15-20 dB bar with room to spare, so this cannot be
# a crossing-point coincidence: the decode tracks truth monotonically across the
# whole span on both record subtypes, not at one point.
#
# GROUNDED THREE INDEPENDENT WAYS — all three agree, and the third needs no
# external truth at all:
#
#  (1) The modem's OWN F3, paired on the RAW DIAG TICK. `lte_ml1_md.c:6186`
#      ("Serving Cell Meas: (%d, %d) LL RSRP (used=rx%d rx0 %d.%04d rx1 %d.%04d)"),
#      :6206 (LL RSRQ) and :6211 (LL RSSI) are the ML1 prints of the very
#      measurement 0xB193 logs, and they carry the SAME tick domain — so pairing
#      is exact, with no ts->UTC map and no AT-poll cadence jitter. 1,428 pairs
#      within 0.5 s: r^2 = 1.00000, **max abs error 0.032 dB** on every field
#      below. (0.032 dB is the F3 renderer's own %04d print resolution, not a
#      field error — this is a bit-exact match.)
#
#  (2) Concurrent AT truth (5 s cadence, 198 polls) — AT#LAPS per-antenna
#      RSRP/RSRQ, AT#MONI, AT#RFSTS:
#          rsrp_rx0 vs #LAPS rx0   median -0.31 dB (n=1520)
#          rsrp_rx1 vs #LAPS rx1   median -0.25 dB (n=1520)
#          rsrq_rx0 vs #LAPS rsrq0 median +0.05 dB (n=1520)
#      in line with v59's own -0.38 dB serving-cell agreement with QENG.
#
#  (3) TRUTH-FREE PHYSICAL CLOSURE — 3GPP TS 36.214 §5.1.3 requires
#      RSRQ = 10*log10(N_RB) + RSRP - RSSI. Feeding the three decoded fields into
#      that identity and solving for N_RB returns the carriers' ACTUAL bandwidths:
#          EARFCN 66786 (B66, 20 MHz)  -> N_RB = 100.0   (p10/p90 +-0.06 dB)
#          EARFCN 900   (B2,  10 MHz)  -> N_RB =  50.1   (p10/p90 +-0.06 dB)
#      +-0.06 dB IS the 1/16-dB quantum. Three fields cannot independently be at
#      wrong offsets or wrong scales and still close a physical identity onto the
#      exact integer RB counts of two different bandwidths. This is the strongest
#      class of evidence in this parser: it cannot be produced by a crossing-point
#      coincidence, and it requires no AT/F3 oracle to reproduce.
#
# The decode also holds on a newer LM960 firmware build: 321 single-cell v36
# records over a ~19 dB band-cycled sweep match own-F3 :6186/:6206, AT#RFSTS
# and AT+CESQ at every quantile within 1.2 dB.
#
# Per-cell layout (8 B carrier header, so cell_offset == sp+8):
#   cell+0  u16 bits0..8   PCI (bit12 observed constant-1; see note below)
#   cell+20 u16 bits0..11  RSRP rx0  raw/16 - 180 dBm   <- entries.rsrp (used chain)
#   cell+24 u16 bits0..11  RSRP rx1  raw/16 - 180 dBm   (located; not surfaced)
#   cell+36 u16 bits0..9   RSRQ rx0  raw/16 -  30 dB    <- entries.rsrq
#   cell+56 u16 bits0..11  RSSI      raw/16 - 110 dBm   (located; not surfaced)
# Same idiom as the v59 family (12-bit fields, raw/16 - offset), different
# geometry — which is itself corroborating: v36 and v59 are the same ML1 struct
# at two chipset generations.
#
# entries.rsrp is the rx0 chain because the firmware says so: :6186 prints
# `used=rx%d` and it is 0 on 1,442/1,442 records of the grounding capture.
#
# TWO CAVEATS:
#   * cell+20 bit10 is set on 2,055/2,055 records here AND on the _SAMPLE_1
#     fixture. So "12-bit bits0..11, raw/16 - 180" and "10-bit bits0..9,
#     raw/16 - 116" are NUMERICALLY IDENTICAL on all evidence in hand and
#     cannot be distinguished. The 12-bit/-180 form is chosen because it is
#     v59's exact idiom (raw/16 - 180 dBm); if a future capture ever clears bit10
#     the two readings diverge by 64 dB and this note is where to start.
#   * cell+36 is read as 10 bits, not 12: bit-occupancy over 2,055 records shows
#     bits0..8 varying, **bit9 never set**, and bits10..15 varying independently
#     at ~50% (a different field). 9 bits would cap RSRQ at +1.9 dB, below the
#     3GPP TS 36.133 max of +2.5 dB, so bit9 is taken as the field's unused top
#     bit rather than the neighbouring field's bottom bit.
#
# SINGLE-CELL ONLY, per the v48/v50 precedent. All grounding above is on
# num_cells == 1 records (2,055 of 2,078). The 23 multi-cell records in the
# capture are NOT validated — neighbour-cell signal reads low on every other
# version where it was measured (v59 neighbours read 3-8 dB low) — so
# multi-cell v36 gates rsrp/rsrq to None and ships the VERIFIED pci/earfcn.
_V36_SUBPACKET = 36
# Per-cell offsets over v36's 8 B carrier base (cell_offset == sp+8).
_V36_RSRP_RX0_OFF = 20    # u16 bits0..11, raw/16 - 180 dBm  (the `used=rx0` chain)
_V36_RSRP_RX1_OFF = 24    # u16 bits0..11, raw/16 - 180 dBm  (located, not surfaced)
_V36_RSRQ_OFF = 36        # u16 bits0..9,  raw/16 -  30 dB
_V36_RSSI_OFF = 56        # u16 bits0..11, raw/16 - 110 dBm  (the `-raw/10` look-alike)
_V36_RSRP_BASE = -180.0
_V36_RSRQ_BASE = -30.0

# v40 (SDX24: Quectel EM120R-GL / EM160R-GL) — 893 records / 7 captures / 2
# modems (three firmware builds). Always 544 B.
#
# THE CELL ARRAY IS A FIXED 4 x 132 B ARRAY — the stride is NOT derived.
# 544 = 16 (outer + subpacket hdr + 8 B carrier header) + 4 x 132, whatever
# num_cells says; unused slots are zero-filled. On the 5 two-cell records cell[1]
# sits at cell+132 (its cell+8 word repeats cell[0]'s at the same in-cell
# offset), while the generic derived stride (528 / num_cells = 264) lands in the
# zero tail and would fabricate a "PCI 0" neighbour. Hence _V40_CELL_STRIDE.
#
# Layout over the 8 B carrier base (cell_offset == sp+8 + i*132):
#   cell+0   u32 bits0..8  PCI (bit12 set on every single-cell/serving slot, clear
#                          on the one neighbour slot seen — 5 records, NOT exposed)
#   cell+20  u32 bits0..11 / cell+24 bits0..11  x16 RSRP-scale values (located,
#                          NOT surfaced: they read like rx0/rx1 on the EM120R —
#                          -107.8/-106.3 vs that capture's own +QRSRP -107,-106 —
#                          but ~4 dB ABOVE cell+36 on the EM160R, so the chain
#                          reading does not hold across modems)
#   cell+36  u32 bits0..11 RSRP, raw/16 - 180 dBm         -> entries.rsrp
#   cell+48  u32 bits20..31 RSRQ, raw/16 - 30 dB          -> entries.rsrq
#   cell+60  u32 bits0..11 RSSI, raw/16 - 110 dBm         (located, not surfaced)
# The same x16 idioms as v36/v59 (cell+48 b20..31 is v59's exact RSRQ slicing).
#
# GROUNDED on the same three-leg bar as v36:
#   (1) TICK-PAIRED, against co-captured 0xB17F (an independently parsed struct
#       whose x16 scale is AT-grounded) on the SAME DIAG tick: RSRP within 1 LSB
#       on 551/551 single-cell records (513 bit-exact; every miss is exactly
#       0.0625 dB and equals 0xB17F's adjacent filter tap), RSRQ bit-exact
#       551/551 — per capture, on all 7 captures and both modems, over a 32.6 dB
#       span across 3 cells (strongest -79.3 dBm). This leg stands in for own-F3
#       pairing because this SDX24 build's ML1 F3 subsystem is SILENT (no
#       lte_ml1_* site in 1.46 M resolved F3 records); a wrong field cannot equal
#       the right one bit-exactly across 32 dB, which rules out a crossing-point
#       coincidence.
#   (2) AT, independent subsystem, echoed in-capture by dsatrsp.c on the survey
#       capture: +QENG "servingcell" 242 / 66786 / RSRP -106 / RSRQ -12 / RSSI -71
#       vs the adjacent v40 records 242 / 66786 / -106.25 / -11.81 / -73.13. On a
#       DIFFERENT modem and day the EM160R decodes PCI 3 @66786 at -110.8 dBm,
#       inside the survey's AT intra-frequency reading for PCI 3 (-111..-114).
#   (3) TRUTH-FREE TS 36.214 closure, RSRQ = 10log10(N_RB) + RSRP - RSSI:
#       median N_RB 25.5 on the 5 MHz B12 carrier (exact: 25) and 110..117 on the
#       20 MHz B66 carrier (exact: 100, +0.4..0.7 dB). Looser than v36's +-0.06 dB
#       (MAD ~0.6 dB) because RSRQ here is evidently formed on a different filter
#       tap than cell+36 (RSRP repeats at cell+20 b12 / +24 / +36 b12), so this leg
#       confirms the SCALES, not a same-tap identity.
#   Identity (pci/earfcn) is triple-anchored: cell+0 == co-captured 0xB0C0 AND
#   0xB17F on every capture ((5035,158), (66786,242), (66786,3)), == the modem's
#   own F3 lte_rrc_sib.c:17725 / lte_rrc_plmn_search.c:8250 "phy_cell_id = 158 &
#   freq = 5035" / "phy_cell_id = 242 & freq = 66786", and the 2-cell records'
#   neighbour (5035,144) is in the survey's measured neighbour table.
#
# SINGLE-CELL ONLY for the dBm, per the v36/v48/v50 precedent: no neighbour
# slot has a same-tick partner (0 of 5), so multi-cell gates rsrp/rsrq to None
# and ships the identity.
_V40_SUBPACKET = 40
_V40_CELL_STRIDE = 132          # fixed array slot — NOT (len - hdr) / num_cells
_V40_RSRP_WORD_OFF = 36         # u32 bits0..11,  raw/16 - 180 dBm
_V40_RSRQ_WORD_OFF = 48         # u32 bits20..31, raw/16 -  30 dB
_V40_RSSI_WORD_OFF = 60         # u32 bits0..11,  raw/16 - 110 dBm (located, not surfaced)

# The v59 FAMILY (SDX55 FN980/EM9190 v50; SDX62 v56/v59) — one per-cell layout:
#   cell+0  u32 valid-RX-antenna mask (0x3 = 2-RX intra, 0xF = 4-RX inter)
#   cell+4  u8[4] antenna indices (ffff0100 on 2-RX, 03020100 on 4-RX)
#   cell+8  u32 bits0..8 PCI (bit15 = carrier-record PRIMARY flag, v59 ONLY — see below)
#   cell+44 u32 bits12..23 combined RSRP (raw/16 - 180 dBm)
#   cell+56 u32 bits20..31 RSRQ          (raw/16 - 30 dB)
#
# v50 (15,145 corpus records, 4.2%) is identified as v59-family by its
# cell+0 = 0x3 / cell+4 = 0xffff0100 signatures. Read with pci_off=0 it decodes
# the ANTENNA MASK (0x3) as "PCI 3", and the wrong-scale rsrp fails the
# -140..-30 gate, so every record would emit ZERO entries. Grounded on an FN980
# DIAG×AT capture (1,408 records + co-captured AT):
#   earfcn 66986 == AT#RFSTS 66986 (1408/1408)
#   pci@cell+8 = 473 == 0xB116 config_word 473 (verified==PCI) == 0xB0C0 pci 473
#   RSRP/RSRQ decoded with v59's bit-exact, INDEPENDENTLY-VALIDATED, NOT-fitted
#   scale reproduce AT #RFSTS truth in ABSOLUTE terms at every quantile:
#     q05 -108.75/-109  q25 -107.81/-108  q50 -107.31/-107  q75 -106.44/-107
#     q95 -105.19/-105   -> median delta -0.31 dB (RSRP) / -0.25 dB (RSRQ)
#   in line with v59's own -0.38 dB vs QENG. Because the scale is KNOWN and
#   merely tested (pass/fail), not fitted, the capture's narrow 7 dB spread does
#   NOT invoke the narrow-range trap.
# v56 (3 records, RM520N-GL 180 B) carries the same signatures (mask 0x3, indices
# 0xffff0100, pci 236, earfcn 66786, rsrp -103.94) and rides the same branch.
#
# bit15 IS NOT A SERVING FLAG OUTSIDE v59. v59's serving cell sets bit15=1
# (fixture pci_word 0x000080c9); v50's serving cell has bit15=0 on all 1,408
# AT-matched records. So the v59 non-serving signal gate is applied to v59 ONLY
# — applying it to v50 would None the very RSRP validated above. Every corpus v50
# and v56 record is single-cell (180 B / num_cells=1), so its one cell IS the
# serving cell; a future MULTI-cell v50/v56 is unvalidated and gates to None.
#
# A second FN980-family v50 witness — Telit FT980m (SDX55), 56 single-cell
# records, ALL rsrp populated — decodes a deep-weak limited-service camp:
# earfcn 800/pci 148 (44 rec, rsrp med -111.75 / rsrq -17.94) + earfcn 1100/pci
# 110 (12 rec, rsrp med -110.75 / rsrq -17.81) — physically sane, matching the
# capture's AT CSURV limited-service state.
# SDX55 ML1 has no serving-RSRP F3 site (measured on two SDX55 builds, FT980m and
# T99W175): that capture's F3 is fully resolved (988,748 frames) yet carries NONE
# of the RSRP-grounding sites (no lte_ml1_md.c / lte_ml1_common_rssi_ind.c /
# dlm_ard / led_modem.c / qm_meas.c — only rfcommon_asdiv_manager, no RSRP). The
# only RSRP in its F3 is AT-layer scan echo (azatdebug.c:112 / dsatrsp.c:356 /
# dsatdebug.c:103) of OTHER candidate cells (pci 175/492/1), which do not cover
# the camped serving cell (148/110). So v50/v48 serving-RSRP grounding must come
# from vendor F3 (Quectel led_modem.c) or AT, not SDX55 ML1.
_V50_SUBPACKET = 50
_V56_SUBPACKET = 56
_V59_FAMILY = frozenset({_V50_SUBPACKET, _V56_SUBPACKET, _V59_SUBPACKET})

# v48 per-cell RSRP: an x16 fixed-point per-Rx RSRP at payload+44 == in-cell +24,
# scale -180 + raw/16, pinned against the modem's own F3 on a 218-record
# RM500Q-AE capture: decoded median -101.50 vs F3 -101.56 (resid 0.14 dB) AND vs
# the capture's own AT+QENG="servingcell" RSRP -101. Same x16 fixed-point family
# as the v59 branch.
#
# v48 RSRQ stays None: the v59-analog candidates (u32 bits20..31 at payload+60 /
# +68) span -17.8..-10.3 against an AT RSRQ spanning -16..-10 — suggestive, but
# range overlap is not tracking, and a ~2 dB median error on 14 AT rows is exactly
# how plausible-but-wrong scales arise. Documented as a lead.
#
# OFFSET COORDINATE BASE: expressed over v48's TRUE 12-byte carrier base
# (cell_offset = sp+12 == payload+20), matching _V48_PCI_OFF. "RSRP
# @payload+44" == "in-cell +24" is therefore **24** here (20 + 24 = 44). Over the
# generic 8 B base it would read 28 (16 + 28 = 44) — the same absolute byte for
# cell 0 only.
_V48_RSRP_OFF = 24        # over v48's true 12 B base; == payload+44 for cell 0

# v48 (SDX55) RECORD-LEVEL enrichment offsets — additive, decoded ONLY on v48,
# None on every other version (their sp+6 / sp+16 bytes are un-grounded). These
# are enrichment, NOT RAW_FIELDS: like the per-cell `entries` array they do not
# participate in the 3-way equivalence diff (RAW_FIELDS[0xB193] is the 4-scalar
# layout allowlist). Byte-joined 21/21 against SCAT output.
#
#   valid_rx  u16 @ sp+6  (inside the 12 B carrier header): valid-Rx-antenna mask.
#             0x3 on the single-cell LV55 fixture (2 Rx), 0xF on the M2000 multi-
#             cell fixtures (4 Rx) — the same 0x3/0xF idiom the v59 family carries
#             as meas_type. The v36 synthetic-corpus test already labels sp+6
#             `num_rx_antennas`, corroborating the reading.
#   sfn/sub_fn  u16 @ sp+16 (== data+24; i.e. "payload+16" counted from the
#             SUBPACKET-payload base): SFN = bits0..9 (0..1023), SubFN =
#             bits10..13 (0..9). 0x15d4 -> SFN 468 / SubFN 5 on the LV55 fixture
#             == SCAT's value; all three v48 fixtures land in-range (SFN
#             468/560/670, SubFN 5/4/4) — a truth-free structural check a wrong
#             offset would fail. DISTINCT from `counter` (data[2:4]), which is
#             43-62x the max SFN and is explicitly NOT a frame number (see the
#             Diag0xB193.counter comment).
_V48_VALID_RX_OFF = 6
_V48_SFN_OFF = 16

# Every subpacket version whose per-cell layout is RE'd. An unknown version gets
# the carrier header ONLY (earfcn is pre-drift) and ZERO entries — never another
# version's offsets. A version-agnostic catch-all would silently mis-decode
# (as it would v50's 15,145 records) and would mis-decode the next chipset's
# version forever: "size invariance != format invariance" — a version byte the
# parser has never seen is NOT an invitation to guess.
_DECODED_SUBPACKET_VERSIONS = frozenset({
    _V3_SUBPACKET, _V18_SUBPACKET, _V22_SUBPACKET, _V35_SUBPACKET,
    _V36_SUBPACKET, _V40_SUBPACKET, _V48_SUBPACKET, _V50_SUBPACKET,
    _V56_SUBPACKET, _V59_SUBPACKET,
})



# Validation: RM520N-GL (SDX62) emits the single corpus-wide outer version v=1;
# every serving-cell to_dict() entry field is a decoded physical quantity with a
# known scale, so it can be checked by direct numeric equality against the LTE
# serving row of AT+QENG="servingcell".

@register(LOG_LTE_ML1_SERVING_CELL_MEAS_RSP, domain="lte-signal",
    name="0xB193",
    description="Serving cell PCI, EARFCN, RSRP, RSRQ from the 0xB193 subpacket — outer v=1 corpus-wide; per-cell layout keyed on subpacket_version {3,18,22,35,36,40,48,50,56,59}. pci/earfcn grounded on every version; RSRP/RSRQ decoded only where an x16 fixed-point scale is grounded (v36, v40, v48 RSRP, v50/v56/v59), single-cell or serving-cell only.",
    version=31,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Outer version 0x01 corpus-wide (359,915 records); the per-cell layout is "
        "keyed on subpacket_version, which tracks the chipset, through a closed "
        "allowlist (unknown versions emit the carrier header only). EARFCN "
        "(carrier header, u32-low18; u16 on v3) and PCI are grounded on every "
        "version against AT+QENG / AT!LTEINFO / AT#RFSTS and co-captured, "
        "independently verified 0xB116 config_word / 0xB0C0 / 0xB192 / 0xB17F: "
        "v3 MC7700 (2175/473), v18 EG25-G and EM7455 (inline serving cell), v22 "
        "EP06-A, v35 MC7411/EM7565, v36 LM960, v40 EM120R-GL/EM160R-GL, v48 "
        "RM500Q-AE/LV55 (12 B carrier header), v50 FN980, v56/v59 RM520N-GL and "
        "CFW-3212. RSRP/RSRQ are x16 fixed-point (raw/16-180 dBm, raw/16-30 dB) "
        "where decoded: v59 (cell+44 b12..23 / cell+56 b20..31, bit-slice RE "
        "against a 28,879-record QENG/QRSRP correlate capture, UE RRC "
        "MeasurementReport and weak-signal F3 -117.6 vs -117.1; serving cell "
        "only, median -0.38 dB vs QENG, neighbours read 3-8 dB low and are "
        "gated to None); v50/v56 (v59 layout; median -0.31/-0.25 dB vs AT#RFSTS "
        "at every quantile); v36 (cell+20 / cell+36; 45 dB drive sweep, own-F3 "
        "tick-paired max error 0.032 dB, AT#LAPS -0.31/+0.05 dB, TS 36.214 "
        "closure onto N_RB 100.0/50.1, reconfirmed on a newer firmware build); "
        "v40 (fixed 4x132 B array; cell+36 / cell+48 b20..31 within 1 LSB / "
        "bit-exact of same-tick 0xB17F on 551/551 over 32.6 dB, AT+QENG-matched, "
        "TS 36.214-consistent); v48 RSRP only (in-cell +24 over the 12 B base, "
        "-101.50 vs own F3 -101.56 and AT -101). v36/v40/v48/v50/v56 dBm is "
        "single-cell only. v3/v18/v22/v35 signal is None: on v35 the `-raw/10` "
        "candidate is +7.0 dB vs the EM7565's own F3 qm_meas.c (and +30 dB on "
        "MC7411 — a wrong field, not an offset), and v18 could not be located "
        "without a wide RSRP sweep. v48 also exposes valid_rx (sp+6) and "
        "SFN/SubFN (sp+16), byte-joined 21/21 against SCAT. SCAT does not "
        "decode v59. Records shorter than their declared subpacket size return "
        "None (registry warning)."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=6,
    fields_parsed=6,
    field_invariants={
        # byte[0] is corpus-invariant 0x01 across all 359,915 records — it
        # discriminates NOTHING and is therefore an INERT gate. The real dispatch
        # key is subpacket_version (byte[5]), gated below.
        "version": {"enum": [1]},
        # 608 = the 4-cell v59 size class (267 records in one RM520N-GL
        # correlate capture; serving + 3 neighbours at 148 B stride).
        # 84 = v3 (MDM9200 MC7700); 180 = the v50/v56 single-cell class.
        # 344 = the v56 TWO-cell class (16 + 2 x 164; 82 records: Inseego M3100
        # + RM520N-GL — the same v56 stride as its 180 B single-cell form).
        # 544 = every v40 record (SDX24 EM120R-GL / EM160R-GL; 16 + a fixed
        # 4 x 132 cell array).
        # NOT 117: the one 117 B record in the corpus is a TRUNCATED v48 frame
        # — it declares subpacket size 156 (a 160 B record) and the
        # short-record guard returns None for it. A truncation is
        # not a size class; adding it would whitelist the damage.
        "payload_size": {
            "enum": [84, 100, 160, 164, 180, 300, 312, 344, 440, 460, 496, 512,
                     528, 544, 580, 608],
        },
        # subpacket_version — THE structural discriminator (it tracks the
        # chipset). Corpus-attested set (full walk of 807 captures / 482 with
        # records / 359,915 records):
        #   v59 38.9% | v36 28.9% | v35 17.6% | v48 6.8% | v50 4.2%
        #   v18  3.2% | v3   0.2% | v22 0.1%  | v56 <0.1%
        # Gating it is the "size invariance != format invariance" rule in its
        # VERSION form: an unseen version means an unknown per-cell layout, and
        # the parser must surface that rather than silently apply some other
        # chipset's offsets (as a catch-all would for v50). The parse path
        # already degrades an unknown version to carrier-header-only; this
        # invariant makes the event VISIBLE instead of a silent partial decode.
        # + v40 (SDX24 EM120R-GL / EM160R-GL, 893 records).
        "subpacket_version": {"enum": [3, 18, 22, 35, 36, 40, 48, 50, 56, 59]},
    },
    wigle_direct=True,
    wigle_roles=("signal", "pci-earfcn-bridge", "rat-context"),
)
def parse_0xb193(
    log_time: int, data: bytes
) -> Diag0xB193 | None:
    """Parse 0xB193 -- LTE ML1 Serving Cell Measurement Response.

    Extracts per-cell PCI, EARFCN, RSRP, and RSRQ from the subpacket
    payload. Supports version 1 with subpacket version 36.

    Returns None if the payload is too short (including shorter than its
    declared subpacket size) or the version is unsupported.
    """
    if len(data) < _MIN_PAYLOAD:
        return None

    version = data[0]
    if version != 1:
        return None
    num_subpackets = data[1]
    # Outer-frame [2:4] counter — UNCONDITIONAL (present on every version and on
    # short/degenerate payloads), read once here and carried on every return path
    # so it is never dropped. Exposed for 0xB192-sibling parity.
    counter = unpack_from('<H', data, 2)[0]

    if num_subpackets < 1:
        return Diag0xB193(
            log_time=log_time,
            version=version,
            subpacket_version=0,
            counter=counter,
            earfcn=0,
            num_cells=0,
            payload_size=len(data),
        )

    # Subpacket header: id(u8), version(u8), size(u16)
    subpacket_version = data[5]
    subpacket_size = unpack_from('<H', data, 6)[0]
    # The subpacket size counts its own 4-byte header (id/version/size) and runs
    # to the end of the record: len(data) == 4 + subpacket_size on every corpus
    # record. A record shorter than the size it declares was truncated — the
    # derived per-cell stride below would silently floor-divide the loss away,
    # so decline it (registry warning) instead.
    if len(data) < _SUBPACKET_HDR_OFFSET + subpacket_size:
        return None

    # Subpacket data starts at offset 8
    sp = data[_SUBPACKET_DATA_OFFSET:]

    # --- v3 (MDM9200) — the 4-byte carrier header, read BEFORE the u32 path ----
    # v3's EARFCN is a u16 @sp+0, so the u32-low18 read below would corrupt it
    # (67711, a band-66 EARFCN this MDM9200 part cannot emit). Serving cell is
    # packed inline: earfcn u16 @sp+0, pci u16 @sp+2. Triple-anchored.
    if subpacket_version == _V3_SUBPACKET:
        if len(sp) < _CARRIER_HEADER_MDM9200:
            return None
        v3_earfcn = unpack_from('<H', sp, 0)[0]
        v3_pci = unpack_from('<H', sp, 2)[0]
        v3_entries: list[LteMl1ServingCellMeasEntry] = []
        if v3_pci <= 503:
            # RSRP/RSRQ not RE'd for v3 -> None (not guessed).
            v3_entries.append(LteMl1ServingCellMeasEntry(
                pci=v3_pci, earfcn=v3_earfcn, rsrp=None, rsrq=None,
            ))
        return Diag0xB193(
            log_time=log_time,
            version=version,
            subpacket_version=subpacket_version,
            counter=counter,
            earfcn=v3_earfcn,
            num_cells=len(v3_entries),
            payload_size=len(data),
            entries=v3_entries,
        )

    if len(sp) < _CARRIER_HEADER_SIZE:
        return None

    # Carrier header. The u32-low18 read is structurally bounded to a valid
    # 18-bit EARFCN space (<= 262143), so no range gate is needed here.
    earfcn_raw = unpack_from('<I', sp, 0)[0]
    earfcn = earfcn_raw & 0x3FFFF

    # v18 (MDM9207) has no num_cells at sp+4 — that u32 is the serving PCI.
    # Decode the serving cell inline from the carrier header.
    if subpacket_version == _V18_SUBPACKET:
        v18_pci = unpack_from('<I', sp, 4)[0] & 0x1FF
        v18_entries: list[LteMl1ServingCellMeasEntry] = []
        if v18_pci <= 503:
            # RSRP/RSRQ scale not yet RE'd for v18 -> None (not guessed).
            v18_entries.append(LteMl1ServingCellMeasEntry(
                pci=v18_pci, earfcn=earfcn, rsrp=None, rsrq=None,
            ))
        return Diag0xB193(
            log_time=log_time,
            version=version,
            subpacket_version=subpacket_version,
            counter=counter,
            earfcn=earfcn,
            num_cells=len(v18_entries),
            payload_size=len(data),
            entries=v18_entries,
        )

    # --- unknown subpacket version -> carrier header ONLY, never guessed cells --
    # The dispatch below is a CLOSED allowlist. A version we have not RE'd has an
    # unknown per-cell layout, so applying any known version's offsets to it
    # fabricates a PCI and a dBm (a catch-all arm would do exactly that to the
    # real FN980 v50). earfcn is a carrier-header field,
    # ahead of every observed per-cell drift, so it is still reported.
    if subpacket_version not in _DECODED_SUBPACKET_VERSIONS:
        return Diag0xB193(
            log_time=log_time,
            version=version,
            subpacket_version=subpacket_version,
            counter=counter,
            earfcn=earfcn,
            num_cells=unpack_from('<H', sp, 4)[0],
            payload_size=len(data),
        )

    num_cells = unpack_from('<H', sp, 4)[0]

    entries: list[LteMl1ServingCellMeasEntry] = []

    # v48 is the ONLY version with a 12 B carrier header, so its cell array starts
    # — and its stride is measured — 4 bytes later than every other version's.
    # See the _V48_CARRIER_HEADER_SIZE block for why this must drive the stride
    # divisor and not just the in-cell offsets.
    carrier_header_size = (
        _V48_CARRIER_HEADER_SIZE
        if subpacket_version == _V48_SUBPACKET
        else _CARRIER_HEADER_SIZE
    )

    if num_cells == 0 or len(sp) <= carrier_header_size:
        return Diag0xB193(
            log_time=log_time,
            version=version,
            subpacket_version=subpacket_version,
            counter=counter,
            earfcn=earfcn,
            num_cells=num_cells,
            payload_size=len(data),
        )

    # Calculate per-cell record size from remaining subpacket data. The stride is
    # DERIVED (the wire carries no stride field), so a garbage num_cells would
    # otherwise floor-divide to a nonsense stride — at num_cells > cell_data_len
    # the stride hits 0 and every "cell" re-reads cell_offset 0, emitting
    # num_cells IDENTICAL duplicate entries. Guard it the way the 0xB195 sibling
    # guards its own count, and reject rather than emit fabricated duplicates.
    cell_data_len = len(sp) - carrier_header_size
    cell_record_size = cell_data_len // num_cells
    if subpacket_version == _V40_SUBPACKET:
        # v40 is a FIXED 4 x 132 B array; the derived stride is wrong for any
        # num_cells > 1 (see the _V40_* block). Slots past the record end are
        # cut off by the per-cell bounds check below.
        cell_record_size = _V40_CELL_STRIDE
    if cell_record_size < _MIN_STRIDE:
        return Diag0xB193(
            log_time=log_time,
            version=version,
            subpacket_version=subpacket_version,
            counter=counter,
            earfcn=earfcn,
            num_cells=num_cells,
            payload_size=len(data),
        )

    # Per-cell field layout is keyed on the subpacket version (which tracks the
    # CHIPSET); the carrier-header / stride math above is version-agnostic. This
    # chain is a CLOSED allowlist — an unknown version returned above, so there is
    # no catch-all arm to leak another chipset's offsets into.
    #   v59 family (v50 SDX55 / v56+v59 SDX62): PCI@cell+8, BITPACKED 12-bit
    #     RSRP@cell+44 b12..23 (raw/16-180) + RSRQ@cell+56 b20..31 (raw/16-30).
    #   v48 (SDX55): 12 B carrier header (drives the stride AND the base) ->
    #     PCI@cell+0 (== sp+12); x16 fixed-point per-Rx RSRP@cell+24
    #     (-180 + raw/16), pinned on SINGLE-cell records only.
    #   v36 (SDX20): PCI@cell+0; x16 RSRP@cell+20 b0..11 (raw/16-180) + RSRQ
    #     @cell+36 b0..9 (raw/16-30), grounded on SINGLE-cell records only.
    #   v40 (SDX24): fixed 132 B slots; RSRP@cell+36 b0..11 + RSRQ@cell+48
    #     b20..31, SINGLE-cell records only.
    #   v22/v35: PCI@cell+0 (verified); signal scales REFUTED/ungrounded.
    # See the per-version constants block above for the full evidence trail.
    if subpacket_version in _V59_FAMILY:
        pci_off = 8
        min_cell_record = _V59_MIN_CELL_RECORD
    elif subpacket_version == _V48_SUBPACKET:
        pci_off = _V48_PCI_OFF
        min_cell_record = _V48_RSRP_OFF + 2      # need the full u16 at cell+24
    elif subpacket_version == _V36_SUBPACKET:
        pci_off = 0
        min_cell_record = _V36_RSRQ_OFF + 2      # need the full u16 at cell+36
    elif subpacket_version == _V40_SUBPACKET:
        pci_off = 0
        min_cell_record = _V40_RSRQ_WORD_OFF + 4  # need the full u32 at cell+48
    else:
        # v22 / v35 — PCI@cell+0 verified, no grounded signal scale.
        pci_off = 0
        min_cell_record = 4                      # just enough to read the PCI u32

    for i in range(num_cells):
        cell_offset = carrier_header_size + i * cell_record_size
        if cell_offset + min_cell_record > len(sp):
            break

        # PCI: low 9 bits of u32 at the version-dependent cell offset
        pci_raw = unpack_from('<I', sp, cell_offset + pci_off)[0]
        pci = pci_raw & 0x1FF

        if pci > 503:
            continue

        serving_flag = None
        meas_type = None

        if subpacket_version in _V59_FAMILY:
            mask = unpack_from('<I', sp, cell_offset)[0]
            meas_type = {0x3: "intra_2rx", 0xF: "inter_4rx"}.get(mask, f"0x{mask:x}")
            # Bit-exact 12-bit fields (see the _V59_* constants block).
            # raw == 0 means the field is unpopulated -> None (keep pci/earfcn).
            rsrp_raw = (unpack_from('<I', sp, cell_offset + _V59_RSRP_WORD_OFF)[0]
                        >> 12) & 0xFFF
            rsrq_raw = unpack_from('<I', sp, cell_offset + _V59_RSRQ_WORD_OFF)[0] >> 20
            rsrp = round(rsrp_raw / 16.0 - 180.0, 2) if rsrp_raw else None
            rsrq = round(rsrq_raw / 16.0 - 30.0, 2) if rsrq_raw else None
            if subpacket_version == _V59_SUBPACKET:
                # v59 ONLY: bit15 of the PCI word is the CARRIER-RECORD PRIMARY
                # flag — the reference cell of *this* carrier's measurement
                # record, not the globally serving cell (262/262 records across
                # 5 carriers set it on one RM520N-GL capture).
                serving_flag = (pci_raw >> 15) & 1
                # serving_flag == 1 is a NECESSARY but not SUFFICIENT trust
                # predicate. On one RM520N-GL capture the RSRP error vs
                # concurrent AT+QENG tracked SAMPLE COUNT, not flag state:
                #     n=236 -> +0.00 dB   n=4 -> -0.38   n=4 -> -2.91   n=1 -> -5.69
                # i.e. carriers the UE actively measures are accurate; carriers it
                # glances at yield 1-4 records that read several dB low (e.g.
                # PCI 471, ~-7 dB, n=2 — the small n is the signature). A
                # consumer wanting high
                # confidence should require both bit15 AND a populated per-carrier
                # sample count; that gate is NOT implemented here because the
                # parser is per-record and has no cross-record state.
                # cell+44/cell+56 are ground-truth-validated ONLY for the serving
                # cell; on non-serving (neighbour) cells they read ~3-8 dB low vs
                # concurrent AT+QENG on an RM520N-GL-AP dual-mask capture. Gate
                # neighbour signal to None rather than
                # emit a known-wrong value; pci/earfcn stay (identity IS valid).
                if serving_flag != 1:
                    rsrp = None
                    rsrq = None
            else:
                # v50/v56: bit15 is NOT a serving flag here (v50's AT-matched
                # serving cell has bit15=0 on all 1,408 grounded records), so the
                # v59 neighbour gate must not be applied. Every corpus v50/v56
                # record is single-cell, and that one cell IS the serving cell
                # (AT #RFSTS-matched, median delta -0.31 dB). A MULTI-cell v50/v56
                # is unvalidated -> gate its signal off rather than guess.
                if num_cells == 1:
                    serving_flag = 1
                else:
                    rsrp = None
                    rsrq = None
        elif subpacket_version == _V48_SUBPACKET:
            # SDX55 v48: x16 fixed-point per-Rx RSRP @cell+24 (== payload+44),
            # -180 + raw/16 — pinned against the modem's own F3
            # (-101.50 decoded vs -101.56 F3, resid 0.14 dB) and re-confirmed vs
            # the same capture's AT+QENG serving RSRP -101. raw == 0 -> None.
            # RSRQ stays None (candidates located, not locked — see the
            # _V48_RSRP_OFF block).
            #
            # SINGLE-CELL ONLY. The scale was pinned on a single-cell RM500Q-AE
            # capture, and it plainly does not hold on multi-cell records: with the
            # 12 B-base geometry the same in-cell slot reads raw 34043
            # -> +1947 dBm on cell 0 of a 3-cell record — i.e. it is wrong even for
            # the SERVING cell once the record is multi-cell, so this is not a
            # neighbour-only drift. Whether cell+24 means something else
            # in a multi-cell layout, or the per-Rx slot moves, is not RE'd — so
            # gate the signal to None and ship the VERIFIED pci/earfcn, exactly as
            # the v50/v56 multi-cell arm above does. Guessing here would ship a
            # plausible-but-wrong dBm, and an out-of-band value would additionally
            # trip the plausibility filter below and delete the identity row too.
            if num_cells > 1:
                rsrp = None
            else:
                rsrp_raw = unpack_from('<H', sp, cell_offset + _V48_RSRP_OFF)[0]
                rsrp = round(-180.0 + rsrp_raw / 16.0, 2) if rsrp_raw else None
            rsrq = None
        elif subpacket_version == _V36_SUBPACKET:
            # SDX20 v36 — grounded on a 45 dB wide-sweep drive capture,
            # grounded three ways (own-F3 tick-paired to 0.032 dB, AT#LAPS to
            # -0.31 dB, and the truth-free TS 36.214 RSRQ/RSRP/RSSI identity
            # closing onto N_RB = 100.0 / 50.1 for the 20/10 MHz carriers). See
            # the _V36_* constants block for the full evidence trail, including
            # why cell+56 is RSSI, not RSRP.
            #
            # SINGLE-CELL ONLY, same discipline as v48/v50 above: all grounding
            # is on num_cells == 1, and neighbour-cell signal has read low on
            # every version where it was actually measured. Multi-cell
            # gates the dBm off and ships the VERIFIED pci/earfcn.
            if num_cells > 1:
                rsrp = None
                rsrq = None
            else:
                rsrp_raw = unpack_from(
                    '<H', sp, cell_offset + _V36_RSRP_RX0_OFF)[0] & 0xFFF
                rsrq_raw = unpack_from(
                    '<H', sp, cell_offset + _V36_RSRQ_OFF)[0] & 0x3FF
                # raw == 0 means the slot is unpopulated -> None (keep identity).
                rsrp = (round(rsrp_raw / 16.0 + _V36_RSRP_BASE, 2)
                        if rsrp_raw else None)
                rsrq = (round(rsrq_raw / 16.0 + _V36_RSRQ_BASE, 2)
                        if rsrq_raw else None)
        elif subpacket_version == _V40_SUBPACKET:
            # SDX24 v40: RSRP within 1 LSB of
            # the same-tick 0xB17F on 551/551 records and RSRQ bit-exact 551/551
            # over 32.6 dB, AT+QENG-matched, TS 36.214-consistent. See the _V40_*
            # block. SINGLE-CELL ONLY, as for v36/v48/v50.
            if num_cells > 1:
                rsrp = None
                rsrq = None
            else:
                rsrp_raw = unpack_from(
                    '<I', sp, cell_offset + _V40_RSRP_WORD_OFF)[0] & 0xFFF
                rsrq_raw = unpack_from(
                    '<I', sp, cell_offset + _V40_RSRQ_WORD_OFF)[0] >> 20
                rsrp = round(rsrp_raw / 16.0 - 180.0, 2) if rsrp_raw else None
                rsrq = round(rsrq_raw / 16.0 - 30.0, 2) if rsrq_raw else None
        else:
            # v22 / v35 — the `-raw/10` u16 is REFUTED on both (it is wideband
            # RSSI / a linear energy, not serving RSRP; see the per-version
            # constants block for the F3/AT evidence), and the `(raw-60)/2` RSRQ
            # is refuted alongside it. Emitting a plausible-but-wrong dBm is
            # worse than emitting nothing — the VERIFIED pci/earfcn still
            # ship. v22/v35 do NOT inherit the v36 branch above — their per-cell
            # geometry is unvalidated and the v36 offsets must not be guessed
            # onto them.
            rsrp = None
            rsrq = None

        # RSRP plausibility filter — only versions that decode a dBm value can
        # trip it; None-RSRP versions still emit their verified pci/earfcn.
        if rsrp is not None and not (-140.0 <= rsrp <= -30.0):
            continue
        # RSRQ plausibility filter (3GPP TS 36.133 §9.1.7 range, widened to the
        # -34..+2.5 the 0xB195 sibling uses), so a mis-aligned record cannot
        # ship an impossible dB value beside a plausible RSRP.
        if rsrq is not None and not (-34.0 <= rsrq <= 2.5):
            rsrq = None

        # 2 decimals is lossless for every decoded scale: the v59-family and v48
        # 1/16-dB quanta are exact at 4 dp and round cleanly at 2.
        entries.append(LteMl1ServingCellMeasEntry(
            pci=pci,
            earfcn=earfcn,
            rsrp=round(rsrp, 2) if rsrp is not None else None,
            rsrq=round(rsrq, 2) if rsrq is not None else None,
            serving_flag=serving_flag,
            meas_type=meas_type,
        ))

    # v48 (SDX55) record-level enrichment: a valid-Rx mask at sp+6 and a
    # bitpacked SFN/SubFN at sp+16. Both v48-only (other versions' bytes there are
    # un-grounded) and additive — never gated onto the RAW 3-way diff. Decoded on
    # the main path only; degenerate/short records leave them None.
    valid_rx = None
    sfn = None
    sub_fn = None
    if subpacket_version == _V48_SUBPACKET:
        # valid_rx lives inside the 12 B carrier header, guaranteed present past
        # the len(sp) <= carrier_header_size guard above.
        valid_rx = unpack_from('<H', sp, _V48_VALID_RX_OFF)[0]
        if len(sp) >= _V48_SFN_OFF + 2:
            sfn_word = unpack_from('<H', sp, _V48_SFN_OFF)[0]
            cand_sfn = sfn_word & 0x3FF          # bits0..9, structurally <= 1023
            cand_sub_fn = (sfn_word >> 10) & 0xF  # bits10..13
            # SubFN is 0..9 on the wire; a value > 9 means this offset is NOT a
            # frame number on this record -> ship neither (not guessed).
            if cand_sub_fn <= 9:
                sfn = cand_sfn
                sub_fn = cand_sub_fn

    return Diag0xB193(
        log_time=log_time,
        version=version,
        subpacket_version=subpacket_version,
        counter=counter,
        earfcn=earfcn,
        num_cells=num_cells,
        payload_size=len(data),
        entries=entries,
        valid_rx=valid_rx,
        sfn=sfn,
        sub_fn=sub_fn,
    )
