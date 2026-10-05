"""0xB115 — LTE LL1 SSS detection results (legacy `LteMacB115`); multi-format.

The canonical log name is **LOG_LTE_LL1_SSS_RESULTS** (Secondary-Sync-Signal
detection results). The legacy `LteMacB115` name is a mislabel: the decoded
shape below is an SSS peak-detection table, not a MAC record.

## Format matrix (byte[0] is a FORMAT discriminator, not a counter)

A 156,894-record sibling-deduped corpus walk found byte[0] takes five values,
covering 100% of the observed corpus:

    byte[0]  size(s)              records         shape
    0x7a     8 + 16*N             137,737 (87.8%) 8B header + N x 16B entries
    0x16     296 (fixed)            7,704 ( 4.9%) 40B hdr + 8 × 32B cell-slots
    0x79     8 + 16*N (sibling)     6,069 ( 3.9%) same as 0x7a
    0x29     608 (fixed)            4,442 ( 2.8%) 40B hdr + 17 × 32B cell-slots
    0x01     168 (fixed)              654 ( 0.4%) 40B hdr + 16 × 8B SSS-peaks

A sixth value, 0x18 (296B, all-zero), is admitted separately (see below).

Chipset coverage: 0x7a/0x79 on SDX62 (em9291) / SDX55 (fn980, em9190) /
MDM9628 (m2000) / Casa CFW3212; 0x29 on EP06A + MC7455 (SDX20); 0x16 on
EG25-G + EG95NA (MDM9607); **0x01 on Sierra MC7700 (SWI9200X / MDM9200-era)**.
A `version` enum field-invariant rejects any unknown format byte (returns
None at layer-2) rather than silently mis-parsing it: an identical size does
not imply an identical format.

## v=0x7a / 0x79 — 8B header + N x 16B entry array (structured)

    hdr[0]    u8    version/format (0x7a or 0x79)
    hdr[1:3]  u16   bits 5..15 = entry count N (LE); bits 0..4 = `header_low5`
    hdr[3]    u8    0x00 (reserved)
    hdr[4:8]  u32   `earfcn` (legacy contract key — see caveat)

The count is a **u16-LE at offset 1**, not a single byte: an N=8 record
(136B) carries `hdr[1:3] == 0x0100 == 0x20*8` (byte1=0x00, byte2=0x01).
A byte-only `hdr[1]==0x20*N` reading only holds for N<=6, where the high byte
is always 0. `u16@1 == 0x20*N` holds on all v=0x7a records in an em9291
manual PLMN-scan capture (N<=6) and on the N=7/N=8 records of a DIAG/AT
correlation capture. 8B records (N=0) carry the header only.
The count is `u16@1 >> 5`, not `u16@1 / 0x20`: the low 5 bits are a separate
field, `header_low5`, which is non-zero on ~9% of records (values 0..4;
semantics unknown, exposed raw). Measured on 999 v=0x7a records in four
captures (EM9291, RM500Q-AE, CFW-3212, FN980):
`(u16@1 >> 5) == (len - 8) / 16` on all 999. A record whose length is not
`8 + 16 * (u16@1 >> 5)` returns None (registry WARN).

Each 16B entry (surfaced with NEUTRAL structural names; byte widths alone do
not establish semantics, which stay deferred pending AT correlation):

    ent[0:2]   u16     a            index/metric A
    ent[2:4]   u16     b            index/metric B
    ent[4:6]   i16     c            metric C (signed)
    ent[6:8]   u16     sentinel     == 0xFFFF in every observed entry
    ent[8:10]  i16     measurement  clustered-negative, RF/correlation shaped
    ent[10]    u8      flag         small {0x03, 0x04}
    ent[11:16] -       trailing/reserved (mostly zero, but NOT strictly
                       invariant: e.g. an em9291 56B record carries 0x10 at
                       ent[12]). Only ent[12] is surfaced (as `field_12`);
                       semantics deferred.

### F3 verdict v0x79: grounded — in-capture F3 co-emission

Version-bound on EM7565 (MDM9x50-class, Sierra SWI9X50C firmware), a
CBRS B48 capture with serving EARFCN 55340 / PCI 451. 1666 v0x79 records
decode; header `earfcn` == **55340** (1620/1666) and `(entries.b & 0x1FF)` ==
PCI **451** (1630 peaks). The same capture's independent plaintext F3
messages (`lte_rrc_csp.c`) print, from a different firmware code path than
the SSS log: `CSP: Received Acq cnf for earfcn 55340 pci 451`, `CSP: Acq
succeeded on physical cell ID 451 on earfcn 55340`, `CSP: Camped on physical
cell ID 451 on earfcn 55340` — plus `channel 55340` ×22k on the RF tune path.
Header `earfcn` == F3 `earfcn` 1:1 and `(b & 0x1FF)` == F3 `physical cell ID`
**{451}**. PCI **451 > 255** is recoverable ONLY with the 9-bit `&0x1FF` mask
(`451 & 0xFF == 195`, wrong), so the F3 co-print establishes the 9-bit PCI
mask on v0x79 silicon, in agreement with the AT (AT!GSTATUS) grounding.

## v=0x16 (296B) / v=0x29 (608B) — 40B header + N x 32B cell-slots (structured)

A distinct older-chipset (MDM9607/MDM9230) layout: a 40B header followed by
`(len-40)//32` fixed 32B cell-slots (8 for v=0x16, 17 for v=0x29). A slot is
populated iff its first 8 bytes are non-zero. Per-slot `earfcn = u16@+6`,
`pci = (u16@+2) & 0x1FF` (9-bit), `measurement = i16@+16` — decoded by
`_decode_slot_entries` and hardware-validated against AT cell info
(EG25-G v=0x16 / EM7455 v=0x29). This region carries cell identity; it is
not an LL1 sample-count table.

**F3 verdict v0x16: grounded.** Same-capture F3 co-emission on an EG25-G
(MDM9607) GNSS cold-start capture: the 42 v=0x16 records decode to EARFCN 2300
with per-slot PCIs {236, 471, 322}; the same capture's plaintext F3
independently prints the serving/neighbour identity `MCC:310 … Physical
CellId:236 … DL Freq:2300` (2126x) and `Physical CellId:471 … DL Freq:2300`
(48x), the CSP acquisition-DB print `acq_entry_ptr[EARFCN:2300,
PCI:{236,471}]`, and `Ngbr srch req (earfcn 2300)` (42x). So slot `earfcn` ==
F3 `DL Freq` 1:1 and the top-2 masked slot `pci` == F3 `Physical CellId`
{236,471} exactly. PCI 471 > 255 requires the 9-bit `&0x1FF` mask to recover,
so the F3 agreement establishes the mask on v=0x16 silicon (a low-byte read
would give 215, not 471). The extra slot PCI 322 is an SSS-detected peak that
does not survive to the F3 serving/acq list (the detector surfaces a
superset — expected).

**F3 verdict v0x29: grounded.** Same-capture F3 co-emission on an EM7455
(MDM9x30/SDX20, Sierra SWI9X30C firmware) all-DIAG capture: the 4 v=0x29
records (all 608B) each decode serving EARFCN **2300** + per-slot PCI **236**
(via `earfcn@+6`, `(u16@+2)&0x1FF`), and are **co-temporal**
(ts 76830062.9e9..76830064.3e9, inside the serving-F3 window
76830056.4e9..76830064.5e9) with 495 same-capture plaintext F3 serving
prints `MCC:310, MNC:260 … Physical CellId:236 … DL Freq:2300` plus the RF-tune
`WWAN_TECH_MSG … Chan 2300` (488x). So slot `earfcn` == F3 `DL Freq` 1:1 and
the serving slot `pci` 236 == F3 `Physical CellId` 236. The extra slots
(EARFCN 8240/8540, PCI 152/382/471) are SSS-detected neighbour peaks that do
not survive to the serving F3 print — the same superset-detector behaviour
seen on v=0x16. PCI 471/382 > 255 are recovered only via the 9-bit `&0x1FF`
mask, AT-grounded cell-by-cell on the same EM7455 silicon. The serving F3
PCI 236 (<255) confirms EARFCN + serving PCI on v=0x29 silicon; the >255 mask
rests on the AT cell-by-cell match.

## v=0x01 — Sierra MC7700 / MDM9200 SSS-peak table (168B fixed, structured)

A distinct oldest-silicon layout, exclusive to the Sierra MC7700 (SWI9200X,
MDM9200-era): a fixed 168B buffer = 40B (idle-zero) header + 16 × 8B SSS-peak
slots, a slot populated iff its first 8B are non-zero (same emptiness rule as
v=0x16/0x29). Per-slot: `a`=u16@+0, `b`=u16@+2 (large ~0x91xx correlation-
energy-shaped), `pci`=(u16@+4)&0x1FF, reserved u16@+6==0. `a` is NOT a
strength-sorted rank (only 22% of multi-entry records are monotone in `a`),
so `a`/`b` are surfaced as neutral structural metrics, semantics deferred.
Unlike every other version, v=0x01 carries **no EARFCN** (header is zero) — the
SSS detection runs implicitly on the serving E-UTRA channel, logged by sibling
codes, so top-level `earfcn` stays 0 and no channel field is invented.

### F3 verdict v0x01: grounded via a cross-log in-capture oracle (no F3 plane on MDM9200)

Version-bound over the **full 654-record MC7700 v=0x01 corpus** (8 captures,
SWI9200X firmware 03.05.10/20/29). This silicon predates the QSH/QSR4 F3
plane (no F3 stream in any MC7700 capture), as with the sibling 0xB196 v=0x02
on the same modem, so no F3 oracle exists. The stand-in is a **cross-log
in-capture oracle**: the same 8 captures' 0xB0C0 (LTE RRC OTA,
v=0x02-grounded on MC7700) **and** 0xB196 (LTE ML1 cell-meas,
v=0x02-grounded) both report serving EARFCN **2175** (unanimous — 0xB196
2175/2175, 0xB0C0 2175/2175) and serving PCI **473** (381 records). The
v=0x01 SSS table's slot-0 `pci` == **473** in 317 records (the plurality) —
1:1 with the serving PCI the two independent RRC/ML1 logs report from
different firmware paths. Two structural checks make `pci` the grounded
field, not a coincidence: (1) the `pci` field's corpus-wide maximum is
**exactly 503** (= the LTE PCI ceiling N_ID_cell = 3·N_ID_1 + N_ID_2, 0..503) —
an arbitrary metric would not cap precisely there; (2) the high bits (`raw>>9`)
are 0 on **all 1924** populated slots (a clean 9-bit PCI, no flag). The
non-slot-0 PCIs (400/346/195/166/…, all ≤503) are SSS-detected
candidate/neighbour peaks — the same superset-detector behaviour seen on
v=0x16/v=0x29 — and are surfaced but not individually oracle-matched. EARFCN
is not carried on v=0x01, so only `pci` is grounded here.

## v=0x18 — Quectel SC200E (QCM2290) empty SSS buffer (296B)

Every observed record is 0x18 + 295 zero bytes, co-temporal with the F3
"Acq search results for bin 0: 0 cells found". Only this all-zero form is
admitted (decoded as `num_entries=0`); a populated v=0x18 returns None.

## Caveat on the legacy `earfcn@offset4` attribution

`earfcn` is the u32-LE at byte-offset 4, validated as the cell EARFCN via
an LM960A18 DIAG×AT correlation. On em9291 v=0x7a **8B** records, u32@4
*increments* (40377 -> 40378 ...) like a sequence counter; on 24B+ v=0x7a
records it is a smaller steadier value (~0x044c). The `earfcn` semantic is
therefore likely **format-specific** (it holds for the LM960 format; a
per-format AT re-check is still open). The `earfcn` to_dict key is preserved
bit-for-bit as a downstream contract regardless.

Log name: LTE LL1 SSS Results
Also known as: LOG_LTE_LL1_SSS_RESULTS, LOG_SSS_RESULTS
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

# v=0x7a / 0x79 entry-array geometry
_ENTRY_FORMATS = (0x7A, 0x79)
_HEADER_SIZE = 8
_ENTRY_SIZE = 16
_COUNT_STRIDE = 0x20  # u16@1 == 0x20 * N + header_low5  (count = u16@1 >> 5)
_COUNT_SHIFT = 5
_LOW5_MASK = 0x1F

# Slot-array fixed-buffer geometry, shared by v=0x16 and v=0x29: a 40B header
# followed by (len-40)//32 fixed 32B cell-slots, established on EG25-G (v=0x16,
# 296B = 40 + 8x32) and EM7455 (v=0x29, 608B = 40 + 17x32): earfcn @ slot+6 (u16)
# and pci = (u16 @ slot+2) & 0x1FF both ground 1:1 against AT cell info
# cell-by-cell. The two formats differ ONLY in the version byte and the slot
# count (the per-slot layout is identical).
_V16_FORMAT = 0x16
_V29_FORMAT = 0x29
_V16_HEADER = 40
_V16_ENTRY = 32
_PCI_MASK = 0x1FF  # LTE PCI is 9 bits (0..503); the high 7 bits are a detect flag
# version byte -> exact fixed payload length (slot-array formats)
_SLOT_FORMATS = {_V16_FORMAT: 296, _V29_FORMAT: 608}

# v=0x01 — Sierra MC7700 (SWI9200X / MDM9200-era) SSS peak table.
# A fixed 168B buffer: 40B (mostly-zero) header + 16 × 8B SSS-peak entries; a
# peak slot is populated iff its first 8 bytes are non-zero. See the v=0x01
# section of the module docstring for the grounding.
_V01_FORMAT = 0x01
_V01_LEN = 168
_V01_HEADER = 40
_V01_ENTRY = 8

# v=0x18 — Quectel SC200E (QCM2290), 296B. Every corpus record
# (288, one capture) is 0x18 + 295 zero bytes, each co-temporal with F3
# lte_ml1_sm_acq.c:2830 "Acq search results for bin 0: 0 cells found": an EMPTY
# SSS result. The size equals v=0x16's, but no v=0x18 slot has ever been
# populated, so the v=0x16 slot offsets are unverified here (size invariance is
# not format invariance): only the all-zero form is admitted, and a populated
# v=0x18 returns None (registry WARN) as the trigger for its own RE pass.
_V18_FORMAT = 0x18
_V18_LEN = 296

# All six format-discriminator bytes observed across the corpus.
_KNOWN_FORMATS = (0x01, 0x16, 0x18, 0x29, 0x79, 0x7A)


@dataclass
class Diag0xB115:
    """0xB115 — LTE LL1 SSS detection results (legacy `LteMacB115`).

    For format 0x7a/0x79 the body is an 8B header (`u16@1 == 0x20*num_entries`)
    followed by `num_entries` x 16B entries, each surfaced as a dict of
    neutral structural fields. Formats 0x16 (MDM9207 EG25-G/EG95NA, 296B = 8
    slots) and 0x29 (MDM9230 EM7455/MC7455 + EP06A, 608B = 17 slots) are decoded
    as a 40B header + N x 32B cell-slots: each populated slot carries
    `{earfcn, pci, pci_flag, a, measurement}`.
    Top-level `earfcn` is the u32-LE at byte-offset 4
    (legacy contract; preserved on every path — for the slot formats the
    grounded EARFCN lives per-slot in `entries[*].earfcn`, not at offset 4).
    """
    log_time: int
    version: int
    earfcn: int
    num_entries: int | None
    entries: list[dict[str, int]]
    structured: bool
    data_density: float
    payload_size: int
    body_raw: bytes
    # v=0x7a/0x79 only: bits 0..4 of the u16@1 count word (0..4 in the corpus,
    # semantics unknown). None on the other formats.
    header_low5: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB115",
            "log_time": self.log_time,
            "version": self.version,
            "earfcn": self.earfcn,
            "num_entries": self.num_entries,
            "entries": self.entries,
            "structured": self.structured,
            "data_density": self.data_density,
            "payload_size": self.payload_size,
            "body_raw": self.body_raw,
            "header_low5": self.header_low5,
        }


def _earfcn(data: bytes) -> int:
    """Legacy contract: u32-LE @ offset 4, with the <8B / <2B fallback."""
    if len(data) >= 8:
        return unpack_from('<I', data, 4)[0]
    if len(data) >= 2:
        return data[1]
    return 0


def _density(data: bytes) -> float:
    if len(data) > 2:
        nonzero = sum(1 for b in data[2:] if b != 0)
        return round(nonzero / max(len(data) - 2, 1), 2)
    return 0.0


def _decode_entries(data: bytes, n_slots: int) -> list[dict[str, int]]:
    entries: list[dict[str, int]] = []
    for s in range(n_slots):
        off = _HEADER_SIZE + s * _ENTRY_SIZE
        a, b, c, sentinel, measurement = unpack_from('<HHhHh', data, off)
        flag = data[off + 10]
        # The 16B entry's bytes [11:16]: across 326 RM500Q-AE entries, byte[12]
        # is a sparse QUANTIZED field — values {0x00,0x10,0x20,0x30} = (0..3)<<4,
        # present on ~20% of entries (an upper-nibble 2-bit field, semantics
        # unknown); bytes [11],[13],[14],[15] are reserved/zero (>99.5% zero
        # across the corpus). byte[12] is surfaced raw.
        field_12 = data[off + 12]
        entries.append({
            "a": a,
            "b": b,
            "c": c,
            "sentinel": sentinel,
            "measurement": measurement,
            "flag": flag,
            "field_12": field_12,
        })
    return entries


def _decode_slot_entries(data: bytes) -> list[dict[str, int]]:
    """Slot-array decode for v=0x16 (8 slots) and v=0x29 (17 slots).

    Both formats are a 40B header + (len-40)//32 fixed 32B cell-slots; a slot
    is populated iff its first 8 bytes are non-zero (trailing zero-filled slots
    are unused capacity). Per-slot layout (grounded against AT cell info on
    EG25-G v=0x16 + EM7455 v=0x29):

        +0  u16  a            (unidentified — neither EARFCN nor PCI)
        +2  u16  pci_raw      pci = pci_raw & 0x1FF; pci_flag = pci_raw >> 9
        +4  u16  (zero)
        +6  u16  earfcn       E-UTRA channel the SSS detection ran on
        +16 i16  measurement  signed SSS detection metric (correlation-shaped)
    """
    entries: list[dict[str, int]] = []
    n_slots = (len(data) - _V16_HEADER) // _V16_ENTRY
    for s in range(n_slots):
        off = _V16_HEADER + s * _V16_ENTRY
        if off + 18 > len(data) or not any(data[off:off + 8]):
            continue
        a, pci_raw = unpack_from('<HH', data, off)
        earfcn = unpack_from('<H', data, off + 6)[0]
        measurement = unpack_from('<h', data, off + 16)[0]
        entries.append({
            "earfcn": earfcn,
            "pci": pci_raw & _PCI_MASK,
            "pci_flag": pci_raw >> 9,
            "a": a,
            "measurement": measurement,
        })
    return entries


def _decode_v01_entries(data: bytes) -> list[dict[str, int]]:
    """SSS-peak decode for v=0x01 (Sierra MC7700 / MDM9200, 168B fixed buffer).

    Layout derived from the full 654-record MC7700 v=0x01 corpus (8 captures,
    SWI9200X firmware 03.05.x). A 40B (idle-zero) header
    followed by 16 × 8B SSS-peak slots; a slot is populated iff its first 8B are
    non-zero (trailing zero slots are unused capacity, like v=0x16/0x29):

        +0  u16  a      neutral structural metric A (NOT sorted by strength —
                        only 22%% of multi-entry records are monotone in a)
        +2  u16  b      neutral structural metric B (large, ~0x91xx / 0xCcxx —
                        SSS correlation-energy-shaped; semantics deferred)
        +4  u16  pci    physical cell ID (9-bit, 0..503); pci = raw & 0x1FF
        +6  u16  (zero) reserved (0 on 100%% of the 1924 populated slots)

    The top-level `earfcn` (u32@4) is 0 on v=0x01 (zero header): the MC7700 does
    NOT carry the E-UTRA channel in the SSS log — the detection runs implicitly
    on the serving EARFCN (2175 across all 8 captures per the same-capture
    0xB0C0/0xB196 oracle), which is logged by sibling codes, not here. So NO
    earfcn field is invented for v=0x01. The grounded quantity is `pci`.
    """
    entries: list[dict[str, int]] = []
    n_slots = (len(data) - _V01_HEADER) // _V01_ENTRY
    for s in range(n_slots):
        off = _V01_HEADER + s * _V01_ENTRY
        if off + 8 > len(data) or not any(data[off:off + 8]):
            continue
        a, b, pci_raw, _reserved = unpack_from('<HHHH', data, off)
        entries.append({
            "a": a,
            "b": b,
            "pci": pci_raw & _PCI_MASK,
            "pci_flag": pci_raw >> 9,
        })
    return entries


# Ground-truth recipe. RM520N-GL SDX62 emits the structured v=0x7a form
# (8B header + N×16B SSS-peak entries) — verified on a live capture: earfcn
# decoded (2300, 66786) with per-entry `measurement` (i16, RF/correlation
# shaped). SSS detection fires during cell search, so drive a PLMN scan to
# populate the entry array, then correlate the per-EARFCN peak against the
# neighbour-cell signal the modem reports for that frequency. Entry internals
# are deferred in the parser, so every mapped entry field is a hypothesis whose
# identity AND scale the correlation must recover.
#
# --- Per-modem fan-out (structured v=0x7a / v=0x79 emitters) -----------------
# Each modem carries its OWN recipe (own ``recipe_key`` = (version, make, model,
# firmware)); ``emitting_modems`` is informational, NOT coverage. The RM520N-GL
# v=0x7a recipe above is the hardware-verified template; each roster entry below
# replicates its falsifiable field map in the emitter's native vendor AT/QMI
# dialect, keyed to the format byte (== version) that modem actually emits in
# the corpus (confirmed from the byte-0 offset distribution of its captures).
# All fields are authored ``status="hypothesis"`` (hw_run_performed=False): the
# RM520N-GL run is a strong cross-modem prior for the same structured format,
# NOT a per-modem validation — each cell awaits its own hardware run.
#
# v=0x16 (eg25g, eg95na) and v=0x29 (em7455, mc7455, ep06a) are decoded and
# hardware-validated: the shared 40B-header + 32B cell-slot layout
# (_decode_slot_entries) with per-slot earfcn (slot+6) and pci
# ((u16@slot+2)&0x1FF) grounds 1:1 against AT cell info. The EG25-G v=0x16 and
# EM7455 v=0x29 GroundTruths carry these runs; eg95na (v=0x16) and mc7455/ep06a
# (v=0x29) share the format and await their own hardware runs. mc7700 (v=0x01)
# has no recipe here.

# parser_field -> (ground-truth quantity, base note). One FieldGround per entry,
# mirroring the RM520N-GL template; {model} is filled per modem.
_B115_FANOUT_FIELDS = (
    ("earfcn", "lte_ll1_sss_earfcn",
     "u32@4 (legacy contract key) — the E-UTRA channel the SSS detection "
     "ran on. The earfcn == serving/neighbour EARFCN identity was hardware-"
     "verified on RM520N-GL v=0x7a (exact 1:1, no "
     "scale); this recipe expects the same on {model}. Match a serving/neighbour "
     "EARFCN from the reference command(s) below to anchor each record."),
    ("entries.measurement", "lte_sss_detection_metric_candidate",
     "i16 per-peak SSS detection metric (clustered-negative / RF-correlation "
     "shaped; sign was scan-vs-track state dependent on RM520N-GL). Correlate "
     "against the matched cell's RSRP and recover whether it is a raw "
     "correlation magnitude or a dBm-scaled quantity (the RM520N-GL run found "
     "raw magnitude, not dBm)."),
    ("entries.b", "lte_sss_detected_pci_candidate",
     "u16 @ ent[2:4]; (b & 0x1FF) is the 9-bit detected PCI, the top 7 bits a "
     "detected-this-scan flag. The mask width is SETTLED: PCI>255 cells on "
     "LV55 (310), SIM8202G-M2 (471) and EM7565 v0x79 (451, F3-confirmed) each "
     "need the 9-bit &0x1FF read (a low-byte &0xFF read gives 54/215/195 — "
     "wrong). Match (b & 0x1FF) to the detected cell PCI from the reference "
     "below."),
    ("entries.c", "lte_sss_secondary_metric_candidate",
     "i16 secondary per-peak metric, neutral name (RSRQ-like / frequency-offset "
     "/ timing-fraction hypotheses). Sweep against the neighbour RSRQ and PCI; "
     "weakest field, expect to stay open."),
    ("num_entries", "lte_sss_detected_peak_count",
     "N from u16@1 == 0x20*N — number of SSS peaks detected on the earfcn. "
     "Bound by the count of distinct neighbour PCIs the reference reports on "
     "that frequency (the detector may surface more peaks than survive to the "
     "cell list)."),
)

# dialect -> {parser_field: ((source_kind, command, per-source note), ...)}.
# Every command string is in the tools/tests/test_ground_truth_refs.py allow-list.
_B115_FANOUT_DIALECT = {
    "quectel": {
        "earfcn": (("at", 'AT+QENG="neighbourcell"', "<earfcn> column of the LTE neighbour rows"),
                   ("at", 'AT+QENG="servingcell"', "<earfcn> of the camped cell, if the peak is the serving freq")),
        "entries.measurement": (("at", 'AT+QENG="neighbourcell"', "per-neighbour RSRP/RSRQ on the matched EARFCN"),
                                ("at", "AT+CESQ", "serving RSRP (rsrp field) / RSRQ if the SSS peak is the serving cell")),
        "entries.b": (("at", 'AT+QENG="neighbourcell"', "<PCID> column of the neighbour rows on the matched EARFCN"),
                      ("at", 'AT+QENG="servingcell"', "<PCID> of the serving cell")),
        "entries.c": (("at", 'AT+QENG="neighbourcell"', "neighbour RSRQ / PCI columns on the matched EARFCN"),),
        "num_entries": (("at", 'AT+QENG="neighbourcell"', "number of neighbour rows sharing the matched EARFCN"),),
    },
    "telit": {
        "earfcn": (("at", "AT#RFSTS", "serving EARFCN field of the LTE serving-cell row"),
                   ("at", "AT#MONI", "serving + strongest-neighbour EARFCN")),
        "entries.measurement": (("at", "AT#RFSTS", "serving RSRP / RSRQ / SINR"),
                                ("at", "AT#MONI=0", "per-neighbour RSRP rows on the matched EARFCN"),
                                ("at", "AT+CESQ", "serving RSRP/RSRQ fallback")),
        "entries.b": (("at", "AT#MONI", "serving / neighbour PCI (PCID field)"),
                      ("at", "AT#SERVINFO", "serving cell physical-cell-id")),
        "entries.c": (("at", "AT#RFSTS", "serving RSRQ"),),
        "num_entries": (("at", "AT#MONI=0", "number of neighbour rows on the matched EARFCN"),),
    },
    "sierra": {
        "earfcn": (("at", "AT!GSTATUS?", "LTE serving EARFCN / channel line"),
                   ("qmi", "QMI_NAS GetCellLocationInfo", "neighbour EARFCN per detected cell")),
        "entries.measurement": (("at", "AT!GSTATUS?", "serving RSRP / RSRQ"),
                                ("qmi", "QMI_NAS GetCellLocationInfo", "per-neighbour RSRP on the matched EARFCN"),
                                ("at", "AT+CESQ", "serving RSRP/RSRQ fallback")),
        "entries.b": (("at", "AT!GSTATUS?", "serving PCI"),
                      ("qmi", "QMI_NAS GetCellLocationInfo", "neighbour PCI per cell")),
        "entries.c": (("at", "AT!GSTATUS?", "serving RSRQ"),
                      ("at", "AT+CESQ", "RSRQ")),
        "num_entries": (("qmi", "QMI_NAS GetCellLocationInfo", "number of detected cells on the matched EARFCN"),),
    },
    "simcom": {
        "earfcn": (("at", "AT+CPSI?", "serving EARFCN field of the LTE CPSI line"),),
        "entries.measurement": (("at", "AT+CPSI?", "serving RSRP field"),
                                ("at", "AT+CESQ", "serving RSRP/RSRQ")),
        "entries.b": (("at", "AT+CPSI?", "serving PCI field"),),
        "entries.c": (("at", "AT+CPSI?", "serving RSRQ field"),
                      ("at", "AT+CESQ", "RSRQ")),
        "num_entries": (("at", "AT+CPSI?", "single camped cell — N>1 implies multi-peak detection beyond the serving cell"),),
    },
    "qmi": {
        "earfcn": (("qmi", "QMI_NAS GetCellLocationInfo", "intra/inter-freq neighbour EARFCN per detected cell"),
                   ("qmi", "QMI_NAS GetServingSystem", "serving-cell EARFCN")),
        "entries.measurement": (("qmi", "QMI_NAS GetCellLocationInfo", "per-neighbour RSRP on the matched EARFCN"),
                                ("qmi", "QMI_NAS GetSignalInfo", "serving RSRP / RSRQ / SNR"),
                                ("at", "AT+CESQ", "serving RSRP/RSRQ if a 3GPP AT port is exposed")),
        "entries.b": (("qmi", "QMI_NAS GetCellLocationInfo", "neighbour PCI per cell on the matched EARFCN"),
                      ("qmi", "QMI_NAS GetServingSystem", "serving PCI")),
        "entries.c": (("qmi", "QMI_NAS GetCellLocationInfo", "neighbour RSRQ per cell"),
                      ("at", "AT+CESQ", "RSRQ")),
        "num_entries": (("qmi", "QMI_NAS GetCellLocationInfo", "number of detected cells on the matched EARFCN"),),
    },
}

# (make, model, firmware, slug, version, dialect). version = corpus byte[0]
# (0x7a=122 / 0x79=121); firmware = the build dir that emitted the records.
_B115_FANOUT_ROSTER = (
    ("Quectel",         "EG12-GT",     "EG12GTPAR01A14M4G",               "eg12-gt",     0x7A, "quectel"),
    ("Quectel",         "EG18-NA",     "EG18NAPAR01A06M4G",               "eg18-na",     0x7A, "quectel"),
    ("Quectel",         "RM500Q-AE",   "RM500QAEAAR11A03M4G_01.200.01.200", "rm500q-ae", 0x7A, "quectel"),
    ("Telit",           "FN980m",       "38.03.282-P0H.000700",            "fn980m",       0x7A, "telit"),
    # Telit LM960 has a dedicated hw_run_performed GroundTruth instead.
    ("Sierra Wireless", "EM9190",      "SWIX55C_03.17.04.00",             "em9190",      0x7A, "sierra"),
    ("Sierra Wireless", "EM9291",      "SWIX65C_02.17.08.00",             "em9291",      0x7A, "sierra"),
    # SIMCom SIM8202G-M2 (v0x7a) has a dedicated hw_run_performed GroundTruth
    # instead — earfcn verified (COPS-swept superset, F3 channel:66786) +
    # entries.b verified (b&0x1FF dominant {236,471} == QMI; 471>255 re-confirms
    # the 9-bit mask on a second SDX55 unit). Listing it here would duplicate it.
    # Casa CFW-3212 (v0x7a) likewise has a dedicated hw_run_performed
    # GroundTruth — earfcn + pci both verified (limited-service RG520N-NA on
    # EARFCN 2300, header earfcn == AT+QENG serving exact, entries.b low-byte 236
    # == serving PCI with a 0x04 detect-flag high byte) on a COPS dereg/rescan
    # capture. Listing it here would duplicate it.
    ("Foxconn",         "T99W175",     "T99W175.F0.1.0.0.9.VZ.009",       "t99w175",     0x7A, "qmi"),
    ("Inseego",         "M2000",       "MiFiOS2-2.302.1.24",              "m2000",       0x7A, "qmi"),
    ("Inseego",         "SkyUS-500V",  "SDx20WID-1.22.4.1",               "skyus500v",   0x7A, "qmi"),
    # Wistron LV55 (v0x7a) has a dedicated hw_run_performed GroundTruth instead
    # — earfcn + entries.b verified; its PCI 310 (>255) settles the b&0x1FF
    # 9-bit mask vs low-byte question in favour of the 9-bit mask. Listing it
    # here would duplicate it.
    ("Sierra Wireless", "EM7511",      "SWI9X50C_01.14.22.00",            "em7511",      0x79, "sierra"),
    # em7565 + mc7411 (both v0x79) are NOT in this hypothesis fan-out — each has
    # its own hardware-run recipe in the ground-truth store (earfcn verified on
    # both). Listing them here would duplicate them.
)


# --- v=0x16 / v=0x29 slot-format SIBLING fan-out ----------------------------
# The slot formats (v=0x16 296B/8 slots, v=0x29 608B/17 slots) share the
# _decode_slot_entries layout (40B header + 32B cell-slots), with field names
# DIFFERENT from the v=0x7a structured array — so they cannot reuse the
# _b115_fanout_recipe above. The HW-verified cells are EG25-G (v=0x16) and EM7455
# (v=0x29); the roster below is the OFFLINE sibling set — each modem emits the
# identical slot format (confirmed via corpus_index size==296/608 + .scan.json
# byte0), so each carries its OWN recipe_key with the EG25-G/EM7455-verified
# field map, all fields status="hypothesis" (hw_run_performed=False) pending its
# own hardware run. Mirrors the hand-written EG95-NA v=0x16 sibling.
_B115_SLOT_FIELDS = (
    ("entries.earfcn", "lte_ll1_sss_earfcn",
     "u16 @ slot+6 — the E-UTRA channel the SSS detection ran on. VERIFIED 1:1 "
     "vs AT cell-info EARFCN on the HW siblings of this exact slot format "
     "(EG25-G v=0x16 / EM7455 v=0x29, no scale); expected identical on {model}. "
     "The decoded slot-earfcn set is a SUPERSET of the AT-reported list (the "
     "cell search sweeps every carrier) — match a decoded earfcn to an "
     "AT-reported EARFCN to anchor the slot, then promote on a {model} drive."),
    ("entries.pci", "lte_sss_detected_pci",
     "(u16 @ slot+2) & 0x1FF — the 9-bit physical cell ID of the SSS peak (top 7 "
     "bits are a detect-state flag). VERIFIED on the HW siblings (top decoded "
     "PCIs == the AT intra-freq pair on the best-populated EARFCN); expected "
     "identical on {model}. Match (pci & 0x1FF) to the AT PCI on the matched "
     "EARFCN."),
    ("entries.measurement", "lte_sss_detection_metric_candidate",
     "i16 @ slot+16 — a signed SSS detection metric (correlation-peak shaped, "
     "clustered negative on the siblings). Per-peak detection strength is the "
     "working hypothesis; the raw->dBm scale is unrecovered (needs a wider-RSRP "
     "{model} drive). Not a plain AT RSRP under any linear map on the siblings."),
    ("entries.a", "lte_sss_slot_field_a_candidate",
     "u16 @ slot+0 — leading per-slot field, neither EARFCN nor PCI on the "
     "siblings (values >503 rule out a second PCI). Possibly a correlation "
     "magnitude, a timing/CP offset, or a detector slot index. Surfaced raw with "
     "a neutral name pending a {model} drive that varies it."),
    ("num_entries", "lte_sss_detected_peak_count",
     "count of populated 32B slots (slot 'live' iff its first 8 bytes are "
     "non-zero). Real count on the siblings; its bound vs the AT neighbour count "
     "needs a multi-cell {model} drive. Bound by the count of distinct neighbour "
     "PCIs the reference reports on the matched freq."),
)

# dialect -> {slot parser_field: ((at_command, per-source note), ...)}.
# Every command string is in the tools/tests/test_ground_truth_refs.py allow-list.
_B115_SLOT_DIALECT = {
    "quectel": {
        "entries.earfcn": (('AT+QENG="neighbourcell"', "<earfcn> column of the LTE neighbour rows"),
                           ('AT+QENG="servingcell"', "<earfcn> of the camped cell")),
        "entries.pci": (('AT+QENG="neighbourcell"', "<PCID> column of the neighbour rows on the matched EARFCN"),
                        ('AT+QENG="servingcell"', "<PCID> of the serving cell")),
        "entries.measurement": (('AT+QENG="neighbourcell"', "per-neighbour RSRP/RSRQ on the matched EARFCN"),),
        "entries.a": (('AT+QENG="neighbourcell"', "neighbour RSRP/RSRQ/PCI columns to sweep against"),),
        "num_entries": (('AT+QENG="neighbourcell"', "number of neighbour rows on the matched EARFCN"),),
    },
    "sierra": {
        "entries.earfcn": (("AT!LTEINFO?", "Serving / IntraFreq / InterFreq EARFCN rows"),
                           ("AT!GSTATUS?", "LTE Rx chan (serving EARFCN)")),
        "entries.pci": (("AT!LTEINFO?", "Serving / IntraFreq PCI column on the matched EARFCN"),),
        "entries.measurement": (("AT!LTEINFO?", "per-neighbour RSRP/RSRQ on the matched EARFCN"),),
        "entries.a": (("AT!LTEINFO?", "neighbour RSRP/RSRQ/PCI columns to sweep against"),),
        "num_entries": (("AT!LTEINFO?", "number of IntraFreq/InterFreq rows on the matched EARFCN"),),
    },
    "simcom": {
        # AT+CPSI? reports only the SINGLE serving cell — no neighbour list — so on
        # SIMCom only the serving slot grounds from AT; the decoded slot set is the
        # SSS sweep superset. CESQ adds a serving RSRP/RSRQ anchor.
        "entries.earfcn": (("AT+CPSI?", "serving EARFCN field of the LTE CPSI line"),),
        "entries.pci": (("AT+CPSI?", "serving PCI field of the CPSI line"),),
        "entries.measurement": (("AT+CPSI?", "serving RSRP field"),
                                ("AT+CESQ", "serving RSRP/RSRQ")),
        "entries.a": (("AT+CPSI?", "serving RSRP/RSRQ/PCI to sweep against"),),
        "num_entries": (("AT+CPSI?", "single camped cell — N>1 implies multi-peak detection beyond the serving cell"),),
    },
}


# Layer-1 gate on the DECLARED version enum: an unknown format byte returns
# None, so the registry WARN fires.
_VERSIONS_B115_4918: tuple[int, ...] = _KNOWN_FORMATS


@register(
    0xB115,
    name="0xB115",
    wigle_direct=False,
    wigle_roles=("pci-earfcn-bridge",),
    description=(
        "0xB115 -- LTE LL1 SSS detection results (LOG_LTE_LL1_SSS_RESULTS); v0x7a/0x79 = "
        "8B header (N = u16@1 >> 5, low 5 bits = header_low5) + N x 16B SSS-peak entries; v0x16 = 40B header + 8 x 32B "
        "cell-slots (earfcn@+6, pci=(u16@+2)&0x1FF); v0x29 = 40B header + 17 x 32B cell-slots (same layout); "
        "v0x18 = 296B empty SSS buffer only (SC200E/QCM2290, F3 '0 cells found')"
    ),
    version=21,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Multi-format decode keyed on byte 0, covering every observed record. "
        "v=0x7a/0x79 (SDX62, SDX55, MDM9628, MDM9x50): 8B header (entry count "
        "N = u16@1 >> 5, low 5 bits = header_low5, values 0..4, semantics unknown; "
        "u32@4 = earfcn) + N x 16B SSS-peak entries; (u16@1 >> 5) == (len - 8) / 16 "
        "on 999/999 records across EM9291, RM500Q-AE, CFW-3212 and FN980. Header "
        "earfcn and (entries.b & 0x1FF) as the detected PCI are hardware-verified "
        "against AT/QMI cell info on RM520N-GL, LM960, RM500Q-AE, CFW-3212, LV55, "
        "SIM8202G-M2, MC7411 and EM7565; PCI > 255 matches (310, 451, 471) "
        "establish the 9-bit mask. On EM7565 v=0x79 the same capture's F3 "
        "(lte_rrc_csp.c 'Camped on physical cell ID 451 on earfcn 55340') matches "
        "earfcn and PCI 1:1. "
        "v=0x16 (296B, MDM9607 EG25-G/EG95NA) and v=0x29 (608B, MDM9x30/SDX20 "
        "EM7455/MC7455/EP06A): 40B header + 8 / 17 x 32B cell-slots, per-slot "
        "earfcn=u16@+6, pci=(u16@+2)&0x1FF, measurement=i16@+16; AT-grounded "
        "cell-by-cell and F3-grounded in-capture (serving 'Physical CellId:236 … "
        "DL Freq:2300'; v=0x16 PCI 471 > 255 needs the 9-bit mask). Extra slots "
        "are SSS-detected neighbour peaks (a superset of the reported cell list). "
        "v=0x01 (168B, Sierra MC7700 / MDM9200): 40B zero header + 16 x 8B "
        "SSS-peak slots {a u16@+0, b u16@+2, pci=(u16@+4)&0x1FF, reserved u16@+6}; "
        "no F3 plane on this silicon, so grounded by a cross-log in-capture oracle "
        "over 654 records / 8 captures: slot-0 pci == 473 (317 records) == the "
        "serving PCI that 0xB0C0 and 0xB196 report; pci corpus max is exactly 503 "
        "and the high bits are 0 on all 1924 populated slots. v=0x01 carries no "
        "EARFCN. "
        "v=0x18 (296B, Quectel SC200E / QCM2290): only the all-zero empty SSS "
        "buffer is admitted (decoded as num_entries=0), co-temporal (287/288, "
        "time-shifted controls 0/288) with F3 'Acq search results for bin 0: 0 "
        "cells found'; a populated v=0x18 returns None. "
        "Every format is exact-size; truncated or over-long payloads and unknown "
        "format bytes return None (registry WARN). Known gaps: entry fields a, c "
        "and measurement (scale) and field_12 are unidentified; the top-level "
        "earfcn at u32@4 is format-specific (a counter on 8B v=0x7a records, 0 on "
        "the slot formats and v=0x01)."
    ),
    source_url="",
    issues=(),
    primary_issue=None,  # canonical primary tracker
    field_invariants={
        "version": {"enum": list(_KNOWN_FORMATS)},
    },
    fields_identified=5,
    fields_parsed=6,  # + header_low5 (raw; semantics unknown)
)
def parse_0xb115(log_time: int, data: bytes) -> Diag0xB115 | None:
    if not data or data[0] not in _VERSIONS_B115_4918:  # loud version gate
        return None
    if len(data) < 1:
        return None
    version = data[0]
    # Every format is exact-size. A payload whose length is not the one its
    # format byte declares returns None (registry WARN): shorter is truncated,
    # longer is an undecoded form. A 690-capture census holds no off-size
    # record of any format.
    header_low5: int | None = None
    if version == _V18_FORMAT:
        if len(data) != _V18_LEN or any(data[1:]):
            return None  # off-size, or a populated v=0x18 whose layout is unverified
        # The attested empty SSS buffer: zero detected cells (F3 "0 cells found").
        entries: list[dict[str, int]] = []
    elif version == _V01_FORMAT:
        if len(data) != _V01_LEN:
            return None
        # Sierra MC7700 / MDM9200 SSS-peak buffer (40B header + 16 × 8B slots).
        entries = _decode_v01_entries(data)
    elif version in _SLOT_FORMATS:
        if len(data) != _SLOT_FORMATS[version]:
            return None
        # slot-array fixed buffer (v=0x16: 8 slots / v=0x29: 17 slots) — count
        # the populated cell-slots.
        entries = _decode_slot_entries(data)
    else:  # _ENTRY_FORMATS
        if len(data) < _HEADER_SIZE:
            return None
        # u16@1: bits 5..15 are the entry count (a u16, not a byte: N>=8 sets
        # the high byte), bits 0..4 a separate field.
        word = unpack_from('<H', data, 1)[0]
        n_slots = word >> _COUNT_SHIFT
        if len(data) != _HEADER_SIZE + n_slots * _ENTRY_SIZE:
            return None
        header_low5 = word & _LOW5_MASK
        entries = _decode_entries(data, n_slots)
    num_entries = len(entries)
    structured = True
    return Diag0xB115(
        log_time=log_time,
        version=version,
        earfcn=_earfcn(data),
        num_entries=num_entries,
        entries=entries,
        structured=structured,
        data_density=_density(data),
        payload_size=len(data),
        body_raw=data[1:],
        header_low5=header_low5,
    )
