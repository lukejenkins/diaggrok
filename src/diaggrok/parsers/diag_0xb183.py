"""0xB183 — LTE ML1 PBCH Decode Packet: EARFCN + decoded MIB word (SFN / dl_bandwidth / PCI).

`to_dict()` emits the offset-4/offset-1 field as `earfcn` (never the generic
`config_word`).

### Layout

Byte-0 selects the layout; the v56 (0x38) layout is the older one with 3 bytes
of padding removed after byte 0, so EVERY body offset moves 3 left. The
MDM9625-era v0x01 layout keeps one pad byte and a **16-bit** EARFCN (it predates
the >65535 Band-66 EARFCNs):

    v0x01                     old {0x02, 0x18, 0x28}   v56 {0x38}
    @0  u8  version           @0  u8  version           @0  u8  version
    @2  u16 earfcn            @4  u32 earfcn            @1  u32 earfcn
    @4  u16 (raw, 0 / 0xA000) @8  u16 (raw, 0 / 0xA000) @5  u16
    @6  u32 MIB word          @10 u32 MIB word          @7  u32 MIB word
    @10.. tail (raw)          @14.. tail (raw)          @11.. tail (raw)
    @12 u16 sfn_tti_start

Sizes: 0x01=32B (same 22B tail as 0x02), 0x02=36B, 0x18=100B (44B-class body +
zero pad), 0x28=44B **or 104B** (EM120R-GL: same 44B body + 60 zero bytes),
0x38=34B.

MIB word bitfields (u32-LE):

    bits 0-9    sfn            PBCH-decoded system frame number (0..1023)
    bits 10-12  phich_raw      CANDIDATE (PHICH duration/resource?) — constant 2
                               on every valid decode seen; no oracle → raw
    bits 13-15  dl_bandwidth   MIB dl-Bandwidth enum n6/n15/n25/n50/n75/n100 = 0..5
    bits 16-24  pci            physical cell id (0..503)
    bits 25-31  bits_25_31_raw raw; 1 on ~all SIB-followed decodes, >=2 enriched in
                               non-followed ones, 7/8 on the all-zero failed decodes

`mib_decoded` is False when sfn, phich_raw and dl_bandwidth are ALL zero — the
failed-PBCH signature (y=7/8, no SIB ever read on that cell, e.g. the EG12-GT
fixture). PCI is still populated on those (it comes from the cell search).

Noise decodes: 12 of 20,548 corpus records (7 sources: SIM7600NA, LV55,
RM520N-GL, LM960, SIM8202G, MC7411, RM500Q) carry a RESERVED dl_bandwidth 6/7.
The 4 inspected all sit on weak neighbours whose previous decode failed, with
phich_raw != 2, bits_25_31_raw >= 2 and a non-zero byte @9 (@6 on v56). They
read as PBCH CRC false-passes, so the values are exposed as-is (dl_bandwidth_prb
None) and are NOT pinned as invariants. Trust the MIB most when phich_raw == 2
and bits_25_31_raw == 1.

### v0x01 (MDM9625 / BandLuxe C505): in-capture 0x79 F3 + OTA MIB

29 records, 5 captures, 2 chipsets: HP X5 / Foxconn T77W595 (MDM9625, Verizon,
24 records / 4 captures) and BandLuxe C505 (5 records). Every capture carries
plaintext 0x79 F3:

* **Emitter**: each of the 24 T77W595 records sits within 20k ticks of
  ``lte_ml1_md.c:1698`` "PBCH CNF received, stopping timer" (24/24). This is
  ML1's PBCH-confirm log.
* **earfcn (u16@2) + pci**: the 08 manual-PLMN-scan capture prints
  ``lte_ml1_bplmn_int.c:1376`` "LTE_ML1_BPLMN_EXEC_ACTION_PBCH, <earfcn>, <pci>"
  before each decode, and **9/9** (earfcn, pci) pairs match exactly:
  (2300,<pci>) (5035,<pci>) (900,<pci>) (2050,<pci>) (5780,<pci>) (5230,<pci>)
  (975,<pci>) (475,<pci>) (100,<pci>). ``lte_ml1_sm_main.c:966`` "SM: RX Cfg
  Req freq F BW B cell_id P mode 4" also matches 15/15 on (earfcn, pci). On the
  C505, ``lte_ml1_md.c:1323`` "Sent Init Acq Req; earfcn N" names 5/5 EARFCNs,
  and ``mc_celldb.c:2279`` "Cell ID Update PhyCellId:<pci> FREQ:2300" names the
  decoded PCI.
* **dl_bandwidth**: ``lte_ml1_mcvs.c:2420`` "MIB update, BW %d num_tx_ant %d"
  prints the same MIB enum, 13/13. The RX-Cfg ``BW`` is the pre-PBCH default
  (25 for every band-scan cell, including the 100 RB ones), so it is no oracle.
* **sfn / sfn_tti_start**: the MIB-word sfn is the full 10-bit decode SFN. It
  is 4-aligned + {0,1} (945, 113, 993). u16@12 is that SFN rounded down to the
  40 ms PBCH TTI. It equals 0xB0C1 v0x01 ``sfn`` on 11/11 sibling records, and
  that is the OTA MIB systemFrameNumber x 4 (SCAT pcap BCCH-BCH, 7/7 joinable).
  ``sfn_tti_start`` is exposed on v0x01 only: the other layouts' tail was never
  checked for it.
* **Failed decodes**: the C505's two EARFCN-5780 records carry an all-zero MIB
  word low half (``mib_decoded`` False), the same signature as on 0x02.

### MIB-field grounding (one capture per version)

Grounding (4 captures, one per version, the same ones the EARFCN grounding uses;
plus EM120R-GL for the 104B v0x28 form):

* **pci** — the (earfcn, pci) pair appears in the SAME capture's 0xB0C0 RRC-OTA
  SIB headers (an independent log) on 241/259 records vs a random-PCI baseline of
  2/259: v0x02 46/47, v0x18 32/32, v0x28 148/162, v0x38 15/18; plus the EG25-G
  0x79 F3 `acq_entry_ptr[EARFCN:2300, PCI:<pci>]` (lte_rrc_csp.c) and
  `LTE_ML1_BPLMN_EXEC_ACTION_PBCH, <earfcn>, <pci>` (lte_ml1_bplmn_int.c) exact.
* **sfn** — the next same-(earfcn,pci) 0xB0C0 SIB carries an SFN a median 2-6
  frames later (204/232 within <=16 frames; chance ~1.7%): v0x02 med 5, v0x18
  med 2, v0x28 med 6, v0x38 med 5.
* **dl_bandwidth** — F3 labels the carrier bandwidth enum per EARFCN:
  `rx_chan/rx_chan_to_check=A/B, rx_bw/rx_bw_to_check=a/b`
  (lte_ml1_rfmgr_stm.c:279, EG25-G) and `Storing DC offset table for earfcn N
  bw B` (LM960). Pre-PBCH tunes use a default rx_bw=2, the post-MIB retune the
  real one. Same-capture: v0x02 9/10 EARFCNs (the only miss, 225, has F3 {3,2}),
  v0x18 5/5 (66786->5 vs 688 F3 prints, 800->3 vs 206). No bandwidth F3 on the
  SDX55/SDX62 builds, so v0x28 (RM500Q 12/12, EM120R-GL 3/3) and v0x38 (RM520N
  9/9) are checked against the pooled F3 carrier map: 0 contradictions, and every
  EARFCN maps to ONE bw on all 5 chipsets.

### EARFCN grounding, v0x02: in-capture 0x79 F3 co-emission

EG25-G (MDM9607) COPS band-scan capture. The 50 v0x02 records (36 B) carry, at
`earfcn = u32@4`, 13 distinct EARFCNs
{100, 225, 350, 475, 477, 900, 975, 1100, 2050, 2175, 2300, 5035, 5230}. ALL
13/13 are independently named in the SAME capture's 0x79 plaintext F3 as
`earfcn N` / `EARFCN:N` / `LTE frequency: N` / `rx_chan=N`, from firmware code
paths distinct from the ML1 PBCH log: `lte_rrc_csp.c` ("CSP: Acq requested on
earfcn 5035", "acq_entry_ptr[EARFCN:2300, PCI:<pci>]"), `lte_ml1_mgr_stm.c`
("LTE_CPHY_ACQ_REQ … earfcn 5035"), `lte_ml1_rfmgr_stm.c` (RX-tune
`rx_chan=…`), and `lte_ml1_bplmn_int.c` (inter-freq scan). Zero absences.
Because the capture drives a band-scan, both the B183 log and the F3
RF-manager enumerate the SAME tuned-channel set — set-membership co-emission
(13/13, incl. large non-coincidental values 5035/5230) shows the u32@4 field
is the tuned EARFCN on v0x02.

### EARFCN grounding, v0x28: in-capture labelled 0x79/0x99 F3 co-emission

RM500Q-AE (SDX55) capture with all F3 armed and fully resolved. v0x28 is the
most common 0xB183 version (652 corpus records; the FN980 / SIMCom / RM500Q SDX55
profile). Structural: all 163 v0x28 records are 44 B/byte0=0x28 with
offsets 1-3 uniformly 0x00 and only offset 4 varying — the EARFCN u32 sits at
offset 4 (not the offset-1 v0x38 layout). The 163 records carry, at
`earfcn = u32@4`, 15 distinct EARFCNs. Grounded against the SAME capture's
`earfcn`-labelled F3 (`FFT_debug band N start earfcn X end earfcn Y`, an
independent LTE-searcher path): ALL FIVE Band-66-class values >65535
{66536, 66661, 66786, 66911, 66986} fall inside the F3-reported band-65 sweep
window [66436, 67135]; mid-band 5035/5110 ∈ band-11 [5010,5179], 5230 ∈ band-12
[5180,5279], 9820 ∈ band-29 [9770,9869]. Five distinct 5-digit B66 values landing
in the exact narrow F3 window cannot be a coincidental u32 misalignment (only
`earfcn`-labelled prints count; bare-number hits such as flags, fractional
values, address substrings and RTC counters are excluded). The 6 non-swept values
are all valid LTE EARFCNs on bands the sweep did not enumerate (Band 2:
800/900/975/1100; Band 14: 5330 — also in SCAT's LTE output for a capture on the
same firmware; Band 43: the 43690 singleton, n=1). QCSuper also decodes the same
capture's LTE RRC/NAS.

### EARFCN grounding, v0x18: in-capture labelled 0x99 F3 exact co-emission

LM960A18 (MDM9x40) DIAG×AT correlation capture, 0x99 QSR4 resolved. The
100 B/byte0=0x18 records read `earfcn = u32@4` (offsets 1-3 uniformly 0x00). ALL
FIVE distinct EARFCNs parsed from the v0x18 records — {800, 2300, 5035, 66786,
66911} — are independently named EXACTLY in the SAME capture's F3: `CSP: earfcn= N`
(`lte_rrc_csp.c`, an LTE-RRC cell-selection path) for 800/5035/66786/66911 and
`X2L/X2L_TIMED: APP CFG dl_earfcn: N` (`lte_ml1_sm_irat_meas_timed_stm.c`,
inter-RAT measurement) for 2300 — 5/5 exact-value co-emission, from firmware code
paths distinct from the ML1 PBCH log itself. Two of the five are Band-66 values
>65535 (66786, 66911) — exact 5-digit matches that cannot be a coincidental u32
misalignment. An MC7411 capture also shows 96.6% of v0x18 EARFCNs on F3.

### EARFCN grounding, v0x38: offset-1 EARFCN, in-capture labelled F3

RM520N-GL (SDX62) capture. The 34 B/byte0=0x38 (v56) layout reads
`earfcn = u32@1` (the field sits 3 bytes LEFT of the older @4 layouts). 19 v0x38
records carry 12 distinct in-range EARFCNs {900, 975, 1100, 5035, 5110, 5230,
5330, 5780, 55340, 66536, 66786, 66911}. Grounded against the SAME capture's
labelled F3: exact serving-cell prints `LTE EARFCN:900` and `EARFCN:5230`
(`tle_base.cpp` / `tle_cell_mgr.cpp`) match the offset-1 values; ALL THREE
Band-66 values >65535 {66536, 66786, 66911} ∈ the F3 `FFT_debug band 65 start
earfcn 66436 end earfcn 67135` sweep window (`srchfs.c`); 975/1100 ∈ the band-1
window [600, 1199]; 5035/5110 ∈ the band-11 window [5010, 5179]. Reading
offset-4 instead yields 0x??000000-class garbage (see `_B183_EARFCN_OFFSET`).
(5330 = Band 14, 5780 = Band 17, 55340 = Band 48/CBRS are valid LTE EARFCNs on
bands this capture's searcher did not sweep.)

Log name: LOG_LTE_ML1_PBCH_DECODE_PACKET
"""
from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

# byte-0 version/sub-layout discriminator — every value observed
# at size>4: 0x01 (size 32), 0x02 (size 36), 0x18 (100), 0x28 (44), 0x38 (34). Each byte-0
# corresponds to a distinct fixed size, i.e. byte-0 selects the record layout.
_B183_VERSIONS_OBSERVED = (0x01, 0x02, 0x18, 0x28, 0x38)

# Per-version byte-offset of the u32-LE EARFCN field.
# The EARFCN is a real, F3-grounded field on EVERY observed version — but the
# SDX6x v56 (0x38, 34B) layout puts it at a DIFFERENT offset than the older
# layouts.
#
#   * 0x02/0x18/0x28 → offset 4  (DIAG×AT; F3-confirmed on MC7411 v0x18 96.6%
#     on-F3, EG25-G v0x02 13/13, and RM500Q-AE SDX55 v0x28 — all 5 Band-66
#     values in the same-capture F3 `FFT_debug ... earfcn` band-65 sweep
#     window; corpus 164/164 in-range).
#   * 0x38 (v56)     → offset 1  (NOT offset 4). Grounded three independent
#     ways on RM520N-GL/SDX62: (a) band-control — in
#     the `bandNN_cfun` sweep the u32@4 value swings 402M-3.96B *within* one
#     fixed band (impossible for a frequency), while u32@1 tracks the scanned
#     neighbour EARFCNs; (b) F3 oracle (fully resolved) — real serving
#     EARFCNs are ≤66911 (LTE) / ≤501390 (NR), and u32@1 lands on them incl.
#     the >65535 Band-66 values 66786/66911/66986; (c) a clean control —
#     u32@1 is 8/8 in-range on v56 but 0/44 on v0x18, and u32@4 is the mirror
#     (2/8 on v56, 44/44 on v0x18), so the two layouts are complementary, not a
#     coincidental fit. The legacy offset-4 window caught the two zero high
#     bytes of the (small) EARFCN plus the next field's byte at offset 7 — hence
#     the 0x??000000/0x??a00000-class garbage.
#   * 0x01 (MDM9625) → offset 2, and only a u16: the field predates the
#     >65535 EARFCNs (F3 BPLMN "EXEC_ACTION_PBCH, earfcn, pci" 9/9 exact).
_B183_EARFCN_OFFSET = {0x01: 2, 0x02: 4, 0x18: 4, 0x28: 4, 0x38: 1}
_B183_EARFCN_FMT = {0x01: '<H'}   # every other version: '<I'

# Per-version byte-offset of the u32-LE MIB word: 10 on the old layouts, 7 on
# v56 (the same 3-byte left shift), 6 on v0x01 (u16 EARFCN @2 + u16 @4).
_B183_MIB_OFFSET = {0x01: 6, 0x02: 10, 0x18: 10, 0x28: 10, 0x38: 7}

# v0x01 only: u16 TTI-start SFN (== 0xB0C1 v0x01 sfn == OTA systemFrameNumber x 4).
_B183_SFN_TTI_OFFSET = {0x01: 12}

logger = logging.getLogger(__name__)

# Every record size the corpus attests, per version (13,304 records / 344
# captures: 0x02 36 B, 0x18 100 B, 0x28 44 B or 104 B, 0x38 34 B; plus 0x01
# 32 B, 29 records / 5 captures). 104 B 0x28
# is the 44 B body + 60 zero bytes (EM120R-GL). A payload that is a known size
# followed by zero padding parses as that known size (`_fit_known_size`); any
# other length returns None and logs a length warning (`_length_alarm`).
_B183_KNOWN_SIZES = {0x01: (32,), 0x02: (36,), 0x18: (100,), 0x28: (44, 104), 0x38: (34,)}

# Per-(version, length) count of payloads the padding check could not explain.
# Every one is counted; the WARN fires on the 1st, 10th, 100th, ... (as 0x192A).
_LENGTH_ALARMS: Counter[tuple[int, int]] = Counter()


def _fit_known_size(version: int, data: bytes) -> int | None:
    """The known record size to parse ``data`` as, or None.

    An exact known size is itself. A longer payload whose bytes past a known size
    are all zero is that size plus padding (the largest such size wins, so 105 B
    of 0x28 is the 104 B form). A cut that removes only padding therefore still
    parses (104 -> 103 B is the 44 B body + 59 zero bytes); a cut into the body
    does not.
    """
    n = len(data)
    sizes = _B183_KNOWN_SIZES[version]
    if n in sizes:
        return n
    padded = [k for k in sizes if k < n and not any(data[k:])]
    return max(padded) if padded else None


def _length_alarm(version: int, data: bytes) -> None:
    key = (version, len(data))
    _LENGTH_ALARMS[key] += 1
    n = _LENGTH_ALARMS[key]
    if str(n).rstrip("0") != "1":   # log the 1st, 10th, 100th, ... per length
        return
    sizes = _B183_KNOWN_SIZES[version]
    why = ("shorter than any known size (truncated)" if len(data) < min(sizes)
           else "non-zero bytes past every known size (not padding)")
    logger.warning(
        "diaggrok 0xB183 length issue #%d: version=0x%02X len=%d is not a known "
        "record size %s or a known size + zero padding — %s; dropping",
        n, version, len(data), "/".join(str(s) for s in sizes), why,
    )

# MIB dl-Bandwidth enum (TS 36.331) -> resource blocks.
_DL_BANDWIDTH_PRB = (6, 15, 25, 50, 75, 100)


@dataclass
class Diag0xB183:
    """0xB183 — LTE ML1 PBCH decode: EARFCN + decoded MIB word.

    `earfcn` is a u32-LE at a PER-VERSION byte-offset (`_B183_EARFCN_OFFSET`):
    offset 4 on {0x02, 0x18, 0x28} (DIAG×AT; F3-confirmed) and
    offset 1 on 0x38 (SDX6x v56, 34B — the field sits 3 bytes left;
    F3 + band-control grounded). A payload that is a known record size
    (`_B183_KNOWN_SIZES`) plus zero padding parses as that size; any other
    length returns None with a length warning.

    The MIB word (u32-LE at `_B183_MIB_OFFSET`) carries `sfn`, `dl_bandwidth`
    and `pci` (F3/0xB0C0-grounded, see module docstring) plus two raw slices.
    (Every accepted payload is long enough to hold the word.)
    """
    log_time: int
    version: int
    earfcn: int | None
    data_density: float
    payload_size: int
    body_raw: bytes
    sfn: int | None = None
    dl_bandwidth: int | None = None
    dl_bandwidth_prb: int | None = None
    pci: int | None = None
    phich_raw: int | None = None
    bits_25_31_raw: int | None = None
    mib_decoded: bool | None = None
    sfn_tti_start: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB183",
            "log_time": self.log_time,
            "version": self.version,
            "earfcn": self.earfcn,
            "data_density": self.data_density,
            "payload_size": self.payload_size,
            "body_raw": self.body_raw,
            "sfn": self.sfn,
            "dl_bandwidth": self.dl_bandwidth,
            "dl_bandwidth_prb": self.dl_bandwidth_prb,
            "pci": self.pci,
            "phich_raw": self.phich_raw,
            "bits_25_31_raw": self.bits_25_31_raw,
            "mib_decoded": self.mib_decoded,
            "sfn_tti_start": self.sfn_tti_start,
        }


@register(
    0xB183,
    name="0xB183",
    wigle_direct=False,
    wigle_roles=("pci-earfcn-bridge",),
    description="0xB183 — LTE ML1 PBCH decode: EARFCN + MIB word (sfn, dl_bandwidth, pci), per-version offsets",
    version=13,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Five layouts keyed on byte 0, each with known record sizes (0x01 32 B, 0x02 36 B, "
        "0x18 100 B, 0x28 44 or 104 B, 0x38 34 B — the full corpus census). A "
        "payload that is a known size followed by zero padding parses as that "
        "size (so a cut into 0x28's 60 B pad still decodes the 44 B body); any "
        "other length returns None and logs a rate-limited length warning. "
        "earfcn is a u32-LE at offset 4 on {0x02,0x18,0x28} and at offset 1 on "
        "0x38 (SDX6x v56, the same body moved 3 bytes left); first attributed by "
        "LM960A18 DIAG×AT correlation (116/117 in-band cross-modem) and "
        "F3-grounded on every version: v0x02 (EG25-G MDM9607 COPS band-scan) "
        "13/13 distinct EARFCNs named in same-capture 0x79 F3 at lte_rrc_csp.c / "
        "lte_ml1_mgr_stm.c / lte_ml1_rfmgr_stm.c / lte_ml1_bplmn_int.c sites; "
        "v0x18 (LM960 MDM9x40) 5/5 distinct EARFCNs {800,2300,5035,66786,66911} "
        "exactly match same-capture `CSP: earfcn= N` / `dl_earfcn: N` prints; "
        "v0x28 (RM500Q-AE SDX55, 163 records / 15 EARFCNs) all 5 Band-66 values "
        ">65535 fall inside the same-capture F3 `FFT_debug band 65 ... earfcn` "
        "sweep window [66436,67135]; v0x38 (RM520N-GL SDX62, 12 EARFCNs) exact "
        "serving-cell F3 `LTE EARFCN:900`/`EARFCN:5230` plus all 3 Band-66 values "
        "inside the band-65 sweep window. The v0x38 offset is confirmed three "
        "ways: band-control (u32@4 swings 402M-3.96B within one fixed band while "
        "u32@1 tracks the scanned EARFCNs), the F3 serving EARFCNs, and a "
        "complementary-fit control (u32@1 8/8 in-range on v56 vs 0/44 on v0x18; "
        "u32@4 the mirror). The u32-LE MIB word at EARFCN offset + 6 carries sfn "
        "(bits 0-9), phich_raw (10-12, CANDIDATE, constant 2), dl_bandwidth "
        "(13-15, MIB enum 0..5 -> 6..100 PRB), pci (16-24) and bits_25_31_raw. "
        "v0x01 (MDM9625 T77W595 + BandLuxe C505, 29 records): u16 earfcn @2, MIB "
        "word @6, sfn_tti_start u16 @12; (earfcn, pci) == same-capture F3 "
        "`LTE_ML1_BPLMN_EXEC_ACTION_PBCH, earfcn, pci` 9/9, `RX Cfg Req` 15/15, "
        "dl_bandwidth == `MIB update, BW %d` 13/13, sfn_tti_start == 0xB0C1 sfn "
        "11/11 == OTA systemFrameNumber x 4. "
        "pci: (earfcn,pci) present in same-capture 0xB0C0 SIB headers 241/259 vs "
        "random baseline 2 (v0x02 46/47, v0x18 32/32, v0x28 148/162, v0x38 "
        "15/18) + EG25-G F3 `acq_entry_ptr[EARFCN:2300, PCI:<pci>]`. sfn: next "
        "same-cell SIB SFN leads by median 2-6 frames, 204/232 within 16. "
        "dl_bandwidth: F3 `rx_bw` (lte_ml1_rfmgr_stm.c:279) / `DC offset table "
        "for earfcn N bw B` — same-capture v0x02 9/10, v0x18 5/5; v0x28 (RM500Q "
        "12/12, EM120R-GL 3/3) and v0x38 (RM520N 9/9) vs the pooled F3 carrier "
        "map, 0 contradictions. mib_decoded=False on the all-zero failed-PBCH "
        "records (bits_25_31 7/8). The 18-bit earfcn range invariant flags "
        "misframed records; earfcn=0 search-mode records are valid."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=8,
    fields_parsed=8,
    field_invariants={
        "version": {"enum": list(_B183_VERSIONS_OBSERVED)},
        "earfcn": {"range": (0, 262143)},
        # No pci / dl_bandwidth range: ~12 of 20,548 corpus records are PBCH
        # false-passes with reserved values (see module docstring), real output.
    },
)
def parse_0xb183(log_time: int, data: bytes) -> Diag0xB183 | None:
    if len(data) < 1:
        return None
    version = data[0]
    # Layer-1 byte-0 version gate.
    if version not in _B183_VERSIONS_OBSERVED:
        return None
    # Parse as a known record size, ignoring trailing zero padding; a length
    # that padding cannot explain is dropped with a warning.
    size = _fit_known_size(version, data)
    if size is None:
        _length_alarm(version, data)
        return None
    received = len(data)
    data = data[:size]
    # The EARFCN is a u32-LE at a PER-VERSION offset — 4 on the
    # older layouts, 1 on the SDX6x v56 (0x38) 34B layout that moved it 3B left.
    off = _B183_EARFCN_OFFSET.get(version)
    earfcn: int | None
    efmt = _B183_EARFCN_FMT.get(version, '<I')
    if off is not None and len(data) >= off + (2 if efmt == '<H' else 4):
        earfcn = unpack_from(efmt, data, off)[0]
    elif len(data) >= 2:
        earfcn = data[1]
    else:
        earfcn = 0
    if len(data) > 2:
        nonzero = sum(1 for b in data[2:] if b != 0)
        total = max(len(data) - 2, 1)
        density = round(nonzero / total, 2)
    else:
        density = 0.0
    rec = Diag0xB183(
        log_time=log_time,
        version=version,
        earfcn=earfcn,
        data_density=density,
        payload_size=received,
        body_raw=data[1:],
    )
    # The MIB word, at a per-version offset.
    moff = _B183_MIB_OFFSET[version]
    if len(data) >= moff + 4:
        w = unpack_from('<I', data, moff)[0]
        rec.sfn = w & 0x3FF
        rec.phich_raw = (w >> 10) & 0x7
        rec.dl_bandwidth = (w >> 13) & 0x7
        rec.pci = (w >> 16) & 0x1FF
        rec.bits_25_31_raw = w >> 25
        rec.mib_decoded = bool(w & 0xFFFF)
        if rec.dl_bandwidth < len(_DL_BANDWIDTH_PRB):
            rec.dl_bandwidth_prb = _DL_BANDWIDTH_PRB[rec.dl_bandwidth]
    toff = _B183_SFN_TTI_OFFSET.get(version)
    if toff is not None:
        rec.sfn_tti_start = unpack_from('<H', data, toff)[0]
    return rec
