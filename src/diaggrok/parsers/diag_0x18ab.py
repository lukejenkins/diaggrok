"""LTE ML1 Intra-Frequency Measurement parser (0x18AB).

⚠️ The "LTE ML1 intra-freq" name below is the historical RE label. The v9/st1
records are GTS (GNSS Time Service) source records: each one is emitted from
gts.c just before an F3 print carrying the same values (FEST frequency
estimate, NR5G cell + Qtimer, LTE cell), which matches the vendor_official
"GNSS GTS log" name in the names block. See the v9/st1
block comment. v7/st1 is the same kind of record for the GNSS-ME time
(gts.c "GpsMeTime."); see its block comment. The v6 records (MDM9150 /
MDM9250 C-V2X units) are GTS records too: st0 latch, st1 GNSS-ME time, st3
FEST; see the v6 block comment. v5 st1 is the same GNSS-ME time record 69
bytes into the 466 B buffer; see the v5 note after the v7 st1 block. v5 st2
and v7 st2 are not yet re-checked against gts.c.

0x18AB -- LTE ML1 Intra-Frequency Measurement
    Cell detection records for cells on the serving frequency.
    Emitted ~every 200ms. Fixed 209 bytes (version 7 on SDX20).

    Two subpacket types coexist in the same log code:
        subtype 2 -- Measurement subpacket: reports one detected cell with
                     EARFCN and PCI. Contains raw ML1 measurement data
                     (timing/phase) in bytes 28-47 and a measurement
                     sequence counter at u16@132. RSRP is NOT present;
                     it is derived by the ML1 layer and emitted in 0xB193.
        subtype 3 -- Timing reference subpacket: two u64 timestamps
                     (19.2 MHz system-timer ticks) bracketing a measurement
                     window. No cell identity -- the u32@6 once read as a
                     PCI is the high word of the start timestamp.

    Subtype 2 and 3 records alternate in pairs: a timing record followed
    by a measurement record for each measurement interval.

Reverse-engineered from SDX20 (LM960) drive captures, cross-referenced
against 0xB193 serving cell measurements for validation.

Key findings:
    - Header: version(u8@0) subtype(u8@1) EARFCN(u32@2) PCI(u32@6)
    - Bytes 2-9 are not two u64 timestamps: bytes 2-5 are EARFCN (u32 LE,
      confirmed value 800 = AT&T Band 26), bytes 6-9 are PCI (u32 LE,
      confirmed values 6, 103, etc.).
    - RSRP is NOT encoded anywhere in the 209-byte payload. Exhaustive
      search of all byte offsets, bitfield widths, and the usual DIAG
      RSRP encodings (div10, 0.0625-resolution, bitpacked u32) found
      zero correlation (R^2 < 0.32) with ground truth from 0xB193.
    - The raw measurement data at bytes 32-47 appears to be IQ accumulator
      or timing/phase data: byte 33 always equals byte 41, and values
      vary pseudo-randomly even when RSRP is constant.
    - Byte 30 cycles through multiples of 5 (0,5,10,15,20,25,30,35),
      likely representing subframe timing within a measurement window.
    - u16@132 is a monotonically increasing measurement sequence counter.
    - Bytes 140-208 sometimes contain neighbor cell data when cells are
      detected on the same frequency (e.g., a neighbour PCI appearing in
      records whose header carries a different PCI).

Unique-contribution analysis (relevant to Kismet mapping):
    Across 12 diverse captures (SDX20, MDM9x50, MDM9650, SDX55, SDX62, SDX65;
    6 vendors; v5/v7/v9 framings; drives + surveys + edge-cases), 0x18AB adds
    ZERO unique (pci, earfcn) keys beyond 0xB193/0xB192/0xB195/0xB0C0. Its 32
    decoded cell keys are a strict SUBSET of those codes' union in every
    capture. This mirrors the 0x18AC result: 0x18AB is intra-frequency
    serving-cell measurement, so every cell it names is the serving/intra cell
    that 0xB193 already carries -- it does NOT surface the inter-frequency
    neighbors a Kismet wardrive wants (that is 0x18AC's job, and 0x18AC also
    contributes zero). A latent-neighbor probe shows the result is not an
    artifact of partial decode: the still-undecoded body regions (v9/sub=0x03
    timing slot-array @28-79, v7 tail @140-208) carry NO neighbor PCI identity
    -- the dozens of neighbor PCIs the B19x codes report never appear as a
    consistent u16 field in 0x18AB payloads (the one apparent "hit" at offset 0
    is the [version, subtype] header [0x09, 0x01] read as u16 LE = 265, not a
    cell). Conclusion: not worth mapping into Kismet for LTE cell coverage, and
    finishing the sub=0x03 slot-array decode would add no cells.
    (That analysis counted LTE keys only. v9/st1/sub=0x16
    carries the GTS NR5G cell (nr_arfcn, nr_pci), which was hidden behind the
    "chipset magic" reading until v21; its NR contribution is not measured.)

Log name: GNSS GTS log
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_LTE_ML1_INTRA_FREQ_MEAS
from diaggrok.registry import register


@dataclass
class Diag0x18AB:
    """LTE ML1 Intra-Frequency Measurement (0x18AB)."""

    log_time: int
    version: int
    subtype: int
    entries: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x18AB',
            'log_time': self.log_time,
            'version': self.version,
            'subtype': self.subtype,
            'entries': self.entries,
        }


# ---------------------------------------------------------------------------
# Subtype 2: measurement record layout
# ---------------------------------------------------------------------------
#   [0]     u8   version (7)
#   [1]     u8   subtype (2)
#   [2:6]   u32  EARFCN
#   [6:10]  u32  PCI
#   [10:28] 18 bytes reserved (zeros)
#   [28]    u8   reserved (0x00)
#   [29]    u8   measurement config flags
#   [30]    u8   subframe timing (cycles 0,5,10,15,20,25,30,35)
#   [31]    u8   timing field 2
#   [32:48] 16 bytes raw measurement data (two 8-byte measurement words)
#   [48:56] 8 bytes reserved
#   [56:60] u32  secondary EARFCN (when non-zero, a second carrier detected)
#   [60:96] 36 bytes reserved
#   [96:100] u32 cell detection metadata
#   [100:128] 28 bytes reserved
#   [128]   u8   summary marker (always 0x01)
#   [129]   u8   summary byte
#   [130:132] u16 copy of u16@36 (raw measurement summary)
#   [132:134] u16 measurement sequence counter (monotonically increasing)
#   [134:140] 6 bytes reserved
#   [140:209] 69 bytes neighbor cell data (variable, often zeros)

_MIN_TYPE2_LEN = 10   # version + subtype + EARFCN + PCI
_MIN_TYPE3_LEN = 18   # version + subtype + v7 u64 start_ts@2 + end_ts@10
_MIN_TYPE1_V9_LEN = 10  # version + subtype + header

_MAX_LTE_EARFCN = 262143
_MAX_LTE_PCI = 503

# v5 (466-byte Sierra MDM9x50) subtype-2 cell-identity offsets.
# The v7 209-byte layout puts EARFCN@2 / PCI@6; on the 466-byte v5 record those
# offsets read 0. Recovered on an EM7565 against a single CBRS B48 cell
# (EARFCN 55340 / PCI <pci>): the LE bytes 2c d8 (55340) sit at offset 128 and
# the PCI's LE u16 at offset 132, consistent across 37/37 v5/st2 records. EARFCN is
# u32 (bytes 130-131 == 0x0000 across all 37); PCI is u16 (bytes 134-135 carry
# a separate varying field, so reading PCI as u32 would range-reject 22/37
# records).
_V5_ST2_EARFCN_OFFSET = 128
_V5_ST2_PCI_OFFSET = 132
_MIN_TYPE2_V5_LEN = 134  # need bytes through the u16 PCI at 132..134


def _parse_subtype2(data: bytes, version: int = 7) -> list[dict[str, Any]]:
    """Parse subtype 2 — measurement subpacket.

    Returns a list of cell entries. The primary cell (from the header)
    is always included with whatever measurement metadata can be
    extracted from the payload. Neighbor cells from bytes 140+
    are not yet decoded (their variable structure requires further RE
    work).

    The v7 (209-byte SDX20) and v5 (466-byte Sierra MDM9x50) layouts place
    the cell identity at different offsets, so the EARFCN/PCI read branches on
    ``version``. The v7-specific measurement words are only meaningful on
    the 209-byte layout and are NOT emitted for v5 (their offsets alias other
    fields there — e.g. the v7 ``meas_seq`` u16@132 is exactly the v5 PCI).

    On v7 this also exposes the raw measurement words (bytes 32..40 and
    40..48) plus the timing fields (bytes 29..32) so downstream consumers can
    attempt their own RE without re-reading captures.
    """
    if version == 0x05:
        # 466-byte Sierra MDM9x50 layout: EARFCN u32@128, PCI u16@132.
        if len(data) < _MIN_TYPE2_V5_LEN:
            return []
        earfcn = unpack_from('<I', data, _V5_ST2_EARFCN_OFFSET)[0]
        pci = unpack_from('<H', data, _V5_ST2_PCI_OFFSET)[0]
        if earfcn > _MAX_LTE_EARFCN or pci > _MAX_LTE_PCI:
            return []
        return [{'pci': pci, 'earfcn': earfcn}]

    earfcn = unpack_from('<I', data, 2)[0]
    pci = unpack_from('<I', data, 6)[0]

    if earfcn > _MAX_LTE_EARFCN or pci > _MAX_LTE_PCI:
        return []

    entry: dict[str, Any] = {
        'pci': pci,
        'earfcn': earfcn,
    }

    # Timing fields at bytes 29..32
    if len(data) >= 32:
        entry['meas_flags'] = data[29]      # config/flag byte
        entry['subframe_timing'] = data[30]  # cycles 0,5,10,15,20,25,30,35
        entry['timing_field2'] = data[31]    # purpose unknown but varies

    # Raw measurement words at bytes 32..40 and 40..48
    # Empirically across 222 EG18-NA records: byte[33] == byte[41]
    # (100% match, stride-8 mirror), bytes 32 and 34..39 vary
    # independently. Likely two parallel per-Rx-antenna measurement
    # blocks where byte 33 is a shared label/rx-id and the other
    # 7 bytes are per-antenna measurement state. Body RE incomplete;
    # exposing as hex for downstream analysis.
    if len(data) >= 48:
        entry['meas_word1_hex'] = data[32:40].hex()
        entry['meas_word2_hex'] = data[40:48].hex()
        entry['meas_word_mirror_byte'] = data[33]  # byte that's shared word1/word2

    # Include measurement sequence counter when available.
    if len(data) >= 134:
        entry['meas_seq'] = unpack_from('<H', data, 132)[0]

    return [entry]


# ---------------------------------------------------------------------------
# Subtype 3: measurement-window timing record (v7 / v5)
# ---------------------------------------------------------------------------
# Two u64 LE timestamps, start and end of one measurement window, in 19.2 MHz
# system-timer ticks. Consecutive records chain: rec[N+1].start_ts ==
# rec[N].end_ts. The record carries NO cell identity. Up to parser v19 the v7
# record was read as u32 ts@2 / u32 PCI@6 / u32 ts@10 / u32 PCI@14, but u32@6 is
# the HIGH WORD of start_ts: it steps 3 -> 4 when the low word wraps, and it
# ranges 0..14,853 across the corpus. So every st3 record emitted a fake PCI.
#
# F3 grounding:
#   v7 (LM960/SDX20, one F3 capture, 270 records): the
#     ticks fit the DIAG header clock at 19.2000 MHz (0.21 ms residual), and
#     the firmware's own 64-bit time prints fall on the same line —
#     mcpm.c:852/961/1930/2702 begin/end time and gts.c:8168 "GetClockAndRtc:
#     64U" (935 lines, median offset 0.02-0.27 ms). Corpus: 148 captures /
#     232,194 records, u64 window chain 97.2% (breaks at session gaps), window
#     lengths 0.100 s, 1.000 s and 1.280 s (the 1.28 s idle DRX cycle).
#   v5 (EM7565/MDM9x50, one F3 capture, 345 records):
#     the same pair sits at @364/@372 of the 466-byte record (the v7 offsets
#     read zeros here). 344/344 chain, 19.19999 MHz, 0.22 ms residual,
#     327/345 windows exactly 1.000 s, on the mcpm.c / mcpm_drv_mcvs.c time
#     prints (median offsets within +-0.31 ms).
# A top-level v9 subtype 3 has never been observed (v9 nests its timing in
# st1/sub_subtype=0x03), so it gets no decode rather than an ungrounded one.
_ST3_TS_OFFSETS = {0x07: (2, 10), 0x05: (364, 372)}
_ST3_TICKS_PER_MS = 19_200  # 19.2 MHz system timer


def _parse_subtype3(data: bytes, version: int) -> list[dict[str, Any]]:
    """Parse subtype 3 — measurement-window timing record.

    Returns one entry with ``start_ts`` / ``end_ts`` (u64, 19.2 MHz ticks) and
    the derived ``window_ms``. Emits no ``pci`` / ``earfcn``: the record has
    none (see the block comment above).
    """
    offsets = _ST3_TS_OFFSETS.get(version)
    if offsets is None:
        return []
    start_ts = unpack_from('<Q', data, offsets[0])[0]
    end_ts = unpack_from('<Q', data, offsets[1])[0]
    return [{
        'format': f'v{version}_st3_timing',
        'start_ts': start_ts,
        'end_ts': end_ts,
        'window_ms': round((end_ts - start_ts) / _ST3_TICKS_PER_MS, 3),
    }]


# ---------------------------------------------------------------------------
# Subtype 1, version 7: GTS GNSS-ME time record (SDX20 / MDM9250-class)
# ---------------------------------------------------------------------------
# v7 st1 is a GTS (gts.c) source record, like v9 st1, but for the GNSS
# measurement engine's time. Each record is emitted just after the gts.c
# F3 print "GpsMeTime. W %u Ms %lu %f %f RefFC %u FcUstmr %u U 0x%lx" with the
# same values:
#   @2  u8  source    0x14 on every corpus record (13,453 / 76 captures)
#   @3  u32 ref_fc    F3 RefFC (GTS frame count, steps 1000 per 1 s record)
#   @7  13 bytes      per-unit/per-build state, constant within a capture on
#                     most; exposed raw
#   @20 u16 gps_week  F3 W
#   @22 u32 gps_ms    F3 Ms (GPS time of week, ms)
#   @26 f32 bias_ms   F3 first float. gts.c's own "TSrc .. OBias %f" line
#                     repeats it as "Bias", so it's the sub-ms remainder (can be
#                     negative: EG12-GT reads about -0.105)
#   @30 f32 tunc_ms   F3 second float == that line's "Tunc"
#   @34 f32, @38 f32  not in any F3 print; exposed raw
#   @42 u8            1 on every corpus record; exposed raw
#   @43 u64 ustmr     F3 "U 0x..." (Qtimer, about 19.2 M ticks per record)
#   @51 f32 ustmr_bias  gts.c "GTS: CalcUstmrAtFCount - FCount:%u,Qtime:%llu,
#                     Bias:%f" Bias (that print's FCount is ref_fc and its Qtime
#                     is ustmr): 301/301 + 254/254 on the two EG18-NA sessions;
#                     first found on v6
#   @55 u32 fc_ustmr  F3 FcUstmr (== ref_fc on every corpus record)
# Bytes 59+ look like stale buffer contents (fragments of earlier records);
# left raw.
#
# F3 grounding, v0x07 st.v1: 301/301 records (EG18-NA cold start)
# and 254/254 (EG18-NA, a second session) match the GpsMeTime print on W, Ms, both
# floats (6 dp), RefFC and U. Median offset is about -0.45k ticks (the print
# comes first). 0x60: EVENT_GNSS_TLE_TIME_UPDATE_C (1951) carries u16 week @9 /
# u32 Ms @11, and 301/301 record Ms values appear in it. GPS week + ms gives
# the capture's own date on 76/76 captures (EG18-NA, LM960, EG12-GT).
#
# The v7 subtype byte looks like the GTS source on its own: in that capture
# st3 = 2,777 records = "Processing FEST Msg" prints, and st2 = 475 = "Processing
# LTE Time Msg TTR". v9 moved this enum into byte 2 under a single st1.
_V7_ST1_SRC_GNSS_ME = 0x14

# v5 st1 (466 B, Sierra MDM9x50 EM7511 / EM7565 / MC7411 and Quectel EM060K-GL):
# the same GNSS-ME time record, starting 69 bytes into the buffer. Every v7
# offset above moves by +69 (source @71, ref_fc @72, gps_week @89, gps_ms @91,
# bias_ms @95, tunc_ms @99, u8 @111 = 1, ustmr @112, ustmr_bias @120,
# fc_ustmr @124). Bytes 2-70 and 128+ are stale buffer
# contents (fragments of other modules' F3 text on some records); left out.
#
# F3 grounding, v0x05 st.v1: on an EM060K-GL survey capture,
# 648 records == 648 gts.c GpsMeTime prints. Joined
# on RefFC, 648/648 match on W, Ms, both floats (6 dp), FcUstmr and U; 647/647
# match "GTS: CalcUstmrAtFCount - FCount:%u,Qtime:%llu,Bias:%f" on Bias
# (@120) and Qtime (== ustmr). The decoded GPS time spans the capture's own
# NMEA host window to within 0.2 s at both ends. The 22 Sierra captures (no
# F3) hold the layout on every record (source 0x14, u8 = 1, ref_fc ==
# fc_ustmr) and their GPS date equals the capture date 22/22; on one EM7565
# run the gps_ms span overlaps the LG290P reference receiver's
# MSM7 epochs (first record 3.4 s after its first epoch).
_V5_ST1_BASE = 69


def _parse_subtype1_v7(data: bytes, base: int = 0) -> list[dict[str, Any]]:
    """Parse a GTS GNSS-ME time record (v7 st1; v5 st1 at ``base`` 69).

    See the block comment above. A record with a source byte other than 0x14
    has never been observed; it gets only ``source`` and no field decode.
    """
    fmt = 'v5_st1_gts' if base == _V5_ST1_BASE else 'v7_st1_gts'
    source_byte = data[2 + base]
    entry: dict[str, Any] = {'format': fmt, 'source_byte': source_byte}
    if source_byte != _V7_ST1_SRC_GNSS_ME:
        return [entry]
    entry.update({
        'source': 'gnss_me',
        'ref_fc': unpack_from('<I', data, base + 3)[0],
        'raw_7_20_hex': data[base + 7:base + 20].hex(),
        'gps_week': unpack_from('<H', data, base + 20)[0],
        'gps_ms': unpack_from('<I', data, base + 22)[0],
        'bias_ms': unpack_from('<f', data, base + 26)[0],
        'tunc_ms': unpack_from('<f', data, base + 30)[0],
        'raw_f32_34': unpack_from('<f', data, base + 34)[0],
        'raw_f32_38': unpack_from('<f', data, base + 38)[0],
        'raw_u8_42': data[base + 42],
        'ustmr': unpack_from('<Q', data, base + 43)[0],
        'ustmr_bias': unpack_from('<f', data, base + 51)[0],
        'fc_ustmr': unpack_from('<I', data, base + 55)[0],
    })
    return [entry]


# v9/st1 is a GTS (GNSS Time Service, gts.c) record, the source the
# vendor_official "GNSS GTS log" name points at. Byte 2 is the time/frequency
# source the GTS is processing; each record is emitted microseconds before the
# matching gts.c F3 print, which carries the same values:
#
#   0x03 FEST (frequency estimate) <-> gts.c "Processing FEST Msg. Src %u
#         Est %ld Unc %ld Cal %u DelayCtr %lu B2bDiffMs %ld NumCtr %lu"
#           @3  u64 start_ts  Qtimer (19.2 MHz) of the previous FEST message
#           @11 u64 end_ts    Qtimer of this one; rec[N+1].start == rec[N].end
#           @19 i32 est       == F3 Est
#           @23 f32 unc       F3 Unc == int(unc * 1e6) on SDX62 builds; SDX55
#                             builds print "Src %u Est %ld Unc %ld" with
#                             int(unc * 1e3), so unc is emitted unscaled
#           @27 u8  cal       == F3 Cal (SDX62 print only)
#         end_ts sits on the same line as the F3-labelled "QT" of the 0x16
#         records (19.20002 MHz against the DIAG clock, median 0.05 ms off).
#         Bytes 21-27 were once pinned as a "per-build sentinel": they are the
#         high half of est plus unc and cal, i.e. per-unit XO calibration state,
#         so they stay constant for one unit and differ between units. Bytes
#         28+ are not in any F3 print and look like stale buffer contents
#         (fragments of other records at varying offsets); left raw.
#   0x16 NR5G <-> gts.c "Proc NR5G. Sub %u Val %u %u BS %u TA %ld PCI %u %lu
#         QT 0x%lx%08lx" and "Stmr SF %lu %lu %u %lu Curr %lu %lu %u %lu"
#           @4  u32 nr_arfcn  F3 "%lu" after the PCI (521310, 501390: NR n41)
#           @8  u16 nr_pci    F3 "PCI %u"
#           @10 u16, @12 u32, @16 u32, @20 u32  the four "Curr" values, F3
#               order Curr = (u32@16, u32@20, u16@10, u32@12)
#           @25 u64 qtimer    F3 "QT"
#         Up to parser v20 bytes 3-9 were an allowlisted "chipset magic"
#         (`00 8e a6 07 00 …` etc.). They are the NR cell: SDX72 `5e f4 07` +
#         u16 PCI = (521310, <pci>) and Foxconn SDX62 `8e a6 07` + u16 PCI =
#         (501390, <pci>), each matching QMI GetCellLocationInfo in that modem's ground-
#         truth recipe. The "magic" looked constant only because the bench units sat
#         on one n41 cell.
#   0x02 LTE (10,943 records, 1.9% of v9/st1) — observed on RM520N-GL (8,698),
#         FN980 (1,072), M2000 (291), LV55 (7), plus 875 from drive and
#         survey captures. NEVER observed on Sierra. **Header layout matches
#         v=7 st=2 and st=3**: u32 LE EARFCN @ 3-6, u32 LE PCI @ 7-10.
#         Verified against an RM520N-GL indoor-cell capture (EARFCN 66786,
#         PCI <pci> — exact match against the EG18-NA v2 fixture used in
#         `test_eg18na_corpus_regression`). {0x16, 0x02} are not mutually
#         exclusive per vendor — RM520N-GL emits BOTH 0x16 (2,870) AND 0x02
#         (8,698). Body @ offsets 11-209 is sparse: most bytes are zero with
#         small populated regions at {30, 31, 33-38, 40-43, 57-60}.
#
# F3 grounding, v0x09: the v9/st1/sub=0x02 (earfcn@3, pci@7) decode is
# grounded against an independent in-capture F3 source on SDX62 (Casa
# Systems CFW-3212 / RG520N-NA). In one capture all 336 v9/st1/sub=0x02
# records decode to EARFCN 2300 / PCI <pci> — matching 336/336 the co-captured
# plaintext F3 (0x79) prints `+QENG "servingcell",...,<pci>,2300` and
# `+QENG "neighbourcell intra","LTE",2300,<pci>` (file dsatrsp.c, the
# AT-response subsystem — a firmware code path independent of the 0x18AB log
# emission). Two subsystems converging on the same (EARFCN,PCI) rule out a
# coincidental byte alignment. NB the field is a measured LTE intra/inter-freq
# CELL identity, NOT always the serving cell: an LV55 SDX55 capture decodes
# sub=0x02 -> (66536, <pci>) while the serving cell was EARFCN 5230, so
# sub=0x02 can carry a neighbour on a different carrier. earfcn/pci naming is
# therefore correct and deliberately generic (no `serving_` prefix).
_V9_ST1_SUB_FEST = 0x03
_V9_ST1_SUB_NR5G = 0x16
_V9_ST1_SUB_LTE = 0x02

_MAX_NR_ARFCN = 3279165
_MAX_NR_PCI = 1007


def _parse_subtype1_v9(data: bytes) -> list[dict[str, Any]]:
    """Parse subtype 1, version >= 9 (SDX55+) — a GTS source record.

    Byte 2 names the GTS time/frequency source (block comment above):
      - 0x03 FEST: start_ts / end_ts (u64 Qtimer @3 / @11), window_ms, and the
        frequency estimate est (i32 @19), unc (f32 @23) and cal (u8 @27).
      - 0x16 NR5G: nr_arfcn (u32 @4) / nr_pci (u16 @8), range-checked, the
        qtimer (u64 @25) and the four F3 "Curr" STMR values (stmr_curr).
      - 0x02 LTE: earfcn (u32 @3) / pci (u32 @7), range-checked.
    """
    if len(data) < _MIN_TYPE1_V9_LEN:
        return []

    sub_subtype = data[2]
    config_word = unpack_from('<H', data, 2)[0]
    nz_bytes = sum(1 for b in data[2:] if b != 0)

    entry: dict[str, Any] = {
        'format': 'v9_st1',
        'sub_subtype': sub_subtype,
        'config_word': config_word,
        'data_bytes': nz_bytes,
        'total_bytes': len(data) - 2,
    }

    if sub_subtype == _V9_ST1_SUB_FEST and len(data) >= 28:
        start_ts, end_ts = unpack_from('<QQ', data, 3)
        entry['source'] = 'fest'
        entry['start_ts'] = start_ts
        entry['end_ts'] = end_ts
        entry['window_ms'] = round((end_ts - start_ts) / _ST3_TICKS_PER_MS, 3)
        entry['est'] = unpack_from('<i', data, 19)[0]
        entry['unc'] = unpack_from('<f', data, 23)[0]
        entry['cal'] = data[27]
    elif sub_subtype == _V9_ST1_SUB_NR5G and len(data) >= 33:
        entry['source'] = 'nr5g'
        nr_arfcn = unpack_from('<I', data, 4)[0]
        nr_pci = unpack_from('<H', data, 8)[0]
        if nr_arfcn <= _MAX_NR_ARFCN and nr_pci <= _MAX_NR_PCI:
            entry['nr_arfcn'] = nr_arfcn
            entry['nr_pci'] = nr_pci
        entry['qtimer'] = unpack_from('<Q', data, 25)[0]
        # F3 print order: Curr %lu %lu %u %lu
        entry['stmr_curr'] = [
            unpack_from('<I', data, 16)[0],
            unpack_from('<I', data, 20)[0],
            unpack_from('<H', data, 10)[0],
            unpack_from('<I', data, 12)[0],
        ]
    elif sub_subtype == _V9_ST1_SUB_LTE and len(data) >= 11:
        entry['source'] = 'lte'
        earfcn = unpack_from('<I', data, 3)[0]
        pci = unpack_from('<I', data, 7)[0]
        if earfcn <= _MAX_LTE_EARFCN and pci <= _MAX_LTE_PCI:
            entry['earfcn'] = earfcn
            entry['pci'] = pci

    return [entry]


# ---------------------------------------------------------------------------
# Version 6 (MDM9150 / MDM9250, C-V2X units) — GTS records
# ---------------------------------------------------------------------------
# v0x06 is the 209-byte class on the WNC 81UMV91M21 / 81UMV91B1 MDM9150
# modules, the Kapsch RIS-9260 RSU (which contains that modem) and the Ficosa
# carcom-g1 MDM9250. These units run C-V2X, so there is no cellular serving
# cell and v6 never emits earfcn/pci (sidelink-channel EARFCNs checked: negative)
#.
#
# The records themselves are GTS (gts.c) records, the same family as v7/v9
# st1. Each one is emitted right after a gts.c
# F3 print that carries the same values. Grounded on two builds: qdb 7fa15caf
# (81UMV91B1, carcom-g1 MDM9250) and qdb d2116626 (the RIS-9260, which is the
# same 81UMV91M21 modem as the bench captures, not a separate device; its
# corpus adds only long uptime). The bench 81UMV91M21 captures emit st3 only.
#
#   st3 FEST <-> gts.c "Processing FEST Msg[. Src %u Est %ld Unc %ld]"
#       @2  u64 start_ts  Qtimer (19.2 MHz) of the previous FEST message
#       @10 u64 end_ts    rec[N+1].start == rec[N].end; windows 0.1 s or 1 s
#       @18 i32 est       == F3 Est (printed as %ld of the u32) on the RIS
#                         build, 946/946. Q20 ppm: est / 2**20 tracks the gts.c
#                         "GTSCal ... QTFB" XO estimate within 0.01-0.02 ppm.
#       @22 f32 unc       F3 Unc == int(unc * 1e3) (0 on every record seen)
#       @26 u8  cal       not printed; 6 on every unit seen
#     This is the v9 sub=0x03 FEST layout without v9's source byte at @2.
#     Up to parser v22 st3 was read as u32@4 / u32@12: bits 16-47 of these
#     u64s, which is why its "window" was ~29 ticks (1.92 M ticks >> 16).
#     The 49 B form is the same record, cut short.
#   st1 GNSS-ME time (byte 2 = 0x14) <-> gts.c "GpsMeTime. W %u Ms %lu %f %f
#       RefFC %u FcUstmr %u U 0x%lx" and "GTS: CalcUstmrAtFCount -
#       FCount:%u,Qtime:%llu,Bias:%f". The v7/st1 layout, plus
#       @51 f32 ustmr_bias == CalcUstmrAtFCount Bias (whose FCount is ref_fc
#       and whose Qtime is ustmr).
#   st0 GTS latch (byte 2 = 0x01) <-> gts.c "GTS: Latch %u,RTC %lu,Ph %lu,SS
#       %lu, USTMR %lu", "GTS: Latch Qtime :0x%x%08x" and "Get Ttr latch %lu
#       %lu 64U 0x%x%08x"
#       @3   u16 gps_week     == GpsMeTime W
#       @9   u32 latch_fcount == "USTMR@FCount %lu RTC %lu" FCount (RIS build;
#                             the 81UMV91B1 print has no FCount argument)
#       @180 u32 latch_rtc
#       @192 u32 latch_ustmr
#       @197 u64 latch_qtime
#     u32@5 is a GPS ms on a 100 ms grid, within a few ms of GpsMeTime Ms, but
#     no print carries it, so it stays raw. Bytes 13-179 are raw.
_V6_VERSION = 0x06
_V6_SUBTYPES = (0x00, 0x01, 0x03)
_V6_ST3_TIMING = 0x03
_V6_ST1_SRC_GNSS_ME = 0x14
_V6_ST0_LATCH = 0x01
_V6_ST0_LATCH_LEN = 205  # through latch_qtime u64@197


def _parse_v6(data: bytes, subtype: int) -> list[dict[str, Any]]:
    """Parse version=0x06 (MDM9150 / MDM9250, C-V2X units) GTS records.

    See the block comment above. No ``earfcn`` / ``pci`` is ever emitted:
    these units have no cellular serving cell. A st0/st1 record whose byte 2
    is not the observed source gets only the bounded raw fallback.
    """
    if subtype == _V6_ST3_TIMING:
        start_ts, end_ts, est = unpack_from('<QQi', data, 2)
        return [{
            'format': 'v6_st3_timing',
            'context': 'cv2x',
            'start_ts': start_ts,
            'end_ts': end_ts,
            'window_ms': (end_ts - start_ts) / 19_200.0,
            'est': est,
            'est_ppm': est / 2**20,
            'unc': unpack_from('<f', data, 22)[0],
            'cal': data[26],
        }]

    if subtype == 0x01 and data[2] == _V6_ST1_SRC_GNSS_ME:
        entry = _parse_subtype1_v7(data)[0]
        entry.update({'format': 'v6_st1_gts', 'context': 'cv2x'})
        return [entry]

    if subtype == 0x00 and data[2] == _V6_ST0_LATCH and len(data) >= _V6_ST0_LATCH_LEN:
        return [{
            'format': 'v6_st0_gts_latch',
            'context': 'cv2x',
            'sub_subtype': data[2],
            'gps_week': unpack_from('<H', data, 3)[0],
            'raw_u32_5': unpack_from('<I', data, 5)[0],
            'latch_fcount': unpack_from('<I', data, 9)[0],
            'latch_rtc': unpack_from('<I', data, 180)[0],
            'latch_ustmr': unpack_from('<I', data, 192)[0],
            'latch_qtime': unpack_from('<Q', data, 197)[0],
        }]

    # Unobserved byte-2 value: expose raw.
    return [{
        'format': f'v6_st{subtype:x}',
        'context': 'cv2x',
        'sub_subtype': data[2],
        'data_bytes': sum(1 for b in data[2:] if b != 0),
        'total_bytes': len(data) - 2,
        'body_hex': data[2:32].hex(),  # bounded raw slice for downstream RE
    }]


_OBSERVED_VERSIONS = (0x05, 0x06, 0x07, 0x09)

# Fixed record sizes. Every corpus record is one of these per-version
# sizes (v5 466 B / 42,909 records; v7 209 B; v9 210 B / 1.2M; v6 209 B for
# subtypes 0x00/0x01 and a 49 B subtype-0x03 timing record on an MDM9250
# unit). The body fields carry no length field, so a payload shorter than
# its (version, subtype) size is a truncated record and returns None (registry
# WARN). Longer payloads are still accepted.
_MIN_RECORD_LEN = {0x05: 466, 0x07: 209, 0x09: 210}
_MIN_V6_RECORD_LEN = {0x00: 209, 0x01: 209, 0x03: 49}
# v6 subtype 0x03 is mostly 209 B; the 49 B form is the short one above. A
# length between them is a cut 209 B record.
_V6_ST3_FULL_LEN = 209
_OBSERVED_SUBTYPES = (0x01, 0x02, 0x03)  # legacy (v5/v7/v9); v6 uses _V6_SUBTYPES


# ---------------------------------------------------------------------------
# Validating the cell identity against AT+QENG
# ---------------------------------------------------------------------------
# Scope caveat: on the RM520N-GL (v=0x09) the cell identity (earfcn/pci) is
# emitted ONLY on the v9/st1/sub_subtype=0x02 records (~1.9% of the v9
# corpus). The dominant sub=0x03 (91.3%) records are timing-only and the
# sub=0x16 (6.8%) records are a chipset-magic config snapshot — neither
# carries cell identity. RSRP is absent from this log code entirely (derived
# by ML1 and emitted in 0xB193), so no signal-strength field can be checked.

@register(LOG_LTE_ML1_INTRA_FREQ_MEAS,
    name="0x18AB",
    description="Cell detection on serving frequency — EARFCN, PCI, timing fields, raw measurement words; v9/st1 GTS source records: sub=0x02 LTE EARFCN+PCI, sub=0x16 NR5G NR-ARFCN+PCI+Qtimer, sub=0x03 FEST est/unc/cal + Qtimer window, v7/st1 GTS GNSS-ME time (GPS week/ms/bias/tunc + RefFC/Qtimer), v5 (MDM9x50, 466-byte) subtype-2 cell identity at EARFCN u32@128 / PCI u16@132, and v6 (MDM9150/MDM9250 C-V2X units) GTS records: st3 FEST Qtimer window + est/unc/cal, st1 GNSS-ME time, st0 GTS latch RTC/USTMR/Qtime",
    version=24,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE starting from SDX20 (LM960) drive captures, extended by "
        "a 185-capture / 429,827-record corpus pass and a 575,274-record "
        "partition of the v9/st1 variant across 8 vendor/chipset paths. "
        "v7 (209 B): EARFCN u32@2 / PCI u32@6 — on an LM960 camped on a CBRS "
        "B48 cell, earfcn == AT#RFSTS (55340) and pci == an external same-cell "
        "QMI PCI; F3 co-emits lte_ml1_dlm_ard.c. "
        "v5 (466 B, EM7565 MDM9x50): EARFCN u32@128 / PCI u16@132, found by "
        "scanning all 37 v5/st2 records for the LE byte patterns of the known "
        "CBRS B48 serving cell; 37/37 decode (55340, <pci>) == AT!GSTATUS? 'LTE "
        "Rx chan' + QMI GetCellLocationInfo PCI, and F3 co-emits "
        "lte_ml1_sm_conn_meas_intra2.c plus an RF-tune 'LTE PRX Band 178, Chan "
        "55340' print. "
        "v9/st1 is split by sub_subtype (byte 2): sub=0x02 carries u32 LE "
        "EARFCN @ 3 and u32 LE PCI @ 7 (same layout as v=7 st=2/st=3), "
        "range-validated against 3GPP LTE limits, checked on an RM520N-GL "
        "indoor-cell capture, and F3-grounded on a second, independent SDX62 "
        "build (Casa Systems CFW-3212 / RG520N-NA: 336/336 and 125/125 records "
        "in two captures == the firmware's own +QENG prints, 2300/<pci>). It is "
        "a measured cell identity, not always the serving cell. v9/st1 is "
        "a GTS (gts.c) source record: each one precedes a gts.c F3 print "
        "with the same values. sub=0x16 (NR5G) carries nr_arfcn u32@4, "
        "nr_pci u16@8, qtimer u64@25 and four STMR 'Curr' words == 'Proc "
        "NR5G ... PCI %u %lu QT' / 'Stmr SF ... Curr' (bytes 3-9 were once "
        "read as a chipset magic; they match QMI GetCellLocationInfo NR "
        "cells on a T99W640 and a T99W373). sub=0x03 (FEST) carries Qtimer "
        "start_ts/end_ts and est i32@19 / unc f32@23 / cal u8@27 == "
        "'Processing FEST Msg' Est/Unc/Cal. "
        "v6 (MDM9150 / MDM9250 C-V2X units, ~1.1M records) carries no "
        "cellular earfcn/pci. Its records are GTS records, each following a "
        "gts.c F3 print with the same values on three builds: st3 FEST "
        "(Qtimer start_ts u64@2 / end_ts u64@10, est i32@18 == 'Processing "
        "FEST Msg ... Est', unc f32@22, cal u8@26), st1 GNSS-ME time (the v7 "
        "GpsMeTime layout plus 'CalcUstmrAtFCount' Bias f32@51) and st0 GTS "
        "latch (gps_week u16@3, latch_fcount u32@9, latch_rtc u32@180, "
        "latch_ustmr u32@192, latch_qtime u64@197 == 'GTS: Latch' / 'Latch "
        "Qtime'). A payload shorter than its fixed per-(version, subtype) "
        "record size returns None (registry WARN); v6 subtype 0x03 below 209 B "
        "is accepted only at exactly 49 B. Open: the sub=0x02 sparse "
        "fields (offsets 30-60). "
        "Subtype 3 (v7, v5) is a measurement-window timing record: u64 "
        "start_ts / end_ts in 19.2 MHz system-timer ticks (v7 @2/@10, v5 "
        "@364/@372), chained rec[N+1].start == rec[N].end, with no cell "
        "identity. It is F3-grounded on LM960/SDX20 and EM7565/MDM9x50: the "
        "ticks lie on the same clock line as the firmware's own mcpm.c and "
        "gts.c 64-bit time prints. "
        "Subtype 1 (v7) is a GTS GNSS-ME time record (byte 2 = 0x14): "
        "ref_fc u32@3, gps_week u16@20, gps_ms u32@22, bias_ms f32@26, "
        "tunc_ms f32@30, ustmr u64@43, fc_ustmr u32@55 == gts.c 'GpsMeTime. "
        "W .. Ms .. RefFC .. FcUstmr .. U' on 555/555 records in two EG18-NA "
        "sessions, with EVENT_GNSS_TLE_TIME_UPDATE_C carrying the same "
        "week/Ms. v5 subtype 1 is the same record 69 bytes into the 466 B "
        "buffer (source @71, ref_fc @72 ... fc_ustmr @124, plus ustmr_bias "
        "f32@120): 648/648 GpsMeTime and 647/647 CalcUstmrAtFCount matches "
        "on an EM060K-GL survey; GPS date == capture date on 22 Sierra "
        "MDM9x50 captures."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    # version, subtype, entries[] — subtype-2 entries carry meas_flags +
    # subframe_timing + meas_word1/2 hex; subtype-3 timing entries
    # carry start_ts/end_ts (u64, 19.2 MHz); v6 entries are GTS records
    # (st0 latch, st1 GNSS-ME time, st3 FEST). All three top-level fields named.
    fields_identified=3,
    fields_parsed=3,
    field_invariants={
        "version": {"enum": list(_OBSERVED_VERSIONS)},
        # union of legacy {0x01,0x02,0x03} + v6 {0x00,0x01,0x03}; the parser body
        # enforces the tighter per-version subtype gate (v6 vs legacy) before
        # emitting, so this net stays sound while admitting v6's subtype 0x00.
        "subtype": {"enum": sorted(set(_OBSERVED_SUBTYPES) | set(_V6_SUBTYPES))},
    },
    # F3-sweep layout axis: byte 1 (subtype) picks the body within a
    # version — 2 measurement, 3 timing reference, 1 v9 GTS source record, 0/1 v6
    # GTS latch / GNSS-ME time — so the unit of F3 work is (0x18AB, v0xNN, st.vN).
    layout_axes={"st": "subtype"},
    wigle_direct=False,
    wigle_roles=("pci-earfcn-bridge", "rat-context"),
)
def parse_0x18ab(
    log_time: int, data: bytes
) -> Diag0x18AB | None:
    """Parse 0x18AB -- LTE ML1 Intra-Frequency Measurement.

    Header layout:
        [0]    u8   version (corpus-observed: 0x05 / 0x06 / 0x07 / 0x09)
        [1]    u8   subtype (corpus-observed: 0x01 / 0x02 / 0x03; v6 0x00)
        [2:6]  u32  EARFCN   (v7; not part of a u64 timestamp)
        [6:10] u32  PCI      (v7; not part of a u64 timestamp)

    Returns an Diag0x18AB with entries list. Cell-identity entries (subtype 2,
    v9 sub_subtype 0x02) carry 'pci' and 'earfcn'; subtype-3 timing entries
    carry 'start_ts' / 'end_ts' and no cell identity. RSRP is not available
    from this log code (use 0xB193 for RSRP).

    Version/subtype gate (per-version): v5/v7/v9 accept subtypes
    {0x01, 0x02, 0x03}; v6 (MDM9150, C-V2X) accepts {0x00, 0x01, 0x03}. Any
    other (version, subtype) is a future-firmware/uncharacterized variant and
    is rejected rather than mis-parsed against the wrong body layout (the
    same size does not imply the same format).

    Returns None if the payload is shorter than its fixed per-(version,
    subtype) record size (v5 466 / v6 209, st3 49 / v7 209 / v9 210 B — a
    truncated record) or the (version, subtype) pair is outside the
    corpus-grounded enums.
    """
    if len(data) < 2:
        return None

    version = data[0]
    subtype = data[1]
    if version not in _OBSERVED_VERSIONS:
        return None
    allowed_subtypes = _V6_SUBTYPES if version == _V6_VERSION else _OBSERVED_SUBTYPES
    if subtype not in allowed_subtypes:
        return None
    min_len = (_MIN_V6_RECORD_LEN[subtype] if version == _V6_VERSION
               else _MIN_RECORD_LEN[version])
    if len(data) < min_len:
        return None  # truncated fixed-size record
    if (version == _V6_VERSION and subtype == 0x03
            and min_len < len(data) < _V6_ST3_FULL_LEN):
        return None  # a cut 209 B v6/st3 record, not the 49 B form

    if version == _V6_VERSION:
        # MDM9150 C-V2X context (F3-grounded): distinct layout, no cellular

        # identity. Dispatched separately so the v7 offset map never touches v6.
        entries = _parse_v6(data, subtype)
    elif subtype == 2 and len(data) >= _MIN_TYPE2_LEN:
        entries = _parse_subtype2(data, version)
    elif subtype == 3 and len(data) >= _MIN_TYPE3_LEN:
        entries = _parse_subtype3(data, version)
    elif subtype == 1 and version == 7:
        entries = _parse_subtype1_v7(data)
    elif subtype == 1 and version == 5:
        entries = _parse_subtype1_v7(data, _V5_ST1_BASE)
    elif subtype == 1 and version >= 9:
        # v9/st1 (SDX55): different format, not yet fully decoded.
        # Extract what we can from the payload structure.
        entries = _parse_subtype1_v9(data)
    else:
        entries = []

    return Diag0x18AB(
        log_time=log_time,
        version=version,
        subtype=subtype,
        entries=entries,
    )
