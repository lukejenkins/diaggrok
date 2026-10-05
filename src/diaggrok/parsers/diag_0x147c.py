"""0x147C — GNSS PE WLS Position Report.

See the module body for the field map and per-version layouts.

Log name: LOG_GNSS_PE_WLS_POSITION_REPORT_C
Also known as: GPS_ME_EPHEMERIS
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


# ---------------------------------------------------------------------------
# 0x147C — GNSS PE WLS Position Report (per-SV measurement cache)
# ---------------------------------------------------------------------------
#
# The canonical log name LOG_GNSS_PE_WLS_POSITION_REPORT_C identifies this as
# the **Position-Engine Weighted-Least-Squares per-SV measurement
# contributions**, NOT raw subframe-derived broadcast ephemeris. The record
# carries PE inputs/outputs, not the Keplerian set the RINEX .nav format
# needs; broadcast-ephemeris decode needs a different log code.
#
# v=0x0D (SDX62 RM520N-GL):
#
# Layout: [44B preamble] + [N × 47B slot grid]
#     The slot grid splits into two classes:
#       - "head slots"  : the structured WLS solution block (see the note
#                         below); on failed-fix records it holds the
#                         `00000000_4912620f` unset-float fill
#       - "SV records"  : one 47-byte record per actively-tracked SV
#
# Verified across 11 distinct payload sizes (796..1407 B) on 1,842 records
# from an RM520N-GL GNSS comparison capture: every size satisfies
# `(size - 44) % 47 == 0` exactly.  For size classes 937..1125 (1,585 / 1,842
# records = 86%), `head_slots` is exactly 15; 1219+ sizes have a variable
# head (18..22 slots) — likely state-transition or different constellation
# pages.  The 796B class (238 records) is a no-SV-tracked state — the
# preamble follows the same template but with session-variable bytes in
# different positions.
#
# Per-SV record layout (47 bytes, cross-capture stable):
#     [0:5]    `00 00 75 11 01`     5-byte signature
#     [5]      0x00                 reserved
#     [6]      u8                   PRN (GPS SV ID; 1..32)
#     [7]      0x00                 reserved
#     [8:10]   `00 07`              record-type marker (LE u16 = 0x0700)
#     [10]     u8                   subframe-type / status flags (per-SV
#                                   constant across consecutive records;
#                                   varies between PRNs — likely IODE or
#                                   tracking-channel state)
#     [11:15]  f32 LE  wls_f1       per-SV measurement; range ±10
#     [15:19]  f32 LE  wls_f2       per-SV measurement; range [2..16),
#                                   often exactly 5.0 (likely constellation
#                                   or # of tracked frequencies)
#     [19:23]  f32 LE  wls_f3       per-SV measurement; range [0.1..1.0],
#                                   often exactly 1.0 (validity weight?)
#     [23:27]  f32 LE  wls_f4       per-SV measurement; range [0.05..1.0]
#                                   (normalized elevation cosine?)
#     [27:31]  f32 LE  wls_f5       per-SV measurement; range [600..30000]
#                                   (likely a measurement magnitude in m)
#     [31:35]  f32 LE  wls_f6       per-SV measurement; range [10..5000]
#                                   (likely a measurement variance)
#     [35:39]  f32 LE  wls_f7       per-SV measurement; range ±0.02
#                                   (small residual; Doppler-rate-like)
#     [39:43]  f32 LE  wls_f8       per-SV measurement; range [0.01..0.6]
#                                   (per-PRN tight range — possibly C/N0
#                                   noise-floor quantization step)
#     [43:47]  f32 LE  wls_f9       per-SV measurement; range [0.7..1.0],
#                                   usually exactly 1.0 (validity flag)
#
# Field names are deliberately generic (wls_f1..wls_f9): the magnitudes and
# ranges are documented above, but assigning RINEX / GPS-ICD names to them
# requires cross-correlation with a known-position fix and per-SV LOS
# computation. The structural layout is fixed.
#
# 44B preamble — a per-byte variance pass on 1,136 records of one capture,
# compared against a second RM520N-GL capture, yields these invariants:
#
#     Cross-capture CONSTANTS (= 22 of 44 bytes):
#         [0]      0x0D                 version byte (matches v=0x0D enum)
#         [4]      0x00                 separator
#         [8:13]   00 00 00 00 00       reserved
#         [15]     0x0F                 magic byte (low byte of session magic)
#         [16:21]  00 00 00 00 00       reserved
#         [21]     0x04                 sub-version / field-count marker
#         [22:32]  00 ... 00 (10 B)     reserved
#         [32]     0x72                 magic byte
#
#     SESSION-stable (constant within session, varies across sessions):
#         [13:15], [33], [42:44] — firmware-state magic bytes
#
#     VARIABLE (per-record):
#         [1:4]    u24 LE counter (increments by ~1000 per record)
#         [5:7]    u16 LE counter (related)
#         [34:42]  session-state floats / TOW
#
# Of the constants above, bytes 13-15, 20 and 21 turn out to be live across
# the wider corpus, and [1:4] / [5:7] are parts of the packed u32 FCounts at
# [1:5] / [5:9] (see the packed-header section below).
#
# Other versions: the shared packed header and the GNSS time + position
# block are decoded on v=0x06/07/08/0A/0B (see the packed-header section
# below); only v=0x0D carries the per-SV `wls_records` slot grid.
#
# The "head slots" are not template space: they are the structured WLS
# solution block (GNSS time at [32:115], lat/lon/HAE, a second solution copy,
# clock terms). They read as `0x4912620F` fill on failed-fix records
# (wls_fail_code=1), where the block is unset. The slot-grid arithmetic
# ((size-44) % 47 == 0) and the SV-record signature hold on every record.
#
# v=0x0A variance map:
#
#   A cross-vendor per-byte variance pass over EM9190 SWIX55C (1,133
#   records, 4641 B fixed) finds **99.4% of body bytes are fixed** (only 29
#   varying offsets in the EM9190 sample). FN980m SDX55 (1,166 records) has
#   only 11 varying offsets, all of them a strict subset of EM9190's 29. The
#   11 common varying positions are the cross-vendor universal-format core:
#
#     1, 2, 3      — part of the packed u32 FCount at [1:5]
#     5, 6, 7      — part of the second packed u32 FCount at [5:9]
#     77, 78       — u16 report sequence counter (`state_x`)
#     97, 98, 99   — u24 slow engine tick (`state_y`)
#
#   The f32 at body offset [41:44] = `59 fc 5a 46` (f32 LE = ~14015) appears
#   exactly once in the 4641 B body and is fixed within a firmware, but
#   differs on FN980 (see below). The live triplets at 30/51/61 are
#   EM9190-specific (fixed on FN980) — likely a Sierra vendor extension, not
#   core 0x147C v=0x0A structure.
#
#   EM9190-only varying offsets: 30-32, 51-53, 61-63, 488, 490, 502-503,
#   506, 547-548, 552, 554. The 488-554 region's 0/1 toggle pattern
#   looks like state flags or SV-availability bitmaps.
#
#   v=0x0A is NOT a per-SV measurement record with fixed-size per-SV slots.
#   Outside the packed header and the GNSS fix block, the 4641 B body is
#   overwhelmingly zero-padded reserved space, not a slotted array.

# ---- v=0x0D structural constants -----------------------------------------

_V0D_PREAMBLE_LEN = 44
_V0D_SLOT_STRIDE = 47
_V0D_SV_SIG = b'\x00\x00\x75\x11\x01'  # 5-byte cross-capture-stable SV-record signature

# Cross-capture preamble invariants — the 16 bytes that hold across every
# v=0x0D capture surveyed (20 captures × 30 records each = 600 records
# spanning normal, warm-restart, reboot, SIM-power-cycle, and airplane-mode
# operational states), confirmed on 946 further v=0x0D records. Bytes that
# are "mostly constant" but change during state transitions (4, 8, 15, 16,
# 17, 21, 32) are deliberately EXCLUDED from this invariant set — they are
# per-session firmware state and would fail otherwise-valid records during
# boot. Byte 20 is also excluded: it is live (nonzero on 392 of 946 v=0x0D
# records), like 13-15 and 21.
#
# `preamble_invariants_ok=False` is a real falsification: a v=0x0D body
# that fails any of these bytes is structurally suspect (not just in
# a transitional state).
_V0D_PREAMBLE_CONSTS: dict[int, int] = {
    0: 0x0D,
    9: 0x00, 10: 0x00, 11: 0x00, 12: 0x00,
    18: 0x00, 19: 0x00,
    22: 0x00, 23: 0x00, 24: 0x00, 25: 0x00, 26: 0x00,
    27: 0x00, 28: 0x00, 29: 0x00, 30: 0x00,
}


# ---- v=0x0A structural constants -----------------------------------------
#
# v=0x0A (SDX55: EM9190 / FN980 / FN980m / sim8202g-m2 / RM500Q-AE) is a
# FIXED 4641-byte sparse GNSS-engine state record — NOT a per-SV slot array
# (see the variance map above). A cross-vendor walk (EM9190 1,133 records +
# FN980 1,166 records) shows that only 11 byte positions carry
# cross-vendor-universal content; the rest is reserved space or per-firmware
# constants.
#
# Cross-vendor-VERIFIED universal fields (hold on BOTH EM9190 and FN980):
#     [0:4]    u32 LE  tick_a  — +256,000 / record. byte[0] is pinned at 0x0A
#                               (256000 % 256 == 0), so it doubles as the
#                               version byte. This is the packed FCount at
#                               [1:5] read one byte early (see below).
#     [4:8]    u32 LE  tick_b  — also +256,000 / record; likewise the second
#                               packed FCount at [5:9] read one byte early.
#     [77:79]  u16 LE  state_x — per-record SEQUENCE COUNTER, strictly +1 each
#                               record (0,1,2,…): all 1,132 deltas == 1 over
#                               the reference EM9190 capture, checked against
#                               gpsd ground truth. Its low byte cycles through
#                               all 256 values and its high byte runs 0..4
#                               over 1,133 records; it is not a flag field.
#                               Equal to the fix block's `report_seq`.
#     [97:100] u24 LE  state_y — monotonic engine tick, +~467 / record (range
#                               462..479, dominant 463/464). A distinct,
#                               slower cadence from tick_a/tick_b — NOT a
#                               status field.
#
# Cross-vendor-VERIFIED fixed anchors (the v=0x0A preamble validator):
#     [0]==0x0A, [9:13]==0x00, [19:23]==0x00
# [4] and [8] are NOT anchors: they are the HIGH bytes of the two u32 FCounts
# at [1:5]/[5:9] and leave zero once the engine has run > 2^24 ms (~4.7 h),
# so a long-uptime record (e.g. a whole RM500Q-AE drive capture) would fail
# them. [23] is `wls_fail_code` (byte W-1), 0x01 only on failed-fix records.
# [13:19] is a live status region (3,495 records over 26 v=0x0A captures:
# bytes 13-18 all vary; 9-12 and 19-22 never do).
#
# NOT universal — deliberately EXCLUDED from the validator (they differ
# across vendors): byte[33] is 0x41 on EM9190 but 0x84 on FN980; the f32 at
# [41:45] is 59fc5a46 (~14015) on EM9190 but 4d903754 on FN980 — fixed
# WITHIN a firmware but per-firmware, not a shared format anchor. The
# [30:33]/[51:53]/[61:63] triplets vary on EM9190 (Sierra) but are fixed
# non-zero constants on FN980 — a per-firmware region, not core structure.
# The 488-554 toggle region is EM9190-only. All left undecoded.
_V0A_PAYLOAD_SIZE = 4641
_V0A_PREAMBLE_CONSTS: dict[int, int] = {0: 0x0A}
_V0A_RESERVED_ZERO = (*range(9, 13), *range(19, 23))
# The EM9190-only [488:554] toggle region — the 9 low-cardinality byte
# positions that carry per-record STATE FLAGS (NOT clocks/counters; no
# monotonic u32 anywhere in [480:560]). A complete walk of the reference
# EM9190 capture (1,133 records) shows these are the only varying bytes in
# the region. They co-vary in 3 correlated groups (a 134-record state, a
# 50-record state, an 87-record state — see source_detail), so the flags are
# ~3 independent GNSS-engine state indicators. On FN980 (Telit SDX55) all 9
# are zero (the region is a Sierra vendor extension), so toggle_region is
# exposed raw and NOT asserted in the cross-vendor validator.
_V0A_TOGGLE_OFFSETS: tuple[int, ...] = (488, 490, 502, 503, 506, 547, 548, 552, 554)


# ---- Cross-version packed header + GNSS fix block --------------------------
#
# The record is a PACKED struct: after the u8 version come two u32 LE
# millisecond counters at [1:5] and [5:9]. The aligned u32 `tick_a` at [0:4]
# (v=0x0A) and the u24 `seq_counter` at [1:4] (v=0x0D) are this same [1:5]
# counter, shifted.
#
#   [1:5]  u32 fcount     — the WLS fix's GNSS-engine FCount (ms). F3-GROUND:
#                           equals the FC= argument of the nf_wls.c
#                           "NF: WLS result: FC=%u, FailCode=%u, altMode=%u"
#                           print, co-emitted 1:1 with every record (v=0x06..
#                           0x0D; see source_detail for per-version counts).
#   [5:9]  u32 fcount_ref — a second FCount, a constant offset behind fcount
#                           within a session (F3-silent → exposed raw).
#
# Whenever the WLS fix SUCCEEDS (F3 FailCode=0) the record carries a GNSS
# time + position block at a per-version base W. Its layout, relative to W, is
# identical on every version that has one:
#
#   W+0  u16 gps_week     W+2  u32 gps_msec (ms of week)   W+6  f32 (raw)
#   W+10 u8  glo_n4       W+11 u16 glo_nt   W+13 u32 glo_msec (ms of day)  W+17 f32
#   W+21 u16 bds_week     W+23 u32 bds_msec                W+27 f32
#   W+31 u16 gal_week     W+33 u32 gal_msec                W+37 f32
#   W+41 u16 navic_week   W+43 u32 navic_msec              W+47 f32
#   W+51 u8  leap_sec     (GPS-UTC; 18)
#   W+52 u8  leap_aux     (0 on most builds, 14 on CFW-3212 / T99W373 — equal to
#                         GPS-BDT seconds, but F3-silent → raw CANDIDATE)
#   W+53 u16 report_seq   (+1 per record; = `state_x` on v=0x0A)
#   W+57 f64 lat (rad)    W+65 f64 lon (rad)    W+77 f32 alt_hae_m
#
# That is the NavIC-capable layout (v=0x0A SDX55, v=0x0B Inseego M3100, v=0x0D
# SDX62). The pre-NavIC
# versions (v=0x06 MDM9x30, v=0x07 MDM9x07, v=0x08 SDX20/MDM9150/MDM9250) have
# NO NavIC entry, so everything after GAL moves up 10 bytes: leap_sec W+41,
# report_seq W+43, lat W+47, lon W+55, alt_hae_m W+67.
#
# The five constellation times obey the published time-system relations on
# every populated record (GLO = GPS time-of-day + 3 h - leap; BDS = GPS - 14 s
# and week - 1356; GAL/NavIC week = GPS week - 1024), which `time_consistent`
# checks over the VALID entries (0xFF/0xFFFF week/day sentinels and leap_sec 0
# mark a constellation time not yet established); the F3 "NF: Clock Adj: ... To PE GPS/GLO/BDS/GAL/NAVIC ms" prints
# carry the same values. Position is ground-truthed against NMEA (see
# source_detail). On a FAILED fix (FailCode=1) the block is zeroed / holds the
# 0x4912620F "unset" float fill, which can be mistaken for template
# padding. On v=0x0A the per-constellation f32 at W+6/27/37 coincide with
# `ext_f32_30/_51/_61` (NavIC's holds the 0x5437904D unset sentinel); their unit is not F3-labelled
# and they stay raw.
# version -> (base W, has_navic_entry)
_FIX_BLOCK_LAYOUT: dict[int, tuple[int, bool]] = {
    0x06: (24, False), 0x07: (24, False), 0x08: (24, False),
    0x0A: (24, True), 0x0B: (24, True), 0x0C: (32, True), 0x0D: (32, True),
}
_MS_PER_DAY = 86_400_000
_MS_PER_WEEK = 604_800_000

_KNOWN_VERSIONS = (0x02, 0x06, 0x07, 0x08, 0x0A, 0x0B, 0x0C, 0x0D)

# Attested record lengths of the fixed-size versions (from a census of the
# capture corpus). No version carries a length field, so the length is the only
# truncation signal: below the largest attested size, only an attested size is
# a record. v0x0D is the 44 B + 47 B-slot grid, gated in the body decode.
_FIXED_SIZES: dict[int, tuple[int, ...]] = {
    0x02: (1559,),
    0x06: (4163,),
    0x07: (4395,),
    0x08: (3521, 4579),
    0x0A: (4641,),
    0x0B: (9530,),
    0x0C: (9538,),
}


@dataclass
class GnssFixBlock:
    """GNSS time + WLS position block (present when the WLS fix succeeded)."""
    gps_week: int
    gps_msec: int
    glo_n4: int          # GLONASS 4-year interval number
    glo_nt: int          # GLONASS day number within the 4-year interval
    glo_msec: int        # GLONASS ms of day (UTC(SU))
    bds_week: int
    bds_msec: int
    gal_week: int
    gal_msec: int
    navic_week: int | None       # None on the pre-NavIC layout
    navic_msec: int | None
    const_f32: tuple[float, ...]  # raw f32 after each constellation's msec
    leap_sec: int
    leap_aux: int        # raw u8 after leap_sec (0 or 14; candidate GPS-BDT s)
    report_seq: int
    lat_deg: float
    lon_deg: float
    alt_hae_m: float
    time_consistent: bool

    def to_dict(self) -> dict[str, Any]:
        d = {k: getattr(self, k) for k in (
            'gps_week', 'gps_msec', 'glo_n4', 'glo_nt', 'glo_msec', 'bds_week',
            'bds_msec', 'gal_week', 'gal_msec', 'navic_week', 'navic_msec',
            'leap_sec', 'leap_aux', 'report_seq', 'time_consistent')}
        d['const_f32'] = [round(x, 6) for x in self.const_f32]
        d['lat_deg'] = round(self.lat_deg, 9)
        d['lon_deg'] = round(self.lon_deg, 9)
        d['alt_hae_m'] = round(self.alt_hae_m, 3)
        return d


def _parse_fix_block(data: bytes, w: int, has_navic: bool) -> GnssFixBlock | None:
    """Decode the time + position block at base ``w``; None when the fix failed
    (block zeroed — gps_week 0) or the record is too short."""
    tail = w + (51 if has_navic else 41)  # leap_sec offset
    if len(data) < tail + 30:
        return None
    gps_week, gps_msec = unpack_from('<HI', data, w)
    if gps_week == 0:
        return None
    glo_n4 = data[w + 10]
    glo_nt, glo_msec = unpack_from('<HI', data, w + 11)
    bds_week, bds_msec = unpack_from('<HI', data, w + 21)
    gal_week, gal_msec = unpack_from('<HI', data, w + 31)
    navic_week = navic_msec = None
    f32_offs = (6, 17, 27, 37)
    if has_navic:
        navic_week, navic_msec = unpack_from('<HI', data, w + 41)
        f32_offs += (47,)
    const_f32 = tuple(unpack_from('<f', data, w + o)[0] for o in f32_offs)
    leap_sec, leap_aux, report_seq = unpack_from('<BBH', data, tail)
    lat_rad, lon_rad = unpack_from('<dd', data, tail + 6)
    alt_hae_m = unpack_from('<f', data, tail + 26)[0]
    # Each constellation entry is checked only when it is VALID: the firmware
    # marks a not-yet-established time with glo_n4 0xFF / glo_nt 0xFFFF and
    # week 0xFFFF, and an unknown UTC offset with leap_sec 0 (early/partial
    # fixes on EG18-NA / EG25-G); the msec field of an invalid entry is an
    # unrelated running value, not a time.
    checks = []
    if glo_n4 != 0xFF and glo_nt != 0xFFFF and leap_sec:
        checks.append(glo_msec == (gps_msec % _MS_PER_DAY + 3 * 3_600_000 - leap_sec * 1000) % _MS_PER_DAY)
    if bds_week != 0xFFFF:
        checks.append(bds_msec == (gps_msec - 14_000) % _MS_PER_WEEK and bds_week == gps_week - 1356)
    if gal_week != 0xFFFF:
        checks.append(gal_msec == gps_msec and gal_week == gps_week - 1024)
    if navic_week is not None and navic_week != 0xFFFF:
        checks.append(navic_msec == gps_msec and navic_week == gps_week - 1024)
    time_consistent = all(checks)
    return GnssFixBlock(
        gps_week=gps_week, gps_msec=gps_msec, glo_n4=glo_n4, glo_nt=glo_nt,
        glo_msec=glo_msec, bds_week=bds_week, bds_msec=bds_msec,
        gal_week=gal_week, gal_msec=gal_msec, navic_week=navic_week,
        navic_msec=navic_msec, const_f32=const_f32,
        leap_sec=leap_sec, leap_aux=leap_aux, report_seq=report_seq,
        lat_deg=math.degrees(lat_rad), lon_deg=math.degrees(lon_rad),
        alt_hae_m=alt_hae_m, time_consistent=time_consistent,
    )


@dataclass
class WlsSvRecord:
    """One per-SV 47-byte record from a 0x147C v=0x0D body."""
    prn: int                # GPS SV ID (1..32)
    subframe_type: int      # byte [10] — per-PRN constant within a session
    wls_f1: float; wls_f2: float; wls_f3: float
    wls_f4: float; wls_f5: float; wls_f6: float
    wls_f7: float; wls_f8: float; wls_f9: float

    def to_dict(self) -> dict[str, Any]:
        return {
            'prn': self.prn,
            'subframe_type': self.subframe_type,
            'wls_f1': round(self.wls_f1, 6),
            'wls_f2': round(self.wls_f2, 6),
            'wls_f3': round(self.wls_f3, 6),
            'wls_f4': round(self.wls_f4, 6),
            'wls_f5': round(self.wls_f5, 4),
            'wls_f6': round(self.wls_f6, 4),
            'wls_f7': round(self.wls_f7, 8),
            'wls_f8': round(self.wls_f8, 6),
            'wls_f9': round(self.wls_f9, 6),
        }


@dataclass
class Diag0x147C:
    """GNSS PE WLS Position Report (0x147C) — header + v=0x0D body decode."""
    log_time: int
    version: int        # byte 0
    counter_hi: int     # byte 1 (legacy name; v=0x0D this is LSB of u24LE counter)
    counter_lo: int     # byte 2 (legacy name; v=0x0D this is mid byte of counter)
    payload_size: int
    body_raw: bytes

    # v=0x0D structural decode. None on other versions.
    n_slots: int | None              # (size - 44) // 47
    n_sv_records: int | None         # count of `00 00 75 11 01` signatures
    head_slots: int | None           # n_slots - n_sv_records
    preamble_invariants_ok: bool | None  # version-specific preamble anchor set present?
    seq_counter: int | None          # u24LE at [1:4] — per-record incrementing counter

    # v=0x0A universal-core decode. None on other versions.
    tick_a: int | None = None        # u32 LE [0:4]  — GNSS clock tick (+256000/rec)
    tick_b: int | None = None        # u32 LE [4:8]  — GNSS clock tick (+256000/rec)
    state_x: int | None = None       # u16 LE [77:79]
    state_y: int | None = None       # u24 LE [97:100]

    # v=0x0A per-record measurement-extension region. These three offsets are
    # the only LIVE (per-record-varying) fields beyond the universal core —
    # isolated by diffing two consecutive EM9190 records (13 differing bytes
    # total: tick_a/tick_b low words, state_x, state_y, and these). They
    # decode as LE f32; the magnitude is firmware-specific (EM9190 SDX55
    # ≈ 15.4 with a stable high word, i.e. a real-valued measurement; FN980
    # ≈ 3.15e12; RM500Q-AE ≈ 0.0 / 0.021 / 0.0 over 260 records), so they are
    # exposed as raw candidates, NOT asserted in the cross-vendor validator.
    # The 10-byte blocks [51:61] and [61:71] are a verified cross-vendor
    # MIRROR (ext_mirror_ok, 3/3 fixtures), so ext_f32_61 duplicates
    # ext_f32_51. Physical semantics (C/N0 vs LNA gain vs clock bias) are
    # unresolved; the "~15.4 physical unit" is specifically an EM9190
    # question. None off-version/off-size.
    #
    # Co-temporal F3 messages on RM500Q-AE place the v=0x0A subsystem in GNSS
    # search strategy (mc_gnsssearchstrategy.c / mc_gnssconfig.c /
    # mc_srchstrategy.c) and the TCXO/clock manager (tcxomgr_data.c "XO Trim
    # Factory/Field/Curr", tcxomgr_rot_client_handling.c "Temp/Rot/VCO"),
    # consistent with the GNSS-engine-clock reading of tick_a/tick_b and a
    # hardware/clock-class meaning for the EM9190 ext_f32 values.
    ext_f32_30: float | None = None  # f32 LE [30:34]
    ext_f32_51: float | None = None  # f32 LE [51:55]
    ext_f32_61: float | None = None  # f32 LE [61:65] — mirror of ext_f32_51
    ext_mirror_ok: bool | None = None  # data[51:61] == data[61:71]

    # v=0x0A EM9190-only [488:554] state-flag region. 9 byte values at the
    # corpus-attested toggle offsets (_V0A_TOGGLE_OFFSETS), in order. All-zero
    # on FN980 (Telit) and on the ~88% of EM9190 records in an inactive state.
    # None off-version/off-size. The structure is complete; the physical
    # meaning (GNSS-engine mode/health bits) is not yet established.
    toggle_region: tuple[int, ...] | None = None

    # Packed-header FCounts (every version) + the GNSS time /
    # position block (versions with a known base, only when the fix succeeded).
    fcount: int | None = None        # u32 LE [1:5] — F3 "WLS result: FC="
    fcount_ref: int | None = None    # u32 LE [5:9] — raw
    wls_fail_code: int | None = None  # u8 at W-1 — F3 "WLS result: FailCode="
    fix: GnssFixBlock | None = None

    wls_records: list[WlsSvRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x147C',
            'log_time': self.log_time,
            'version': self.version,
            'counter_hi': self.counter_hi,
            'counter_lo': self.counter_lo,
            'payload_size': self.payload_size,
            'n_slots': self.n_slots,
            'n_sv_records': self.n_sv_records,
            'head_slots': self.head_slots,
            'preamble_invariants_ok': self.preamble_invariants_ok,
            'seq_counter': self.seq_counter,
            'tick_a': self.tick_a,
            'tick_b': self.tick_b,
            'state_x': self.state_x,
            'state_y': self.state_y,
            'ext_f32_30': self.ext_f32_30,
            'ext_f32_51': self.ext_f32_51,
            'ext_f32_61': self.ext_f32_61,
            'ext_mirror_ok': self.ext_mirror_ok,
            'toggle_region': list(self.toggle_region) if self.toggle_region is not None else None,
            'fcount': self.fcount,
            'fcount_ref': self.fcount_ref,
            'wls_fail_code': self.wls_fail_code,
            'fix': self.fix.to_dict() if self.fix is not None else None,
            'wls_records': [r.to_dict() for r in self.wls_records],
        }


def _parse_v0d_body(data: bytes) -> tuple[int, int, int, bool, int, list[WlsSvRecord]]:
    """Decode the v=0x0D body. Returns (n_slots, n_sv, head_slots, preamble_ok,
    seq_counter, wls_records)."""
    sz = len(data)
    # Slot-count check — already enforced by formula in caller.
    n_slots = (sz - _V0D_PREAMBLE_LEN) // _V0D_SLOT_STRIDE

    preamble_ok = all(data[o] == v for o, v in _V0D_PREAMBLE_CONSTS.items())
    seq_counter = data[1] | (data[2] << 8) | (data[3] << 16)

    # Scan ONLY the slot grid (not the preamble) for SV-record signatures.
    # The grid starts at offset _V0D_PREAMBLE_LEN.
    wls_records: list[WlsSvRecord] = []
    pos = _V0D_PREAMBLE_LEN
    while True:
        i = data.find(_V0D_SV_SIG, pos)
        if i < 0:
            break
        if i + _V0D_SLOT_STRIDE > sz:
            break
        # Only count signatures aligned on the slot grid — guards against
        # accidental matches inside the head-slot padding (which is mostly
        # the `0f621249` fill but could in theory align).
        if (i - _V0D_PREAMBLE_LEN) % _V0D_SLOT_STRIDE != 0:
            pos = i + 1
            continue
        floats = unpack_from('<9f', data, i + 11)
        wls_records.append(WlsSvRecord(
            prn=data[i + 6],
            subframe_type=data[i + 10],
            wls_f1=floats[0], wls_f2=floats[1], wls_f3=floats[2],
            wls_f4=floats[3], wls_f5=floats[4], wls_f6=floats[5],
            wls_f7=floats[6], wls_f8=floats[7], wls_f9=floats[8],
        ))
        pos = i + _V0D_SLOT_STRIDE

    head_slots = n_slots - len(wls_records)
    return n_slots, len(wls_records), head_slots, preamble_ok, seq_counter, wls_records


def _parse_v0a_body(
    data: bytes,
) -> tuple[int, int, int, int, bool, float, float, float, bool, tuple[int, ...]]:
    """Decode the v=0x0A body. Returns (tick_a, tick_b, state_x, state_y,
    preamble_ok, ext_f32_30, ext_f32_51, ext_f32_61, ext_mirror_ok,
    toggle_region). Caller guarantees len(data) == _V0A_PAYLOAD_SIZE."""
    tick_a = unpack_from('<I', data, 0)[0]
    tick_b = unpack_from('<I', data, 4)[0]
    state_x = unpack_from('<H', data, 77)[0]
    state_y = data[97] | (data[98] << 8) | (data[99] << 16)
    preamble_ok = (
        all(data[o] == v for o, v in _V0A_PREAMBLE_CONSTS.items())
        and all(data[o] == 0 for o in _V0A_RESERVED_ZERO)
    )
    # Per-record measurement-extension region (the 3 live offsets beyond the
    # universal core). f32 magnitude is firmware-specific — exposed raw.
    ext_f32_30 = unpack_from('<f', data, 30)[0]
    ext_f32_51 = unpack_from('<f', data, 51)[0]
    ext_f32_61 = unpack_from('<f', data, 61)[0]
    ext_mirror_ok = data[51:61] == data[61:71]
    # EM9190-only [488:554] state-flag region — 9 byte values in offset order.
    toggle_region = tuple(data[o] for o in _V0A_TOGGLE_OFFSETS)
    return (tick_a, tick_b, state_x, state_y, preamble_ok,
            ext_f32_30, ext_f32_51, ext_f32_61, ext_mirror_ok, toggle_region)


# ---------------------------------------------------------------------------
# Ground-truth recipe — v=0x0D, RM520N-GL (Quectel SDX62)
# ---------------------------------------------------------------------------
# v=0x0D is the only version whose BODY is decoded (per-SV WLS records). Of
# its decoded fields, exactly one is a clean cross-checkable anchor — the GPS
# PRN at slot byte [6] — plus a SV-used count. The nine wls_f* floats are a
# deliberate DISCOVERY design: the structural layout is
# locked but the f-slot -> physical-quantity mapping is unknown. The parser's
# own decode of PRN=1 (f5=11.54, f6=56.79, f9=0.99) gives magnitude evidence
# for candidate semantics — f6 sits in the GNSS C/N0 dB-Hz band, f9 looks like
# a normalized WLS weight. The recipe's job is to let a hardware capture
# recover WHICH slot is which quantity (and its scale) by correlating against
# the per-SV GSV columns. Structural counters (seq_counter, tick_*) carry no
# physical-quantity AT source and are intentionally left out of the field_map.

@register(
    0x147C, domain="gnss",
    name="0x147C",
    description=(
        "GNSS PE WLS Position Report. Packed header decoded on all 8 "
        "versions (fcount = F3 'NF: WLS result: FC=' 1:1); GNSS time + WLS "
        "position block (GPS/GLO/BDS/GAL/NavIC time, leap, report_seq, "
        "lat/lon/HAE) on v=0x06/07/08/0A/0B/0D, time-system-consistent and "
        "NMEA/LG290P-grounded; wls_fail_code = F3 FailCode. v=0x0D per-SV WLS "
        "records (PRN hardware-verified); v=0x0A EM9190 [488:554] state-flag "
        "region. v=0x02 (MDM9200, no F3 in corpus) decodes fcount/fcount_ref "
        "only"
    ),
    version=11,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Eight versions observed, attributed by chipset: v=0x02 MDM9200, "
        "v=0x06 MDM9x30 (EM7455), v=0x07 MDM9x07 (EG25-G), v=0x08 "
        "SDX20/MDM9150/MDM9250, v=0x0A SDX55, v=0x0B Inseego M3100, v=0x0C "
        "T99W373, v=0x0D SDX62. The record is a PACKED struct: [1:5] u32 "
        "`fcount` equals the FC= argument of the firmware's nf_wls.c F3 print "
        "'NF: WLS result: FC=%u, FailCode=%u, altMode=%u', co-emitted 1:1: "
        "v=0x0D 163/163 (RM520N-GL), v=0x0A 94/94 + 240 (RM500Q-AE), v=0x08 "
        "256/256 (MDM9250), v=0x07 354/354 (EG25-G), v=0x0B 5/5 + 443/461 "
        "(Inseego M3100), v=0x0C 179/179 (T99W373); v=0x06 (EM7455) co-emits "
        "nf_navsolution.c 'Clock Adj: FC=' 155/155. [5:9] `fcount_ref` is a "
        "second FCount at a constant per-session offset (F3-silent, raw). "
        "Byte W-1 == F3 FailCode on 1,127/1,127 joined records; when it is 0 "
        "the GNSS time + position block at W (v=0x06/07/08/0A/0B: 24, "
        "v=0x0C/0D: 32) is populated: GPS week/msec (= F3 'UpdEnvDetector "
        "GpsMsec' and 'Clock Adj: To PE GPS ms' 163/163), GLONASS N4/NT/msec, "
        "BDS, GAL, NavIC (SDX55+ only; pre-NavIC versions shift the tail up "
        "10 B), leap_sec u8 (18) + a raw u8 leap_aux (14 on CFW-3212/T99W373 "
        "builds), a +1 report_seq, lat/lon f64 radians and f32 HAE. On a "
        "failed fix the block holds the 0x4912620F unset-float fill. "
        "Position vs independent truth: v=0x0A RM500Q-AE moving drive capture "
        "vs its NMEA GGA, 1,253 joined, median 1.4 m N / 1.7 m E, HAE 0.08 m; "
        "v=0x07 EG25-G 340/340 exact (0.00 m) to its own GGA; v=0x0B M3100 "
        "50/50 exact; v=0x0D RM520N-GL vs co-located LG290P TPV, 1,562 "
        "joined, median 1.3 m N / 1.1 m E (HAE -9.7 m bias = WLS vertical "
        "error). One RM520N-GL firmware build reports gps_week = true week - "
        "1024 (BDS/GAL weeks inherit it) — exposed raw, not corrected. "
        "0x60 EVENT_GNSS_TLE_TIME_UPDATE_C (id 1951) payload [9:11] u16 week "
        "+ [11:15] u32 msec == the block's gps_week/gps_msec 351/351 (EG25-G) "
        "and 460/460 (M3100). "
        "Corpus: stratified walk (377 captures, 80,058 records, all 8 "
        "versions and every version x firmware stratum): 0 exceptions / 0 "
        "rejects; time_consistent holds on every populated record once "
        "invalid entries are skipped (glo_n4 0xFF / week 0xFFFF / leap_sec 0 "
        "mark a constellation time not yet established — 1,408 early-fix "
        "EG18-NA/EG25-G records). FailCodes 6/10/11/17 (246 records) also "
        "occur and some carry a block. "
        "v=0x0D body: `[44B preamble] + [N × 47B slots]`, verified "
        "`(size - 44) % 47 == 0` on every attested size (796..1407 B); a "
        "per-SV record is an 11-byte prefix (5B signature `0000 7511 01`, PRN "
        "at [6], 0x0007 marker, subframe_type byte) + 9 LE f32 measurement "
        "fields. Corpus-wide (20 captures, 5,443 v=0x0D records, 29,532 per-SV "
        "records): 100% decode success. 16 of 44 preamble bytes are "
        "cross-capture invariants across normal, warm-restart, reboot, "
        "SIM-power-cycle and airplane-mode states (`preamble_invariants_ok`). "
        "The wls_f1..wls_f9 names are deliberately generic: the slot -> "
        "physical-quantity mapping (residual vs weight vs elevation-cos vs "
        "C/N0 vs Doppler-rate) needs per-SV LOS cross-correlation against "
        "known-position fixes. "
        "v=0x0A body (fixed 4641 B; EM9190 1,133 + FN980 1,166 records): "
        "sparse — only 11 byte positions carry cross-vendor content "
        "(`tick_a`/`tick_b` are the packed FCounts read one byte early, "
        "`state_x`=u16[77:79] = report_seq, `state_y`=u24[97:100] slow "
        "engine tick). The validator asserts only [0]=0x0A and the zero sets "
        "[9:13]+[19:23] (13-18 are live); byte[33] and the f32 at [41:45] "
        "are per-firmware constants. `ext_f32_30/_51/_61` are the only other "
        "live per-record fields (EM9190 ≈ 15.4, firmware-specific magnitude, "
        "raw); [51:61] mirrors [61:71] (`ext_mirror_ok`, 3/3 fixtures). "
        "`toggle_region` exposes the EM9190-only [488:554] state flags (9 "
        "bytes at 488/490/502/503/506/547/548/552/554), which co-vary in 3 "
        "groups: off=488 <-> off=506 (same 134 records), off=490 <-> off=547 "
        "<-> off=552 (same 50 records), off=502 <-> off=503 (same 87 records) "
        "— ~3 independent GNSS-engine state indicators; all-zero on FN980 "
        "and on ~88% of EM9190 records. Physical semantics of the flags and "
        "of ext_f32_* are not established. "
        "Length checks: the fixed-size versions return None (registry WARN) "
        "on a length below their attested size that is not itself attested "
        "(v0x02 1559, v0x06 4163, v0x07 4395, v0x08 3521/4579, v0x0A 4641, "
        "v0x0B 9530, v0x0C 9538 B; longer payloads are accepted, and an "
        "off-size v0x0A keeps its body undecoded). A v=0x0D record that is "
        "not the 44 B preamble + a whole number of 47 B slots, or any record "
        "shorter than its fix-block base W, returns None."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=46,  # version, counter_hi/lo, n_slots, n_sv_records,
                            # head_slots, preamble_invariants_ok, seq_counter,
                            # v=0x0A: tick_a, tick_b, state_x, state_y,
                            # ext_f32_30/_51/_61, ext_mirror_ok, toggle_region,
                            # plus per-SV: prn, subframe_type, wls_f1..f9 (11 fields);
                            # header: fcount, fcount_ref, wls_fail_code + fix block
                            # (gps_week/msec, glo_n4/nt/msec, bds_week/msec,
                            # gal_week/msec, navic_week/msec, const_f32,
                            # leap_sec, leap_aux, report_seq, lat/lon/alt,
                            # time_consistent)
    fields_parsed=46,
    field_invariants={
        "version": {"enum": list(_KNOWN_VERSIONS)},
    },
)
def parse_0x147c(log_time: int, data: bytes) -> Diag0x147C | None:
    if len(data) < 9:
        return None
    version = data[0]
    if version not in _KNOWN_VERSIONS:
        return None
    sizes = _FIXED_SIZES.get(version)
    if sizes is not None and len(data) < max(sizes) and len(data) not in sizes:
        # A cut fixed-size record — return None (registry WARN) instead
        # of a record whose body_raw / tail fields silently came up short.
        return None
    fcount, fcount_ref = unpack_from('<II', data, 1)
    layout = _FIX_BLOCK_LAYOUT.get(version)
    if layout is not None and len(data) < layout[0]:
        # Shorter than the packed header up to the fix-block base W
        # (wls_fail_code sits at W-1) — return None instead of an IndexError.
        return None
    fix = _parse_fix_block(data, *layout) if layout is not None else None
    wls_fail_code = data[layout[0] - 1] if layout is not None else None

    n_slots: int | None = None
    n_sv: int | None = None
    head_slots: int | None = None
    preamble_ok: bool | None = None
    seq_counter: int | None = None
    tick_a: int | None = None
    tick_b: int | None = None
    state_x: int | None = None
    state_y: int | None = None
    ext_f32_30: float | None = None
    ext_f32_51: float | None = None
    ext_f32_61: float | None = None
    ext_mirror_ok: bool | None = None
    toggle_region: tuple[int, ...] | None = None
    wls_records: list[WlsSvRecord] = []

    # v=0x0D structural decode (per-SV slot grid). v=0x06/0x07/0x08 decode
    # only the packed header and fix block — their fixed sizes (4163/4395/4579 B)
    # do NOT satisfy the v=0x0D formula and would silently mis-parse.
    if version == 0x0D:
        sz = len(data)
        # The v=0x0D record IS the 44 B preamble +
        # a whole number of 47 B slots — every attested size satisfies it. An
        # off-grid record is truncated (or an unknown layout): return None
        # (registry WARN) instead of a record with the body silently skipped.
        if sz < _V0D_PREAMBLE_LEN or (sz - _V0D_PREAMBLE_LEN) % _V0D_SLOT_STRIDE != 0:
            return None
        (n_slots, n_sv, head_slots,
         preamble_ok, seq_counter, wls_records) = _parse_v0d_body(data)
    # v=0x0A universal-core decode. Fixed 4641 B sparse state record;
    # gate on the exact size so off-size v=0x0A records (none observed) don't
    # read past meaningful offsets.
    elif version == 0x0A and len(data) == _V0A_PAYLOAD_SIZE:
        (tick_a, tick_b, state_x, state_y, preamble_ok,
         ext_f32_30, ext_f32_51, ext_f32_61, ext_mirror_ok,
         toggle_region) = _parse_v0a_body(data)

    return Diag0x147C(
        log_time=log_time,
        version=version,
        counter_hi=data[1],
        counter_lo=data[2],
        payload_size=len(data),
        body_raw=data[8:],
        n_slots=n_slots,
        n_sv_records=n_sv,
        head_slots=head_slots,
        preamble_invariants_ok=preamble_ok,
        seq_counter=seq_counter,
        tick_a=tick_a,
        tick_b=tick_b,
        state_x=state_x,
        state_y=state_y,
        ext_f32_30=ext_f32_30,
        ext_f32_51=ext_f32_51,
        ext_f32_61=ext_f32_61,
        ext_mirror_ok=ext_mirror_ok,
        toggle_region=toggle_region,
        fcount=fcount,
        wls_fail_code=wls_fail_code,
        fcount_ref=fcount_ref,
        fix=fix,
        wls_records=wls_records,
    )
