"""0x147D — GNSS Position Engine Kalman-filter position report.

See the module body for the field map and the evidence behind it.

Log name: LOG_GNSS_PE_KF_POSITION_REPORT_C
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


# ---------------------------------------------------------------------------
# 0x147D — GNSS PE Kalman-filter position report (companion to 0x147C)
# ---------------------------------------------------------------------------
# Record forms, keyed by the version byte [0]:
#     v=0x00  1957 B fixed               Sierra MC7700 (SWI9200X platform)
#     v=0x04  3185 B fixed               MC7455 / EM7455 (MDM9x30)
#     v=0x05  3665 B fixed               MDM9x07 (EP06A, EG18-NA), SDX20 (LM960),
#                                        MDM9650 (WNC 81UMV91B1), MDM9607 (EG25-G)
#     v=0x06  4717 B fixed               SDX55 (FN980m, EM9190, RM500Q-AE)
#     v=0x07  variable, len % 46 == 33   SDX65 (Inseego M3100)
#     v=0x08  variable, len % 46 == 35   SDX55 / SDX62 (RM520N-GL and others)
#
# Identity: the per-fix Position Engine Kalman-filter position report
# (canonical log name LOG_GNSS_PE_KF_POSITION_REPORT_C). The firmware's own F3
# debug stream grounds this on four generations, each by a 1:1 count match
# against the per-fix lm_mgp.c / nf_navsolution.c prints at a constant phase
# offset (a fixed pipeline latency, not coincidence):
#     v=0x04  EM7455 (MDM9x30)     155 records    (see the v=0x04 note below)
#     v=0x05  EG25-G (MDM9607)     1,799 records  -106.70 ms phase
#     v=0x06  RM500Q-AE (SDX55)    305 records    ~47.5 ms phase
#     v=0x08  RM520N-GL (SDX62)    163 records    ~60.9 ms phase
# v=0x00 and v=0x07 are grounded instead by joining against the co-emitted
# 0x1476 position report (see their notes below).
#
# v=0x05 on MDM9650 (Wistron/WNC 81UMV91B1): 48 records, and all seven v=0x05
# structural invariants hold 48/48 ([4]=0x00; [8:16]=0; body tags
# [17]=0x09/[22]=0x08/[24]=0x03/[30]=0x04; bipartite body[2:6]==body[21:25]),
# 100% parse via the existing branch (size_class=mdm9x07_3665). This is a new
# chipset family for an already-handled format, not a same-size layout drift.
# Byte [16] takes a fourth observed value (0x80) on MDM9650; it is not
# asserted (see the body substructure below).
#
# v=0x05 on MDM9607 (Quectel EG25-G): the 1,799 v=0x05 records co-emit 1:1
# with the per-fix lm_mgp.c prints (lm_mgp.c:228 'New fix saved as best' /
# :441 / :609, all == 1800; the +1 is a capture-boundary fix) at a constant
# -106.70 ms phase (99.9% within ±5 ms) over a 1.000 s fix interval. All 7
# v=0x05 invariants hold 1799/1799; byte [16]=0x80, as on MDM9650.
#
# Byte [5] is not a constant format marker (``sub_counter``, kept for
# compatibility, reads it raw). bytes[5:7] is a header-state word taking
# values from a small set (0x1091 modal, 0x1011, 0x0011, 0x0002) that varies
# within a single capture as well as across captures of the same module (883
# records from 4 LG290P-paired captures: EP06A, EM7511, EG18-NA, FN980). The
# record-field markers at [17]/[22]/[24]/[30]/[36] are body-record tags (see
# "Body substructure" below) and hold as body-internal invariants.
#
# Header (offsets cross-chipset stable; values where noted):
#     [0]      u8    version                (5 on MDM9x07/SDX20; 6 on SDX55;
#                                            0 on MC7700 — a different
#                                            header, see _parse_0x147d_v00)
#     [1:4]    u24LE scope_id               (per-record, varies)
#     [4]      u8    0x00 on v=0x05         (not constant on v=0x04 — see
#                                            below; [1:5] is one u32)
#     [5:7]    u16LE marker_bytes_5_7       (header-state word; observed
#                                            values: 0x1091 modal, 0x1011,
#                                            0x0011, 0x0002 — not a constant)
#     [7]      u8    size_flag              (bitfield: bit 4 = SDX55 4717B
#                                            size class, bit 1 = FN980
#                                            firmware variant)
#     [8:16]   8B    reserved               (all zero)
#
#     F3-grounded on v=0x04 only: [1:5] u32LE fcount_ms is the GNSS engine's
#     millisecond FCount (scope_id is its low 24 bits, and [4] its MSB — 0x00
#     on MC7455 uptimes, 0x10/0x01 on EM7455). Body [16:18] u16LE gps_week and
#     [18:22] u32LE gps_msec (GPS msec-of-week of the fix, repeated at
#     [37:41]) — so the "record-start marker [+0]" + "type tag [+1]=0x09"
#     below are the two bytes of the GPS week, and the "ephemeris value
#     [+2:6]" is the fix time. The same header very likely holds on
#     v=0x05/0x06/0x08 but is not F3-grounded there, so those fields stay None.
#
# Body substructure (starts at offset 16) — per-SV table with a mixed
# record-size pattern:
#     19-byte header record at offset 16, layout:
#         [+0]   0x6d/0x6e (MDM9x07/SDX20), 0x71 (MC7455/MDM9x30), 0x80
#                (MDM9650, MDM9607) — not asserted. On v=0x04 [+0:2] is the
#                u16LE GPS week, so [+0] tracks the capture date rather than
#                the chipset.
#         [+1]   0x09          record-type tag (0x09 on all observed records;
#                on v=0x04 it is the GPS week's high byte for 2304..2559)
#         [+2:6] 4B            ephemeris value  (repeats in the 6B tail record)
#                (on v=0x04: u32LE gps_msec, GPS msec-of-week of the fix)
#         [+6]   0x08          field marker
#         [+7]   u8 kind       (0x40 / 0x44 — varies)
#         [+8]   0x03          field marker
#         [+9:14] 5B           per-SV data
#         [+14]  0x04          field marker
#         [+15:19] 4B          per-SV data (repeats in the tail record's body)
#     6-byte tail record at offset 35, layout:
#         [+0]   0x6d / 0x6e   same marker as the header record at [+0]
#         [+1]   0x05          record-type tag (always 0x05 for the tail)
#         [+2:6] 4B            ephemeris value  (== 19B record's [+2:6])
#
# The header-record's 4B value at [+2:6] is byte-exact identical to the
# tail-record's 4B value at [+2:6] on every fixture observed.
#
# On SDX55 (4717B variant) this per-SV pattern repeats past offset 41
# (6B tail-record, then another 6B tail-record at 41) giving the extra
# 1052B over MDM9x07's 3665B.  MDM9x07 captures have zeros from offset 41
# to 44 before the next 19B record starts.
#
# Full per-SV field labelling still requires correlating with a known-
# ephemeris baseline; the 19B + 6B bipartite record structure is
# cross-chipset-stable.
#
# A second structural layer, from per-byte variance across fixtures: a
# 46-byte-stride repeating table starting around payload offset 440. Slot
# density pattern (across 3665B fixture pairs):
#
#     [ 440:486] slot 0   high variability — populated
#     [ 486:532] slot 1   partial
#     [ 532:578] slot 2   ~0 variability — empty/reserved
#     [ 578:624] slot 3   populated
#     [ 624:670] slot 4   populated
#     ...
#
# The pattern resembles an ephemeris cache: a pre-sized per-SV slot table
# where only actively-tracked SVs have populated slots.  Slot size 46 bytes
# fits a standard 40-byte-core ephemeris record plus a 6B auxiliary header.
# Per-slot field naming still requires an ephemeris-baseline cross-check, but
# the slot-table structure itself is an invariant, so per-slot 46B windows are
# exposed for downstream decode.

# Cross-chipset signature markers (empirically stable).
_NAVDB147D_SIG_1091 = 0x1091

# Per-byte variance over 1482 EM9190 SDX55 records shows two distinct per-slot
# layouts, both SDX55-specific; MDM9x07 uses different constants at the same
# offsets.
#
# Slot-0 "summary" layout — 5 cross-chipset format markers (SDX55 only).
# (A 6th candidate at [+3] is constant within a single 1482-record EM9190
# session at 0x3f, but the fn980m SDX55 fixture has it at 0x3e — consistent
# with the sign+exp_hi byte of an f32 that varies by session but not by
# record within a session. Excluded from the validator set.)
#     [+18] = 0x3b   marker byte (combined with +19 forms u16 0xc13b)
#     [+19] = 0xc1   marker byte
#     [+27] = 0xc1   marker byte (same value as +19)
#     [+34] = 0x4f   marker byte / f32 mantissa tail
#     [+35] = 0x41   f32 sign+exp_hi byte of a [2..4) range float
#
# Slot-4..7 "per-SV measurement" layout — 8 shared format zeros +
# 1 non-zero marker (SDX55 only):
#     [+ 1] = 0x00
#     [+ 5..+7] = 0x00 (3 zero bytes)
#     [+ 9] = 0x00
#     [+10] = 0x07   constellation or field-type marker
#     [+12] = 0x00
#     [+45] = 0x00   trailer byte
#
# Slot 1 is populated but appears to carry densely-packed ephemeris-style
# data (uniform-256 byte distribution); structure unknown.  Slots 2-3 and 8+
# are usually empty/zero.
#
# On MDM9x07 fixtures (ep06a, eg18na) the slot-0 offsets hold entirely
# different values (no cross-chipset invariance at these positions),
# indicating the 46-byte-stride layout is an SDX55-family format choice.
# Validators therefore return None on non-SDX55 size classes.

_NAVDB147D_SDX55_SLOT0_CONSTS: dict[int, int] = {
    18: 0x3B, 19: 0xC1, 27: 0xC1, 34: 0x4F, 35: 0x41,
}
_NAVDB147D_SDX55_SLOTC_CONSTS: dict[int, int] = {
    1: 0x00, 5: 0x00, 6: 0x00, 7: 0x00, 9: 0x00, 10: 0x07, 12: 0x00, 45: 0x00,
}
# Slot indices that carry the per-SV "format-C" measurement layout on SDX55.
_NAVDB147D_SDX55_SLOTC_INDICES: tuple[int, ...] = (4, 5, 6, 7)

# Slot-0 f32 candidate offsets. The two at offsets 16 and 32 are locked by the
# marker constants above (exp_hi bytes 0xC1 and 0x41 at [+19] and [+35]). The
# two at offsets 0 and 8 are bounded by the exp_hi bytes 0x3e/0x3f observed on
# the EM9190/fn980m SDX55 corpus — small positive fractions. Values outside
# these ranges signal a quantizer change or a layout drift.
_NAVDB147D_SDX55_SLOT0_F32_OFFSETS: tuple[int, ...] = (0, 8, 16, 32)


@dataclass
class Diag0x147D:
    """GNSS nav DB 147D (0x147D) — companion to 0x147C, size-variant."""
    log_time: int
    version: int
    scope_id: int               # u24LE at [1:4] — per-record scope / sequence id
    marker_bytes_5_7: int       # u16LE at [5:7] — header-state word
    sig_1091_ok: bool           # marker_bytes_5_7 == 0x1091; deprecated —
                                # bytes[5:7] is not a format marker: it takes
                                # values from a small set (0x1091, 0x1011,
                                # 0x0011, 0x0002) that varies within and
                                # across captures. Kept for compatibility;
                                # new code should read marker_bytes_5_7.
    size_flag: int              # byte [7] — 0x00 on 3665B / 0x10 on 4717B
    size_class: str             # "mdm9x07_3665" | "sdx55_4717" | "unknown"
    payload_size: int
    body_raw: bytes
    # 46-byte-stride slot table starting at offset 440. Exposed as raw slots
    # so downstream consumers can iterate without re-parsing.  None on
    # unknown sizes.
    body_slot_table_start: int | None
    body_slot_stride: int | None
    body_slots: list[bytes] | None  # list of 46B slices starting at [440:]

    # SDX55-family slot-layout validators. None on MDM9x07 (the
    # 46-byte-stride constants do not hold on that family).
    slot_0_sdx55_format_ok: bool | None   # slot 0's 6 cross-record constants all present
    slot_c_sdx55_format_count: int | None  # how many of slots 4..7 match format-C

    # Slot-0 f32 decodes on SDX55. None on MDM9x07. The two at offsets 16 and
    # 32 are locked by the marker constants (exp_hi 0xC1 → [-16, -8) range;
    # exp_hi 0x41 → [8, 16) range). The two at offsets 0 and 8 are
    # empirically small positive fractions.
    slot_0_sdx55_f32_at_0: float | None   # ≈ [0.1, 0.5) on SDX55 corpus
    slot_0_sdx55_f32_at_8: float | None   # ≈ [0.1, 0.5)
    slot_0_sdx55_f32_at_16: float | None  # ≈ [-16, -8) via 0xC1 marker
    slot_0_sdx55_f32_at_32: float | None  # ≈ [8, 16) via 0x41 marker

    # Kept for backward compatibility with older consumers.  Deprecated —
    # prefer scope_id.
    counter_hi: int
    counter_lo: int
    sub_counter: int            # raw byte [5] (see marker_bytes_5_7); kept for compat.

    # F3-grounded header time fields — populated on v=0x04 only (the one
    # version grounded against the firmware's own F3) and on v=0x00 (own
    # layout); None on v=0x05/0x06/0x07/0x08, where the layout is likely but
    # ungrounded.
    fcount_ms: int | None = None  # u32LE [1:5] — GNSS ms FCount (== F3 "FC=")
    gps_week: int | None = None   # u16LE [16:18] — GPS week of the fix
    gps_msec: int | None = None   # u32LE [18:22] — GPS msec-of-week of the fix
                                  # (on v=0x00 the week/msec sit at
                                  # [10:12]/[12:16] — see _parse_0x147d_v00)

    # v=0x00-only fix fields, grounded bit-exact against the co-emitted 0x1476
    # position report + the modem's NMEA/AT + an LG290P. Names match 0x1476 so
    # the two codes join field-for-field. None elsewhere.
    lat_rad: float | None = None       # f64LE [27:35] — WGS84 latitude (rad)
    lon_rad: float | None = None       # f64LE [35:43] — WGS84 longitude (rad)
    alt_m: float | None = None         # f32LE [43:47] — height above ellipsoid (m)
    vel_sigma_e: float | None = None   # f32LE [88:92]  (== 0x1476 vel_sigma_e)
    vel_sigma_n: float | None = None   # f32LE [92:96]  (== 0x1476 vel_sigma_n)
    vel_sigma_u: float | None = None   # f32LE [96:100] (== 0x1476 vel_sigma_u)
    glo_four_year: int | None = None   # u8    [16]     GLONASS N4 four-year interval
    glo_days: int | None = None        # u16LE [17:19]  GLONASS N_T day in interval
    glo_tow_ms: int | None = None      # u32LE [19:23]  GLONASS msec-of-DAY (0x1476 name)

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x147D',
            'log_time': self.log_time,
            'version': self.version,
            'scope_id': self.scope_id,
            'marker_bytes_5_7': self.marker_bytes_5_7,
            'sig_1091_ok': self.sig_1091_ok,
            'size_flag': self.size_flag,
            'size_class': self.size_class,
            'payload_size': self.payload_size,
            'body_slot_table_start': self.body_slot_table_start,
            'body_slot_stride': self.body_slot_stride,
            'body_slots_count': len(self.body_slots) if self.body_slots else 0,
            'slot_0_sdx55_format_ok': self.slot_0_sdx55_format_ok,
            'slot_c_sdx55_format_count': self.slot_c_sdx55_format_count,
            'slot_0_sdx55_f32_at_0': (
                None if self.slot_0_sdx55_f32_at_0 is None
                else round(self.slot_0_sdx55_f32_at_0, 9)
            ),
            'slot_0_sdx55_f32_at_8': (
                None if self.slot_0_sdx55_f32_at_8 is None
                else round(self.slot_0_sdx55_f32_at_8, 9)
            ),
            'slot_0_sdx55_f32_at_16': (
                None if self.slot_0_sdx55_f32_at_16 is None
                else round(self.slot_0_sdx55_f32_at_16, 6)
            ),
            'slot_0_sdx55_f32_at_32': (
                None if self.slot_0_sdx55_f32_at_32 is None
                else round(self.slot_0_sdx55_f32_at_32, 6)
            ),
            # Compatibility fields (deprecated).
            'counter_hi': self.counter_hi,
            'counter_lo': self.counter_lo,
            'sub_counter': self.sub_counter,
            # F3-grounded on v=0x04; also populated on v=0x00. None elsewhere.
            'fcount_ms': self.fcount_ms,
            'gps_week': self.gps_week,
            'gps_msec': self.gps_msec,
            # Populated on v=0x00 only; None elsewhere.
            'lat_rad': self.lat_rad,
            'lon_rad': self.lon_rad,
            'alt_m': self.alt_m,
            'vel_sigma_e': self.vel_sigma_e,
            'vel_sigma_n': self.vel_sigma_n,
            'vel_sigma_u': self.vel_sigma_u,
            'glo_four_year': self.glo_four_year,
            'glo_days': self.glo_days,
            'glo_tow_ms': self.glo_tow_ms,
        }


def _147d_size_class(n: int) -> str:
    if n == 1957:
        return "mc7700_1957"
    if n == 3185:
        return "mc7455_3185"
    if n == 3665:
        return "mdm9x07_3665"
    if n == 4717:
        return "sdx55_4717"
    return "unknown"


_NAVDB147D_SLOT_TABLE_START = 440
_NAVDB147D_SLOT_STRIDE = 46

# v=0x08 is the variable-size, 46-byte-stride form (SDX55/SDX62) and the
# dominant real-world 0x147D shape (15,351 corpus records, 68 distinct sizes).
# Structure, from a Quectel RM520N-GL SDX62 capture (1,582 records, 8 sizes
# 1691..2013 B):
#   * Sizes advance in exact 46-byte steps; every size == 35 (mod 46).
#   * Within-record byte autocorrelation peaks at lag 46 (0.639) and 92
#     (2x46) — the 46B slot stride is the dominant period.
#   * Adjacent sizes differ by exactly one 46B slot (1691 vs 1737: 1-byte
#     common prefix, diff regions differ by exactly 46B) -> header + N*46B
#     slots + trailer; bumping the size appends one per-SV entry.
#   * The v=0x05/0x06 header convention carries forward: [0]=0x08, [8:15]=0;
#     [5] is the state-word high bit (0x11/0x91, giving marker_bytes_5_7 in
#     {0x1011, 0x1091} — the same small set as v=0x05/0x06).
# The absolute slot-table start offset is not uniquely determinable from
# size arithmetic alone (many (header, trailer) splits satisfy the (mod 46)
# == 35 constraint; the universal common trailer is only 36B), and slots
# carry no cross-record locked columns (consistent with all-varying per-SV
# fields). So the format is recognized and the stride is exposed, but
# body_slots stay raw.
#
# Header bytes [4], [6] and [7] are not invariant across firmware builds
# (byte distribution over all 15,351 v=0x08 records / 65 v=0x08-only
# captures):
#     byte[4]: 0x00 81% (also 0x01/0x02/0x0a/0x0b/0x04 …)
#     byte[6]: 0x10 90% / 0x00 9%
#     byte[7]: 0x00 66% / 0x12 20% / 0x10 12% (size_flag bitfield)
# Anchoring any of them would reject every build where it differs. The
# invariant header region across all 15,351 records is byte[8:15]==0 (bytes
# 8..14; byte[15] takes 0x00 98% / 0x03 2% — a reserved-region flag, exposed
# raw, not asserted). The gate is therefore len%46==35 AND data[8:15]==0,
# which holds on 15351/15351 corpus records.
_NAVDB147D_V08_VERSION = 0x08
_NAVDB147D_V08_SIZE_MOD = 35   # len(data) % 46 on every observed v=0x08 record
# Reserved region zero across all 15,351 corpus v=0x08 records. byte[15] is
# not included — it takes 0x00/0x03 (a reserved-region flag), so anchoring
# [8:16] would wrongly reject 361 records.
_NAVDB147D_V08_RESERVED = slice(8, 15)
# v=0x07: Inseego M3100 (SDX65), 925 records / 7 sessions, 2149..3253 B — the
# same 46B-stride variable form as v=0x08 with a 2-byte-shorter header:
# len % 46 == 33 on 925/925 and the reserved [8:15] (in fact [8:16]) zero on
# 925/925. Same recognizer, own residue.
# Identity grounded as the per-fix position report: f64 lat/lon at [51:67] are
# bit-exact equal to a co-emitted 0x1476 v0x15 (lat@49, lon@57) on 913/925
# records (8-byte-shifted null 0/925). F3 corroborates the cadence (189
# records vs 194 lm_mgp.c:2889 "Received FIX REPORT from MGP" prints; 856/925
# within 300 ms of a 0x1477 v0 epoch), but a per-record F3 time lock is not
# measurable: that capture's plaintext F3 timestamps are not a usable clock.
# The lat/lon are not yet exposed as fields on v=0x07 (body stays raw).
_NAVDB147D_VAR_SIZE_MOD = {0x07: 33, _NAVDB147D_V08_VERSION: _NAVDB147D_V08_SIZE_MOD}
_NAVDB147D_VAR_SIZE_CLASS = {0x07: "sdx65_v07_var", _NAVDB147D_V08_VERSION: "sdx62_v08_var"}


# --- v=0x04 (MC7455 / EM7455, MDM9x30) --------------------------------------
# On the MC7455 (MDM9x30) this log is the v=0x04 / 3185B variant. The header is
# decoded structurally; the body carries the KF nav solution
# (lat/lon/alt/velocity) but the 46B slot table does not tile cleanly for
# 3185B, so the position payload is exposed raw. The SDX55-only slot_0_* f32
# fields are None on this form. scope_id is the low 24 bits of the ms FCount
# (fcount_ms).

# The header time fields are F3-grounded on v=0x04 only; the other
# versions sharing this header layout leave them None.
_NAVDB147D_TIME_FIELDS_VERSION = 0x04

# v=0x00 / 1957B, Sierra MC7700 (SWI9200X platform; two units on two firmware
# builds, 734 records / 5 captures). Its header is not the v=0x04+ header: the
# GPS time sits 6 bytes earlier ([10:16], not [16:22]) and a GLONASS time
# block fills [16:23]. Grounded field-by-field, per record, on a 4-stream
# GNSS-compare session (301 records, 1 Hz, ~301 s):
#   No F3 is available: all five captures are DLF (log items only — no 0x79 /
#   0x99 / 0x60 plane survives the HDLC->DLF conversion) and no raw MC7700
#   HDLC capture carrying 0x147D exists. The grounding uses the firmware's
#   other self-labels for the same fix plus one fully independent receiver:
#   * 0x1476 POSITION REPORT (co-emitted, joined on f_count): [1:5] f_count,
#     [10:12] gps_week, [12:16] gps_tow_ms, [27:35] lat_rad f64, [35:43]
#     lon_rad f64, [43:47] alt_m f32, [88:100] vel_sigma_e/n/u f32 — all
#     bit-exact 734/734 over the whole v=0x00 corpus (vel_sigma 733/734). And
#     the 7-byte [16:23] block recurs bit-exact in the joined 0x1476 797B
#     record at offset 25, 301/301 (0x1476's glo_four_year/glo_days/glo_tow_ms
#     triple on its 291B path).
#   * 0x1477 GPS MEASUREMENT REPORT (joined on f_count): (gps_week,
#     gps_milliseconds) == ([10:12], [12:16]) 299/301 exact, the other two off
#     by 1 ms (fix rounding); the same join shifted by one record: 0/300.
#   * Modem NMEA ($GPGGA, 6-dp minutes): exact string equality 296/299 at
#     UTC = round(gps_sec) - 18 s, vs ~171 at +/-1 s (the receiver is static,
#     so neighbours partly collide) — timing is pinned, not just position.
#     [43:47] == GGA MSL-alt + geoid-sep (i.e. HAE) within 0.05 m 299/299.
#   * AT!GPSLOC? (firmware's own 180/2^25-deg units): round(lat/lon deg *
#     2^25/180) == the AT hex 299/299. Not time-discriminating (one distinct
#     value over 300 polls) — it grounds the encoding, not the epoch.
#   * LG290P (gpsd TPV, independent receiver): 301/301 join at GPS week
#     [10:12]+1024 / msec [12:16] / 18 s leap; horizontal separation p50
#     0.94 m, max 1.75 m.
# WEEK ROLLOVER: [10:12] reads 1397, not 2421 — this firmware is one 1024-
# week rollover behind (a known bug in this firmware family). The firmware
# says so itself: AT!GPSLOC? "Time: 2006 10 17" and $GPRMC date 171006 are
# week 1397. Yet the msec-of-week + 18 s leap map exactly onto real UTC.
# gps_week is emitted RAW (as the firmware computed it, the same value 0x1476
# emits); consumers needing a calendar date add 1024 on this build family.
# GLONASS TIME [16:23]: gps_msec - glo_tow_ms is constant within each capture
# and on all five lands exactly on the most recent 21:00:18 GPS = 21:00:00
# UTC = 00:00 UTC+3, i.e. glo_tow_ms == msec since GLONASS midnight: GLONASS
# system time (UTC(SU)+3h), 734/734. [17:19] N_T =
# 1020/1021/1022 == 2006-10-16/17/18 (the rolled-back GLONASS date, counted
# from 2004-01-01) and [16] N4 = 3 (2004-2007 is the 3rd interval since 1996)
# — both track each capture's date exactly.
# CANDIDATE (raw, not named — no oracle labels which solution each is):
# [100:116] a second lat/lon f64 pair (~4.4 m p50 from the fix — another
# solution, e.g. pre-KF/WLS); [196:220] ECEF X/Y/Z f64 (~8-10 m from both);
# [404:428] lat/lon/alt f64 (== the fix lat/lon 733/734) with its own ECEF at
# [500:524] (0.3 mm from that LLA). [23:25] u16 +1 per record (a fix sequence
# number — structural only). [5:7] is 0x3001 in steady state (0x2002/0x1001
# on session-start records) and [8:10] is 0 on 733/734 — neither is gated.
_NAVDB147D_V00_VERSION = 0x00
_NAVDB147D_V00_SIZE = 1957

# v=0x06 identity (F3-grounded) on an RM500Q-AE (SDX55) GNSS-comparison
# capture — a stationary splitter-fed fix session (~305 s @ 1 Hz). The 0x79
# plaintext F3 plane (236,234 records) carries the Position Engine's own
# per-fix pipeline prints:
#   * lm_mgp.c:2415 "Received FIX REPORT from MGP, Best Position=…" — 305 emits
#   * lm_mgp.c:368  "=LM TASK= Fix Report received, PositionFlags…"    — 305 emits
#   * nf_navsolution.c:1485/1491/1494 KF nav-solution prints            — 915 = 3×305
#     ("NF: WLS to KF distance", "NF: KF uncertainty [HEPE2,AltUnc2]") — the
#     Kalman filter ("KF" in the log name) runs once per fix epoch.
# The 305 v=0x06/4717B records match the 305 lm_mgp FIX-REPORTs 1:1 — count-exact
# and temporally locked: over the same 304.8 s window every 0x147D record pairs to
# a FIX-REPORT at a constant ~2.49 M-tick (~47.5 ms @ 52 MHz DIAG clock) phase
# offset (p50 2,489,305; p95 2,540,381; range well below the ~52 M-tick fix
# interval), i.e. a fixed pipeline latency, not coincidental co-occurrence.
# Scope: F3 grounds the identity and cadence only. The slot-0 f32 fields
# (slot_0_sdx55_f32_at_16 ≈ [-16,-8); _at_32 ≈ [8,16)) live in the per-SV
# body and are not named by F3 — nf_navsolution prints only the scalar KF
# uncertainties (HEPE2≈85, AltUnc2=6), which do not match those f32 ranges.
# Body fields stay raw. The 0x60 DIAG_EVENT_REPORT_F plane is present (514
# frames) but its GNSS-event content was not classified and is not relied upon.
#
# v=0x08 identity (F3-grounded) on a Quectel RM520N-GL (SDX62) 1 Hz fix
# capture: 163 v=0x08 records, 61,392 × 0x79 plaintext F3. The 0x79 plane
# carries the Position Engine's own per-fix pipeline prints, count-exact 1:1
# with the 163 v=0x08 records:
#   * lm_mgp.c:2995 "Received FIX REPORT from MGP, Best Position = …" — 163
#   * lm_mgp.c:841  "=LM TASK= Fix Report received, PositionFlags: IsBest…" — 163
#   * lm_mgp.c:3022 "Received FIX REPORT from MGP (BestAvailPos=…)"        — 163
#   * nf_navsolution.c:2515 "NF: DetectErrorState [WlsValid,KfValid]"      — 163
#   * nf_navsolution.c:7428/7437/7447/7455 "NF: Clock Adj" (per-fix KF)    — 163 ea.
# The records are also temporally locked: every v=0x08 record pairs to a FIX
# REPORT at a constant ~3.19 M-tick (~60.9 ms @ 52.4288 MHz DIAG clock) phase
# offset (signed median 3,191,390 ≈ mean 3,182,169; p95 62.1 ms; max 62.8 ms — all
# far below the 1.00 s / 52,439,154-tick fix interval). So v=0x08 is the per-fix
# PE KF position report, the same as v=0x06, across both the SDX55 and SDX62
# generations. The variable length follows from the per-fix identity: each
# record carries the N SVs used for that fix (N=16..95), so length = 16B pkt hdr +
# 19B body-header record + N×46B per-SV slots (every one of 68 corpus sizes ≡ 35
# mod 46; adjacent sizes differ by exactly one 46B slot). The SDX62 FIX-REPORT
# prints sit at lm_mgp.c:2995/841/3022 vs the SDX55 build's 2415/368 — the same
# site with cross-build line-number drift. The 0x60 plane was not armed on this
# capture; 0x79 is dispositive. Body per-SV slots stay raw (F3 grounds identity
# + cadence, not the per-SV fields).
# Corroborating (not a clean 1:1): a second SDX6x device, a Casa CFW3212 /
# RG520N-NA capture, shows 223 v=0x08 records against ~215 lm_mgp fix-pipeline
# prints — same per-fix cadence, but its exact FIX-REPORT site is 0x99
# QShrink4-hashed and no build-matched string database is available, so it is
# not counted as an exact match.
#
# v=0x04 identity and three header fields (F3-grounded, exact integer match) on
# a Sierra EM7455 (MDM9x30, same firmware as the MC7455) all-diag F3 capture:
# 155 v=0x04/3185B records over a 154 s, 1.000 s-interval fix session; 159,714 x
# 0x79 plaintext F3.
#   IDENTITY: the per-fix sites that ground v=0x05 on MDM9607 (lm_mgp.c:228/
#   441/609) sit here at lm_mgp.c:229/442/610 (one-line cross-build drift) and
#   emit 155 each == the record count, as do lm_tm.c:296 "Sending FINAL_FIX
#   report to TM" and nf_navsolution.c:4922 "NF: Clock Adj: FC=%u, To ME GAL
#   ms=[%u], To PE GAL ms=[%u]" (the per-fix KF print). Temporally locked:
#   nf_navsolution.c:4922 follows each record by median +1.22 ms (155/155
#   within +/-5 ms; range -0.02..+2.25 ms); lm_mgp.c:229 "New fix saved as best"
#   by median +118.6 ms (all 155 in [103.9, 129.2] ms) — the same "PE KF report
#   logged, then the LM commits the best fix ~110 ms later" pipeline as v=0x05.
#   FIELDS (exact integer equality vs the nearest nf_navsolution.c:4922 print):
#     [1:5]   u32LE == FC                       155/155  -> fcount_ms
#     [18:22] u32LE == "To ME/PE GAL ms"        155/155  -> gps_msec
#     [16:18] u16LE == mc_clock.c:3570 "Wk"     155/155  -> gps_week
#   and [18:22] == mc_clock.c:3570 "Ms" 154/155 (the one miss is a -1000 ms
#   nearest-neighbour slip). Record-to-record delta (fcount_ms, gps_msec) ==
#   (+1000, +1000) on 154/154. Whole v=0x04 corpus (1,203 records / 7 captures,
#   MC7455 + EM7455): parse 1203/1203; gps_msec repeat [18:22]==[37:41]
#   1203/1203; gps_msec in [0, 604800000) 1203/1203; the decoded GPS week
#   (2414, 2417, 2422) matches the capture date on 7/7 captures; gps_msec and
#   fcount_ms advance in lockstep (equal deltas even on 688/820/987 ms gaps;
#   the offset re-anchors only across a warm restart / small clock
#   re-estimation steps).
#   This explains three header patterns: [4] is the FCount MSB, not a
#   constant (0x10 on 155/155 EM7455 records); byte [16] (0x6e/0x71/0x76/0x80)
#   and [17]=0x09 are the GPS week bytes (they track capture date, not
#   silicon); and [18:22]==[37:41] is the fix time stored twice. Not grounded:
#   the position / velocity / HEPE payload — Sierra's gpstask.c prints lat/lon
#   as whole degrees (too coarse to match) and lm_mgp's hepe matched no f32/f64
#   body offset. The 0x60 plane was not armed (outer opcodes are 0x10/0x79/0x92
#   only). QCSuper and SCAT do not decode 0x147D (not in their tables).

@register(
    0x147D, domain="gnss",
    name="0x147D",
    description="GNSS nav DB 147D — companion to 0x147C, size-variant",
    version=16,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Decodes the per-fix GNSS Position Engine Kalman-filter position "
        "report (canonical log name LOG_GNSS_PE_KF_POSITION_REPORT_C) across six "
        "record forms: v=0x00/1957B (Sierra MC7700), v=0x04/3185B (MC7455/EM7455, "
        "MDM9x30), v=0x05/3665B (MDM9x07, SDX20, MDM9650, MDM9607), v=0x06/4717B "
        "(SDX55), and the variable 46-byte-stride v=0x07 (SDX65, len%46==33) and "
        "v=0x08 (SDX55/SDX62, len%46==35) forms. Identity is grounded against the "
        "firmware's own F3 debug prints on v=0x04 (EM7455), v=0x05 (EG25-G), "
        "v=0x06 (RM500Q-AE) and v=0x08 (RM520N-GL): records co-emit 1:1 with the "
        "per-fix lm_mgp.c FIX-REPORT and nf_navsolution.c KF prints at a constant "
        "pipeline-latency phase. On v=0x04, fcount_ms, gps_week and gps_msec equal "
        "the F3-printed FCount, GPS week and msec-of-week on 155/155 records and "
        "are consistent across the whole 1,203-record v=0x04 corpus. v=0x00 has its "
        "own header layout; its fix time, GLONASS time, lat/lon/alt and velocity "
        "sigmas are bit-exact against the co-emitted 0x1476 report on 734/734 "
        "records and agree with the modem's NMEA and AT!GPSLOC? output and an "
        "independent LG290P receiver (p50 0.94 m); its gps_week is emitted raw, "
        "one 1024-week rollover behind. v=0x07 is grounded by bit-exact lat/lon "
        "against a co-emitted 0x1476 (913/925 records). Header structure "
        "(scope_id, the header-state word marker_bytes_5_7 — it varies with "
        "session state and is not a constant 0x1091 — the size_flag "
        "bitfield, reserved-zero bytes) and the SDX55 slot-0 markers and f32 "
        "values come from per-byte variance and corpus-wide byte distributions; "
        "the v=0x08 gate (len%46==35, data[8:15]==0) holds on all 15,351 corpus "
        "records. Known gaps: the per-SV body slots stay raw on every form, the "
        "position/velocity/HEPE payload is not decoded on v=0x04 through v=0x08, "
        "and the time fields are F3-grounded only on v=0x04. QCSuper and SCAT do "
        "not decode 0x147D."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    # 15 named header/metadata fields + 4 slot-0 f32 decodes on SDX55 +
    # marker_bytes_5_7. Body still opaque at per-field level for slots 1-N.
    # + fcount_ms / gps_week / gps_msec (F3-grounded, v=0x04; also v=0x00).
    # + lat_rad / lon_rad / alt_m / vel_sigma_e/n/u / glo_four_year /
    # glo_days / glo_tow_ms (v=0x00 only; 0x1476 bit-exact + NMEA/AT/LG290P).
    fields_parsed=32,
    fields_identified=33,
    field_invariants={
        # payload_size is not a global invariant — it is version-conditional
        # (fixed 1957/3185/3665/4717 for v0/v4/v5/v6, variable in 46B steps
        # for v7/v8). As for other variable-size codes, the size relationship
        # is enforced in the parser body (exact-size gates for the fixed
        # forms; the (len % 46) residue + reserved-zero gate for v7/v8) rather
        # than via an exploding/incorrect payload_size enum here.
        "version": {"enum": [0x00, 0x04, 0x05, 0x06, 0x07, 0x08]},
    },
)
def parse_0x147d(log_time: int, data: bytes) -> Diag0x147D | None:
    if len(data) < 16:
        return None
    # Gate on byte 0 (version) before reading scope_id at bytes [1:4], so an
    # unknown layout is rejected instead of silently mis-parsed. The version
    # is locked to the size class: 0x05 on 3665B (mdm9x07/sdx20) and 0x06 on
    # 4717B (sdx55). Reject anything outside the observed (size, version)
    # pairs.
    sz = len(data)
    version = data[0]
    # Explicit Layer-1 version gate. The joint (size, version) constraint
    # below is the tighter invariant; this looser `data[0] not in {…}` form
    # keeps the accepted version set visible in one place.
    if data[0] not in (0x00, 0x04, 0x05, 0x06, 0x07, 0x08):
        return None
    # v=0x00 is the MC7700 1957B form with its own header layout (GPS time at
    # [10:16], GLONASS time at [16:23]) — its own path, gated on its exact
    # size.
    if version == _NAVDB147D_V00_VERSION:
        return _parse_0x147d_v00(log_time, data)
    # v=0x07 / v=0x08 are the variable-size 46B-stride forms (SDX65 /
    # SDX55-SDX62). They do not participate in the fixed-size joint gate
    # below; they are recognized by the per-version (len % 46) residue (33 /
    # 35) + the reserved-zero header region. A record failing either rejects
    # (None) rather than mis-decoding through the fixed-size path.
    if version in _NAVDB147D_VAR_SIZE_MOD:
        return _parse_0x147d_v08(log_time, data)
    # v=0x04 ↔ 3185B is the MC7455 (MDM9x30) form. Header + body record tags
    # match the v=0x05/0x06 format ([0]=0x04, [4]=0x00 on MC7455, [5:7]
    # header-state word, [7]=0x00, and body tags [17]=0x09/[22]=0x08/
    # [24]=0x03/[30]=0x04 with the 19B-rec[+2:6] == 6B-tail[+2:6] bipartite
    # invariant intact).
    if not (
        (sz == 3185 and version == 0x04)
        or (sz == 3665 and version == 0x05)
        or (sz == 4717 and version == 0x06)
    ):
        return None
    scope_id = data[1] | (data[2] << 8) | (data[3] << 16)
    # F3-grounded on v=0x04 only (see the v=0x04 module note).
    fcount_ms: int | None = None
    gps_week: int | None = None
    gps_msec: int | None = None
    if version == _NAVDB147D_TIME_FIELDS_VERSION:
        fcount_ms = unpack_from('<I', data, 1)[0]
        gps_week = unpack_from('<H', data, 16)[0]
        gps_msec = unpack_from('<I', data, 18)[0]
    marker_bytes_5_7 = unpack_from('<H', data, 5)[0]
    sig_1091_ok = marker_bytes_5_7 == _NAVDB147D_SIG_1091
    size_class = _147d_size_class(len(data))

    body_slot_table_start: int | None = None
    body_slot_stride: int | None = None
    body_slots: list[bytes] | None = None
    slot_0_sdx55_format_ok: bool | None = None
    slot_c_sdx55_format_count: int | None = None
    slot_0_sdx55_f32_at_0: float | None = None
    slot_0_sdx55_f32_at_8: float | None = None
    slot_0_sdx55_f32_at_16: float | None = None
    slot_0_sdx55_f32_at_32: float | None = None
    if size_class in ('mc7455_3185', 'mdm9x07_3665', 'sdx55_4717'):
        body_slot_table_start = _NAVDB147D_SLOT_TABLE_START
        body_slot_stride = _NAVDB147D_SLOT_STRIDE
        body_slots = []
        off = _NAVDB147D_SLOT_TABLE_START
        while off + _NAVDB147D_SLOT_STRIDE <= len(data):
            body_slots.append(bytes(data[off:off + _NAVDB147D_SLOT_STRIDE]))
            off += _NAVDB147D_SLOT_STRIDE

    # SDX55-only slot-format validators. MDM9x07 slots do not share these
    # constants (see docstring); leave as None to signal "not applicable".
    if size_class == 'sdx55_4717' and body_slots is not None:
        slot0 = body_slots[0]
        slot_0_sdx55_format_ok = all(
            slot0[o] == v for o, v in _NAVDB147D_SDX55_SLOT0_CONSTS.items()
        )
        slot_c_sdx55_format_count = sum(
            1 for si in _NAVDB147D_SDX55_SLOTC_INDICES
            if si < len(body_slots) and all(
                body_slots[si][o] == v for o, v in _NAVDB147D_SDX55_SLOTC_CONSTS.items()
            )
        )
        # 4 marker-backed slot-0 f32 decodes
        slot_0_sdx55_f32_at_0  = unpack_from('<f', slot0, 0)[0]
        slot_0_sdx55_f32_at_8  = unpack_from('<f', slot0, 8)[0]
        slot_0_sdx55_f32_at_16 = unpack_from('<f', slot0, 16)[0]
        slot_0_sdx55_f32_at_32 = unpack_from('<f', slot0, 32)[0]

    return Diag0x147D(
        log_time=log_time,
        version=data[0],
        scope_id=scope_id,
        marker_bytes_5_7=marker_bytes_5_7,
        sig_1091_ok=sig_1091_ok,
        size_flag=data[7],
        size_class=size_class,
        payload_size=len(data),
        body_raw=bytes(data[16:]),
        body_slot_table_start=body_slot_table_start,
        body_slot_stride=body_slot_stride,
        body_slots=body_slots,
        slot_0_sdx55_format_ok=slot_0_sdx55_format_ok,
        slot_c_sdx55_format_count=slot_c_sdx55_format_count,
        slot_0_sdx55_f32_at_0=slot_0_sdx55_f32_at_0,
        slot_0_sdx55_f32_at_8=slot_0_sdx55_f32_at_8,
        slot_0_sdx55_f32_at_16=slot_0_sdx55_f32_at_16,
        slot_0_sdx55_f32_at_32=slot_0_sdx55_f32_at_32,
        # Compatibility fields — existing consumers rely on these.
        counter_hi=data[1],
        counter_lo=data[2],
        sub_counter=data[5],
        fcount_ms=fcount_ms,
        gps_week=gps_week,
        gps_msec=gps_msec,
    )


def _parse_0x147d_v08(log_time: int, data: bytes) -> Diag0x147D | None:
    """v=0x07 / v=0x08 variable-size 46B-stride form.

    Structural recognition (see the module constants for the corpus
    evidence). Gate: ``len(data) % 46`` equals the per-version residue (35 for
    v=0x08, 33 for v=0x07) plus the corpus-attested reserved region
    ``data[8:15] == 0`` (bytes 8..14 zero on all 15,351 corpus v=0x08 records).
    A record failing either is rejected so a format drift surfaces as a
    no-parse miss instead of a plausible-but-garbage decode. Header bytes [4],
    [6] and [7] vary across firmware builds and are not anchored.

    The 46B slot stride is exposed (confirmed by within-record autocorrelation
    + the exact 46B size quantum), but ``body_slots`` stays raw: the absolute
    slot-table start is not uniquely determinable from size arithmetic alone
    and slots carry no cross-record locked columns. Per-slot decode is not
    implemented.
    """
    if len(data) % _NAVDB147D_SLOT_STRIDE != _NAVDB147D_VAR_SIZE_MOD[data[0]]:
        return None
    if any(b != 0 for b in data[_NAVDB147D_V08_RESERVED]):
        return None
    scope_id = data[1] | (data[2] << 8) | (data[3] << 16)
    marker_bytes_5_7 = unpack_from('<H', data, 5)[0]
    return Diag0x147D(
        log_time=log_time,
        version=data[0],
        scope_id=scope_id,
        marker_bytes_5_7=marker_bytes_5_7,
        sig_1091_ok=marker_bytes_5_7 == _NAVDB147D_SIG_1091,
        size_flag=data[7],
        size_class=_NAVDB147D_VAR_SIZE_CLASS[data[0]],
        payload_size=len(data),
        body_raw=bytes(data[16:]),
        # Stride confirmed; absolute table start + per-slot decode deferred.
        body_slot_table_start=None,
        body_slot_stride=_NAVDB147D_SLOT_STRIDE,
        body_slots=None,
        # SDX55 fixed-size slot validators do not apply to the variable form.
        slot_0_sdx55_format_ok=None,
        slot_c_sdx55_format_count=None,
        slot_0_sdx55_f32_at_0=None,
        slot_0_sdx55_f32_at_8=None,
        slot_0_sdx55_f32_at_16=None,
        slot_0_sdx55_f32_at_32=None,
        # Compatibility fields — existing consumers rely on these.
        counter_hi=data[1],
        counter_lo=data[2],
        sub_counter=data[5],
    )


def _parse_0x147d_v00(log_time: int, data: bytes) -> Diag0x147D | None:
    """v=0x00 / 1957B Sierra MC7700 (SWI9200X) form.

    Header layout differs from v=0x04+: GPS week/msec at [10:12]/[12:16] and a
    GLONASS time block at [16:23]. Every named field is grounded bit-exact
    against the co-emitted 0x1476 position report (and the modem's NMEA / AT /
    an LG290P) — see the module v=0x00 note. Gated on the exact size only:
    [5:7] and [8:10] take other values on session-start records, so anchoring
    them would drop legitimate traffic. ``gps_week`` is RAW — on this firmware
    family it is one 1024-week rollover behind.
    """
    if len(data) != _NAVDB147D_V00_SIZE:
        return None
    scope_id = data[1] | (data[2] << 8) | (data[3] << 16)
    marker_bytes_5_7 = unpack_from('<H', data, 5)[0]
    lat_rad, lon_rad = unpack_from('<2d', data, 27)
    return Diag0x147D(
        log_time=log_time,
        version=data[0],
        scope_id=scope_id,
        marker_bytes_5_7=marker_bytes_5_7,
        sig_1091_ok=marker_bytes_5_7 == _NAVDB147D_SIG_1091,
        size_flag=data[7],
        size_class="mc7700_1957",
        payload_size=len(data),
        body_raw=bytes(data[16:]),
        # No slot table identified on the 1957B form.
        body_slot_table_start=None,
        body_slot_stride=None,
        body_slots=None,
        slot_0_sdx55_format_ok=None,
        slot_c_sdx55_format_count=None,
        slot_0_sdx55_f32_at_0=None,
        slot_0_sdx55_f32_at_8=None,
        slot_0_sdx55_f32_at_16=None,
        slot_0_sdx55_f32_at_32=None,
        # Compatibility fields — existing consumers rely on these.
        counter_hi=data[1],
        counter_lo=data[2],
        sub_counter=data[5],
        fcount_ms=unpack_from('<I', data, 1)[0],
        gps_week=unpack_from('<H', data, 10)[0],
        gps_msec=unpack_from('<I', data, 12)[0],
        lat_rad=lat_rad,
        lon_rad=lon_rad,
        alt_m=unpack_from('<f', data, 43)[0],
        vel_sigma_e=unpack_from('<f', data, 88)[0],
        vel_sigma_n=unpack_from('<f', data, 92)[0],
        vel_sigma_u=unpack_from('<f', data, 96)[0],
        glo_four_year=data[16],
        glo_days=unpack_from('<H', data, 17)[0],
        glo_tow_ms=unpack_from('<I', data, 19)[0],
    )
