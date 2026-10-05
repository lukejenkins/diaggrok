"""LOG_GNSS_CD_DB_REPORT (0x147B) parser.

Companion log codes 0x1477 (LOG_GNSS_GPS_MEASUREMENT_REPORT) and 0x1478
(LOG_GNSS_CLOCK_REPORT) are decoded in ``diag_0x1477.py`` and
``diag_0x1478.py`` respectively.

0x147B is the GNSS clock/cell-database report, not an SV-health log; an
external MIT-licensed reference also enumerates it as
LOG_GNSS_CD_DB_REPORT. The backward-compat alias ``GpsSvHealth`` is kept
in diaggpsd's ``gnss_packets`` module.

Log name: LOG_GNSS_CD_DB_REPORT_C
Also known as: LOG_GNSS_CD_DATABASE_REPORT
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_GNSS_CD_DB_REPORT
from diaggrok.registry import register


@dataclass
class Diag0x147B:
    """LOG_GNSS_CD_DB_REPORT (0x147B).

    GNSS clock-database / cell-database report emitted at 1 Hz with
    per-SV health and nav-message data. The 11-byte header was decoded
    against EG18-NA and FN980m captures; the body region is preserved as
    ``raw``.

    ## Header layout — two layouts (version-dependent)

    **Legacy layout (v0/8/9/11/14/18, 11-byte header; F3-grounded on v8, v11,
    v14 and v18; externally grounded on v0 and v9):**

        byte 0:     u8   version        (11 on SDX20 V2, 18 on SDX55)
        byte 1..4:  u32  f_count        frame counter
        byte 5..6:  u16  gps_week       matches the capture's GPS week
        byte 7..10: u32  gps_ms         GPS time of week in ms

    v18 (SDX55 RM500Q-AE) F3 ground truth: f_count == cd_task.c:18224
    "CD: Received consolidated NF report [Fcount=..]" (315/315), gps_week/gps_ms
    == cd_utils.c:6334 "PE: Deliver PQWP.. [GpsWk .. GpsMs ..]" exact.

    v11 (0x0b, 535 B) F3 ground truth, the same Cell-DB sites on four
    chipsets (line numbers are per-build):

    | capture                              | recs | f_count == CD "Fcount=" | (wk,ms) same F3 line |
    |--------------------------------------|-----:|------------------------:|---------------------:|
    | EG25-G MDM9207 (0x79 text)           |   58 | 58/58 cd_task.c:7248    | 58/58                |
    | EG18-NA SDX20 (0x99, string DB)      |   14 | 14/14 cd_task.c:8611    | 14/14                |
    | LM960 SDX20                          |  396 | 396/396 cd_task.c:8611  | 394/396 cd_utils:5290|
    | MDM9250 C-V2X                        | 1447 | 1447/1447 cd_task:8877  | (fc,ms) 1447/1447    |

    A v11 record is emitted on two triggers, and its (f_count, gps_ms) is the
    trigger's own timestamp: (a) a nav-filter fix epoch — (wk,ms) == cd_utils
    "PE: Deliver PQWP4 at [GpsWk .., GpsMs ..]" and == the ``0x60``
    EVENT_GNSS_TLE_TIME_UPDATE_C payload (u16 wk@9, u32 ms@11; 30/30 on EG25-G);
    (b) a slow-clock time update — all three fields on one line in mgp_pe_api
    "PE: Slow Clock Time: Wk=.., Ms=.., FCnt=.." (28/28 EG25-G, 1310/1447
    MDM9250). The interleave is why EG25-G shows a bimodal 617/383 ms cadence
    rather than a clean 1 Hz. f_count is a millisecond-rate receiver counter
    (its delta tracks the gps_ms delta to within a few ms). Corpus-wide all
    275,170 v11 records (257 captures) read a current-era gps_week (hi byte
    0x09) or the 0xFFFF no-fix sentinel — no mis-offset garbage.

    v8 (0x08, 445 B, MDM9x30 Sierra MC7455/EM7455) F3 ground truth, 0x79
    plaintext on an EM7455 all-diag capture: (gps_week, gps_ms) sit on one F3
    line for 315/315 records. Like v11, a v8 record fires on two triggers —
    fix-epoch records (160) == mc_gnssmeasreport.c:3197 "Gps_MeasBlk(0) - N
    SVs, FC .., Wk .., Ms .." (all three header fields on one line, 159/160)
    and nf_navsolution.c:4922 "NF: Clock Adj: FC=.., To ME GAL ms=[..]";
    slow-clock records (155) == mc_slow_clk.c:2544 "Slow Clk releasing Time
    Update: .. GpsRtc .. GpsWk .. GpsMs ..". f_count is the MeasBlk/NF-domain
    frame counter: the same epoch prints FC 282930001 in Gps_MeasBlk and FC
    276818000 in mc_tick, and slow-clock records carry f_count == GpsRtc +
    6112002 (±1, 155/155) — the same domain offset. That is why v8 f_count !=
    the co-captured 0x1478 f_count (0x1478 reports the mc_tick domain).
    Cross-capture (no F3): MC7455 decoded UTC hits 298/298 LG290P
    reference-receiver seconds.

    v9 (0x09, 503 B, MDM9x07 Quectel EP06A / EG95-NA) — no F3 and no 0x60 in
    any of the 13 bearing captures; grounded on external truth: decoded UTC
    (gps_to_utc, 18 s leap) hits 296/296 LG290P reference-receiver TPV
    seconds and 296/296 of the modem's own NMEA RMC seconds (EP06A), 305/305
    AT+QGPSLOC seconds (a second EP06A capture) and 290/290 (EG95-NA);
    gps_week is the date-correct week on all 4752 fix records (2414 / 2416 /
    2417); (wk,ms) == the co-captured 0x1478 v0x02 on the fix-epoch class
    (2978/4752 — the other class is slow-clock-style, as on v8/v11). No-fix
    records read 0xFFFF with an all-zero header (89 recs). f_count here is a
    STRUCTURAL TRANSFER (a ms-rate counter: Δf_count == Δgps_ms on the
    dominant class) — no independent reference for it on v9.

    v0 (0x00, 183 B, Sierra MC7700, MDM9600) — no F3 and no 0x60 in any of
    the 5 bearing captures (all DLF); grounded on external truth. gps_week
    reads the 10-bit-rolled GPS week: 1397 = 2421 - 1024, where 2421 is the
    real week at capture time. Four surfaces of the same receiver agree on
    the rollover — this field, the co-captured 0x1478 v0x00, AT!GPSLOC
    ("Time: 2006 10 17 .. (GPS)") and the NMEA RMC date (2006, exactly
    +619,315,200 s = 1024 weeks). With +1024 weeks and the 18 s leap, decoded
    UTC hits 299/299 AT!GPSLOC GPS-time seconds (second run) and 298/299 NMEA
    RMC seconds (first run, span edges within 0.3 s). ts64 slope vs decoded
    time is 52428.8 (the DIAG tick rate) on both comparison runs. f_count is
    a STRUCTURAL TRANSFER only (it neither equals 0x1478 v0x00's f_count nor
    tracks gps_ms record-to-record). Consumers doing absolute-time math must
    add 1024 weeks.

    **Shifted layout (v21/23/24, 13-byte header):** the newer silicon
    inserts a 2-byte u16 at [1:3], shifting the frame counter and GPS
    timestamp by +2.

    SDX65 v21: Inseego M3100 (SDX65) v=21 (0x15), 2248 B, uses the same
    +2-shifted header as v23/v24 — f_count u32@3, gps_week u16@7, gps_ms
    u32@9 ([1:3] is a u16, 1 on 89/90 records, 6 on one). The legacy offsets
    read gps_week 2/3/96/97 (garbage). No F3 and no 0x60 in either bearing
    capture; grounded on (gps_week, gps_ms) == the co-captured 0x1478 v0x04
    exactly on 90/90 records, gps_week 2428 correct for the capture date,
    and gps_ms 64506573 (Sunday 17:54:48 UTC) matching the capture's own
    start-time stamp. f_count is a ms-rate counter (Δf_count == Δgps_ms,
    88/88) at a capture-constant offset to 0x1478's — a STRUCTURAL TRANSFER.

    SDX62 v23 (F3-grounded): the SDX62 (Quectel RM520N-GL) v=23 record:

        byte 0:     u8   version        (23 = 0x17)
        byte 1..2:  u16  usually 1      not constant: over 55,006 v23
                                        records it reads 1 (53,226),
                                        6 (1,436), 7 (338), 0xa0 (6) — the
                                        same value set v21/v24 show.
                                        Kept raw (CANDIDATE: a report-reason enum)
        byte 3..6:  u32  f_count        frame counter (clean +N/record monotonic)
        byte 7..8:  u16  gps_week       2427 on a real fix / 0xFFFF no-fix sentinel
        byte 9..12: u32  gps_ms         GPS time of week in ms

    v23 F3 ground truth (RM520N-GL, real-fix capture): gps_week=2427
    (39/39), (gps_week,gps_ms) exact in cd_utils.c:6555 "PE: Deliver PQWP..
    [GpsWk .. GpsMs ..]" Cell-DB prints (32/39 co-temporal), f_count exact
    in ale_proc.c:8674 "NF: PFR .. (FC=..)" (34/39). A no-fix RM520N-GL
    capture reads gps_week@7 == 0xFFFF uniformly (80/80).

    SDX72 v24 (F3-grounded): the SDX72 (Foxconn T99W640) v=24 record has the
    same +2-shifted header as v21/v23:

        byte 0:     u8   version        (24 = 0x18)
        byte 1..2:  u16  usually 1      not a constant marker: 0x0007 (3 recs)
                                        and 0x00a0 (6 all-zero cold-clear recs)
                                        also seen across 1514 records
        byte 3..6:  u32  f_count        ME frame counter (== F3 "Fcount")
        byte 7..8:  u16  gps_week       2423 on a fix / 0xFFFF no-fix sentinel
        byte 9..12: u32  gps_ms         GPS time of week; with no fix, the
                                        receiver's free-running msec

    v24 F3 ground truth, all three fields on one line on two firmware
    builds, 439/443 records: fix captures (0x99, string DB)
    tle_ptm_mgr.cpp:381 "Slowclock Update, Fcount:242500, wk:2423,
    msec:61220071" and mc_gnssmeasreport.c:6974 "L1Gps_MBlk(1Hz) .. FC ..,
    Wk .., Ms .." (63/63), plus the Cell-DB cd_task.c:14388 "CD: Handle
    consolidated NF report [Fcount=..]"; no-fix captures on the other build
    mc_gnssmeasreport.c:6974 "L1Gps_MBlk(1Hz) - 0 SVs,FC 12500,Wk 65535,Ms
    12484" (376/380). (gps_week, gps_ms, f_count) also == the co-captured
    0x1478 v0x05 on the same record 63/63. Reading f_count as u32@1 instead
    folds the [1:3] u16 in (3007578113 for a true 242500) and matches 0/422
    F3 Fcount prints. Corroboration (not load-bearing): the 0x60 event id
    3204 (listed in an older name table as EVENT_GNSS_ME_MULTIPATH_ENV_IND)
    carries f_count at payload u32@4 on 207/380 no-fix-build records.

    Naively routing v21, v23 or v24 through the legacy offsets yields garbage
    (v21: gps_week=2/3/96/97; v23: gps_week=12513, gps_ms>1 week; v24:
    gps_week=3) — the "same code, new header layout" trap. The parser
    dispatches header offsets on the version byte (see ``_HEADER_OFFSETS``).

    Note: unlike 0x1478, this log code does **not** have a flags u16
    before f_count. The two parsers share the concept of a per-epoch
    header but the layouts differ slightly.

    ## Size and version variants (corpus scan: 60,468 records)

    The version byte at offset 0 is a chipset-generation discriminator,
    not a constant:

    | version (hex) | records | %    | size (B) | chipset(s)                       |
    |--------------:|--------:|-----:|---------:|----------------------------------|
    | 0x0B (11)     | 25,219  | 41.7 | 535      | SDX20 V2 / MDM9x50 / MDM9207     |
    | 0x12 (18)     | 20,102  | 33.2 | 1011     | SDX55 (FN980m, EM9190, RM500Q)   |
    | 0x09 ( 9)     |  6,290  | 10.4 | 503      | MDM9x07 (Quectel EP06A, EG95-NA) |
    | 0x17 (23)     |  5,807  |  9.6 | 2464     | SDX62 (RM520N-GL)                |
    | 0x08 ( 8)     |  3,050  |  5.0 | 445      | MDM9x30 (Sierra MC7455)          |

    Further versions from later captures:

    | version (hex) | records | captures | size (B) | chipset(s)                   |
    |--------------:|--------:|---------:|---------:|------------------------------|
    | 0x00 ( 0)     |  2,183  |    5     | 183      | MDM9600 (Sierra MC7700)      |
    | 0x0E (14)     |    225  |    2     | 844      | SDX24 (Quectel EM160R)       |
    | 0x15 (21)     |     90  |    2     | 2248     | SDX65 (Inseego M3100)        |
    | 0x18 (24)     |  1,579  |   28     | 2472     | SDX72 (Foxconn T99W640)      |

    The version byte is declared as ``{"enum": [0, 8, 9, 11, 14, 18, 21, 23,
    24]}`` in ``field_invariants`` — a chipset-generation discriminator is
    exactly what an enum invariant is for. Invariant checking surfaces
    previously-unseen variants (e.g., a future SDX75 v=25) instead of
    silently passing them through. The 503 B and 2464 B variants are spread
    thin across many small captures and are easy to miss without an
    offset-0 distribution check; the enum invariant surfaces them
    automatically.

    The body (bytes 11..end) contains per-SV health/clock database
    state and is not yet decoded. Body layout is almost certainly different
    per version (the 7-version jump from v=11 to v=18 alone implies a
    significant struct reorganization).
    """
    log_time: int
    version: int
    f_count: int
    gps_week: int
    gps_ms: int
    raw: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x147B',
            'log_time': self.log_time,
            'version': self.version,
            'f_count': self.f_count,
            'gps_week': self.gps_week,
            'gps_ms': self.gps_ms,
            'payload_size': len(self.raw),
        }


# Per-version payload sizes from a 43,632-record corpus walk, extended as new
# versions appear. Size is strictly version-correlated — each
# chipset-generation version byte ships exactly one record length. Used as a
# Layer-1 gate so a (version, len) pair outside this set returns None rather
# than silently mis-parsing a future-firmware layout that reuses a known
# version byte at a new length (size-invariance is not format-invariance).
# Mirrors the _VERSION_TO_SIZE gate in the sibling 0x1478 parser.
_VERSION_TO_SIZE = {0x00: 183, 0x08: 445, 0x09: 503, 0x0b: 535, 0x0e: 844, 0x12: 1011,
                    0x15: 2248, 0x17: 2464, 0x18: 2472}

# Header field offsets are version-dependent. The legacy layout (v0..v18) packs
# f_count(u32)@1, gps_week(u16)@5, gps_ms(u32)@7 — F3-grounded on v18 (SDX55
# RM500Q-AE): f_count/gps_week/gps_ms each match the firmware's own
# Cell-Database F3 prints field-for-field (cd_task.c:18224 "Fcount=" 315/315,
# cd_utils.c:6334 "[GpsWk .. GpsMs ..]" exact) — and on v11 (0x0b) across
# MDM9207 / SDX20 / MDM9x50 builds: f_count == the cd_task "consolidated NF
# report [Fcount=..]" print on 1915/1915 records over 4 captures, (wk,ms) ==
# cd_utils PQWP4 / mgp_pe_api "Slow Clock Time" prints, and (wk,ms) == the
# 0x60 EVENT_GNSS_TLE_TIME_UPDATE_C payload (see class docstring).
#
# The newer silicon (SDX65 v21/0x15, SDX62 v23/0x17 and SDX72 v24/0x18) inserts
# a 2-byte u16 at [1:3] (usually 1), shifting the header by +2 — the
# "same code, new header layout" trap. All three use the same shifted offsets:
#   * v23 (0x17, SDX62 RM520N-GL): f_count = u32@3 (a clean +N/record
#     monotonic counter spanning [3:7]), gps_week@7, gps_ms@9. F3-grounded on
#     an RM520N-GL capture with a real GNSS fix: gps_week=2427 (39/39),
#     (gps_week,gps_ms) exact in the firmware's own cd_utils.c:6555 "PE:
#     Deliver PQWP [GpsWk .. GpsMs ..]" Cell-DB prints (32/39 co-temporal),
#     f_count exact in ale_proc.c:8674 "NF: PFR .. (FC=..)" prints (34/39).
#     Corroborated on a no-fix RM520N-GL capture where gps_week@7 reads the
#     0xFFFF no-fix sentinel uniformly (80/80) — a wrong offset could not
#     produce a clean sentinel. The legacy (1,5,7) offsets applied to v23
#     yield garbage (gps_week=12513, gps_ms=1.1e9 > a week).
#   * v24 (0x18, SDX72 T99W640): the same layout as v23 — f_count = u32@3,
#     gps_week@7, gps_ms@9. f_count must not be read as u32@1: that view
#     folds in the [1:3] u16, which is not constant (1 on 1505/1514 records,
#     0x0007 x3, 0x00a0 x6). u32@3 == the F3 "Fcount" print on 439/443
#     records over two builds (tle_ptm_mgr.cpp:381 "Slowclock Update,
#     Fcount:.., wk:.., msec:.." / mc_gnssmeasreport.c:6974 "L1Gps_MBlk(1Hz)
#     .. FC ..,Wk ..,Ms .."); the u32@1 view matches 0/422.
#   * v21 (0x15, SDX65 Inseego M3100): the v23 layout too — the legacy
#     offsets read gps_week 2/3/96/97; the shifted ones read 2428 on 90/90,
#     == the co-captured 0x1478 v0x04 (gps_week, gps_ms) exactly.
#   * v0 (0x00, MDM9600 Sierra MC7700): the legacy layout. gps_week is the
#     10-bit-rolled week (1397 = real week 2421 - 1024), as the receiver's
#     0x1478 v0x00, AT!GPSLOC and NMEA all show.
#   * v14 (0x0e, SDX24 Quectel EM160R, 844 B): the legacy layout.
#     (f_count, gps_week, gps_ms) @ (1,5,7) == the firmware's own
#     mc_gnssmeasreport.c:4464 "L1 Gps_MeasBlk(0) - .. FC n,Wk w,Ms m" print
#     on 83/83 records over two firmware builds (39/39 and 44/44);
#     nf_navsolution.c:8981 "[Fcount=, GpsMsec=]" 82/83; cd_task.c:10679
#     "consolidated NF report [Fcount=]" 80/83 (3 prints missing from the F3
#     stream). The +2-shifted offsets score 0/83. No fix in either capture:
#     gps_week reads the 0xFFFF sentinel, == the F3 "Wk 65535".
# [1:3] is not a constant marker on any shifted version: it reads 1 / 6 / 7 /
# 0xa0 on v21, v23 and v24 alike (v23: value distribution over 55,006
# records). It is kept raw — an unnamed field (CANDIDATE: a report-reason
# enum).
#   version: (f_count_off, gps_week_off, gps_ms_off)
_HEADER_OFFSETS = {
    0x00: (1, 5, 7), 0x08: (1, 5, 7), 0x09: (1, 5, 7), 0x0b: (1, 5, 7),
    0x0e: (1, 5, 7), 0x12: (1, 5, 7),
    0x15: (3, 7, 9), 0x17: (3, 7, 9), 0x18: (3, 7, 9),
}


# Validation anchor: SIMCom SIM7600NA-H (MDM9207), the v=0x0b / 535B
# emitter ("MDM9207-OCPU" class). The decoded 11-byte header has the same
# GPS-time + frame-counter shape as the sibling 0x1478
# LOG_GNSS_CLOCK_REPORT — gps_week + gps_ms timestamp the clock/database
# snapshot. The SIM7600NA capture carries a valid fix (gps_week=2417,
# gps_ms=146601397), so the GPS-time anchor is directly testable with a sky
# fix.

@register(LOG_GNSS_CD_DB_REPORT, domain="gnss",
    name="0x147B",
    primary_issue=None,
    description="GNSS clock/cell database report; version-dependent header (legacy 11-byte v0/v8..18; +2-shifted 13-byte v21/v23/v24) with f_count+gps_week+gps_ms decoded; body preserved as raw for ongoing RE",
    version=9,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail="The header (version, f_count, gps_week, gps_ms) is decoded on nine chipset-generation versions: a legacy 11-byte header (v0 MDM9600, v8 MDM9x30, v9 MDM9x07, v11 SDX20/MDM9x50/MDM9207, v14 SDX24, v18 SDX55) and a 13-byte header shifted by +2 behind a u16 at [1:3] (v21 SDX65, v23 SDX62, v24 SDX72). On v8, v11, v14, v18, v23 and v24, f_count, gps_week and gps_ms equal the firmware's own Cell-DB and measurement-block F3 prints (cd_task.c 'consolidated NF report [Fcount=..]', cd_utils.c 'PE: Deliver PQWP [GpsWk .. GpsMs ..]', mc_gnssmeasreport.c 'Gps_MeasBlk .. FC, Wk, Ms', mgp_pe_api 'PE: Slow Clock Time', tle_ptm_mgr.cpp 'Slowclock Update') with record-level exact matches across MDM9207, MDM9x30, MDM9250, SDX20, SDX24, SDX55, SDX62 and SDX72 captures; v11 (wk,ms) also equals the 0x60 EVENT_GNSS_TLE_TIME_UPDATE_C payload. Versions without F3 in the available captures are grounded externally: v9 decoded UTC matches an LG290P reference receiver, the modem's NMEA RMC and AT+QGPSLOC seconds; v0 matches AT!GPSLOC GPS time (its gps_week is WNRO-rolled by 1024); v21 (wk,ms) equals the co-captured 0x1478. f_count on v0, v9 and v21 is decoded by structural transfer only. On the shifted versions f_count is u32@3, not u32@1. Version/size pairs are checked over a 60K-record corpus walk. The log name is cross-checked against an external MIT-licensed reference that does not decode the body. The body is not decoded.",
    source_url="",
    # fields_parsed/fields_identified are intentionally unset: the body
    # region is still preserved as ``raw``, so an equal-value declaration
    # would overstate coverage. The unset state signals "header parsed,
    # body unknown".
    #
    # Layer-2 plausibility (corpus walk over 43,632 records plus later
    # captures):
    #   version (offset 0): {0x00, 0x08, 0x09, 0x0b, 0x0e, 0x12, 0x15, 0x17, 0x18}
    #     0x00 (0)  =  183B (MDM9600: Sierra MC7700)
    #     0x08 (8)  =  445B (MDM9x30: MC7455)
    #     0x09 (9)  =  503B (MDM9x07: EP06A, EG95-NA)
    #     0x0b (11) =  535B (SDX20 V2 / MDM9650 / MDM9207-OCPU)
    #     0x0e (14) =  844B (SDX24: EM160R)
    #     0x12 (18) = 1011B (SDX55: FN980m, EM9190, RM500Q)
    #     0x15 (21) = 2248B (SDX65: Inseego M3100 — shifted header)
    #     0x17 (23) = 2464B (SDX62: RM520N-GL)
    #     0x18 (24) = 2472B (SDX72: Foxconn T99W640 — shifted header)
    # 0x00 is admitted only at its exact 183 B size (the Layer-1 size gate), so
    # a zero byte-0 at any other length still returns None.
    # An enum invariant is the correct declaration for a chipset-generation
    # discriminator — it surfaces previously-unseen variants (e.g., a future
    # SDX75 v=25) instead of silently emitting them. f_count / gps_week /
    # gps_ms remain undeclared because they are time-varying (no enum/range
    # fits).
    field_invariants={
        "version": {"enum": [0, 8, 9, 11, 14, 18, 21, 23, 24]},
    },
    # timebase_roles=("absolute-time", "ts-anchor"). Per-code, cross-chipset
    # evidence:
    #   * absolute-time — the header's gps_week + gps_ms are a real GPS week /
    #     time-of-week. Decoded GPS time matches the capture's own wall clock
    #     within ~1 min on two chipset generations: LM960 SDX20 v=11 (decoded
    #     time 20 s after the capture start stamp, 56 records, monotonic) and
    #     RM500Q-AE SDX55 v=18 (39 s after the capture start stamp, 662
    #     records, monotonic). EG25-G without a GNSS fix emits
    #     gps_week=0xFFFF, the no-fix sentinel, so the field is filled only on
    #     a valid fix.
    #   * ts-anchor — pairing each record's DIAG ts64 (log_time) with its
    #     header GPS time gives a clean linear map ts64 -> GPS wall clock:
    #     R²=0.99999985 (SDX55, n=662) / 0.99999939 (SDX20, n=56), with a
    #     chipset-invariant slope of ~52428 ts64 units per GPS ms, the known
    #     ts64 rate (cf. 0x1755's 52428.8 dts64/ms). Residual RMS ~70 ms is the
    #     GNSS-fix-vs-DIAG-stamp jitter. This makes 0x147B usable to timestamp
    #     every ts64 in the same capture against GPS wall clock (cross-stream
    #     alignment).
    #   * ts-anchor caveat for v11: v11 records fire on two triggers (see the
    #     class docstring). The slow-clock class stamps "now", so it is a
    #     sub-ms anchor — RMS 0.4-1.6 ms, slope 52428.1-52430.3 (EG25-G n=28,
    #     EG18-NA n=18; MDM9250 n=1310: R²=1.000000000, RMS 0.5 ms, slope
    #     52428.8). The fix-epoch class reports an earlier nav-filter epoch with
    #     a variable processing lag (RMS 166-219 ms while acquiring). A naive
    #     fit over both classes gives ~300 ms RMS and a biased slope. Split them
    #     capture-locally: fix-epoch records share one exact gps_ms%1000 phase,
    #     while slow-clock phases drift. That split reproduces the F3-established
    #     classes exactly (EG25-G 30/28, MDM9250 137/1310).
    timebase_roles=("absolute-time", "ts-anchor"),
)
def parse_0x147b(log_time: int, data: bytes) -> Diag0x147B | None:
    """Parse a LOG_GNSS_CD_DB_REPORT (0x147B) log payload.

    Decodes the 11-byte header (version, f_count, gps_week, gps_ms).
    Preserves the full payload as ``raw`` for downstream RE of the body
    region (bytes 11..end) which contains per-SV health/nav-message data.

    Eight chipset-generation variants observed (see ``Diag0x147B``
    docstring for the full version/size matrix):

    - MC7700  MDM9600: v=0,  183 B (gps_week is the 1024-rolled week)
    - MC7455  MDM9x30: v=8,  445 B
    - EP06A   MDM9x07: v=9,  503 B
    - EG18-NA SDX20-V2: v=11, 535 B
    - EM160R  SDX24:   v=14, 844 B
    - FN980m  SDX55:   v=18, 1011 B
    - M3100   SDX65:   v=21, 2248 B (+2-shifted header)
    - RM520N-GL SDX62: v=23, 2464 B (+2-shifted header)
    - T99W640 SDX72:   v=24, 2472 B (+2-shifted header)

    The header carries the same three fields on every version, at the
    legacy offsets (v0/8/9/11/14/18) or the +2-shifted ones (v21/23/24) — see
    ``_HEADER_OFFSETS``.

    Layer-1 invariant: rejects (returns None on) any record whose
    (version, len) pair is outside the corpus-validated set
    ``{(0,183), (8,445), (9,503), (11,535), (14,844), (18,1011), (21,2248),
    (23,2464), (24,2472)}``. A v=18
    record at 535 bytes (wrong size for the version) would otherwise
    parse through the 11-byte header path with a mis-attributed body —
    the "same version byte, new layout" trap. A visible parse-rate drop
    is the desired signal instead. Mirrors the sibling 0x1478 gate.
    """
    if len(data) < 13:
        return None
    # Layer-1 version gate.
    if data[0] not in (0, 8, 9, 11, 14, 18, 21, 23, 24):
        return None
    # Layer-1 per-version size gate. The `not in` form above keeps the
    # version gate visible to static audits; this is the semantic
    # (version, len) pairing check — size is strictly version-correlated
    # across the corpus.
    if len(data) != _VERSION_TO_SIZE[data[0]]:
        return None
    # Version-aware header offsets — v21/v23/v24 shift the header by +2.
    fc_off, wk_off, ms_off = _HEADER_OFFSETS[data[0]]
    return Diag0x147B(
        log_time=log_time,
        version=data[0],
        f_count=unpack_from('<I', data, fc_off)[0],
        gps_week=unpack_from('<H', data, wk_off)[0],
        gps_ms=unpack_from('<I', data, ms_off)[0],
        raw=data,
    )
