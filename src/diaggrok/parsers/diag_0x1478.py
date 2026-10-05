"""LOG_GNSS_CLOCK_REPORT (0x1478) parser.

Companion log codes 0x1477 (LOG_GNSS_GPS_MEASUREMENT_REPORT) and 0x147B
(LOG_GNSS_CD_DB_REPORT) are decoded in ``diag_0x1477.py`` and
``diag_0x147b.py`` respectively.

0x1478 is the GNSS clock report, not an RF status log: an external
MIT-licensed reference also enumerates it as LOG_GNSS_CLOCK_REPORT, and the
RF hardware status log is 0x147E (LOG_GNSS_PRX_RF_HW_STATUS_REPORT). The
backward-compat alias ``GpsRfStatus`` is kept in diaggpsd's
``gnss_packets`` module.

Log name: LOG_GNSS_CLOCK_REPORT_C
Also known as: LOG_GAN_HANDIN_COMMAND
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_GNSS_CLOCK_REPORT
from diaggrok.registry import register


@dataclass
class Diag0x1478:
    """LOG_GNSS_CLOCK_REPORT (0x1478).

    Multi-constellation GNSS clock report emitted at 1 Hz. The 13-byte
    header was decoded against EG18-NA and FN980m captures; the
    per-constellation engine times below are decoded from the body, and the
    rest of the body is preserved as ``raw``.

    ## Header layout (13 B)

        byte 0:     u8   version        (3 on SDX20 V2, 4 on SDX55)
        byte 1..2:  u16  flags          0x01ff on the dominant subset —
                                        plausibly a GNSS constellation /
                                        signal enable mask (9 low bits set)
        byte 3..6:  u32  f_count        frame counter, ~1 Hz increment
        byte 7..8:  u16  gps_week       matches the capture's actual GPS
                                        week (e.g. 2413)
        byte 9..12: u32  gps_ms         GPS time of week in ms, matches
                                        the clock in 0x1477/0x1480/0x147B
                                        on the same epoch — equals the
                                        firmware's F3 "To ME/PE GPS ms"

    ## Per-constellation clock block (body, F3-grounded)

        byte 25..28: u32  glo_ms         GLONASS engine time-of-day ms —
                                         firmware F3 "To ME/PE GLO ms"
        byte 40..43: u32  bds_ms         BeiDou engine time-of-week ms —
                                         firmware F3 "To ME/PE BDS ms"

    **F3-VERDICT v0x03: GROUND.** Grounded against the firmware's own
    ``nf_navsolution.c`` F3 prints
    ("NF: Clock Adj: FC=%u, To ME GPS/GLO/BDS ms=[%u]") in an EG18-NA
    cold-GNSS-start capture decoded with the matching F3 string database:
    the co-temporal 0x1478 record's u32@9/@25/@40 exactly equal the
    F3-printed GPS/GLO/BDS ms. Two physical invariants confirm the offsets
    independently, corpus-wide:

      - ``gps_ms - bds_ms == 14000`` (the fixed 14 s BDT−GPST offset) on
        100% of records — 617 (EG18-NA SDX20 V2 v=3) + 770 (RM500Q SDX55
        v=4) = 1,387 fix records across two chipset generations, plus an
        LM960 SDX20 v=3 capture (229/229 fix records).
      - ``gps_ms - glo_ms`` carries the current GPS−UTC leap remainder
        (…018 s) atop the GLONASS day/week framing offset, stable per
        capture (== 162018000 on the LM960 capture, 229/229).

    v=0x03/174B is not EG18-NA-specific — it emits across SDX20 (EG18-NA,
    LM960), Sierra (EM7511, MC7411), and the WNC 81UMV91M21 (MDM9150)
    C-V2X modem. The 81UMV91M21 v0x03 records include long-uptime captures
    taken inside a Kapsch RIS-9260 RSU, which houses the same 81UMV91M21
    modem (same physical unit, same baseband) as the bench/OTA captures,
    so those records are not an independent device. The
    silicon-independent 14000 ms BDT−GPST invariant holding across the
    SDX20 v=3 records and the SDX55 v=4 records (different chipset
    generations) confirms this is one shared wire layout, not one
    firmware's struct packing.

    Galileo shares the GPS timescale (F3 "To ME GAL ms" == "To ME GPS ms"),
    so on v0x02..v0x04 there is no distinct GAL field — GAL ms == gps_ms.

    **F3-VERDICT v0x02: GROUND.** The 156 B MDM9207 variant is fix-verified
    against the firmware's own ``mc_clock.c`` plaintext (0x79) prints on an
    EG25-G open-sky GNSS capture:

      - ``mc_clock.c:4435`` — ``ClockPut_GPS: FC %u Wk %u Ms %u`` — the
        decoded ``f_count`` (u32@3), ``gps_week`` (u16@7) and ``gps_ms``
        (u32@9) equal the firmware's printed ``FC`` / ``Wk`` / ``Ms``
        field-for-field on 1,799 / 1,799 co-temporal v0x02 records
        (100%, exact equality — not a ±tolerance timing match; e.g.
        FC 1538040 / Wk 2432 / Ms 65920393). Corroborated by
        ``mc_clock.c:1894`` (``GNSSWk:2432``) and ``mc_clock.c:5151``
        (``TimeEstPut. … Week:2432 GPSMsec:…``).
      - ``bds_ms`` (u32@40) is grounded by the silicon-independent
        physical BDT−GPST invariant ``gps_ms - bds_ms == 14000`` (the
        fixed 14 s BeiDou−GPS timescale offset) on 3,957 / 3,957
        BeiDou-enabled fix records (100%) across five MDM9207/MDM9x30
        modems — EG25-G (MDM9207), EP06, EG95NA, SIM7600NA, EM7455 —
        and six GPS weeks (2414/2417/2422/2431/2432). MC7455 is a
        negative control: its reduced constellation mask
        (``flags=0x7f`` vs ``0x7ff``, BeiDou disabled) shows no 14000
        offset on 314 records, confirming @40 is genuinely BeiDou engine
        time, not a coincidental constant.

    The no-fix sentinel (gps_week=0xFFFF/gps_ms=0) is what protocol-only
    probes without a sky view show.

    **F3-VERDICT v0x05: GROUND.** The 222 B SDX72 variant (Foxconn
    T99W640) is grounded field-for-field against the firmware's own
    co-temporal F3 on a GNSS-fix survey capture (64 v0x05 records, 56 with
    a same-FC F3 print; exact integer equality, joined on FC):

      - ``nf_navsolution.c:7593`` ``NF: Clock Adj: FC=%lu, To ME GPS ms=[%lu]
        … GLO ms=[%lu] … BDS ms=[%lu]`` == ``gps_ms``@9 / ``glo_ms``@25 /
        ``bds_ms``@40 on 56/56 (the same site that grounds v0x03).
      - ``nf_navsolution.c:7601`` ``… To ME GAL ms=[%lu] … NAVIC ms=[%lu]``
        == ``gal_ms``@55 / ``navic_ms``@70 on 56/56 — two fields new
        with this version (decoded on v0x05 only; see below).
      - ``mc_clock.c:6843`` (0x79 plaintext) ``ClockPut_GPS: FC %u Wk %u
        Ms %u TBias %f TUnc %f TSrc %d ClkOpMode %d`` == ``f_count``@3 /
        ``gps_week``@7 / ``gps_ms``@9 on 54/54 — the SDX72 descendant
        of the v0x02 ``mc_clock.c:4435`` site, now with TBias/TUnc/TSrc.

    Physical invariants on all 78/78 v0x05 fix records (two T99W640
    survey captures, GPS week 2423): ``gps_ms - bds_ms ==
    14000`` (BDT−GPST), ``gal_ms == gps_ms`` (GST shares the GPS
    timescale), and the GLONASS closed form ``glo_ms == (gps_ms - 18000 +
    10_800_000) % 86_400_000`` — GLONASS time is UTC(SU)+3 h time-of-DAY,
    GPS−UTC leap 18 s (firmware ``mc_clock.c:9533`` "Time Transformed from
    GPS to GLO … Ms" prints the same transform). This is the closed form
    behind the per-capture-stable GLONASS framing offset seen on
    v0x02..v0x04: ``gps_ms - glo_ms == dow*86_400_000 + 18_000 -
    10_800_000`` (dow = GPS day-of-week; the LM960 capture's value
    162018000 is dow=2, a Tuesday). The closed form is checked on v0x05 only.

    v0x05 block structure (per-constellation, stride 15 after a 16 B GPS
    block): ``[u32 ms][f32][f32][…]`` at GPS@9 / GLO@25 / BDS@40 / GAL@55 /
    NavIC@70. The f32 at @13 is a CANDIDATE GPS clock time-bias (ms): it
    equals the previous epoch's ``ClockPut_GPS TBias`` (``%.4f``) on 45/63
    fix records (the 0x1478 record is logged 4-6 ms before the same-FC
    ClockPut, so it carries the pre-put, propagated bias; the misses follow
    a slow-clock re-init at FC 255010). f32@17 does not equal TUnc (TUnc
    prints constant 0.033356; @17 drifts 0.03347→0.03346). Both stay in
    ``raw`` — not named on a partial match.

    ``navic_ms`` on these US captures is the firmware's NavIC engine time
    with NavIC untracked: it runs as ``f_count - 15`` (with occasional
    re-anchors), not an IRNSS time-of-week — decoded because the firmware
    itself labels it "NAVIC ms". No-fix v0x05 records (gps_week=0xFFFF,
    flags=0x0009, 1854 of 1933 unique corpus records) carry the same
    ``f_count - 15`` placeholder in every constellation's ms slot.
    Neither QCSuper nor SCAT decodes 0x1478, so no decoder cross-check is
    available.

    **F3-VERDICT v0x00: GROUND (without F3).** The 85 B Sierra MC7700
    (MDM9600, SWI9200X firmware) variant is grounded by non-F3 in-capture
    references. The 764 corpus records (5 captures, 2 units, two firmware
    builds) come from DLF files that kept LOG records only, so F3
    (0x79/0x99) and ``0x60`` events are absent; the one MC7700 HDLC capture
    carries no F3 and no 0x1478. QCSuper and SCAT emit nothing for 0x1478.
    Grounding, all exact or sub-second, on two bench comparison runs:

      - GPS week-number rollover (WNRO). ``gps_week`` == 1397 on
        749/749 fix records == the real GPS week 2421 minus 1024. This
        firmware resolves the 10-bit broadcast week against a pre-2019
        pivot and lands 1024 weeks early — the modem's own ``AT!GPSLOC?``
        prints "2006 10 17 … (GPS)" (the same trait as the 0x1476 MDM9600
        variant). ``gps_ms`` is not affected: time-of-week is exact.
      - Firmware-labelled GPS time. ``AT!GPSLOC?`` "Time: … (GPS)"
        (the GNSS engine's own GPS time, polled at 1 Hz) lands on a
        0x1478 ``(gps_week, gps_ms//1000)`` on 299/300 polls in each run.
      - Cross-code exact twin. The co-captured 0x1476 position report
        (MDM9600 variant) carries an identical ``(gps_week,
        gps_tow_ms)`` for 598/601 v0x00 fix records — exact integer
        equality, the same standard as an F3 join.
      - Independent DIAG time path. The record's DIAG ts64 (stamped by
        the DIAG time service, not the GNSS payload) equals
        ``gps_week*604800000 + gps_ms`` to a capture-constant −34…−328 ms
        (tight spread, 4/5 captures); the fifth (older firmware build) runs
        an unsynced DIAG clock but still tracks ``gps_ms`` 1:1 (±7 ms).
      - External reference receiver. On the second run an LG290P's RTCM
        1077 MSM7 epochs join a 0x1478 fix record within ±1 s on 300/300
        (median −119 ms: the MC7700 fixes at ~.88 s of each GPS second).
        This is real GPS TOW — UTC would sit 18 s off. (The first run's
        LG290P stream is undecodable.)
      - ``glo_ms``@25 obeys the GLONASS closed form ``(gps_ms − 18000 +
        10_800_000) % 86_400_000`` on 733/749 exactly and 749/749 within
        1 ms (the 16 misses are −1 ms rounding).

    v0x00 has no BeiDou block: the MC7700 is GPS+GLONASS only
    (``flags=0x003f`` on every fix, 6 low bits vs 9 on SDX-class), ``gps_ms
    − u32@40`` is never 14000 (749 distinct values), and bytes 38..41 are one
    f32 (≈ −4496, meaning unknown). ``bds_ms`` is therefore ``None`` on
    v0x00. ``f_count``@3 is decoded by structural transfer of the shared
    header only (no ``ClockPut_GPS FC`` witness without F3): it steps
    1000/s on the older firmware build but ~200–320/s on the newer one.

    CANDIDATEs, left in ``raw``: u8@47 == 18 on 764/764 — equal to the
    GPS−UTC leap second count, which is the closed form's 18 000 ms offset,
    but a corpus-constant cannot be told apart from a coincidental constant
    until a leap second happens; the ``flags`` acquisition ladder on the one
    cold start (older firmware build) — ``0x0009`` (no time; ``gps_ms ==
    glo_ms == f_count − 65541`` placeholder) → ``0x000b`` (TOW valid, week
    still 0xFFFF) → ``0x002b`` → ``0x003f`` (week + GLONASS time valid),
    n=1; f32@13/@17 and @29/@33 sit in the same GPS/GLO bias/uncertainty
    slots as v0x05's CANDIDATE; f32@53 == 0.02 on 697/749; u32@57 is a
    +1000/s ms counter; u16@69 steps +1 per record; bytes 71..84 are zero.

    ## Size variants
    - 85 B on MDM9600 (version 0, Sierra MC7700 SWI9200X) — header +
      glo_ms GROUND (non-F3 references); gps_week is WNRO-rolled (−1024);
      no BeiDou (bds_ms=None)
    - 156 B on MDM9207 (version 2, EG25-G / EP06 / EG95NA / SIM7600NA /
      MC7455 / EM7455) — v0x02 header + gps_ms/glo_ms/bds_ms F3-GROUND
    - 174 B on SDX20 V2 (version 3, EG18-NA / LM960)
    - 221 B on SDX55 (version 4, FN980m / RM500Q)
    - 222 B on SDX72 (version 5, Foxconn T99W640) — adds F3-grounded
      gal_ms@55 + navic_ms@70

    glo_ms@25 / bds_ms@40 are verified version-invariant on v=2, v=3 and
    v=4 (glo_ms@25 also on v=0, which has no bds_ms): the header and the
    leading per-constellation block are shared across sizes, and the
    version size differences live in the trailing region. As on
    v=3/v=4, ``glo_ms`` carries a per-capture-stable GLONASS day/week
    framing offset (not a universal constant), so ``gps_ms - glo_ms`` is
    constant within a capture but differs between captures — expected for
    GLONASS engine-time framing, not a decode error.

    The remaining body bytes (per-constellation frequency bias, drift
    uncertainty, and similar clock state) are preserved as ``raw``.

    ## Constellation-configuration drift — flags as passive validator

    The ``flags`` u16 at bytes 1..2 is a passive validator for GNSS
    constellation-configuration drift, complementing the ``constellations``
    field of 0x147E. Observed signatures:

      - EG25-G (OCPU firmware), indoor:    flags=0x0009 (~2 bits, GPS only)
      - EG18-NA, GPS/BDS config:           flags=0x018f (mixed)
      - EG18-NA, GPS/GLO/BDS/GAL config:   flags=0x01ff (all 9 bits set)
      - FN980m SDX55, antenna outdoors:    flags=0x01ff

    The 0x70 difference between the two EG18-NA configurations (0x018f vs
    0x01ff) correlates exactly with the GPS/BDS → GPS/GLO/BDS/GAL
    constellation set change in 0x147E's ``constellations`` field —
    same drift, two log codes confirm it. If a capture reports flags below
    0x01ff on a unit that should have all constellations enabled, the modem
    is not actually tracking what its configuration claims.

    The cross-modem regression tests lock these signatures in.
    """
    log_time: int
    version: int
    flags: int
    f_count: int
    gps_week: int
    gps_ms: int
    glo_ms: int
    # None on v0x00 (the MC7700 is GPS+GLONASS only, with no BeiDou block).
    bds_ms: int | None
    raw: bytes
    # F3-grounded on v0x05 only (nf_navsolution.c:7601); None on other
    # versions until grounded on their own records.
    gal_ms: int | None = None
    navic_ms: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d = {
            'type': 'Diag0x1478',
            'log_time': self.log_time,
            'version': self.version,
            'flags': self.flags,
            'f_count': self.f_count,
            'gps_week': self.gps_week,
            'gps_ms': self.gps_ms,
            'glo_ms': self.glo_ms,
            'payload_size': len(self.raw),
        }
        if self.bds_ms is not None:
            d['bds_ms'] = self.bds_ms
        if self.gal_ms is not None:
            d['gal_ms'] = self.gal_ms
        if self.navic_ms is not None:
            d['navic_ms'] = self.navic_ms
        return d


_VERSION_TO_SIZE = {0x00: 85, 0x02: 156, 0x03: 174, 0x04: 221, 0x05: 222}


# Validation anchor for the SIMCom SIM7600NA-H (MDM9207), the
# v=0x02 / 156B emitter. The decoded 13-byte header carries a GPS time
# (gps_week + gps_ms) plus a free-running frame counter (f_count) and a
# status word (flags). The GPS-time pair is the cleanest anchor: under an
# open-sky fix it should equal the GPS time derivable from the modem's
# reported UTC. gps_week=0xFFFF / gps_ms=0 is the no-fix sentinel, so the
# comparison is only meaningful with a sky fix.

@register(LOG_GNSS_CLOCK_REPORT, domain="gnss",
    name="0x1478",
    description="Multi-constellation GNSS clock state; 13-byte header + F3-grounded per-constellation engine time (gps_ms@9, glo_ms@25, bds_ms@40) decoded across 5 versions (v=0x00/85B, v=0x02/156B, v=0x03/174B, v=0x04/221B, v=0x05/222B; v0x00 has no bds_ms and a WNRO-rolled gps_week; v0x05 adds gal_ms@55 + navic_ms@70); remaining body preserved as raw for ongoing RE",
    version=11,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail="Header (version, flags, f_count, gps_week, gps_ms) decoded from EG18-NA SDX20 V2 and FN980m SDX55 captures and checked over a 53,723-record / 196-capture corpus walk; gps_week + gps_ms are hardware-verified as GPS time against the modem's reported UTC (SDX55/SDX62 v0x04). Per-constellation engine times (glo_ms@25, bds_ms@40; gal_ms@55 + navic_ms@70 on v0x05) are grounded field-for-field against the firmware's own F3 clock prints (nf_navsolution.c 'To ME GPS/GLO/BDS/GAL/NAVIC ms', mc_clock.c 'ClockPut_GPS: FC Wk Ms') on v0x02 (MDM9207), v0x03 (SDX20) and v0x05 (SDX72) records with exact integer equality, and by the BDT-GPST 14000 ms offset and GLONASS UTC(SU)+3 h closed form across MDM9207, SDX20, SDX55 and SDX72. v0x00 (MC7700, MDM9600) carries no F3 in the available captures and is grounded against the modem's AT!GPSLOC GPS time, the co-captured 0x1476 position report and an external RTCM reference receiver; its gps_week is WNRO-rolled by 1024. The log name is cross-checked against an external MIT-licensed reference that does not decode the body. Body bytes beyond the per-constellation time fields are not decoded.",
    source_url="",
    # Corpus walk over 53,723 records / 196 captures:
    #   v=0x04 / 221B: 24,654 records (45.9%)
    #   v=0x03 / 174B: 19,128 records (35.6%)
    #   v=0x02 / 156B:  9,941 records (18.5%)
    # Size is strictly version-correlated. Byte 1 = 0xff on 79.1% of records
    # and byte 2 has 3 dominant values (0x01=68.6%, 0x00=16.7%, 0x07=14.7%),
    # so flags=0x01ff is the dominant case but not invariant. Byte 3 (low
    # byte of f_count) shows the uniform 256-value distribution expected of
    # a counter.
    field_invariants={"version": {"enum": [0x00, 0x02, 0x03, 0x04, 0x05]}},
    # fields_parsed/fields_identified are intentionally unset: the body
    # region (bytes 13..end) is still preserved as ``raw``, so an equal-value
    # declaration would overstate coverage. The unset state signals "header
    # parsed, body unknown". Declare them once the body is decoded or the
    # ``raw`` field is removed from Diag0x1478.
    # timebase_roles=("absolute-time", "ts-anchor"), as on the sibling
    # 0x147B, which shares the gps_week (u16@7) + gps_ms (u32@9) header.
    # Per-code, cross-chipset evidence (single-capture sequential decode +
    # linear fit):
    #   * absolute-time — the header's gps_week + gps_ms are a real GPS week /
    #     time-of-week, hardware-verified against the modem's QGPSLOC UTC.
    #     Decoded GPS time matches the capture's own wall clock within ~1 min
    #     on two chipset generations:
    #       RM500Q-AE SDX55 v=0x04 drive capture — 658 fix records, monotonic,
    #         decoded UTC 21 s after the capture start stamp, gps_week 2422.
    #       LM960 SDX20 v=0x03 drive capture — 1246 fix records, monotonic,
    #         decoded UTC 36 s after the capture start stamp, gps_week 2422.
    #     gps_week=0xFFFF is the no-fix sentinel (as on 0x147B); the field is
    #     filled only on a valid fix.
    #   * ts-anchor — pairing each record's DIAG ts64 (log_time) with its
    #     header GPS time gives a clean linear map ts64 -> GPS wall clock:
    #       SDX55: R²=1.0, slope 52428.63 ts64/ms, residual RMS 0.1 ms (n=658)
    #       SDX20: R²=1.0, slope 52429.20 ts64/ms, residual RMS 2.3 ms (n=1246)
    #     The slope is the chipset-invariant ts64 rate of ~52428.8 units/ms
    #     (cf. 0x1755 and 0x147B). The residual is an order of magnitude
    #     tighter than 0x147B's ~70 ms because this is the GNSS clock report:
    #     its time-of-week is stamped off the same counter that drives ts64,
    #     which makes it the best ts-anchor of the GNSS logs.
    timebase_roles=("absolute-time", "ts-anchor"),
)
def parse_0x1478(log_time: int, data: bytes) -> Diag0x1478 | None:
    """Parse a LOG_GNSS_CLOCK_REPORT (0x1478) log payload.

    Decodes the 13-byte header (version, flags, f_count, gps_week, gps_ms).
    Preserves the full payload as ``raw`` for downstream RE of the body
    region (bytes 13..end) which contains per-constellation clock state.

    Five accepted version variants (size strictly version-correlated):
    - v=0x00 / 85-byte record — MDM9600 (Sierra MC7700 SWI9200X); GPS +
      GLONASS only, so ``bds_ms`` is None; ``gps_week`` is the firmware's
      WNRO-rolled week (real week − 1024)
    - v=0x02 / 156-byte record — earliest variant (MDM9207, EG25-G)
    - v=0x03 / 174-byte record — SDX20 V2 (EG18-NA, LM960)
    - v=0x04 / 221-byte record — SDX55 (FN980m, RM500Q) and SDX62
    - v=0x05 / 222-byte record — SDX72 (Foxconn T99W640); also decodes
      gal_ms@55 + navic_ms@70 (F3-grounded on this version only)

    The ``flags`` u16 is `0x01ff` on the dominant subset (~69%) but cycles
    through `0x00ff` (~17%) and `0x07ff` (~15%) across a 53,723-record corpus
    walk — likely a constellation/signal enable mask whose low byte (byte 2)
    tracks enabled satellite systems.

    Layer-1 invariant: rejects (returns None on) any record whose
    (version, len) pair is outside the corpus-validated set above.
    A v=2 record at 174 bytes would silently mis-parse otherwise —
    that's the "same K bytes, new layout" trap (size-invariance does
    not imply format-invariance; a future firmware could ship a new version at
    156 bytes with a different struct, and a visible parse-rate
    drop is preferable to garbage output).
    """
    if len(data) < 13:
        return None
    # Explicit Layer-1 version gate. The subsequent
    # `_VERSION_TO_SIZE.get(version)` check is the semantic gate; this
    # explicit `not in` form keeps the version gate visible to static audits.
    if data[0] not in (0x00, 0x02, 0x03, 0x04, 0x05):
        return None
    version = data[0]
    expected_size = _VERSION_TO_SIZE.get(version)
    if expected_size is None or len(data) != expected_size:
        return None
    return Diag0x1478(
        log_time=log_time,
        version=version,
        flags=unpack_from('<H', data, 1)[0],
        f_count=unpack_from('<I', data, 3)[0],
        gps_week=unpack_from('<H', data, 7)[0],
        gps_ms=unpack_from('<I', data, 9)[0],
        # Per-constellation engine time (F3-grounded): the firmware's
        # nf_navsolution.c "To ME/PE GLO ms" @25 and "To ME/PE BDS ms" @40.
        # Verified version-invariant on v=3 (174B) + v=4 (221B).
        # On a no-fix record these carry the same sentinel as gps_ms.
        # v0x00 (MC7700) has no BeiDou block — bytes 38..41 are one f32.
        glo_ms=unpack_from('<I', data, 25)[0],
        bds_ms=unpack_from('<I', data, 40)[0] if version != 0x00 else None,
        raw=data,
        # v0x05 only (F3 nf_navsolution.c:7601 "To ME GAL ms" / "NAVIC ms").
        gal_ms=unpack_from('<I', data, 55)[0] if version == 0x05 else None,
        navic_ms=unpack_from('<I', data, 70)[0] if version == 0x05 else None,
    )
