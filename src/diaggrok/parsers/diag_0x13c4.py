"""0x13C4 — CGPS ME Time-Estimate Put Info (GNSS): v0x01 60B / v0x02 65B / v0x03 66B.

Log name ``LOG_CGPS_ME_TIME_EST_PUT_INFO_C``: the GNSS measurement engine's
time-estimate put. Every field is named from the firmware's own F3 prints.

## Layout

The record is two copies of one GPS clock struct, `{u16 week, u32 ms, f32
bias_ms, f32 unc_ms}`: the clock half at [24..37] and the estimate half at
[46..59]. On v0x03 subversion-1 records (clock == estimate) the two halves are
byte-identical (3/3). Between them sits the frequency estimate. The firmware
prints the estimate half outright:

  mc_clock.c:8646 (T99W640 SDX72, QSR4) / mc_clock.c:6436 (Compal RXM-G1, v0x02):
    "TimeEstPut. FCount:%u Week:%u GPSMsec:%u Bias:%f Unc:%f SrcID:%u"

  joined on FCount == fcount_est, all five fields EXACT (f32 vs %f to 1e-6):
    v0x03 T99W640 12/12 and 57/57 (two captures);  v0x02 RXM-G1 15/15.

  [ 0]    version       u8  — 0x01 / 0x02 / 0x03, each with its own size (below)
  [ 1]    subversion    u8  — {0x00, 0x01}; on v0x02, 1 means the clock half is absent
  [ 2]    src_id        u8  — "SrcID" (84/84 exact; 18/27/29 seen)
  [ 3- 6] fcount_est    u32 — "FCount Est"
  [ 7-10] fcount_clk    u32 — "FCount Clk"
  [12-15] time_tick_ms  u32 — v0x03 ONLY (CANDIDATE): the GNSS TimeTick at the
                              clock's FCount, +1 ms (+2 on a minority) vs
                              gts.c:10446 "TimeTick @FCount %u FC %u TT %lu"
                              (FC == fcount_clk), 71/71. On v0x01/v0x02
                              [11..23] is high-entropy noise on 37k/37k records
                              (an unfilled struct), so it stays raw there.
  [24-25] week_alt      u16 — GPS week of the clock half (0xFFFF = clock absent)
  [26-29] tow_alt_ms    u32 — "GPSMs Clk" (None when week_alt is 0xFFFF)
  [30-33] clk_bias_ms   f32 — the clock half's sub-ms bias. vs ClockPut_GPS
                              "FC Wk Ms TBias TUnc" (FC == fcount_clk; week/ms
                              exact 52/52): TBias within p5/p95 -4.8/+3.3 us.
  [34-37] clk_unc_ms    f32 — the clock half's time uncertainty (ms); ≈ TUnc
                              (0.0334 vs 0.033356). Both None when the clock
                              half is absent.
  [38-41] freq_bias_mps f32 — trunc() == the bracketing "FreqEstPut - Bias %d
                              m/s" 249/249 (EG18-NA v0x02 180, T99W640 v0x03
                              69), signed to -7. MC7700 v0x01 reads ~-4496 m/s
                              (~-15 ppm XO).
  [42-45] freq_unc_mps  f32 — CANDIDATE: r=0.996 vs FreqEstPut "FreqUnc %d m/s"
                              when the print is the same source (94 == 94.0),
                              r=0.93/0.61 vs a different source. Two fleet-wide
                              plateaus: 94.0 (6,406 records, all 3 versions, 7
                              vendors — a stock initial freq uncertainty) and
                              1500.0 (205 records — not yet initialised;
                              freq_bias is 0.0 there). It tracks the time
                              uncertainty only grossly: a 0.998 fit against
                              mc_slow_clk.c "UcMs" was carried by two saturated
                              1500.0 points and collapses without them.
  [46-47] gps_week      u16 — GPS week of the estimate
  [48-51] tow_ms        u32 — "GPSMs Est" (GPS time-of-week, 0..604_799_999 ms)
  [52-55] bias_ms       f32 — "Bias", exact (above). Also on the EG18-NA v0x02
                              (no TimeEstPut print): tow_ms+bias reproduces
                              mc_receiver.c:2219 GtsTimeEst GPSMsec+Bias
                              (FCount-corrected) to median 14 us, 151/151 joins.
  [56-59] unc_ms        f32 — "Unc", exact (above). 0.1 is the floor most
                              tracking records sit on. unc_ms >= clk_unc_ms on
                              240/240 v0x01, 72/72 v0x03.
  [60]    tail_const_60 u8  — v0x02 / v0x03 only (below)

## Versions

The gate is a coupled `version -> size` map; a valid size under another
version byte is rejected:

* **v0x01 60B** (Sierra MC7700 MDM9200, 240 records): the v0x02 layout ending
  at byte 60, no tail.
* **v0x02 65B** (37,041 records, 17 modems).
* **v0x03 66B** (Foxconn T99W640 SDX72, 72 records): the v0x02 layout plus one
  trailing byte, 0x00 on 72/72.

`tail_const_60` ([60]) is 0x01 on every v0x02 record and on v0x03 subversion-0
records; it is 0x00 on 3/4 v0x03 subversion-1 records (clock == estimate), so
the declared enum is {0x00, 0x01}. v0x01 has no byte 60 (None). The
subversion / week_alt correlation holds on v0x02 only: v0x03 subversion 1
carries a week_alt on 3/4 records.

## Grounding

The (clock, estimate) pair: F3-grounded 12/12 on the T99W640 (QSR4) against
`mc_clock.c:8651 "FCount - Clk[%u] Est[%u], GPSMs - Clk[%u] Est[%u]"`, printed
one DIAG frame before each record. Structural identity on every version:
`fcount_est - fcount_clk == tow_ms - tow_alt_ms` (±2) on 240/240 v0x01, 71/71
v0x03 and the clock-present v0x02 fixture. When the clock half is absent (v0x02
subversion 1), fcount_est == fcount_clk (5/5 fixtures).

v0x01 (MC7700, no F3 on that part): FCount-exact against the co-captured,
F3-grounded 0x13C6 `gps_tow_ms + time_bias_ms`, the record's ms + bias
lands at {0, +2} ms with <=34 us fractional residual on 155/155 joins (19 clock,
136 estimate); week 240/240, and where the same FCount appears in both codes
the clock TOW agrees within 2 ms (19/19). The same {0, 2} ms integer split
shows on EG18-NA v0x02 vs GtsTimeEst — the two prints carve ms vs sub-ms
differently; the fraction agrees. This is also why estimate bias_ms reaches
-0.9998 on v0x02 while clk_bias_ms never leaves +-0.5. 0x13C6 tunc_ms is a
different (slow-clock) uncertainty and does NOT equal unc_ms; v0x01 unc rests
on the exact v0x02/v0x03 grounding plus unc_ms >= clk_unc_ms (240/240). The
MC7700 reports week 1397 = true 2421 - 1024 (2019 rollover); the raw value is
kept.

tow_ms on the EG25-G MDM9607 (a forced cold start): it tracks the co-temporal
`tle_log.c:669` F3 print `TPC: Sub:0, ... Wk:%d, msec:%d` over a 354 s cold
acquisition window at slope 0.99912 / r=0.99964, 358 of 359 non-decreasing
(n=360; residual sd 2.7 s is the join skew, TPC firing sparser). gps_week
equals the co-temporal F3 `GtsTimeEst Week:` on every record checked (181/181
records vs 179/179 lines on an EG18-NA cold start), and the "const 1398" seen
when GNSS is dark (indoor, no fix) is the no-time-source default week.

Whole corpus (37,353 records: 240 v0x01, 37,041 v0x02, 72 v0x03): 0 rejected,
0 invariant violations, every float finite; |bias_ms| < 1 and |clk_bias_ms| <=
0.5 on 100 %.

⛔ NOT an LTE serving-cell record. An early reading took offset 46 for a DL
EARFCN (GPS weeks of the period fall inside an LTE band's EARFCN range) and the
floats for RSRP/RSRQ. Both are refuted: the offset-46 value stays constant
across an LTE reselection, it equals the live GPS week on every capture
checked, and the build-matched GNSS-engine F3 (`mc_receiver.c:2219
GtsTimeEst`, `mc_fee.cpp:1151 ProcCgpsFreqEstimate`, `tm_standalone.c:577 Time
Uncertainty`) fires co-temporally with every record.

Also known as: LOG_INTERNAL_CGPS_ME_GENERIC_TIME_ESTIMATE_PUT_LNFORMATION

Log name: LOG_CGPS_ME_TIME_EST_PUT_INFO_C
Also known as: LOG_INTERNAL_CGPS_ME_GENERIC_TIME_ESTIMATE_PUT_LNFORMATION
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


_13C4_VERSION = 0x02
# Coupled version -> size map. v0x01 is the v0x02 layout ending at byte
# 60; v0x03 is the v0x02 layout plus one trailing byte.
_13C4_VERSION_SIZE = {0x01: 60, 0x02: 65, 0x03: 66}


# Ground truth: gps_week (offset 46) is the strongest anchor. It equals the
# live GPS week (F3 GtsTimeEst `Week:`), NOT an EARFCN. The four floats are
# named from the firmware's own TimeEstPut / FreqEstPut prints (see the
# docstring).

@dataclass
class Diag0x13C4:
    """CGPS ME Time-Estimate Put Info (0x13C4) — (clock, freq, estimate) put record."""
    log_time: int
    version: int
    subversion: int
    src_id: int
    fcount_est: int
    fcount_clk: int
    time_tick_ms: int | None
    week_alt: int | None
    tow_alt_ms: int | None
    clk_bias_ms: float | None
    clk_unc_ms: float | None
    freq_bias_mps: float
    freq_unc_mps: float
    gps_week: int
    tow_ms: int
    bias_ms: float
    unc_ms: float
    tail_const_60: int | None
    body_raw: bytes
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x13C4',
            'log_time': self.log_time,
            'version': self.version,
            'subversion': self.subversion,
            'src_id': self.src_id,
            'fcount_est': self.fcount_est,
            'fcount_clk': self.fcount_clk,
            'time_tick_ms': self.time_tick_ms,
            'week_alt': self.week_alt,
            'tow_alt_ms': self.tow_alt_ms,
            'clk_bias_ms': self.clk_bias_ms,
            'clk_unc_ms': self.clk_unc_ms,
            'freq_bias_mps': self.freq_bias_mps,
            'freq_unc_mps': self.freq_unc_mps,
            'gps_week': self.gps_week,
            'tow_ms': self.tow_ms,
            'bias_ms': self.bias_ms,
            'unc_ms': self.unc_ms,
            'tail_const_60': self.tail_const_60,
            'payload_size': self.payload_size,
        }


@register(0x13C4,
    name="0x13C4",
    description="CGPS ME Time-Est Put Info (0x13C4) — GNSS clock/freq/estimate "
                "put record, v0x01 60B / v0x02 65B / v0x03 66B; FCount, GPS week/ms, "
                "bias/unc, freq bias and SrcID F3-grounded, NOT LTE serving",
    version=10, author="Luke Jenkins", author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail="Clean-room RE across 7 chipsets. Every field is named from the "
                  "firmware's F3: the estimate half exact vs mc_clock.c "
                  "`TimeEstPut. FCount Week GPSMsec Bias Unc SrcID` (84/84, v0x02 RXM-G1 + "
                  "v0x03 T99W640); fcount_est / fcount_clk / tow_alt_ms vs mc_clock.c:8651 "
                  "`FCount - Clk Est, GPSMs - Clk Est` 12/12 (T99W640 QSR4); freq_bias_mps "
                  "trunc == FreqEstPut Bias m/s 249/249; clk_bias_ms / clk_unc_ms vs "
                  "ClockPut_GPS; tow_ms vs tle_log.c:669 TPC msec (slope 0.99912, n=360, "
                  "EG25-G MDM9607); gps_week == GtsTimeEst Week. freq_unc_mps and the "
                  "v0x03-only time_tick_ms are CANDIDATE. Versions v0x01 60B (MC7700 "
                  "MDM9200) / v0x02 65B / v0x03 66B (T99W640 SDX72) share one layout via a "
                  "coupled version->size map; Est-Clk agree in FCount and ms on 240/240 v1, "
                  "71/71 v3. Not an LTE record: the early LTE-serving field mappings are "
                  "refuted.",
    issues=(),
    fields_identified=20, fields_parsed=19,
    field_invariants={
        "version": {"enum": sorted(_13C4_VERSION_SIZE)},
        "payload_size": {"enum": sorted(_13C4_VERSION_SIZE.values())},
        "subversion": {"enum": [0x00, 0x01]},
        "tail_const_60": {"enum": [0x00, 0x01]},
        "tow_ms": {"range": [0, 604_799_999]},
        # v10: a sub-ms bias; the integer ms is carried separately (tow_ms).
        "bias_ms": {"range": [-1.0, 1.0]},
    },
)
def parse_0x13c4(log_time: int, data: bytes) -> Diag0x13C4 | None:
    if not data:
        return None
    # Byte-0 FIRST: layer-1 version gate, coupled to the size.
    expected_size = _13C4_VERSION_SIZE.get(data[0])
    if expected_size is None or len(data) != expected_size:
        return None
    version = data[0]
    subversion = data[1]
    # body_raw covers the still-opaque regions only. v5 carved metric_c
    # [38..41] and metric_d [52..55]; v8 carved tow_ms [48..51]; v9
    # carved fcount_est [3..6], fcount_clk [7..10] and tow_alt_ms [26..29]
    #; v10 carved src_id [2], clk_bias/unc [30..37] and, on v0x03
    # only, time_tick_ms [12..15]. [11] and [16..23] (all of [11..23] on
    # v0x01/v0x02, where it is unfilled noise) and the v0x02/v0x03 tail stay raw.
    has_tick = version == 0x03
    body = (
        (bytes(data[11:12]) + bytes(data[16:24]) if has_tick else bytes(data[11:24])) +
        bytes(data[61:])
    )
    week_alt_raw = unpack_from('<H', data, 24)[0]
    week_alt = None if week_alt_raw == 0xFFFF else week_alt_raw
    fcount_est, fcount_clk = unpack_from('<II', data, 3)
    clk_bias_ms, clk_unc_ms = unpack_from('<ff', data, 30)
    return Diag0x13C4(
        log_time=log_time,
        version=version,
        subversion=subversion,
        src_id=data[2],
        fcount_est=fcount_est,
        fcount_clk=fcount_clk,
        time_tick_ms=unpack_from('<I', data, 12)[0] if has_tick else None,
        week_alt=week_alt,
        tow_alt_ms=None if week_alt is None else unpack_from('<I', data, 26)[0],
        clk_bias_ms=None if week_alt is None else clk_bias_ms,
        clk_unc_ms=None if week_alt is None else clk_unc_ms,
        freq_bias_mps=unpack_from('<f', data, 38)[0],
        freq_unc_mps=unpack_from('<f', data, 42)[0],
        gps_week=unpack_from('<H', data, 46)[0],
        tow_ms=unpack_from('<I', data, 48)[0],
        bias_ms=unpack_from('<f', data, 52)[0],
        unc_ms=unpack_from('<f', data, 56)[0],
        tail_const_60=data[60] if len(data) > 60 else None,
        body_raw=body,
        payload_size=len(data),
    )
