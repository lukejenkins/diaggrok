"""Public zero-PII test for diaggrok.ts64_cal (ts64 -> UTC calibration).

Fully synthetic: the 0x1476 position reports are the public 0x1476 fixture
with fabricated GPS week / time-of-week values spliced in at their documented
offsets ([23:25] u16 gps_week, [25:29] u32 gps_tow_ms). No bytes come from a
capture. The fixture's own fabricated position fields are unchanged.
"""
import struct
from datetime import timedelta

from public_corpus.test_diag_0x1476 import _synthetic_1476
from diaggrok.ts64_cal import (
    TS64_NOMINAL_TICK_S,
    build_calibrator,
    gps_to_utc,
    gnss_anchor_from_payload,
)

_WEEK = 2200          # fabricated
_TOW0_MS = 100_000    # fabricated
_TS0 = 1 << 40        # fabricated boot-relative ts64


def _report(week: int, tow_ms: int) -> bytes:
    raw = bytearray(_synthetic_1476())
    struct.pack_into("<HI", raw, 23, week, tow_ms)
    return bytes(raw)


def _ticks(seconds: float) -> int:
    return round(seconds / TS64_NOMINAL_TICK_S)


def test_anchor_reads_the_spliced_gps_time():
    assert gnss_anchor_from_payload(_TS0, _report(_WEEK, _TOW0_MS)) == (_WEEK, _TOW0_MS)


def test_sentinel_week_is_not_an_anchor():
    assert gnss_anchor_from_payload(_TS0, _report(0, _TOW0_MS)) is None


def test_build_calibrator_fits_one_report_per_second():
    records = [(0x1476, _TS0 + _ticks(k), _report(_WEEK, _TOW0_MS + 1000 * k))
               for k in range(10)]
    records.append((0xB0C0, _TS0, b"\x00" * 8))  # other codes are ignored
    cal = build_calibrator(records)
    assert cal.is_calibrated and cal.rate_fitted
    assert cal.num_anchors == 10
    mid = cal.ts64_to_utc(_TS0 + _ticks(4.5))
    want = gps_to_utc(_WEEK, _TOW0_MS + 4500)
    assert abs((mid - want) / timedelta(milliseconds=1)) < 1.0


def test_no_anchor_means_uncalibrated():
    cal = build_calibrator([(0xB0C0, _TS0, b"\x00" * 8)])
    assert not cal.is_calibrated
    assert cal.ts64_to_utc(_TS0) is None
