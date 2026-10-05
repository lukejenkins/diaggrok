"""GNSS parsed position report (log code 0x1837).

One record per position report the location middleware hands to QMI-LOC, at
the fix rate of the GNSS session — 1 Hz on the bench modules, 10 Hz
(Δgps_tow_ms = 100) on the C-V2X units (WNC/Wistron 81UMV91B1, 81UMV91M21 —
whose Kapsch RIS-9260 captures are the same 81UMV91M21 modem, same physical
unit — and Ficosa CARCOM-G1). The firmware names the event on the same
epoch:
``loc_qmi_shim.c`` prints ``LOC_EVENT_PARSED_POSITION_REPORT
gpsWeek=%u, gpsTimeOfWeekMs=%u, position report time=%u`` (newer builds:
``locQmiHandleParsedPositionReport …``), and on the SDX62 builds the shim's
``QMI_LOC Msg 0x0024 ind succeed`` fires exactly once per 0x1837 record
(163/163 RM520N-GL, 75/75 CFW-3212 RG520N). It is the structured,
floating-point twin of the NMEA GGA/RMC the engine emits for the same fix
(0x1384 / 0x1CB2) and of the 0x1476 position report.

Two versions, one body. v0x03 (61 B) is v0x02 (53 B) plus an 8-byte tail;
bytes [0:53] are identical in both. v0x02 is emitted only by the Sierra
MC7455 / EM7455 (MDM9x30) firmware; v0x03 by every other
GNSS-capable chipset in the corpus (MDM9207/9607, MDM9x50, SDX20/20V2, SDX55,
SDX62, SDX72, and the C-V2X units above).

## Layout (little-endian)

    [0]      u8   version                  2 (53 B) | 3 (61 B)
    [1:5]    u32  position_report_time_ms  F3 "position report time" (ms
                                           timetick on the DIAG ts clock)
    [5:9]    u32  report_seq               +1 per REPORT (not per epoch: a skipped
                                           epoch is seq +1 with a 2x/3x TOW step);
                                           resets when a GNSS session starts
    [9]      u8   subtype                  2 on every record in the corpus
    [10:18]  f64  latitude_deg             WGS-84, +N
    [18:26]  f64  longitude_deg            WGS-84, +E
    [26:34]  f64  altitude_m               WGS-84 ELLIPSOID height (HAE)
    [34:42]  f64  position_uncertainty_m   1.73 x the engine HEPE (horizontal)
    [42]     u8   horizontal_confidence_pct_candidate   95 on every record
    [43:47]  f32  heading_rad              course over ground, radians,
                                           [0, 2pi); exactly 0.0 only at (near-)
                                           zero speed ("no course yet")
    [47:49]  u16  gps_week                 F3 "gpsWeek"
    [49:53]  u32  gps_tow_ms               F3 "gpsTimeOfWeekMs"
    ---- v0x03 only ----
    [53]     u8   v3_byte_53               4 (0 on 0.13%) — unknown; not the GGA
                                           fix quality, not a clean function of
                                           0x1476 pos_source
    [54:61]  7 B  reserved_tail            zero on every record in the corpus

## Grounding

In-capture F3, per build (the fix-level sites fire once per 0x1837 record):

* ``gps_week`` / ``gps_tow_ms`` — the ``loc_qmi_shim.c`` parsed-position-report
  print carries both on the same epoch: EG18-NA 89/89, RM520N-GL
  163/163, RM500Q-AE 206/206, 81UMV91M21 via its RIS-9260 capture path (same
  81UMV91M21 modem) 162/243 (the other 81 reports print no shim line),
  Wistron 81UMV91B1 479/479 — 1,099/1,099 wherever the line exists.
  Independently, the week/TOW implied by the same engine's NMEA ``$GxRMC``
  UTC date+time (+18 s leap) equals ``(gps_week, gps_tow_ms)`` exactly (v0x02
  EM7455 155/155), and the F3-grounded 0x1476 report joins 1:1 on the same
  ``(week, tow)`` key. ``gps_week`` is the engine's own week, not the host
  clock: the RM520N-GL captures that suffer the 1024-week rollover report
  week 1394 in 2026 here AND in 0x1C8F / NMEA alike.
* ``position_report_time_ms`` — the same shim print's ``position report time``
  equals ``[1:5]`` to within the ms tick (Δ ∈ [−2, +1] ms on all 1,099 records
  of the five builds that print it). It advances tick-for-tick with the DIAG
  ``ts64`` clock (consecutive-record change of ``ts64_ms − [1:5]`` ≤ 2 ms on
  98.5% of steps corpus-wide, ≤ 10 ms on the rest); the offset only jumps
  where the DIAG clock itself is re-set mid-capture (18 times). For the same
  reason ``(gps_week, gps_tow_ms)`` is a clean ``ts64`` → GPS-time map per
  clock segment (median slope 1.000002, median residual RMS ~1.2 ms over 355
  capture segments; up to ~0.2 s on reboot / airplane-cycle edge-case captures
  while the clock settles) — hence the ``absolute-time`` + ``ts-anchor``
  ``timebase_roles``.
* ``position_uncertainty_m`` — ``lm_mgp.c`` ``New fix saved as best. hepe:``
  (and ``Override=0 Hepe=``) times exactly 1.73 (float precision): EM7455 v0x02
  149/155, EG25-G 59/61 (a few re-report the retained best fix up to 8 s
  later), RM520N-GL 163/163, RM500Q-AE 206/206, 81UMV91M21 (RIS-9260 capture
  path, same physical unit) 206/243, CFW-3212
  70/75, EG18-NA 42/89, Wistron 81UMV91B1 244/479. On the fix-regime records
  that do not match a PRINTED HEPE exactly, the ratio to the latest printed
  HEPE is still 1.73 within a few percent (median 1.71) — the report carries a
  HEPE from a refinement step the firmware does not print. The 1.73 factor is
  the circular-Gaussian 63%→95% radius ratio (2.4477/1.4142 = 1.7308) to
  rounding, which is why [42] = 95 is read as a confidence percentage —
  CANDIDATE only: no F3 prints that byte. During no-fix / coarse-position
  periods (km-scale values) the report takes its uncertainty from a path that
  prints no HEPE (T99W640 capture: 26/58 match).
* ``altitude_m`` — **ellipsoidal (HAE)**, settled against the same engine's
  own NMEA GGA (field 9 MSL altitude + field 11 geoid separation, NMEA-0183):
  ``altitude_m − (GGA_msl + GGA_sep)`` = +0.035 m median on EM7455 v0x02
  (155/155; GGA rounds to 0.1 m), whereas ``altitude_m − GGA_msl`` is just the
  (negative) geoid separation. A single fix compared to an external receiver
  can make it look like MSL — a vertical-error coincidence the same-engine NMEA
  comparison cannot suffer.
  Corpus-wide the residual is within GGA's 0.1 m rounding on every chipset
  (even though the modems' geoid models disagree by several metres), and on
  SDX62 ``altitude_m`` equals 0x1C8F ``altitude_ellipsoid_m``, not its
  ``altitude_msl_m``.
* ``heading_rad`` — ``degrees(heading_rad)`` equals the NMEA ``$GxRMC``
  course-over-ground (field 8, "degrees true", printed to 0.1°) to within
  print rounding on every chipset (|Δ| p99 ≤ 0.05°), and the F3-grounded
  0x1476 ``heading_deg`` exactly when stationary (p99 ≤ 1° when moving) — e.g.
  1.63832 rad = 93.868° vs RMC 93.9. Exactly 0.0 only at (near-)zero speed.
  Corpus-wide the exponent byte [46] takes only 13 of 256 values, all in the
  non-negative float32 band below 8.0 — the signature of an angle in [0, 2π).

## Field-boundary caveats

* [1:9] is two u32 fields (``position_report_time_ms`` + ``report_seq``), not
  one u64 timestamp. A u64 read folds ``report_seq`` into the upper word; it
  is still monotonic, so it passes a "timestamp increases" check while being
  wrong by 2^32 per fix.
* [42:46] is not a u32 marker: it is ``[42]`` + the low 3 bytes of the
  float32 heading. On a stationary capture it looks "constant per capture,
  varies per boot"; its low byte 0x5F (95) on every chipset is the tell.
* [46:53] is the heading exponent byte + ``gps_week`` + ``gps_tow_ms``, not
  two counters.

Format caveat: every record currently in the corpus fits this layout; a future
firmware may ship a different layout in the same byte count under a new
version byte, which the version gate + ``field_invariants`` below surface as a
parse-rate drop rather than silent mis-decoding.

Log name: LOG_EVENTS_DS_GSM_AMR_CMC_TURNAROUND_TIME
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


PAYLOAD_SIZE_V3 = 61
PAYLOAD_SIZE_V2 = 53
TOW_MS_PER_WEEK = 604_800_000

# Ground-truth capture recipes for v03 RM520N-GL / RM500Q-AE / LM960 / EM9190
# ground lat/lon against the vendor AT fix (AT+QGPSLOC / AT$GPSACP /
# AT!GPSLOC?); the in-capture F3 + NMEA grounding above covers every field of
# both versions without any AT poll.
ALLOWED_VERSIONS = (2, 3)


@dataclass
class Diag0x1837:
    """GNSS parsed position report (log code 0x1837)."""

    log_time: int
    version: int
    position_report_time_ms: int
    report_seq: int
    subtype: int
    latitude_deg: float
    longitude_deg: float
    altitude_m: float
    position_uncertainty_m: float
    horizontal_confidence_pct_candidate: int
    heading_rad: float
    gps_week: int
    gps_tow_ms: int
    # v0x03 only — None on v0x02 records (the 8-byte tail is absent).
    v3_byte_53: int | None
    reserved_tail: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1837',
            'log_time': self.log_time,
            'version': self.version,
            'position_report_time_ms': self.position_report_time_ms,
            'report_seq': self.report_seq,
            'subtype': self.subtype,
            'latitude_deg': self.latitude_deg,
            'longitude_deg': self.longitude_deg,
            'altitude_m': self.altitude_m,
            'position_uncertainty_m': self.position_uncertainty_m,
            'horizontal_confidence_pct_candidate': self.horizontal_confidence_pct_candidate,
            'heading_rad': self.heading_rad,
            'heading_deg': self.heading_rad * 180.0 / math.pi,
            'gps_week': self.gps_week,
            'gps_tow_ms': self.gps_tow_ms,
            'v3_byte_53': self.v3_byte_53,
            'reserved_tail': self.reserved_tail,
        }


@register(
    0x1837, domain="gnss",
    name="0x1837",
    description=(
        "GNSS parsed position report (one per QMI-LOC position report, ~1 Hz): "
        "lat/lon/HAE altitude as f64, horizontal uncertainty (1.73 x HEPE), "
        "heading (f32 rad), GPS week + time-of-week, report timetick + "
        "sequence. v0x02 / 53 B on MDM9x30; v0x03 / 61 B = v0x02 "
        "+ an 8-byte tail on every later chipset."
    ),
    version=5,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Both versions sliced against in-capture F3 — loc_qmi_shim.c "
        "LOC_EVENT_PARSED_POSITION_REPORT (gpsWeek / gpsTimeOfWeekMs / position "
        "report time) and lm_mgp.c HEPE (x1.73) — plus the same engine's NMEA "
        "GGA/RMC (HAE altitude, course over ground, UTC-derived week/TOW) and "
        "the F3-grounded 0x1476 report joined on (week, tow). Initial clean-room "
        "RE from FN980m SDX55 (v=3) and MC7455 (v=2). [42] (confidence) and "
        "[53] remain CANDIDATE / unknown."
    ),
    source_url="",
    # Both = the genuinely named body fields:
    # the 14 decoded fields minus the two placeholders v3_byte_53 / reserved_tail.
    fields_identified=12,
    fields_parsed=12,
    issues=(),
    primary_issue=None,
    # Layer-2 invariants — paired with the in-parser hard gates below. The
    # ranges are PHYSICAL bounds (a heading outside [0, 2pi), a TOW past the
    # end of the week), so a mis-sliced layout trips them while no legitimate
    # value can. Semantic bytes a firmware may legitimately fill differently
    # ([42], [53]) are deliberately NOT pinned (size invariance != format
    # invariance cuts both ways).
    field_invariants={
        "version": {"enum": list(ALLOWED_VERSIONS)},
        "subtype": {"const": 2},
        "heading_rad": {"range": [0.0, 2 * math.pi]},
        "gps_tow_ms": {"range": [0, TOW_MS_PER_WEEK - 1]},
        # v0x03-only (None on v0x02); the registry skips invariant checks when
        # observed is None, so this pins v0x03 without rejecting v0x02.
        "reserved_tail": {"const": 0},
    },
    timebase_roles=("absolute-time", "ts-anchor"),
)
def parse_0x1837(log_time: int, data: bytes) -> Diag0x1837 | None:
    # Version byte first: gate the version BEFORE any
    # structural decode. v0x02 and v0x03 share [0:53]; v0x03 appends [53:61].
    if len(data) < 1:
        return None
    version = data[0]
    if version not in ALLOWED_VERSIONS:
        return None
    need = PAYLOAD_SIZE_V3 if version == 3 else PAYLOAD_SIZE_V2
    if len(data) < need:
        return None

    if version == 3:
        v3_byte_53: int | None = data[53]
        reserved_tail: int | None = int.from_bytes(data[54:61], 'little')
    else:
        v3_byte_53 = None
        reserved_tail = None

    return Diag0x1837(
        log_time=log_time,
        version=version,
        position_report_time_ms=unpack_from('<I', data, 1)[0],
        report_seq=unpack_from('<I', data, 5)[0],
        subtype=data[9],
        latitude_deg=unpack_from('<d', data, 10)[0],
        longitude_deg=unpack_from('<d', data, 18)[0],
        altitude_m=unpack_from('<d', data, 26)[0],
        position_uncertainty_m=unpack_from('<d', data, 34)[0],
        horizontal_confidence_pct_candidate=data[42],
        heading_rad=unpack_from('<f', data, 43)[0],
        gps_week=unpack_from('<H', data, 47)[0],
        gps_tow_ms=unpack_from('<I', data, 49)[0],
        v3_byte_53=v3_byte_53,
        reserved_tail=reserved_tail,
    )
