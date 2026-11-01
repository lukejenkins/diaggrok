"""GNSS BeiDou B1I measurement report (0x1756) — two layouts, keyed on byte 0.

The firmware calls it ``BDS B1 (0x1756)`` (``mc_gnssmeasreport.c``, the log
packet allocation print). Byte 0 selects the layout:

* **v0x00** — the GPS 0x1477 report's layout for BeiDou: a 30 B header (the
  0x1477 header ``<BIHIffffB`` behind two extra bytes) and N x 70 B per-SV
  slots, each exactly 0x1477's ``GpsSv`` struct. SDX20 (LM960), MDM9650
  (EM7511), SDX55 (EM9190, FN980, SIM8202G-M2) and MDM9207 (SIM7600NA).
* **v0x01** — the shared ``47 + 118 * N`` GNSS report of 0x1CC6 / 0x1CCC /
  0x1CCB / 0x1CE1 (``_gnss_meas118_helpers.py``). EM9291 (SDX62) only.

Corpus (149 captures): v0x00 33,561 records, v0x01 9,246.
Every record of both families satisfies its length formula; 0 off-stride.

v0x00 layout
------------
Header (30 B)::

    [0]      u8   version          0
    [1]      u8   minor            6 (SDX20/MDM9650/SDX55), 4 (MDM9207); raw
    [2]      u8   hdr_b2           0x00 / 0x05 / 0x46 seen; raw
    [3:7]    u32  f_count          FC
    [7:9]    u16  bds_week         BDS week (GPS week - 1356)
    [9:13]   u32  bds_milliseconds BDS ms of week (GPS ms - 14,000)
    [13:17]  f32  clock bias, ms
    [17:21]  f32  clock time uncertainty, **ns** (the firmware prints ms)
    [21:25]  f32  clock freq bias, m/s
    [25:29]  f32  clock freq uncertainty, m/s
    [29]     u8   N, the slot count

Slot (70 B) = 0x1477 ``GpsSv``: sv_id, observation_state, observations,
good_observations, parity, filter_stages, carrier_noise (u16, 0.01 dB-Hz),
latency (i16 ms), predetect, postdetections, meas integral (u32 ms) and
fraction (f32 ms), time unc (f32 ms), speed and speed unc (f32 m/s),
measurement_status (u32), misc, multipath, azimuth / elevation (f32 rad),
carrier phase, fine speed and unc, cycle slips, pad.

The old names (``sub_version``, ``sv_tow_ticks``, ``float_a..d``) were
guesses at this struct. They stay available as aliases: ``float_a`` (the
"tracking coefficient", range 0..1) is the SV-time fraction, ``float_b`` the
time uncertainty, ``float_c`` the speed and ``float_d`` the speed
uncertainty. ``sub_version`` is the observation state. An earlier LG290P
test compared ``float_a`` to elevation; the elevation is 25 B later, at @47.

v0x00 grounding
---------------
* **F3, header.** ``mc_gnssmeasreport.c:7341 Bds_MeasBlk(1Hz) - N SVs, FC,
  Wk, Ms, ClkBiasMs, TMs`` (0x79 plaintext) joined by FC. EM9190 SDX55
  (no time): 278 / 278 on N, Wk, Ms, ClkBiasMs. SIM8202G-M2 SDX55 wardrive
  (time known): 656 / 656 on N, Wk, Ms. TMs == f32@17 x 1e-6 on 934 / 934,
  so f32@17 is in ns on SDX55. The unit depends on the build (the
  sibling 0x1477 is ns on SDX55 and ms on SDX62, and v0x01 below is ms on
  the SDX62 EM9291). SDX20 / MDM9650 / MDM9207 v0x00 have no TMs print in
  the corpus, so ns there is assumed, not measured. ClkBiasMs agrees within the print's rounding when the
  freq bias is small and within 1.3e-4 ms otherwise (the print samples the
  clock at a slightly different instant).
* **F3, slots.** The per-SV table rows (``mc_gnssmeasreport.c:5312``,
  ``SV Status FCount Lat Ms SubMs Speed CNo TuncMs SpeedUnc NxM``) that follow
  each ``Bds_MeasBlk`` join by (FC, SV) to 6,972 / 6,972 slots:
  Lat == latency 6,972; FCount == FC - latency 6,860; Speed == int(speed)
  6,972; Status == measurement_status without bit 21 6,972; CNo (0.1 dB-Hz)
  == carrier_noise // 10 on all 3,505 non-zero slots. The row's Ms / SubMs /
  TuncMs are the slot's SV time and time unc propagated back by the latency:
  wire time - print time == latency x (1 - speed / c) (median ratio
  -0.9985 on the speed term; Ms == integral - latency on 6,951).
* **Cross-code.** Header joins the co-emitted GPS 0x1477 by FC on 33,559 /
  33,561: week + 1356 and ms + 14,000 on every time-known record (7 at
  +14,001..+14,008 ms), clock bias and freq bias / unc equal. Time unc
  equal on two thirds (BDS has its own time uncertainty once time is known).
* **Slots, external.** az / el at @43 / @47 (radians), FN980 SDX55
  ``gnss_comparison_lg290p_2026-04-23``: the modem's own ``$BDGSV``
  (whole degrees) on 2,334 / 2,338 rows within 1 deg, 2,338 within 2 deg; the
  independent LG290P reference (gpsd SKY, BDS) on 2,004 / 2,004 within 2 deg
  of elevation and 1,969 / 2,004 of azimuth (medians +0.02 / -0.4 deg).
  Slots with no SV position carry el = -pi/2, az = 0 (12,063 slots). The
  other 2,363 negative elevations are real below-horizon values (-1 to
  -33 deg); ``position_known`` is True for them.
* Range checks on all 95,979 + 3,012 slots: sv_id 201..263, fraction in
  [0, 1), az in [0, 2 pi], el in [-pi/2, pi/2], C/N0 <= 60 dB-Hz.

The ``00 04`` records (882, SIM7600NA MDM9207, 170 / 240 / 310 B) are the
same layout: 882 / 882 on length, 3,012 / 3,012 slots in range, header
joined to 0x1477 on 882 / 882. The v9 parser dropped them (it gated on u16
0x0600). It also dropped 599 records at N = 23 (1640 B) to
``parser_format='unknown'``.

v0x01 layout and grounding
--------------------------
Header and slots as in ``_gnss_meas118_helpers.py``; u16@20 / u32@22 are BDS
week / ms. N = byte[46], attested {0, 4..10, 13, 14}.

* **F3.** EM9291 DIAG + QMI correlation capture:
  ``mc_gnssmeasreport.c:6905 L1Gps_MBlk(1Hz) - N SVs,FC,Wk,Ms,CB,TMs`` joined
  by FC to 405 / 405 records: Wk == u16@20, Ms == u32@22, CB == f32@26,
  TMs == f32@30 (ms here, unlike v0x00). These epochs have no time.
* **Cross-code.** Header bytes [20:30] equal the co-emitted 0x1CC6 (itself
  F3-grounded, 155 / 155) at the same FC on 9,246 / 9,246. Slot az / el equal
  0x1CC6's on 23,492 / 23,492 SV rows and match ``AT!GPSSATINFO?`` within
  its whole-degree rounding (see ``diag_0x1cc6.py``).

What the older parser called the ``0x0301`` (47 B) and ``0x0401`` (755 B)
families are v0x01 at N = 0 and N = 6, with byte[1] a receiver state
(3 / 4) rather than a version. ``0x5437904d`` at @30 is the no-time TMs
sentinel (f32 3.15e12), not a signature. 755 B is 47 + 6 x 118; there is no
truncated sixth block. The v9 parser dropped every other N (2,603 records).

Whole corpus (149 captures): 42,807 / 42,807 records parse (33,561 v0x00,
9,246 v0x01), 0 rejects, 0 invariant violations.

In-capture oracle verdicts: F3 labelled (above). ``0x60`` silent: on the
EM9291 run2 and EM9190 ``gnss_acquire_2026-08-04`` captures the GNSS events
are session / spectrum / multipath / TLE state only (``GPS_PD_*``,
``GNSS_SPECTRUM_ANALYZER_STATUS``, ``GNSS_ME_MULTIPATH_ENV_IND``,
``GNSS_TLE_TIME_UPDATE_C``); none carries a per-SV or clock quantity.
Black-box (qcsuper / SCAT): no output for this code (neither decodes GNSS
measurement reports).

Size (fail loudly): v0x00 needs ``len == 30 + 70 * byte[29]`` with N in
0..23 (attested 0..13, 15, 16, 23); v0x01 needs ``len == 47 + 118 *
byte[46]`` with N in 0..14. Any other byte 0, N or length returns None.

Log name: LOG_GNSS_BDS_B1_MEASUREMENT_REPORT_C
Also known as: LOG_GNSS_BDS_MEASUREMENT_REPORT
Also seen applied to this code, but belonging to a different log: LOG_EVENT_DS_RAT_CHANGE
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_GNSS_BDS_MEASUREMENT_REPORT
from diaggrok.parsers._gnss_meas118_helpers import (
    _TRIO_HEADER_LEN,
    GnssMeas118Slot,
    _parse_trio_header,
    parse_slots,
    trio_payload_sizes,
)
from diaggrok.parsers.diag_0x1477 import _GPS_SV_FIELDS, _GPS_SV_FMT, GpsSv
from diaggrok.registry import register

# BDS epoch is 2006-01-01 00:00:00 UTC; GPS epoch is 1980-01-06 00:00:00 UTC.
BDS_GPS_WEEK_OFFSET = 1356

_BDS_HDR_SZ = 30
_BDS_SV_SZ = 70
# Corpus-attested v0x00 slot counts are 0..13, 15, 16 and 23; accept the
# interior. Widen only against a real record.
_V00_SLOT_COUNTS = frozenset(range(0, 24))
_V00_PAYLOAD_SIZES = [_BDS_HDR_SZ + _BDS_SV_SZ * n for n in sorted(_V00_SLOT_COUNTS)]
# Corpus-attested v0x01 slot counts are 0, 4..10, 13 and 14.
_V01_SLOT_COUNTS = frozenset(range(0, 15))
_V01_PAYLOAD_SIZES = trio_payload_sizes(_V01_SLOT_COUNTS)
# 30 + 70a is even and 47 + 118b is odd, so the two sets never overlap.
_PAYLOAD_SIZES = sorted(_V00_PAYLOAD_SIZES + _V01_PAYLOAD_SIZES)

# Layer-1 version gate: the closed byte-0 enum, kept in step with the
# field_invariants["version"] enum below. An out-of-enum byte 0 returns None
# before any dispatch, so the equality-dispatch form is a recognised gate.
_VERSIONS = (0, 1)

# Back-compat aliases for code that imported the old names.
_BDS_N_SLOTS_MAX = max(_V00_SLOT_COUNTS)
_SDX55_HDR_SZ = _BDS_HDR_SZ
_SDX55_SV_SZ = _BDS_SV_SZ
_SDX55_N_SLOTS_MAX = _BDS_N_SLOTS_MAX


@dataclass
class BdsSv(GpsSv):
    """v0x00 per-SV slot: the 0x1477 ``GpsSv`` struct, for a BDS SV."""

    @property
    def prn(self) -> int | None:
        """BeiDou PRN from the modem's 200 + PRN numbering."""
        if 201 <= self.sv_id <= 263:
            return self.sv_id - 200
        return None

    # Old names (v9 and earlier), kept for callers.
    @property
    def sub_version(self) -> int:
        return self.observation_state

    @property
    def status_counter_a(self) -> int:
        return self.observations | (self.good_observations << 8)

    @property
    def sv_tow_ticks(self) -> int:
        return self.unfiltered_meas_integral

    @property
    def float_a(self) -> float:
        return self.unfiltered_meas_fraction

    @property
    def float_b(self) -> float:
        return self.unfiltered_time_unc

    @property
    def float_c(self) -> float:
        return self.unfiltered_speed

    @property
    def float_d(self) -> float:
        return self.unfiltered_speed_unc

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d['prn'] = self.prn
        d['position_known'] = not (
            abs(self.elevation + math.pi / 2) < 1e-6 and self.azimuth == 0.0)
        # Old keys, kept for JSON consumers.
        d['sub_version'] = self.observation_state
        d['sv_tow_ticks'] = self.unfiltered_meas_integral
        d['float_a_tracking_coeff'] = self.unfiltered_meas_fraction
        d['float_b_variance_term'] = self.unfiltered_time_unc
        d['float_c_doppler_like'] = self.unfiltered_speed
        d['float_d_uncertainty_term'] = self.unfiltered_speed_unc
        return d


def _parse_bds_sv_slot(data: bytes, offset: int) -> BdsSv:
    return BdsSv(**dict(zip(_GPS_SV_FIELDS, unpack_from(_GPS_SV_FMT, data, offset))))


@dataclass
class Diag0x1756:
    """v0x00: 30 B header + N x 70 B 0x1477-layout slots."""

    log_time: int
    version: int                     # byte 0 == 0
    minor: int                       # byte 1: 6 or 4, raw
    sub_version: int                 # byte 2, raw (old name kept)
    f_count: int
    bds_week: int
    bds_milliseconds: int
    gps_to_bds_time_bias_ms: float   # clock bias, ms (old name kept)
    clock_time_unc_ns: float         # f32@17, ns on SDX55 (TMs x 1e6)
    clock_freq_bias: float           # m/s
    clock_freq_unc: float            # m/s
    sv_count_actual: int             # byte 29, N
    payload_size: int
    svs: list[BdsSv] = field(default_factory=list)
    parser_format: str = 'header_only'  # 'header_only' | f'with_svs_{n}'

    @property
    def clock_time_unc_ms(self) -> float:
        """Clock time uncertainty in ms (TMs). Measured on SDX55 only."""
        return self.clock_time_unc_ns * 1e-6

    @property
    def version_u16(self) -> int:
        """Bytes [0:2] as the v6..v9 parser read them (0x0600 / 0x0400)."""
        return self.version | (self.minor << 8)

    @property
    def gps_week(self) -> int:
        return self.bds_week + BDS_GPS_WEEK_OFFSET

    @property
    def bds_tow_seconds(self) -> float:
        return self.bds_milliseconds / 1000.0

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'type': 'Diag0x1756',
            'log_time': self.log_time,
            'version': self.version,
            'minor': self.minor,
            'sub_version': self.sub_version,
            'version_u16': self.version_u16,
            'f_count': self.f_count,
            'bds_week': self.bds_week,
            'gps_week': self.gps_week,
            'bds_milliseconds': self.bds_milliseconds,
            'bds_tow_seconds': self.bds_tow_seconds,
            'gps_to_bds_time_bias_ms': self.gps_to_bds_time_bias_ms,
            'clock_time_unc_ns': self.clock_time_unc_ns,
            'clock_time_unc_ms': self.clock_time_unc_ms,
            'clock_freq_bias': self.clock_freq_bias,
            'clock_freq_unc': self.clock_freq_unc,
            'sv_count_actual': self.sv_count_actual,
            'payload_size': self.payload_size,
            'parser_format': self.parser_format,
        }
        if self.svs:
            d['svs'] = [sv.to_dict() for sv in self.svs]
        return d


@dataclass
class Diag0x1756B1I:
    """v0x01: 47 B header + N x 118 B slots, the shared meas118 layout."""

    log_time: int
    version: int
    code_discriminator: int
    capture_marker: int
    const_word: int
    tick_a: int
    fcount: int
    bds_week: int
    bds_ms: int
    clk_bias_ms: float
    clk_tunc_ms: float
    freq_bias_mps: float
    freq_unc_mps: float
    hdr_f32_42: float
    slot_count: int
    sv_ids: tuple[int, ...]
    slots: list[GnssMeas118Slot]
    body: bytes
    payload_size: int
    parser_format: str = 'meas118'

    # Old names from the v7 / v8 0x0401 and 0x0301 paths.
    @property
    def tow_ms_a(self) -> int:
        return self.tick_a

    @property
    def tow_ms_b(self) -> int:
        return self.fcount

    @property
    def tow_ms_c(self) -> int:
        return self.bds_ms

    @property
    def clock_float_0(self) -> float:
        return self.clk_bias_ms

    @property
    def version_u16(self) -> int:
        return self.version | (self.code_discriminator << 8)

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1756B1I',
            'log_time': self.log_time,
            'version': self.version,
            'code_discriminator': self.code_discriminator,
            'capture_marker': self.capture_marker,
            'const_word': self.const_word,
            'tick_a': self.tick_a,
            'fcount': self.fcount,
            'bds_week': self.bds_week,
            'bds_ms': self.bds_ms,
            'clk_bias_ms': self.clk_bias_ms,
            'clk_tunc_ms': self.clk_tunc_ms,
            'freq_bias_mps': self.freq_bias_mps,
            'freq_unc_mps': self.freq_unc_mps,
            'hdr_f32_42': self.hdr_f32_42,
            'slot_count': self.slot_count,
            'sv_ids': list(self.sv_ids),
            'slots': [sl.to_dict() for sl in self.slots],
            'payload_size': self.payload_size,
            'parser_format': self.parser_format,
            # Old keys, kept for JSON consumers.
            'version_u16': self.version_u16,
            'tow_ms_a': self.tick_a,
            'tow_ms_b': self.fcount,
            'tow_ms_c': self.bds_ms,
        }


# The v7 (0x0401 / 755 B) and v8 (0x0301 / 47 B) classes are v0x01 records.
Diag0x1756Sdx65 = Diag0x1756B1I
Diag0x1756Sdx65Clock = Diag0x1756B1I


def _parse_v00(log_time: int, data: bytes) -> Diag0x1756 | None:
    if len(data) < _BDS_HDR_SZ:
        return None
    n = data[29]
    if n not in _V00_SLOT_COUNTS or len(data) != _BDS_HDR_SZ + _BDS_SV_SZ * n:
        return None
    bias, tunc_ns, fbias, func = unpack_from('<4f', data, 13)
    return Diag0x1756(
        log_time=log_time,
        version=data[0],
        minor=data[1],
        sub_version=data[2],
        f_count=unpack_from('<I', data, 3)[0],
        bds_week=unpack_from('<H', data, 7)[0],
        bds_milliseconds=unpack_from('<I', data, 9)[0],
        gps_to_bds_time_bias_ms=bias,
        clock_time_unc_ns=tunc_ns,
        clock_freq_bias=fbias,
        clock_freq_unc=func,
        sv_count_actual=n,
        payload_size=len(data),
        svs=[_parse_bds_sv_slot(data, _BDS_HDR_SZ + _BDS_SV_SZ * i) for i in range(n)],
        parser_format='header_only' if n == 0 else f'with_svs_{n}',
    )


def _parse_v01(log_time: int, data: bytes) -> Diag0x1756B1I | None:
    # Also enforces len == 47 + 118 * byte[46] with byte[46] in the k set.
    h = _parse_trio_header(data, _V01_SLOT_COUNTS)
    if h is None:
        return None
    return Diag0x1756B1I(
        log_time=log_time,
        version=h.version,
        code_discriminator=h.code_discriminator,
        capture_marker=h.capture_marker,
        const_word=h.const_word,
        tick_a=h.tick_a,
        fcount=h.fcount,
        bds_week=h.gps_week,
        bds_ms=h.gps_ms,
        clk_bias_ms=h.clk_bias_ms,
        clk_tunc_ms=h.clk_tunc_ms,
        freq_bias_mps=h.freq_bias_mps,
        freq_unc_mps=h.freq_unc_mps,
        hdr_f32_42=h.hdr_f32_42,
        slot_count=h.slot_count,
        sv_ids=h.sv_ids,
        slots=parse_slots(data, h.slot_count),
        body=bytes(data[_TRIO_HEADER_LEN:]),
        payload_size=len(data),
    )


@register(
    LOG_GNSS_BDS_MEASUREMENT_REPORT, domain="gnss",
    name="0x1756",
    description=(
        "GNSS BeiDou B1I measurement report. v0x00: 30 B header + N x 70 B "
        "slots, the GPS 0x1477 layout (N 0..23); header and slots F3-grounded "
        "against Bds_MeasBlk and its per-SV rows (6,972/6,972), az/el against "
        "NMEA and an LG290P. v0x01 (EM9291): the shared 47 + 118 x N report "
        "(N 0..14); header F3-grounded against L1Gps_MBlk (405/405) and "
        "equal to 0x1CC6 (9,246/9,246)."
    ),
    version=10,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE across six chipsets. v10: v0x00 "
        "re-read as the 0x1477 struct for BDS. Header: Bds_MeasBlk "
        "(mc_gnssmeasreport.c:7341, 0x79) by FC, 278/278 EM9190 and 656/656 "
        "SIM8202G-M2 on N/Wk/Ms; TMs == f32@17 x 1e-6 (ns on the wire) 934/934; "
        "0x1477 week+1356 / ms+14,000 on every time-known record. Slots: the "
        "per-SV rows (mc_gnssmeasreport.c:5312) by (FC, SV), 6,972/6,972: "
        "latency, speed, CNo (0.01 dB-Hz), status, and SV time propagated by "
        "latency. az/el (rad @43/@47) vs modem $BDGSV 2,334/2,338 within 1 deg "
        "and LG290P 2,004/2,004 el within 2 deg. MDM9207 '00 04' (882) and "
        "N=23 (599) records now decode. v0x01: the shared meas118 layout; "
        "L1Gps_MBlk (6905) by FC 405/405 on Wk/Ms/CB/TMs; header == 0x1CC6 "
        "9,246/9,246; slot az/el == 0x1CC6 23,492/23,492. The v7/v8 0x0401 / "
        "0x0301 families are v0x01 at N=6 / N=0. v9: timebase_roles "
        "on the v0x00 BDT epoch (bds_week/bds_milliseconds)."
    ),
    source_url="",
    fields_parsed=50,
    fields_identified=52,
    field_invariants={
        "version": {"enum": [0, 1]},
        "payload_size": {"enum": _PAYLOAD_SIZES},
    },
    issues=(),
    primary_issue=None,
    # BDT epoch on v0x00 (bds_week + bds_milliseconds): UTC = 2006-01-01 +
    # weeks + ms - 4 s. Matches the capture's own 0x1477 GPS->UTC exactly at
    # the same ts64 on LM960 SDX20 and two SIM8202G-M2 SDX55 wardrives;
    # ts64 -> BDT is linear (R^2 = 1.000000, ~52428.8 ts64/ms).
    timebase_roles=("absolute-time", "ts-anchor"),
)
def parse_0x1756(log_time: int, data: bytes) -> Diag0x1756 | Diag0x1756B1I | None:
    if len(data) not in _PAYLOAD_SIZES:
        return None
    if data[0] not in _VERSIONS:
        return None
    if data[0] == 0:
        return _parse_v00(log_time, data)
    if data[0] == 1:
        return _parse_v01(log_time, data)
    return None
