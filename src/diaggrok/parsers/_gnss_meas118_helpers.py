# diaggrok-provenance: re
"""Shared 47-byte header for the 118-byte-per-SV GNSS measurement reports
(0x1CCB / 0x1CCC / 0x1CE1, and 0x1CC6 BDS B1C).

Skipped by ``parsers/__init__.py`` auto-discovery because of the leading
underscore. Imported directly by the per-code parser modules
(``diag_0x1ccb.py``, ``diag_0x1ccc.py``, ``diag_0x1ce1.py``,
``diag_0x1cc6.py``).

SUBJECT MATTER: these are **GNSS per-SV measurement reports**, NOT NR5G ML1
codes, despite the log-code range. The same
``47 + 118 * N`` framing is carried by 0x1CC6
(``LOG_GNSS_BDS_B1C_MEASUREMENT_REPORT``), which uses this module, and by
0x1756 B1I on the EM9291 SDX62 (not yet ported); a public log-name table
puts 0x1CE0 (GAL E5b) beside it.

The [20:22] week / [22:26] ms pair is the **signal's own system time**:
GPS on 0x1CCC / 0x1CCB / 0x1CE1, BDS on 0x1CC6 (GPS week − 1356, ms − 14,000,
3,228 / 3,228). With no time (week 0xFFFF) every code carries the same
raw value. The field names below say ``gps_`` for the GPS codes; 0x1CC6
exposes them as ``bds_week`` / ``bds_ms``.

F3 grounding (v0x01)
--------------------
The measurement engine prints each report's header as 0x79 plaintext
(self-decoding, no qdb needed), and allocates the log packet with a QSR4 print
that names the code:

    mc_gnssmeasreport.c:923   Log packet id|SvCnt 0x1ccc000b. Tot sz 1357 bytes.
                              118 bytes per SV
    mc_gnssmeasreport.c:6614  L1Gps_MBlk(1Hz) - 11 SVs,FC 4397485,Wk 2437,
                              Ms 415541422,CB -0.48466,TMs 0.00012035,Src 8 Seq 1,C 2
    mc_gnssmeasreport.c:9868  L5QzSbas_MBlk - 1 SVs,FC ..,Wk ..,Ms ..,CB ..,TMs ..,
                              Src 8 Seq 6 C 7
    mc_gnssmeasreport.c:6597  FSrc: 5,F: 20 m/s,FUnc: 5 m/s,S: 0,Coff: ..,Mode: 6,..

``0x1ccc000b`` is (code << 16 | SvCnt) and 1357 = 12 B log header + 47 + 11 * 118.
Joined by FC on two Inseego M3100 (SDX65) captures, every joined pair
matches, 0 mismatches:

* 0x1CCC == ``L1Gps_MBlk``: N SVs == header[46] on 745/745 joined records.
* 0x1CE1 == ``L5QzSbas_MBlk``: N SVs == header[46] and Seq == header[1] on
  736/736.
* 0x1CCB has no MBlk print of its own in this build. Its header carries the
  same epoch (FC / Wk / Ms / CB / TMs) as its two siblings, and its slots hold
  QZSS / SBAS SVs (see ``diag_0x1ccb.py``).

Header (47 B)::

    [0]      u8   version            = 0x01 (only on-wire version)
    [1]      u8   code_discriminator == F3 "Seq" on 0x1CE1 (6 == 6, 736/736),
                                       but 0x1CCC carries 0 where L1Gps prints
                                       "Seq 1", so it is NOT Seq in general. Raw.
    [2:4]    u16  capture_marker     per-session constant (7 on M3100). Raw.
    [4:8]    u32  const_word         not labelled by any print. Constant in some
                                       sessions, varying in others. Raw.
    [8:12]   u32  tick_a             a receiver-ms stamp 1.5-2.5 s after FC
                                       (CANDIDATE: FCount at emission). Raw.
    [12:16]  u32  reserved           zero
    [16:20]  u32  fcount             == F3 "FC" (receiver ms frame count; this
                                       is the old ``tick_b``)
    [20:22]  u16  gps_week           == F3 "Wk"
    [22:26]  u32  gps_ms             == F3 "Ms" (GPS ms of week)
    [26:30]  f32  clk_bias_ms        == F3 "CB"
    [30:34]  f32  clk_tunc_ms        == F3 "TMs"
    [34:38]  f32  freq_bias_mps      == F3 :6597 "F" (the print is %d of this
                                       float: int() matches 100%, round() ~50%)
    [38:42]  f32  freq_unc_mps       == F3 :6597 "FUnc" (same truncation)
    [42:46]  f32  hdr_f32_42         0.0 on the L1 codes, a per-session constant
                                       on 0x1CE1 (L5). Un-grounded. Raw.
    [46]     u8   slot_count         == F3 "N SVs"; ``len == 47 + 118 * N``

Bytes [20:46] are exposed under the legacy name ``cell_context`` as well
(see the note on old attribute names below).

Per-SV slot (118 B). On 0x1CCC every named field below is VALUE-JOINED to the
co-emitted legacy GPS report 0x1477 (``LOG_GNSS_GPS_MEASUREMENT_REPORT_C``,
itself F3-grounded) by (FC == 0x1477 f_count, sv_id): 7,597 / 7,597
joined SV rows match on every field, 0 mismatches, on three chipset generations
(RM520N-GL SDX62 2,804; Inseego M3100 SDX65 1,121 + 3,430; Foxconn T99W640
SDX72 242)::

    [0:2]    u16  sv_id              gnss_sv_id (GPS 1..32, SBAS 120..158,
                                       QZSS 193..202)
    [3]      u8   observation_state  == 0x1477 observation_state (*)
    [4]      u8   observations       == 0x1477 observations
    [5]      u8   good_observations  == 0x1477 good_observations
    [7:9]    u16  parity_error_count == 0x1477 parity_error_count
    [9]      u8   filter_stages      == 0x1477 filter_stages (*)
    [10]     u8   predetect_interval == 0x1477 predetect_interval (*)
    [11:13]  u16  postdetections     == 0x1477 postdetections
    [13:17]  u32  measurement_status == 0x1477 measurement_status
    [21]     u8   misc_status        == 0x1477 misc_status (*)
    [25:27]  u16  cno_raw            C/N0 in 0.1 dB-Hz (== 0x1477
                                       carrier_noise / 10, which is 0.01 dB-Hz)
    [27:31]  i32  latency_ms         == 0x1477 latency (widened from i16)
    [31:35]  u32  meas_integral_ms   == 0x1477 unfiltered_meas_integral (SV
                                       time, ms of week; 67-86 ms below the
                                       header gps_ms for GPS, the signal transit)
    [35:39]  f32  meas_fraction_ms   == 0x1477 unfiltered_meas_fraction
    [39:43]  f32  time_unc_ms        == 0x1477 unfiltered_time_unc
    [43:47]  f32  speed_mps          == 0x1477 unfiltered_speed
    [47:51]  f32  speed_unc_mps      == 0x1477 unfiltered_speed_unc
    [80:84]  f32  azimuth_deg        == 0x1477 azimuth (rad) in degrees
    [84:88]  f32  elevation_deg      == 0x1477 elevation (rad) in degrees;
                                       -90.0 is the direction-not-computed
                                       sentinel (-pi/2 rad on 0x18F5)
    [92:96]  f32  fine_speed_mps     == 0x1477 fine_speed
    [96:100] f32  fine_speed_unc_mps == 0x1477 fine_speed_unc
    [112]    u8   cycle_slip_count   == 0x1477 cycle_slip_count

(*) These bytes are constant in some 0x1CCC captures. On an M3100 (SDX65)
capture they vary and match
exactly: 0x1CCC vs 0x1477 on 3,430 / 3,430 SV rows (observation_state 5 / 7,
misc_status 2 / 3), and 0x1CCB vs 0x18F5 on 1,677 / 1,677 (observation_state
1 / 4 / 7, predetect_interval 2 / 20, misc_status 0 / 2). On 0x1CC6 (BDS B1C) they are
named by transfer; no join checked them there.

Un-grounded, kept in ``raw``: bytes that are constant in the joined set
(1..2, 14 etc., which prove nothing) and the varying bytes 6, 18,
55..62, 71, 75, 88..91, 108..111, 113. Bytes [51:71] repeat the [31:51]
measurement block: the integral, speed and speed_unc copies are equal, the
fraction and time-uncertainty copies differ (CANDIDATE: a filtered copy).

0x1CCB is VALUE-JOINED to its legacy twin 0x18F5
(``LOG_GNSS_QZSS_SBAS_MEASUREMENT_REPORT_C``, decoded as the 0x1477 struct
with a u16 sv_id). By (FC, sv_id) on one M3100 capture, every named
slot field above equals the 0x18F5 block field on 1,677 / 1,677 rows (SBAS
131 / 133, QZSS 195), except parity_error_count on QZSS rows that are not
yet tracking (observation_state 1 or 2): 0x18F5 carries 16-bit noise there
and 0x1CCB carries 0. A 322-capture walk repeats the join on three chipset
generations: 26,726 / 26,726 rows on SDX62 (RM520N-GL, EM9291), SDX65
(M3100) and SDX72 (T99W640), parity 25,735.

0x1CE1 is the L5 report, so no legacy L1 record can confirm its per-signal
fields. Only the frequency-independent ones join to 0x18F5: azimuth,
elevation, fine_speed and fine_speed_unc on 543 / 543 QZSS 195 rows, speed on
536 / 543. Its C/N0, measurement block, latency and status bytes use this
layout by transfer (same writer, the generic ``Log packet id|SvCnt ... 118
bytes per SV`` allocator). Treat those as CANDIDATE.

In-capture oracle verdicts: F3 labelled (above). ``0x60`` not consulted for a
per-SV quantity: only GNSS session events fire, as on 0x1C60.
QCSuper / SCAT: not applicable, since neither decodes GNSS measurement
reports.

No ``mc_gnssmeasreport.c`` string in the M3100 or T99W640 qdb names a
``LOG_...`` symbol for these three codes, so the names used here are
descriptive.

Each code has its own corpus-attested N set, and each parser passes it to
``_parse_trio_header``, which rejects any other N and any length that is not
``47 + 118 * N`` (fail loudly):
    0x1CE1  N in {0, 1}    — 47 B (all SDX62/65) and 165 B (M3100 SDX65)
    0x1CCB  N in {1, 2, 3} — 165 B (SDX62/65/72), 283 B, 401 B (M3100)
    0x1CCC  N in 0..16     — 47..1935 B
    0x1CC6  N in 0..9      — 47..1109 B (EM9291 SDX62; N = 2 interior, unseen)

The old attribute names (``tick_b``, ``cell_context``, ``trailing_zero``) stay
available on the parsers for JSON consumers. ``body`` still carries the raw
slot bytes.
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from


_TRIO_HEADER_LEN = 47
_TRIO_SLOT_LEN = 118
_TRIO_SLOT_COUNT_OFFSET = 46


def trio_payload_sizes(slot_counts: frozenset[int]) -> list[int]:
    """The payload sizes a k set allows, for the ``payload_size`` enum."""
    return [_TRIO_HEADER_LEN + _TRIO_SLOT_LEN * k for k in sorted(slot_counts)]


@dataclass
class GnssMeas118Slot:
    """One 118-byte per-SV slot (layout in the module docstring)."""

    sv_id: int
    observation_state: int
    observations: int
    good_observations: int
    parity_error_count: int
    filter_stages: int
    predetect_interval: int
    postdetections: int
    measurement_status: int
    misc_status: int
    cno_raw: int
    latency_ms: int
    meas_integral_ms: int
    meas_fraction_ms: float
    time_unc_ms: float
    speed_mps: float
    speed_unc_mps: float
    azimuth_deg: float
    elevation_deg: float
    fine_speed_mps: float
    fine_speed_unc_mps: float
    cycle_slip_count: int
    raw: bytes

    @property
    def cno_dbhz(self) -> float:
        return self.cno_raw / 10.0

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k != "raw"}
        d["cno_dbhz"] = self.cno_dbhz
        return d


def _parse_slot(s: bytes) -> GnssMeas118Slot:
    (meas_integral, meas_fraction, time_unc, speed, speed_unc) = unpack_from(
        "<I4f", s, 31
    )
    azimuth, elevation = unpack_from("<2f", s, 80)
    fine_speed, fine_speed_unc = unpack_from("<2f", s, 92)
    return GnssMeas118Slot(
        sv_id=unpack_from("<H", s, 0)[0],
        observation_state=s[3],
        observations=s[4],
        good_observations=s[5],
        parity_error_count=unpack_from("<H", s, 7)[0],
        filter_stages=s[9],
        predetect_interval=s[10],
        postdetections=unpack_from("<H", s, 11)[0],
        measurement_status=unpack_from("<I", s, 13)[0],
        misc_status=s[21],
        cno_raw=unpack_from("<H", s, 25)[0],
        latency_ms=unpack_from("<i", s, 27)[0],
        meas_integral_ms=meas_integral,
        meas_fraction_ms=meas_fraction,
        time_unc_ms=time_unc,
        speed_mps=speed,
        speed_unc_mps=speed_unc,
        azimuth_deg=azimuth,
        elevation_deg=elevation,
        fine_speed_mps=fine_speed,
        fine_speed_unc_mps=fine_speed_unc,
        cycle_slip_count=s[112],
        raw=bytes(s),
    )


def parse_slots(data: bytes, k: int) -> list[GnssMeas118Slot]:
    """The k 118 B slots after the header (length already gated)."""
    return [
        _parse_slot(
            data[_TRIO_HEADER_LEN + _TRIO_SLOT_LEN * i:
                 _TRIO_HEADER_LEN + _TRIO_SLOT_LEN * (i + 1)]
        )
        for i in range(k)
    ]


@dataclass
class GnssMeas118Header:
    """Shared 47-byte header for 0x1CCB / 0x1CCC / 0x1CE1 (layout above)."""

    version: int
    code_discriminator: int
    capture_marker: int
    const_word: int
    tick_a: int
    fcount: int
    gps_week: int
    gps_ms: int
    clk_bias_ms: float
    clk_tunc_ms: float
    freq_bias_mps: float
    freq_unc_mps: float
    hdr_f32_42: float
    cell_context: bytes
    slot_count: int
    sv_ids: tuple[int, ...]

    @property
    def tick_b(self) -> int:
        """Old name for ``fcount``."""
        return self.fcount


def _parse_trio_header(
    data: bytes, slot_counts: frozenset[int]
) -> GnssMeas118Header | None:
    """Parse the header and enforce the coupled slot_count -> size gate.

    ``slot_counts`` is the calling code's corpus-attested k set. A k outside
    it, or a length other than ``47 + 118 * k``, returns ``None`` so the
    record surfaces as unhandled instead of being guessed at.
    """
    if len(data) < _TRIO_HEADER_LEN:
        return None
    if data[0] != 1:
        return None
    k = data[_TRIO_SLOT_COUNT_OFFSET]
    if k not in slot_counts:
        return None
    if len(data) != _TRIO_HEADER_LEN + _TRIO_SLOT_LEN * k:
        return None
    clk_bias, clk_tunc, f_bias, f_unc, f42 = unpack_from("<5f", data, 26)
    return GnssMeas118Header(
        version=data[0],
        code_discriminator=data[1],
        capture_marker=unpack_from("<H", data, 2)[0],
        const_word=unpack_from("<I", data, 4)[0],
        tick_a=unpack_from("<I", data, 8)[0],
        fcount=unpack_from("<I", data, 16)[0],
        gps_week=unpack_from("<H", data, 20)[0],
        gps_ms=unpack_from("<I", data, 22)[0],
        clk_bias_ms=clk_bias,
        clk_tunc_ms=clk_tunc,
        freq_bias_mps=f_bias,
        freq_unc_mps=f_unc,
        hdr_f32_42=f42,
        cell_context=bytes(data[20:46]),
        slot_count=k,
        sv_ids=tuple(
            unpack_from("<H", data, _TRIO_HEADER_LEN + _TRIO_SLOT_LEN * i)[0]
            for i in range(k)
        ),
    )
