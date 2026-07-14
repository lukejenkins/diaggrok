"""GNSS Client-API location report parser (0x1C8F) — #N.

Canonical QXDM name: ``LOG_GNSS_CLIENT_API_LOCATION_REPORT``
(qxdm_itemtype_list_zukgit_2025_04_03).

v4 (2026-07-02) — FULL DECODE.  Every byte of the 2240-byte v=0x0A payload
is now assigned to a named field.  The record is a flat, packed (unaligned)
little-endian GNSS position-fix struct — NOT a TLV / QMI-IDL descriptor
table (that reading, and the v1 "AT-Forwarder state beacon" reading, are
both retired).  Reverse-engineered from 8,061 records across 26 RM520N-GL
captures (23 R03A03 + 3 R03A04); layout is byte-identical across both
firmware builds.  Cross-validated against the in-record 0x1476 position
stream (lat/lon/alt r=1.0000000) and against AT+QGPSLOC=2 polls
(HDOP / MSL-alt / nsat / lat / lon all matched 100 % on 1,735 time-aligned
epochs).  See ``libs/diaggrok/recipes_out``-adjacent analysis under the
session RE bundle for the full evidence trail.

Struct map (payload offsets, all little-endian)
-----------------------------------------------

===== record + time header =====
* 0x000 u8  version              = 0x0A (Layer-1 gate).
* 0x001 u8  motion_fix_state     3-way iff 8,061/8,061: 0x77 stationary
  (speed==0), 0xFF moving (speed>0), 0x33 velocity-solution-invalid
  (velocity/vel-unc/speed-unc all zeroed; the ``velocity_solution_marker``
  at 0x03D also flips).  Nibble-mirrored bit mask; only {0011,0111,1111}
  observed.  (v3's ``session_id`` — retracted; the true session key is
  ``engine_start_monotonic_ns`` at 0x8B4.)
* 0x002 u8  const_0x07           = 0x07 (Layer-1 gate).
* 0x003 u64 utc_timestamp_ms     UTC milliseconds since the Unix epoch,
  GPS-derived.  Exact identity in 8,061/8,061:
  ``== 315964800000 + gps_week*604800000 + gps_tow_ms - 18000`` (18000 ms =
  GPS-UTC leap seconds).  When ``gps_week`` is stored mod-1024 (time not yet
  resolved — see ``time_week_confidence``), this value is 1024 weeks in the
  past; add 1024*604800000 ms to recover wall time.  (v3's ``record_token``
  @0x03 + ``record_counter`` u32 @0x04 + "01 00 00 constant" @0x08 were all
  slices of this one field — retired.)

===== position (packed f64 triplet, unaligned) =====
* 0x00B f64 latitude_deg         WGS84 degrees.
* 0x013 f64 longitude_deg        WGS84 degrees.
* 0x01B f64 altitude_ellipsoid_m height above the WGS84 ellipsoid.

===== motion + horizontal accuracy =====
* 0x023 f32 speed_2d_mps         Horizontal speed.  An INDEPENDENT firmware
  output (truncated to 0.01 m/s with a 0.15 m/s zero-clamp) — NOT
  ``hypot(vel_n, vel_e)``; do not derive it.
* 0x027 f32 heading_deg          Course over ground, 0.1°-quantised, 0..360.
  Independent filtered estimate; tracks ``atan2(vel_e, vel_n)`` to a median
  0.03° but deviates during dynamics (forced 0 when stationary).
* 0x02B f32 horizontal_unc_m     Circular horizontal position uncertainty.
* 0x02F f32 vertical_unc_m       Vertical position uncertainty.
* 0x033 f32 speed_unc_mps        == f32-pipeline ``hypot(vel_unc_n,
  vel_unc_e)`` bit-exact 8,061/8,061.
* 0x037 f32 heading_unc_deg      == 0 iff speed == 0 (8,061/8,061).

===== small constant/marker block =====
* 0x03B u16 const_1_0x3b         = 1.
* 0x03D f32 velocity_solution_marker  4.88e-4 normally; 3.68e-4 in exactly
  the 45 ``motion_fix_state==0x33`` (velocity-invalid) records.
* 0x041 u32 const_6              = 6.

===== altitude MSL + DOPs + declination =====
* 0x045 f32 altitude_msl_m       Height above mean sea level.  ==
  ``AT+QGPSLOC=2`` altitude 100 % of joined polls; == altitude_ellipsoid_m
  + ~16.4 m (N-Utah geoid undulation ≈ -16.4 m, so MSL sits ABOVE the
  ellipsoidal height).
* 0x049 f32 pdop / 0x04D f32 hdop / 0x051 f32 vdop / 0x055 f32 gdop /
  0x059 f32 tdop.  0.1-quantised.  Assignment is the UNIQUE survivor of all
  120 label permutations under (HDOP==AT-hdop, H<=P<=G, hypot(H,V)~P,
  hypot(P,T)~G).
* 0x05D f32 magnetic_deviation_deg  0 (velocity-invalid rows) or
  10.73..11.83 (N-Utah magnetic declination ≈ 11°E).

===== fix reliability + uncertainty ellipse =====
* 0x061 u32 horizontal_reliability / 0x065 u32 vertical_reliability
  enum {2,3,4}; equal to each other in 8,061/8,061.
* 0x069 f32 horiz_unc_semi_major_m / 0x06D f32 horiz_unc_semi_minor_m
  (semi_major >= semi_minor 8,061/8,061).
* 0x071 f32 horiz_unc_azimuth_deg   Azimuth of the ellipse major axis;
  5.625°-quantised (=180/32; 32 distinct values).
* 0x075 f32 horiz_unc_north_m / 0x079 f32 horiz_unc_east_m  FIRMWARE-DERIVED
  from (semi_major, semi_minor, azimuth) via ``hypot(smaj*cos(a),
  smin*sin(a))`` — but the firmware feeds the azimuth DEGREE value to
  sin/cos AS RADIANS (a units bug), so these equal the true North/East
  uncertainties only when azimuth==0 (or the ellipse is circular).
  Consumers wanting real N/E uncertainty should recompute from the ellipse.

===== velocity (NEU) + velocity uncertainty (NEU) =====
* 0x07D f32 vel_north_mps / 0x081 f32 vel_east_mps / 0x085 f32 vel_up_mps.
  vel_north == 0x1476 vel_n, vel_east == 0x1476 vel_e (bit-exact).
* 0x089 f32 vel_unc_north_mps / 0x08D f32 vel_unc_east_mps /
  0x091 f32 vel_unc_up_mps.

===== SVs-used bitmasks (three packed u64) =====
* 0x095 u64 gps_svs_used_mask      bit i set  <=> GPS PRN (i+1) used in fix.
* 0x09D u64 glonass_svs_used_mask  bit i set  <=> GLONASS slot (i+1) used
  (unified sv_id = slot + 64, so bit = sv_id - 65).
* 0x0A5 u64 galileo_svs_used_mask  bit i set  <=> Galileo E(i+1) used
  (unified sv_id = 300 + E-PRN, so bit = sv_id - 301).
  Each mask reproduces its constellation's SVs in the ``sv_signals`` table
  exactly (both directions), and ``popcount`` over the three ==
  ``n_svs_used_in_fix`` == AT nsat.  (v3 read this region as five u32 slots
  plus an ``unknown_bool_0xa9``; the "bool" was Galileo bit 32 = E33.)

===== reserved + week/tow + clock-bias =====
* 0x0AD..0x0C8  reserved (0); conventionally the BDS/QZSS/NavIC mask slots,
  never populated in this GPS+GLO+GAL corpus.
* 0x0C9 u32 const_1_0xc9 = 1.  0x0CD..0x118 reserved (0).
* 0x119 u32 const_1_0x119 = 1.  0x11D u32 const_0x0f = 0x0F.
* 0x121 u16 gps_week    Raw; mod-1024 when time is unresolved.
* 0x123 u32 gps_tow_ms  GPS time-of-week ms (< 604 800 000).
* 0x127 f32 receiver_clock_bias_ms  Session-quasi-constant, |value| < 0.5 ms
  in steady state; jumps by an integer 6..8 ms during time-uncertainty
  spikes (millisecond-ambiguity).
* 0x12B f32 time_unc    Time uncertainty; byte-identical to the copy at
  0x81A (8,061/8,061).
* 0x12F..0x136 reserved (0).

===== SV/signal used-in-fix table =====
* 0x137 u8 stale_pad_byte    Uninitialised (leftover heap/NMEA text).
* 0x138 u8 n_sv_signal_entries   Count of table entries below (3..30
  observed; capacity 176).
* 0x139 sv_signals[176], 10 bytes each, packed:
  ``{u32 signal_mask, u32 sv_system, u16 sv_id}``.
  signal_mask is always a single bit ∈ {0x01 GPS L1 C/A, 0x08 GPS L5,
  0x10 GLONASS G1, 0x40 Galileo E1, 0x80 Galileo E5a}; sv_system ∈
  {1 GPS, 2 Galileo, 5 GLONASS}; sv_id is the unified GNSS SV number.
  Entries beyond ``n_sv_signal_entries`` are zero-filled through 0x818
  (8,061/8,061).  A dual-signal SV (e.g. GPS L1+L5) appears as two entries
  but one mask bit — so ``n_sv_signal_entries`` >= ``n_svs_used_in_fix``.

===== time / clock status block =====
* 0x819 u8 gps_utc_leap_s = 18.
* 0x81A f32 time_unc_dup   == 0x12B.
* 0x81E u32 n_svs_used_in_fix  Unique SVs used in the fix (see masks/table).
* 0x822 u8 pad (0).
* 0x823 u64 time_since_boot_ns   ~1 GHz monotonic ns since boot; locked to
  ``qtimer_ticks`` (ratio 1e9/19.2e6 = 52.083).
* 0x82B u32 const_1_0x82b = 1.  0x82F u32 const_1_0x82f = 1.
* 0x833 f32 time_week_confidence  [0.01..0.99]; 0.01 whenever the GPS week
  is mod-1024-ambiguous, ramps to 0.99 once time is resolved.
* 0x837..0x856 reserved (0).
* 0x857 u64 qtimer_ticks_19p2mhz  19.2 MHz QTimer since power-on.
* 0x85F..0x866 reserved (0).

===== LOC client name + report tail =====
* 0x867 char[32] loc_client_name  ``atfwd_daemon<NNN>`` + NUL (16 bytes),
  the registered GNSS-LOC client (the AT+QGPS* forwarder daemon).  <NNN> is
  a small per-registration id (survives warm GNSS restart, changes on
  reboot, NOT unique).  Bytes 16..31 of this buffer (payload 0x877..0x886)
  are UNINITIALISED heap residue — frequently recycled bytes of the modem's
  own recent NMEA stream (verbatim-matched to the modem NMEA within ~15 s;
  a minor privacy leak).  This is the source of v3's ``nmea_fragments`` /
  ``subsystem_descriptor``; it carries NO report semantics.
* 0x887 u8 report_class_flag   1 = steady-state 1 Hz tracking fix (8,034);
  0 = provisional / asynchronous fix (27: 60 s single-shot, week-resync, or
  pre-convergence).  Same struct layout either way.
* 0x888 u8 const_0xff = 0xFF.  0x889..0x8A3 reserved (0).
* 0x8A4 u64 report_monotonic_ns   Monotonic ns latched at report assembly.
  On R03A03 it leads ``time_since_boot_ns`` by ~19 ms; on R03A04 it is a
  separate suspend-halting clock domain that can lag by hours — do NOT
  assume a fixed offset.
* 0x8AC u64 clock_unc_ns   65 ns steady state; 5,000,000 (5 ms) once, right
  after an airplane-mode clock re-init.  (u32+pad indistinguishable in
  corpus; u64 by analogy with the neighbours.)
* 0x8B4 u64 engine_start_monotonic_ns   The GNSS session key: monotonic ns
  latched at the most recent GNSS engine/session start.  Constant within a
  session, steps at a warm GNSS restart, resets on reboot.
* 0x8BC u32 const_2 = 2.

=== names-block:start (auto-generated by tools/inject_names_block_parsers.py) ===

Names by source (from sources/DIAG_LOG_INDEX.yaml):
    canonical: LOG_GNSS_CLIENT_API_LOCATION_REPORT
        source: qxdm_itemtype_list_zukgit_2025_04_03 (authority: community)
    aliases: (none recorded)

Source-precedence (#N): vendor_official > observation >
community (specification) > community (reference).
=== names-block:end ===
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


GNSS_LOC_REPORT_1C8F_SIZE = 2240
QMI_ATFWD_1C8F_SIZE = 2240  # legacy alias (kept for back-compat with v1 callers)
_VERSION_BYTE = 0x0A
_SPEC_BYTE = 0x07

# SV/signal used-in-fix table (0x139): 176 slots × 10 bytes, packed.
_SV_TABLE_OFFSET = 0x139
_SV_TABLE_STRIDE = 10
_SV_TABLE_CAPACITY = 176
_SV_TABLE_END = _SV_TABLE_OFFSET + _SV_TABLE_STRIDE * _SV_TABLE_CAPACITY  # 0x819

# LOC-client name buffer (0x867): char[32] = 16 B name + 16 B residue.
_NAME_OFFSET = 0x867
_NAME_LEN = 16
_RESIDUE_OFFSET = _NAME_OFFSET + _NAME_LEN  # 0x877
_RESIDUE_LEN = 16
_NAME_PREFIX = "atfwd_daemon"

# sv_system enum (observed {1,2,5}; conventional QMI-LOC values annotated).
_SV_SYSTEM_NAMES = {
    1: "GPS",
    2: "GALILEO",
    3: "SBAS",
    4: "COMPASS_BDS",
    5: "GLONASS",
    6: "QZSS",
    7: "NAVIC",
}
# signal_mask single-bit enum (observed {0x01,0x08,0x10,0x40,0x80}).
_SIGNAL_NAMES = {
    0x01: "GPS_L1CA",
    0x08: "GPS_L5",
    0x10: "GLONASS_G1",
    0x40: "GALILEO_E1",
    0x80: "GALILEO_E5A",
}
# Per-constellation unified-sv_id → mask-bit base (bit = sv_id - base).
_MASK_BASE = {1: 1, 5: 65, 2: 301}

# Embedded NMEA sentence-fragment marker inside the residue window. These are
# uninitialised-heap leakage, NOT a report field — surfaced only for the ASCII
# audit + privacy documentation. Truncated (16-byte window), never checksum-
# valid.
_NMEA_FRAGMENT = re.compile(rb"\$G[A-Z]{4},[\x20-\x7e]*")

# Unix-epoch ms of the GPS epoch (1980-01-06) and the GPS-UTC leap offset used
# by the on-wire utc_timestamp_ms identity.
_GPS_EPOCH_UNIX_MS = 315964800000
_WEEK_MS = 604800000
_LEAP_MS = 18000


@dataclass
class SvSignal:
    """One (SV, signal) entry from the used-in-fix table at 0x139."""

    signal_mask: int
    sv_system: int
    sv_id: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal_mask": self.signal_mask,
            "signal": _SIGNAL_NAMES.get(self.signal_mask, f"0x{self.signal_mask:02x}"),
            "sv_system": self.sv_system,
            "system": _SV_SYSTEM_NAMES.get(self.sv_system, str(self.sv_system)),
            "sv_id": self.sv_id,
        }


@dataclass
class Diag0x1C8F:
    """0x1C8F GNSS Client-API location report (2240 B, v=0x0A)."""

    log_time: int
    version: int
    motion_fix_state: int
    utc_timestamp_ms: int
    latitude_deg: float
    longitude_deg: float
    altitude_ellipsoid_m: float
    speed_2d_mps: float
    heading_deg: float
    horizontal_unc_m: float
    vertical_unc_m: float
    speed_unc_mps: float
    heading_unc_deg: float
    velocity_solution_marker: float
    altitude_msl_m: float
    pdop: float
    hdop: float
    vdop: float
    gdop: float
    tdop: float
    magnetic_deviation_deg: float
    horizontal_reliability: int
    vertical_reliability: int
    horiz_unc_semi_major_m: float
    horiz_unc_semi_minor_m: float
    horiz_unc_azimuth_deg: float
    horiz_unc_north_m: float
    horiz_unc_east_m: float
    vel_north_mps: float
    vel_east_mps: float
    vel_up_mps: float
    vel_unc_north_mps: float
    vel_unc_east_mps: float
    vel_unc_up_mps: float
    gps_svs_used_mask: int
    glonass_svs_used_mask: int
    galileo_svs_used_mask: int
    gps_week: int
    gps_tow_ms: int
    receiver_clock_bias_ms: float
    time_unc: float
    n_sv_signal_entries: int
    sv_signals: list[SvSignal]
    gps_utc_leap_s: int
    n_svs_used_in_fix: int
    time_since_boot_ns: int
    time_week_confidence: float
    qtimer_ticks_19p2mhz: int
    loc_client_name: str
    loc_client_instance: int
    name_buffer_residue: bytes
    nmea_fragments: list[str]
    report_class_flag: int
    report_monotonic_ns: int
    clock_unc_ns: int
    engine_start_monotonic_ns: int
    payload_size: int

    # --- derived helpers -------------------------------------------------
    def used_prns(self) -> dict[str, list[int]]:
        """Unified sv_ids used in the fix, per constellation, from the masks."""
        out: dict[str, list[int]] = {}
        for name, mask, base in (
            ("GPS", self.gps_svs_used_mask, 1),
            ("GLONASS", self.glonass_svs_used_mask, 65),
            ("GALILEO", self.galileo_svs_used_mask, 301),
        ):
            svs = [base + i for i in range(64) if (mask >> i) & 1]
            if svs:
                out[name] = svs
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x1C8F",
            "log_time": self.log_time,
            "version": self.version,
            "motion_fix_state": self.motion_fix_state,
            "utc_timestamp_ms": self.utc_timestamp_ms,
            "latitude_deg": self.latitude_deg,
            "longitude_deg": self.longitude_deg,
            "altitude_ellipsoid_m": self.altitude_ellipsoid_m,
            "altitude_msl_m": self.altitude_msl_m,
            "speed_2d_mps": self.speed_2d_mps,
            "heading_deg": self.heading_deg,
            "horizontal_unc_m": self.horizontal_unc_m,
            "vertical_unc_m": self.vertical_unc_m,
            "speed_unc_mps": self.speed_unc_mps,
            "heading_unc_deg": self.heading_unc_deg,
            "velocity_solution_marker": self.velocity_solution_marker,
            "pdop": self.pdop,
            "hdop": self.hdop,
            "vdop": self.vdop,
            "gdop": self.gdop,
            "tdop": self.tdop,
            "magnetic_deviation_deg": self.magnetic_deviation_deg,
            "horizontal_reliability": self.horizontal_reliability,
            "vertical_reliability": self.vertical_reliability,
            "horiz_unc_semi_major_m": self.horiz_unc_semi_major_m,
            "horiz_unc_semi_minor_m": self.horiz_unc_semi_minor_m,
            "horiz_unc_azimuth_deg": self.horiz_unc_azimuth_deg,
            "horiz_unc_north_m": self.horiz_unc_north_m,
            "horiz_unc_east_m": self.horiz_unc_east_m,
            "vel_north_mps": self.vel_north_mps,
            "vel_east_mps": self.vel_east_mps,
            "vel_up_mps": self.vel_up_mps,
            "vel_unc_north_mps": self.vel_unc_north_mps,
            "vel_unc_east_mps": self.vel_unc_east_mps,
            "vel_unc_up_mps": self.vel_unc_up_mps,
            "gps_svs_used_mask": self.gps_svs_used_mask,
            "glonass_svs_used_mask": self.glonass_svs_used_mask,
            "galileo_svs_used_mask": self.galileo_svs_used_mask,
            "used_prns": self.used_prns(),
            "gps_week": self.gps_week,
            "gps_tow_ms": self.gps_tow_ms,
            "receiver_clock_bias_ms": self.receiver_clock_bias_ms,
            "time_unc": self.time_unc,
            "n_sv_signal_entries": self.n_sv_signal_entries,
            "sv_signals": [sv.to_dict() for sv in self.sv_signals],
            "gps_utc_leap_s": self.gps_utc_leap_s,
            "n_svs_used_in_fix": self.n_svs_used_in_fix,
            "time_since_boot_ns": self.time_since_boot_ns,
            "time_week_confidence": self.time_week_confidence,
            "qtimer_ticks_19p2mhz": self.qtimer_ticks_19p2mhz,
            "loc_client_name": self.loc_client_name,
            "loc_client_instance": self.loc_client_instance,
            "name_buffer_residue": self.name_buffer_residue.hex(),
            "nmea_fragments": list(self.nmea_fragments),
            "report_class_flag": self.report_class_flag,
            "report_monotonic_ns": self.report_monotonic_ns,
            "clock_unc_ns": self.clock_unc_ns,
            "engine_start_monotonic_ns": self.engine_start_monotonic_ns,
            "payload_size": self.payload_size,
        }


def _read_name(data: bytes) -> tuple[str, int]:
    """Return (client name, small instance id) from the char[32] at 0x867."""
    raw = data[_NAME_OFFSET : _NAME_OFFSET + _NAME_LEN]
    null = raw.find(b"\x00")
    name = raw[: null if null != -1 else _NAME_LEN].decode("ascii", errors="replace")
    instance = -1
    if name.startswith(_NAME_PREFIX):
        suffix = name[len(_NAME_PREFIX) :]
        try:
            instance = int(suffix)
        except ValueError:
            instance = -1
    return name, instance


def _extract_nmea_fragments(residue: bytes) -> list[str]:
    """Embedded NMEA fragments inside the 16-byte name-buffer residue window.

    These are uninitialised heap leakage (recycled NMEA text), not a report
    field — always truncated, never checksum-valid. Surfaced for the ASCII
    audit + privacy documentation only.
    """
    return [m.group().decode("ascii", errors="replace")
            for m in _NMEA_FRAGMENT.finditer(residue)]


# --- Ground-truth recipe (#N) ---------------------------------------
# Authored offline (hw_run_performed=False) from the corpus RE + the paired
# AT+QGPSLOC / LG290P streams already present in the gnss_comparison captures.
# Field statuses are `partial` where a corpus AT/anchor cross-check already
# holds, `hypothesis` otherwise — per the ⛔ rule, only a fresh <redacted-ref>
# hardware run may promote these to `verified`. Keyed to the RM520N-GL (the
# only modem in the corpus that emits 0x1C8F).

@register(
    0x1C8F, domain="gnss",
    name="0x1C8F",
    description=(
        "GNSS Client-API location report (LOG_GNSS_CLIENT_API_LOCATION_"
        "REPORT) — 2240 B fixed, v=0x0A. Full flat little-endian position-fix "
        "struct: UTC-ms timestamp, f64 lat/lon/ellipsoidal-alt, MSL altitude, "
        "2D speed + course, five DOPs, position/velocity uncertainty ellipse, "
        "NEU velocity, three per-constellation used-SV u64 bitmasks (GPS/"
        "GLONASS/Galileo), a 176-slot SV/signal used-in-fix table, GPS "
        "week/TOW, boot/QTimer/session clocks, and the registered LOC-client "
        "name `atfwd_daemon<NNN>`. Quectel RM520N-GL SDX62 only in observed "
        "corpus (R03A03 + R03A04, byte-identical layout)."
    ),
    version=4,
    author="Claude Code",
    author_url="<redacted-issue-ref>",
    source_type="re",
    source_detail=(
        "v4 (2026-07-02, #N full-decode ultracode round, 8,061 records / 26 "
        "RM520N-GL captures, 5-lane RE + 5-lane adversarial verify, 100% "
        "parse): every byte of the 2240 B v=0x0A payload assigned. Key "
        "results (all 8,061/8,061 unless noted): u64 UTC-ms timestamp @0x03 "
        "(== GPS-epoch + week*604800000 + tow - 18000); f64 lat/lon @0x0B/0x13 "
        "(r=1.0000000 vs 0x1476 and vs AT+QGPSLOC 5 dp); altitude_msl @0x45 "
        "== AT altitude and hdop @0x4D == AT hdop and n_svs_used @0x81E == AT "
        "nsat, each 100% on 1,735 joins; three u64 used-SV masks @0x95/0x9D/"
        "0xA5 (bit=sv_id-{1,65,301}) reproducing the on-record SV table both "
        "directions; DOP quintet assignment the unique survivor of 120 "
        "permutations; uncertainty ellipse with a firmware deg-as-rad quirk on "
        "the N/E components. Retired v3 fields: session_id -> motion_fix_state "
        "(0x77 stationary / 0xFF moving / 0x33 velocity-invalid); "
        "record_token+record_counter+prefix -> the u64 timestamp; "
        "subsystem_descriptor/nmea_fragments -> uninitialised heap residue in "
        "the 16-byte tail of the char[32] client-name buffer (a privacy leak, "
        "not a report field); name offset fixed at 0x867 (the v1/v2 "
        "'12-byte variable shift' was a DLF-header-inclusive measurement "
        "artifact).\n"
        "v2 (2026-05-31): ASCII-lens re-id as LOG_GNSS_CLIENT_API_LOCATION_"
        "REPORT. v1 (2026-04-23): single-family RE, atfwd_daemon C-string."
    ),
    issues=(),
    fields_identified=60,
    fields_parsed=60,
    field_invariants={
        "version": {"enum": [_VERSION_BYTE]},
        "motion_fix_state": {"enum": [0x33, 0x77, 0xFF]},
        "horizontal_reliability": {"enum": [2, 3, 4]},
        "vertical_reliability": {"enum": [2, 3, 4]},
        "report_class_flag": {"enum": [0, 1]},
        "loc_client_name": {"required_populated": True},
    },
    # ASCII audit: the embedded LOC-client C-string `atfwd_daemon<NNN>`
    # (decoded as `loc_client_name`) is a fixed diagnostic label (frac 1.0);
    # plus `nmea` — recycled NMEA text in the uninitialised name-buffer residue
    # window (0x877), surfaced as `nmea_fragments` for the audit + privacy note.
    ascii_kinds=("label", "nmea"),
)
def parse_0x1c8f(log_time: int, data: bytes) -> Diag0x1C8F | None:
    if len(data) != GNSS_LOC_REPORT_1C8F_SIZE:
        return None
    # Layer-1 gate: version @0x00 and the spec byte @0x02 (both corpus-
    # invariant, and together reject foreign 2240-byte payloads).
    if data[0] != _VERSION_BYTE:
        return None
    if data[2] != _SPEC_BYTE:
        return None

    # --- record + time header ---
    motion_fix_state = data[1]
    utc_timestamp_ms = int.from_bytes(data[3:11], "little")

    (latitude_deg, longitude_deg, altitude_ellipsoid_m) = unpack_from("<3d", data, 0x0B)

    (speed_2d_mps, heading_deg, horizontal_unc_m, vertical_unc_m,
     speed_unc_mps, heading_unc_deg) = unpack_from("<6f", data, 0x23)

    velocity_solution_marker = unpack_from("<f", data, 0x3D)[0]
    altitude_msl_m = unpack_from("<f", data, 0x45)[0]
    (pdop, hdop, vdop, gdop, tdop) = unpack_from("<5f", data, 0x49)
    magnetic_deviation_deg = unpack_from("<f", data, 0x5D)[0]
    (horizontal_reliability, vertical_reliability) = unpack_from("<2I", data, 0x61)
    (horiz_unc_semi_major_m, horiz_unc_semi_minor_m, horiz_unc_azimuth_deg,
     horiz_unc_north_m, horiz_unc_east_m) = unpack_from("<5f", data, 0x69)
    (vel_north_mps, vel_east_mps, vel_up_mps,
     vel_unc_north_mps, vel_unc_east_mps, vel_unc_up_mps) = unpack_from("<6f", data, 0x7D)

    (gps_svs_used_mask,) = unpack_from("<Q", data, 0x95)
    (glonass_svs_used_mask,) = unpack_from("<Q", data, 0x9D)
    (galileo_svs_used_mask,) = unpack_from("<Q", data, 0xA5)

    (gps_week,) = unpack_from("<H", data, 0x121)
    (gps_tow_ms,) = unpack_from("<I", data, 0x123)
    receiver_clock_bias_ms = unpack_from("<f", data, 0x127)[0]
    time_unc = unpack_from("<f", data, 0x12B)[0]

    # --- SV/signal used-in-fix table ---
    n_sv_signal_entries = data[0x138]
    n = min(n_sv_signal_entries, _SV_TABLE_CAPACITY)
    sv_signals: list[SvSignal] = []
    for i in range(n):
        off = _SV_TABLE_OFFSET + i * _SV_TABLE_STRIDE
        mask, system = unpack_from("<2I", data, off)
        (sv_id,) = unpack_from("<H", data, off + 8)
        sv_signals.append(SvSignal(signal_mask=mask, sv_system=system, sv_id=sv_id))

    # --- time / clock status block ---
    gps_utc_leap_s = data[0x819]
    (n_svs_used_in_fix,) = unpack_from("<I", data, 0x81E)
    (time_since_boot_ns,) = unpack_from("<Q", data, 0x823)
    time_week_confidence = unpack_from("<f", data, 0x833)[0]
    (qtimer_ticks_19p2mhz,) = unpack_from("<Q", data, 0x857)

    # --- LOC client name + report tail ---
    loc_client_name, loc_client_instance = _read_name(data)
    name_buffer_residue = bytes(data[_RESIDUE_OFFSET : _RESIDUE_OFFSET + _RESIDUE_LEN])
    nmea_fragments = _extract_nmea_fragments(name_buffer_residue)

    report_class_flag = data[0x887]
    (report_monotonic_ns,) = unpack_from("<Q", data, 0x8A4)
    (clock_unc_ns,) = unpack_from("<Q", data, 0x8AC)
    (engine_start_monotonic_ns,) = unpack_from("<Q", data, 0x8B4)

    return Diag0x1C8F(
        log_time=log_time,
        version=data[0],
        motion_fix_state=motion_fix_state,
        utc_timestamp_ms=utc_timestamp_ms,
        latitude_deg=latitude_deg,
        longitude_deg=longitude_deg,
        altitude_ellipsoid_m=altitude_ellipsoid_m,
        speed_2d_mps=speed_2d_mps,
        heading_deg=heading_deg,
        horizontal_unc_m=horizontal_unc_m,
        vertical_unc_m=vertical_unc_m,
        speed_unc_mps=speed_unc_mps,
        heading_unc_deg=heading_unc_deg,
        velocity_solution_marker=velocity_solution_marker,
        altitude_msl_m=altitude_msl_m,
        pdop=pdop,
        hdop=hdop,
        vdop=vdop,
        gdop=gdop,
        tdop=tdop,
        magnetic_deviation_deg=magnetic_deviation_deg,
        horizontal_reliability=horizontal_reliability,
        vertical_reliability=vertical_reliability,
        horiz_unc_semi_major_m=horiz_unc_semi_major_m,
        horiz_unc_semi_minor_m=horiz_unc_semi_minor_m,
        horiz_unc_azimuth_deg=horiz_unc_azimuth_deg,
        horiz_unc_north_m=horiz_unc_north_m,
        horiz_unc_east_m=horiz_unc_east_m,
        vel_north_mps=vel_north_mps,
        vel_east_mps=vel_east_mps,
        vel_up_mps=vel_up_mps,
        vel_unc_north_mps=vel_unc_north_mps,
        vel_unc_east_mps=vel_unc_east_mps,
        vel_unc_up_mps=vel_unc_up_mps,
        gps_svs_used_mask=gps_svs_used_mask,
        glonass_svs_used_mask=glonass_svs_used_mask,
        galileo_svs_used_mask=galileo_svs_used_mask,
        gps_week=gps_week,
        gps_tow_ms=gps_tow_ms,
        receiver_clock_bias_ms=receiver_clock_bias_ms,
        time_unc=time_unc,
        n_sv_signal_entries=n_sv_signal_entries,
        sv_signals=sv_signals,
        gps_utc_leap_s=gps_utc_leap_s,
        n_svs_used_in_fix=n_svs_used_in_fix,
        time_since_boot_ns=time_since_boot_ns,
        time_week_confidence=time_week_confidence,
        qtimer_ticks_19p2mhz=qtimer_ticks_19p2mhz,
        loc_client_name=loc_client_name,
        loc_client_instance=loc_client_instance,
        name_buffer_residue=name_buffer_residue,
        nmea_fragments=nmea_fragments,
        report_class_flag=report_class_flag,
        report_monotonic_ns=report_monotonic_ns,
        clock_unc_ns=clock_unc_ns,
        engine_start_monotonic_ns=engine_start_monotonic_ns,
        payload_size=len(data),
    )
