"""0x1383 — CGPS PDSM extended-status POSITION report.

`LOG_CGPS_PDSM_EXT_STATUS_POS_REPORT_C`: the gpsOne PD layer's position report,
committed once per position report (final fix, intermediate fix, or a
no-GNSS TLE / seed position). Split from `lte_misc.py` because the old
"LTE status" description was wrong; this is a GNSS code.

## v4 — full semantic decode, three versions

Byte 0 is a **version**, not the `entry_count` earlier sessions assumed. Three
values occur, each with its own size and tail layout (corpus, sidecar census,
deduped by capture sha256):

  version  size  records  captures  silicon
  0x08     150B  98,995   351       MDM9x50 / SDX20 / SDX55 / SDX62 / SDX65 ...
  0x32     125B     811     7       MC7700 (MDM9200, SWI9200X)
  0x05     141B      40     2       MC7455 (MDM9x30)

Common layout [0:75] (identical on all three versions):

  [ 0]     version            u8   {0x05, 0x08, 0x32}
  [ 1- 4]  client_id          u32  PDSM client handle: 3491 (0x0DA3) on
                                   v05/v08, 9001 (0x2329) on v32. 3491 ==
                                   F3 `loc_pd_ext_event_cb ... client_id 3491`
                                   (sibling 0x1378). v32 is the
                                   first differing-client value seen.
  [ 5- 8]  lat_is801          i32  LSB 180/2^25 deg (IS-801 resolution)
  [ 9-12]  lon_is801          i32  LSB 180/2^25 deg
  [13-16]  time_stamp_s       u32  GPS seconds since 1980-01-06. When GPS
                                   time is invalid (opt mask 0x20 clear) this
                                   is a fixed seed 980,862,337 (2011-02-04
                                   13:45:19 GPST) + elapsed seconds.
  [17]     loc_unc_ang        u8   CANDIDATE (uncertainty-ellipse angle)
  [18]     loc_unc_a          u8   IS-801 uncertainty index, along-axis
  [19]     loc_unc_p          u8   IS-801 uncertainty index, perpendicular;
                                   0x1F = beyond 12,288 m / not computable
  [20]     opt_field_mask     u8   see OPT_* below
  [21-22]  altitude_raw       i16  HAE metres + 500
  [23-24]  heading_raw        u16  LSB 360/1024 deg
  [25-26]  velocity_hor_raw   u16  LSB 0.25 m/s
  [27]     byte_27            u8   CANDIDATE fix_type (0/1)
  [28]     velocity_ver_raw   i8   CANDIDATE (IS-801 0.5 m/s), always 0 seen
  [29]     loc_unc_v          u8   CANDIDATE IS-801 vertical-uncertainty idx
  [30-33]  byte_30..byte_33   raw  ([30]=0x02 on 98,951/98,995; [31] in
                                   {0x41,0x43,0xC1,0x60}) — meaning open
  [34]     utc_leap_s         u8   GPS-UTC leap seconds; meaningful only when
                                   opt mask 0x04 is set (18 on every such
                                   record; 15 = stale MC7700 default)
  [35-38]  lat_ext            i32  LSB pi/2^32 rad (= 180/2^32 deg)
  [39-42]  lon_ext            i32  LSB pi/2^31 rad (= 180/2^31 deg)
  [43-44]  ext_unc_a_m        u16  along-axis uncertainty, metres (0xFFFF
                                   invalid). loc_unc_a is its IS-801 ceiling
  [45-46]  ext_unc_p_m        u16  perpendicular uncertainty, metres
  [47-50]  speed_hor_cms      i32  horizontal speed, cm/s
  [51-54]  vel_ver_cms        i32  CANDIDATE vertical velocity, cm/s
  [55-58]  gps_tow_ms         u32  GPS time of week, ms
  [59-60]  gps_week           u16  0xFFFF = invalid. Legacy firmware
                                   (MC7700, RM520 R03A03) reports the
                                   1024-week-rolled value
  [61-74]  tail_61            14B  raw — meaning open
  [75-78]  hdop_x10           u32  DOP x10; 0 = no fix, >=5000 = sentinel
  [79-82]  pdop_x10           u32
  [83-86]  vdop_x10           u32

Version-specific tail:
  v0x08:  [87-90] tdop_x10 u32, [91-94] gdop_x10 u32, [95-149] tail raw
  v0x05:  [87-140] tail raw
  v0x32:  [87-124] tail raw

opt_field_mask bits (per-record co-occurrence, 6 fix-rich + 40 diverse captures):
  0x01  altitude present
  0x02  velocity-of-this-fix flag. Clear on every record where F3 says
        "Velocity fix failed" (451/451) — but one-directional: 192 v08 and
        6 v05 records carry non-zero velocity with it clear, so the
        velocity fields are exposed unconditionally
  0x04  utc_leap_s valid
  0x20  GPS week/TOW valid (one-directional: set => valid on 3452/3452 v08,
        450/450 v32, 11/11 v05; a few records have it clear yet a valid week)
  0x08, 0x10 meaning open (0x10 always set); 0x40/0x80 never seen

## Ground truth (F3-VERDICT per version)

v0x32 (MC7700 gnss_comparison capture, 301 records, 1 Hz NMEA GGA/GSA
join on time_stamp_s - 18 leap):
  * lat_ext/lon_ext vs GGA: <= 1 cm (301/301); lat/lon_is801 within the
    0.6 m quantum; altitude_raw - 500 vs GGA MSL + geoid sep: +/-0.5 m
  * hdop/pdop/vdop_x10 == NMEA HDOP/PDOP/VDOP x 10 exactly, 301/301
  * time_stamp_s and gps_week/gps_tow_ms both land on the NMEA epoch
    (1024-week-rolled firmware)
  * F3/0x60: the MC7700 captures carry no 0x79/0x99 F3 (oracle absent)

v0x08 (RM520 / SIM8202 / EM9291 / FN980 / ...):
  * F3 1:1 — an RM520 wardrive (451 records, clean single-writer
    capture): "Velocity fix failed", "TM: tm_util_get_fix_time()
    failed. GPS 0", "locPd_FillTimestampUtc: time is invalid" and "GPS/GLO
    time both invalid ... GPSWeek=65535" each fire exactly 451x. Every
    record has opt mask 0x1d (bit 0x02 clear, velocity bytes zero),
    gps_week == 0xFFFF and loc_unc_a 0x1F; position is the seed (115) or
    a coarse non-GNSS position (336). (The same 1:1 shows 537/537 on a
    second drive, but that capture is a two-writer splice and is not
    cited as evidence.)
  * 0x60: EVENT_GNSS_ME_MULTIPATH_ENV_IND (3204) fires 451/451 on the same
    capture (co-cadenced; 9-byte ME payload, labels no 0x1383 field);
    GPS_PD_SESSION/FIX START/END bracket the session (2x each).
  * NMEA (RM520 gnss_comparison capture): 9/9 session-final fixes within
    5-13 m of the next-epoch GGA (the 0x1383 epoch itself precedes NMEA's
    first fix); IS-801 and ext lat/lon agree to 0.2 m.
  * Kinematics: speed_hor_cms matches 1 Hz displacement of consecutive fixes
    (14.15 vs 14.27, 5.71 vs 5.67 m/s; median heading error 9.9 deg, n=17);
    speed_hor_cms/100 vs velocity_hor_raw*0.25 agree to 0.1 m/s.
  * DOP algebra: PDOP^2 = HDOP^2 + VDOP^2 and GDOP^2 = PDOP^2 + TDOP^2 hold
    on 330/330 populated records (+/-1.5 rounding).
  * gps_week = 2415 / gps_tow_ms land on the drive's own wall clock.
  * Seed position (38.0, -117.0) with loc_unc_a 0x1F is a firmware default
    (184/252 records on one RM520 drive), not a fix.

v0x05 (MC7455, 40 records / 2 captures): structure only — same [0:87]
layout (DOP identity 2/2, leap 18 under bit 0x04 11/11). No co-temporal
NMEA or F3 in either capture.

## Raw tails (v6, the Kaitai audit)

`tail_61` [61:75] and `tail_raw` carry live bytes on the committed fixtures:
tail_61 [62:66] / [66:70] differ by chipset, and v0x08 [95:107] / [138:142]
vary per record. F3 is silent on them (the PD / TM sites that fire 1:1 label
only the time and velocity validity; 0x60 event 3204 labels no field), so they
stay raw, not split into invented named words. Until v5 they were on the
dataclass but missing from `to_dict()`, so every JSON consumer lost them; v6
emits both as hex (the 0x1C8F `name_buffer_residue` convention). An
independent Kaitai layout of all three versions diffs both against this
parser.

## Superseded claims

* "byte 0 = entry_count, version_less" — refuted: three
  version values, three sizes, three layouts, no repeated entries.
* "[1:3] = 0xA30D family magic" — it is the low half of the u32 client_id;
  v0x32 carries 9001, so the old gate rejected every MC7700 record.
* "0x1389 / 0x03E9 at [1:5] are HDLC misframes" —
  refuted: they are the SIM7600NA / T99W175 PDSM client_ids, and both
  records decode to a plausible fix. v5 accepts them.
* "const_byte_30 == 0x02" — 44 of 98,995 v0x08 records carry 0x00.

Log name: LOG_CGPS_PDSM_EXT_STATUS_POS_REPORT_C
Also known as: LOG_CGPS_PDSM_EXTENDED_STATUS_POSITION_REPORT, LOG_INTERNAL_CGPS_PDSM_EXTENDED_STATUS_POSITION_REPORT, LOG_SNSD_DEVICE_DOWN
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.parsers._pdsm_client_ids import PDSM_CLIENT_IDS
from diaggrok.registry import register

V05_VERSION = 0x05
V08_VERSION = 0x08
V32_VERSION = 0x32
_SIZES = {V05_VERSION: 141, V08_VERSION: 150, V32_VERSION: 125}
_CLIENT_IDS = tuple(sorted(PDSM_CLIENT_IDS))

OPT_ALTITUDE = 0x01
OPT_VELOCITY = 0x02
OPT_UTC_LEAP = 0x04
OPT_GPS_TIME = 0x20

# Corpus-validated invariant-zero runs on the 150B/141B layouts (N=17,304).
# Not asserted on v0x32, whose tail differs.
_RESERVED_RUNS = ((71, 74), (120, 128), (134, 137))
_RESERVED_RUNS_150 = ((142, 149),)

_IS801_DEG = 180.0 / (1 << 25)


@dataclass
class Diag0x1383:
    """CGPS PDSM extended-status position report (0x1383)."""
    log_time: int
    version: int
    client_id: int
    lat_is801: int
    lon_is801: int
    time_stamp_s: int
    loc_unc_ang: int
    loc_unc_a: int
    loc_unc_p: int
    opt_field_mask: int
    altitude_raw: int
    heading_raw: int
    velocity_hor_raw: int
    byte_27: int
    velocity_ver_raw: int
    loc_unc_v: int
    byte_30: int
    byte_31: int
    byte_32: int
    byte_33: int
    utc_leap_s: int
    lat_ext: int
    lon_ext: int
    ext_unc_a_m: int
    ext_unc_p_m: int
    speed_hor_cms: int
    vel_ver_cms: int
    gps_tow_ms: int
    gps_week: int
    tail_61: bytes
    hdop_x10: int
    pdop_x10: int
    vdop_x10: int
    tdop_x10: int | None
    gdop_x10: int | None
    tail_raw: bytes
    body_reserved_zeros_ok: bool | None
    payload_size: int

    @property
    def lat_deg(self) -> float:
        return self.lat_ext * 180.0 / (1 << 32)

    @property
    def lon_deg(self) -> float:
        return self.lon_ext * 180.0 / (1 << 31)

    @property
    def altitude_hae_m(self) -> int | None:
        return self.altitude_raw - 500 if self.opt_field_mask & OPT_ALTITUDE else None

    @property
    def heading_deg(self) -> float:
        return self.heading_raw * 360.0 / 1024

    @property
    def speed_hor_mps(self) -> float:
        return self.speed_hor_cms / 100.0

    @property
    def gps_time_valid(self) -> bool:
        return bool(self.opt_field_mask & OPT_GPS_TIME) and self.gps_week != 0xFFFF

    @property
    def position_known(self) -> bool:
        return self.loc_unc_a != 0x1F

    def to_dict(self) -> dict[str, Any]:
        def dop(v: int | None) -> float | None:
            return None if v is None or v == 0 or v >= 5000 else v / 10.0
        return {
            'type': 'Diag0x1383',
            'log_time': self.log_time,
            'version': self.version,
            'client_id': self.client_id,
            'lat_deg': self.lat_deg,
            'lon_deg': self.lon_deg,
            'lat_is801_deg': self.lat_is801 * _IS801_DEG,
            'lon_is801_deg': self.lon_is801 * _IS801_DEG,
            'time_stamp_s': self.time_stamp_s,
            'loc_unc_ang': self.loc_unc_ang,
            'loc_unc_a': self.loc_unc_a,
            'loc_unc_p': self.loc_unc_p,
            'loc_unc_v': self.loc_unc_v,
            'opt_field_mask': self.opt_field_mask,
            'altitude_hae_m': self.altitude_hae_m,
            'heading_deg': self.heading_deg,
            'velocity_hor_mps': self.velocity_hor_raw * 0.25,
            'speed_hor_mps': self.speed_hor_mps,
            'vel_ver_cms': self.vel_ver_cms,
            'byte_27': self.byte_27,
            'velocity_ver_raw': self.velocity_ver_raw,
            'byte_30': self.byte_30,
            'byte_31': self.byte_31,
            'byte_32': self.byte_32,
            'byte_33': self.byte_33,
            'utc_leap_s': (self.utc_leap_s
                           if self.opt_field_mask & OPT_UTC_LEAP else None),
            'ext_unc_a_m': None if self.ext_unc_a_m == 0xFFFF else self.ext_unc_a_m,
            'ext_unc_p_m': None if self.ext_unc_p_m == 0xFFFF else self.ext_unc_p_m,
            'gps_week': None if self.gps_week == 0xFFFF else self.gps_week,
            'gps_tow_ms': self.gps_tow_ms,
            'gps_time_valid': self.gps_time_valid,
            'position_known': self.position_known,
            'hdop': dop(self.hdop_x10),
            'pdop': dop(self.pdop_x10),
            'vdop': dop(self.vdop_x10),
            'tdop': dop(self.tdop_x10),
            'gdop': dop(self.gdop_x10),
            # v6: raw, not named — live on real records, F3-silent.
            'tail_61': self.tail_61.hex(),
            'tail_raw': self.tail_raw.hex(),
            'body_reserved_zeros_ok': self.body_reserved_zeros_ok,
            'payload_size': self.payload_size,
        }


def _reserved_zeros_ok(data: bytes) -> bool | None:
    """True if every corpus-validated reserved run is all-zero (v05/v08 only)."""
    if data[0] == V32_VERSION:
        return None
    runs = _RESERVED_RUNS
    if len(data) == 150:
        runs = runs + _RESERVED_RUNS_150
    return all(data[a:b + 1] == b'\x00' * (b - a + 1) for a, b in runs)


@register(0x1383, domain="gnss",
    primary_issue=None,
    name="0x1383",
    description=(
        "CGPS PDSM extended-status position report (0x1383) — v0x08 150B "
        "(MDM9x50/SDX20/SDX55/SDX62), v0x05 141B (MC7455), v0x32 125B "
        "(MC7700). Position (IS-801 and pi/2^32 forms), GPS time, IS-801 + "
        "metre uncertainties, altitude, heading, speed, GPS week/TOW, "
        "leap seconds, H/P/V(/T/G) DOP, PDSM client_id."
    ),
    version=6,
    author="Luke Jenkins", author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE. v4: byte0 is a version (0x05/0x08/0x32, three "
        "sizes, three layouts; refutes the v3 entry_count/version_less "
        "claim). Grounded on NMEA GGA/GSA (v0x32 301/301), F3 1:1 sites "
        "(v0x08 451/451), kinematics and DOP algebra (330/330)"
    ),
    issues=(),
    # 34 named fields (incl. tdop/gdop on v08) + 2 raw regions (tail_61,
    # tail_raw). Raw-named bytes (byte_27/30-33) and CANDIDATEs are parsed
    # but their meaning is open.
    fields_identified=36, fields_parsed=36,
    supported_versions=frozenset({V05_VERSION, V08_VERSION, V32_VERSION}),
    field_invariants={
        "version": {"enum": [V05_VERSION, V08_VERSION, V32_VERSION]},
        "client_id": {"enum": list(_CLIENT_IDS)},
        "byte_30": {"enum": [0x00, 0x02]},
        "lat_deg": {"range": (-90.0, 90.0)},
        "lon_deg": {"range": (-180.0, 180.0)},
    },
    wigle_direct=True,
    wigle_roles=("position", "gnss-quality", "timing-anchor:on-fix"),
    timebase_roles=("absolute-time",))
def parse_0x1383(log_time: int, data: bytes) -> Diag0x1383 | None:
    if len(data) < 87:
        return None
    if data[0] not in (V05_VERSION, V08_VERSION, V32_VERSION):
        return None
    if _SIZES[data[0]] != len(data):
        return None
    client_id = unpack_from('<I', data, 1)[0]
    # Layer-1 gate: the PDSM client_id. The two v0x08 records carrying
    # 0x1389 (SIM7600NA) / 0x03E9 (T99W175), once read as HDLC misframes,
    # are real records from other PDSM clients.
    if client_id not in _CLIENT_IDS:
        return None
    v08 = data[0] == V08_VERSION
    return Diag0x1383(
        log_time=log_time,
        version=data[0],
        client_id=client_id,
        lat_is801=unpack_from('<i', data, 5)[0],
        lon_is801=unpack_from('<i', data, 9)[0],
        time_stamp_s=unpack_from('<I', data, 13)[0],
        loc_unc_ang=data[17],
        loc_unc_a=data[18],
        loc_unc_p=data[19],
        opt_field_mask=data[20],
        altitude_raw=unpack_from('<h', data, 21)[0],
        heading_raw=unpack_from('<H', data, 23)[0],
        velocity_hor_raw=unpack_from('<H', data, 25)[0],
        byte_27=data[27],
        velocity_ver_raw=unpack_from('<b', data, 28)[0],
        loc_unc_v=data[29],
        byte_30=data[30],
        byte_31=data[31],
        byte_32=data[32],
        byte_33=data[33],
        utc_leap_s=data[34],
        lat_ext=unpack_from('<i', data, 35)[0],
        lon_ext=unpack_from('<i', data, 39)[0],
        ext_unc_a_m=unpack_from('<H', data, 43)[0],
        ext_unc_p_m=unpack_from('<H', data, 45)[0],
        speed_hor_cms=unpack_from('<i', data, 47)[0],
        vel_ver_cms=unpack_from('<i', data, 51)[0],
        gps_tow_ms=unpack_from('<I', data, 55)[0],
        gps_week=unpack_from('<H', data, 59)[0],
        tail_61=bytes(data[61:75]),
        hdop_x10=unpack_from('<I', data, 75)[0],
        pdop_x10=unpack_from('<I', data, 79)[0],
        vdop_x10=unpack_from('<I', data, 83)[0],
        tdop_x10=unpack_from('<I', data, 87)[0] if v08 else None,
        gdop_x10=unpack_from('<I', data, 91)[0] if v08 else None,
        tail_raw=bytes(data[95:] if v08 else data[87:]),
        body_reserved_zeros_ok=_reserved_zeros_ok(data),
        payload_size=len(data),
    )
