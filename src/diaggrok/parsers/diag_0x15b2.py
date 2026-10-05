"""0x15B2 — LOG_GNSS_PDSM_EXT_STATUS_BEST_AVAILABLE_INFO, 352B v=0x08.

The **response** half of the PDSM "best available position" query: the request
is logged as sibling **0x15B1** (``pdsm_pd_get_best_avail_pos()``) and
this record carries the position the engine hands back, ~0–1 ms later (4/4
request→response pairs in the corpus). ``[1:9]`` is byte-identical to 0x15B1's.

Name: ``LOG_GNSS_PDSM_EXT_STATUS_BEST_AVAILABLE_INFO`` (from a community
log-name table).

## Layout (v=0x08, 352 bytes)

After a 10-byte head the body is a **packed ``(valid u8, value)`` list** — the
shape of a QMI-IDL C struct (``uint8_t foo_valid; T foo;``, pack(1)). 32 valid
bytes, at [10 19 28 33 38 43 48 50 55 60 65 70 75 80 82 87 92 97 102 107 112 117
122 127 132 141 143 148 153 162 327 329]. A field whose valid byte is 0 decodes
to ``None``; the raw 32 bytes are kept as ``valid_flags``.

  [  0]      version                        u8   = 0x08 (Layer-1 gate)
  [  1:  5]  client_id                      u32  PDSM client (3491) — GROUND via 0x15B1
  [  5:  9]  cand_client_data_ptr           u32  CANDIDATE (mirrors 0x15B1 [5:9])
  [  9]      raw_09                         u8   0 on every record
  [ 11: 19]  lat_deg                        f64  GROUND  (F3 + 0x1476)
  [ 20: 28]  lon_deg                        f64  GROUND  (F3 + 0x1476)
  [ 29: 33]  hor_unc_circular_m             f32  GROUND  (F3 unc_cir / PUNC)
  [ 34: 38]  hor_unc_ellipse_semi_major_m   f32  GROUND  (F3 unc_semi_maj)
  [ 39: 43]  hor_unc_ellipse_semi_minor_m   f32  GROUND  (F3 unc_semi_min)
  [ 44: 48]  cand_hor_unc_ellipse_orient_deg f32 CANDIDATE
  [ 49]      cand_hor_ellipse_confidence_pct u8  CANDIDATE (63 on all 4)
  [ 51: 55]  hor_reliability                u32  GROUND  (F3 rel_value)
  [ 56: 60]  unk_56_f32                     f32  raw (0, 0, 1.0, 0)
  [ 61: 65]  hor_speed_mps                  f32  GROUND  (0x1476 speed_mps)
  [ 66: 70]  altitude_hae_m                 f32  GROUND  (0x1476 alt_m; F3 altitude)
  [ 71: 75]  altitude_plus500_m             f32  == altitude_hae_m + 500.0 exactly, 4/4
  [ 76: 80]  cand_vert_unc_m                f32  CANDIDATE (F3 unc_altitude, n=1)
  [ 81]      cand_vert_confidence_pct       u8   CANDIDATE (68 on all 4)
  [ 83: 87]  cand_vert_reliability          u32  CANDIDATE
  [ 88: 92]  vert_speed_mps                 f32  GROUND  (0x1476 vel_u)
  [ 93: 97]  unk_93_f32                     f32  raw — == [76:80] on 4/4
  [ 98:102]  heading_deg                    f32  GROUND  (0x1476 heading_deg)
  [103:107]  heading_unc_deg                f32  GROUND  (0x1476 heading_unc_deg)
  [108:112]  cand_magnetic_deviation_deg    f32  CANDIDATE (0 on all 4)
  [113:117]  cand_technology_mask           u32  CANDIDATE (1 GNSS fix / 2 cell seed)
  [118:122]  pdop                           f32  GROUND  (0x1476 pdop)
  [123:127]  hdop                           f32  GROUND  (0x1476 hdop)
  [128:132]  vdop                           f32  GROUND  (0x1476 vdop)
  [133:141]  timestamp_utc_ms               u64  GROUND  (== GPS time − 18 s leap)
  [142]      unk_142                        u8   raw (126, 126, 126, 237)
  [144:148]  cand_time_unc_ms               f32  CANDIDATE
  [149:153]  cand_time_src                  u32  CANDIDATE (14 propagated / 7 fresh fix)
  [154:162]  cand_sensor_usage_raw          8B   CANDIDATE (all-zero on all 4)
  [163:167]  sv_used_count                  u32  GROUND  (0x1476 gps.used)
  [167:327]  sv_used_list                   u16[80], first sv_used_count — GROUND (0x1476 gps.prns)
  [328]      cand_hor_cir_confidence_pct    u8   CANDIDATE (39 on all 4)
  [330:332]  gps_week                       u16  GROUND  (0x1476 gps_week)
  [332:336]  gps_tow_ms                     u32  GROUND  (F3 tod_ms + 0x1476 gps_tow_ms)
  [336:352]  tail_raw                       16B  all-zero on every record

## F3 grounding (v0x08)

Two independent in-capture oracles, one per chipset, on different fix types:

* **LM960A18 (SDX20) drive capture — F3.** The consumer, LTE RRC
  building an RLF report, prints its decoded copy of this exact response
  (``lte_rrc_loc_services.c:1765-1801``) in the same tick as the record, right
  after ``loc_pd.c:5694 "Received best available position"``:
  ``rel_value 3`` == [51:55]; ``lat_degree``/``lon`` (3GPP GAD) == [11:19]/[20:28]
  to <3e-5°; ``altitude 0`` == [66:70]; ``unc_cir 2287012`` == [29:33]
  (2287012.25; also ``tm_core PUNC:2287012``); ``unc_semi_maj``/``unc_semi_min
  1617161`` == [34:38]/[39:43]; ``ori_maj_axi 0`` == [44:48];
  ``unc_altitude 14`` == [76:80] (14.43); ``tod_ms 808572`` == [332:336]
  gps_tow_ms 227608572 **mod 3 600 000** (3GPP gnss-TOD-msec is TOW mod 1 h).
  That record is a coarse cell seed (≈2,287 km unc, SV list empty,
  technology_mask 2); RRC rejected it (``la_min accuracy not satisfied``).
* **MC7411 (MDM9x50) GNSS comparison capture — 0x1476.** Every
  0x15B2 is co-emitted with a 0x1476 GNSS position report carrying the
  **identical log_time** (3/3), and the two agree **bit-exactly**: lat/lon
  (Δ 0.0000 m), alt_m, heading, heading_unc, speed, vel_u, PDOP/HDOP/VDOP,
  gps_week/gps_tow_ms, and the used-SV PRN list [1,14,17,19,20,22]. 0x1476 is
  itself grounded against an LG290P reference (alt_m is HAE; position
  2.84 m median), so these fields chain to external truth. The
  ``AT!GPSLOC?`` poll of the same session agrees too (lat Δ 0.7 m; LocUncA/
  LocUncP 16/3 m vs semi-major/minor 16.48/3.84 m).

Internal identities, all 4 records: ``hor_unc_circular = hypot(semi_major,
semi_minor)`` (16.92 = √(16.48²+3.84²); LM960 √2·1617161.75 = 2287012);
``pdop² = hdop² + vdop²``; ``altitude_plus500 − altitude_hae = 500.0``;
``gps_time − timestamp_utc = 18 s`` (±9 ms — UTC is 10 ms-quantised).

Oracle notes: ``0x60`` carries no field (on the LM960 the trigger is
``EVENT_LTE_RRC_RADIO_LINK_FAILURE``, id 1608, at dt 0 — see 0x15B1);
qcsuper/SCAT do not decode 0x15B2 (absent). The MC7411 capture has no F3.

## Open / CANDIDATE

* **Every valid byte is 1 on every record** — even the LM960's heading, which
  holds −57238.5° and which RRC itself treats as absent (``hor_velocity_valid
  0``). The flag is kept for fidelity but is not evidence of a field's validity.
* ``cand_vert_unc_m``: the LM960 F3 match is one record (14 vs 14.43), and the
  MC7411 values (0.24–0.90 m) disagree with that session's AT ``LocUncVe 8.0``.
  ``unk_93_f32`` equals it on 4/4.
* Orientation 0 == F3 ``ori_maj_axi 0`` is a 0 == 0 match and may be
  coincidental; the MC7411's 145° vs AT ``LocUncAngle 0.0`` is unexplained.
* ``cand_time_src`` 7/14 tracks 0x1476 ``pos_source`` 2/8 (fresh fix vs
  propagated) but is not equal to it; the numbers match QMI-LOC TIME_SRC
  NAV_SOLUTION / SYSTEM_TIMETICK, which is not an in-capture oracle.
* The 0x15B2 struct is not the QMI-LOC indication itself: ``loc_task.c``
  allocates 448 bytes for that alongside the log.

## Corpus

4 records / 2 sessions, all 352 B, all v=0x08:

  * Sierra MC7411 (MDM9x50), a GNSS comparison capture — 3 (6-SV GPS fix)
  * Telit LM960A18 (SDX20), a drive capture — 1 (cell seed)

Size-invariance ≠ format-invariance: the Layer-1 ``version`` gate rejects a
future layout at the same length rather than mis-decoding it. PII: lat/lon are
the device's real position — decoded in full; fixtures carry a 0.0/0.0 sentinel.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_GNSS_PDSM_EXT_STATUS_BEST_AVAILABLE_INFO
from diaggrok.registry import register

_SIZE = 352
_VERSION = 0x08
_SV_LIST_OFF = 167
_SV_LIST_MAX = 80

# (name, valid-byte offset, struct fmt) — the value follows its valid byte.
_VALUED: tuple[tuple[str, int, str], ...] = (
    ('lat_deg',                         10, '<d'),
    ('lon_deg',                         19, '<d'),
    ('hor_unc_circular_m',              28, '<f'),
    ('hor_unc_ellipse_semi_major_m',    33, '<f'),
    ('hor_unc_ellipse_semi_minor_m',    38, '<f'),
    ('cand_hor_unc_ellipse_orient_deg', 43, '<f'),
    ('cand_hor_ellipse_confidence_pct', 48, '<B'),
    ('hor_reliability',                 50, '<I'),
    ('unk_56_f32',                      55, '<f'),
    ('hor_speed_mps',                   60, '<f'),
    ('altitude_hae_m',                  65, '<f'),
    ('altitude_plus500_m',              70, '<f'),
    ('cand_vert_unc_m',                 75, '<f'),
    ('cand_vert_confidence_pct',        80, '<B'),
    ('cand_vert_reliability',           82, '<I'),
    ('vert_speed_mps',                  87, '<f'),
    ('unk_93_f32',                      92, '<f'),
    ('heading_deg',                     97, '<f'),
    ('heading_unc_deg',                102, '<f'),
    ('cand_magnetic_deviation_deg',    107, '<f'),
    ('cand_technology_mask',           112, '<I'),
    ('pdop',                           117, '<f'),
    ('hdop',                           122, '<f'),
    ('vdop',                           127, '<f'),
    ('timestamp_utc_ms',               132, '<Q'),
    ('unk_142',                        141, '<B'),
    ('cand_time_unc_ms',               143, '<f'),
    ('cand_time_src',                  148, '<I'),
    ('cand_hor_cir_confidence_pct',    327, '<B'),
)
_SENSOR_USAGE_VALID = 153      # value [154:162]
_SV_LIST_VALID = 162           # count u32 [163:167] + u16[80] [167:327]
_GPS_TIME_VALID = 329          # week u16 [330:332] + tow_ms u32 [332:336]
_VALID_OFFSETS = tuple(sorted(
    [off for _, off, _ in _VALUED]
    + [_SENSOR_USAGE_VALID, _SV_LIST_VALID, _GPS_TIME_VALID]))


@dataclass
class Diag0x15B2:
    """PDSM best-available-position response (0x15B2) — 352B v=0x08."""
    log_time: int
    version: int
    client_id: int
    cand_client_data_ptr: int
    raw_09: int
    valid_flags: bytes
    lat_deg: float | None
    lon_deg: float | None
    hor_unc_circular_m: float | None
    hor_unc_ellipse_semi_major_m: float | None
    hor_unc_ellipse_semi_minor_m: float | None
    cand_hor_unc_ellipse_orient_deg: float | None
    cand_hor_ellipse_confidence_pct: int | None
    hor_reliability: int | None
    unk_56_f32: float | None
    hor_speed_mps: float | None
    altitude_hae_m: float | None
    altitude_plus500_m: float | None
    cand_vert_unc_m: float | None
    cand_vert_confidence_pct: int | None
    cand_vert_reliability: int | None
    vert_speed_mps: float | None
    unk_93_f32: float | None
    heading_deg: float | None
    heading_unc_deg: float | None
    cand_magnetic_deviation_deg: float | None
    cand_technology_mask: int | None
    pdop: float | None
    hdop: float | None
    vdop: float | None
    timestamp_utc_ms: int | None
    unk_142: int | None
    cand_time_unc_ms: float | None
    cand_time_src: int | None
    cand_sensor_usage_raw: bytes | None
    sv_used_count: int | None
    sv_used_list: list[int] | None
    cand_hor_cir_confidence_pct: int | None
    gps_week: int | None
    gps_tow_ms: int | None
    tail_raw: bytes
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {'type': 'Diag0x15B2'}
        for f in fields(self):
            v = getattr(self, f.name)
            d[f.name] = v.hex() if isinstance(v, bytes) else v
        return d


@register(
    LOG_GNSS_PDSM_EXT_STATUS_BEST_AVAILABLE_INFO, domain="gnss",
    name="0x15B2",
    description=(
        "LOG_GNSS_PDSM_EXT_STATUS_BEST_AVAILABLE_INFO (0x15B2) — 352B v=0x08; "
        "the best-available-position response (lat/lon, unc ellipse, "
        "altitude, velocity, DOP, UTC + GPS time, used-SV list), "
        "F3-grounded (SDX20) + 0x1476 bit-exact (MDM9x50)"
    ),
    version=1,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "RE from the whole corpus (4 records: MC7411 MDM9x50 ×3, LM960A18 "
        "SDX20 ×1). F3-grounded by LM960 lte_rrc_loc_services.c:1765-"
        "1801 prints of the same response (rel/lat/lon/alt/unc_cir/semi-axes/"
        "unc_altitude/tod_ms) + MC7411 same-tick 0x1476 bit-exact on 3/3 "
        "(lat/lon/alt/heading/speed/vel_u/DOP/week/tow/SV list)."
    ),
    issues=(),
    fields_identified=38,
    fields_parsed=38,
    field_invariants={
        "version": {"enum": [_VERSION]},
        "payload_size": {"enum": [_SIZE]},
    },
)
def parse_0x15b2(log_time: int, data: bytes) -> Diag0x15B2 | None:
    if len(data) != _SIZE:
        return None
    if data[0] != _VERSION:
        return None
    client_id, cdptr = unpack_from('<II', data, 1)
    vals: dict[str, Any] = {}
    for name, voff, fmt in _VALUED:
        vals[name] = unpack_from(fmt, data, voff + 1)[0] if data[voff] else None

    sensor = bytes(data[154:162]) if data[_SENSOR_USAGE_VALID] else None
    if data[_SV_LIST_VALID]:
        sv_n = unpack_from('<I', data, 163)[0]
        k = min(sv_n, _SV_LIST_MAX)
        sv_list: list[int] | None = list(unpack_from(f'<{k}H', data, _SV_LIST_OFF))
    else:
        sv_n, sv_list = None, None
    if data[_GPS_TIME_VALID]:
        week, tow = unpack_from('<HI', data, 330)
    else:
        week = tow = None

    return Diag0x15B2(
        log_time=log_time,
        version=data[0],
        client_id=client_id,
        cand_client_data_ptr=cdptr,
        raw_09=data[9],
        valid_flags=bytes(data[o] for o in _VALID_OFFSETS),
        cand_sensor_usage_raw=sensor,
        sv_used_count=sv_n,
        sv_used_list=sv_list,
        gps_week=week,
        gps_tow_ms=tow,
        tail_raw=bytes(data[336:_SIZE]),
        payload_size=len(data),
        **vals,
    )
