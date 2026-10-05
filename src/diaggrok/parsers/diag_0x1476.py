"""Position report parser (0x1476).

The struct layout is established from our own GNSS DIAG capture corpus,
not from third-party decoder source: the v1/v2/v10/v13/v24 and
MDM9600/SWI9200X position-report offsets and types are pinned by those
captures. The v10 (SDX20 V2) trailer is decoded from EG18-NA, LM960 and
EM7511 captures, the 797 B MDM9600 variant from Sierra MC7700 captures, and
lat/lon are grounded against the firmware's own F3 debug messages on the
LM960 (``gm_core.c`` / ``tle_log.c``).

Position accuracy is validated against an independent receiver: on an
MDM9607 EG25-G capture (941 records) the decoded ``lat_deg``/``lon_deg`` sit
**2.84 m median** (p95 6.63, max 7.56) from a same-antenna survey-grade
LG290P fix on a stationary bench. The 0x14E0 computed nav solution
(~3.9 m horizontal) agrees with both the LG290P and 0x1476, so the position
core of both codes is cross-validated against an independent chip and
firmware.

Per-version status
------------------

- **v0x0a (10), SDX20 V2 layout.** The dominant variant (~860 k corpus
  records, the largest 0x1476 profile). Fixed size 2237/2325/2332 B. The
  v10-specific trailer is decoded by the ``version == 10`` branch of
  ``parse_0x1476``, with the DOP triple at **@228/232/236**, 8 B earlier than
  the shared struct. Confirmed on two survey-grade same-antenna LG290P
  benches: an EG25-G (MDM9607, 941 records) and a second SDX20 modem, the
  Quectel EG12-GT (966 + 100 records); all records are v=0x0a, 100 % parse,
  0 invariant violations. The motion-independent DOP identity
  ``pdop**2 = hdop**2 + vdop**2`` holds **1936/1936** at @228 on the real-fix
  (pos_source 2/8) records, and DOP is correctly absent on the pos_source=4
  prediction epochs (EG25-G split: 290 raw-ME / 580 combined / 71
  prediction; DOP present on all 870 real-fix records, absent on all 71
  prediction records). A DOP of 0.0 on an otherwise good-looking epoch is
  therefore prediction-epoch behavior, not a mis-parse. Position: EG25-G
  **2.84 m median** (p95 6.63), EG12-GT ~9 m (no modem-side RTK; SV az/el
  agree to +-3 deg with the reference). The field meanings are grounded
  against the firmware's own QMI_LOC F3 prints
  (``dsatm2mgpsif.c``:21496/21498/21500 position/horizontal/vertical_dop,
  which also identify 500.0 as the "no-DOP" sentinel) and the LM960 lat/lon
  labels (``gm_core.c`` / ``tle_log.c``). On the GNSS-only bench captures F3
  is 0x79-plaintext-only (69 non-position records; the 0x99 position prints
  need a build-matched QShrink database), and neither QCSuper nor SCAT
  decodes 0x1476 into coordinates, so the v10 F3 position label rests on the
  ``dsatm2mgpsif.c`` sites rather than a re-observation on those captures.

- **v0x18 (24), SDX62 layout.** Variable length (corpus 1245-2895 B); the
  SV array is a variable N x 30 B, so size is not an invariant. Grounded on
  an RM520N-GL (SDX62) same-antenna LG290P comparison (1540/1540 records
  v=0x18): **616 matched epochs, horizontal median 2.59 m** (mean 2.92,
  max 6.37), SV az/el within +-3 deg, matching the v0x0a bench. The DOP
  triple @461/465/469 satisfies ``pdop**2 = hdop**2 + vdop**2`` on 480/480
  records of that capture and 1325/1325 across three more SDX62 captures
  (CFW-3212 / RG520N-NA, RM520N-GL). F3 from ``tle_base.cpp``
  (``PTM:ALE pos, Lat/Lon/Alt``) co-locates with the decoded fix. The
  CFW-3212 (Casa RG520N-NA, SDX62) emits the same variant. The RM520N-GL
  reports a 1024-rolled ``gps_week`` (1394/1398) while the CFW-3212 reports
  the full week (2422) in the same era: different firmware rollover
  handling, with a correct position on both.

- **v0x0d (13), SDX55 layout.** Routes through ``_parse_0x1476_v13`` on the
  fixed-size v13 branch (header @0-64, 65-float block, DOP triple
  @301/305/309, SV counts @358-363, 2477 B). Grounded on a Telit FN980
  (SDX55) same-antenna LG290P comparison (1340/1340 records v=0x0d, 100 %
  parse): **334 matched epochs, horizontal median 5.04 m** (mean 4.60, max
  7.88). ``pdop**2 = hdop**2 + vdop**2`` holds **1002/1002** on the real-fix
  (pos_source 2/8) records; the same 1002 records populate ``num_gps_svs``
  > 0, and the pos_source=4 (prediction/database) records carry DOP 0.0 /
  used 0. Unlike v10, v13 populates both DOP and used counts on every
  real-fix epoch. On an SDX55 EM9190 capture, ``tle_base.cpp:104`` emits
  ``PTM:ALE pos, Lat/Lon/Alt/PUNC`` and ``PTM:ALE pos, Week/GpsMsec``
  (GpsWk:2430), the firmware's own position and GPS-week labels (the ALE
  estimate is a coarse seed with PUNC ~4900 km, so it corroborates field
  meaning, not the precise fix). ``0x60`` events are absent from the
  GNSS-only comparison capture.

- **v0x07 (7) and v0x08 (8), large-record fall-through variants.** v0x07:
  Sierra MC7455 / EM7455, MDM9x30-class, fixed 2115 B. v0x08: Quectel
  EP06A, MDM9x07, fixed 2229 B. Both use the shared 291 B ``_POS_FMT``
  struct for the header, velocity block and SV counts, but their **DOP
  triple sits at the v10 offset @228/232/236, not the struct's
  @236/240/244**; reading the struct offset would report the *vdop* slot as
  ``pdop`` and drop hdop. ``pdop²=hdop²+vdop²`` holds on the real-fix
  (pos_source 2/8) records at **v7 3583/3583 @228** (0/1031 at @236) and
  **v8 1802/1802 @228**. Prediction epochs (pos_source=4) render DOP
  absent. The position core decodes survey-grade on same-antenna LG290P
  benches (EM7455 and EP06). The v7/v8 trailer past the DOP triple is not
  decoded (the per-SV Kalman / secondary-SV decode is v10-only). An EM7455
  capture with F3 enabled carries 159 k 0x79 plaintext frames alongside 488
  v7 0x1476 records.

- **v0x15 (21).** Inseego M3100 (SDX65) and an early RM520N-GL (SDX62)
  firmware; 321 records across 4 captures. Size tracks fix state: 1547 B
  for a real fix (pos_source 2/8, 178 records), 647 B for prediction
  (pos_source 4, 143 records). v21 routes through the v13 branch (initial
  ``pdop_off=301``); @301 never holds a valid triple (0/321), so the
  ``_find_dop_offset`` fallback resolves the DOP triple at the **v24 offset
  @461**. ``pdop²=hdop²+vdop²`` holds **70/70 @461** on DOP-bearing
  real-fix records, ``_find_dop_offset`` returns 461 for all 70, and the
  parser's ``pdop`` equals the @461 float exactly. The other 108 real-fix
  records carry the (500.0, 500.0, 500.0) no-DOP sentinel @461 (rendered
  absent); the 143 prediction epochs carry no DOP. F3 is silent for GNSS/LOC
  on these captures (the M3100 emits mostly terse 0x99 QShrink4 frames and
  no build-matched database is available); ``0x60`` events are absent. No
  open-source decoder emits decoded lat/lon for comparison.

- **v0x1a (26).** Foxconn T99W640 / Dell DW5934e (SDX-class). Routes
  through the ``version >= 24`` branch of ``_parse_0x1476_v13``. Measured on
  real T99W640 field data (three drive / GNSS survey captures plus a GNSS
  bring-up capture; 354 fix-region records, 100 % parse, 0 exceptions), the
  v24 layout is **correct for the header, float block and DOP core**:

  * Position: ``lat_rad``@49 / ``lon_rad``@57 decode a coherent drive track
    over ``gps_week``@32 = 2422/2423, the **full (non-rolled) week**.
  * The DOP triple @461/465/469 (the **v24 offset**, not v13's @301)
    satisfies ``pdop²=hdop²+vdop²`` on **all 7** genuine DOP triples (e.g.
    18.44²≈12.56²+13.50², 9.37²≈6.47²+6.77²) and **never** at @301 (0.0).
    The other **219/226** real-fix (pos_source 2/8) records carry the
    **500.0 "no-DOP" sentinel** at @461 (rendered absent by ``to_dict``),
    and the **111/111** pos_source=4 prediction epochs carry no DOP, the
    same real-fix-vs-prediction split as v10/v13.
  * The ``version`` enum includes 26 (798 corpus records).

  F3 is silent on the T99W640 GNSS captures (no 0x79 or 0x99 frames; only
  0x98 multi-radio wrappers whose inner payload needs a build-matched
  QShrink database), ``0x60`` events are absent, and QCSuper / SCAT do not
  decode 0x1476. The v26 field labels therefore rest on the field-level DOP
  identity, the position drive track, and the ``dsatm2mgpsif.c`` QMI_LOC /
  ``tle_base.cpp`` ``PTM:ALE pos`` F3 sites established on v0x0a/v0x0d.
  Caveat: v26 records (1245-1365 B) are **shorter** than the v24 records
  (1575 B+) whose SV-array tail (@565-611 counts, @1215+ array) is grounded,
  so the v26 tail past the DOP triple is not claimed (the SV-count bytes
  @565 fall in [0,32] but are not asserted).

Log name: LOG_GNSS_POSITION_REPORT_C
Also known as: field name issue, LOG_GAN_CALL_DISCONNECT
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from struct import calcsize, unpack_from
from typing import Any

from diaggrok.codes import LOG_GNSS_POSITION_REPORT
from diaggrok.parsers.gnss_helpers import unpack_dict
from diaggrok.registry import register

# ---------------------------------------------------------------------------
# Struct format strings — corpus-confirmed position-report layout
# ---------------------------------------------------------------------------

# position_report v1/v2 (83 fields, 291 bytes) — MDM9607 and earlier
_POS_FMT = '<BIBIHIBHIHIBHIIdd' + 'f' * 48 + 'BffffBBHffIIBBBBBB'
_POS_SZ = calcsize(_POS_FMT)

# position_report v13+ (SDX55/SDX62 and later)
_POS_V13_MIN_SZ = 407  # header(65) + floats(260) + tail(82), excluding SV array

# MDM9600 / SWI9200X (legacy gpsOne/PDS) position report — version byte 0x02
# but a DISTINCT layout from the MDM9607 291-byte _POS_FMT: the 4-byte
# `fake_align` field present in _POS_FMT is ABSENT, so every field from the
# GPS-week onward sits 4 bytes earlier, and the record carries a long (510 B)
# trailer that is only partly decoded. Size is a stable 797 bytes / version 2
# across all three observed Sierra MC7700 (SWI9200X) firmware builds. Routing
# a 797 B v2 record through _POS_FMT lands gps_week/tow/lat/lon on the wrong
# bytes (garbage lat≈1e-129, week≈3880). The (version, size) pair is the
# discriminator.
_POS_MDM9600_SZ = 797

_POS_FIELDS = [
    # Header (17 fields)
    'version', 'f_count', 'pos_source', 'reserved1',
    'pos_vel_flag', 'pos_vel_flag2', 'failure_code', 'fix_events',
    'fake_align', 'gps_week', 'gps_tow_ms',
    'glo_four_year', 'glo_days', 'glo_tow_ms',
    'pos_count',
    'lat_rad', 'lon_rad',
    # Float block (48 fields)
    'alt_m', 'heading_rad', 'heading_unc_rad',
    'vel_e', 'vel_n', 'vel_u',
    'vel_sigma_e', 'vel_sigma_n', 'vel_sigma_u',
    'clock_bias', 'clock_bias_sigma',
    'ggtb', 'ggtb_sigma', 'gbtb', 'gbtb_sigma', 'bgtb', 'bgtb_sigma',
    'filt_ggtb', 'filt_ggtb_sigma', 'filt_gbtb', 'filt_gbtb_sigma',
    'filt_bgtb', 'filt_bgtb_sigma',
    'sft_offset', 'sft_offset_sigma',
    'clock_drift', 'clock_drift_sigma',
    'filtered_alt', 'filtered_alt_sigma',
    'raw_alt', 'raw_alt_sigma',
    'align0', 'align1', 'align2', 'align3', 'align4', 'align5', 'align6',
    'align7', 'align8', 'align9', 'align10', 'align11', 'align12', 'align13',
    'pdop', 'hdop', 'vdop',
    # Tail (18 fields)
    'ellipse_confidence',
    'ellipse_angle', 'ellipse_semi_major', 'ellipse_semi_minor', 'pos_sigma_vertical',
    'horiz_reliability', 'vert_reliability', 'reserved2',
    'gnss_heading_rad', 'gnss_heading_unc_rad',
    'sensor_data_mask', 'sensor_aid_mask',
    'num_gps_svs', 'total_gps_svs',
    'num_glo_svs', 'total_glo_svs',
    'num_bds_svs', 'total_bds_svs',
]
assert len(_POS_FIELDS) == 83, f"_POS_FIELDS length mismatch: {len(_POS_FIELDS)}"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class Diag0x1476:
    log_time: int
    version: int
    f_count: int
    pos_source: int        # 0=None 1=WLS 2=Kalman 3=Injected 4=DB
    gps_week: int
    gps_tow_ms: int
    lat_rad: float
    lon_rad: float
    alt_m: float           # WGS84 ellipsoidal (HAE), NOT orthometric MSL — confirmed against LG290P gpsd altHAE
    heading_rad: float
    heading_unc_rad: float
    vel_e: float           # east velocity m/s
    vel_n: float           # north velocity m/s
    vel_u: float           # up velocity m/s
    vel_sigma_e: float
    vel_sigma_n: float
    vel_sigma_u: float
    pdop: float
    hdop: float
    vdop: float
    num_gps_svs: int
    total_gps_svs: int
    num_glo_svs: int
    total_glo_svs: int
    num_bds_svs: int
    total_bds_svs: int
    # List of GPS PRNs parsed from the trailer SV block. Populated by the
    # v10 (SDX20 V2) path and the MDM9600/SWI9200X 797 B path (decoded from
    # the offset-198 stride-20 array — see `_parse_mdm9600_gps_sv_block`).
    # Empty for v1/v2 and v13+ parser paths (they don't use this field).
    gps_sv_prns: list[int] = field(default_factory=list)
    # v10-only (SDX20 V2): full per-SV Kalman residual + variance structs
    # from the trailer GPS SV block. One entry per tracked GPS SV. See
    # ``V10SvResidual`` for the field hypotheses.
    gps_sv_residuals: list['V10SvResidual'] = field(default_factory=list)
    # v10-only (SDX20 V2): decoded intermediate block (bytes 291..322).
    # Empty dict on non-v10 paths. See ``_parse_v10_intermediate_block``
    # for the field documentation.
    v10_intermediate: dict = field(default_factory=dict)
    # v10-only (SDX20 V2): multi-constellation SV block at bytes 741..~1159
    # (same 22-byte stride as the GPS block at 323). One entry per slot —
    # const_id identifies the constellation (2 = GLONASS, others TBD). See
    # ``V10SecondarySv`` and :func:`_parse_v10_secondary_sv_block`.
    secondary_svs: list['V10SecondarySv'] = field(default_factory=list)
    # GLONASS time triplet — the direct GLONASS analog of gps_week/
    # gps_tow_ms, exposed on the 291B _POS_FMT path (glo_four_year @29 u8,
    # glo_days @30 u16, glo_tow_ms @32 u32) and the v6/v12 compact path. None
    # on the v13/v24 and mdm9600 paths, where the offset is not yet located
    # for that layout.
    glo_four_year: int | None = None
    glo_days: int | None = None
    glo_tow_ms: int | None = None

    # Known GNSS-engine cold-start seed positions (lat_rad, lon_rad).
    # These are hardcoded prediction positions emitted before the first
    # real satellite fix, typically for 10-30 seconds after AT$GPSP=1
    # or AT$GPSR=1 cold reset.
    _COLD_START_SEEDS = [
        (38.0 * math.pi / 180.0, -117.0 * math.pi / 180.0),  # Nevada default
    ]

    @property
    def is_cold_start_seed(self) -> bool:
        """True if this position looks like a GNSS-engine cold-start seed.

        Checks: pos_source=4 (prediction/database), gps_used=0, and
        lat/lon matches a known hardcoded seed position within ~1 km.
        Consumers should skip these records — they represent the GNSS
        engine's default prediction, not a real satellite fix.
        """
        if self.pos_source != 4 or self.num_gps_svs != 0:
            return False
        for seed_lat, seed_lon in self._COLD_START_SEEDS:
            if (abs(self.lat_rad - seed_lat) < 0.001 and
                    abs(self.lon_rad - seed_lon) < 0.001):
                return True
        return False

    def to_dict(self) -> dict[str, Any]:
        speed = math.sqrt(self.vel_e ** 2 + self.vel_n ** 2)
        gps_dict: dict[str, Any] = {
            'used': self.num_gps_svs,
            'total': self.total_gps_svs,
        }
        if self.gps_sv_prns:
            gps_dict['prns'] = self.gps_sv_prns
        if self.gps_sv_residuals:
            gps_dict['sv_residuals'] = [sv.to_dict() for sv in self.gps_sv_residuals]
        glo_dict: dict[str, Any] = {
            'used': self.num_glo_svs, 'total': self.total_glo_svs,
        }
        # GLONASS time triplet — the GLONASS analog of gps_week/gps_tow_ms,
        # exposed on the 291B path. Omitted when absent (v13/mdm9600 paths).
        if self.glo_four_year is not None:
            glo_dict['four_year'] = self.glo_four_year
            glo_dict['days'] = self.glo_days
            glo_dict['tow_ms'] = self.glo_tow_ms
        # v10-only: expose GLONASS PRNs + FCNs parsed from the
        # secondary SV block.  Observed on the LM960: num_glo_svs
        # from the header (e.g. 5 used) can exceed the tail slot count
        # (3 tracked in the 22-byte block) — the secondary block
        # appears to be capacity-limited, so ``tracked`` here is a
        # lower bound, not an authoritative count.
        glo_svs = [sv for sv in self.secondary_svs
                   if sv.const_id in (0x02, 0x03)]
        if glo_svs:
            glo_dict['prns'] = [sv.sv_id for sv in glo_svs]
            glo_dict['tracked'] = len(glo_svs)
            glo_dict['fcns'] = [sv.aux for sv in glo_svs]
        out = {
            'type': 'Diag0x1476',
            'log_time': self.log_time,
            'version': self.version,
            'pos_source': self.pos_source,
            'is_cold_start_seed': self.is_cold_start_seed,
            'gps_week': self.gps_week,
            'gps_tow_ms': self.gps_tow_ms,
            'lat_deg': self.lat_rad * 180.0 / math.pi,
            'lon_deg': self.lon_rad * 180.0 / math.pi,
            'alt_m': self.alt_m,
            'heading_deg': self.heading_rad * 180.0 / math.pi,
            'heading_unc_deg': self.heading_unc_rad * 180.0 / math.pi,
            'speed_mps': speed,
            'vel_e': self.vel_e,
            'vel_n': self.vel_n,
            'vel_u': self.vel_u,
            # A valid DOP is strictly positive and below the sentinel. 0.0
            # (prediction-only epochs / no-fix, and the MDM9600 identity-guard
            # zeroing) and the 500.0 receiver sentinel (both F3-confirmed on v10)
            # mean "no DOP this epoch" — render absent (None), not as a real
            # zero, so a dead field never renders like a genuine value.
            # NB: only PDOP has a ~1.0 floor; HDOP/VDOP
            # components can legitimately be < 1.0 (e.g. vdop 0.913), so the
            # window is `> 0.0`, not `>= 1.0`.
            'pdop': self.pdop if 0.0 < self.pdop < 100.0 else None,
            'hdop': self.hdop if 0.0 < self.hdop < 100.0 else None,
            'vdop': self.vdop if 0.0 < self.vdop < 100.0 else None,
            'svs': {
                'gps': gps_dict,
                'glonass': glo_dict,
                'beidou': {'used': self.num_bds_svs, 'total': self.total_bds_svs},
            },
        }
        # v10-only: surface per-constellation buckets for every named
        # const_id.  const_id=0x04 → BeiDou (sv_id −200 = PRN);
        # const_id=0x06/0x07 → Galileo (sv_id − 50 and − 46 respectively —
        # different signal-band slots observed on the EM7511);
        # const_id=0x0a → SBAS/QZSS augmentation.  Any other const_id stays
        # under ``svs.by_const_id`` for downstream refinement.
        bds_prns = [sv.sv_id - 200 for sv in self.secondary_svs
                    if sv.const_id == 0x04 and 201 <= sv.sv_id <= 237]
        if bds_prns:
            out['svs']['beidou']['prns'] = bds_prns
            out['svs']['beidou']['tracked'] = len(bds_prns)
        gal_prns: list[int] = []
        for sv in self.secondary_svs:
            if sv.const_id == 0x06 and sv.sv_id > 50:
                gal_prns.append(sv.sv_id - 50)
            elif sv.const_id == 0x07 and sv.sv_id > 46:
                gal_prns.append(sv.sv_id - 46)
        if gal_prns:
            out['svs']['galileo'] = {
                'tracked': len(gal_prns),
                'prns': gal_prns,
            }
        sbas_prns = [sv.sv_id for sv in self.secondary_svs
                     if sv.const_id == 0x0a]
        if sbas_prns:
            out['svs']['sbas'] = {
                'tracked': len(sbas_prns),
                'prns': sbas_prns,
            }
        by_const: dict[int, list[int]] = {}
        for sv in self.secondary_svs:
            if sv.const_id in (1, 2, 3, 4, 6, 7, 10):
                continue
            by_const.setdefault(sv.const_id, []).append(sv.sv_id)
        if by_const:
            out['svs']['by_const_id'] = {
                str(k): v for k, v in sorted(by_const.items())
            }
        if self.v10_intermediate:
            out['v10_intermediate'] = self.v10_intermediate
        return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# v10 (SDX20 V2) trailer structure constants, established against EG18-NA
# captures and confirmed on LM960, EM7511 and EG25-G captures.
#
# Byte layout of a v10 Diag0x1476 payload (2325 bytes total):
#   0..290     v1/v2-compatible fixed-layout struct (`_POS_FMT`)
#              — version, f_count, pos_source, gps_week/tow, lat/lon (rad),
#                float block (alt, velocity, DOP), SV counts (GPS/GLO/BDS only)
#   291..322   32-byte intermediate block.  Exposed as named fields below;
#              see ``_parse_v10_intermediate_block`` for field semantics.
#              Populated only on pos_source=8 (combined) captures; pos_source=2
#              (raw ME) and pos_source=4 (prediction) emit mostly zeros here.
#   323..740   GPS SV block.  Up to 19 slots × 22 bytes.  Active entries at
#              the start, zero padding after ``num_gps_svs`` entries.  Each
#              entry is a 6-byte header
#                  [const_id, sv_id, 0x00, 0x00, flag, 0x00]
#              followed by 16 bytes (4 × float32) of per-SV Kalman filter
#              innovation + covariance data — see ``_parse_v10_gps_sv_block``.
#              const_id observed = 0x01 (GPS).
#   741..1159  Secondary multi-constellation SV block.  Up to 19 slots ×
#              22 bytes — SAME stride as the GPS block at 323, but
#              const_id identifies the constellation per slot (not per
#              block).  See ``_V10_CONST_ID_NAMES`` and
#              ``V10SecondarySv`` for the const_id mapping (GPS / GLONASS /
#              BeiDou / Galileo / SBAS-QZSS).
#              GLONASS slots have an all-zero 16-byte float block (no
#              Kalman residuals populated); some non-GLONASS const_ids
#              (0x03, 0x07) carry non-zero floats with magnitudes in the
#              pseudorange-residual range.  Terminates at first all-zero
#              slot.  Some captures (e.g. EG18-NA with GLONASS tracking
#              inactive) carry an all-zero block here.
#   1160..2324 Reserved / zero on the entire observed corpus.  Galileo
#              and QZSS counts still not present in the v1/v2 header and
#              have not surfaced here either.
_V10_TRAILER_GPS_BLOCK_START = 323
_V10_TRAILER_SV_ENTRY_SIZE = 22
_V10_TRAILER_GPS_BLOCK_SLOTS = 19  # 19 * 22 = 418 bytes for the GPS block
_V10_INTERMEDIATE_START = 291
_V10_INTERMEDIATE_END = 323
# v10 tail region after the GPS SV block. Populated on 66% of v10 records
# across Sierra EM7511, Telit LM960 and EG18-NA captures. The populated
# bytes form a 22-byte-strided array at offsets 741+, decoded as a
# multi-constellation SV block (GLONASS dominant).
_V10_TAIL_START = 741
_V10_TAIL_END = 2325  # exclusive end; v10 record is 2325 bytes total
_V10_TAIL_SECOND_SV_BLOCK_START = 741
_V10_SECONDARY_BLOCK_SLOTS = 19  # matches GPS block slot count


def _parse_v10_intermediate_block(data: bytes) -> dict:
    """Decode the v10 intermediate block at bytes 291..322.

    Identified fields (from 573 pos_source=8 records on EG18-NA captures):

    - Bytes 291..296 (u48, always zero): reserved / padding
    - Bytes 297..298 (u16, *field_a*): varies per epoch in the 360..2247
      range on pos_source=8. Zero on pos_source=2. All-ones (0xFFFF) on
      pos_source=4. Semantics unknown — possibly a quality or covariance
      metric.  Non-monotonic but loosely correlated with *field_b*
      (ratio ~0.95).
    - Bytes 299..300 (u16, *field_b*): varies per epoch in the 317..1729
      range. Same duplication pattern as *field_a*. Zero on pos_source=2/4.
    - Bytes 301..304 (u32, *field_c*): varies per epoch on both pos_source=2
      and pos_source=8. High byte consistently 0x8e on pos_source=8 records.
      Possibly a timestamp delta, checksum, or packed status bitfield.
    - Bytes 305..312 (8 bytes, always zero): reserved
    - Bytes 313..314 (u16, *field_b_dup*): **identical to field_b** across
      every record tested — appears to be a duplicated copy of the same
      u16, suggesting field_b is being mirrored into a second slot.
    - Bytes 315..322 (8 bytes, always zero): reserved

    Field semantics are not yet validated — the field names are prefixed
    with ``u16_`` / ``u32_`` to make clear they're raw decodes, not known
    semantic meanings.
    """
    if len(data) < _V10_INTERMEDIATE_END:
        return {}
    return {
        'u16_field_a': unpack_from('<H', data, 297)[0],
        'u16_field_b': unpack_from('<H', data, 299)[0],
        'u32_field_c': unpack_from('<I', data, 301)[0],
        'u16_field_b_dup': unpack_from('<H', data, 313)[0],
    }


@dataclass
class V10SvResidual:
    """Per-SV 16-byte trailing block from the v10 GPS SV array.

    Each entry follows a 6-byte SV header (const_id, sv_id, reserved, flag)
    and contains four little-endian float32 values. Value ranges from 573
    pos_source=8 records across 6 GPS PRNs on an EG18-NA capture:

    - **f0 range [-50, +66] m, mean near 0**: pseudorange residual
      (measured − predicted range, in metres).  Low for strong tracks
      (PRN 2 mean −1.28, PRN 32 mean +0.25), larger for weak tracks
      (PRN 24 mean −19.5).
    - **f1 range [-1.9, +1.2] m/s, mean near 0**: Doppler / range-rate
      residual (m/s).
    - **f2 range [5, 21009] m²**: Kalman filter pseudorange variance /
      weight. Strong tracks stay under 100 m² (PRN 2 always ≤101), weak
      tracks saturate near 21000 m² (~150 m uncertainty).
    - **f3 range [0.05, 465]**: range-rate variance, paired with f2. Also
      saturates high for weak tracks.

    **f2 (PR variance) is grounded and f0 (PR residual) strongly supported
    against an independent log code.** Every v10 GPS SV slot is
    cross-checked against the co-temporal **0x14DE OEMDRE C/No** for the
    same (nearest-epoch, PRN) — a *different* measurement path, so not a
    self-consistency check of one code against itself — over four captures
    spanning **both** v10 size classes:

    | chipset / size | spearman(f2, C/No) | med f2 @C/No≥35 | med f2 @C/No<25 |
    |---|--:|--:|--:|
    | MDM9607 / 2237 B (capture 1) | −0.925 | 50 m² | 16 120 m² |
    | MDM9607 / 2237 B (capture 2) | −0.923 | 50 m² | 16 121 m² |
    | SDX20-V2 / 2325 B (capture 3) | −0.981 |  —    |  210 m² |
    | SDX20-V2 / 2325 B (capture 4) | −0.743 | 54 m² | 3 784 m² |

    - **f2 = pseudorange variance/weight**: strong monotone anti-correlation
      with C/No on all four (Kalman inverse-weight signature — strong SVs
      ~50 m², weak SVs saturate 3 800–16 000 m²). n = 4 040 / 24 216 /
      3 548 / 24 558 matched SV rows.
    - **f0 = pseudorange residual (m)**: zero-mean on all four (per-capture
      means +1.48 / −0.26 / −1.21 / −0.03 m), and the **normalized residual
      f0/√f2 has ~unit std** (1.02 on EG12-GT; 0.48–0.83 elsewhere ⇒ f2 is a
      slightly-inflated/robustified variance of f0) — so f0 and f2 are a
      matched (residual, variance) Kalman pair. The exact filter stage
      (a-priori innovation vs post-fit residual) is not pinned, so the
      ``possibly_`` prefix stays on the output keys; the *variance* and
      *residual-domain* readings themselves are grounded.

    **f3 (range-rate variance) is grounded and f1 (range-rate residual)
    strongly supported** on the same 4 captures / matched SV rows, by three
    converging tests:

    | chipset | spearman(f3,C/No) | med f2 (m²) / med f3 ((m/s)²) | f1 mean (m/s) |
    |---|--:|--:|--:|
    | MDM9607 (capture 1) | −0.963 | 580 / 0.51 = 1143× | −0.007 |
    | MDM9607 (capture 2) | −0.936 | 832 / 0.54 = 1532× | −0.007 |
    | SDX20-V2 (capture 3) | −0.913 | 126 / 0.68 =  186× | −0.056 |
    | SDX20-V2 (capture 4) | −0.846 | 184 / 0.62 =  295× | −0.003 |

    - **f3 = range-rate variance ((m/s)²)**: strong monotone anti-correlation
      with the independent C/No on all four (same Kalman inverse-weight
      signature as f2 — carrier-tracking noise also scales ~1/(C/No));
      floors at 0.05 (m/s)² for strong SVs, saturates 20–80 (m/s)² for weak.
      C/No alone can't separate an RR- from a second PR-variance (both track
      C/No), so two more tests pin the *domain*: (a) f3 is **186–1532× smaller
      than f2**, i.e. rate-scaled ((m/s)² not m²); (b) the cross-normalization
      ``f1/√f3`` is order-unity (0.09–0.33) while the **cross** pairing
      ``f0/√f3`` is 12–19 and ``f1/√f2`` is 0.005–0.02, i.e. 1–3 orders off
      unity — so f1 pairs with f3, not f2.
    - **f1 = range-rate residual (m/s)**: zero-mean on all four (means above),
      m/s-domain spread (std 0.19–0.44 m/s), and normalized ``f1/√f3``
      order-unity ⇒ f1 and f3 are a matched (residual, variance) pair, exactly
      as f0/f2 are. The slot layout is therefore [PR-res, RR-res, PR-var,
      RR-var] = [f0, f1, f2, f3] by data, not by byte order alone.

    The offset-323 per-SV block decodes correctly on both the 2237 B MDM9607
    (EG25-G) variant and the 2325 B SDX20-V2 variant.

    **Output keys stay ``possibly_``-prefixed** because the exact filter
    stage is unpinned.
    """
    const_id: int           # 0x01 = GPS on observed captures
    sv_id: int              # PRN
    flag: int               # 1-byte status flag at slot offset 4
    f0: float               # possible pseudorange residual (m)
    f1: float               # possible range-rate residual (m/s)
    f2: float               # possible pseudorange variance (m²)
    f3: float               # possible range-rate variance ((m/s)²)

    def to_dict(self) -> dict[str, Any]:
        return {
            'sv_id': self.sv_id,
            'flag': self.flag,
            'possibly_pr_residual_m': self.f0,
            'possibly_rr_residual_mps': self.f1,
            'possibly_pr_variance_m2': self.f2,
            'possibly_rr_variance_m2ps2': self.f3,
        }


def _parse_v10_gps_sv_block(data: bytes, num_gps_svs: int) -> list[int]:
    """Walk the v10 trailer GPS SV block and return the list of used GPS PRNs.

    Reads up to ``num_gps_svs`` entries starting at offset 323. Each entry
    is a 6-byte header ``(const_id, sv_id, 0, 0, flag, 0)`` followed by 16
    bytes of per-SV data. Stops early on a malformed header or end-of-
    buffer. Only returns entries with ``const_id == 0x01`` (GPS).

    Kept for backward compatibility with callers that only want the PRN
    list — :func:`_parse_v10_gps_sv_entries` returns the full struct.
    """
    return [sv.sv_id for sv in _parse_v10_gps_sv_entries(data, num_gps_svs)]


def _parse_v10_gps_sv_entries(data: bytes, num_gps_svs: int) -> list[V10SvResidual]:
    """Walk the v10 trailer GPS SV block and return ``V10SvResidual`` entries.

    Full decode — returns PRN + flag + the 4 per-SV float fields per slot.
    """
    out: list[V10SvResidual] = []
    if num_gps_svs <= 0:
        return out
    if len(data) < _V10_TRAILER_GPS_BLOCK_START + 6:
        return out
    off = _V10_TRAILER_GPS_BLOCK_START
    for _ in range(min(num_gps_svs, _V10_TRAILER_GPS_BLOCK_SLOTS)):
        if off + _V10_TRAILER_SV_ENTRY_SIZE > len(data):
            break
        const_id = data[off]
        sv_id = data[off + 1]
        if const_id != 0x01 or data[off + 2] != 0 or data[off + 3] != 0 or data[off + 5] != 0:
            break
        if not (1 <= sv_id <= 96):
            break
        flag = data[off + 4]
        f0 = unpack_from('<f', data, off + 6)[0]
        f1 = unpack_from('<f', data, off + 10)[0]
        f2 = unpack_from('<f', data, off + 14)[0]
        f3 = unpack_from('<f', data, off + 18)[0]
        out.append(V10SvResidual(
            const_id=const_id, sv_id=sv_id, flag=flag,
            f0=f0, f1=f1, f2=f2, f3=f3,
        ))
        off += _V10_TRAILER_SV_ENTRY_SIZE
    return out


# Const_id observations across 10725 v10 records from 8 captures / 6
#   firmware builds, with the final assignment made on an EM7511 capture
#   where the modem's own
#   0x147E RF-config declared ``constellations='GPS/GLO/BDS/GAL'`` and a
#   concurrent LG290P reference confirmed GPS + GLONASS + Galileo +
#   BeiDou SVs in view + used the whole session.
#
#   ** const_id is a packed (constellation_index, engine_track_bit) **
#   The low bit of const_id flags whether the slot carries
#   measurement-engine Kalman residuals (bit=1) or is an acquisition-
#   only / secondary-band track (bit=0).  The remaining 7 bits index
#   the constellation:
#     index 0 = GPS                 → 0x01 (MEAS)
#     index 1 = GLONASS             → 0x02 (ACQ) / 0x03 (MEAS)
#     index 2 = BeiDou              → 0x04 (ACQ) / 0x05 (MEAS, not observed)
#     index 3 = Galileo             → 0x06 (ACQ) / 0x07 (MEAS)
#     index 5 = SBAS / QZSS aug.    → 0x0a (ACQ) / 0x0b (MEAS, not observed)
#   Verified by the same-record co-appearance of GLONASS R20 sv_id=84
#   with byte3=+2 (R20's assigned FCN) under BOTH const=0x02 and 0x03
#   on the LM960, plus the consistent floats-populated-iff-odd
#   pattern across every const_id in the corpus.
#
#   const_id | n     | sv_id range | floats populated | mapping | notes
#   ---------+-------+-------------+------------------+---------+--------
#   0x01     | 66128 | 1..32       | yes (GPS Kalman) | GPS (MEAS)  | primary block @ offset 323
#   0x02     | 6555  | 65..96      | NEVER            | GLONASS (ACQ) | byte 3 = signed FCN ∈ [-7, +6]
#   0x03     |    13 | 84          | yes (Kalman)     | GLONASS (MEAS) | R20 only in corpus; byte3=+2 matches R20 FCN
#   0x04     |  1270 | 219..230    | NEVER            | BeiDou (ACQ) | sv_id − 200 = PRN ∈ [19, 30]
#   0x06     |   611 | 51..78      | NEVER            | Galileo (ACQ) | sv_id − 50 = PRN
#   0x07     |   866 | 47..70      | yes (Kalman)     | Galileo (MEAS)| sv_id − 46 = PRN; different band slot than 0x06
#   0x0a     |   432 | 133,135,194 | NEVER            | SBAS/QZSS (ACQ) | 133/135 = WAAS GEO; 194 in Sierra QZSS range
#
# Inference basis for 0x06/0x07 = Galileo: the EM7511 capture is the
# only corpus member carrying these IDs, the modem declares exactly
# ``GPS/GLO/BDS/GAL`` via 0x147E, and GPS/GLO/BDS are already assigned
# (GPS at 0x01 in the primary block; GLONASS at 0x02 is absent on
# EM7511 — consistent with a Verizon-configured unit not acquiring it;
# BeiDou at 0x04 confirmed via sv_id).  The sv_id encoding for Galileo
# in this block does NOT match Sierra's AT!GPSSATINFO convention
# (Galileo=301..336); instead it looks like a PRN + offset encoding
# (0x06: sv_id − 50 ∈ [1, 28]; 0x07: sv_id − 46 ∈ [1, 24]) suggesting
# different signal-band slots.  0x0a's PRN 133/135 are classic WAAS
# GEO SBAS PRNs by NMEA convention; sv_id 194 falls in Sierra's
# AT!GPSSATINFO QZSS range (193-197) — the bucket appears to carry
# both SBAS and QZSS as "augmentation" signals.
#
# The 16-byte float block uses the same Kalman residual/variance layout
# as the GPS block (f0 = PR residual m, f1 = RR residual m/s, f2 = PR
# variance m², f3 = RR variance (m/s)²) whenever floats are populated:
# per-field ranges for const_ids 0x01/0x03/0x07 all match the GPS
# signature (f0/f1 straddle zero, f2/f3 strictly positive).
#
# GLONASS residual-floats are ALL-ZERO across every observed firmware
# (several LM960 builds, EG18-NA, EG25-G, EM7511) — this
# is a baseband-design decision, not firmware-specific.  Max observed
# slot count in a single record is 16 (out of 19-slot cap) on Sierra
# EM7511; typical LM960 records carry 3 GLONASS slots regardless of
# whether ``num_glo_svs`` in the header is 3, 5, 6, or 7 — the
# relationship between header count and tail slot count is NOT a clean
# "used vs tracked" ratio.
_V10_CONST_ID_NAMES = {
    0x01: 'GPS',
    0x02: 'GLONASS',
    0x03: 'GLONASS',    # measurement-engine track (byte 3 = FCN, floats populated)
    0x04: 'BeiDou',
    0x06: 'Galileo',
    0x07: 'Galileo',
    0x0a: 'SBAS',
}

# Whether each const_id carries a measurement-engine Kalman residual
# (odd IDs = measurement track, even IDs = acquisition / secondary band).
# Exposed as ``V10SecondarySv.is_measurement_track`` to let consumers
# filter to residual-bearing slots without having to know the bit trick.
def _is_measurement_track(const_id: int) -> bool:
    return bool(const_id & 0x01)


def _constellation_name_for_secondary_sv(const_id: int, sv_id: int) -> str | None:
    """Best-effort constellation name for a secondary-block slot.

    Returns ``None`` when the const_id is ambiguous — callers get the
    raw ``const_id`` in that case and can refine naming downstream.
    """
    name = _V10_CONST_ID_NAMES.get(const_id)
    if name is not None:
        return name
    # Fall back to sv_id range inference (parallels
    # gnss_oemdre.derive_constellation_from_svs):
    if 301 <= sv_id <= 336:
        return 'Galileo'
    if 201 <= sv_id <= 237:
        return 'BeiDou'
    return None


@dataclass
class V10SecondarySv:
    """One 22-byte slot from the v10 multi-constellation secondary SV block
    at offset 741, decoded from LM960, EG18-NA and EM7511 captures.

    Slot layout mirrors the GPS block at offset 323 — 6-byte header
    ``(const_id, sv_id, reserved, aux, flag, reserved)`` followed by
    16 bytes that hold four little-endian float32 values.  When the
    float block is populated the layout matches :class:`V10SvResidual`
    exactly (verified across const_id 0x01, 0x03, 0x07 — f0/f1 straddle
    zero, f2/f3 strictly positive with variance-like ranges).  GLONASS
    slots (const_id=0x02) have an all-zero 16-byte float block on every
    firmware observed (several LM960 builds, EG18-NA, EG25-G, EM7511) —
    this is a baseband-design choice, not firmware-specific.

    ``const_id`` mapping (see ``_V10_CONST_ID_NAMES`` for the canonical
    table):

    - 0x01 — GPS (primary block at offset 323, not here).
    - 0x02 — GLONASS.  sv_id 65..96.  ``aux`` (byte 3) is the **signed
      int8 GLONASS FCN** in [-7, +6], matching FDMA channel convention.
    - 0x04 — BeiDou.  sv_id 219..230 (PRN − 200 ∈ [19, 30]).
    - 0x06 / 0x07 — **Galileo** (inferred from an EM7511 capture
      where 0x147E RF-config declared GPS/GLO/BDS/GAL; 0x06 sv_id −50 ∈
      [1, 28], 0x07 sv_id −46 ∈ [1, 24] — different signal-band slots).
      Float block populated only on 0x07 (measurement-engine track).
    - 0x0a — **SBAS / QZSS** augmentation bucket (sv_id 133/135 are WAAS
      GEO PRNs; sv_id 194 falls in Sierra AT!GPSSATINFO QZSS range
      193-197; never carries floats).
    - 0x03 — **GLONASS measurement-engine track**.  Same sv_id range
      (65..96) and byte-3 FCN encoding as 0x02, but floats populated
      with Kalman residuals.  Verified via LM960 records where
      const=0x03 sv=84 (R20) byte3=+2 co-appears with
      const=0x02 entries in the same record — R20's real assigned
      FCN is +2.

    General pattern: **odd const_ids carry Kalman residuals (measurement
    engine); even ones are acquisition-only (floats always zero)**.
    See ``is_measurement_track`` and the module-level comment for the
    packed (constellation_index, engine_track_bit) decoding.
    """
    const_id: int
    sv_id: int
    aux: int                # byte 3 — signed FCN for GLONASS
    flag: int
    f0: float
    f1: float
    f2: float
    f3: float

    @property
    def constellation(self) -> str | None:
        """Constellation name if inferable from const_id or sv_id range."""
        return _constellation_name_for_secondary_sv(self.const_id, self.sv_id)

    @property
    def is_measurement_track(self) -> bool:
        """True when this slot carries Kalman residuals/variances (odd const_id).

        Even const_ids are acquisition / secondary-band tracks whose
        16-byte float block is always zero.
        """
        return _is_measurement_track(self.const_id)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            'const_id': self.const_id,
            'sv_id': self.sv_id,
            'flag': self.flag,
        }
        name = self.constellation
        if name is not None:
            out['constellation'] = name
        out['measurement_track'] = self.is_measurement_track
        if self.const_id in (0x02, 0x03):
            # GLONASS byte 3 is the signed int8 FCN on both the
            # acquisition (0x02) and measurement (0x03) tracks.
            out['fcn'] = self.aux
        else:
            out['aux'] = self.aux
        if any(f != 0.0 for f in (self.f0, self.f1, self.f2, self.f3)):
            # Float layout verified to match the GPS Kalman residual/
            # variance struct on every const_id that populates floats.
            # Use the same ``possibly_`` prefix as V10SvResidual
            # to signal the semantic hypothesis isn't independently
            # verified against ground truth.
            out['floats'] = {
                'possibly_pr_residual_m': self.f0,
                'possibly_rr_residual_mps': self.f1,
                'possibly_pr_variance_m2': self.f2,
                'possibly_rr_variance_m2ps2': self.f3,
            }
        return out


def _parse_v10_secondary_sv_block(data: bytes) -> list[V10SecondarySv]:
    """Walk the v10 secondary SV block at offset 741.

    Same 22-byte stride as the GPS block at offset 323.  Terminates at
    the first fully-zero slot (const_id=0, sv_id=0, floats all zero) or
    at the 19-slot cap (which stays inside the observed populated
    region 741..1159 and leaves the reserved 1160..2324 zone untouched).

    Byte 3 is decoded as a **signed int8** and stored in ``aux`` — for
    GLONASS (const_id=2) that's the FCN in [-7, +6].  For non-GLONASS
    const_ids the byte-3 semantics aren't verified; the value is
    preserved as-is.
    """
    out: list[V10SecondarySv] = []
    if len(data) < _V10_TAIL_SECOND_SV_BLOCK_START + _V10_TRAILER_SV_ENTRY_SIZE:
        return out
    off = _V10_TAIL_SECOND_SV_BLOCK_START
    for _ in range(_V10_SECONDARY_BLOCK_SLOTS):
        if off + _V10_TRAILER_SV_ENTRY_SIZE > len(data):
            break
        const_id = data[off]
        sv_id = data[off + 1]
        byte3 = data[off + 3]
        flag = data[off + 4]
        f0, f1, f2, f3 = unpack_from('<ffff', data, off + 6)
        # Stop at the first fully-empty slot — the block is variable-
        # length; padding is pure zeros.
        if (const_id == 0 and sv_id == 0 and byte3 == 0 and flag == 0
                and f0 == 0.0 and f1 == 0.0 and f2 == 0.0 and f3 == 0.0):
            break
        # Decode byte 3 as signed int8 (FCN for GLONASS).
        aux = byte3 - 256 if byte3 >= 128 else byte3
        out.append(V10SecondarySv(
            const_id=const_id, sv_id=sv_id, aux=aux, flag=flag,
            f0=f0, f1=f1, f2=f2, f3=f3,
        ))
        off += _V10_TRAILER_SV_ENTRY_SIZE
    return out


def scan_v10_tail_nonzero(data: bytes) -> dict:
    """Characterize the v10 0x1476 tail region (bytes 741..2324).

    Across 6342 v10 records (Sierra EM7511, several Telit LM960 builds,
    EG18-NA) the tail is populated on 66% of records, with a consistent
    22-byte-strided structure at offset 741+ that mirrors the GPS SV
    block layout at offset 323 — the secondary multi-constellation SV
    block decoded by :func:`_parse_v10_secondary_sv_block`. Some captures
    carry all-zero tails.

    Returns a dict with:
      - ``tail_nonzero_bytes`` (int): count of non-zero bytes in 741..2324
      - ``tail_first_nonzero_offset`` (int): first non-zero offset, or -1
      - ``tail_has_strided_sv_block`` (bool): non-zero bytes observed at
        the predicted SV block headers (741, 763, 785, ...) — heuristic
        that this record carries a populated secondary SV block

    On pos_source=4 (prediction-only) records the tail is always
    all-zero, so callers can skip this detector when pos_source==4
    to save work.
    """
    if len(data) < _V10_TAIL_END:
        return {
            'tail_nonzero_bytes': 0,
            'tail_first_nonzero_offset': -1,
            'tail_has_strided_sv_block': False,
        }
    tail = data[_V10_TAIL_START:_V10_TAIL_END]
    if not any(tail):
        return {
            'tail_nonzero_bytes': 0,
            'tail_first_nonzero_offset': -1,
            'tail_has_strided_sv_block': False,
        }
    first = next(i for i, b in enumerate(tail) if b != 0)
    count = sum(1 for b in tail if b != 0)
    # Heuristic: if the first three predicted SV slot headers are all
    # non-zero (741, 763, 785), treat the tail as carrying the strided
    # SV block — matches the GPS block layout at offset 323.
    slot0 = data[_V10_TAIL_SECOND_SV_BLOCK_START] != 0
    slot1 = data[_V10_TAIL_SECOND_SV_BLOCK_START + _V10_TRAILER_SV_ENTRY_SIZE] != 0
    slot2 = data[_V10_TAIL_SECOND_SV_BLOCK_START + 2 * _V10_TRAILER_SV_ENTRY_SIZE] != 0
    return {
        'tail_nonzero_bytes': count,
        'tail_first_nonzero_offset': _V10_TAIL_START + first,
        'tail_has_strided_sv_block': slot0 and slot1 and slot2,
    }


def _dop_triple_valid(data: bytes, off: int) -> bool:
    """True if bytes at ``off`` hold a valid DOP triple.

    A valid triple has pdop/hdop/vdop all in (0.5, 50) and satisfies the
    motion-independent identity ``pdop² = hdop² + vdop²`` (2% tolerance).
    Used to decide whether a version-specific DOP offset is trustworthy or
    the identity search (:func:`_find_dop_offset`) should be consulted.
    """
    if len(data) < off + 12:
        return False
    f1 = unpack_from('<f', data, off)[0]
    f2 = unpack_from('<f', data, off + 4)[0]
    f3 = unpack_from('<f', data, off + 8)[0]
    if not (0.5 < f1 < 50 and 0.5 < f2 < 50 and 0.5 < f3 < 50):
        return False
    return abs(f1 - (f2 ** 2 + f3 ** 2) ** 0.5) < 0.02 * max(f1, 1.0)


def _find_dop_offset(data: bytes) -> int:
    """Find the PDOP float offset by searching for a DOP triplet.

    DOP triplets satisfy: pdop = sqrt(hdop^2 + vdop^2) with all values
    in (0.5, 50.0).  Searches the float block region starting after the
    sentinel zone.

    Returns the byte offset of PDOP, or -1 if not found.
    """
    # Sentinel zone starts at float[16] (offset 129).  Scan from float[40]
    # onward to skip early floats and most sentinels.
    # Start at offset 65 + 40*4 = 225 (float-block-aligned).
    for off in range(65 + 40 * 4, min(len(data) - 11, 600), 4):
        f1 = unpack_from('<f', data, off)[0]
        f2 = unpack_from('<f', data, off + 4)[0]
        f3 = unpack_from('<f', data, off + 8)[0]
        if 0.5 < f1 < 50 and 0.5 < f2 < 50 and 0.5 < f3 < 50:
            expected = (f2 ** 2 + f3 ** 2) ** 0.5
            if abs(f1 - expected) < 0.02:
                return off
    return -1


def _parse_0x1476_v13(log_time: int, data: bytes) -> Diag0x1476:
    """Parse a v13+ Diag0x1476 (SDX55/SDX62+).

    Handles both v13 (2477 bytes, 65-float block, SDX55) and v24
    (1575+ bytes, 104-float block, SDX62).  The header (65 bytes) is
    identical between v13 and v24; the float block is extended in v24
    with 39 additional sentinel pairs, shifting DOP and tail offsets.

    v13 layout (2477 bytes):
      Header 0-64, float block 65-324 (65 floats),
      tail 325-406 (82 B), SV array 407-2476 (90 x 23 B)
      DOP at offsets 301/305/309, SV counts at 358-363

    v24 layout (1575+ bytes, variable):
      Header 0-64, float block 65-480 (104 floats),
      tail 481-1214 (734 B), SV array 1215+ (N x 30 B)
      DOP at offsets 461/465/469, SV counts at 565/567 (GPS),
      599/601 (GLO), 611 (BDS)
    """
    # Header fields — identical offsets for v13 and v24
    version = data[0]
    f_count = unpack_from('<I', data, 1)[0]
    pos_source = data[5]
    gps_week = unpack_from('<H', data, 32)[0]
    gps_tow_ms = unpack_from('<I', data, 34)[0]
    lat_rad = unpack_from('<d', data, 49)[0]
    lon_rad = unpack_from('<d', data, 57)[0]

    # Float block starts at offset 65 — first 15 floats are identical
    alt_m = unpack_from('<f', data, 65)[0]
    heading_rad = unpack_from('<f', data, 69)[0]
    heading_unc_rad = unpack_from('<f', data, 73)[0]
    vel_e = unpack_from('<f', data, 77)[0]
    vel_n = unpack_from('<f', data, 81)[0]
    vel_u = unpack_from('<f', data, 85)[0]
    vel_sigma_e = unpack_from('<f', data, 89)[0]
    vel_sigma_n = unpack_from('<f', data, 93)[0]
    vel_sigma_u = unpack_from('<f', data, 97)[0]

    # DOP offsets differ between v13 and v24.  Use version-specific
    # offsets first, with DOP-triplet search as fallback.
    if version >= 24 and len(data) >= 480:
        # v24: 104-float block, DOP at float[99-101] = offsets 461-469.
        # v26 (0x1a, Foxconn T99W640, 1245-1365 B) also routes here (26 >= 24)
        # and the @461 DOP offset is measured-correct for it:
        # the pythagorean identity holds on all genuine v26 triples, and the
        # 500.0 no-DOP sentinel / prediction epochs render absent as expected.
        pdop_off = 461
    else:
        # v13: 65-float block, DOP at float[59-61] = offsets 301-309
        pdop_off = 301

    # Validate the version-specific offset and fall back to the identity
    # search when it does NOT hold a valid DOP triple. Checking only for the
    # exact 599584.9375 "no-DOP" sentinel is not enough: v21 (0x15) routes
    # here (21 >= 13) but its DOP triple sits at the *v24* offset
    # 461/465/469, and its v13 offset 301 reads a constant 0.0, not the
    # sentinel. On the Inseego M3100 (SDX65) the identity pdop²=hdop²+vdop²
    # holds at @461 on all 70 real-fix (pos_source 2/8) records and never at
    # @301; v21's @301 is 0.0 in 311/311 records. Testing "not a valid triple
    # here" rather than "exactly the sentinel here" also covers a genuine
    # no-DOP epoch (0.0 / 500.0), where the search returns -1 and the offset —
    # and its non-physical value, rendered absent by to_dict — is left as-is.
    if not _dop_triple_valid(data, pdop_off):
        found = _find_dop_offset(data)
        if found > 0:
            pdop_off = found

    pdop = unpack_from('<f', data, pdop_off)[0] if len(data) > pdop_off + 3 else 0.0
    hdop = unpack_from('<f', data, pdop_off + 4)[0] if len(data) > pdop_off + 7 else 0.0
    vdop = unpack_from('<f', data, pdop_off + 8)[0] if len(data) > pdop_off + 11 else 0.0

    # SV counts — version-specific tail offsets
    if version >= 24 and len(data) >= 612:
        # v24 tail: SV counts at byte offsets 565/567 (GPS), 599/601 (GLO),
        # 611 (BDS).  Each count is a uint8 with a zero-pad byte between.
        num_gps_svs = data[565]
        total_gps_svs = data[567]
        num_glo_svs = data[599]
        total_glo_svs = data[601]
        num_bds_svs = data[611] if len(data) > 611 else 0
        total_bds_svs = 0  # BDS total not yet located in v24
    else:
        # v13 tail: SV counts at offsets 358-363 (consecutive bytes)
        num_gps_svs = data[358] if len(data) > 358 else 0
        total_gps_svs = data[359] if len(data) > 359 else 0
        num_glo_svs = data[360] if len(data) > 360 else 0
        total_glo_svs = data[361] if len(data) > 361 else 0
        num_bds_svs = data[362] if len(data) > 362 else 0
        total_bds_svs = data[363] if len(data) > 363 else 0

    return Diag0x1476(
        log_time=log_time, version=version, f_count=f_count,
        pos_source=pos_source, gps_week=gps_week, gps_tow_ms=gps_tow_ms,
        lat_rad=lat_rad, lon_rad=lon_rad, alt_m=alt_m,
        heading_rad=heading_rad, heading_unc_rad=heading_unc_rad,
        vel_e=vel_e, vel_n=vel_n, vel_u=vel_u,
        vel_sigma_e=vel_sigma_e, vel_sigma_n=vel_sigma_n, vel_sigma_u=vel_sigma_u,
        pdop=pdop, hdop=hdop, vdop=vdop,
        num_gps_svs=num_gps_svs, total_gps_svs=total_gps_svs,
        num_glo_svs=num_glo_svs, total_glo_svs=total_glo_svs,
        num_bds_svs=num_bds_svs, total_bds_svs=total_bds_svs,
    )


# MDM9600/SWI9200X per-SV GPS tracking array. 20-byte slots from
# offset 198, u16 LE PRN at slot+0, zero-PRN-terminated. Cross-
# validated on a 16-SV and a 4-SV MC7700 capture.
_MDM9600_SV_BASE = 198
_MDM9600_SV_STRIDE = 20
_MDM9600_SV_MAX = 14  # generous cap; real arrays observed at 9–11 GPS slots


def _parse_mdm9600_gps_sv_block(data: bytes) -> list[int]:
    """Decode the GPS PRN list from the MDM9600/SWI9200X 0x1476 trailer.

    The array is a 20-byte-stride table starting at offset 198; each slot's
    first u16 (LE) is the GPS PRN. Slots run in tracking-channel order (roughly
    ascending; first slot = lowest tracked PRN) and the block is terminated by a
    zero PRN (or a non-GPS-PRN value, or end of record). PRNs are bounded to
    the GPS range 1..32 — a foreign/corrupt 797 B record that lands non-PRN
    bytes here yields an empty list rather than a garbage SV count, matching
    the conservative posture of the header / DOP guards.

    The stride is established on a 16-SV MC7700 capture, where the array's
    first slot is PRN 5 — the lowest AT!GPSSATINFO in-view GPS PRN — and the
    PRN union covers every AT in-view GPS PRN. The per-slot float32
    sub-fields (Kalman residual / measurement class) are not decoded.
    """
    prns: list[int] = []
    for i in range(_MDM9600_SV_MAX):
        off = _MDM9600_SV_BASE + i * _MDM9600_SV_STRIDE
        if off + 2 > len(data):
            break
        prn = unpack_from('<H', data, off)[0]
        if prn == 0:
            break
        if 1 <= prn <= 32:
            prns.append(prn)
        else:
            break  # non-GPS-PRN byte → end of the GPS block (don't mis-decode)
    return prns


def _parse_0x1476_mdm9600(log_time: int, data: bytes) -> Diag0x1476:
    """Parse the MDM9600 / SWI9200X (legacy gpsOne/PDS) 0x1476 variant.

    Version byte is ``0x02`` (same as the MDM9607 ``_POS_FMT`` family) but the
    layout differs: the 4-byte ``fake_align`` field that ``_POS_FMT`` carries
    between ``fix_events`` and ``gps_week`` is **absent**, so every field from
    the GPS week onward is 4 bytes earlier. The discriminator is the
    ``(version==2, len==797)`` pair (see ``_POS_MDM9600_SZ``).

    Validated against 1799 records of a stationary MC7700 capture (and
    reproduced on two other firmware builds): the header decodes to
    gps_week=1397, a valid in-week TOW matching the concurrent 0x1477
    measurement clock, and lat/lon/alt matching the known stationary
    position — fields that a ``_POS_FMT`` parse turns to garbage.

    **Scope.** Header fields confirmed byte-for-byte: ``version``,
    ``f_count``, ``pos_source``, ``gps_week``, ``gps_tow_ms``, ``lat_rad``,
    ``lon_rad``, ``alt_m``. Trailer fields (1799-record stationary
    capture): the velocity block resumes the ``_POS_FMT`` field order
    contiguously after ``alt_m`` — ``heading_rad``@56, ``heading_unc_rad``@60,
    ``vel_e/n/u``@64/68/72, ``vel_sigma_e/n/u``@76/80/84 — and the **DOP
    triple** ``pdop``@144 / ``hdop``@148 / ``vdop``@152, structurally pinned by
    the motion-independent identity ``pdop² = hdop² + vdop²`` holding in
    1799/1799 records (guarded; zeroed if a record fails it), and the
    **per-SV GPS tracking array** — a 20-byte-stride table from offset 198 with
    a u16 LE PRN at each slot+0, decoded into ``gps_sv_prns`` /
    ``num_gps_svs``. The stride is established on a 16-SV capture: its first
    slot is PRN 5 (the lowest AT!GPSSATINFO in-view GPS PRN) and the array's
    PRN union covers every AT in-view GPS PRN; a 4-SV capture's array carries
    PRN 28 (its one in-view GPS SV). See ``_parse_mdm9600_gps_sv_block``.

    **Byte 196 is not a satellites-in-view count.** It equals 0 in all 1801
    records of a solid 16-SV fix, so it is not emitted.

    **SBAS/GLONASS SV arrays are NOT present in 0x1476** on the
    MC7700/SWI9200X. On a capture where ``AT!GPSSATINFO`` reports 16 SVs in
    view — 8–10 GPS plus SBAS PRN **46/48** and 6×PRN-255 (unlabeled) —
    across 200 steady records: (a) the GPS stride-20 array never exceeds
    slot 10 and **no non-GPS PRN ever continues it** (so SBAS does not extend
    the GPS block); (b) PRN 46/48 appear **nowhere** as a stable u16/u8, and
    no standard SBAS numbering (120–158) appears as a stable PRN; (c) the
    **entire tail [398:797] is all-zero in 200/200 records**. 0x1476 is the
    gpsOne/PDS **position-solution** report and carries only the GPS SVs used
    in the (GPS-only 2D) fix; the full satellites-in-view set
    (SBAS-for-corrections + GLONASS/255) is carried by the SV-measurement
    codes 0x1440 / 0x13BA / 0x150B.

    **Not decoded.** The per-slot float32 sub-fields (present at slot+2..)
    are **internal Kalman-residual / measurement-weight floats, NOT the AT
    SV-info**: a direct correlation against ``AT!GPSSATINFO`` ELEV/AZI/SNR
    (e.g. PRN 5 = 21°/50°/42) finds none of those integers in the slot as
    plain byte/u16, so they stay unnamed rather than mis-mapped to
    elev/azi/snr. The 88–144 "uncertainty" gap is also undecoded: the
    AT!GPSLOC LocUncA/P (3.0) / LocUncVe (4.0) / HEPE (4.242 = 3·√2, a
    derived term) appear nowhere as plain float32.
    """
    # Header, with the _POS_FMT `fake_align` u32 removed → everything from
    # gps_week (offset 19, was 23) onward shifts 4 bytes earlier.
    version = data[0]
    f_count = unpack_from('<I', data, 1)[0]
    pos_source = data[5]
    gps_week = unpack_from('<H', data, 19)[0]
    gps_tow_ms = unpack_from('<I', data, 21)[0]
    lat_rad = unpack_from('<d', data, 36)[0]
    lon_rad = unpack_from('<d', data, 44)[0]
    alt_m = unpack_from('<f', data, 52)[0]

    # Structural guard: a 797 B v2 record that fails these is corrupt/foreign,
    # not a layout to silently emit garbage for (matches the
    # raise-on-bad-data posture of the other 0x1476 paths).
    if not (0 < gps_week and 0 <= gps_tow_ms < 604_800_000):
        raise ValueError(
            f"MDM9600 0x1476: implausible time week={gps_week} tow={gps_tow_ms}"
        )
    if not (-math.pi / 2 <= lat_rad <= math.pi / 2 and -math.pi <= lon_rad <= math.pi):
        raise ValueError(
            f"MDM9600 0x1476: lat/lon out of range "
            f"({lat_rad} rad, {lon_rad} rad)"
        )

    # Velocity block: the _POS_FMT field ORDER resumes
    # contiguously right after the header's alt_m (offset 52→56) — heading,
    # heading_unc, vel_e/n/u, vel_sigma_e/n/u — then a 56-byte gap (clock /
    # uncertainty fields, not yet named) before the DOP triple at 144.
    # Grounded on a 1799-record stationary MC7700 capture: heading@56 and
    # vel_e/n/u@64/68/72 are
    # 0.0 in 1799/1799 records, matching the concurrent ``AT!GPSLOC?``
    # (Heading 0.0 deg, VelHoriz/VelVert 0 m/s); vel_sigma@76/80/84 carry
    # real nonzero uncertainties (0.01–1.36 m/s).
    heading_rad = unpack_from('<f', data, 56)[0]
    heading_unc_rad = unpack_from('<f', data, 60)[0]
    vel_e = unpack_from('<f', data, 64)[0]
    vel_n = unpack_from('<f', data, 68)[0]
    vel_u = unpack_from('<f', data, 72)[0]
    vel_sigma_e = unpack_from('<f', data, 76)[0]
    vel_sigma_n = unpack_from('<f', data, 80)[0]
    vel_sigma_u = unpack_from('<f', data, 84)[0]

    # DOP triple @144/148/152. Structurally pinned, motion-independent: the
    # pythagorean identity pdop² = hdop² + vdop² holds in 1799/1799 records
    # at exactly this offset (no other trailer offset satisfies it). Guard
    # against a foreign/corrupt record by requiring the identity + a sane
    # range before trusting it; otherwise leave DOP at zero (do not
    # mis-attribute — same posture as the conservative header guards above).
    pdop = unpack_from('<f', data, 144)[0]
    hdop = unpack_from('<f', data, 148)[0]
    vdop = unpack_from('<f', data, 152)[0]
    if not (
        0.0 < pdop < 100.0 and 0.0 < hdop < 100.0 and 0.0 < vdop < 100.0
        and abs(pdop * pdop - (hdop * hdop + vdop * vdop)) < 0.05 * max(pdop * pdop, 1.0)
    ):
        pdop = hdop = vdop = 0.0

    # Per-SV GPS tracking array: GPS PRNs sit in a 20-byte-stride array
    # starting at offset 198 (u16 LE PRN @ slot+0), zero-PRN-terminated. On a
    # 16-SV capture the first slot = PRN 5 — exactly the lowest AT!GPSSATINFO
    # in-view GPS PRN — and the array's PRN union contains every AT in-view
    # GPS PRN (5/15/18/20/23/26/27/29) plus tracking-only channels; a 4-SV
    # capture's array contains PRN 28 (its one in-view GPS SV). See
    # `_parse_mdm9600_gps_sv_block`.
    gps_sv_prns = _parse_mdm9600_gps_sv_block(data)

    # Byte 196 is not an SV count (0 in all 1801 records of a solid 16-SV fix)
    # and is left undecoded. Also undecoded: the per-slot float32 sub-fields
    # (Kalman residual / measurement class, at slot+2..) and the 88–144
    # "uncertainty" gap — HEPE 4.242 = 3.0·√2 is a DERIVED circular-error
    # term, not a stored meters-float. SBAS/GLONASS SV arrays are not present
    # in this record.
    return Diag0x1476(
        log_time=log_time, version=version, f_count=f_count,
        pos_source=pos_source, gps_week=gps_week, gps_tow_ms=gps_tow_ms,
        lat_rad=lat_rad, lon_rad=lon_rad, alt_m=alt_m,
        heading_rad=heading_rad, heading_unc_rad=heading_unc_rad,
        vel_e=vel_e, vel_n=vel_n, vel_u=vel_u,
        vel_sigma_e=vel_sigma_e, vel_sigma_n=vel_sigma_n, vel_sigma_u=vel_sigma_u,
        pdop=pdop, hdop=hdop, vdop=vdop,
        num_gps_svs=len(gps_sv_prns), total_gps_svs=len(gps_sv_prns),
        num_glo_svs=0, total_glo_svs=0,
        num_bds_svs=0, total_bds_svs=0,
        gps_sv_prns=gps_sv_prns,
    )


# ---------------------------------------------------------------------------
# Ground-truth recipe
# ---------------------------------------------------------------------------
# v0x18 (24) is the RM520N-GL (SDX62) emission: a corpus body-walk of
# RM520N-GL captures shows byte-0 == 0x18 on 3263/3266 sampled records
# (a handful of v=0x15 stragglers). This is the modern v13+ SDX55/SDX62
# layout, the same physical fix LOG_GNSS_POSITION_REPORT carries.

# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

# Layer-1 gate on the DECLARED version enum: an undeclared version returns
# None so the registry WARN fires instead of a silent mis-decode.
_VERSIONS_1476_4918: tuple[int, ...] = (0x02, 0x06, 0x07, 0x08, 0x0A, 0x0C, 0x0D, 0x15, 0x18, 0x1A)


# Layout-implied minimum sizes / SV-array geometry.
#
# * v13 (0x0d, SDX55): fixed layout header(65) + 65 floats + tail(82) + a
#   fixed-capacity 90 x 23 B SV array = 2477 B (corpus len_min 2477).
# * v24 (0x18) / v26 (0x1a): the SV array starts at 1215 and is N x 30 B
#   (see the module docstring); corpus 1245..2985 / 1245..1365, all on-grid.
# * v21 (0x15): the same 30 B SV-entry stride over a 647 B base (647 B =
#   prediction epochs with no SV entries; 1547 B real-fix = 647 + 30 x 30;
#   corpus 647..2267, all on-grid).
# * v2 (0x02): the only attested v2 is the 797 B MDM9600 record; the 291 B
#   _POS_FMT v2 still parses, but 292..796 B is a truncated MDM9600 record.
# There is no length/count field in any of these headers, so the stride is the
# only integrity check available: a trailing partial SV entry means the record
# was cut. v7/v8/v10 have no stride either; they are gated on their attested
# sizes (_ATTESTED_SZ below; v10's 645..1821 B one-offs are single records,
# not a variable layout), and v7/v8 keep the 291 B plain-path length used by
# the shared .ksy / C++ synthetic contract fixtures.
_POS_V13_FIXED_SZ = 2477
_SV30_STRIDE = 30
_SV30_BASE = {0x15: 647, 0x18: 1215, 0x1A: 1215}
# Attested lengths of the versions with no length field and no grid (corpus
# census: v7 10,323 x 2115 B; v8 4,924 x 2229 B; v10 103,340 x 2237 /
# 475,916 x 2325 / 726,367 x 2332 B). Below the largest, only an attested
# size is a record; the rest is a cut record.
_ATTESTED_SZ = {0x07: (2115,), 0x08: (2229,), 0x0A: (2237, 2325, 2332)}
# v7/v8 also keep the bare 291 B _POS_FMT length: the frozen .ksy / C++
# contract fixtures are 291 B v7/v8 records. No corpus v7/v8 record is
# 291 B, and a cut 2115/2229 B record never is either.
_PLAIN_291_VERSIONS = (0x07, 0x08)


# v6 / v12 compact header. The v13 header field
# ORDER, packed tighter: [week u16][tow u32][glo_4yr u8][glo_days u16]
# [glo_tow u32][u32 counter][lat f64][lon f64][float block: alt, heading,
# heading_unc, vel_e/n/u, vel_sigma_e/n/u], starting at a version-specific base
# B (week offset): v6 B=19 (AirCard 791L, MDM9x35, 1175 B), v12 B=24 (Quectel
# EM160R / EM120R, SDX24, 1895 B) — v13 is the same order at B=32. Grounded vs
# co-temporal F3 (see source_detail). Exact sizes only: the two sizes
# observed, so a size drift is loud rather than decoded.
_COMPACT_HDR_BASE = {0x06: 19, 0x0C: 24}
_COMPACT_FIXED_SZ = {0x06: 1175, 0x0C: 1895}


def _parse_0x1476_compact(log_time: int, data: bytes) -> Diag0x1476:
    """v6 / v12 compact-header position report.

    Both corpora are pos_source=4 (database/prediction) epochs with no fix, so
    only the header is grounded: gps_week/gps_tow_ms, the GLONASS time block,
    lat/lon and alt. The float block (heading, velocity, sigmas) is read in the
    v13 field order at the shifted base — structurally consistent (heading
    holds the -999.0 invalid sentinel on both versions) but not independently
    grounded. DOP and SV counts are NOT located on these versions: DOP is 0.0
    (rendered absent) and SV counts 0.
    """
    b = _COMPACT_HDR_BASE[data[0]]
    fl = b + 33
    (alt_m, heading_rad, heading_unc_rad, vel_e, vel_n, vel_u,
     vel_sigma_e, vel_sigma_n, vel_sigma_u) = unpack_from('<9f', data, fl)
    return Diag0x1476(
        log_time=log_time, version=data[0],
        f_count=unpack_from('<I', data, 1)[0],
        pos_source=data[5],
        gps_week=unpack_from('<H', data, b)[0],
        gps_tow_ms=unpack_from('<I', data, b + 2)[0],
        lat_rad=unpack_from('<d', data, b + 17)[0],
        lon_rad=unpack_from('<d', data, b + 25)[0],
        alt_m=alt_m, heading_rad=heading_rad, heading_unc_rad=heading_unc_rad,
        vel_e=vel_e, vel_n=vel_n, vel_u=vel_u,
        vel_sigma_e=vel_sigma_e, vel_sigma_n=vel_sigma_n, vel_sigma_u=vel_sigma_u,
        pdop=0.0, hdop=0.0, vdop=0.0,
        num_gps_svs=0, total_gps_svs=0, num_glo_svs=0, total_glo_svs=0,
        num_bds_svs=0, total_bds_svs=0,
        glo_four_year=data[b + 6],
        glo_days=unpack_from('<H', data, b + 7)[0],
        glo_tow_ms=unpack_from('<I', data, b + 9)[0],
    )


def _length_fits_layout(version: int, n: int) -> bool:
    """False when ``n`` bytes cannot hold the layout ``version`` implies."""
    if version in _COMPACT_FIXED_SZ:
        return n == _COMPACT_FIXED_SZ[version]
    if version == 2:
        return not (_POS_SZ < n < _POS_MDM9600_SZ)
    if version == 13:
        return n >= _POS_V13_FIXED_SZ
    sizes = _ATTESTED_SZ.get(version)
    if sizes is not None:
        return (n in sizes or n > max(sizes)
                or (version in _PLAIN_291_VERSIONS and n == _POS_SZ))
    base = _SV30_BASE.get(version)
    if base is not None:
        return n >= base and (n - base) % _SV30_STRIDE == 0
    return True


@register(LOG_GNSS_POSITION_REPORT, domain="gnss",
    name="0x1476",
    description="Fix position, velocity, DOP, SV counts; v10 (SDX20 V2) trailer decoded with per-SV Kalman residuals, intermediate block and multi-constellation secondary SV block (all 7 observed const_ids named — GPS/GLONASS/BeiDou/Galileo/SBAS; odd const_ids are measurement-engine tracks); v1/v2/v6/v7/v8/v12/v13/v21/v24/v26 layouts; MDM9600/SWI9200X 797B legacy gpsOne variant — header, velocity block (heading/vel/vel_sigma), DOP triple (pdop²=hdop²+vdop² pinned) and per-SV GPS PRN array (offset-198 stride-20) — supported",
    version=24,

    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail="Position-report layout established from our own GNSS DIAG capture corpus, not from third-party decoder source. Decoded variants: v1/v2 291 B _POS_FMT struct (MDM9607); MDM9600/SWI9200X 797 B v2 (Sierra MC7700, three firmware builds: header, velocity block, DOP triple @144 pinned by pdop²=hdop²+vdop² on 1799/1799 records, offset-198 stride-20 GPS PRN array); v7 (MC7455/EM7455, 2115 B), v8 (EP06A, 2229 B) and v10 (SDX20 V2, 2237/2325/2332 B) on the shared struct with the DOP triple at @228 (identity holds on 100% of real-fix records); v10 trailer: per-SV GPS Kalman residual/variance floats (variance and residual domains grounded against independent 0x14DE C/No), intermediate block, multi-constellation secondary SV block (const_ids named via an EM7511 capture with LG290P reference and LM960 GLONASS FCN cross-reference); v13 (SDX55, 2477 B), v21 (SDX65/SDX62, 647 B + N x 30 B), v24 (SDX62, 1215 B + N x 30 B) and v26 (T99W640, 1215 B + N x 30 B) on the v13/v24 path. Position is validated against same-antenna survey-grade LG290P fixes (EG25-G 2.84 m median, RM520N-GL 2.59 m, FN980 5.04 m, EG12-GT ~9 m) and field meanings against the firmware's own F3 prints (dsatm2mgpsif.c QMI_LOC DOP prints with the 500.0 no-DOP sentinel, tle_base.cpp 'PTM:ALE pos', LM960 gm_core.c/tle_log.c lat/lon). v6 (AirCard 791L MDM9x35, 1175 B) and v12 (EM160R/EM120R SDX24, 1895 B) use a compact header (the v13 header order at base 19 / 24; v13 = 32), F3-grounded: v12 (gps_week@24, gps_tow_ms@26) == ale_proc.c 'Nav solution GPS time (wk, tow)' 45/47 (shifts -6/-10/0 score 0/47); lat/lon @41/@49 round(deg*2^25/180) == loc_pd.c:2452/2454 coarse-position hex exactly; glo_four_year 255 == tm_core.c 'GLO4Year=255'; v6 lat/lon @36/@44 == tle_log.c 'TPC: Lat:38.000000, Lon:-117.000000' to 1e-9 deg 12/12, alt@52 == 'Alt:0.000000' 12/12 on the same DIAG tick; week 65535 == 'TimeValid:0'. All v6/v12 corpus epochs are pos_source=4 with no fix, so their float block (heading -999.0 invalid sentinel) is structural and DOP/SV counts are not located. Truncated payloads return None (registry WARN): v13 below 2477 B, v21/v24/v26 with a partial 30 B SV entry, v2 between 291 and 797 B, sub-291 B struct payloads, and v7/v8/v10 lengths below the largest attested size that are not themselves attested (v7/v8 also accept the bare 291 B struct used by the contract fixtures). Known gaps: v7/v8 trailer past the DOP triple, v26 SV tail, v13/v24 extended trailers, MDM9600 per-SV float sub-fields, Galileo/QZSS SV counts.",
    # 29 named top-level fields cover v1/v2 header + v10 per-SV GPS
    # residuals + secondary-SV block + intermediate block. Known
    # limitations: v10 intermediate-block 32B not fully field-named
    # (exposed as dict); Galileo/QZSS SV counts still not located in any
    # header field; v13/v24 extended trailers partially decoded; the
    # MDM9600/SWI9200X per-SV slot float32 sub-fields stay unnamed. Count
    # those as a single "remaining-gaps" field: 29 parsed / 30 identified.
    #
    fields_parsed=29,
    fields_identified=30,
    # Layer-2 plausibility. Derived from a corpus-wide walk
    # against 145,597 records / 231 captures / 14 chipset families
    # (EG12-GT, EG18-NA, EG25-G, EG95-NA, EM7511, EM9190, EP06A, FN980,
    # LM960, M2000, MC7411, MC7455, RM500Q, RM520N-GL, SIM7600NA).
    #
    # `version` enum [7, 8, 10, 13, 21, 24, 26]: every value observed at
    # offset+0. Crucially, v=7 (MC7455 SDX20-class only, 4,875 rec),
    # v=8 (EP06A MDM9x07 only, 3,698 rec) and v=21 (RM520N-GL early
    # capture only, 3 rec) are chipset-keyed minorities that would
    # silently mis-decode against an SDX55-only assumption; the (size,
    # version) profile reports the v=21 sample as a 647B/v=0x15 row.
    # v=26 (0x1a): Foxconn T99W640 / Dell DW5934e (SDX-class), 1245-1365 B,
    # 798 corpus rec — routes through the `version >= 24` branch,
    # header/float/DOP-@461 layout measured-correct (position drive-track +
    # pythagorean DOP on 7 genuine triples). v=6 (AirCard 791L, 1175 B,
    # 12 rec) and v=12 (0x0c, EM160R/EM120R, 1895 B, 159 rec) are decoded
    # on their own compact-header path.
    #
    # `pos_source` enum [0, 1, 2, 4, 8]: every value observed at
    # offset+5 across 141,328 records. The dataclass docstring lists
    # 0=None / 1=WLS / 2=Kalman / 3=Injected / 4=DB; 3 is documented
    # but never observed and 8 (combined) is observed but not in the
    # original enum. The check flags both directions of drift.
    field_invariants={
        # 2 includes the MDM9600/SWI9200X legacy gpsOne variant (797 B record,
        # fake_align-removed layout) — Sierra MC7700, three SWI9200X firmwares.
        "version": {"enum": [2, 6, 7, 8, 10, 12, 13, 21, 24, 26]},
        "pos_source": {"enum": [0, 1, 2, 4, 8]},
    },
    issues=(),
    primary_issue=None,
    wigle_direct=True,
    wigle_roles=("position", "gnss-quality", "timing-anchor:periodic"),
)
def parse_0x1476(log_time: int, data: bytes) -> Diag0x1476 | None:
    """Parse a LOG_GNSS_POSITION_REPORT (0x1476) log payload.

    Returns None (registry WARN) for an undeclared version or a record too
    short for its version's layout (see ``_length_fits_layout``).

    Supports v1/v2 (291 bytes, MDM9607), the MDM9600/SWI9200X legacy
    gpsOne variant (797 bytes, version byte 2, ``fake_align``-removed
    layout), v6/v12 (compact header), v7/v8/v10 (shared struct, v10 2325
    bytes on SDX20 V2), v13 (2477 bytes, SDX55), and v21/v24/v26 (SV-array
    stride 30 B; v24 1575+ bytes on SDX62).  The variant is detected from
    the first byte and packet size (the (version, size) pair).

    **v10 (EG18-NA / SDX20 V2)** details:

    - The fixed 291-byte v1/v2 struct maps over the first 291 bytes of the
      2325-byte v10 record for the header, velocity block and the
      GPS/GLONASS/BeiDou SV **counts** (@285..290), all of which decode to
      sensible values (e.g. gps_week=2413, lat/lon matching the capture site,
      num_glo/num_gps tracking the live fix).
    - **DOP is the exception — it is NOT at the struct offset.** The DOP
      triple sits 8 bytes EARLIER on v10 (pdop@228 / hdop@232 / vdop@236), so
      the struct's ``pdop``@236 is really the *vdop*. Pinned by
      pdop²=hdop²+vdop² (100% at @228 on MC7411/EM7511/SIM7600NA/LM960,
      0% at @236) and F3-confirmed field-by-field against the firmware's own
      QMI_LOC prints (``dsatm2mgpsif.c``:21496/21498/21500). The v10 branch below
      overrides the DOP read accordingly; 500.0 is the receiver "no-DOP"
      sentinel, 0.0 marks prediction-only epochs.
    - Three `pos_source` values are emitted by the modem each epoch:
      2 (raw ME fix), 4 (prediction from internal database), 8 (combined).
      All three have identical header/float-block layouts; the trailer
      SV data is populated only on pos_source 2 and 8.
    - The trailer starts at offset 291 with a 32-byte intermediate block
      whose fields are only partly identified (see
      ``_parse_v10_intermediate_block``).
    - Starting at offset 323, the GPS SV block holds up to 19 slots × 22
      bytes (418 bytes total).  Each slot is a 6-byte header
      ``[const_id=0x01, sv_id, 0x00, 0x00, flag, 0x00]`` followed by a
      16-byte per-SV data block of Kalman-filter measurement residuals
      and variances (NOT az / el / C/N0 — those fields live in
      0x14DE `OemdreMeasurementReport`; see ``V10SvResidual``).  This
      parser walks the first `num_gps_svs` slots and returns the PRN list
      as `svs.gps.prns`.
    - Starting at offset 741 is a **secondary multi-constellation SV
      block** — same 22-byte stride as the GPS block, up to 19 slots.
      ``const_id`` identifies the constellation per slot (not per block):
      0x02/0x03 are GLONASS (sv_id 65..96, byte 3 = signed int8 FCN ∈
      [-7, +6]), 0x04 BeiDou, 0x06/0x07 Galileo, 0x0a SBAS/QZSS (see
      ``V10SecondarySv``).
      The block is populated on 66% of v10 records across the full
      corpus (Sierra EM7511, several Telit LM960 builds, EG18-NA); some
      captures carry an empty tail.
      GLONASS slots have an all-zero 16-byte float block on the
      observed corpus (the tracker doesn't populate residuals for
      GLONASS even when the SV is tracked), while some non-GLONASS
      const_ids (0x03, 0x07) do carry non-zero floats with
      pseudorange-residual magnitudes.  The slot count can be **less
      than** ``num_glo_svs`` from the header (LM960:
      header says 5 GLONASS used but only 3 slots populated) —
      the block appears to be capacity-limited.  Decoded
      slots are exposed in:
        - ``svs.glonass.prns`` / ``svs.glonass.fcns`` /
          ``svs.glonass.tracked`` (const_id 0x02/0x03 entries)
        - ``svs.beidou`` / ``svs.galileo`` / ``svs.sbas`` buckets
        - ``svs.by_const_id`` (grouped by raw const_id for any other ID)
        - ``secondary_svs`` on the dataclass (full per-slot detail)
      The tail is still **always zero on pos_source=4** (prediction-only
      epochs).
    - Bytes 1160..2324 remain zero on the entire observed corpus.
    - Galileo / QZSS SV **counts** are still not surfaced in any known
      header field and have not been located in the trailer either.
    """
    if not data or data[0] not in _VERSIONS_1476_4918:  # loud version gate
        return None
    version = data[0]
    if not _length_fits_layout(version, len(data)):
        return None  # truncated for its layout — registry WARN

    # MDM9600 / SWI9200X legacy variant: version byte 2 but a 797 B
    # record with the `fake_align`-removed layout. Gate on the stable
    # (version, size) pair before the _POS_FMT path, which would otherwise
    # mis-parse it (the 291 B struct lands week/tow/lat/lon on wrong bytes).
    if version == 2 and len(data) == _POS_MDM9600_SZ:
        return _parse_0x1476_mdm9600(log_time, data)

    # v6 / v12 compact header: before the v13 / 291 B paths, neither
    # of which fits (both read f_count/time/position off the wrong bytes).
    if version in _COMPACT_HDR_BASE:
        return _parse_0x1476_compact(log_time, data)

    if version >= 13 and len(data) >= _POS_V13_MIN_SZ:
        return _parse_0x1476_v13(log_time, data)

    # v1/v2 (291 bytes) and v10 (2325 bytes SDX20 V2) share the same
    # fixed-layout 291-byte struct.
    if len(data) < _POS_SZ:
        return None  # loud decline (registry WARN), not a ValueError
    d = unpack_dict(_POS_FMT, _POS_FIELDS, data)

    # v10-only: walk the trailer GPS SV block for the PRN list + residuals,
    # and decode the intermediate block.
    gps_prns: list[int] = []
    gps_residuals: list[V10SvResidual] = []
    v10_intermediate: dict = {}
    secondary_svs: list[V10SecondarySv] = []
    pdop, hdop, vdop = d['pdop'], d['hdop'], d['vdop']
    # DOP: the large-record GNSS variants — v7 (Sierra
    # MC7455/EM7455, MDM9x30), v8 (Quectel EP06A, MDM9x07) and v10 (SDX20 V2)
    # — all place the DOP triple 8 bytes EARLIER than the v1/v2 _POS_FMT struct
    # does: pdop@228 / hdop@232 / vdop@236 (the struct reads @236/240/244, so
    # what it labels `pdop`@236 is really the *vdop*). Pinned by the motion-
    # independent identity pdop²=hdop²+vdop²:
    #   - v10: 100% at @228 on four modems (MC7411 903/903, EM7511 873/873,
    #     SIM7600NA 927/927 incl. 2237 B, LM960 80/80), 0% at @236; F3-confirmed
    #     field-by-field vs the firmware's own QMI_LOC prints
    #     (dsatm2mgpsif.c:21496/21498/21500 position/horizontal/vertical_dop).
    #   - v7/v8: 100% at @228 (v7 3583/3583, v8 1802/1802 real-fix
    #     pos_source 2/8 records) and 0% at the struct's @236 — the v10 @228
    #     shift applies to v7/v8 too; the struct offset would report the vdop
    #     slot as pdop. Sizes fixed 2115 B (v7) / 2229 B (v8).
    # 500.0 is the receiver "no-DOP" sentinel (F3-confirmed on v10); prediction-
    # only epochs (pos_source=4) write 0.0. Both are non-physical for a DOP
    # (≥1.0 always) and render absent via to_dict's validity window. The
    # SV-count bytes @285..290 are NOT shifted, so only the DOP read moves. v1/v2
    # (291 B) keep the struct offset — they never reach this branch (size < 323).
    # v21/v24 route through _parse_0x1476_v13 (version ≥ 13); v21 DOP @461.
    if version in (7, 8, 10) and len(data) >= _V10_TRAILER_GPS_BLOCK_START:
        pdop = unpack_from('<f', data, 228)[0]
        hdop = unpack_from('<f', data, 232)[0]
        vdop = unpack_from('<f', data, 236)[0]
    # v10-only: walk the decoded trailer (per-SV GPS Kalman residuals,
    # intermediate block, multi-constellation secondary SV block). The v7/v8
    # trailer layout past the DOP triple is not decoded, so they get the
    # corrected DOP above but no trailer decode.
    if version == 10 and len(data) >= _V10_TRAILER_GPS_BLOCK_START:
        gps_residuals = _parse_v10_gps_sv_entries(data, d['num_gps_svs'])
        gps_prns = [sv.sv_id for sv in gps_residuals]
        v10_intermediate = _parse_v10_intermediate_block(data)
        tail_info = scan_v10_tail_nonzero(data)
        v10_intermediate.update(tail_info)
        if tail_info.get('tail_has_strided_sv_block'):
            secondary_svs = _parse_v10_secondary_sv_block(data)

    return Diag0x1476(
        log_time=log_time,
        version=d['version'],
        f_count=d['f_count'],
        pos_source=d['pos_source'],
        gps_week=d['gps_week'],
        gps_tow_ms=d['gps_tow_ms'],
        lat_rad=d['lat_rad'],
        lon_rad=d['lon_rad'],
        alt_m=d['alt_m'],
        heading_rad=d['heading_rad'],
        heading_unc_rad=d['heading_unc_rad'],
        vel_e=d['vel_e'],
        vel_n=d['vel_n'],
        vel_u=d['vel_u'],
        vel_sigma_e=d['vel_sigma_e'],
        vel_sigma_n=d['vel_sigma_n'],
        vel_sigma_u=d['vel_sigma_u'],
        pdop=pdop,
        hdop=hdop,
        vdop=vdop,
        num_gps_svs=d['num_gps_svs'],
        total_gps_svs=d['total_gps_svs'],
        num_glo_svs=d['num_glo_svs'],
        total_glo_svs=d['total_glo_svs'],
        num_bds_svs=d['num_bds_svs'],
        total_bds_svs=d['total_bds_svs'],
        gps_sv_prns=gps_prns,
        gps_sv_residuals=gps_residuals,
        v10_intermediate=v10_intermediate,
        secondary_svs=secondary_svs,
        glo_four_year=d['glo_four_year'],
        glo_days=d['glo_days'],
        glo_tow_ms=d['glo_tow_ms'],
    )
