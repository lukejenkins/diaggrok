"""QMI Common Service Interface packet-log parser (0x1544, ``LOG_QMI_MCS_QCSI_PKT``).

The 28-byte header is QMI framing (service id / message type / message id /
client id) and the variable-length body is a chain of ``(type u8, length u16
LE, value)`` QMI TLVs, grounded against the firmware's own F3 debug messages.
0x1544 is not a bespoke GNSS format, although it is often described as a
"GNSS SV aggregate report" / "per-SV measurement report": QMI_LOC (svc 0x10)
messages dominate the stream, and the firmware's own F3 shows the QMI_LOC
client pipeline (``locClnt_PositionCallback`` / ``locPd_ReportPosition``)
driving these records.  Observed on SDX20 V2 (EG18-NA), SDX55 (FN980m /
RM500Q-AE) and others at ~9 Hz.  Several header and body fields keep
GNSS-flavoured names for downstream compatibility and are documented below
as misnomers; prefer ``tlvs`` / ``position`` / ``at_text`` and the ``qmi_*``
aliases.  The NMEA-TLV and binary-SV bodies are real QMI_LOC indications (a
TLV whose value is an NMEA sentence; a TLV 0x10 whose value is a per-SV
table).

QMI framing
-----------

1. **The body is a chain of QMI TLVs** — ``(type u8, length u16 LE,
   value[length])``, repeated to the end of the body.  Walking that grammar
   consumes the body **exactly, on 100.0% of bodies, on every body_kind, on
   both chipsets measured**: 7,556/7,556 (EG18-NA SDX20 V2) and 4,318/4,318
   (RM500Q-AE SDX55), zero trailing bytes, zero overruns.  Exact consumption
   is the detector, not a nicety — a merely plausible grammar leaves slack.
2. **Four header fields partition on QMI framing**, cross-tabulated against
   the TLV chain over an RM500Q-AE capture:

       header field            QMI role       observed
       ----------------------  -------------  ---------------------------
       num_constellations @4   service id     0x10 LOC (3786), 0x08 AT
                                              (474), 0x03 (46), 0x01 (6),
                                              0x05 (2), 0x2a (6)
       sub_type @1             message type   LOC: all 2 (indication);
                                              AT: {0:204, 1:204, 2:66} —
                                              204 requests balanced
                                              against 204 responses
       counter2 @20            message id     scoped PER SERVICE — msg
                                              0x0026 appears under svc
                                              0x08, 0x10 AND 0x2a with
                                              unrelated payloads
       constellation_mask @12  client id      one constant per service
                                              (LOC 131, AT 6, NAS 378)

Consequences for the legacy field names:

* The three GNSS "body kinds" are three QMI_LOC indications.  ``nmea`` is a
  message whose single TLV 0x01 value is an NMEA sentence.  ``binary_sv`` is
  ``[0x01, 0x10]`` — a 1-byte mandatory TLV then TLV 0x10 whose value is
  ``(count u8, svInfo[count] × 28 B)``.  ``idle`` is a lone TLV 0x02.
* body[4]/body[5]/body[6] are not three fields; they are ONE TLV header.
  ``body_header_signature`` is the TLV *type* byte (hence its value 0x10 — a
  type, not a format code); ``body_header_measurement`` is the **low** byte of
  that TLV's u16 length; ``body_header_enum`` is its **high** byte.  This is
  why body[5] follows ``(slots*28+1) mod 256`` — a mod-256 is a low byte — and
  why body[6] appears to partition chipset families: it is the length's high
  byte, which tracks SV count, which tracks receiver capacity.  The fields
  are kept (the bytes are real) but their names are misnomers; use ``tlvs``.
* ``counter2`` is a QMI **message id**, scoped per *service*, not per
  firmware.  It predicts body shape with 100% purity because a message id
  determines its payload; comparing values drawn from different services as
  one namespace yields no universal taxonomy.
* ``body_seq_flag`` (body[3]) is TLV 0x01's 1-byte value on the ``binary_sv``
  shape.  It toggles 0/1 with no correlation to the tracking-slot ratio —
  consistent with a mandatory boolean.
* ``body_word1`` is the first TLV's length: the NMEA text length on ``nmea``
  bodies and a constant 1 on ``binary_sv``.

Two payloads are decoded on top of the TLV chain, both cross-checked against
the modem's own AT surface in the SAME capture (``AT+QGPSLOC=2``):

* **QMI_LOC position report** (svc 0x10, the 29-TLV chain) — TLV 0x10 f64
  latitude, 0x11 f64 longitude, 0x1A f32 altitude wrt ellipsoid, 0x1B f32
  altitude wrt mean sea level, 0x24 3×f32 (PDOP, HDOP, VDOP), 0x25 u64 UTC
  ms, 0x26 u8 leap seconds, 0x27 (u16 gps_week, u32 tow_ms).  Six
  independent agreements with AT ground truth: lat/lon to AT's 5-decimal
  rounding; 0x1B altitude equal to AT's altitude while 0x1A sits 13 m lower
  (the geoid separation, so the ELLIPSOID/MSL assignment is not
  interchangeable); 0x24's middle f32 equal to AT's HDOP; and 0x25 / 0x27 /
  0x26 mutually consistent — gps_week+tow resolves 18 s ahead of the 0x25 UTC
  stamp, which is exactly 0x26's value.
* **QMI AT service** (svc 0x08) — TLV 0x01 carries a length-prefixed embedded
  AT string: the ``+QGPSLOC:`` response text on the sub_type=0 message and the
  bare ``+QGPSLOC`` command name on the sub_type=2 indication.  The bytes
  self-label with the literal command name, so the body_kind is read off the
  capture rather than inferred.

Classification: a body whose TLV chain closes exactly and is not one of the
established kinds is ``qmi_position_report`` / ``qmi_at_text`` /
``qmi_tlv_chain``; ``unknown`` is reserved for bodies where the grammar does
NOT close, so the label carries information.

F3 grounding
------------

The QMI framing and the ``qmi_position_report`` f64 lat/lon decode are
grounded against the firmware's own F3 debug prints on three chipset
generations, none circular with the QMI wire bytes.

EG18-NA SDX20 V2 (GNSS cold-start capture, F3 resolved against a
build-matched string database):

1. **The QMI_LOC client pipeline prints in F3.** ``locClnt_PositionCallback``
   (900) and ``locPd_ReportPosition`` (603) fire across the session — QMI
   location-service client callbacks, grounding
   ``num_constellations@4 == 0x10 -> QMI_LOC`` directly.
2. **1:1 report count.** ``tle_log.c:669`` "Serving cell position updated"
   fires **exactly 295** times == the **295** ``qmi_position_report`` records
   0x1544 carries in the same capture.
3. **Position value grounded to 1.3 m.** The GNSS manager's own fix,
   ``gm_core.c:6595`` "Got position update, Lat:<rad> Long:<rad>"
   (**radians**), lies **1.3 m** from the 0x1544 f64 TLV decode, inside the
   6-decimal radian-print quantization (~3 m).  ``gm_core.c:6595`` is the SAME
   quantity 0x1544's QMI_LOC report carries (the engine fix feeding the
   QMI_LOC EVENT_POSITION_REPORT), so this is a same-quantity ground, not a
   coarse cross-check — the ``tle_log.c:669`` degrees line is the coarse
   serving-cell estimate (Punc 20 km) and matches to 14 m.

MDM9650 (Wistron 81UMV C-V2X module, 1,202,883 F3 frames):

1. ``locClnt_PositionCallback`` fires **7,920** times (3,299 on EG18-NA) —
   the QMI_LOC client pipeline, grounding ``num_constellations@4 == 0x10 ->
   QMI_LOC`` independently of chipset.
2. **Position value grounded to 3.0 m (centroid) / 1.4 m (nearest).**
   ``gm_core.c:5978`` (the same GNSS-manager print family as EG18-NA's
   ``:6595``, different build) vs the centroid of 330 ``qmi_position_report``
   f64-TLV records, inside the ~3 m radian-print quantization.

EM7455 (MDM9x30 class, 1,860 records of 0x1544) — grounded against the legacy
0x92 / plaintext 0x79 F3 family (1,364,845 ``0x92`` + 159,714 ``0x79``
frames; the 0x99/0x98 families are absent on this generation):

1. **Grammar closes 100% exactly.** 1,860/1,860 records exact, 0 trailing, 0
   declined; all QMI service ``0x10`` (LOC).  body_kinds nmea 1085 /
   binary_sv 310 / idle 310 / qmi_position_report 155.  Internal value-free
   checks ``gps_utc_delta_ok`` and ``alt_ellipsoid_below_msl`` hold 155/155.
2. **1:1 report count.** ``gm_core.c:5339`` "Got position update" fires
   **exactly 155** times == the **155** ``qmi_position_report`` records == 155
   ``nf_navsolution.c:4922`` clock-adj prints == 155 co-temporal ``0x1477``
   GPS-measurement reports.
3. **Position value grounded to 2.19 m.** ``gm_core.c:5339`` vs the 0x1544
   f64-TLV decode, inside the ~3 m radian-print quantization; the FixTime join
   is 155/155 exact (dt = 0 ms).
4. **GPS week agrees across three independent sources.** 0x1544 TLV 0x27 ==
   F3 ``tle_log.c:645`` == the ``0x1477`` parser, all the same week; 0x1477's
   TOW window anchors the same epoch as the F3 ``nf_navsolution`` /
   ``gm_core`` FixTime.
5. This capture carries no ``qmi_at_text`` records and no ``+QGPSLOC`` polls,
   so the comparison is 0x1544 f64 vs F3 only.

Corpus-wide, over every F3-bearing capture: ``gm_core.c`` "Got position
update, Lat:<rad> Long:<rad>" vs the nearest ``qmi_position_report``
(≤ 3 s) — 169,081 prints within 10 m, 26 beyond 50 m, 147 joined captures,
per-capture median 2.4 m.  QMI reports at exactly (0, 0) are the no-fix
sentinel and are excluded from the join.

``ref_value`` (u32 @16)
-----------------------

F3 never prints ``ref_value`` (no reprint in 1.2M co-temporal frames), so it
cannot be F3-grounded.  It is a per-(QMI service) CONSTANT, not a per-record
switch and not a live timestamp:

    capture         svc 0x10 (LOC)          non-LOC service(s)
    --------------  ----------------------  ----------------------------
    EG18-NA SDX20   0x63e1a3c0 (×6876,      svc 0x08 AT: 0x2c==44 (×903)
                    1 distinct)
    81umv MDM9650   0x35fbedc0 (×420,       svc 0x03 NAS: {0x8b,0x95}
                    1 distinct)             (139/149, ×1199)

The ``fn980_wardriving`` sample ``[0x20b0f580, 0x2c, 0x43]`` in
``_REF_VALUE_INTERPRETATIONS`` is exactly this: ``0x2c``==44 is the AT
service's constant (the same value seen on EG18-NA), the Unix-class
``0x20b0f580`` is LOC's, and the other small int is another service's — one
value per service, pooled into one sample.  The chipset-keyed table is
therefore confounded on service; see the caveat at that table.

NMEA body layout (3-byte TLV + payload):

    off  type  name          notes
    0    u8    tag           0x01 = NMEA-ASCII content marker
    1    u16   nmea_len      length of NMEA sentence (including \r\n)
    3    byte[nmea_len]      NMEA sentence text, e.g.
                             ``$GPVTG,297.3,T,285.7,M,0.0,N,0.0,K,A*24\r\n``

Observed sentence types include standard talkers: GNGSA, GPGSV, GLGSV,
GAGSV, GPGGA, GAGGA, GNGNS, GPVTG, GAVTG, GPRMC, GARMC, GPGSA, GAGSA,
GPGLL, GPDTM, plus proprietary ``$PQGSA`` on some firmwares.  Share of NMEA
bodies per chipset:

    | Chipset            | Records | NMEA body |  % |
    |---|---:|---:|---:|
    | em7511 MDM9650     | 20,172  | 16,500+   | 82% |
    | eg18na SDX20 V2    |  5,104  |  3,958    | 78% |
    | lm960  SDX20       |  6,567  |  4,910    | 75% |
    | fn980m SDX55       |    681  |    381    | 56% |

Binary-body per-SV layout (offsets relative to body, not record):

    off  type  name                  notes
    0    u8    tag                   always 0x01 (same tag as NMEA)
    1    u8    body_sub_format
    2..7 bytes body_header_reserved
    8+i*28     28-byte SV slot       for i in 0..(body_len-8)//28 - 1

Slot record (offsets within slot; see ``SvSlot`` for the full layout):

    +0   u8    constellation_code    0xff=GPS, 0xfb=GLONASS, 0x9b=SBAS
    +8   u8    sv_id                 PRN / slot number
    +16  f32LE elevation_deg
    +20  f32LE azimuth_deg
    +24  f32LE cn0_db_hz

A 484 B body holds 17 SV slots, 456 B holds 16, and a 7 B body holds none
(idle / keepalive).  On an em7511 MDM9650 corpus (19,172 records) this
decodes cleanly on 829 non-NMEA binary bodies, with per-SV floats in sensible
GNSS ranges on every slot inspected (elevation 0-90°, azimuth 0-360°, CN0
25-45 dB·Hz on active SVs).

## Header layout (28 bytes)

    Byte  0:     u8   version                (always 2)
    Byte  1:     u8   sub_type               (QMI message type: 0, 1, 2)
    Byte  2:     u8   sequence_counter        (wrapping u8 counter, increments per record)
    Byte  3:     u8   flags                   (observed: 0, 1, 34)
    Byte  4:     u8   num_constellations      (QMI service id)
    Bytes 5..7:  u8   reserved[3]             (always 0)
    Byte  8:     u8   format_type             (1 or 2 — discriminates body layout)
    Bytes 9..11: u8   reserved[3]             (always 0)
    Bytes 12..13: u16  constellation_mask      (QMI client id)
    Bytes 14..15: u8   reserved[2]             (always 0)
    Bytes 16..19: u32  ref_value               (per-service constant; see above)
    Bytes 20..23: u32  counter2                (QMI message id, scoped per service)
    Bytes 24..25: u16  body_len                (exact body length = payload_size - 28)
    Bytes 26..27: u8   reserved[2]             (varies)

The ``body_len`` invariant (u16 @24 == payload_size - 28) holds across 1,210
records on two chipsets.

Header-field statistics across five chipsets (em7511 MDM9650, em9190 SDX55,
lm960 SDX20, fn980 SDX55 wardriving, rm520ngl SDX62; 55,257 records):

- ``counter2`` (u32 @ 20-23, the QMI message id) predicts body shape with
  100% purity within a firmware.  Per-capture value table (values are
  message ids from whichever services dominate each capture, so the columns
  are not one namespace):

      counter2  em7511   em9190    lm960   fn980-wd  rm520ngl
      --------  -------  --------  ------  --------  --------
        36      unknown  unknown   unknown bundle    -
        37      bin_sv   idle      bin_sv  idle      -
        38      nmea     nmea      -       -         (16 binsv)
        44      idle     idle      idle    -         -
        134     -        -         -       bundle    -

  Exposed as ``qmi_message_id``; ``body_format_subcode`` is a legacy alias.

- ``constellation_mask`` (u16 @ 12-13, the QMI client id) per-chipset
  values:

      em7511 single-band:    0x0049
      em9190 multi-band:     0x0091
      lm960  GLO+SBAS only:  0x0048
      fn980  wardriving:     0x0091 / 0x015b
      rm520ngl SDX62:        0x0006 / 0x009b

  Its popcount does not track ``num_constellations``; neither field is a
  constellation count.

- ``sequence_counter`` (u8 @ 2) is a **global u8-wrapping frame index**
  across all message ids within a capture, NOT a per-substream counter.  On
  em7511 the dominant counter2=38 stream is 93% delta==1 because the
  non-dominant 884+478+422 ≈ 10% records of other ids interleave and
  "consume" frame indices.  All 256 values are observed in long captures
  (full u8 wrap).

- ``ref_value`` (u32 @ 16-19) keeps its raw u32 on the dataclass.
  ``interpret_ref_value(chipset_family, value)`` returns the per-family
  observations recorded in ``_REF_VALUE_INTERPRETATIONS``; read its
  ``class`` as service-confounded (see above), not as a semantic bound.

RM520N-GL (SDX62) emits 0x1544 (12,919 records in one GNSS comparison
capture), predominantly with counter2=34 and counter2=38 (16 binary_sv
records).

Log name: QMI_MCS_QCSI_PKT
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import calcsize, unpack_from
from typing import Any

from diaggrok.registry import register

LOG_GNSS_SV_AGGREGATE = 0x1544

_HDR_FMT = '<BBBBBBBBBBBBHHIIHBB'
_HDR_SZ = calcsize(_HDR_FMT)
assert _HDR_SZ == 28, f"Expected 28, got {_HDR_SZ}"


_TAG_01 = 0x01  # body tag — distinguishes NMEA-ASCII (v2) from binary-SV (v3)

_SV_SLOT_SIZE = 28
_SV_BODY_HEADER_SIZE = 8

# FN980m SDX55 wardriving-mode periodic bundle.
#
# In field operation the FN980m firmware emits a periodic 5-record bundle
# that replaces the static-mode 0x1544 stream: four "data" records of
# distinct sizes + one 4B idle marker, repeated at ~1Hz throughout a
# wardriving capture (4×1166 + 1166 idle = 5,830 of 6,111 records, 95.4%).
#
# The bundle's four data sizes are byte[0]=0x01-tagged but match neither
# the NMEA nor the binary_sv decode.  The discriminator is the
# (body[1], body[3]) pair plus body_len:
#
#   body_len  body[1]  body[3]   role
#   --------  -------  -------   -------------------------------------
#   290       1        1         sub-record 1/4 (largest)
#   126       1        2         sub-record 2/4
#   129       1        3         sub-record 3/4
#   323       4        1         sub-record 4/4 (different kind — likely
#                                summary/footer; byte[1] discriminates
#                                from the byte[1]=1 trio)
#
# Bytes [11..23] of sub-records 1..3 share a 13-byte invariant
# fingerprint (`0c 00 27 d8 60 bf 7d 90 b3 42 01 00 00`) — looks like
# a chipset/firmware/RTC-snapshot identifier.  Sub-record 4 has
# different content there (different role).
#
# The 5th cycle entry (4B idle) already classifies as 'idle' via the
# body_len <= 8 fall-through; only the 4 data sizes are labelled here.
#
# Tight criteria: only label records that match BOTH the size and the
# (byte[1], byte[3]) discriminator triple.  Rare interjections (sizes
# 21, 157, 11) and the wider FN980m static-mode variants are NOT
# labelled here.
_FN980_PERIODIC_BUNDLE: dict[tuple[int, int, int], int] = {
    (290, 1, 1): 1,
    (126, 1, 2): 2,
    (129, 1, 3): 3,
    (323, 4, 1): 4,
}

# Constellation-code → human-readable label.  Empirically-derived labels
# from an em7511 MDM9650 corpus; SV IDs in each group match the
# expected PRN / slot ranges for the named constellation (GPS 1-32,
# GLONASS 1-24, SBAS 120-158).
_CONSTELLATION_CODES = {
    0xff: 'GPS',
    0xfb: 'GLONASS',
    0x9b: 'SBAS',
}


# ─────────────────────────────────────────────────────────────────────
# `ref_value` (u32 @ 16-19) — varies along the QMI SERVICE axis, not the
# chipset-family axis.
#
# Caveat: the per-chipset-family table below is service-confounded.  Cut by
# (qmi_service_id, qmi_message_id) on a multi-service RM500Q-AE capture
# (4,320 records, ONE chipset — so the chipset axis is held constant):
#   • ref_value takes 9 distinct values inside that single capture, which a
#     constant chipset-family key cannot explain.
#   • Cut by service it is near-constant per service: LOC → a single big u32
#     (0xef5401f0, the "unix_time_like" value; constant across all 3,786 LOC
#     records, so a baked reference, not a live clock), while the small-int
#     services each carry their own small int (WDS 0x09, WMS 0x14, AT 0x1c,
#     DSD {0x20,0x3f}, NAS {0x06,0x0e,0x15}).
#   • By (service, message_id): 11/13 groups (85%) are single-valued; the only
#     residual spread is two NAS message ids (likely a NAS state/handle).
#   Two further captures (EG18-NA SDX20, 81UMV MDM9650) show the same
#   per-service constants: LOC (svc 0x10) carries the big-u32 value, AT (0x08)
#   carries 0x2c==44, NAS (0x03) a small int.
# The 'unix_time_like' families are LOC-dominated fleets and the 'mixed'
# families carry a broader service mix (the fn980 sample [0x20b0f580, 0x2c,
# 0x43] is LOC's value + AT's 44 + one more service's int).  The values are
# real (LOC does carry a firmware-baked u32), but a correct table would key
# by service.  The per-family entries are kept as observed data for
# downstream compatibility; do NOT treat the `class` field as a semantic
# bound.
#
# Per-family observations (DIAG-only cross-chipset analysis):
#
#   sierra_mdm9650    'unix_time_like'    Two distinct Unix-time-like u32
#   sierra_sdx55      'unix_time_like'    snapshots per capture; values
#                                         resolve to 2019-04..2020-06 UTC;
#                                         consistent with almanac /
#                                         ephemeris reference time.
#   sdx20_legacy      'unix_time_like'    Single old timestamp per capture
#                                         (lm960 SDX20: 0x2f58c200 ≈
#                                         1995-03-04 UTC — likely
#                                         embedded firmware build date,
#                                         NOT current almanac time).
#   sdx62_quectel     'mixed'             Small-int dominant (0x06) with
#                                         occasional large u32 (0xe1854ac0
#                                         class).
#   fn980_wardriving  'mixed'             3-value mix with a Unix-time-
#                                         class value plus 2 small ints
#                                         (0x2c, 0x43).
#
# Each entry's `class` is the bound the parser commits to; `notes` carry the
# per-family state.
_REF_VALUE_INTERPRETATIONS: dict[str, dict[str, Any]] = {
    'sierra_mdm9650': {
        'class': 'unix_time_like',
        'sample_values': [0x5ee24480, 0x5ed4ecb0],
        'sample_decode': ['~2020-06-11 UTC', '~2020-06-01 UTC'],
        'hypothesis': 'almanac/ephemeris reference time',
        'tier': 'T1',
        'notes': (
            'em7511 highsignal capture flips ref_value mid-capture '
            '(11,541 vs 8,631 records) — likely an XTRA-data refresh '
            'boundary. T2 promotion would require correlating with '
            'AT!GPSXTRADATA? polls in a paired AT+DIAG capture.'
        ),
    },
    'sierra_sdx55': {
        'class': 'unix_time_like',
        'sample_values': [0x5cc7d680],
        'sample_decode': ['~2019-04-30 UTC'],
        'hypothesis': 'almanac/ephemeris reference time',
        'tier': 'T1',
        'notes': 'em9190 SDX55 — single value per capture observed; same family as MDM9650.',
    },
    'sdx20_legacy': {
        'class': 'unix_time_like',
        'sample_values': [0x2f58c200],
        'sample_decode': ['~1995-03-04 UTC'],
        'hypothesis': 'embedded firmware build date (NOT current almanac time)',
        'tier': 'T1',
        'notes': (
            'lm960 SDX20 — fixed 1995 epoch suggests this is a '
            'firmware-baked constant, not a live reference. Distinct '
            'from MDM9650/SDX55 behavior despite sharing the same '
            'unix_time_like class.'
        ),
    },
    'sdx62_quectel': {
        'class': 'mixed',
        'sample_values': [0x06, 0xe1854ac0, 0xe21b5ae0],
        'sample_decode': None,
        'hypothesis': (
            'small-int dominant (mode_id / agps_state) + large-u32 '
            'minority; secondary discriminator suspected'
        ),
        'tier': 'T0',
        'notes': (
            'rm520ngl SDX62 — small-int 0x06 dominates with rare '
            'large-u32 values. Per-record discriminator unidentified; '
            'likely the QMI service mix (see the module docstring).'
        ),
    },
    'fn980_wardriving': {
        'class': 'mixed',
        'sample_values': [0x20b0f580, 0x2c, 0x43],
        'sample_decode': None,
        'hypothesis': (
            'per-record interpretation switch — Unix-time-like in '
            'some records, mode-ID-like in others; discriminator '
            'suspected to be body_format_subcode'
        ),
        'tier': 'T0',
        'notes': (
            'Telit FN980m wardriving-mode capture. '
            'Mix of one Unix-time-class value with 2 small ints — '
            'inconsistent with single-meaning across records. '
            'Decoding the per-record discriminator would T1-promote.'
        ),
    },
}


def interpret_ref_value(
    chipset_family: str,
    ref_value: int,
) -> dict[str, Any] | None:
    """Resolve the semantic interpretation of `ref_value` for a chipset.

    `ref_value` (u32 @ 16-19 of the 0x1544 header) is a per-QMI-service
    constant; this helper returns the per-chipset-family observations,
    which are confounded on service (see ``_REF_VALUE_INTERPRETATIONS``).
    The parser keeps the raw u32 so the field is round-trippable;
    downstream consumers that want to assign meaning should call this
    helper rather than guessing.

    Parameters
    ----------
    chipset_family : str
        Canonical family key. One of: ``sierra_mdm9650``, ``sierra_sdx55``,
        ``sdx20_legacy``, ``sdx62_quectel``, ``fn980_wardriving``.
    ref_value : int
        The raw u32 value from the parsed record's ``ref_value`` field.

    Returns
    -------
    dict | None
        Interpretation metadata: ``{'class', 'tier', 'hypothesis', ...}``
        for known families; ``None`` for unknown families (consumer
        should treat the value as opaque and not assign meaning).

    Notes
    -----
    The returned dict does NOT carry a decoded value — only the
    interpretation class plus the per-family hypothesis. To actually
    decode a unix_time_like value, the caller can pass ``ref_value`` to
    ``datetime.fromtimestamp(value, tz=UTC)`` after this helper
    confirms the class. For 'mixed' families, the caller should inspect
    the parsed record's ``counter2`` (body_format_subcode) and other
    fields before committing to a meaning.
    """
    entry = _REF_VALUE_INTERPRETATIONS.get(chipset_family)
    if entry is None:
        return None
    return dict(entry)


# ─────────────────────────────────────────────────────────────────────
# QMI framing
# ─────────────────────────────────────────────────────────────────────
# 0x1544 is LOG_QMI_MCS_QCSI_PKT — a QMI Common Service Interface packet
# log. The 28-byte header is QMI framing and the body is a QMI message
# payload: a chain of (type u8, length u16 LE, value[length]) TLVs.

_QMI_TLV_HDR_SZ = 3

# QMI message type, from `sub_type` (u8 @1). Grounded on the AT service in
# the RM500Q-AE capture, where requests and responses balance EXACTLY
# (204 / 204) — a control-flow signature a mis-assignment would not produce.
_QMI_MESSAGE_TYPES = {0: 'request', 1: 'response', 2: 'indication'}

# QMI service id, from `num_constellations` (u8 @4).
#
# 0x1544 carries a whole QMI service multiplex, not just GNSS.  Every service
# a corpus census observed is named, in two provenance tiers:
#
# ── Tier A · payload-corroborated (strongest) ─────────────────────────
#   0x10 LOC → the NMEA sentences, per-SV tables and f64 lat/lon position
#              reports all arrive under it
#   0x08 AT  → its TLV 0x01 carries literal embedded "+QGPSLOC" AT text
#
# ── Tier B · census-observed + enum-named ─────────────────────────────
# The rest are ids the corpus census observed emitting well-formed QMI
# framing — every one closes its TLV chain exactly (the one exception is a
# 0.71% trailing-byte tail in the AT service, not a service-id misparse) —
# named from libqmi's canonical `QmiService` enum (libqmi 1.39.0,
# qmi-enums.h).  Validity control: the same enum reproduces the two Tier-A
# ids exactly (0x08→AT, 0x10→LOC).
#   0x2a=DSD (Data System Determination): its TLV *type* bytes 0x10–0x13 are
#   a false friend with LOC's lat/lon/unc TLV ids — DSD-specific TLVs, not a
#   position fix.  TLV grammar is per service, not shared.
#   Two observed ids are NOT in libqmi's enum and stay unnamed (likely
#   vendor/OEM extensions): 0x30 (6 rec) and 0x55 (48 rec).
#   `qmi_service_id` still exposes their raw byte.  Add an entry only with an
#   authoritative source or in-capture payload evidence.
_QMI_SERVICES = {
    0x01: 'WDS',    # Tier B
    0x02: 'DMS',    # Tier B
    0x03: 'NAS',    # Tier B
    0x04: 'QOS',    # Tier B
    0x05: 'WMS',    # Tier B
    0x08: 'AT',     # Tier A — payload-proven
    0x09: 'VOICE',  # Tier B
    0x0b: 'UIM',    # Tier B
    0x10: 'LOC',    # Tier A — payload-proven
    0x11: 'SAR',    # Tier B
    0x1a: 'WDA',    # Tier B
    0x24: 'PDC',    # Tier B
    0x2a: 'DSD',    # Tier B
    0x2f: 'DPM',    # Tier B
    0xe3: 'FOX',    # Tier B
}

# QMI_LOC position-report TLV types. Each was confirmed against
# AT+QGPSLOC=2 ground truth in the same capture — see the module docstring
# for the six agreements.
_TLV_LATITUDE = 0x10          # f64 degrees
_TLV_LONGITUDE = 0x11         # f64 degrees
_TLV_HOR_UNC = 0x12           # f32 metres
_TLV_ALT_ELLIPSOID = 0x1A     # f32 metres
_TLV_ALT_MSL = 0x1B           # f32 metres
_TLV_DOP = 0x24               # 3 × f32: PDOP, HDOP, VDOP
_TLV_UTC_MS = 0x25            # u64 milliseconds since the Unix epoch
_TLV_LEAP_SECONDS = 0x26      # u8
_TLV_GPS_TIME = 0x27          # u16 gps_week + u32 tow_ms


@dataclass
class QmiTlv:
    """One TLV of a QMI message payload: (type u8, length u16 LE, value).

    ``value`` is the raw slice — it may hold decoded PII (the position
    report's f64 coordinates are the user's own location). ``to_dict()``
    deliberately emits **type and length only**, never the value, so a
    derived artifact (recipe output, corpus sweep, analysis log)
    carries the message STRUCTURE without the captured values. Consumers
    that genuinely want a value read it off the object.
    """
    type: int
    length: int
    value: bytes

    def to_dict(self) -> dict[str, Any]:
        return {'type': self.type, 'length': self.length}


def walk_qmi_tlvs(body: bytes) -> tuple[list[QmiTlv], int]:
    """Walk a QMI TLV chain over ``body``.

    Returns ``(tlvs, trailing)`` where ``trailing`` is the number of bytes
    the chain did not consume — 0 on a well-formed chain. The walk stops at
    the first TLV whose declared length would overrun the body, leaving the
    remainder in ``trailing`` rather than raising.

    ``trailing`` is the correctness detector for this grammar, not a
    diagnostic afterthought. Measured 0 on 11,874/11,874 bodies across
    EG18-NA SDX20 V2 and RM500Q-AE SDX55; a nonzero value means the
    body is not a plain QMI message and must not be interpreted as one.
    """
    tlvs: list[QmiTlv] = []
    off = 0
    n = len(body)
    while off + _QMI_TLV_HDR_SZ <= n:
        t = body[off]
        ln = unpack_from('<H', body, off + 1)[0]
        end = off + _QMI_TLV_HDR_SZ + ln
        if end > n:
            break
        tlvs.append(QmiTlv(type=t, length=ln, value=body[off + _QMI_TLV_HDR_SZ:end]))
        off = end
    return tlvs, n - off


@dataclass
class QmiLocPositionReport:
    """A QMI_LOC position report decoded from the body's TLV chain.

    Every field below is cross-checked against ``AT+QGPSLOC=2`` on the same
    modem in the same capture (see the module docstring). Two
    checks are worth restating because they pin assignments that would
    otherwise be interchangeable:

    * ``altitude_msl_m`` equals AT's altitude field exactly, while
      ``altitude_ellipsoid_m`` sits ~13 m lower — the geoid separation at
      the capture site. Swapping the two would break that agreement, so
      TLV 0x1A/0x1B are not assigned by convention but by measurement.
    * ``gps_week`` + ``gps_tow_ms`` resolves exactly ``leap_seconds`` ahead
      of ``utc_timestamp_ms``. Three fields mutually confirming one another
      is stronger evidence than any one of them matching AT.

    Fields are None when the corresponding TLV is absent — QMI optional
    TLVs really are optional, and a short position message (the
    ``[0x01 0x10 0x11]`` shape) carries coordinates and nothing else.
    """
    latitude_deg: float | None = None
    longitude_deg: float | None = None
    horizontal_unc_m: float | None = None
    altitude_ellipsoid_m: float | None = None
    altitude_msl_m: float | None = None
    pdop: float | None = None
    hdop: float | None = None
    vdop: float | None = None
    utc_timestamp_ms: int | None = None
    leap_seconds: int | None = None
    gps_week: int | None = None
    gps_tow_ms: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            'latitude_deg': self.latitude_deg,
            'longitude_deg': self.longitude_deg,
            'horizontal_unc_m': self.horizontal_unc_m,
            'altitude_ellipsoid_m': self.altitude_ellipsoid_m,
            'altitude_msl_m': self.altitude_msl_m,
            'pdop': self.pdop,
            'hdop': self.hdop,
            'vdop': self.vdop,
            'utc_timestamp_ms': self.utc_timestamp_ms,
            'leap_seconds': self.leap_seconds,
            'gps_week': self.gps_week,
            'gps_tow_ms': self.gps_tow_ms,
        }

    @property
    def has_position(self) -> bool:
        return self.latitude_deg is not None and self.longitude_deg is not None


def _decode_qmi_loc_position(tlvs: list[QmiTlv]) -> QmiLocPositionReport | None:
    """Decode a QMI_LOC position report from a walked TLV chain.

    Returns None unless BOTH the f64 latitude and f64 longitude TLVs are
    present at their expected widths. Requiring the pair (and the exact
    8-byte width) keeps this from firing on the unrelated messages that also
    happen to use types 0x10/0x11 — e.g. the ``binary_sv`` shape's TLV 0x10
    is a 981-byte SV array, not a coordinate.
    """
    by_type: dict[int, QmiTlv] = {}
    for t in tlvs:
        by_type.setdefault(t.type, t)

    lat_tlv = by_type.get(_TLV_LATITUDE)
    lon_tlv = by_type.get(_TLV_LONGITUDE)
    if lat_tlv is None or lon_tlv is None:
        return None
    if lat_tlv.length != 8 or lon_tlv.length != 8:
        return None

    out = QmiLocPositionReport(
        latitude_deg=unpack_from('<d', lat_tlv.value)[0],
        longitude_deg=unpack_from('<d', lon_tlv.value)[0],
    )

    def _f32(tlv_type: int) -> float | None:
        tlv = by_type.get(tlv_type)
        if tlv is None or tlv.length != 4:
            return None
        return unpack_from('<f', tlv.value)[0]

    out.horizontal_unc_m = _f32(_TLV_HOR_UNC)
    out.altitude_ellipsoid_m = _f32(_TLV_ALT_ELLIPSOID)
    out.altitude_msl_m = _f32(_TLV_ALT_MSL)

    dop = by_type.get(_TLV_DOP)
    if dop is not None and dop.length == 12:
        out.pdop, out.hdop, out.vdop = unpack_from('<3f', dop.value)

    utc = by_type.get(_TLV_UTC_MS)
    if utc is not None and utc.length == 8:
        out.utc_timestamp_ms = unpack_from('<Q', utc.value)[0]

    leap = by_type.get(_TLV_LEAP_SECONDS)
    if leap is not None and leap.length == 1:
        out.leap_seconds = leap.value[0]

    gps = by_type.get(_TLV_GPS_TIME)
    if gps is not None and gps.length == 6:
        out.gps_week = unpack_from('<H', gps.value)[0]
        out.gps_tow_ms = unpack_from('<I', gps.value, 2)[0]

    return out


def _decode_qmi_at_text(tlvs: list[QmiTlv]) -> str | None:
    """Extract the embedded AT string from a QMI AT-service TLV 0x01 value.

    Two inner layouts are attested on RM500Q-AE, both a fixed prelude then a
    length-prefixed string:

        sub_type=0 (carries the response text)
            u32 handle | u8 | u8 | u16 text_len | text[text_len]
        sub_type=2 (carries the bare command name)
            u32 handle | u32       | u8  text_len | text[text_len]

    Rather than key off sub_type — which would bake in one modem's
    convention — each layout is tried and accepted only if its length
    prefix consumes the value EXACTLY. Same detector as the TLV walk: a
    wrong layout cannot silently pass unless the two length fields agree,
    and the printability check below closes that residual gap.
    """
    if not tlvs or tlvs[0].type != _TAG_01:
        return None
    val = tlvs[0].value

    candidates: list[bytes] = []
    # sub_type=2 layout: u8 length at offset 8.
    if len(val) >= 9 and val[8] == len(val) - 9:
        candidates.append(val[9:])
    # sub_type=0 layout: u16 length at offset 6.
    if len(val) >= 8 and unpack_from('<H', val, 6)[0] == len(val) - 8:
        candidates.append(val[8:])

    for raw in candidates:
        if not raw:
            continue
        # An AT command / response is printable ASCII plus CR/LF/TAB. Any
        # other byte means the length prefix matched by coincidence.
        if any(not (0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D)) for b in raw):
            continue
        try:
            return raw.decode('ascii').strip('\r\n')
        except UnicodeDecodeError:
            continue
    return None


@dataclass
class QgpslocFix:
    """Fields of a Quectel ``+QGPSLOC:`` response embedded in an AT-service body.

    The AT text is `<mode 2>` form — decimal degrees —
    which is what makes it directly comparable to the QMI_LOC TLV f64
    coordinates decoded from the LOC-service records of the same capture:

        +QGPSLOC: <utc>,<lat>,<lon>,<hdop>,<altitude>,<fix>,<cog>,<spkm>,
                  <spkn>,<date>,<nsat>

    ``<cog>`` is routinely empty on a stationary fix, so every field is
    optional and a missing one stays None rather than failing the parse.
    ``altitude_m`` is the mean-sea-level altitude — it is the field that
    equals the position report's TLV 0x1B, NOT its TLV 0x1A.
    """
    utc: str | None = None
    latitude_deg: float | None = None
    longitude_deg: float | None = None
    hdop: float | None = None
    altitude_m: float | None = None
    fix_type: int | None = None
    course_over_ground: float | None = None
    speed_kmh: float | None = None
    speed_knots: float | None = None
    date: str | None = None
    num_satellites: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            'utc': self.utc,
            'latitude_deg': self.latitude_deg,
            'longitude_deg': self.longitude_deg,
            'hdop': self.hdop,
            'altitude_m': self.altitude_m,
            'fix_type': self.fix_type,
            'course_over_ground': self.course_over_ground,
            'speed_kmh': self.speed_kmh,
            'speed_knots': self.speed_knots,
            'date': self.date,
            'num_satellites': self.num_satellites,
        }


_QGPSLOC_PREFIX = '+QGPSLOC:'


def parse_qgpsloc(text: str) -> QgpslocFix | None:
    """Parse a ``+QGPSLOC:`` response line into a QgpslocFix.

    Returns None if ``text`` is not a ``+QGPSLOC:`` response (e.g. it is the
    bare command name, which the AT service also carries). Positional
    fields are decoded independently — an unparseable or empty field yields
    None for that field only, so one odd value never discards the fix.
    """
    if _QGPSLOC_PREFIX not in text:
        return None
    body = text.split(_QGPSLOC_PREFIX, 1)[1].strip()
    if not body:
        return None
    parts = [p.strip() for p in body.split(',')]

    def _f(i: int) -> float | None:
        if i >= len(parts) or not parts[i]:
            return None
        try:
            return float(parts[i])
        except ValueError:
            return None

    def _i(i: int) -> int | None:
        if i >= len(parts) or not parts[i]:
            return None
        try:
            return int(parts[i])
        except ValueError:
            return None

    def _s(i: int) -> str | None:
        return parts[i] if i < len(parts) and parts[i] else None

    return QgpslocFix(
        utc=_s(0),
        latitude_deg=_f(1),
        longitude_deg=_f(2),
        hdop=_f(3),
        altitude_m=_f(4),
        fix_type=_i(5),
        course_over_ground=_f(6),
        speed_kmh=_f(7),
        speed_knots=_f(8),
        date=_s(9),
        num_satellites=_i(10),
    )


@dataclass
class SvSlot:
    """One row of the binary-body per-SV tracking table (28B stride).

    All float-valued fields are f32 little-endian.  Elevation is in
    degrees above the horizon (0..90).  Azimuth is in degrees clockwise
    from true north (0..360).  CN0 is in dB·Hz (typically 25..50 on
    active SVs; 0 when the SV is visible-but-not-tracked).

    Slot byte layout (14,694-slot corpus from 884 binary-SV bodies on an
    em7511 MDM9650):

    ```
    off  type  name                       notes
     0   u8    constellation_code         0xff=GPS, 0xfb=GLONASS, 0x9b=SBAS
     1..3      reserved_zeros
     4   u8    signal_type                1=L1_GPS, 5=L1_GLONASS, 3=L1_SBAS
                                          (100% correlated with constellation)
     5..7      reserved_zeros
     8   u8    sv_id                      GPS 1-32 / GLO 65-88 / SBAS 120-158
     9         reserved_zero
    10   u8    is_primary_family          1 iff constellation == GPS; 0
                                          otherwise (band / service flag)
    11   u8    tracking_flag              2 = visible-only (CN0 == 0),
                                          3 = tracking (CN0 > 0)
                                          100% correlation with CN0 state
    12..14     reserved_zeros
    15   u8    elevation_class            3 = high-elev (≥19°), 2 = low-elev
                                          (<30°), 0 = no-elevation (SBAS)
    16   f32   elevation_deg              0..90
    20   f32   azimuth_deg                0..360
    24   f32   cn0_db_hz                  0 or 25..50
    ```

    All 28 bytes are now accounted for (18 named + 10 invariant reserved).
    """
    constellation_code: int        # raw byte (0xff / 0xfb / 0x9b / …)
    constellation_name: str | None  # 'GPS' / 'GLONASS' / 'SBAS' / None
    signal_type: int                # u8 @ 4 (1/5/3 per constellation)
    sv_id: int
    is_primary_family: int          # u8 @ 10 (1 iff GPS)
    tracking_flag: int              # u8 @ 11 (2=no-signal, 3=tracking)
    elevation_class: int            # u8 @ 15 (0/2/3)
    elevation_deg: float
    azimuth_deg: float
    cn0_db_hz: float

    def to_dict(self) -> dict[str, Any]:
        return {
            'constellation_code': self.constellation_code,
            'constellation_name': self.constellation_name,
            'signal_type': self.signal_type,
            'sv_id': self.sv_id,
            'is_primary_family': self.is_primary_family,
            'tracking_flag': self.tracking_flag,
            'elevation_class': self.elevation_class,
            'elevation_deg': self.elevation_deg,
            'azimuth_deg': self.azimuth_deg,
            'cn0_db_hz': self.cn0_db_hz,
        }


@dataclass
class Diag0x1544:
    """QMI Common Service Interface packet record (0x1544).

    Header + body parser.  The body is a QMI TLV chain (``tlvs``); four
    established shapes, all starting with tag=0x01, are also decoded:
      1. NMEA-ASCII (TLV-wrapped sentence)
      2. Binary per-SV tracking table (8-byte body header + 28-byte slots)
      3. Idle / keepalive (7-byte body, no slots, no sentence)
      4. FN980m periodic bundle sub-record — wardriving-mode 5-record
         cycle, identified by (body_len, body[1], body[3])
    Other closed chains are labelled ``qmi_position_report`` /
    ``qmi_at_text`` / ``qmi_tlv_chain``.

    ``body_kind`` captures which interpretation was applied.  ``body_raw``
    is always preserved for downstream consumers.
    """
    log_time: int
    version: int
    sub_type: int
    sequence_counter: int
    flags: int
    num_constellations: int
    format_type: int
    constellation_mask: int
    ref_value: int
    counter2: int
    body_len: int
    body_raw: bytes
    # Discriminator: 'nmea' | 'binary_sv' | 'idle' | 'fn980_periodic_bundle'
    # | 'qmi_position_report' | 'qmi_at_text' | 'qmi_tlv_chain' | 'unknown'
    #
    # The three qmi_* kinds cover well-formed QMI messages outside the four
    # established shapes (12-21% of records).  'unknown' means the
    # QMI TLV grammar did NOT close on the body (tlv_trailing_bytes != 0) —
    # i.e. genuinely unmodelled framing, not merely an uninterpreted payload.
    body_kind: str = 'unknown'
    # Sub-kind index 1..4 when body_kind == 'fn980_periodic_bundle';
    # None on every other body_kind.  Indexes the role within the 5-record
    # cycle: 1=290B, 2=126B, 3=129B, 4=323B.
    body_sub_kind: int | None = None
    # NMEA decode (populated when body_kind == 'nmea')
    body_tag: int | None = None           # 0x01 = tag byte (all variants)
    nmea_sentence: str | None = None      # e.g. "$GPVTG,297.3,T,...*24"
    nmea_sentence_type: str | None = None  # e.g. "GPVTG", "GNGSA"
    # Binary-SV decode (populated when body_kind == 'binary_sv')
    #   body_seq_flag: body[3] — TLV 0x01's 1-byte value; toggles 0/1
    #     across consecutive records (even/odd split, no correlation with
    #     tracking-slot ratio).
    #   body_slot_count_echo: body[7] — echoes slot count, always equals
    #     len(sv_slots). Redundant with body_len but useful for corruption
    #     detection (mismatch would flag a malformed body).
    body_seq_flag: int | None = None
    body_slot_count_echo: int | None = None
    # body[4..6] are ONE QMI TLV header (type byte + u16 length), exposed as
    # three raw u8 under legacy names.  Cross-chipset values on 2,028
    # binary_sv records × 4 chipsets (em7511 MDM9650, lm960 SDX20, fn980m
    # SDX55, eg18na SDX20 V2):
    #
    #   body[4] body_header_signature — the TLV type byte
    #     0x10 (1,939 records): em7511 + lm960 + eg18na
    #     0x02 (89 records): fn980m SDX55 enum=0 only
    #     Strictly binds (sig, enum) pairs: (0x10, {1,2,4}) and
    #     (0x02, 0) — no crossover observed.  See me_format_code alias.
    #
    #   body[5] body_header_measurement — low byte of the TLV length
    #     For sig=0x10: meas = (slot_count * 28 + 1) mod 256 — holds
    #       on 1,933/1,939 records (99.7%).  The 6 exceptions are the
    #       enum=4 wide-capture outliers (slots=99) with a different
    #       formula, not noise.
    #     For sig=0x02: meas is constant 1 across all 89 records
    #       (slots=28).
    #     See body_size_echo_valid.
    #
    #   body[6] body_header_enum — high byte of the TLV length
    #     Tracks SV-array size, hence per-chipset-family.  Observed:
    #       enum=0  → fn980m SDX55 (slots=28)
    #       enum=1  → em7511 MDM9650 + lm960 SDX20 (slots 11..18)
    #       enum=2  → eg18na SDX20 V2 (slots 20..21)
    #       enum=4  → fn980m SDX55 wide-capture (slots=99)
    #     The observed value set is {0, 1, 2, 4}.
    body_header_signature: int | None = None
    body_header_measurement: int | None = None
    body_header_enum: int | None = None
    sv_slots: list[SvSlot] | None = None
    # Two RAW body words, surfaced un-named: the firmware's F3 on the GNSS
    # stack (cd_*/tm_*/loc_*/sm_api sites) carries no per-field label for
    # either, so they are exposed raw rather than given invented names.
    #
    #   body_tag_raw — body[0] verbatim, whatever its value.  ``body_tag`` is
    #     NOT this byte: ``_decode_nmea_tlv`` returns None for any tag != 0x01,
    #     so a non-0x01 body's tag byte would otherwise survive only inside
    #     body_raw.  Tag 0x14 is attested in the corpus.
    #   body_word1 — the u16 LE at body[1:3] (the first TLV's length).
    #     ``_decode_nmea_tlv`` reads this word on every tag-0x01 body to bound
    #     the sentence and keeps it only when the payload starts with '$'.  It
    #     is the NMEA text length on nmea bodies; this field also carries it
    #     on the 12-21% of records that are neither nmea nor binary_sv
    #     (882/7,556 on EG18-NA SDX20 V2; 916/4,320 on RM500Q-AE SDX55).
    #
    # Both are None only when the body is too short to contain them (body_len
    # < 1 and < 3 respectively) — mirroring the Kaitai layout's
    # `if: body_len >= 3` gate (diag_0x1544.ksy).
    body_tag_raw: int | None = None
    body_word1: int | None = None
    # QMI framing.  The body is a QMI message payload; `tlvs` is its TLV chain
    # and `tlv_trailing_bytes` is how many bytes the chain failed to consume
    # (0 on every one of the 11,874 bodies measured — see walk_qmi_tlvs).
    # `tlv_trailing_bytes != 0` is the signal that a body is NOT a plain QMI
    # message and must not be read as one.
    tlvs: list[QmiTlv] | None = None
    tlv_trailing_bytes: int | None = None
    # Populated when the chain carries an f64 lat/lon pair (svc 0x10 LOC).
    position: QmiLocPositionReport | None = None
    # Populated on QMI AT-service bodies (svc 0x08): the embedded AT string,
    # and its decoded fields when that string is a `+QGPSLOC:` response.
    at_text: str | None = None
    qgpsloc: QgpslocFix | None = None

    @property
    def qmi_service_id(self) -> int:
        """QMI service id — the real meaning of ``num_constellations`` (u8 @4).

        Grounded by cross-tabulation against the body's TLV
        chain: 0x10 carries every NMEA / per-SV / position payload and 0x08
        carries literal embedded ``+QGPSLOC`` AT text.  The legacy name is
        kept on the dataclass for compatibility and because it is the name
        the .ksy raw-field diff pins.
        """
        return self.num_constellations

    @property
    def qmi_service_name(self) -> str | None:
        """Name of ``qmi_service_id``; None for an id not in _QMI_SERVICES.

        Every service a corpus census observed is named: 0x08/0x10 by
        in-capture payload, the rest from libqmi 1.39.0's ``QmiService``
        enum. Two observed vendor extensions
        (0x30, 0x55) are absent from the enum and return None — see
        _QMI_SERVICES for provenance per id."""
        return _QMI_SERVICES.get(self.num_constellations)

    @property
    def qmi_message_id(self) -> int:
        """QMI message id — the real meaning of ``counter2`` (u32 @20).

        The value predicts body shape with 100% purity because a message id
        determines a message's payload.  It is scoped **per service**, not
        per firmware, so values compared across services in one namespace
        show no universal taxonomy.  Always read this together with
        ``qmi_service_id``; the pair is the key, not the id.
        """
        return self.counter2

    @property
    def qmi_message_type(self) -> str | None:
        """'request' / 'response' / 'indication' from ``sub_type`` (u8 @1).

        Grounded on the AT service, where requests and
        responses balance exactly (204/204) in the RM500Q-AE capture.
        """
        return _QMI_MESSAGE_TYPES.get(self.sub_type)

    @property
    def qmi_client_id(self) -> int:
        """QMI client id — the real meaning of ``constellation_mask`` (u16 @12).

        Holds one constant value per service within a capture (LOC 131,
        AT 6, NAS 378 on RM500Q-AE): a per-service client handle, not an
        active-band bitmask.
        """
        return self.constellation_mask

    @property
    def me_format_code(self) -> int | None:
        """Legacy misnomer, kept for compatibility.

        This is not a "Measurement Engine format code" — it is the **type
        byte of the body's second QMI TLV**.  Its value 0x10 is a TLV type,
        not a format enum.  Use ``tlvs`` instead.
        """
        return self.body_header_signature

    @property
    def receiver_class(self) -> int | None:
        """Legacy misnomer, kept for compatibility.

        This is not a "receiver capability class" — it is the **high byte of
        that TLV's u16 length**.  It appeared to partition chipset families
        because the length tracks the SV-array size, which tracks receiver
        capacity.  Use ``tlvs`` instead.
        """
        return self.body_header_enum

    @property
    def body_format_subcode(self) -> int:
        """Legacy alias for ``counter2``; prefer ``qmi_message_id``.  The
        value is a QMI **message id**, so it predicts body
        shape for the ordinary reason that a message id determines a
        message's payload.  It is scoped per SERVICE, not per firmware —
        always pair it with ``qmi_service_id``.  Kept for compatibility;
        prefer ``qmi_message_id``."""
        return self.counter2

    @property
    def body_size_echo_valid(self) -> bool | None:
        """True iff body[5] is consistent with the decoded slot count.

        **Weaker than its name suggests.**  It is not an independent
        "size echo" corruption check:
        body[4:7] is a QMI TLV header, so body[5] is the **low byte of that
        TLV's u16 length** and the compared quantity ``(n*28+1) & 0xFF`` is
        that same length re-derived from the slot count — a mod-256 because
        it is a low byte.  So this confirms that the TLV's declared length
        agrees with the slot count the walker derived from the body size,
        which is a real (if narrow) consistency check, not a second
        independent witness to the record's integrity.  For genuine framing
        validation use ``tlv_trailing_bytes == 0``.

        Returns None on non-binary_sv records.
        """
        if self.body_header_signature is None or self.sv_slots is None:
            return None
        n = len(self.sv_slots)
        expected: int | None
        if self.body_header_signature == 0x10 and n != 99:
            expected = (n * 28 + 1) & 0xFF
        elif self.body_header_signature == 0x02:
            expected = 1
        else:
            # Format class with no known echo formula yet (e.g. sig=0x10
            # enum=4 wide-capture or any other unobserved pairing).
            return None
        return self.body_header_measurement == expected

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            'type': 'Diag0x1544',
            'log_time': self.log_time,
            'version': self.version,
            'sub_type': self.sub_type,
            'sequence_counter': self.sequence_counter,
            'flags': self.flags,
            'num_constellations': self.num_constellations,
            'format_type': self.format_type,
            'constellation_mask': self.constellation_mask,
            'ref_value': self.ref_value,
            'counter2': self.counter2,
            # Legacy alias of counter2 (the QMI message id).  Always
            # exported (derived).
            'body_format_subcode': self.body_format_subcode,
            'body_len': self.body_len,
            'body_bytes': len(self.body_raw),
            'body_kind': self.body_kind,
            'body_tag': self.body_tag,
            # Raw body words, always exported.
            # Unlike body_tag these are NOT filtered on tag == 0x01, so a
            # non-0x01 body's tag byte and every body's length word survive
            # into the dict instead of being reachable only via body_raw.
            'body_tag_raw': self.body_tag_raw,
            'body_word1': self.body_word1,
            # QMI framing aliases.  Always exported (derived) —
            # a consumer reading this dict should not have to know that
            # `num_constellations` is a service id and `counter2` a message
            # id.  The legacy keys above stay for compatibility.
            'qmi_service_id': self.qmi_service_id,
            'qmi_service_name': self.qmi_service_name,
            'qmi_message_id': self.qmi_message_id,
            'qmi_message_type': self.qmi_message_type,
            'qmi_client_id': self.qmi_client_id,
            'tlv_trailing_bytes': self.tlv_trailing_bytes,
        }
        if self.tlvs is not None:
            # STRUCTURE ONLY — QmiTlv.to_dict() emits (type, length) and
            # never the value, so a committed derived artifact carries the
            # message shape without the captured bytes.  See QmiTlv.
            out['tlvs'] = [t.to_dict() for t in self.tlvs]
        if self.position is not None:
            out['position'] = self.position.to_dict()
        if self.at_text is not None:
            out['at_text'] = self.at_text
        if self.qgpsloc is not None:
            out['qgpsloc'] = self.qgpsloc.to_dict()
        if self.body_sub_kind is not None:
            out['body_sub_kind'] = self.body_sub_kind
        if self.nmea_sentence is not None:
            out['nmea_sentence'] = self.nmea_sentence
            out['nmea_sentence_type'] = self.nmea_sentence_type
        if self.sv_slots is not None:
            out['sv_slots'] = [s.to_dict() for s in self.sv_slots]
            out['body_seq_flag'] = self.body_seq_flag
            out['body_slot_count_echo'] = self.body_slot_count_echo
            out['body_header_signature'] = self.body_header_signature
            out['body_header_measurement'] = self.body_header_measurement
            out['body_header_enum'] = self.body_header_enum
            # Legacy aliases + integrity check (all derived)
            out['me_format_code'] = self.me_format_code
            out['receiver_class'] = self.receiver_class
            out['body_size_echo_valid'] = self.body_size_echo_valid
        return out


def _decode_nmea_tlv(body: bytes) -> tuple[int | None, str | None, str | None]:
    """Decode an NMEA TLV body if present.

    Returns (body_tag, nmea_sentence, nmea_sentence_type) — all None on
    non-NMEA bodies.  TLV layout:

        body[0]       = tag byte (0x01 = NMEA-ASCII)
        body[1..2]    = u16 LE length of the NMEA text
        body[3..3+L]  = ASCII NMEA sentence (typically ends with CRLF)
    """
    if len(body) < 3:
        return None, None, None
    tag = body[0]
    if tag != _TAG_01:
        return None, None, None
    nmea_len = unpack_from('<H', body, 1)[0]
    if nmea_len == 0 or 3 + nmea_len > len(body):
        return tag, None, None
    raw = body[3:3 + nmea_len]
    # NMEA sentences start with '$'.  If not, it's another tag-0x01 payload
    # (non-NMEA) — don't decode as a sentence.
    if not raw.startswith(b'$'):
        return tag, None, None
    try:
        sentence = raw.rstrip(b'\r\n').decode('ascii')
    except UnicodeDecodeError:
        return tag, None, None
    # Sentence type is the 5-char talker+sentence code following '$'
    # e.g. "$GPVTG,..." -> "GPVTG"
    stype = None
    comma = sentence.find(',')
    if 2 <= comma <= 8:
        stype = sentence[1:comma]
    return tag, sentence, stype


def _decode_binary_sv_table(body: bytes) -> list[SvSlot] | None:
    """Decode the binary-body per-SV tracking table.

    Returns a list of SvSlot entries on success, or None if the body
    doesn't match the binary-SV format (wrong length, bad tag, etc.).

    Valid binary-SV bodies have length = 8 + N*28 for some N >= 1.
    The 8-byte body header (TLV 0x01 plus the TLV 0x10 header) is skipped
    here; its bytes are exposed separately on the record.
    """
    if len(body) < _SV_BODY_HEADER_SIZE + _SV_SLOT_SIZE:
        return None
    if body[0] != _TAG_01:
        return None
    slots_region = len(body) - _SV_BODY_HEADER_SIZE
    if slots_region % _SV_SLOT_SIZE != 0:
        return None
    n_slots = slots_region // _SV_SLOT_SIZE
    slots: list[SvSlot] = []
    for i in range(n_slots):
        off = _SV_BODY_HEADER_SIZE + i * _SV_SLOT_SIZE
        cc = body[off]
        sig_type = body[off + 4]
        sv_id = body[off + 8]
        is_primary = body[off + 10]
        tracking = body[off + 11]
        elev_class = body[off + 15]
        elevation_deg = unpack_from('<f', body, off + 16)[0]
        azimuth_deg = unpack_from('<f', body, off + 20)[0]
        cn0_db_hz = unpack_from('<f', body, off + 24)[0]
        slots.append(SvSlot(
            constellation_code=cc,
            constellation_name=_CONSTELLATION_CODES.get(cc),
            signal_type=sig_type,
            sv_id=sv_id,
            is_primary_family=is_primary,
            tracking_flag=tracking,
            elevation_class=elev_class,
            elevation_deg=elevation_deg,
            azimuth_deg=azimuth_deg,
            cn0_db_hz=cn0_db_hz,
        ))
    return slots


# ---------------------------------------------------------------------------
# Ground-truth recipe — v=0x02, RM520N-GL (Quectel SDX62)
# ---------------------------------------------------------------------------
# 0x1544 is among the cleanest GNSS grounding targets in the corpus: in its
# `binary_sv` body it decodes a real per-SV sky table (sv_id / elevation /
# azimuth / C/N0), and in its `nmea` body it carries a literal NMEA sentence.
# Both map by DIRECT comparison to the modem's own GNSS surface — the per-SV
# table to `AT+QGPSGNMEA="GSV"`/`"GSA"`, the embedded sentence to whichever
# QGPSGNMEA talker matches `nmea_sentence_type`. The header counters/format
# bytes are structural (no physical-quantity AT source) and are deliberately
# left out of the field_map — grounding them would overclaim.

# domain="gnss" is a deliberate pragmatic bucket, NOT a claim that 0x1544 is
# a GNSS code.  Structurally this is a QMI transport log
# (LOG_QMI_MCS_QCSI_PKT) carrying six QMI services — WDS/NAS/WMS/AT/LOC/DSD —
# of which only LOC is GNSS.  But `domain` is single-valued, the closed
# DOMAIN_VOCAB has no qmi/transport/data bucket, and on every corpus fleet
# LOC dominates 0x1544 traffic (3,786/4,320 = 88% on the RM500Q-AE grounding
# capture) — the position payloads are the reason anyone reads this code, so
# `gnss` is where a domain filter should surface it.  If a fleet shows
# meaningful NON-GNSS QMI volume through 0x1544 (heavy WDS/NAS/WMS), a
# `data`/`qmi` domain would be the better fit.
@register(
    LOG_GNSS_SV_AGGREGATE, domain="gnss",
    name="0x1544",
    description=(
        "QMI Common Service Interface packet log (0x1544) — 28-byte QMI "
        "framing header (service id / message type / message id / client "
        "id) + a QMI TLV-chain body. Predominantly QMI_LOC traffic on this "
        "fleet, hence the GNSS reputation: NMEA sentence, binary per-SV "
        "tracking table, position report (f64 lat/lon, DOP, GPS time), "
        "idle/keepalive, embedded AT text (QMI AT service), or FN980m "
        "wardriving-mode periodic bundle sub-record."
    ),
    version=13,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE from DIAG captures across MDM9x30, MDM9650, SDX20, "
        "SDX20 V2, SDX55 and SDX62 modems (EM7455, EM7511, EM9190, LM960, "
        "EG18-NA, FN980m, RM500Q-AE, RM520N-GL).  The 28-byte header is QMI "
        "framing: num_constellations is the QMI service id, sub_type the "
        "message type (AT-service requests and responses balance 204/204), "
        "counter2 the service-scoped message id and constellation_mask the "
        "client id.  The body is a (type u8, len u16 LE, value) QMI TLV "
        "chain that consumes every body exactly (11,874/11,874 across "
        "EG18-NA SDX20 V2 + RM500Q-AE SDX55, zero trailing bytes).  Decoded "
        "payloads: NMEA sentences; the binary per-SV tracking table "
        "(constellation_code / signal_type / sv_id / tracking_flag / "
        "elevation / azimuth / CN0, 14,694 slots validated on 884 bodies); "
        "QMI_LOC position reports (f64 lat/lon, ellipsoid/MSL altitude, "
        "PDOP/HDOP/VDOP, UTC ms, leap seconds, gps_week/tow) with six "
        "independent agreements against AT+QGPSLOC=2 in the same capture; "
        "the QMI AT service's embedded AT text; and the FN980m "
        "wardriving-mode periodic-bundle sub-records keyed by (body_len, "
        "body[1], body[3]).  Position reports are F3-grounded against the "
        "firmware's GNSS-manager 'Got position update' prints on three "
        "chipset generations (1.3 m SDX20 V2, 3.0 m MDM9650, 2.19 m "
        "MDM9x30) and corpus-wide (per-capture median 2.4 m over 147 "
        "captures).  Legacy GNSS-era field names (body_header_signature / "
        "_measurement / _enum, body_format_subcode, me_format_code, "
        "receiver_class) are kept for compatibility and documented as "
        "misnomers.  Known gaps: ref_value is a per-service constant with "
        "no F3 label; the AT service leaves 1-2 trailing bytes on 0.71% of "
        "its records; service ids 0x30 and 0x55 are unnamed.  A header "
        "body_len overrunning the payload returns None."
    ),
    source_url="",
    # Field count: 11 header + 7 body-header (tag, seq_flag,
    # slot_count_echo, signature, measurement, enum, discriminator) +
    # 10 slot fields (×N slots) + NMEA alternative (sentence, type) = 26,
    # + 2 RAW body words (body_tag_raw, body_word1) exposed on every body
    # kind = 28 on binary_sv, + 14 fields decoded out of bytes otherwise
    # reachable only as opaque `body_raw` — tlv_trailing_bytes, at_text, and
    # the 12 QmiLocPositionReport fields.  `qgpsloc`'s 11 fields are NOT
    # counted: they re-decode the same bytes `at_text` already exposes, and
    # double-counting a re-parse would inflate the number.  The 5 QMI framing
    # aliases are likewise uncounted — they rename existing header fields
    # rather than reach new bytes.  -> 42 parsed / 42 identified.
    fields_parsed=42,
    fields_identified=42,
    # version=0x02 holds across 451,819 records / 188 captures / 4+ chipset
    # generations (MDM9x07 / MDM9x30 / MDM9650 / SDX20 / SDX20 V2 / SDX55 /
    # SDX62).  Size invariance is not format invariance: without this
    # invariant a future v=0x03 record with the same byte count would
    # silently mis-parse as v=0x02.
    field_invariants={
        "version": {"enum": [0x02]},
    },
    # WiGLE tagging: per-SV cn0_db_hz + tracking_flag + sky geometry
    # (elevation_deg / azimuth_deg) + sv_id + constellation_name are exposed
    # at the SvSlot dataclass level — the raw inputs the receiver runs its
    # fix-quality interpretation on, which is what WiGLE's GNSS-capture
    # quality columns reflect.
    wigle_direct=True,
    # `position`: the QMI_LOC position report's TLV 0x10/0x11 f64 pair agrees
    # with the same modem's AT+QGPSLOC=2 output to AT's 5-decimal rounding,
    # and its TLV 0x1B altitude agrees with AT's altitude while TLV 0x1A sits
    # a geoid separation below it.  0x1476 also carries `position` — the role
    # is not exclusive, and the two codes are independent witnesses (0x1476
    # carries lat/lon in RADIANS from the position engine, 0x1544 carries the
    # DEGREES f64 the LOC service published to its QMI clients).
    wigle_roles=("position", "gnss-quality"),
    # The QMI AT-service bodies carry embedded AT command / response text
    # (`at_text`).  ASCII_KINDS has no at-command entry, and `config-token`
    # ("embedded config/profile/path/operator-name strings") already covers
    # an embedded command string, so no new kind is claimed here.
    ascii_kinds=("config-token", "identifier", "nmea"),  # config dump ALSO embeds device IMEI (15-digit); nmea path ($GPVTG/$GNVTG/$GBVTG, +CGPSINFO) confirmed cross-vendor in the Telit+SIMCom slice (FN980m + SIM8202G-M2)
    issues=(),
    primary_issue=None,
)
def parse_0x1544(log_time: int, data: bytes) -> Diag0x1544 | None:
    """Parse a QMI packet-log (0x1544) payload.

    Returns None if the payload is too short for the header, or
    shorter than the header's declared body_len.
    """
    if len(data) < _HDR_SZ:
        return None

    (version, sub_type, sequence_counter, flags,
     num_constellations, _r0, _r1, _r2,
     format_type, _r3, _r4, _r5,
     constellation_mask, _r6,
     ref_value, counter2,
     body_len, _r7, _r8) = unpack_from(_HDR_FMT, data)

    # Layer-1 version gate. Mirrors the field_invariants enum at parse
    # time so a future v=0x03 record rejects early instead of populating a
    # Diag0x1544 whose body-discrimination logic below was tuned against
    # the 451,819-record v=0x02 corpus. Cheap belt-and-suspenders next to
    # the layer-2 invariant.
    if version != 0x02:
        return None

    # The header's u16 body_len declares the body.
    # A body_len that overruns the payload means the record is truncated —
    # return None (registry WARN) instead of decoding a short body (which
    # also raised IndexError on an empty body). Trailing bytes beyond
    # _HDR_SZ + body_len are still tolerated (body_raw stops at body_len).
    if _HDR_SZ + body_len > len(data):
        return None

    body_raw = data[_HDR_SZ:_HDR_SZ + body_len] if body_len > 0 else b''
    body_tag, nmea_sentence, nmea_sentence_type = _decode_nmea_tlv(body_raw)
    # The two RAW body words, read unconditionally and independently of the
    # NMEA discriminator.  `body_tag` above is None for any tag != 0x01 and
    # `_decode_nmea_tlv`'s length word is discarded on every non-'$' body, so
    # without these two the bytes would reach the dataclass only as opaque
    # `body_raw`.  Gated purely on length (mirrors the Kaitai layout's
    # `if: body_len >= 1` / `>= 3`), never on value.
    body_tag_raw = body_raw[0] if len(body_raw) >= 1 else None
    body_word1 = unpack_from('<H', body_raw, 1)[0] if len(body_raw) >= 3 else None

    # Discriminate body sub-format.  NMEA wins when a valid sentence is
    # present; otherwise try binary-SV; otherwise idle / fn980-bundle /
    # unknown.
    body_kind = 'unknown'
    body_sub_kind: int | None = None
    sv_slots = None
    body_seq_flag: int | None = None
    body_slot_count_echo: int | None = None
    body_header_signature: int | None = None
    body_header_measurement: int | None = None
    body_header_enum: int | None = None
    if nmea_sentence is not None:
        body_kind = 'nmea'
    elif body_len > 0:
        sv_slots = _decode_binary_sv_table(body_raw)
        if sv_slots is not None:
            body_kind = 'binary_sv'
            # Body-header fields valid only on binary-SV variant
            body_seq_flag = body_raw[3]
            body_slot_count_echo = body_raw[7]
            body_header_signature = body_raw[4]
            body_header_measurement = body_raw[5]
            body_header_enum = body_raw[6]
        elif body_len <= 8:
            # Too short to hold any SV slots — treat as idle/keepalive.
            body_kind = 'idle'
        elif (
            body_len >= 4
            and body_raw[0] == _TAG_01
            and (sub_kind := _FN980_PERIODIC_BUNDLE.get(
                (body_len, body_raw[1], body_raw[3])
            )) is not None
        ):
            # FN980m wardriving-mode 5-record cycle sub-record.
            body_kind = 'fn980_periodic_bundle'
            body_sub_kind = sub_kind

    # Walk the body as the QMI TLV chain it is.  Done for EVERY
    # body kind, not just the ones classified below — the chain is the body's
    # real structure, and `nmea` / `binary_sv` / `idle` are simply three
    # particular QMI messages.  `tlv_trailing_bytes == 0` on 11,874/11,874
    # bodies measured, so a nonzero value is a genuine "not a QMI message"
    # signal rather than a routine miss.
    tlvs: list[QmiTlv] | None = None
    tlv_trailing_bytes: int | None = None
    position: QmiLocPositionReport | None = None
    at_text: str | None = None
    qgpsloc: QgpslocFix | None = None
    if body_raw:
        walked, tlv_trailing_bytes = walk_qmi_tlvs(body_raw)
        tlvs = walked

        # Only REFINE the `unknown` fallthrough.  The four established kinds
        # keep their labels; `unknown` does not absorb well-formed messages,
        # so it means "the QMI grammar did not close on this body" — a label
        # that carries information.
        if body_kind == 'unknown' and tlv_trailing_bytes == 0 and walked:
            if num_constellations == 0x08:
                at_text = _decode_qmi_at_text(walked)
                if at_text is not None:
                    body_kind = 'qmi_at_text'
                    qgpsloc = parse_qgpsloc(at_text)
            if body_kind == 'unknown':
                position = _decode_qmi_loc_position(walked)
                if position is not None and position.has_position:
                    body_kind = 'qmi_position_report'
                else:
                    position = None
                    body_kind = 'qmi_tlv_chain'

    return Diag0x1544(
        log_time=log_time,
        version=version,
        sub_type=sub_type,
        sequence_counter=sequence_counter,
        flags=flags,
        num_constellations=num_constellations,
        format_type=format_type,
        constellation_mask=constellation_mask,
        ref_value=ref_value,
        counter2=counter2,
        body_len=body_len,
        body_raw=body_raw,
        body_kind=body_kind,
        body_sub_kind=body_sub_kind,
        body_tag=body_tag,
        nmea_sentence=nmea_sentence,
        nmea_sentence_type=nmea_sentence_type,
        body_seq_flag=body_seq_flag,
        body_slot_count_echo=body_slot_count_echo,
        body_header_signature=body_header_signature,
        body_header_measurement=body_header_measurement,
        body_header_enum=body_header_enum,
        sv_slots=sv_slots,
        body_tag_raw=body_tag_raw,
        body_word1=body_word1,
        tlvs=tlvs,
        tlv_trailing_bytes=tlv_trailing_bytes,
        position=position,
        at_text=at_text,
        qgpsloc=qgpsloc,
    )
