"""GNSS NMEA-over-DIAG parser (0x1384).

Wraps NMEA sentences from the GNSS engine as DIAG log frames.  The DIAG
path is a complete carrier for the engine's NMEA output, which matters
wherever the NMEA port is unavailable (e.g. DIAG-only bring-up on a Sierra
EM9190/EM9291).  Whether DIAG carries sentence types the AT NMEA port omits
is **not** a general property of this code: measured on v0x32 (below) the
DIAG and AT-port sentence streams are byte-identical, `$GN*`/`$PQ*`
included.  An AT-port gap seen on a Quectel EG18-NA is a device finding,
not a DIAG-path one.  v0x02 *does* carry Galileo `$GA*`, BeiDou `$GB*` and
QZSS `$GQ*` types (see the bitmap section), but no v0x02 capture has yet
been compared against a simultaneous AT NMEA stream, so whether the AT
port omits them there is still open.

## Format versions

Two on-the-wire format versions identified by the leading version byte.
The v1 layout is the original Sierra / older-MDM shape; v2 inserts
two bytes (``fix_quality`` + reserved zero) between the bitmap and the
sentence-length field but is otherwise identical, including a fixed
200-byte NMEA body.

### v1 — 208 bytes (`version = 0x32`)

    Byte  0:        u8   version = 0x32
    Bytes 1..4:     u32 LE  client_id (firmware-baked vendor magic)
    Bytes 5..6:     u16 LE  nmea_bitmap (one-hot sentence-type selector)
    Byte  7:        u8   nmea_length  ($..*XX + CRLF, inclusive)
    Bytes 8..207:   200 B  NMEA sentence (CRLF-terminated ASCII; the rest of
                           the 200 B is a REUSED, non-zeroed buffer)

#### v0x32 grounding (five independent checks)

Evidence: **15,875 records / 12 captures / 3 Sierra models over 2 chipset
generations** — MC7700 8,911 (SWI9200X, MDM9200), MC7455 5,879 and EM7455
1,085 (both SWI9X30C, MDM9x30).  Both the MC7455 and the EM7455 emit v0x32.

1. **F3 co-emission — GROUND.**  Site ``tm_nmea.c:665`` (an EM7455 capture
   with all F3 armed) is the firmware's own NMEA print.
   All **1,085/1,085 (100.00%)** log-record sentences appear there verbatim,
   with ``|DIAG − F3| = 0`` over distinct sentences.  On those same records
   ``nmea_length == len(F3 sentence) + 2`` in **1,085/1,085, zero exceptions**
   — so byte 7 counts ``$..*XX`` **plus the CRLF**.  ``gpstask.c:2509``
   ("M: LOC NMEA event") corroborates at event level.
2. **AT NMEA port — GROUND (independent transport).**  On an MC7700
   comparison capture: **3,305 DIAG records ↔ 3,305 AT-port lines**,
   per-talker histograms equal count-for-count, and **100.0%** of distinct
   sentences byte-identical.  On an MC7455 comparison capture the AT stream
   covers ~half the window (a consistent ~2:1 ratio on every talker) and is a
   strict subset — zero AT-only sentences.
3. **LG290P reference receiver — GROUND (external).**  MC7455 run vs
   5,690 mode-3 gpsd TPV fixes: mean-fix separation **3.7 m** horizontal;
   altitude **−0.8 m** MSL-vs-MSL (and +2.4 m HAE-vs-HAE once
   ``parsed.geoid_sep_m = −13.0`` is applied, which independently confirms
   the geoid-separation field).
4. **``0x60 DIAG_EVENT_REPORT_F`` — ABSENT.**  No 0x60 frames in any of the
   12 v0x32 captures (outer opcodes are 0x10/0x79/0x92 only).  Absent, not
   silent — there is nothing to read here.
5. **QCSuper / SCAT — no output.**  Both exit 0 on an MC7700 capture holding
   429 v0x32 records and emit no NMEA/0x1384 output (QCSuper's geo dump is
   0xB0C0-only; SCAT's stdout has zero mentions).  Neither covers this code.

Structural facts measured over all 15,875 v0x32 records:

* ``$`` sits at **offset 8 in 15,875/15,875** — the header is exactly 8 B.
  (Scan from the fixed offset, never for the ``$``: when ``nmea_length``
  happens to be 36 the length byte *is* ``0x24`` and a from-zero delimiter
  search lands on it.  The dispatch below starts at 8 and is immune.)
* ``byte7 == len(sentence) + 2`` in **15,798/15,875**.  The 77 exceptions are
  all MC7700 and are a **firmware buffer artifact, not a parse error**.  Two
  independent signals land on the *same* 77 records and together give the
  mechanism: ``nmea_bitmap`` is ``0x0020`` (``PQXFI``) while the body text is
  ``$GNGNS,,,,,,NN,,,,,,*53\\r\\n*78\\r\\n``, and ``nmea_length`` is 30 —
  i.e. the firmware selected a ``$PQXFI``, but the NMEA buffer still held a
  stale ``$GNGNS`` and only the intended sentence's ``*78\\r\\n`` checksum
  tail made it in.  ``nmea_length`` correctly counts the whole 30-byte blob;
  it is authoritative.  This parser's first-terminator scan is the
  conservative reading and drops the fragment.  ``nmea_sentence_id`` reports
  the ENVELOPE's claim and is intentionally not harmonised with the text, so
  this disagreement stays visible.
* The 200 B body is a **reused, non-zeroed buffer** — 1,799/15,875 records
  carry additional ``$`` characters in the tail, stale from prior sentences,
  and some tails carry non-zero heap residue.  Only ``nmea_length`` / the
  first terminator delimit the live sentence.
* ``byte7 <= 8`` in **0/15,875** — a positive disproof that v1 carries v2's
  ``fix_quality`` byte.  The two layouts genuinely differ; v1 is not a
  structural guess derived by subtraction from v2.
* ``popcount(nmea_bitmap) == 1`` in **15,875/15,875** (see below).

### v2 — 210 bytes (`version = 0x02`)

    Byte  0:        u8   version = 0x02
    Bytes 1..4:     u32 LE  client_id
    Bytes 5..6:     u16 LE  nmea_bitmap
    Byte  7:        u8   fix_quality (NMEA fix-quality enum 0..N: 0=invalid,
                          1=GPS, 2=DGPS, 4=RTK, 5=float-RTK; RXM-G1 emits 4) — added in v2
    Byte  8:        u8   reserved (zero) — added in v2
    Byte  9:        u8   nmea_length
    Bytes 10..209:  200 B  NMEA sentence (null-terminated ASCII + padding)

#### v0x02 grounding (F3 co-emission on two firmwares)

The v2 layout is the 210-byte majority (3,235,362 records / 386 captures).
It is grounded against the firmware's own NMEA print on **two Quectel
firmwares of different F3 vintage**:

1. **F3 co-emission — GROUND.**
   * **EG25-G** (MDM9x07, plaintext 0x79 F3; 14,898 v0x02 records).  Site
     ``loc_pd.c:3242`` prints
     ``…Receive Normal NMEA pdsmNormalNmeaCB %d, NMEA type 0x%04x`` — the
     ``NMEA type`` argument histogram is ``{0x1,0x2,0x8,0x10,0x80,0x100}`` each
     2,483, **identical to the DIAG ``nmea_bitmap`` histogram** value-for-value
     (14,898/14,898).  Companion site ``loc_pd.c:3146`` emits the six talker
     prefixes (``$GPGGA/$GPRMC/$GPGSA/$GPVTG/$GNGSA/$GNGNS``) each 2,483, matching
     the DIAG talker histogram count-for-count.  So the firmware **prints the
     selector as a literal integer** and it equals the envelope's ``nmea_bitmap``
     — a decode, not an inference (stronger than v0x32's one-hot correlation).
   * **EG18-NA** (QShrink 0x99 F3, real GNSS fix; a boot-plus-GNSS capture,
     4,912 v0x02 records / 488 with fix_quality=1).  Site
     ``loc_pd.c:5521`` prints **both** fields at once:
     ``locPd_HandleNmeaPosReport %d length nmea, nmea_type = 0x%x``.  Over all
     14 attested bins the DIAG ``nmea_bitmap`` equals ``(F3 nmea_type & 0xFFFF)``
     with max per-bin ``|Δ| = 1`` (the single 4,911-vs-4,912 boundary record).
2. **Layout — measured, not assumed.**  Reserved byte 8 == 0x00 in **14,898/14,898
   (EG25-G) + 4,912/4,912 (EG18-NA)**.  ``nmea_length`` (byte 9) ==
   ``len(sentence) + 2`` in **14,898/14,898** — so byte 9 counts ``$..*XX`` **plus
   the CRLF**, the v2-layout analog of v0x32's byte 7.  ``fix_quality`` (byte 7)
   present and independent (0 on the indoor EG25-G run; 1 on 488 EG18-NA records).
3. **``0x60 DIAG_EVENT_REPORT_F``.**  ABSENT on the EG25-G capture (outer opcodes
   0x10/0x79/0x92 only).  Present as a subsystem on the EG18-NA capture
   but carries LOC lifecycle events, not the NMEA sentence — the sentence lives in
   the 0x1384 log frame + the ``loc_pd`` F3 prints, nowhere else.
4. **QCSuper / SCAT — no output.**  QCSuper exits 0 and emits a geo dump sourced
   **only** from 0xB0C0 (``log_type 45248``), zero 0x1384/NMEA output; SCAT
   skips the code at preflight.  Neither covers 0x1384.

**``nmea_bitmap`` is the low 16 bits of a wider firmware ``nmea_type``.**
The F3 ``nmea_type`` on EG18-NA takes values ``0x10000`` /
``0x10004`` / ``0x10005`` that the DIAG envelope stores as ``0x0000`` / ``0x0004``
/ ``0x0005`` — i.e. the envelope's u16 ``nmea_bitmap`` (bytes 5..6) **truncates
bit 16 (0x10000)**.  This explains two v0x02 observations below:
``bitmap == 0`` is not "no selector assigned" but ``nmea_type
0x10000`` truncated, and bit 2's apparent ambiguity (``0x0004`` carrying both
``$GPGSV`` and the ``$PQGSA`` family) is ``0x00004`` and ``0x10004`` colliding onto
the same 16-bit value.  The firmware selector is genuinely one-per-record; the
collision is an artifact of the envelope's width, not of the firmware.  The F3
site name is firmware-specific (Sierra prints the full sentence at
``tm_nmea.c:665``; Quectel prints the talker + type at ``loc_pd.c``).

F3 also shows that the EG18-NA DIAG stream carries the full Galileo family
(``$GARMC`` 0x0200 / ``$GAGSV`` 0x0400 / ``$GAGSA`` 0x0800 / ``$GAVTG`` 0x1000 /
``$GAGGA`` 0x8000) — so DIAG v0x02 does NOT drop Galileo.  Whether the *AT NMEA
port* omits it on v0x02 still needs a simultaneous AT capture and stays open.

## nmea_bitmap — the sentence-type selector

``nmea_bitmap`` (u16 LE, bytes 5..6) selects WHICH sentence the record
carries; ``NMEA_SENTENCE_BITS`` below maps bit → sentence type and
``nmea_sentence_id`` reports the name.

**On v0x32 it is a clean one-hot selector**: exactly one bit is set in
**15,875/15,875** records, and bit → talker is 1:1 across all nine bits that
occur (the only exceptions are the 77 MC7700 firmware-artifact records
described above, where the envelope and the payload genuinely disagree).

**Do NOT promote either property to a code-level invariant** — a
147,306-record v0x02 sample over 45 vendor/model combinations breaks both:

* ``popcount`` is not always 1.  ``0x0000`` (popcount **0**) is common — F3
  grounds it (above) as ``nmea_type 0x10000`` **truncated** to the envelope's
  16 bits, carrying the BeiDou ``$GB*``, QZSS ``$GQ*``, combined ``$GNGGA`` and
  proprietary ``$PQW*``/``$PQMECLK`` families.  ``0x0005`` (popcount **2**, 333
  records) is ``nmea_type 0x10005`` truncated, carrying ``$PQGSA``.
* bit 2 is **ambiguous** on v0x02: ``0x0004`` carries ``$GPGSV`` (24,997)
  *and* ``$PQGSA`` (381).  F3 shows why — ``0x00004`` (``$GPGSV``) and
  ``0x10004`` (the ``$PQGSA`` family) collide onto the same u16 value once bit
  16 is dropped; the firmware selector itself is unambiguous.
* v0x02 lights six bits v0x32 never does — the five-strong Galileo family
  (``$GARMC`` 0x0200 / ``$GAGSV`` 0x0400 / ``$GAGSA`` 0x0800 /
  ``$GAVTG`` 0x1000 / ``$GAGGA`` 0x8000) plus ``$PSTIS`` (0x2000).

This asymmetry is why the grounding verdict here is version-bound:
"0x1384's bitmap is one-hot" is false as a statement about the code
and true as a statement about v0x32.

Also measured at ``tm_nmea.c:665``: the firmware prints ``$PQME1..4`` and
``$PQPE1`` at the same site, but **no bitmap bit is assigned to them and
0x1384 never carries them** (930 F3-only sentences on the EM7455).  Those
belong to the proprietary-GNSS codes — 0x1C7C / 0x1375 — which is the
division of labour between this code and that family.

## Observed values

Across 3,244,161 records / 382 captures (the absolute counts grow with the
capture set; re-measure rather than relying on them):

| version | client_id  | size | chipsets                          | records            |
|---------|------------|------|-----------------------------------|-------------------:|
| 0x02    | 0x00000DA3 | 210  | most chipsets (except below)      | 2,701,712 (99.51%) |
| 0x02    | 0x00001389 | 210  | sim7600 / sim8202                 |    (within above)  |
| 0x02    | 0xFFFFFFFF | 210  | rxm-g1 (proprietary $PQW*)        |    (within above)  |
| 0x32    | 0x00000DA3 | 208  | mc7455 5,879 + **em7455 1,085**   |     6,964 ( 0.21%) |
| 0x32    | 0x00002329 | 208  | mc7700 (SWI9200X / MDM9200)       |     8,911 ( 0.27%) |

``client_id`` is firmware-baked vendor magic, independent of ``version``:
SimCom emits 0x00001389; the Sierra MC7700 (an older MDM9200-class part)
emits 0x00002329 and uses the older v1/208-byte layout; the Compal RXM-G1
emits the all-ones sentinel 0xFFFFFFFF on its proprietary $PQW* sentences;
every other vendor (Quectel, most Sierra, Telit, Inseego, Foxconn) emits
0x00000DA3.

## Decoded sentence types

This parser extracts the raw NMEA sentence and additionally parses
the fields of known sentence types (GGA, RMC, GSV, GSA, VTG, GNS,
GLL, DTM) into structured dataclasses accessible via the `parsed`
field.

GLL and DTM are standard NMEA types that recur in captures (GLL ~136,
DTM ~147 in a 29k-record / 15-vendor sample); GLL in particular carries
lat/lon and this code is ``wigle_direct``.  Proprietary ``$PSTIS`` (empty
marker) and ``$PQXFI`` (XTRA fix-info; same $PQ* family as 0x1C7C/0x1375)
remain pass-through raw — their structured decode belongs with the
proprietary-GNSS codes, not here.

Log name: LOG_CGPS_PDSM_EXT_STATUS_NMEA_REPORT_C
Also known as: LOG_CGPS_PDSM_EXTENDED_STATUS_NMEA_REPORT, LOG_INTERNAL_CGPS_PDSM_EXTENDED_STATUS_NMEA_REPORT, LOG_SNSD_ERROR, LOG_CGPS_PDSM_EXTERNAL_STATUS_NMEA_REPORT
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from diaggrok.registry import register


# ---------------------------------------------------------------------------
# nmea_bitmap — one-hot sentence-type selector
# ---------------------------------------------------------------------------
# Measured bit->talker map.  Bits 0..8 are attested on BOTH format versions;
# bits 9..15 so far only on v0x02 (the Galileo family + $PSTIS).  Counts are
# from all 15,875 v0x32 records, plus a 147,306-record v0x02 sample spanning
# 45 vendor/model combinations.
#
# This map is a LABEL, not a guarantee.  On v0x02 bit 2 is ambiguous —
# 0x0004 carries $GPGSV (24,997) *and* $PQGSA (381) — so a disagreement
# between nmea_sentence_id and nmea_talker is expected there and is reported,
# not suppressed.  On v0x32 the map is 1:1 apart from 77 firmware-artifact
# records (see the module docstring).
NMEA_SENTENCE_BITS: dict[int, str] = {
    0x0001: 'GPGGA',   # v0x32 1,735   v0x02 15,098
    0x0002: 'GPRMC',   # v0x32 1,735   v0x02 15,194
    0x0004: 'GPGSV',   # v0x32 5,529   v0x02 24,997 (+381 $PQGSA — ambiguous)
    0x0008: 'GPGSA',   # v0x32 1,735   v0x02 15,181
    0x0010: 'GPVTG',   # v0x32 1,735   v0x02 15,079
    0x0020: 'PQXFI',   # v0x32   728   v0x02    115  — XTRA fix-info
    0x0040: 'GLGSV',   # v0x32   186   v0x02  5,120  — GLONASS SVs-in-view
    0x0080: 'GNGSA',   # v0x32 1,533   v0x02 11,210
    0x0100: 'GNGNS',   # v0x32   882   v0x02  6,939
    0x0200: 'GARMC',   # v0x02 only  3,580  — Galileo
    0x0400: 'GAGSV',   # v0x02 only  1,481
    0x0800: 'GAGSA',   # v0x02 only  3,519
    0x1000: 'GAVTG',   # v0x02 only  3,468
    0x2000: 'PSTIS',   # v0x02 only    299
    0x8000: 'GAGGA',   # v0x02 only  3,449
}


def sentence_id_for_bitmap(bitmap: int) -> str | None:
    """Name the sentence type ``nmea_bitmap`` selects, or None.

    Returns None for an unmapped bit AND for ``bitmap == 0`` — the latter is
    legal on v0x02, where F3 grounds it as a wider ``nmea_type`` (0x10000)
    truncated to the envelope's 16 bits (see the v0x02 grounding block), i.e. a
    proprietary/unclassified sentence ($PQW* / $PQMECLK).  Deliberately does
    NOT guess from the sentence text: this field reports what the *envelope*
    claims, so a disagreement with ``nmea_talker`` stays visible instead of
    being silently harmonised away.
    """
    return NMEA_SENTENCE_BITS.get(bitmap)


# ---------------------------------------------------------------------------
# Parsed NMEA sentence dataclasses
# ---------------------------------------------------------------------------

@dataclass
class NmeaGGA:
    """GGA — Global Positioning System Fix Data."""
    utc_time: str              # HHMMSS.ss
    latitude: float | None     # Decimal degrees (negative = South)
    longitude: float | None    # Decimal degrees (negative = West)
    fix_quality: int           # 0=invalid, 1=GPS, 2=DGPS, 4=RTK, 5=float RTK
    num_satellites: int
    hdop: float | None
    altitude_m: float | None   # Altitude above MSL in meters
    geoid_sep_m: float | None  # Geoid separation in meters
    dgps_age: float | None     # Age of differential correction
    dgps_station_id: str       # Reference station ID

    def to_dict(self) -> dict[str, Any]:
        return {
            'sentence_type': 'GGA',
            'utc_time': self.utc_time,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'fix_quality': self.fix_quality,
            'num_satellites': self.num_satellites,
            'hdop': self.hdop,
            'altitude_m': self.altitude_m,
            'geoid_sep_m': self.geoid_sep_m,
        }


@dataclass
class NmeaRMC:
    """RMC — Recommended Minimum Navigation Information."""
    utc_time: str              # HHMMSS.ss
    status: str                # A=active, V=void
    latitude: float | None     # Decimal degrees
    longitude: float | None    # Decimal degrees
    speed_knots: float | None  # Speed over ground in knots
    course_deg: float | None   # Course over ground in degrees true
    date: str                  # DDMMYY
    mag_variation: float | None
    mode: str                  # A=autonomous, D=DGPS, E=estimated, N=not valid

    def to_dict(self) -> dict[str, Any]:
        return {
            'sentence_type': 'RMC',
            'utc_time': self.utc_time,
            'status': self.status,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'speed_knots': self.speed_knots,
            'course_deg': self.course_deg,
            'date': self.date,
            'mode': self.mode,
        }


@dataclass
class NmeaSvInfo:
    """Single satellite info within a GSV sentence."""
    prn: int                   # Satellite PRN number
    elevation_deg: int | None  # Elevation in degrees (0-90)
    azimuth_deg: int | None    # Azimuth in degrees (0-359)
    snr_dbhz: int | None       # Signal-to-noise ratio in dB-Hz

    def to_dict(self) -> dict[str, Any]:
        return {
            'prn': self.prn,
            'elevation_deg': self.elevation_deg,
            'azimuth_deg': self.azimuth_deg,
            'snr_dbhz': self.snr_dbhz,
        }


@dataclass
class NmeaGSV:
    """GSV — Satellites in View."""
    total_messages: int        # Total number of GSV messages in this set
    message_number: int        # This message number (1-based)
    total_svs: int             # Total satellites in view
    satellites: list[NmeaSvInfo] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            'sentence_type': 'GSV',
            'total_messages': self.total_messages,
            'message_number': self.message_number,
            'total_svs': self.total_svs,
            'satellites': [sv.to_dict() for sv in self.satellites],
        }


@dataclass
class NmeaGSA:
    """GSA — GNSS DOP and Active Satellites."""
    mode_auto: str             # M=manual, A=automatic
    fix_type: int              # 1=no fix, 2=2D, 3=3D
    sv_ids: list[int]          # Up to 12 active satellite PRNs
    pdop: float | None
    hdop: float | None
    vdop: float | None
    system_id: int | None      # NMEA 4.11: 1=GPS, 2=GLONASS, 3=Galileo, 4=BeiDou

    def to_dict(self) -> dict[str, Any]:
        return {
            'sentence_type': 'GSA',
            'mode_auto': self.mode_auto,
            'fix_type': self.fix_type,
            'sv_ids': self.sv_ids,
            'pdop': self.pdop,
            'hdop': self.hdop,
            'vdop': self.vdop,
            'system_id': self.system_id,
        }


@dataclass
class NmeaVTG:
    """VTG — Track Made Good and Ground Speed."""
    course_true: float | None   # Course over ground, degrees true
    course_mag: float | None    # Course over ground, degrees magnetic
    speed_knots: float | None   # Speed over ground in knots
    speed_kmh: float | None     # Speed over ground in km/h
    mode: str                   # A=autonomous, D=DGPS, E=estimated, N=not valid

    def to_dict(self) -> dict[str, Any]:
        return {
            'sentence_type': 'VTG',
            'course_true': self.course_true,
            'course_mag': self.course_mag,
            'speed_knots': self.speed_knots,
            'speed_kmh': self.speed_kmh,
            'mode': self.mode,
        }


@dataclass
class NmeaGNS:
    """GNS — GNSS Fix Data (NMEA 4.10+ multi-constellation)."""
    utc_time: str              # HHMMSS.ss
    latitude: float | None     # Decimal degrees
    longitude: float | None    # Decimal degrees
    mode_indicator: str        # Mode per constellation (e.g. "AAN" = GPS auto, GLONASS auto, Galileo none)
    num_satellites: int
    hdop: float | None
    altitude_m: float | None
    geoid_sep_m: float | None
    dgps_age: float | None
    dgps_station_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            'sentence_type': 'GNS',
            'utc_time': self.utc_time,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'mode_indicator': self.mode_indicator,
            'num_satellites': self.num_satellites,
            'hdop': self.hdop,
            'altitude_m': self.altitude_m,
            'geoid_sep_m': self.geoid_sep_m,
        }


@dataclass
class NmeaGLL:
    """GLL — Geographic Position, Latitude/Longitude."""
    latitude: float | None     # Decimal degrees (negative = South)
    longitude: float | None    # Decimal degrees (negative = West)
    utc_time: str              # HHMMSS.ss
    status: str                # A=valid, V=invalid
    mode: str                  # A=autonomous, D=DGPS, E=estimated, N=not valid

    def to_dict(self) -> dict[str, Any]:
        return {
            'sentence_type': 'GLL',
            'latitude': self.latitude,
            'longitude': self.longitude,
            'utc_time': self.utc_time,
            'status': self.status,
            'mode': self.mode,
        }


@dataclass
class NmeaDTM:
    """DTM — Datum Reference."""
    local_datum: str           # e.g. "W84", "P90"
    lat_offset_min: float | None   # Latitude offset, minutes
    lon_offset_min: float | None   # Longitude offset, minutes
    alt_offset_m: float | None     # Altitude offset, meters
    ref_datum: str             # Reference datum (e.g. "W84")

    def to_dict(self) -> dict[str, Any]:
        return {
            'sentence_type': 'DTM',
            'local_datum': self.local_datum,
            'lat_offset_min': self.lat_offset_min,
            'lon_offset_min': self.lon_offset_min,
            'alt_offset_m': self.alt_offset_m,
            'ref_datum': self.ref_datum,
        }


# ---------------------------------------------------------------------------
# NMEA field parsing helpers
# ---------------------------------------------------------------------------

def _parse_float(s: str) -> float | None:
    """Parse a float field, returning None for empty strings."""
    if not s:
        return None
    try:
        return float(s)
    except ValueError:
        return None


def _parse_int(s: str) -> int | None:
    """Parse an integer field, returning None for empty strings."""
    if not s:
        return None
    try:
        return int(s)
    except ValueError:
        return None


def _parse_latlon(value: str, hemisphere: str) -> float | None:
    """Parse NMEA latitude (DDMM.MMMM) or longitude (DDDMM.MMMM) to decimal degrees.

    Returns negative for S/W hemispheres.
    """
    if not value or not hemisphere:
        return None
    try:
        # Find the decimal point to split degrees from minutes
        dot_pos = value.index('.')
        # Degrees are everything before the last 2 digits before the dot
        deg_digits = dot_pos - 2
        if deg_digits < 1:
            return None
        degrees = int(value[:deg_digits])
        minutes = float(value[deg_digits:])
        result = degrees + minutes / 60.0
        if hemisphere in ('S', 'W'):
            result = -result
        return result
    except (ValueError, IndexError):
        return None


def _strip_checksum(sentence: str) -> str:
    """Strip the *XX checksum suffix from an NMEA sentence."""
    idx = sentence.find('*')
    if idx >= 0:
        return sentence[:idx]
    return sentence


# ---------------------------------------------------------------------------
# Sentence parsers
# ---------------------------------------------------------------------------

def _parse_gga(fields: list[str]) -> NmeaGGA | None:
    """Parse GGA fields: time,lat,N/S,lon,E/W,quality,numSV,hdop,alt,M,sep,M,age,stn."""
    if len(fields) < 15:
        return None
    return NmeaGGA(
        utc_time=fields[1],
        latitude=_parse_latlon(fields[2], fields[3]),
        longitude=_parse_latlon(fields[4], fields[5]),
        fix_quality=int(fields[6]) if fields[6] else 0,
        num_satellites=int(fields[7]) if fields[7] else 0,
        hdop=_parse_float(fields[8]),
        altitude_m=_parse_float(fields[9]),
        geoid_sep_m=_parse_float(fields[11]),
        dgps_age=_parse_float(fields[13]),
        dgps_station_id=fields[14] if len(fields) > 14 else '',
    )


def _parse_rmc(fields: list[str]) -> NmeaRMC | None:
    """Parse RMC fields: time,status,lat,N/S,lon,E/W,spd,cog,date,mv,mvE/W,mode."""
    if len(fields) < 12:
        return None
    return NmeaRMC(
        utc_time=fields[1],
        status=fields[2],
        latitude=_parse_latlon(fields[3], fields[4]),
        longitude=_parse_latlon(fields[5], fields[6]),
        speed_knots=_parse_float(fields[7]),
        course_deg=_parse_float(fields[8]),
        date=fields[9],
        mag_variation=_parse_float(fields[10]),
        mode=fields[12] if len(fields) > 12 else '',
    )


def _parse_gsv(fields: list[str]) -> NmeaGSV | None:
    """Parse GSV fields: numMsg,msgNum,numSV,[prn,elev,az,snr]*4."""
    if len(fields) < 4:
        return None
    total_messages = _parse_int(fields[1]) or 0
    message_number = _parse_int(fields[2]) or 0
    total_svs = _parse_int(fields[3]) or 0

    satellites = []
    # Each satellite takes 4 fields starting at index 4
    i = 4
    while i + 3 < len(fields):
        prn = _parse_int(fields[i])
        if prn is None:
            break
        satellites.append(NmeaSvInfo(
            prn=prn,
            elevation_deg=_parse_int(fields[i + 1]),
            azimuth_deg=_parse_int(fields[i + 2]),
            snr_dbhz=_parse_int(fields[i + 3]),
        ))
        i += 4

    return NmeaGSV(
        total_messages=total_messages,
        message_number=message_number,
        total_svs=total_svs,
        satellites=satellites,
    )


def _parse_gsa(fields: list[str]) -> NmeaGSA | None:
    """Parse GSA fields: mode,fixType,sv1..sv12,pdop,hdop,vdop[,systemId]."""
    if len(fields) < 18:
        return None
    mode_auto = fields[1]
    fix_type = int(fields[2]) if fields[2] else 1

    # SV IDs are in fields 3..14 (12 slots)
    sv_ids = []
    for i in range(3, 15):
        if i < len(fields) and fields[i]:
            sv = _parse_int(fields[i])
            if sv is not None:
                sv_ids.append(sv)

    pdop = _parse_float(fields[15]) if len(fields) > 15 else None
    hdop = _parse_float(fields[16]) if len(fields) > 16 else None
    vdop = _parse_float(fields[17]) if len(fields) > 17 else None
    # NMEA 4.11 system ID is field 18 (after vdop)
    system_id = _parse_int(fields[18]) if len(fields) > 18 else None

    return NmeaGSA(
        mode_auto=mode_auto,
        fix_type=fix_type,
        sv_ids=sv_ids,
        pdop=pdop,
        hdop=hdop,
        vdop=vdop,
        system_id=system_id,
    )


def _parse_vtg(fields: list[str]) -> NmeaVTG | None:
    """Parse VTG fields: cogt,T,cogm,M,spdN,N,spdK,K,mode."""
    if len(fields) < 9:
        return None
    return NmeaVTG(
        course_true=_parse_float(fields[1]),
        course_mag=_parse_float(fields[3]),
        speed_knots=_parse_float(fields[5]),
        speed_kmh=_parse_float(fields[7]),
        mode=fields[9] if len(fields) > 9 else '',
    )


def _parse_gns(fields: list[str]) -> NmeaGNS | None:
    """Parse GNS fields: time,lat,N/S,lon,E/W,mode,numSV,hdop,alt,sep,age,stn."""
    if len(fields) < 13:
        return None
    return NmeaGNS(
        utc_time=fields[1],
        latitude=_parse_latlon(fields[2], fields[3]),
        longitude=_parse_latlon(fields[4], fields[5]),
        mode_indicator=fields[6],
        num_satellites=int(fields[7]) if fields[7] else 0,
        hdop=_parse_float(fields[8]),
        altitude_m=_parse_float(fields[9]),
        geoid_sep_m=_parse_float(fields[10]),
        dgps_age=_parse_float(fields[11]),
        dgps_station_id=fields[12] if len(fields) > 12 else '',
    )


def _parse_gll(fields: list[str]) -> NmeaGLL | None:
    """Parse GLL fields: lat,N/S,lon,E/W,time,status,mode."""
    if len(fields) < 7:
        return None
    return NmeaGLL(
        latitude=_parse_latlon(fields[1], fields[2]),
        longitude=_parse_latlon(fields[3], fields[4]),
        utc_time=fields[5],
        status=fields[6],
        mode=fields[7] if len(fields) > 7 else '',
    )


def _parse_dtm(fields: list[str]) -> NmeaDTM | None:
    """Parse DTM fields: localDatum,subDatum,latOff,N/S,lonOff,E/W,altOff,refDatum."""
    if len(fields) < 9:
        return None
    lat_off = _parse_float(fields[3])
    if lat_off is not None and fields[4] in ('S', 'W'):
        lat_off = -lat_off
    lon_off = _parse_float(fields[5])
    if lon_off is not None and fields[6] in ('S', 'W'):
        lon_off = -lon_off
    return NmeaDTM(
        local_datum=fields[1],
        lat_offset_min=lat_off,
        lon_offset_min=lon_off,
        alt_offset_m=_parse_float(fields[7]),
        ref_datum=fields[8],
    )


# Map sentence type suffix to parser
_SENTENCE_PARSERS = {
    'GGA': _parse_gga,
    'RMC': _parse_rmc,
    'GSV': _parse_gsv,
    'GSA': _parse_gsa,
    'VTG': _parse_vtg,
    'GNS': _parse_gns,
    'GLL': _parse_gll,
    'DTM': _parse_dtm,
}


def parse_nmea_sentence(sentence: str) -> Any | None:
    """Parse a complete NMEA sentence string into a structured dataclass.

    Returns None if the sentence type is not recognized or parsing fails.
    """
    stripped = _strip_checksum(sentence)
    fields = stripped.split(',')
    if not fields:
        return None

    # Identify sentence type: last 3 chars of talker field (e.g. "$GPGGA" → "GGA")
    talker = fields[0]
    if len(talker) < 4:
        return None
    # Handle $PQGSA (proprietary) — sentence type is last 3 chars
    sentence_type = talker[-3:]

    parser = _SENTENCE_PARSERS.get(sentence_type)
    if parser is None:
        return None
    try:
        return parser(fields)
    except (ValueError, IndexError):
        return None


# ---------------------------------------------------------------------------
# Top-level dataclass and parser
# ---------------------------------------------------------------------------

@dataclass
class Diag0x1384:
    """GNSS NMEA sentence wrapped in a DIAG log frame (0x1384)."""
    log_time: int
    version: int                  # byte 0 — 0x32 (v1) or 0x02 (v2)
    client_id: int                # u32 LE bytes 1..4 (firmware-baked vendor magic)
    nmea_bitmap: int              # u16 LE bytes 5..6 — one-hot sentence-type selector
    fix_quality: int | None       # byte 7 (v2 only); None on v1
    nmea_length: int              # byte 7 (v1) or byte 9 (v2) — sentence + CRLF
    nmea_sentence: str            # Raw decoded NMEA string
    nmea_talker: str              # First field (e.g., "$GPGGA")
    parsed: Any | None = None     # Structured parse of known sentence types
    # Sentence type named by nmea_bitmap (envelope's own claim, not inferred
    # from the text).  None for bitmap==0 / unmapped bits.
    nmea_sentence_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'type': 'Diag0x1384',
            'log_time': self.log_time,
            'version': self.version,
            'client_id': self.client_id,
            'nmea_talker': self.nmea_talker,
            'nmea_sentence': self.nmea_sentence,
            'nmea_bitmap': self.nmea_bitmap,
            'nmea_sentence_id': self.nmea_sentence_id,
            'fix_quality': self.fix_quality,
            'nmea_length': self.nmea_length,
        }
        if self.parsed is not None:
            d['parsed'] = self.parsed.to_dict()
        return d


# ---------------------------------------------------------------------------
# Ground-truth plan — EG95-NA (Quectel, MDM9x07). Not yet run on hardware:
# every field below is a hypothesis until a verification run captures the log
# alongside the paired AT/NMEA reference.
#
# 0x1384 is the cleanest GNSS anchor on the EG95: it WRAPS the GNSS
# engine's NMEA sentences inside the DIAG frame, so it grounds two ways —
#   (1) the structured `parsed.*` scalars ground numerically vs AT+QGPSLOC=2;
#   (2) the raw `nmea_sentence` should be byte-comparable (same talker+type+
#       fix epoch) to AT+QGPSGNMEA output on the AT port.
# Target version is 0x02 (210 B) — confirmed on EG95-NA (2,945 records in an
# LG290P-paired capture).  v0x32 is Sierra-only (mc7700 / mc7455 / em7455).
# The canonical name LOG_CGPS_PDSM_EXT_STATUS_NMEA_REPORT_C confirms the
# GNSS/CGPS subsystem — title and name agree.

#: Fixed NMEA body size shared by both layouts (bytes after the 8/10-byte header).
_NMEA_BODY_LEN = 200


@register(
    0x1384, domain="gnss",
    name="0x1384",
    description="NMEA sentences from the GNSS engine via DIAG — a complete carrier for the engine's NMEA output where the NMEA port is unavailable",
    version=12,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail="Clean-room decode of both on-the-wire layouts (v0x02 210 B, v0x32 208 B) — version, client_id (u32), nmea_bitmap (u16), fix_quality (v0x02), nmea_length and the NMEA sentence, with structured GGA/RMC/GSV/GSA/VTG/GNS/GLL/DTM parsing; $PSTIS/$PQXFI stay raw pass-through. v0x32 is grounded on 15,875 Sierra records (F3 tm_nmea.c print verbatim 1,085/1,085, AT NMEA port byte-identical, LG290P reference 3.7 m); v0x02 is F3-grounded on two Quectel firmwares (nmea_bitmap == F3 nmea_type & 0xFFFF). nmea_bitmap is decoded to nmea_sentence_id. Records shorter than header + the fixed 200-byte NMEA body return None. Open: whether the AT NMEA port omits v0x02 Galileo/BeiDou/QZSS types.",
    source_url="",
    issues=(),
    primary_issue=None,
    # Envelope fields identified + parsed: version, client_id, nmea_bitmap,
    # fix_quality (v2-only), nmea_length, nmea_sentence (full structured NMEA
    # via parse_nmea_sentence — GGA/RMC/GSV/GSA/VTG/GNS/GLL/DTM).
    # NOTE: nmea_sentence_id is a SEMANTIC decode of nmea_bitmap, not a
    # separate wire field, so the counts stay at 6.
    fields_identified=6, fields_parsed=6,
    # ASCII audit (Quectel slice): 654/654 records carry NMEA
    # sentences ($GPVTG/$GAVTG/$GPGSV/$PSTIS) — the structured NMEA-
    # passthrough code, parsed via parse_nmea_sentence below.
    ascii_kinds=("nmea",),
    # WiGLE tagging: NmeaGGA exposes
    # latitude/longitude/altitude_m/num_satellites/hdop/utc_time at dataclass
    # level via .parsed; NmeaRMC + NmeaGNS likewise expose lat/lon/utc/date.
    # Periodic ~1 Hz cadence per sentence type. Validated 422,364 records /
    # 14 chipset families.
    wigle_direct=True,
    wigle_roles=("position", "gnss-quality", "timing-anchor:periodic"),
    # Timebase capability (from a cadence sweep). Unlike
    # the GNSS *measurement-report* time family (0x1477/0x1478/0x147B/0x1480/
    # 0x1756/0x14DE, which carry a binary GPS/GLONASS/BDT week+TOW header), 0x1384
    # carries the GNSS-derived UTC as an ASCII NMEA field — RMC (utc_time + date),
    # GGA/GNS/GLL (utc_time) — decoded self-contained (no qdb; the code IS its own
    # ground truth, provenance = SELF-CONTAINED). So it is BOTH:
    #   * absolute-time — RMC gives a full real-world UTC datetime; the decoded UTC
    #     matches each capture's own wall-clock start + a plausible GNSS TTFF
    #     (RM500Q-AE SDX55: first fix 22 s after capture start; EM9190 SDX55
    #     and SIM8202G-M2 SDX55 likewise consistent with their capture starts),
    #     monotonic across the capture.
    #   * ts-anchor — pairing each record's DIAG ts64 (log_time) with its NMEA
    #     UTC-seconds is a clean linear ts64->wall map, chipset-invariant slope
    #     ~52428.8 ts64/ms (the known ts64 rate), across 3 independent SDX55
    #     vendors: Quectel RM500Q-AE R2=1.00000000 slope 52428.63 resid 0.9 ms
    #     (n=2782), Sierra EM9190 R2=1.00000000 slope 52428.89 resid 1.7 ms
    #     (n=6277), SIMCom SIM8202G-M2 R2=0.99999998 slope 52428.60 resid 22.2 ms
    #     (n=3226). The larger SIMCom residual is NMEA-vs-DIAG-stamp jitter (cf.
    #     0x147B's ~70 ms), well within the clean-anchor bar.
    # Scope: 0x1384 is the SDX55-class GNSS-NMEA-report code; older Telit SDX20/
    # MDM9x07 parts emit their GNSS NMEA under 0x1389/other codes, so the cross-
    # chipset evidence here is cross-VENDOR on SDX55 (3 firmwares) rather than
    # cross-generation. UTC resolution is NMEA's 0.01 s / ~1 Hz, so the anchor is
    # ~10 ms-grained (vs the measurement-report siblings' sub-ms) — still R2~=1.0.
    timebase_roles=("absolute-time", "ts-anchor"),
    field_invariants={
        # Validated against 3,244,161 records / 382 captures via a
        # (size, byte0) census — exactly two pairs exist, 210|0x02
        # (2,701,712) and 208|0x32 (15,875).
        #
        # version: 0x02 (v2 layout, 210 B) dominates at 99.51%; 0x32 (v1
        # layout, 208 B) is Sierra-only (mc7700 / mc7455 / em7455) at 0.49%.
        # v2 inserts a fix_quality byte + reserved zero between the bitmap
        # and the sentence-length field — DISPROVED-by-measurement for v1,
        # not assumed: byte7 <= 8 in 0/15,875 v0x32 records, while
        # byte7 == len(sentence)+2 in 15,798/15,875.
        "version": {
            "enum": [0x02, 0x32],
        },
        # nmea_bitmap is deliberately NOT pinned to an enum, even though
        # only 10 values are attested.  It is an extensible selector: a
        # firmware that starts emitting a new sentence type (a Galileo
        # $GAGSV, say) simply lights a new bit, and an enum would silently
        # invariant-REJECT that record (as a too-narrow client_id enum would
        # drop MC7700 and RXM-G1 traffic).
        # NMEA_SENTENCE_BITS maps the known bits; an unknown bit yields
        # nmea_sentence_id=None and the record still parses.
        # client_id (u32 LE bytes 1..4) is firmware-baked vendor magic.
        # Tracked here so regression testing catches a new client_id
        # appearing on a new firmware.  Observed set, all capture-attested +
        # modem-attributed + parse-valid:
        #   0x00000DA3  most chipsets (Quectel/Sierra/Telit/Inseego/Foxconn)
        #   0x00001389  SimCom (sim7600 / sim8202)
        #   0x00002329  Sierra MC7700 (SWI9200X / MDM9200) — v=0x32, 8,911
        #               records, 100% NMEA-checksum-valid
        #   0xFFFFFFFF  Compal RXM-G1 all-ones sentinel on proprietary $PQW*
        #               sentences — F3-verified nmea_sentence
        "client_id": {
            "enum": [0x00000DA3, 0x00001389, 0x00002329, 0xFFFFFFFF],
        },
    },
)
def parse_0x1384(log_time: int, data: bytes) -> Diag0x1384 | None:
    if len(data) < 10:
        return None

    version = data[0]
    # Layer-1 version gate. The dispatch below has
    # `if version == 0x32 / else` shape; rejecting unknown versions
    # explicitly here (rather than relying on the trailing
    # `nmea_start < 0` check) keeps the gate visible to audits.
    if version not in (0x02, 0x32):
        return None
    client_id = data[1] | (data[2] << 8) | (data[3] << 16) | (data[4] << 24)
    nmea_bitmap = data[5] | (data[6] << 8)

    # v1 (208 B): no fix_quality byte; sentence-length at byte 7;
    #             NMEA $ starts at byte 8; body is 200 B.
    # v2 (210 B): fix_quality at byte 7; reserved zero at byte 8;
    #             sentence-length at byte 9; NMEA $ at byte 10; body 200 B.
    if version == 0x32:
        fix_quality: int | None = None
        nmea_length = data[7]
        search_start = 8
    else:
        fix_quality = data[7]
        nmea_length = data[9]
        search_start = 10

    # Both layouts carry a FIXED 200-byte NMEA body after
    # the header (v1 8 + 200 = 208 B, v2 10 + 200 = 210 B). A record that does
    # not hold the whole body is truncated: return None (registry WARN) rather
    # than decode a sentence out of a partial buffer.
    if len(data) < search_start + _NMEA_BODY_LEN:
        return None

    nmea_start = data.find(b'$', search_start)
    if nmea_start < 0:
        return None

    # Find end of NMEA: CR/LF line ending, null terminator, or end of data
    nmea_end = len(data)
    for terminator in (b'\r\n', b'\r', b'\n', b'\x00'):
        pos = data.find(terminator, nmea_start)
        if 0 <= pos < nmea_end:
            nmea_end = pos

    nmea_sentence = data[nmea_start:nmea_end].decode('ascii', errors='replace')
    nmea_talker = nmea_sentence.split(',')[0] if ',' in nmea_sentence else nmea_sentence

    # Parse the NMEA fields into a structured object
    parsed = parse_nmea_sentence(nmea_sentence)

    return Diag0x1384(
        log_time=log_time,
        version=version,
        client_id=client_id,
        nmea_bitmap=nmea_bitmap,
        fix_quality=fix_quality,
        nmea_length=nmea_length,
        nmea_sentence=nmea_sentence,
        nmea_talker=nmea_talker,
        parsed=parsed,
        nmea_sentence_id=sentence_id_for_bitmap(nmea_bitmap),
    )
