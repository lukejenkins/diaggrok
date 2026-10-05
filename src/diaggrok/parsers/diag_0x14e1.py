"""0x14E1 — OEM DRE SV polynomial orbit report.

Per-SV polynomial orbit coefficients used for DR-assisted positioning
during signal outages. Carries satellite polynomial orbit coefficients
used for dead-reckoning prediction when raw measurements are briefly
unavailable (e.g., inside tunnels or during urban-canyon obstructions).

Provenance:
- Clean-room: the 259-byte fixed-size SV-poly struct layout is established
  from GNSS DIAG captures (offset/type pinned by the constellation-derived
  SV identity check + plausible MEO orbital geometry), not from third-party
  decoder source. Every field of the struct is exposed in the dataclass
  and to_dict().
- Observed on Sierra EM7511 (SWI9X50C), Telit LM960, Quectel EP06,
  EG18-NA (SDX20 V2), EG12-GT (SDX20) and EG25-G (MDM9607), and FN980m
  (SDX55). Every record is v=0x02, fixed 259 B.
- No F3 grounding is available for this code. Across all 20
  0x14E1-bearing captures (1,136 records) none carries usable F3: the
  OEM-DRE-enabled builds that emit it (EM7511, LM960, EP06, EG18-NA) emit
  no plaintext 0x79 and have no build-matched message database for their
  0x99 QSR4 stream. The 0x79-plaintext candidates an F3 extractor finds on
  the EM7511 and LM960 captures (69 and 60 frames) have no printable site
  or format string — they are false positives on binary payload, not real
  F3. Grounding the deep SV-poly fields against F3 needs an OEM-DRE GNSS
  capture from a build whose F3 resolves. The fields are instead grounded
  against independent survey-grade geometry (see the class docstring).
- The ``other`` SV-clock-polynomial grounding (r=-1.0000 on EG25-G MDM9607)
  holds on a third chipset family, Quectel EG18-NA SDX20 V2, from an
  extended capture (283 SVPOLY + 5,406 0x14DE records, same-antenna
  survey-grade LG290P reference). The non-circular geometry test —
  measured 0x14DE pseudorange minus the light-time-corrected (transmit-time
  + Sagnac) geometric range to the fixed LG290P survey fix (a surveyed
  static reference position; SV position from THIS record's xyz0+xyzN
  poly), regressed against the co-temporal ``other[0]`` clock bias —
  gives, over **n=12,603 GPS SV-epochs / 1,433 epochs**:
  **slope -299,793.9 m/ms** (ideal -c×1e-3 = -299,792.458; **ratio 1.000005**,
  5 ppm) at **r=-0.999998**, post-rx-clock-removal residual **28.2 m RMS
  filtered / 29.0 m unfiltered** (smoothed < raw). Regressing against
  ``other[0]`` alone vs the full clock polynomial ``other[0..3]`` evaluated
  at the measurement TOW gives an identical slope/r — so ``other[0]`` is the
  constant (bias) term and the higher-order terms are negligible over the
  ~50 s poly window. EG25-G MDM9607 and FN980m SDX55 are the other two
  attested chipsets.
- The GLONASS clock-poly is grounded the same way. GLONASS SVPOLY ``t0`` is
  a distinct base (≈9.66e8) — seconds since the 1996-01-01 GLONASS epoch in
  GLONASS system time, whereas GPS ``t0`` is GPS-seconds-of-week (≈9.4e4).
  The co-temporal 0x14DE GLONASS record times its receiver clock in
  ``glo_milliseconds`` (ms of day) tagged by ``glo_year``=N4 (4-year
  interval) and ``glo_day``=Nt (day within interval); converting that epoch
  into the ``t0`` base lets the GLONASS bucket pair. On the same EG18-NA
  capture the GLONASS bucket lands **slope −299,805 m/ms (ratio 1.000042 to
  −c), r=−0.99996, rx-clock-removed residual 12.6 m filtered / 15.8 m
  unfiltered** (n=6764 SV-epochs) — attesting ``other[0]`` as the SV clock
  bias for GLONASS exactly as for GPS. The ±3 h Moscow / GPS-leap offset
  cancels in ``dt = meas_t − t0``, so no constellation-specific geometry
  change is needed.

Log name: LOG_GNSS_OEMDRE_POSITION_REPORT
Also known as: LOG_GNSS_OEMDRE_SVPOLY_REPORT
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from struct import calcsize
from typing import Any

from diaggrok.codes import LOG_GNSS_OEMDRE_SVPOLY_REPORT
from diaggrok.parsers.gnss_helpers import unpack_dict
from diaggrok.registry import register


# oemdre_svpoly_report (43 fields)
_SVPOLY_FMT = '<BHbBH' + 'd' * 13 + 'f' * 13 + 'd' * 12
_SVPOLY_SZ = calcsize(_SVPOLY_FMT)
_SVPOLY_FIELDS = [
    'version', 'sv_id', 'frequency_index', 'flags', 'iode',
    't0',
    'xyz0_0', 'xyz0_1', 'xyz0_2',
    'xyzN_0', 'xyzN_1', 'xyzN_2', 'xyzN_3', 'xyzN_4',
    'xyzN_5', 'xyzN_6', 'xyzN_7', 'xyzN_8',
    'other_0', 'other_1', 'other_2', 'other_3',
    'position_uncertainty', 'iono_delay', 'iono_dot',
    'sbas_iono_delay', 'sbas_iono_dot', 'tropo_delay',
    'elevation', 'elevation_dot', 'elevation_uncertainty',
    'vel_coeff_0', 'vel_coeff_1', 'vel_coeff_2', 'vel_coeff_3',
    'vel_coeff_4', 'vel_coeff_5', 'vel_coeff_6', 'vel_coeff_7',
    'vel_coeff_8', 'vel_coeff_9', 'vel_coeff_10', 'vel_coeff_11',
]
assert len(_SVPOLY_FIELDS) == 43


@dataclass
class Diag0x14E1:
    """OEM DRE SV polynomial orbit report (0x14E1).

    Carries satellite polynomial orbit coefficients used for dead-reckoning
    prediction when raw measurements are briefly unavailable (e.g., inside
    tunnels or during urban-canyon obstructions).  Every field from the
    259-byte fixed-size struct is retained and emitted by ``to_dict()``.

    **Field layout** (validated against EG18-NA SDX20 V2):

    - **Header (7 B):** version, sv_id, frequency_index, flags, iode
    - **Reference time (8 B):** t0 (double — GPS seconds of week)
    - **Initial position (24 B):** xyz0 (3 × double ECEF metres)
    - **Position polynomial (72 B):** xyzN (9 × double; 3 axes × 3 orders
      of polynomial velocity/accel/jerk)
    - **SV clock-correction polynomial (16 B):** other (4 × **float**, NOT
      double — part of the f×13 group at +111). **Grounded as the SV clock
      polynomial in MILLISECONDS (r=-1.0000).** The decreasing-magnitude
      series c0 + c1·dt + c2·dt² + c3·dt³ (dt = t - t0) gives the SV clock
      correction: other[0] = clock bias (ms), other[1] = clock drift (ms/s ≡
      GPS af1, ~1e-11 s/s), other[2..3] = higher order. Populated on EM7511
      and on MDM9607 all-constellation (34 GPS / 3 Gal / 25 GLONASS, all
      nonzero).
    - **Corrections (24 B):** position_uncertainty, iono_delay, iono_dot,
      sbas_iono_delay, sbas_iono_dot, tropo_delay (6 × float)
    - **Elevation dynamics (12 B):** elevation, elevation_dot,
      elevation_uncertainty (3 × float; radians)
    - **Velocity coefficients (96 B):** velocity_coeff (12 × double)

    (7 + 104 + 52 + 96 = 259 B; the 'other' floats and the 6 correction
    + 3 elevation floats together form the f×13 group. Reading 'other' as
    4 doubles would make the record 275 B.)

    **Cross-corpus field observations:**

    - ``velocity_coeff`` is **CONSTELLATION-GATED = GLONASS-only** (EG25-G
      MDM9607, 62 records). It is populated on **25/25 GLONASS** records and
      **0/34 GPS + 0/3 Galileo** — a clean split, not RF/SV-state noise.
      Physical basis: GLONASS broadcasts ephemeris as ECEF
      **position+velocity+acceleration** (PVA), whereas GPS/Galileo use
      Keplerian elements, so the DR velocity polynomial is natively
      available only for GLONASS. The EM7511's 88/361 non-zero records are
      consistent with this (its non-zero set is its GLONASS SVs). NOT a
      parser offset bug: a synthetic-populated-record test confirms the
      12-double offsets read correctly.
    - ``flags`` (+4, u8): low nibble 0x0F is a **universal validity mask**
      (set on all 62 records, every constellation). **Bit 6 (0x40) is
      GLONASS-exclusive** (set on 21/25 GLONASS, NEVER on GPS 0/34 or
      Galileo 0/3) — the frequency-slot-valid flag for the only FDMA
      constellation (the 4 GLONASS records with bit6 clear are SVs whose
      freq slot isn't yet resolved).
    - ``flags`` bit 4 (0x10) is a **predicted/extrapolated-orbit
      indicator, emitted only by the Sierra EM7511 (MDM9650/SDX20-X16)
      OEM-DRE — NEVER by the MDM9607/MDM9x40 firmware.** An exhaustive
      EG25-G (MDM9607) config sweep — all 8 ``AT+QGPSCFG="gnssconfig"`` enum
      values (0-7), warm AND cold, ~343 records across GPS/GLONASS/Galileo —
      leaves bit 4 **0/343**; EP06-A (MDM9607) 0/45 and LM960 0/29 agree. On
      the EM7511 it sets in ~78% of records across **all** constellations
      incl. BeiDou (280/361 and 198/252 on two firmware builds). Within the
      EM7511 captures, bit-4-set records are consistently distinguished
      (both firmwares) by a **higher ``position_uncertainty``** (≥4.0 vs
      ~2.4 m) and a strong skew toward **below-horizon SVs** (~75% vs ~35%)
      — the signature of a full-sky *predicted* orbit rather than a
      freshly-tracked broadcast-ephemeris SV. (On the newer build every
      bit-4-set record additionally carries the IODE placeholder
      ``iode==1``; on the older it does not — so IODE is a firmware-specific
      tell, not the invariant.) The MDM9607 EG25-G cannot reproduce it via
      any ``gnssconfig`` because it emits SV-poly only for actively-tracked
      SVs and has no valid XTRA/predicted-orbit source
      (``xtra_autodownload`` → ``+CME 501``). Distinguishing
      "EM7511/MDM9650-firmware-only emission" from "XTRA-predicted-orbit
      conditioned" needs a same-model EM7511 A/B (XTRA loaded vs cleared).
    - xyz0 values look like correct GPS MEO positions (||xyz0|| ≈ 26,600
      km matches the nominal GPS orbital radius from Earth center).
    - xyzN first-order value is around ±1000 m/s, consistent with typical
      GPS SV velocity.
    - iono_delay / tropo_delay / elevation values are all physically
      reasonable.

    **xyz0 + elevation are grounded against independent survey-grade
    geometry** (EG25-G MDM9607, ``version=2``, 62 records across
    GPS/GLONASS/Galileo, with an LG290P reference receiver). Computing each
    SV's elevation/azimuth from the decoded ``xyz0`` ECEF position as seen
    from the LG290P survey-grade receiver fix (a surveyed static reference
    position) reproduces —

    - the record's own separately-decoded ``elevation`` float to **0.000°
      (mean & max, n=62)** — a NON-circular self-consistency proof: the
      ECEF-position bytes and the elevation float are two independently
      decoded payload regions, so a byte misalignment in either would
      diverge.  They agree to machine precision.
    - the **co-temporal 0x14DE** az/el for the same PRN to **0.97° mean /
      2.07° max azimuth, 0.72° mean / 1.91° max elevation (n=48)** — and
      0x14DE az/el is itself validated <1° vs LG290P GSV in the same
      capture.  So ``xyz0`` is grounded against an independent,
      survey-grade orbit reference, not just plausibility.

    Below-horizon SVs (negative computed elevation, e.g. GPS PRN 8/10/23/
    24/27) correctly carry no 0x14DE az/el (untracked) yet still decode a
    sane predicted ``xyz0`` — consistent with SVPOLY being a *predicted*
    orbit valid across the whole sky.  The ``other`` **SV clock polynomial
    (ms)** is grounded by non-circular geometry: measured 0x14DE
    pseudorange minus the geometric range to the LG290P survey fix (SV
    position from this record's xyz0+xyzN poly) correlates with ``other[0]``
    at **r=-1.0000, slope exactly -c×1e-3 m/ms** (n=2610), fixing the unit as
    milliseconds; the post-clock-model residual is 15.7 m RMS (orbit-poly +
    pseudorange-noise floor). It holds on a third chipset family (EG18-NA
    SDX20 V2: slope 1.000005×(-c·1e-3), r=-0.999998, n=12,603 GPS
    SV-epochs) — see the module docstring. Together with ``velocity_coeff``
    (GLONASS-only), ``flags`` bit 6 (GLONASS freq-slot-valid) and ``flags``
    bit 4 (predicted orbit, EM7511 only), **every decoded field has a
    grounded semantic.**

    **Constellation determination**: per-OEM-DRE convention the SV is
    identified by ``sv_id`` rather than by ``frequency_index``. See
    :attr:`constellation`.
    """
    log_time: int
    version: int
    sv_id: int                 # Per-constellation-encoded SV ID (see .constellation)
    frequency_index: int       # signed int8; GLONASS freq slot (0 for other constellations)
    flags: int                 # bit field
    iode: int                  # Issue of Data, Ephemeris
    t0: float                  # Reference time for polynomial (GPS seconds of week)
    xyz0: list[float]          # 3 — initial position at t0 (ECEF, metres)
    xyzN: list[float]          # 9 — position polynomial coefficients (3 axes × 3 orders)
    other: list[float]         # 4 — SV clock-correction polynomial in MILLISECONDS
                               # (grounded r=-1.0000): clock(t) =
                               # other[0] + other[1]·dt + other[2]·dt² + other[3]·dt³,
                               # dt = t - t0. other[0]=clock bias (ms), other[1]=
                               # drift (ms/s ≡ GPS af1), other[2..3]=higher order.
    position_uncertainty: float
    iono_delay: float          # metres
    iono_dot: float            # m/s
    sbas_iono_delay: float     # metres
    sbas_iono_dot: float       # m/s
    tropo_delay: float         # metres
    elevation: float           # radians
    elevation_dot: float       # rad/s
    elevation_uncertainty: float  # radians
    velocity_coeff: list[float]  # 12 — velocity polynomial coefficients

    @property
    def elevation_deg(self) -> float:
        return self.elevation * 180.0 / math.pi

    @property
    def sv_clock_bias_ms(self) -> float | None:
        """SV clock bias (ms) at t0 = other[0] (grounded).

        The ``other`` 4-float group is the SV clock-correction polynomial in
        milliseconds; ``other[0]`` is the bias at the polynomial reference time
        ``t0``. Grounded to r=-1.0000 against an independent geometry oracle:
        measured 0x14DE pseudorange minus the geometric range to the LG290P
        survey-grade fix (SV position from this record's xyz0+xyzN poly) tracks
        ``-c·other[0]·1e-3`` with slope exactly -c×1e-3 m/ms (n=2610, EG25-G
        MDM9607 bench). Returns None if ``other`` is unpopulated."""
        return self.other[0] if self.other else None

    @property
    def constellation(self) -> str:
        """Decode the constellation from sv_id using OEM DRE offsets.

          GPS:     1..32     → 'GPS'
          SBAS:    33..64    → 'SBAS'
          GLONASS: 65..96    → 'GLONASS'
          BeiDou:  201..237  → 'BeiDou'
          Galileo: 301..336  → 'Galileo'
        """
        if 1 <= self.sv_id <= 32:
            return 'GPS'
        if 33 <= self.sv_id <= 64:
            return 'SBAS'
        if 65 <= self.sv_id <= 96:
            return 'GLONASS'
        if 201 <= self.sv_id <= 237:
            return 'BeiDou'
        if 301 <= self.sv_id <= 336:
            return 'Galileo'
        return 'unknown'

    @property
    def prn(self) -> int:
        """Derive the per-constellation PRN from sv_id (see .constellation)."""
        if 1 <= self.sv_id <= 32:
            return self.sv_id
        if 65 <= self.sv_id <= 96:
            return self.sv_id - 64
        if 201 <= self.sv_id <= 237:
            return self.sv_id - 200
        if 301 <= self.sv_id <= 336:
            return self.sv_id - 300
        return self.sv_id

    @property
    def is_gps(self) -> bool:
        return self.constellation == 'GPS'

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x14E1',
            'log_time': self.log_time,
            'version': self.version,
            'sv_id': self.sv_id,
            'prn': self.prn,
            'constellation': self.constellation,
            'frequency_index': self.frequency_index,
            'is_gps': self.is_gps,
            'flags': self.flags,
            'iode': self.iode,
            't0': self.t0,
            'xyz0_ecef_m': self.xyz0,
            'xyzN_poly_coefficients': self.xyzN,
            # SV clock-correction polynomial in ms (grounded r=-1.0000):
            # [bias_ms, drift_ms_per_s, d2, d3]. See sv_clock_bias_ms.
            'other_coefficients': self.other,
            'sv_clock_bias_ms': self.sv_clock_bias_ms,
            'position_uncertainty': self.position_uncertainty,
            'iono_delay_m': self.iono_delay,
            'iono_dot_mps': self.iono_dot,
            'sbas_iono_delay_m': self.sbas_iono_delay,
            'sbas_iono_dot_mps': self.sbas_iono_dot,
            'tropo_delay_m': self.tropo_delay,
            'elevation_rad': self.elevation,
            'elevation_deg': self.elevation_deg,
            'elevation_dot_radps': self.elevation_dot,
            'elevation_uncertainty_rad': self.elevation_uncertainty,
            'velocity_coefficients': self.velocity_coeff,
        }


@register(LOG_GNSS_OEMDRE_SVPOLY_REPORT,
    name="0x14E1",
    description="Full polynomial orbit, iono/SBAS iono/tropo delays, elevation dynamics, velocity coefficients, and SV clock-correction polynomial (ms) per SV; validated on EG18-NA SDX20 V2; other[]=SV clock poly grounded r=-1.0000 vs LG290P geometry",
    version=5,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail="Clean-room RE: the 259-byte SV-poly struct layout is established from GNSS DIAG captures (constellation-derived SV identity check, MEO orbital geometry), not from third-party decoder source, and validated on EG18-NA SDX20 V2. The 'other' 4-float group is the SV clock-correction polynomial in ms, grounded by non-circular pseudorange geometry on an EG25-G MDM9607 with an LG290P survey-grade reference (0x14DE PR − geometric range to the survey fix, SV pos from this record's xyz0+xyzN poly, correlates with other[0] at r=-1.0000, slope exactly -c×1e-3 m/ms, n=2610, post-clock residual 15.7 m RMS) and reproduced on EG18-NA SDX20 V2 for GPS and GLONASS; other[1]=drift ≡ GPS af1; sv_clock_bias_ms is derived. xyz0 and elevation agree with LG290P-referenced geometry (0.000° self-consistency, <1° mean vs co-temporal 0x14DE az/el). No F3 is available for the emitting builds. Payloads shorter than the fixed 259 B struct return None (registry WARN).",
    issues=(),
    primary_issue=None,
    # 43 binary fields per _SVPOLY_FIELDS (5 header + 1 t0 + 3 xyz0 + 9 xyzN
    # + 4 other + 6 corrections + 3 elevation + 12 vel_coeff). All exposed
    # via to_dict() — list-typed fields preserve underlying values (xyz0,
    # xyzN, other, velocity_coefficients). prn/constellation/is_gps/
    # elevation_deg are derived from sv_id/elevation, not counted.
    fields_identified=43,
    fields_parsed=43,
    supported_versions=[0x02],
    # Corpus-wide byte+0 invariant (1,191 records, all
    # version=0x02). Defensive gate against future polynomial-struct
    # drift under a new version byte.
    field_invariants={'version': {'enum': [0x02]}},
)
def parse_0x14e1(log_time: int, data: bytes) -> Diag0x14E1 | None:
    """Parse a LOG_GNSS_OEMDRE_SVPOLY_REPORT (0x14E1) log payload.

    Deep-parses all 43 fields: header (version, sv_id, frequency_index,
    flags, iode), reference time t0, initial ECEF position (xyz0),
    9 position polynomial coefficients (xyzN), 4 'other' SV clock-polynomial
    coefficients, ionospheric + SBAS ionospheric + tropospheric delay,
    elevation + derivative + uncertainty, and 12 velocity polynomial
    coefficients.  Covers EG18-NA SDX20 V2 captures (259-byte records).
    """
    # A payload shorter than the fixed 259 B struct returns None (registry
    # WARN) instead of raising.
    if len(data) < _SVPOLY_SZ:
        return None
    if data[0] != 0x02:
        return None
    d = unpack_dict(_SVPOLY_FMT, _SVPOLY_FIELDS, data)
    return Diag0x14E1(
        log_time=log_time,
        version=d['version'],
        sv_id=d['sv_id'],
        frequency_index=d['frequency_index'],
        flags=d['flags'],
        iode=d['iode'],
        t0=d['t0'],
        xyz0=[d['xyz0_0'], d['xyz0_1'], d['xyz0_2']],
        xyzN=[d[f'xyzN_{i}'] for i in range(9)],
        other=[d[f'other_{i}'] for i in range(4)],
        position_uncertainty=d['position_uncertainty'],
        iono_delay=d['iono_delay'],
        iono_dot=d['iono_dot'],
        sbas_iono_delay=d['sbas_iono_delay'],
        sbas_iono_dot=d['sbas_iono_dot'],
        tropo_delay=d['tropo_delay'],
        elevation=d['elevation'],
        elevation_dot=d['elevation_dot'],
        elevation_uncertainty=d['elevation_uncertainty'],
        velocity_coeff=[d[f'vel_coeff_{i}'] for i in range(12)],
    )
