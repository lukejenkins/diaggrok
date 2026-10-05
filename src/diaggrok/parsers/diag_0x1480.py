"""GLONASS measurement parser (0x1480).

The GLONASS per-SV measurement struct offsets/types are confirmed against a
GNSS DIAG capture corpus (cross-chipset CNR-scale + sv_id-numbering findings
below), not taken from third-party decoder source.

A second SDX20 modem, the Quectel EG12-GT, confirms the per-SV layout in a
4-stream comparison against an LG290P reference receiver: 356 records, all
v=0x00, 100% parse, byte-identical in version to the EG18-NA SDX20 V2.

F3 value-level ground truth:
  The per-SV struct is checked field-by-field against the firmware's own F3
  print ``loc_pd.c:1094`` — ``locPd_dumpSvIn: sig:%d sv_id:%d elev:%d azi:%d
  c_no:%d sv_state:%d FreqNum:%d`` (GLONASS = sig 5) — on an RM520N-GL
  (SDX62) capture with a build-matched message database (resolution 1.0), 840
  co-temporal per-SV pairs, dt ~= 4 ms. Verdicts:
    - sv_id      F3-CONFIRM  — 840/840 in-window, 0 missing. NMEA numbering
                  (65..96) is the on-wire form on this SDX62 part (F3 emits the
                  same 65..85), so the raw-1..24 vs NMEA-65..96 ambiguity is
                  resolved to NMEA here — no +64 remap needed for SDX62.
    - freq_index F3-CONFIRM  — 840/840 exact vs FreqNum (GLONASS slot -7..+6).
    - az_deg     F3-CONFIRM  — median |err| 0.46 deg (F3 truncates to int deg).
    - el_deg     F3-CONFIRM  — median |err| 0.54 deg (F3 truncates to int deg).
    - sv_count   F3-CONFIRM  — 84/84 records equal the distinct-GLONASS SvIn
                  count in-window (also independently == GLO NumMeas at
                  ``gpsfft_spansrchcore.c:1726``).
    - cno_db     F3-CORROBORATE — the 0.01 dB-Hz scale is confirmed EXACT:
                  regression F3_c_no(0.1 dB) = 0.9986*(raw*0.01) + 4.04 dB,
                  R^2 0.988, slope 1.00. The DIAG carrier_noise*0.01 is the
                  measurement-engine C/N0; it runs a fixed ~+4 dB BELOW the
                  position-engine SvIn c_no (a real inter-stage offset, not a
                  scale error) — so the scale stays raw*0.01 and this DIAG
                  field is documented as the ME-stage value.
    - obs_state  correlates with F3 sv_state (tracked 5<->4, idle 1<->1) but the
                  enum values differ; left as a raw code, not remapped.

Log name: LOG_GNSS_GLONASS_MEASUREMENT_REPORT_C
Also seen applied to this code, but belonging to a different log: LOG_GAN_HANDOUT_COMMAND
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from struct import calcsize
from typing import Any

from diaggrok.codes import LOG_GNSS_GLONASS_MEASUREMENT_REPORT
from diaggrok.parsers.gnss_helpers import unpack_dict
from diaggrok.registry import register

# ---------------------------------------------------------------------------
# Struct format strings — corpus-confirmed GLONASS measurement layout
# ---------------------------------------------------------------------------

_GLO_MEAS_HDR_FMT = '<BIBHIffffB'
_GLO_MEAS_HDR_SZ = calcsize(_GLO_MEAS_HDR_FMT)
_GLO_MEAS_HDR_FIELDS = [
    'version', 'f_count', 'glonass_cycle_number', 'glonass_days',
    'milliseconds',
    'time_bias', 'clock_time_unc', 'clock_freq_bias', 'clock_freq_unc',
    'sv_count',
]

_GLO_SV_FMT = '<BbBBBBBHhBHIffffIBIffiHffBI'
_GLO_SV_SZ = calcsize(_GLO_SV_FMT)
# Field name spelling note: an early external reference used 'hemming' but
# the correct spelling is 'hamming' (GLONASS nav message Hamming code decode).
# We use the corrected spelling in the dataclass; the struct field list keeps
# the corrected spelling too since it's only used for dict unpacking.
_GLO_SV_FIELDS = [
    'sv_id', 'frequency_index', 'observation_state',
    'observations', 'good_observations', 'hamming_error_count',
    'filter_stages', 'carrier_noise', 'latency',
    'predetect_interval', 'postdetections',
    'unfiltered_meas_integral', 'unfiltered_meas_fraction',
    'unfiltered_time_unc', 'unfiltered_speed', 'unfiltered_speed_unc',
    'measurement_status', 'misc_status', 'multipath_estimate',
    'azimuth', 'elevation',
    'carrier_phase_integral', 'carrier_phase_fraction',
    'fine_speed', 'fine_speed_unc',
    'cycle_slip_count', 'pad',
]
assert len(_GLO_SV_FIELDS) == 27


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class GloSv:
    """Per-SV GLONASS measurement record (70 bytes on the wire).

    Exposes every field from the 0x1480 SV struct — tracking counts, filter
    state, raw pseudorange (integral + fractional ms), raw/fine Doppler,
    carrier phase (integral + fractional), measurement / misc status bitmasks,
    multipath estimate, and cycle-slip counter.
    """
    sv_id: int
    frequency_index: int        # signed int8; GLONASS frequency slot, -7..+6
    observation_state: int      # uint8; tracking state machine
    observations: int           # uint8; total measurements taken
    good_observations: int      # uint8; measurements accepted by filter
    hamming_error_count: int    # uint8; GLONASS nav-message Hamming decode errors (was typo'd 'hemming_error_count')
    filter_stages: int          # uint8; Kalman filter stage bitmask
    carrier_noise: int          # raw uint16, 0.01 dB-Hz units (see to_dict)
    latency: int                # signed int16; measurement latency (ms)
    predetect_interval: int     # uint8; coherent pre-detection integration
    postdetections: int         # uint16; non-coherent post-detection count
    unfiltered_meas_integral: int  # uint32; raw pseudorange integer ms
    unfiltered_meas_fraction: float  # float32; raw pseudorange fractional ms
    unfiltered_time_unc: float  # float32; pseudorange time uncertainty (ms)
    unfiltered_speed: float     # float32; raw Doppler / speed (m/s)
    unfiltered_speed_unc: float  # float32; raw speed uncertainty (m/s)
    measurement_status: int     # uint32; per-measurement status bitmask
    misc_status: int            # uint8; additional status bits
    multipath_estimate: int     # uint32; multipath error estimate
    azimuth: float              # float32; radians
    elevation: float            # float32; radians
    carrier_phase_integral: int   # signed int32; raw carrier phase integer part
    carrier_phase_fraction: int   # uint16; raw carrier phase fractional part
    fine_speed: float           # float32; filtered speed (m/s)
    fine_speed_unc: float       # float32; filtered speed uncertainty (m/s)
    cycle_slip_count: int       # uint8; carrier phase cycle slip counter
    pad: int                    # uint32; struct alignment padding (typically 0)

    def to_dict(self) -> dict[str, Any]:
        d = {
            'sv_id': self.sv_id,
            'freq_index': self.frequency_index,
            # Position / tracking
            'az_deg': self.azimuth * 180.0 / math.pi,
            'el_deg': self.elevation * 180.0 / math.pi,
            # 0.01 dB-Hz scale F3-CONFIRMED (slope 1.00 vs loc_pd.c:1094 c_no,
            # R^2 0.988); this ME-stage value reads ~4 dB below the PE SvIn
            # c_no (documented inter-stage offset, not an error).
            'cno_db': self.carrier_noise * 0.01,
            # Tracking state
            'obs_state': self.observation_state,
            'obs_total': self.observations,
            'obs_good': self.good_observations,
            'hamming_error_count': self.hamming_error_count,
            'filter_stages': self.filter_stages,
            'latency': self.latency,
            'predetect_interval': self.predetect_interval,
            'postdetections': self.postdetections,
            # Raw measurements (pseudorange + carrier phase)
            'pseudorange_ms_integral': self.unfiltered_meas_integral,
            'pseudorange_ms_fraction': self.unfiltered_meas_fraction,
            'pseudorange_time_unc_ms': self.unfiltered_time_unc,
            'carrier_phase_integral': self.carrier_phase_integral,
            'carrier_phase_fraction': self.carrier_phase_fraction,
            'cycle_slip_count': self.cycle_slip_count,
            # Velocity (raw and filtered)
            'speed_raw_mps': self.unfiltered_speed,
            'speed_raw_unc_mps': self.unfiltered_speed_unc,
            'speed_mps': self.fine_speed,
            'speed_unc_mps': self.fine_speed_unc,
            # Quality / status
            'measurement_status': self.measurement_status,
            'misc_status': self.misc_status,
            'multipath_estimate': self.multipath_estimate,
        }
        # Only surface `pad` if it's nonzero (it should always be 0 on a
        # correctly aligned parse)
        if self.pad:
            d['pad'] = self.pad
        return d


@dataclass
class Diag0x1480:
    log_time: int
    version: int
    f_count: int
    glonass_cycle_number: int
    glonass_days: int
    milliseconds: int
    time_bias: float
    clock_time_unc: float
    clock_freq_bias: float
    clock_freq_unc: float
    sv_count: int                # uint8; raw on-wire per-SV slot count (byte[28])
    svs: list[GloSv] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1480',
            'log_time': self.log_time,
            'version': self.version,
            'f_count': self.f_count,
            'glonass_cycle_number': self.glonass_cycle_number,
            'glonass_days': self.glonass_days,
            'milliseconds': self.milliseconds,
            'time_bias': self.time_bias,
            'clock_time_unc': self.clock_time_unc,
            'clock_freq_bias': self.clock_freq_bias,
            'clock_freq_unc': self.clock_freq_unc,
            # Raw slot count the modem reported this epoch. NOTE this is the
            # on-wire count, which may EXCEED len(svs): the parser drops all-zero
            # filler slots (sv_id==0 && observation_state==0), so the filtered
            # `svs` list alone cannot recover how many slots were on the wire.
            'sv_count': self.sv_count,
            'svs': [sv.to_dict() for sv in self.svs],
        }


# ---------------------------------------------------------------------------
# Hardware validation: GLONASS per-SV az/el/CNo → $GLGSV
# ---------------------------------------------------------------------------
# Sibling of the 0x1477 GPS-L1 check: same $GxGSV correlation design, but
# for the GLONASS constellation. Decoded az/el/CNR match the concurrent
# $GLGSV output and the LG290P `SKY gnssid=6` rows within ~1° az on an
# SDX20 V2 capture (see the parser docstring).

# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

@register(LOG_GNSS_GLONASS_MEASUREMENT_REPORT, domain="gnss",
    name="0x1480",
    description="Per-SV carrier noise, azimuth, elevation with GLONASS frequency slot index; validated on MDM9207, SDX20 V2, SDX55, SDX20 (LM960)",
    version=8,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail="Clean-room: GLONASS measurement struct confirmed from a GNSS DIAG capture corpus — cross-chipset validation against LG290P-referenced EG18-NA SDX20 V2 and FN980m SDX55 captures, not from third-party decoder source. Per-SV sv_id, freq_index, az/el and sv_count F3-confirmed on RM520N-GL SDX62 (loc_pd.c:1094 locPd_dumpSvIn, 840 pairs); cno_db 0.01 dB-Hz scale F3-corroborated (slope 1.00). SDX62 emits sv_id already in NMEA numbering 65-96 (no +64). Header glonass_days/milliseconds/time_bias verified against F3 Glo_MeasBlk on LM960A18 SDX20. Truncated payloads (header < 29 B, or sv_count x 70 B overrunning the record) return None.",
    # Header: version, f_count, glonass_cycle_number, glonass_days,
    # milliseconds, time_bias, clock_time_unc, clock_freq_bias,
    # clock_freq_unc, sv_count (raw on-wire slot count; all 10 header
    # fields surfaced). Body: svs[] (GloSv
    # dataclass — all 27 SV fields decoded). 11 top-level named fields exposed.
    fields_identified=11,
    fields_parsed=11,
    issues=(),
    primary_issue=None,
    supported_versions=[0x00],
    # Corpus-wide byte+0 invariant (73,453 records, all version=0x00).
    # Same defensive gate as
    # the sibling 0x1477 GPS L1 measurement parser.
    field_invariants={'version': {'enum': [0x00]}},
    # WiGLE tagging: GloSv.to_dict() exposes per-SV
    # cno_db + az_deg + el_deg + tracking state — same evidence shape as
    # 0x1477 (GPS L1) and 0x1544 (SV Aggregate), applied here to the
    # GLONASS constellation.
    wigle_direct=True,
    wigle_roles=("gnss-quality",),
    # timebase_roles=("absolute-time", "ts-anchor"): the GLONASS-measurement
    # sibling of the GPS-time codes 0x1477 / 0x1478 / 0x147B. Its header carries
    # a GLONASS time epoch (glonass_cycle_number N4 / glonass_days NT /
    # milliseconds), which is UTC(SU)-referenced (Moscow, UTC+3) with NO
    # leap-second offset — a different codec from the GPS week/TOW fit, with
    # its own conversion: utc = datetime(1996+4*(N4-1),1,1) + (NT-1) days
    # + ms - 3h. Per-code, cross-chipset evidence (single-capture sequential
    # decode + linear fit; the same two captures as the 0x1477 GPS-time tag,
    # which co-emit 0x1480):
    #   * absolute-time — decoded GLONASS time -> UTC matches the capture's own
    #     wall-clock within ~½ min on two chipset generations, and matches the
    #     0x1477 GPS->UTC of the same capture exactly (cross-system check):
    #       RM500Q-AE SDX55 drive capture — 658 valid-fix records,
    #         GLONASS->UTC +21 s after the capture start, monotonic, N4=8.
    #       LM960 SDX20 drive capture — 1246 valid-fix records,
    #         GLONASS->UTC +36 s after the capture start, monotonic, N4=8.
    #     Records failing the cycle/day/ms validity window (no-fix sentinels) are
    #     skipped; the +21/+36 s skew is the drive-start→first-fix gap (identical
    #     to 0x1477's), not clock error.
    #   * ts-anchor — pairing each record's DIAG ts64 (log_time) with its header
    #     GLONASS time is a clean linear map ts64 -> GLONASS wall-clock:
    #       SDX55: R²=1.000000, slope 52428.64 ts64/ms, residual RMS 0.17 ms (n=658)
    #       SDX20: R²=1.000000, slope 52429.19 ts64/ms, residual RMS 2.30 ms (n=1246)
    #     Slope == the chipset-invariant ~52428.8 ts64/ms (the known ts64 rate);
    #     residuals match 0x1477's (0.17/2.31 ms) almost exactly — 0x1480, 0x1477
    #     and 0x1478 are the GLONASS-meas / GPS-meas / clock reports of the same
    #     GNSS-subsystem epoch, stamped off the counter that drives ts64. This
    #     is a metadata/capability tag only.
    timebase_roles=("absolute-time", "ts-anchor"),
)
def parse_0x1480(log_time: int, data: bytes) -> Diag0x1480 | None:
    """Parse a LOG_GNSS_GLONASS_MEASUREMENT_REPORT (0x1480) log payload.

    Cross-chipset validation summary:

    - **MDM9207 (Quectel EG25-G)** — the layout's original reference
      platform; not separately cross-receiver validated.
    - **SDX20 V2 (Quectel EG18-NA)** — 300 records, all 659 bytes (29-byte
      header + 9 × 70-byte SV entries), version field = 0, all parse cleanly.
      Decoded SV az/el/CNR values match the concurrent NMEA ``$GLGSV``
      output and the LG290P ``SKY gnssid=6`` entries within ~1° (azimuth)
      and ~0.5° (elevation) for 564 cross-receiver SV comparisons.
    - **SDX55 (Telit FN980m)** — 322 records, same 659-byte layout, same
      version=0, all parse cleanly. 996 cross-receiver SV comparisons against
      LG290P show azimuth |mean| 1.28°, elevation |mean| 0.58° — comparable
      to the SDX20 V2 numbers.

    The ``version`` field in the header is ``0`` on all three chipset
    generations, indicating this is effectively an unversioned format that
    has remained stable since the MDM9x07 era. The 70-byte SV entry layout
    and 29-byte header layout appear identical across MDM9207, SDX20 V2,
    and SDX55.

    Note on C/N0 scaling: the raw ``carrier_noise`` field is a uint16 in
    **0.01 dB-Hz units** on all three validated chipsets (MDM9207, SDX20 V2,
    SDX55), not 0.1 dB: raw 3630 → 36.3 dB-Hz matches concurrent NMEA
    ``$GLGSV`` SV 70 = 36 dB-Hz. ``cno_db`` carries the 0.01-scaled value.
    MDM9607 has not been cross-validated with this parser; if its scale genuinely differs, add
    a version-gated divisor like ``gnss_oemdre.py`` does for 0x14DE.

    Cross-receiver CNR comparison with LG290P shows a chipset-dependent
    bias of a few dB (|mean| 3.9–4.2 dB) — this is an expected RF
    front-end calibration difference, not a parser bug.
    """
    # A short header or an sv_count x 70 B array that
    # overruns the record returns None (registry WARN) — never a raise, never
    # a record that silently drops the tail SVs.
    if len(data) < _GLO_MEAS_HDR_SZ:
        return None
    if data[0] != 0x00:
        return None
    hdr = unpack_dict(_GLO_MEAS_HDR_FMT, _GLO_MEAS_HDR_FIELDS, data)
    sv_count = hdr['sv_count']
    if _GLO_MEAS_HDR_SZ + sv_count * _GLO_SV_SZ > len(data):
        return None

    svs: list[GloSv] = []
    sv_data = data[_GLO_MEAS_HDR_SZ:]
    for i in range(sv_count):
        off = i * _GLO_SV_SZ
        if off + _GLO_SV_SZ > len(sv_data):
            break
        s = unpack_dict(_GLO_SV_FMT, _GLO_SV_FIELDS, sv_data, off)
        if s['sv_id'] == 0 and s['observation_state'] == 0:
            continue
        svs.append(GloSv(
            sv_id=s['sv_id'],
            frequency_index=s['frequency_index'],
            observation_state=s['observation_state'],
            observations=s['observations'],
            good_observations=s['good_observations'],
            hamming_error_count=s['hamming_error_count'],
            filter_stages=s['filter_stages'],
            carrier_noise=s['carrier_noise'],
            latency=s['latency'],
            predetect_interval=s['predetect_interval'],
            postdetections=s['postdetections'],
            unfiltered_meas_integral=s['unfiltered_meas_integral'],
            unfiltered_meas_fraction=s['unfiltered_meas_fraction'],
            unfiltered_time_unc=s['unfiltered_time_unc'],
            unfiltered_speed=s['unfiltered_speed'],
            unfiltered_speed_unc=s['unfiltered_speed_unc'],
            measurement_status=s['measurement_status'],
            misc_status=s['misc_status'],
            multipath_estimate=s['multipath_estimate'],
            azimuth=s['azimuth'],
            elevation=s['elevation'],
            carrier_phase_integral=s['carrier_phase_integral'],
            carrier_phase_fraction=s['carrier_phase_fraction'],
            fine_speed=s['fine_speed'],
            fine_speed_unc=s['fine_speed_unc'],
            cycle_slip_count=s['cycle_slip_count'],
            pad=s['pad'],
        ))

    return Diag0x1480(
        log_time=log_time,
        version=hdr['version'],
        f_count=hdr['f_count'],
        glonass_cycle_number=hdr['glonass_cycle_number'],
        glonass_days=hdr['glonass_days'],
        milliseconds=hdr['milliseconds'],
        time_bias=hdr['time_bias'],
        clock_time_unc=hdr['clock_time_unc'],
        clock_freq_bias=hdr['clock_freq_bias'],
        clock_freq_unc=hdr['clock_freq_unc'],
        sv_count=sv_count,
        svs=svs,
    )
