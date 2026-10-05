"""0x18F5 - GNSS QZSS/SBAS measurement report, 30B header + N x 71B per-SV blocks, all v=0x00.

GNSS (domain="gnss"), NOT LTE, despite older "LTE measurement" labels. The
canonical name is LOG_GNSS_QZSS_SBAS_MEASUREMENT_REPORT_C: the SDX-generation
firmware's own mc_gnssmeasreport.c emits the symbolic F3 "Log packet
allocation for LOG_GNSS_QZSS_SBAS_MEASUREMENT_REPORT_C failed" (some name
tables carry the non-_C form).

**F3-grounded subsystem identity:** co-temporal F3 (+/-300 ticks per record,
EG18-NA MDM9x55, 248 records) independently confirms the name. The two
highest-density co-temporal files are the firmware's own
`mc_gnssmeasreport.c` (13.2% of its prints fall in the record window) and
`nf_sbas.c` (34.5% - the SBAS navigation filter), plus
`mc_gnsssearchstrategy.c`, `nf_navsolution.c`, `nf_wls.c`, `mgp_gpm.c`,
`mc_receiver.c`. This is a GNSS QZSS/SBAS per-SV measurement report. The
-pi/2 f32 sentinel at block-rel 48 (the GNSS engine's not-computed-angle
value) is consistent with this GNSS-measurement-engine grounding.

Single-version code (v=0x00) across 18,322 records / 100 captures, with
several sizes — but unlike the strict chipset-generation split of
0x1894/0x18E1, here the **same chipset can emit different sizes**: Telit
LM960 + FN980m records appear at both 101B and 172B in the same captures,
because the size encodes the SV count rather than the chipset.

  profile      | records | share | observed on
  -------------+---------+-------+--------------------------------------
  172 / 0x00   | 10,464  | 57.1% | FN980m, LM960 (some), RM500Q,
                                   RM520NGL, EM9190, EM7511 (mixed),
                                   EG18-NA (mixed)
  101 / 0x00   |  6,792  | 37.1% | EM7511, EG18-NA, SIM7600NA, EG12-GT,
                                   LM960 (some), FN980m (carrier-bound)
  243 / 0x00   |     75  |  0.4% | one LM960 drive capture only
  314/385/456  |    32   |   —   | RSU/MDM9150 (Kapsch RIS-9260)
   / 0x00                          N=4/5/6 blocks

Since 71 is prime and the sizes include {101, 172, 243}, the only
header/block split consistent with all of them is a fixed **30-byte header
+ N*71-byte block array** (101=30+71, 172=30+2*71, 243=30+3*71), confirmed
on the committed fixtures (remainder 0 in every case). The Kapsch RIS-9260
RSU corpus extends the ladder to N=4/5/6 — sizes 314/385/456. The RIS-9260
is not a separate device or firmware build: it is an RSU appliance around
the same Wistron/WNC 81UMV91M21 (MDM9150) modem as the 81UMV91M21 bench
captures, so it adds long fielded uptime, not cross-device corroboration.

The f32 at block-relative offset 48 decodes to -pi/2 (-1.5707963) on
every block of every 101/172/243 fixture across MDM9x55 / SDX55 / SDX20 —
a cross-chipset "not-computed angle" default. It is NOT a universal
invariant, though: in the RSU 314/385/456 records the trailing two blocks
carry a LIVE angle (~0.675/0.70 rad), so -pi/2 is the common default, not
a constant. The per-SV decode below names it elevation_rad.

**Per-SV decode + coupled count gate.** 0x18F5 is the legacy 0x1477 GPS
measurement report's layout applied to QZSS / SBAS. The header is the 0x1477
28 B header (``<BIHIffffB``) with two bytes inserted after the version. The
block is the 0x1477 70 B SV struct with ``sv_id`` widened to u16, so every
later field moves +1. That is why the elevation, 0x1477 +47, sits at +48
here, where the -pi/2 sentinel is found.

Header (30 B)::

    [0]      u8   version            0x00 (only on-wire version)
    [1]      u8   hdr_byte1          raw. 6 on every chipset except MDM9207
                                       (EG25-G, SIM7600NA: 4). 0x1CE1's
                                       header[1] is 6 too (== its F3 "Seq")
    [2]      u8   hdr_byte2          raw. A per-build constant on SDX parts
                                       (SDX55 5, SDX62 / SDX65 7, SDX72 9,
                                       MDM9207 70); varies per record on
                                       MDM9x55 / SDX20 / MDM9150 / MDM9250.
                                       Un-grounded
    [3:7]    u32  fcount             F3 "FC"; == 0x1477 f_count
    [7:9]    u16  gps_week           F3 "Wk"
    [9:13]   u32  gps_ms             F3 "Ms"
    [13:17]  f32  clk_bias_ms        F3 "ClkBiasMs"; == 0x1477 time_bias
    [17:21]  f32  clk_tunc           == 0x1477 clock_time_unc. UNIT IS
                                       BUILD-DEPENDENT: ns on MDM9150 (F3 "TMs"
                                       = value * 1e-6 ms, 88 / 88), ms on SDX65
                                       (M3100: 0x1CCx header == F3 "TMs").
                                       SDX55 / SDX20 / MDM9x55 magnitudes
                                       (20..120 with a fix) read as ns
    [21:25]  f32  freq_bias_mps      == 0x1477 clock_freq_bias
    [25:29]  f32  freq_unc_mps       == 0x1477 clock_freq_unc
    [29]     u8   sv_count           F3 "N SVs"; len == 30 + 71 * N

F3 site (MDM9150 Wistron 81UMV91M21): ``mc_gnssmeasreport.c:3355
"QzssSbas_MeasBlk(0) - %d SVs, FC %u, Wk %u, Ms %u, ClkBiasMs %f, TMs %f Src
%d"`` prints this header. FC-joined on one MDM9150 drive capture (88
prints), N, FC, Wk, Ms and ClkBiasMs match 88 / 88 and TMs == clk_tunc * 1e-6
on 88 / 88. The header also equals the co-emitted 0x1477 header of the same
FC field for field (558 / 558 on M3100 SDX65).

Block (71 B), 0x1477 names and units::

    [0:2]    u16  sv_id              SBAS 120..158 / QZSS 193..202
    [2]      u8   observation_state
    [3]      u8   observations
    [4]      u8   good_observations
    [5:7]    u16  parity_error_count  undefined on a QZSS SV that is not yet
                                        tracking (observation_state 1 / 2):
                                        16-bit noise where 0x1CCB has 0
    [7]      u8   filter_stages
    [8:10]   u16  carrier_noise      C/N0, 0.01 dB-Hz
    [10:12]  i16  latency_ms
    [12]     u8   predetect_interval
    [13:15]  u16  postdetections
    [15:19]  u32  meas_integral_ms   SV time, ms of week
    [19:23]  f32  meas_fraction_ms
    [23:27]  f32  time_unc_ms
    [27:31]  f32  speed_mps
    [31:35]  f32  speed_unc_mps
    [35:39]  u32  measurement_status
    [39]     u8   misc_status
    [40:44]  u32  multipath_estimate  (transfer)
    [44:48]  f32  azimuth_rad
    [48:52]  f32  elevation_rad      -pi/2 = direction not computed (the old
                                       ``angle_rad_48``, kept as an alias)
    [52:56]  i32  carrier_phase_integral  (transfer)
    [56:58]  u16  carrier_phase_fraction  (transfer)
    [58:62]  f32  fine_speed_mps
    [62:66]  f32  fine_speed_unc_mps
    [66]     u8   cycle_slip_count
    [67:71]  u32  pad                (transfer)

Value join: 0x18F5 is the legacy twin of **0x1CCB** (the new-format L1
QZSS/SBAS report, 118 B slots). Joined by (FC, sv_id) on an Inseego M3100
(SDX65) capture, every field above not marked "(transfer)" equals the 0x1CCB
slot field on 1,677 / 1,677 SV rows (SBAS 131 / 133, QZSS 195), apart from
parity on the not-tracking QZSS rows. A full corpus walk (322 captures)
repeats it on three chipset generations: 26,726 / 26,726 joined rows on
SDX62 (RM520N-GL, EM9291), SDX65 (M3100) and SDX72 (T99W640); parity 25,735.
The header equals the 0x1477 header on 87,408 / 87,408 FC-joined records
across 21 corpus subtrees (MDM9207 through SDX72). C/N0 differs only in scale
(0x18F5 keeps 0.01 dB-Hz, 0x1CCB 0.1 dB-Hz). Against 0x1CE1 (the L5 report)
only the frequency-independent fields agree: direction and fine speed on
543 / 543. "(transfer)" fields were zero on every joined row and are named
from the 0x1477 struct.

Size: header byte[29] is N, coupled to ``len == 30 + 71 * N``. N ranges
0..13 in the corpus: N 7..13 (527..953 B) on Quectel EG25-G (MDM9207) and
Wistron 81UMV91B1 (MDM9250), and N 0 (30 B) on SIMCom SIM8202G-M2;
header[29] == N on 87,578 / 87,578 on-ladder records. Accepted: N in
_SV_COUNTS (0..13) with the matching length. Any other N or length returns
None (fail loudly). One 493 B record in the corpus (off-stride) is rejected.

Log name: LOG_GNSS_QZSS_SBAS_MEASUREMENT_REPORT_C
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

# --- Validation notes -------------------------------------------------------
# ``block_count`` can be checked against the NMEA QZSS/SBAS satellites-in-view
# count, and ``blocks[].elevation_rad`` (alias ``angle_rad_48``) for the -pi/2
# not-computed sentinel.

_18F5_HEADER_FMT = "<BBBIHIffffB"
_18F5_HEADER_LEN = 30
_18F5_BLOCK_FMT = "<HBBBHBHhBHIffffIBIffiHffBI"
_18F5_BLOCK_LEN = 71
_18F5_SV_COUNT_OFFSET = 29
# Block-relative offset of elevation_rad (the old angle_rad_48).
_18F5_BLOCK_ANGLE_OFF = 48

# Corpus-attested SV counts. Widen only against a real record.
_SV_COUNTS = frozenset(range(0, 14))
_PAYLOAD_SIZES = [_18F5_HEADER_LEN + _18F5_BLOCK_LEN * n for n in sorted(_SV_COUNTS)]


@dataclass
class Gnss18F5Block:
    """One 71-byte per-SV block (layout in the module docstring)."""
    block_index: int
    sv_id: int
    observation_state: int
    observations: int
    good_observations: int
    parity_error_count: int
    filter_stages: int
    carrier_noise: int          # 0.01 dB-Hz
    latency_ms: int
    predetect_interval: int
    postdetections: int
    meas_integral_ms: int
    meas_fraction_ms: float
    time_unc_ms: float
    speed_mps: float
    speed_unc_mps: float
    measurement_status: int
    misc_status: int
    multipath_estimate: int
    azimuth_rad: float
    elevation_rad: float
    carrier_phase_integral: int
    carrier_phase_fraction: int
    fine_speed_mps: float
    fine_speed_unc_mps: float
    cycle_slip_count: int
    pad: int
    raw: bytes                  # full 71B block payload

    @property
    def cno_dbhz(self) -> float:
        return self.carrier_noise / 100.0

    @property
    def angle_rad_48(self) -> float:
        """Old name for ``elevation_rad``."""
        return self.elevation_rad

    def to_dict(self) -> dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items() if k != "raw"}
        d["cno_dbhz"] = self.cno_dbhz
        d["angle_rad_48"] = self.elevation_rad
        d["direction_known"] = not math.isclose(
            self.elevation_rad, -math.pi / 2, rel_tol=1e-6)
        return d


@dataclass
class Diag0x18F5:
    """GNSS QZSS/SBAS measurement report (0x18F5): 30B header + N*71B per-SV blocks, all v=0x00.

    GNSS (domain="gnss") - NOT LTE. Canonical name LOG_GNSS_QZSS_SBAS_MEASUREMENT_REPORT_C.
    """
    log_time: int
    version: int
    variant: str
    hdr_byte1: int
    hdr_byte2: int
    fcount: int
    gps_week: int
    gps_ms: int
    clk_bias_ms: float
    clk_tunc: float          # unit build-dependent (ns MDM9150, ms SDX65)
    freq_bias_mps: float
    freq_unc_mps: float
    sv_count: int
    raw_header: bytes        # 30B header (includes version byte at offset 0)
    block_count: int         # == sv_count (the gate enforces it)
    blocks: list[Gnss18F5Block]
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x18F5',
            'log_time': self.log_time,
            'version': self.version,
            'variant': self.variant,
            'hdr_byte1': self.hdr_byte1,
            'hdr_byte2': self.hdr_byte2,
            'fcount': self.fcount,
            'gps_week': self.gps_week,
            'gps_ms': self.gps_ms,
            'clk_bias_ms': self.clk_bias_ms,
            'clk_tunc': self.clk_tunc,
            'freq_bias_mps': self.freq_bias_mps,
            'freq_unc_mps': self.freq_unc_mps,
            'sv_count': self.sv_count,
            'block_count': self.block_count,
            'payload_size': self.payload_size,
            'blocks': [b.to_dict() for b in self.blocks],
        }


@register(
    0x18F5,
    name="0x18F5",
    domain="gnss",
    description=(
        "GNSS QZSS/SBAS measurement report (0x18F5): 30 B header (0x1477 "
        "header + 2 B; byte[29] = N SVs) + N x 71 B per-SV blocks (0x1477 SV "
        "struct, u16 sv_id), N 0..13, all v=0x00. Header F3-labelled "
        "(mc_gnssmeasreport.c QzssSbas_MeasBlk); blocks value-joined to "
        "0x1CCB"
    ),
    version=4,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Cross-chipset corpus RE: 30 B header + N x 71 B blocks, N 0..13 "
        "(including RSU/MDM9150 N=4..6, EG25-G MDM9207 and 81UMV91B1 MDM9250 "
        "N 7..13, SIM8202G-M2 N 0). Header = 0x1477 header + 2 B, byte[29] = "
        "N; block = 0x1477 SV struct with u16 sv_id. Header == 0x1477 header "
        "on 558/558 FC-joined records and F3 mc_gnssmeasreport.c:3355 "
        "QzssSbas_MeasBlk labels N/FC/Wk/Ms/ClkBiasMs (88/88) and TMs = "
        "clk_tunc*1e-6 (ns on MDM9150); 17 block fields == 0x1CCB slot fields "
        "on 1,677/1,677 (FC, sv_id) rows (M3100 SDX65). Coupled N -> size gate."
    ),

    source_url="",
    fields_identified=37,
    fields_parsed=37,
    issues=(),
    field_invariants={
        "version": {"enum": [0x00]},
        "sv_count": {"range": [min(_SV_COUNTS), max(_SV_COUNTS)]},
        "payload_size": {"enum": _PAYLOAD_SIZES},
    },
)
def parse_0x18f5(log_time: int, data: bytes) -> Diag0x18F5 | None:
    if len(data) < _18F5_HEADER_LEN:
        return None
    if data[0] != 0x00:
        return None
    n_sv = data[_18F5_SV_COUNT_OFFSET]
    if n_sv not in _SV_COUNTS:
        return None
    if len(data) != _18F5_HEADER_LEN + _18F5_BLOCK_LEN * n_sv:
        return None
    (version, hdr_byte1, hdr_byte2, fcount, gps_week, gps_ms, clk_bias,
     clk_tunc, freq_bias, freq_unc, _n) = unpack_from(_18F5_HEADER_FMT, data, 0)
    blocks: list[Gnss18F5Block] = []
    for i in range(n_sv):
        off = _18F5_HEADER_LEN + i * _18F5_BLOCK_LEN
        (sv_id, obs_state, obs, good_obs, parity, filt, cn, latency, predet,
         postdet, meas_int, meas_frac, time_unc, speed, speed_unc, meas_status,
         misc, multipath, az, el, cp_int, cp_frac, fine_speed, fine_speed_unc,
         slips, pad) = unpack_from(_18F5_BLOCK_FMT, data, off)
        blocks.append(Gnss18F5Block(
            block_index=i, sv_id=sv_id, observation_state=obs_state,
            observations=obs, good_observations=good_obs,
            parity_error_count=parity, filter_stages=filt, carrier_noise=cn,
            latency_ms=latency, predetect_interval=predet,
            postdetections=postdet, meas_integral_ms=meas_int,
            meas_fraction_ms=meas_frac, time_unc_ms=time_unc, speed_mps=speed,
            speed_unc_mps=speed_unc, measurement_status=meas_status,
            misc_status=misc, multipath_estimate=multipath, azimuth_rad=az,
            elevation_rad=el, carrier_phase_integral=cp_int,
            carrier_phase_fraction=cp_frac, fine_speed_mps=fine_speed,
            fine_speed_unc_mps=fine_speed_unc, cycle_slip_count=slips, pad=pad,
            raw=bytes(data[off:off + _18F5_BLOCK_LEN]),
        ))
    return Diag0x18F5(
        log_time=log_time,
        version=version,
        variant=f"qzss_sbas_{n_sv}sv_v00",
        hdr_byte1=hdr_byte1,
        hdr_byte2=hdr_byte2,
        fcount=fcount,
        gps_week=gps_week,
        gps_ms=gps_ms,
        clk_bias_ms=clk_bias,
        clk_tunc=clk_tunc,
        freq_bias_mps=freq_bias,
        freq_unc_mps=freq_unc,
        sv_count=n_sv,
        raw_header=bytes(data[:_18F5_HEADER_LEN]),
        block_count=n_sv,
        blocks=blocks,
        payload_size=len(data),
    )
