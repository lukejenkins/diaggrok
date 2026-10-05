"""0x19EB — LOG_GNSS_GPS_L5_MEASUREMENT_REPORT.

A **GNSS GPS L5 per-SV measurement report** carrying one 70B slot per
tracked L5 SV (not an LTE status / measurement list, as older labels
suggested).

The canonical name is LOG_GNSS_GPS_L5_MEASUREMENT_REPORT_C: the
SDX-generation firmware's own mc_gnssmeasreport.c emits the symbolic F3
"Log packet allocation for LOG_GNSS_GPS_L5_MEASUREMENT_REPORT_C failed %d"
(some name tables carry the non-_C form).

=========================================================================
L5 body is the SAME 70B per-SV struct as 0x1477 (L1)
=========================================================================
0x19EB's per-SV slot is **byte-for-byte the same 70-byte struct** as
0x1477's ``GpsSv`` (LOG_GNSS_GPS_MEASUREMENT_REPORT, the L1 twin), preceded
by a 32-byte header. This parser **reuses 0x1477's ``GpsSv``**.

Known-answer control: parse a 0x1477 (L1) record and a 0x19EB (L5) record
from the SAME capture epoch, with the SAME struct. For every PRN tracked on
both frequencies the per-SV fields line up as physics demands — L1 and L5
are two signals from ONE satellite:

  * azimuth / elevation are **byte-identical** per PRN across L1 and L5
    (e.g. at one epoch, ms=393323422: PRN 6 → 156.8° / 46.7° on both;
    PRN 11 → 187.2° / 15.7°; PRN 14 → 98.6° / 36.9°; PRN 20 → 225.9° / 5.7°).
  * ``unfiltered_meas_integral`` (pseudorange integer ms) is **identical**
    per PRN across L1 and L5 (PRN 6 → 393323349 on both) — the L1/L5 range
    to one SV differs only by sub-ms ionospheric delay + inter-frequency
    bias, so the integer-ms part must match.

0x1477's struct is F3-grounded on 14 chipsets (mc_peak.c per-SV C/No,
mc_gnssmeasreport.c GPS-meas-block header), so the L5 field semantics also
inherit that grounding through the shared struct + same-epoch same-PRN
identity; the L5 record is additionally grounded against its own prints
(below).

**Header (32B) — ``<BIHIffffIB``:** 0x1477's 27-byte header prefix
(``version, f_count, gps_week, gps_ms, time_bias, clock_time_unc,
clock_freq_bias, clock_freq_unc``) followed by a 4-byte word
(``l5_reserved``: the f32 L5 group delay in ms, 0 only where L5 is not
tracked — see below) and a 1-byte ``sv_count`` at offset 31.
**version == 0x01** for 0x19EB (0x1477 L1 is version 0x00).

**CN0** lives at struct offset 7-8 (``carrier_noise``, uint16, **×0.01
dB-Hz** — same as 0x1477 L1), NOT at byte[2] (``observations``, a
measurement count that only weakly correlates with CN0). Epoch-aligned vs
LG290P MSM7 1077 GPS-signal-5 truth on one capture (355 (PRN,epoch) pairs):
``carrier_noise*0.01`` gives MAE 8.8 dB / stdev 5.9 (the ~7 dB low bias is
the SAME antenna/gain offset 0x1477 shows on the EG12-GT LG290P compare),
while ``byte[2]/4`` gives stdev 19.95 dB and produces impossible values
(PRN 20 → 60 dB). The ``carrier_noise*0.1`` scale is ruled out (MAE 265 dB).

**Speed:** the struct's ``unfiltered_speed`` (offset 26, raw) and
``fine_speed`` (offset 57, filtered) are **range-rate in m/s**, not Doppler
Hz. (To L5 carrier Hz: ×f_L5/c ≈ ×3.925.) Offset 18 is
``unfiltered_meas_fraction`` — the pseudorange fractional-ms part, in [0,1].

CN0, pseudorange (integral + fraction ms), carrier phase (integral +
fraction), and range-rate are all decoded via the shared struct.

=========================================================================
F3 grounding of v0x01 against its own prints
=========================================================================
v0x01 is the ONLY version fleet-wide (51,382 records, byte0 == 0x01 on
every sidecar: SDX55 RM500Q-AE / FN980 / EM9190 / SIM8202G-M2, SDX62
RM520N-GL / CFW-3212, SDX65 EM9291 / Inseego M3100). The L5 record is
grounded against its OWN firmware prints, on three builds:

* **SDX55 RM500Q-AE (plaintext 0x79, 129/129 records, FC-joined).**
  ``mc_gnssmeasreport.c:8342 'L5 Gps_MeasBlk - N SVs,FC,Wk,Ms,CB,TMs,Src 8
  Seq 5 C 7'`` + one table row per SV (row printer ``:5313``, columns
  ``SV Status FCount Lat Ms SubMs Speed CNo TuncMs SpeedUnc NxM``):
    - header ``sv_count == N SVs`` 129/129 AND ``== number of rows``
      129/129 — so ``sv_count`` IS the L5 report size and every slot past
      it is the stale reserved tail (the ``in_report`` flag below);
    - ``gps_week == Wk``, ``gps_milliseconds == Ms`` 129/129;
    - ``time_bias == CB - 0.00786 ms`` 129/129 — the L1 clock bias minus
      the L5 inter-signal group delay (the firmware prints the same value
      as ``mc_jobmanager.c:4065 'GPS L5_TRK SV_28 GD: 7.860000 us'``);
      the L1 twin 0x1477 carries CB unshifted (CB - time_bias == 0).
      The delay itself is carried in the header word at +27 (``l5_reserved``)
      as an f32: ``time_bias + f32(+27) == CB`` 129/129. Corpus walk: that
      word is non-zero on 15,987 / 27,989 records (0.00786 ms SDX55,
      0.007883 ms M3100) and 0 where CB - time_bias is 0 (SDX62 capture);
    - per-SV (764/764 rows): ``sv_id == SV``, ``latency == Lat``,
      ``unfiltered_meas_integral == Ms``, ``unfiltered_meas_fraction ==
      SubMs`` (6-dp), ``unfiltered_time_unc == TuncMs``,
      ``int(unfiltered_speed) == Speed``, ``int(unfiltered_speed_unc) ==
      SpeedUnc``, ``carrier_noise == CNo*10``, ``predetect_interval x
      postdetections == NxM``; ``measurement_status == Status | 0x200000``
      (bit 21 is set in the log and never in the print — the SAME XOR on
      the L1 0x1477 table, 939/939, so it is not an L5 flag).
    The row ``FCount`` column is per-SV and has no struct field (not
    carried in the log).
* **SDX65 Inseego M3100 (QSR4 0x99, build-matched message database, 212
  records).** ``mc_peak.c:6952 'Gnss:%u,Job:%u,SV:%u,CNo:%u,…'`` — for each
  PRN the firmware runs TWO peak jobs. L5 ``carrier_noise == CNo*10`` of
  **Job 40** on 1,050/1,066 non-zero slots (L1 0x1477 matches Job 17 on 878;
  L1 != L5 C/N0 on 936/939 same-PRN same-FC pairs, so 0x19EB is NOT an L1
  copy). Job 40 = 0x28 is the job-type byte of the firmware's own
  ``'GPS_jobdone_L5_DPO:SV_30,Jobid 0x21e2800'`` (0x02|SV 0x1e|0x28|00),
  so the C/N0 is tied to an F3-labelled L5 job. 0.01 dB-Hz scale confirmed
  on real, non-zero L5 values (SDX55's L5 slots in the F3 capture were all
  acquiring, CNo 0).
* **SDX62 RM520N-GL (QSR4, 108 records).** No L5-GPS table print on this
  build; the shared epoch header (``L1Gps_MBlk`` / ``L5QzSbas_MBlk``) gives
  ``gps_week`` / ``gps_ms`` 108/108.

**``clock_time_unc`` unit is BUILD-dependent, not band-dependent:** on
SDX55 it is ``TMs x 1e6`` (ns) for BOTH 0x19EB and the L1 0x1477 (median
ratio 1.000014e6, 129/129 each); on SDX62 it is ``TMs`` (ms) directly
(0x1477 ratio 1.0000, 117/117). Exposed raw; do not assume a unit.

**Populated predicate.** Across all three builds the report-slot state
partitions cleanly: states 5 and 7 always carry ``carrier_noise > 0`` (a
real L5 measurement; the SDX65 M3100 build reports its L5 DPO measurements
as state 7 — 1,062 of 1,272 report slots), states 0 and 1 always carry 0
(candidate / acquiring). A ``state == 5 and 1<=prn<=32`` test would (a) drop
every M3100 state-7 measurement and (b) walk the stale tail, where garbage
occasionally reads state 5 with an in-range PRN — producing impossible C/N0
values (e.g. PRN 25 ``carrier_noise`` 65313 = 653 dB-Hz in slot 17 of a
``sv_count == 6`` M3100 record, fixture ``gnss_19eb_m3100_sdx65_tailfp.bin``).
``populated`` is therefore ``in_report and carrier_noise > 0 and 1 <= prn <= 32``.

Sources that do NOT label this record:
``sm_api.c 'Allocated MeasBlk System[8] … NumSvs'`` does NOT track
``sv_count`` (FC-joined 63/192 SDX65 M3100, 1/107 SDX62).
``0x60`` events: absent on the SDX55 / SDX65 M3100 captures; present on SDX62
(GPS PD/LM session + fix lifecycle, multipath-env, spectrum analyser) but
silent on every 0x19EB field. QCSuper and SCAT do not decode 0x19EB.
No 0x19EB instance of ``mc_gnssmeasreport.c 'Log packet id|SvCnt'`` exists
in the corpus. CFW-3212: no build-matched message database, so no F3.

Log name: LOG_GNSS_GPS_L5_MEASUREMENT_REPORT_C
"""
from __future__ import annotations

from dataclasses import dataclass, field
import struct
from struct import calcsize
from typing import Any

from diaggrok.parsers.diag_0x1477 import (
    GpsSv,
    _GPS_SV_FIELDS,
    _GPS_SV_FMT,
)
from diaggrok.parsers.gnss_helpers import unpack_dict
from diaggrok.registry import register

# 32-byte L5 header: 0x1477's 27B header prefix (through clock_freq_unc),
# then a 4B word (the f32 L5 group delay), then the 1B L5 report SV count
# (F3-grounded == 'L5 Gps_MeasBlk - N SVs' and == the printed row count,
# SDX55 129/129).
_L5_HDR_FMT = '<BIHIffffIB'
_L5_HDR_SZ = calcsize(_L5_HDR_FMT)
assert _L5_HDR_SZ == 32
_L5_HDR_FIELDS = [
    'version', 'f_count', 'gps_week', 'gps_milliseconds',
    'time_bias', 'clock_time_unc', 'clock_freq_bias', 'clock_freq_unc',
    'l5_reserved', 'sv_count',
]

_SV_SZ = calcsize(_GPS_SV_FMT)
assert _SV_SZ == 70

@dataclass
class Gnss19EBL5Sv:
    """One L5 per-SV measurement slot (70 bytes) inside a 0x19EB record.

    Wraps 0x1477's ``GpsSv`` — the L5 body is the SAME struct as the L1
    (0x1477) per-SV measurement (known-answer control: same-PRN same-epoch
    az/el/pseudorange are byte-identical between L1 and L5).

    ``in_report`` is True for the first ``sv_count`` slots — the SVs the
    firmware's own ``L5 Gps_MeasBlk`` table lists (F3-grounded).
    Slots past ``sv_count`` are a stale reserved tail and never measurements.

    ``populated`` is True for an in-report slot carrying a real L5
    measurement: ``carrier_noise > 0`` and a valid GPS PRN. Within the
    report, observation_state 5 (SDX55/62) and 7 (SDX65 M3100) always carry
    C/N0 and states 0/1 (candidate / acquiring) never do, so the C/N0 test
    is the build-independent form of a ``state == 5`` rule. Such
    slots carry physical CN0 / az / el / pseudorange / carrier-phase /
    range-rate; the rest are exposed with the raw struct but ``None`` for
    the derived measurement dict.
    """
    sv: GpsSv               # the shared 0x1477 GpsSv struct
    populated: bool         # in_report and carrier_noise > 0 and 1 <= prn <= 32
    raw: bytes              # full 70B slot payload
    in_report: bool = True  # slot index < header sv_count

    @property
    def prn(self) -> int:
        return self.sv.sv_id

    @property
    def observation_state(self) -> int:
        return self.sv.observation_state

    @property
    def cn0_db_hz(self) -> float | None:
        # carrier_noise is uint16 in 0.01 dB-Hz units (same scale as 0x1477
        # L1); only meaningful on a locked slot.
        if not self.populated:
            return None
        return self.sv.carrier_noise * 0.01

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'prn': self.prn,
            'observation_state': self.observation_state,
            'in_report': self.in_report,
            'populated': self.populated,
        }
        if self.populated:
            # The full per-SV measurement, via the shared 0x1477 struct:
            # az/el, CN0, pseudorange (integral+fraction ms), carrier phase,
            # raw/fine range-rate (m/s), status bitmasks, cycle-slip, etc.
            d.update(self.sv.to_dict())
            d['prn'] = self.prn  # keep the L5 alias for sv_id
        return d


@dataclass
class Diag0x19EB:
    """LOG_GNSS_GPS_L5_MEASUREMENT_REPORT (0x19EB) — 32B header + N×70B per-SV slots.

    Cleanly framed as ``size = 32 + N * 70``. The per-SV slot is the SAME
    70B struct as 0x1477 (L1); see the module docstring for the
    known-answer control that established this.

    Header decoded as ``<BIHIffffIB`` — 0x1477's 27B header prefix
    (version, f_count, gps_week, gps_milliseconds, time_bias, clock_time_unc,
    clock_freq_bias, clock_freq_unc), then a 4-byte word
    (``l5_reserved`` — an f32 L1→L5 group delay in ms, exposed as
    ``l5_group_delay_ms``), then the
    1-byte ``sv_count``: the L5 report size, F3-grounded against
    ``mc_gnssmeasreport.c 'L5 Gps_MeasBlk - N SVs'`` and its printed row
    count (SDX55, 129/129). Slots past it are a stale reserved tail
    (typically ``entry_count - 20``); ``entries`` still exposes every
    physical slot, flagged ``in_report``, and ``populated`` never fires on
    the tail.

    ``clock_time_unc`` is exposed raw: its unit is build-dependent (ns on
    SDX55, ms on SDX62 — see the module docstring). ``time_bias`` is the L1
    clock bias minus the L5 inter-signal group delay (SDX55: CB − 7.86 µs;
    the delay is ``l5_group_delay_ms``).

    Cross-vendor emission confirmed: SDX55 (RM500Q-AE, FN980, EM9190,
    SIM8202G-M2), SDX62 (RM520N-GL, CFW-3212), SDX65 (EM9291,
    Inseego M3100) all emit ``size = 32 + N*70`` at version 0x01.

    ``version`` (header byte 0) is the discriminator — observed == 0x01
    across all corpus emissions (0x1477 L1 is 0x00); a hard rejection guard
    fails fast on any other value (silent-mis-parse protection).
    """
    log_time: int
    version: int              # [0] — corpus-invariant 0x01 (0x1477 L1 is 0x00)
    f_count: int
    gps_week: int
    gps_milliseconds: int
    time_bias: float
    clock_time_unc: float
    clock_freq_bias: float
    clock_freq_unc: float
    l5_reserved: int          # uint32 @27 raw; as f32 == L5 group delay ms (l5_group_delay_ms)
    sv_count: int             # uint8 @31 — reported-SV-count-shaped field (see docstring)
    raw_header: bytes         # 32B (includes the version byte at offset 0)
    entry_count: int          # derived: (payload_size - 32) // 70
    entries: list[Gnss19EBL5Sv] = field(default_factory=list)
    payload_size: int = 0

    @property
    def l5_group_delay_ms(self) -> float:
        """L1→L5 inter-signal group delay (ms): header word +27 as f32.

        F3-grounded: ``time_bias + l5_group_delay_ms`` equals the
        firmware's ``L5 Gps_MeasBlk`` CB (the L1 clock bias) on 129/129
        SDX55 records, and 7.86 µs is the firmware's own
        ``'GPS L5_TRK … GD: 7.860000 us'`` print. 0.0 where L5 is untracked.
        """
        return struct.unpack('<f', struct.pack('<I', self.l5_reserved))[0]

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x19EB',
            'log_time': self.log_time,
            'version': self.version,
            'f_count': self.f_count,
            'gps_week': self.gps_week,
            'gps_milliseconds': self.gps_milliseconds,
            'time_bias': self.time_bias,
            'clock_time_unc': self.clock_time_unc,
            'clock_freq_bias': self.clock_freq_bias,
            'clock_freq_unc': self.clock_freq_unc,
            'l5_reserved': self.l5_reserved,
            'l5_group_delay_ms': self.l5_group_delay_ms,
            'sv_count': self.sv_count,
            'entry_count': self.entry_count,
            'payload_size': self.payload_size,
            'populated_count': sum(1 for e in self.entries if e.populated),
            'entries': [e.to_dict() for e in self.entries],
        }


# ---------------------------------------------------------------------------
# Validation notes — GPS L5 per-SV CN0 / range-rate
# ---------------------------------------------------------------------------
# The external reference for the L5 per-SV measurements is an LG290P (RTCM3
# MSM7 1077, GPS signalId 23 = L5Q) on a GNSS splitter alongside the modem
# (LG290P + modem NMEA + modem DIAG + AT poll). The modem-side join key is
# the PRN. The known-answer control additionally cross-checks az/el/
# pseudorange against the co-temporal 0x1477 (L1) record for the SAME PRN,
# which must match to sub-ms — a self-contained ground truth needing no
# external receiver.

@register(0x19EB, domain="gnss",
    name="0x19EB",
    description="LOG_GNSS_GPS_L5_MEASUREMENT_REPORT — 32B header + N*70B per-SV slots; per-SV body is the shared 0x1477 GpsSv struct (CN0/az/el/pseudorange/carrier-phase/range-rate)",
    version=8,

    author="Luke Jenkins", author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Canonical name LOG_GNSS_GPS_L5_MEASUREMENT_REPORT_C (firmware "
        "mc_gnssmeasreport.c). The per-SV 70B slot is the SAME struct as 0x1477 "
        "(L1) GpsSv, preceded by a 32B header (<BIHIffffIB, version=0x01 vs "
        "0x1477's 0x00); size = 32 + N*70 on SDX55 (RM500Q-AE, FN980m, EM9190, "
        "SIM8202G-M2), SDX62 (RM520N-GL, CFW-3212) and SDX65 (EM9291, M3100). "
        "Known-answer control: same-epoch same-PRN az/el and pseudorange-"
        "integer-ms are byte-identical between the L1 (0x1477) and L5 "
        "(0x19EB) records. CN0 = carrier_noise (offset 7-8, uint16 x0.01 "
        "dB-Hz) — epoch-aligned vs LG290P MSM7 1077 GPS-signal-5 truth (355 "
        "(PRN,epoch) pairs): MAE 8.8 dB, ~7 dB low bias == the antenna/gain "
        "offset 0x1477 shows on EG12-GT. Speeds at @26/@57 are range-rate "
        "m/s, not Doppler Hz. F3-grounded against its OWN prints: SDX55 "
        "RM500Q-AE mc_gnssmeasreport.c:8342 'L5 Gps_MeasBlk' header + per-SV "
        "table, FC-joined 129/129: sv_count/Wk/Ms exact, time_bias == CB - "
        "7.86 us (L5 group delay, carried as f32 in header word +27 -> "
        "l5_group_delay_ms; time_bias + delay == CB 129/129), and 764/764 rows "
        "exact on PRN, latency, PR integer/fraction ms, time unc, speed, speed "
        "unc, CNo*10, predetect x postdetections, status (|0x200000). SDX65 "
        "Inseego M3100 mc_peak.c CNo of the L5 DPO job (Job 40) == "
        "carrier_noise/10 on 1,050/1,066 non-zero slots (L1 0x1477 matches "
        "Job 17). SDX62 RM520N-GL epoch header Wk/Ms 108/108. sv_count is the "
        "L5 report size; populated is report-scoped and CNo>0 (a state==5 "
        "rule would drop the M3100's state-7 measurements and admit stale-tail "
        "garbage, e.g. 653 dB-Hz)."
    ),
    issues=(),
    primary_issue=None,
    fields_identified=19, fields_parsed=19,
    field_invariants={"version": {"enum": [0x01]}},
    )
def parse_0x19eb(log_time: int, data: bytes) -> Diag0x19EB | None:
    n = len(data)
    if n < _L5_HDR_SZ + _SV_SZ:  # need header + at least one entry
        return None
    if data[0] != 0x01:         # version gate: 0x1477 L1 is 0x00

        return None
    body_len = n - _L5_HDR_SZ
    if body_len % _SV_SZ != 0:
        return None
    entry_count = body_len // _SV_SZ

    hdr = unpack_dict(_L5_HDR_FMT, _L5_HDR_FIELDS, data)
    body = data[_L5_HDR_SZ:]

    entries: list[Gnss19EBL5Sv] = []
    for i in range(entry_count):
        off = i * _SV_SZ
        raw = body[off:off + _SV_SZ]
        sv = GpsSv(**unpack_dict(_GPS_SV_FMT, _GPS_SV_FIELDS, body, off))
        in_report = i < hdr['sv_count']
        populated = (in_report and sv.carrier_noise > 0
                     and 1 <= sv.sv_id <= 32)
        entries.append(Gnss19EBL5Sv(sv=sv, populated=populated, raw=raw,
                                    in_report=in_report))

    return Diag0x19EB(
        log_time=log_time,
        version=hdr['version'],
        f_count=hdr['f_count'],
        gps_week=hdr['gps_week'],
        gps_milliseconds=hdr['gps_milliseconds'],
        time_bias=hdr['time_bias'],
        clock_time_unc=hdr['clock_time_unc'],
        clock_freq_bias=hdr['clock_freq_bias'],
        clock_freq_unc=hdr['clock_freq_unc'],
        l5_reserved=hdr['l5_reserved'],
        sv_count=hdr['sv_count'],
        raw_header=bytes(data[:_L5_HDR_SZ]),
        entry_count=entry_count,
        entries=entries,
        payload_size=n,
    )
