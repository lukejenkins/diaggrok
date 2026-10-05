"""GNSS Galileo E5a measurement report (0x1C60) - 34B header + N x 71B per-SV slots.

This is a **GNSS measurement** log code, not an NR5G code, despite its
position in the code range. Canonical name
``LOG_GNSS_GAL_E5A_MEASUREMENT_REPORT_C``; the firmware's own debug message
names it (``mc_gnssmeasreport.c``: "Log packet allocation failed for GAL E5a
0x1C60").

F3 grounding (v0x01)
--------------------
The firmware prints this exact measurement block as 0x79 plaintext (self-
decoding - no qdb needed): a header line at ``mc_gnssmeasreport.c:8576``

    E5a Gal_MeasBlk(1Hz) - N SVs,FC ..,Wk ..,Ms ..,ClkBiasMs ..,TMs .. Src .. Seq ..

followed by one row per SV at ``mc_gnssmeasreport.c:5313`` under the column
header (``:8586``) ``SV Status FCount Lat Ms SubMs Speed CNo TuncMs SpeedUnc NxM``.
Joined by FC across four RM500Q-AE (SDX55) captures - a GNSS-reboot edge case,
an all-mask F3 capture and two drive captures - **2,334/2,334 blocks and
5,692/5,692 SV rows match every field named below** (0 misses). The GST
week/ms and clock bias also match the independent ``mc_msg.c`` ``GALClockEst``
print on the RM520N-GL (SDX62, 35/35). Whole corpus: 18,735 records / 95
captures / 9 device families (SDX55, SDX62, SDX65 incl. the Inseego M3100),
every one v=0x01, every one tiling 34 + 71*N exactly.

Header (34 B)::

    [0]      u8   version            = 0x01 (only on-wire version)
    [1]      u8   hdr_byte1          = 0x06 on 18,735/18,735 (constant; possibly
                                       the F3 print's "Seq 6" - CANDIDATE, cannot
                                       be confirmed while constant)
    [2]      u8   hdr_byte2          5 or 7. Not a chipset marker (the SDX55
                                       EM9190 emits both). Raw.
    [3:7]    u32  fcount             == F3 "FC" (receiver ms frame count)
    [7:9]    u16  gst_week           == F3 "Wk" (Galileo week = GPS week - 1024;
                                       a 10-bit-rolled value, e.g. 370, is seen
                                       during warm-restart time settling)
    [9:13]   u32  gst_ms             == F3 "Ms" (Galileo ms-of-week)
    [13:17]  f32  clk_bias_ms_base   } F3 "ClkBiasMs" == base + offset
    [29:33]  f32  clk_bias_ms_offset } (offset is 0.006383 on RM500Q, 0 on SDX62)
    [17:21]  f32  clk_tunc_ns        == F3 "TMs" * 1e6 (time uncertainty, ns)
    [21:25]  f32  freq_bias_mps      CANDIDATE (tracks GALClockEst FreqB loosely)
    [25:29]  f32  freq_unc_mps       CANDIDATE
    [33]     u8   inner_record_count == F3 "N SVs"

Per-SV slot (71 B), values PROPAGATED to the report epoch (FC) - the F3 row
prints the raw measurement at its own FCount, the log carries it moved
forward by Lat::

    [0:2]    u16  sv_id              == F3 "SV" (Galileo 301..336; PRN = sv_id-300)
    [2]      u8   slot_kind          1 = propagated-only (CNo 0, NxM 0x0);
                                       5 / 7 = fresh measurement (CNo populated,
                                       76,831/76,833 slots). Raw enum.
    [3:8]    5 B  raw_3_8            un-grounded
    [8:10]   u16  cno_raw            F3 "CNo" == cno_raw // 10 (F3 column is
                                       0.1 dB-Hz), so C/N0 = cno_raw / 100 dB-Hz
                                       (corpus 3.1..45.6, median 28.7)
    [10:12]  i16  latency_ms         == F3 "Lat" (= FC - measurement FCount;
                                       signed - 728 corpus values are negative)
    [12]     u8   n_coherent         == F3 "NxM" N
    [13]     u8   m_noncoherent      == F3 "NxM" M
    [14]     u8   reserved_14        0 on every corpus slot
    [15:19]  u32  sv_time_ms         == F3 "Ms" + Lat
    [19:23]  f32  sv_time_sub_ms     == F3 "SubMs" - Speed*Lat/c  (time match
                                       |d| < 2e-5 ms on 745/745 rows with
                                       Lat < 3 s; longer gaps drift with accel)
    [23:27]  f32  tunc_ms            == F3 "TuncMs" + (su0*t + 1.5*t^2)/c,
                                       t = Lat s (2,955/2,955, allmask)
    [27:31]  f32  speed_mps          == F3 "Speed" (m/s, |d| < 1)
    [31:35]  f32  speed_unc_mps      == F3 "SpeedUnc" + 1.5*t
    [35:39]  u32  meas_status        == F3 "Status" | 0x00200000 (bit 21 is set
                                       in the log on every row; masked in the
                                       print)
    [39]     u8   status_byte_39     raw
    [40:44]  u32  reserved_40        0 on every corpus slot
    [44:48]  f32  azimuth_rad        on the 360/256 deg grid (all joined rows)
    [48:52]  f32  elevation_rad      == F3 ``mc_msg.c`` "GAL SV Direction: SV n,
                                       elev e" as e*90/128 deg (qsr4; 4,988/4,988)
    [52:71]  19 B tail_raw           zero on slot_kind 1; populated on 5/7
                                       (an f32 @58, f32 @62, u8 @66) - un-grounded

In-capture oracle verdicts: F3 labelled (above). ``0x60`` present (345 frames
on the reboot capture) but silent for this code - only GNSS session/fix-level
events fire, none carries a per-SV E5a quantity. Black-box (qcsuper/SCAT):
not applicable - neither tool decodes GNSS measurement reports.

Log name: LOG_GNSS_GAL_E5A_MEASUREMENT_REPORT_C
Also known as: LOG_GNSS_GAL_E5A_MEASUREMENTS
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

_C60_INNER_RECORD_SIZE = 71
_C60_HEADER_SIZE = 34
_GAL_SVID_BASE = 300  # Galileo gnss_sv_id 301..336 -> PRN 1..36


@dataclass
class Diag0x1C60SvRecord:
    """One 71-byte per-SV Galileo E5a measurement slot (layout in module docstring)."""

    sv_id: int
    slot_kind: int
    raw_3_8: bytes
    cno_raw: int
    latency_ms: int
    n_coherent: int
    m_noncoherent: int
    reserved_14: int
    sv_time_ms: int
    sv_time_sub_ms: float
    tunc_ms: float
    speed_mps: float
    speed_unc_mps: float
    meas_status: int
    status_byte_39: int
    reserved_40: int
    azimuth_rad: float
    elevation_rad: float
    tail_raw: bytes

    @property
    def prn(self) -> int:
        return self.sv_id - _GAL_SVID_BASE

    @property
    def cno_db_hz(self) -> float:
        return self.cno_raw / 100.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "sv_id": self.sv_id,
            "prn": self.prn,
            "slot_kind": self.slot_kind,
            "raw_3_8": self.raw_3_8.hex(),
            "cno_raw": self.cno_raw,
            "cno_db_hz": self.cno_db_hz,
            "latency_ms": self.latency_ms,
            "n_coherent": self.n_coherent,
            "m_noncoherent": self.m_noncoherent,
            "reserved_14": self.reserved_14,
            "sv_time_ms": self.sv_time_ms,
            "sv_time_sub_ms": self.sv_time_sub_ms,
            "tunc_ms": self.tunc_ms,
            "speed_mps": self.speed_mps,
            "speed_unc_mps": self.speed_unc_mps,
            "meas_status": self.meas_status,
            "status_byte_39": self.status_byte_39,
            "reserved_40": self.reserved_40,
            "azimuth_rad": self.azimuth_rad,
            "elevation_rad": self.elevation_rad,
            "tail_raw": self.tail_raw.hex(),
        }


@dataclass
class Diag0x1C60:
    log_time: int
    version: int
    hdr_byte1: int
    hdr_byte2: int
    fcount: int
    gst_week: int
    gst_ms: int
    clk_bias_ms_base: float
    clk_tunc_ns: float
    freq_bias_mps: float
    freq_unc_mps: float
    clk_bias_ms_offset: float
    inner_record_count: int
    inner_records: list[Diag0x1C60SvRecord]
    inner_trailer_raw: bytes
    payload_size: int

    @property
    def clk_bias_ms(self) -> float:
        """F3 "ClkBiasMs" (5 dp) == base + offset on every joined block."""
        return self.clk_bias_ms_base + self.clk_bias_ms_offset

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x1C60",
            "log_time": self.log_time,
            "version": self.version,
            "hdr_byte1": self.hdr_byte1,
            "hdr_byte2": self.hdr_byte2,
            "fcount": self.fcount,
            "gst_week": self.gst_week,
            "gst_ms": self.gst_ms,
            "clk_bias_ms": self.clk_bias_ms,
            "clk_bias_ms_base": self.clk_bias_ms_base,
            "clk_bias_ms_offset": self.clk_bias_ms_offset,
            "clk_tunc_ns": self.clk_tunc_ns,
            "freq_bias_mps": self.freq_bias_mps,
            "freq_unc_mps": self.freq_unc_mps,
            "inner_record_count": self.inner_record_count,
            "inner_records": [r.to_dict() for r in self.inner_records],
            "payload_size": self.payload_size,
        }


def _parse_sv(slot: bytes) -> Diag0x1C60SvRecord:
    return Diag0x1C60SvRecord(
        sv_id=unpack_from("<H", slot, 0)[0],
        slot_kind=slot[2],
        raw_3_8=bytes(slot[3:8]),
        cno_raw=unpack_from("<H", slot, 8)[0],
        latency_ms=unpack_from("<h", slot, 10)[0],
        n_coherent=slot[12],
        m_noncoherent=slot[13],
        reserved_14=slot[14],
        sv_time_ms=unpack_from("<I", slot, 15)[0],
        sv_time_sub_ms=unpack_from("<f", slot, 19)[0],
        tunc_ms=unpack_from("<f", slot, 23)[0],
        speed_mps=unpack_from("<f", slot, 27)[0],
        speed_unc_mps=unpack_from("<f", slot, 31)[0],
        meas_status=unpack_from("<I", slot, 35)[0],
        status_byte_39=slot[39],
        reserved_40=unpack_from("<I", slot, 40)[0],
        azimuth_rad=unpack_from("<f", slot, 44)[0],
        elevation_rad=unpack_from("<f", slot, 48)[0],
        tail_raw=bytes(slot[52:_C60_INNER_RECORD_SIZE]),
    )


@register(
    0x1C60,
    name="0x1C60",
    description=(
        "GNSS Galileo E5a measurement report -- 34B header (FC, GST week/ms, "
        "clock bias/unc) + N x 71B per-SV slots (SV id, C/N0, latency, SV "
        "time, speed, az/el), F3-grounded"
    ),
    version=8,
    author="Claude Code",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Cross-generation RE on RM500Q-AE (SDX55), EM9190 (SDX55) and "
        "RM520N-GL (SDX62) captures. Header and per-SV slot are F3-grounded "
        "v0x01: joined to the firmware's own 'E5a Gal_MeasBlk' header and "
        "per-SV row prints (mc_gnssmeasreport.c:8576/5313, 0x79 plaintext) "
        "on 2,334 blocks / 5,692 rows with 0 misses; elevation checked "
        "against mc_msg.c 'GAL SV Direction', clock against 'GALClockEst' "
        "on SDX62. Truncated payloads (count x 71 B overrunning the record) "
        "return None (registry WARN). Remaining gaps: raw_3_8 and the 19 B "
        "per-SV tail are un-grounded; freq bias/unc are candidates."
    ),
    issues=(),
    fields_identified=34,
    fields_parsed=34,
    field_invariants={
        "version": {"enum": [1]},
    },
)
def parse_0x1c60(log_time: int, data: bytes) -> Diag0x1C60 | None:
    if len(data) < _C60_HEADER_SIZE:
        return None
    version = data[0]
    if version != 1:
        return None
    # Byte 1 is 0x06 on every corpus record (18,735/18,735).
    if data[1] != 0x06:
        return None

    def _f32(off: int) -> float:
        return unpack_from("<f", data, off)[0]

    inner_record_count = data[33]
    # The header's count x 71 B must fit in the payload; a shortfall is a truncated record -> None (registry WARN), not a silent
    # drop of the tail SV slot.
    if _C60_HEADER_SIZE + inner_record_count * _C60_INNER_RECORD_SIZE > len(data):
        return None
    usable = inner_record_count
    inner_records = [
        _parse_sv(
            data[
                _C60_HEADER_SIZE + i * _C60_INNER_RECORD_SIZE:
                _C60_HEADER_SIZE + (i + 1) * _C60_INNER_RECORD_SIZE
            ]
        )
        for i in range(usable)
    ]
    consumed = _C60_HEADER_SIZE + usable * _C60_INNER_RECORD_SIZE

    return Diag0x1C60(
        log_time=log_time,
        version=version,
        hdr_byte1=data[1],
        hdr_byte2=data[2],
        fcount=unpack_from("<I", data, 3)[0],
        gst_week=unpack_from("<H", data, 7)[0],
        gst_ms=unpack_from("<I", data, 9)[0],
        clk_bias_ms_base=_f32(13),
        clk_tunc_ns=_f32(17),
        freq_bias_mps=_f32(21),
        freq_unc_mps=_f32(25),
        clk_bias_ms_offset=_f32(29),
        inner_record_count=inner_record_count,
        inner_records=inner_records,
        inner_trailer_raw=bytes(data[consumed:]),
        payload_size=len(data),
    )
