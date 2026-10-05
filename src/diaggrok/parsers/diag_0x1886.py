"""Galileo measurement parser (0x1886).

Reverse-engineered against a Telit FN980m (SDX55) 5-minute capture with a
co-located LG290P reference receiver (23 records × 811 bytes), and against a
Quectel EG25-G (MDM9607) same-antenna LG290P bench.

Log name: LOG_GNSS_GAL_E1_MEASUREMENT_REPORT_C
Also known as: LOG_GNSS_GAL_MEASUREMENT_REPORT_C
Also seen applied to this code, but belonging to a different log: LOG_EVENT_MTP_FORMAT_STORE_DONE
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_GNSS_GAL_MEASUREMENT_REPORT_C
from diaggrok.registry import register


# Validation notes. The rich per-SV decode is the FN980m SDX55 811-byte form
# (gated on flags1=0x02c02006), so the natural validation target is the
# FN980m — NOT the RM520N-GL, whose 811-byte records land in
# 'sdx55_811_unrecognized'. version=0x00 is the DIAG payload version byte
# (field_invariants enum), distinct from the parser-format version.
# Per-SV C/N0 grounds cleanly against the Galileo GSV NMEA sentence; per-SV
# Doppler has no standard NMEA/AT reference and stays the weakest field.

# ---------------------------------------------------------------------------
# Known record layouts
# ---------------------------------------------------------------------------
#
# **SDX55 "full" format — 811 bytes** (FN980m corpus):
#
#     Bytes 0..29     fixed header (30 bytes) — version, const flags, system tick
#     Bytes 30..100   "anchor" block (71 bytes, same size as an SV slot but
#                     different layout; not yet RE'd — contains reference
#                     measurement or global clock state)
#     Bytes 101..810  10 × 71-byte SV slots
#
# **Per-SV 71-byte slot layout** (all offsets relative to slot start):
#
#     [0]       u8    sv_id_raw  — raw satellite ID.  PRN = sv_id_raw − 49
#                                  (raw 50..85 maps to PRN 1..36)
#     [1:3]     u16   const_0x0101 — constant `0x01 0x01` on every slot;
#                                    likely a status/version marker
#     [3:10]    zero-filled padding (7 bytes)
#     [10:12]   u16   status_counter — 0x01ee (494) on most SVs, occasionally
#                                      0x275c / 0x2cab on the tail slots.
#                                      Possibly a parity/health counter.
#     [12:15]   3 bytes (unknown; low byte varies per slot)
#     [15:19]   u32   gps_tow_ms_tick — local milliseconds-of-week-ish counter,
#                                       varies ±20 ms across SVs within a
#                                       single report (per-SV measurement epoch)
#     [19:23]   f32   float_a — varies per SV, small (0.05..0.83 rad range).
#                               Plausible interpretations: elevation in
#                               radians, or carrier-phase fractional part.
#                               Not yet validated against NMEA ground truth.
#     [23:27]   f32   float_b — **nearly constant within a capture window**
#                               (0.2932 for PRN 1..18, 0.0137/0.0139 for PRN
#                               22/31 — groups of SVs share the value).
#                               Likely a per-frequency-band or per-signal
#                               shared constant, not a per-SV measurement.
#     [27:31]   f32   float_c — wide range (−486..+458), plausibly Doppler
#                               or line-of-sight velocity in m/s.
#     [31:35]   f32   float_d — narrow range (15.5..22.2) — plausibly
#                               **C/N0 in dB-Hz**.  Consistent with weak
#                               Galileo reception on the FN980m (Galileo
#                               tracked but not used in fix) and in the
#                               valid dB-Hz range.
#     [35]      u8    misc_status_byte — 0x17 observed; possibly per-SV
#                                        tracking/status byte (not yet
#                                        cross-checked across records).
#     [36:40]   u32   flags1 — constant `0x02c02006` across all 230 SV slots
#                              in the 23-sample corpus.  Likely reserved or
#                              firmware-build-specific status bitfield.
#     [40:44]   zeros (u32) — reserved
#     [44:48]   f32   float_e — varies per SV (populated slots: 0..10 range);
#                               zero on unused slots.  Unknown semantics.
#     [48:52]   f32   float_f — varies per SV (0.2..0.97 range on populated
#                               slots, zero on unused).  Unknown semantics.
#     [52:71]   19 bytes zero-filled tail (padding)
#
# **30-byte "indoor/degraded" format** (emitted when no Galileo SVs are
# tracked):
#
#     [0]      u8    version (0)
#     [1]      u8    sv_count placeholder (observed always 6, not trustworthy)
#     [2]      u8    sub_version (observed always 5)
#     [3:5]    u16   field_a
#     [5:7]    u16   system_time
#     [12:16]  f32   float_1
#     [17:21]  f32   float_2
#     [21:25]  f32   float_3
#     [-1]     u8    trailing byte = header [29] slot count N (0 here)
#
# The 30-byte and 811-byte paths are both handled below for compatibility
# with existing 30-byte-only captures.  The 811-byte path is the one that
# actually produces SV data.

# Record grammar shared by every attested form: a 30-byte header whose
# LAST byte [29] declares the slot count N, then N x 71-byte slots — size ==
# 30 + N*71 on all 15 corpus sizes (30..1166 B); the FN980m 811 B form counts
# its anchor block as one of its N=11 slots. A payload shorter than the header
# or than 30 + N*71 is truncated and returns None (registry WARN).
_HDR_SIZE = 30
_HDR_SLOT_COUNT_OFF = 29
_SLOT_SIZE = 71

_SDX55_FULL_SIZE = 811
_SDX55_HDR_SIZE = 101
_SDX55_SV_SIZE = 71
_SDX55_N_SLOTS = 10

# PRN offset applied to the raw sv_id byte at SV slot offset 0.  Validated
# empirically on the FN980m corpus: PRNs 1, 4, 5, 6, 7, 14, 16, 18, 22, 31
# (raw 50, 53, 54, 55, 56, 63, 65, 67, 71, 80) are consistently the 10
# Galileo SVs tracked at the capture location.
_SV_ID_OFFSET = 49

# Per-slot ``flags1`` magic that identifies the FN980m-validated 811-byte slot
# layout.  The *same* 811-byte size, header (b1,b2)=(6,5), is emitted with at
# least three distinct per-slot ``flags1`` values — ``0x02c02006`` (FN980m,
# validated against LG290P ground truth), ``0x02c82000``, and ``0x02002006`` —
# each a different, unvalidated slot layout.  Only the ``0x02c02006`` layout
# has its 71-byte slot offsets confirmed, so SV decode is gated on this
# signature (see ``parse_0x1886``).
_FN980M_SLOT_FLAGS1 = 0x02c02006

# ---------------------------------------------------------------------------
# MDM9607 variable-length variant (EG25-G), solved against an EG25-G ×
# LG290P same-antenna bench.
# ---------------------------------------------------------------------------
# The MDM9607 EG25-G emits 0x1886 records with header
# ``(header_b1, header_b2) = (4, 0x46)`` — a DIFFERENT struct from the FN980m
# SDX55 ``(6, 5)`` / ``flags1=0x02c02006`` layout (same 811 bytes at N=11,
# different layout: size invariance is not format invariance).  The FN980m
# slot offsets do not apply.  This variant's layout was solved against the
# co-temporal 0x14DE Galileo report from the same 4-stream capture:
#
#   header  : 30 bytes.  [0]=version(0) [1]=b1(4) [2]=b2(0x46);
#             u32 @ [3] = f_count / system-RTC tick (ms) — matches the
#             co-temporal 0x14DE ``f_count`` exactly, 1 Hz (+1000/record).
#   slots   : N × 71-byte SV slots starting at offset 30 (30 + 11*71 = 811).
#   per slot: [0]  u8   sv_id_raw — PRN = sv_id_raw − 44.  Validated 290/290
#                       records against the co-temporal 0x14DE Galileo PRN set
#                       {3,5,6,9,15,16,25,31,32,34,36} → raw {47,49,50,53,59,
#                       60,69,75,76,78,80}; the raw=PRN+44 map is EXACT for all
#                       11 PRNs (wide baseline PRN 3..36).
#             [8]  u16  cno_raw — C/N0 in 0.01 dB-Hz (same raw scale + units as
#                       0x14DE ``carrier_noise``).  BIT-EXACT vs the
#                       co-temporal 0x14DE Galileo C/N0 (12,593 samples).
#                       0 for the three no-signal (C/N0=0) SVs.  Byte [9] is
#                       the high byte of this u16 (2.56 dB-Hz per count), not
#                       a separate quality index.
#             [31] f32  measurement_unc — inverse of C/N0 (r=−0.971): ~0.37..1.5
#                       on locked SVs, ~15..16 on the three no-signal SVs.  A
#                       measurement sigma / noise metric.
#             [44] f32  azimuth_rad — SV azimuth (radians, 0..2π).  BIT-EXACT vs
#                       0x14DE ``azimuth`` (slope 1.0, intercept 0, max|resid| 0;
#                       12,593 samples / 7 PRNs).  Populated even for
#                       tracked-but-no-signal SVs (az/el are geometric).
#             [48] f32  elevation_rad — SV elevation (radians, 0..π/2).  BIT-EXACT
#                       vs 0x14DE ``elevation`` (slope 1.0, intercept 0,
#                       max|resid| 0; 12,593 samples).
#             These az/el/C-No identities are cross-log-code (both are the same
#             GNSS engine's self-report for the same SV/epoch) — they name the
#             field with certainty but share a source; an independent LG290P
#             GSV az/el check has not been done.
#
# The record is VARIABLE-LENGTH — 30-byte header + N × 71-byte SV slots, N =
# tracked Galileo SV count (size = 30 + N*71).  A static-sky bench stayed at
# N=11 (811 B); a same-rig changing-geometry capture (gnssconfig=1, 13 Galileo
# SVs → 953 B, N=13) reproduced the raw=PRN+44 map against the live 0x14DE
# Galileo set {4,6,9,10,11,12,19,21,23,27,28,29,36} — 13/13 exact.  Slot
# decode is gated on the (4, 0x46) header AND ``size == 30 + N*71`` AND
# per-slot PRN validity, so out-of-range slot bytes get prn=None rather than
# a fabricated PRN and a non-rung size never enters the decoder.
_MDM9607_HDR_SIZE = 30
_MDM9607_SV_SIZE = 71
_MDM9607_N_SLOTS = 11   # the static-sky rung; N is computed per record
_MDM9607_SV_ID_OFFSET = 44
_MDM9607_HDR_B1 = 4
_MDM9607_HDR_B2 = 0x46


def _mdm9607_prn_from_raw(raw: int) -> int | None:
    """Map an MDM9607 slot sv_id byte to Galileo PRN, or None if out of range."""
    if 45 <= raw <= 85:  # Galileo PRN 1..41 → raw 45..85 (valid PRNs are 1..36)
        return raw - _MDM9607_SV_ID_OFFSET
    return None


def _mdm9607_slot_count(size: int) -> int | None:
    """Slot count N for an MDM9607 0x1886 record, or None if size isn't a rung.

    The MDM9607 (EG25-G) form is VARIABLE-LENGTH: a 30-byte header followed by
    N × 71-byte SV slots, where N is the number of tracked Galileo SVs — i.e.
    ``size == 30 + N*71``. A static-sky bench always tracked 11 SVs (811 B); a
    changing-geometry capture (gnssconfig=1, 13 Galileo SVs → 953 B) shows the
    record is SV-count-scaled, with raw-44 reproducing the live 0x14DE Galileo
    set 13/13.
    """
    body = size - _MDM9607_HDR_SIZE
    if body < _MDM9607_SV_SIZE or body % _MDM9607_SV_SIZE != 0:
        return None
    return body // _MDM9607_SV_SIZE


def _prn_from_raw(raw: int) -> int | None:
    """Map raw sv_id byte to Galileo PRN, or None if out of range."""
    if 50 <= raw <= 85:  # conservative; valid Galileo PRNs are 1..36 → raw 50..85
        return raw - _SV_ID_OFFSET
    return None


@dataclass
class GalileoSv:
    """Per-SV Galileo E1 measurement slot (71 bytes on the wire).

    Field semantics are partially RE'd — sv_id and the per-SV tick offset
    are identified with high confidence, the four float fields are named
    by empirical value range but have not been cross-validated against
    ground-truth azimuth/elevation/CNR.  ``raw`` preserves the full 71-byte
    slot for future RE work.
    """
    sv_id_raw: int         # raw byte at slot offset 0
    prn: int | None        # PRN = raw − 49, or None if raw is out of range
    status_counter: int    # u16 at offset 10 (0x01ee typical)
    gps_tow_tick: int      # u32 at offset 15 — per-SV measurement tick
    float_a: float         # f32 at 19 — per-SV varying (small, <1.0)
    float_b: float         # f32 at 23 — near-constant within per-signal group
    float_c: float         # f32 at 27 — wide range, plausibly Doppler m/s
    float_d: float         # f32 at 31 — narrow range, plausibly C/N0 dB-Hz
    misc_status_byte: int  # u8 at 35 — 0x17 observed; per-SV status
    flags1: int            # u32 at 36 — constant 0x02c02006 in validated corpus
    float_e: float         # f32 at 44 — per-SV varying
    float_f: float         # f32 at 48 — per-SV varying
    raw: bytes             # full 71-byte slot for downstream RE

    def to_dict(self) -> dict[str, Any]:
        return {
            'sv_id_raw': self.sv_id_raw,
            'prn': self.prn,
            'status_counter': self.status_counter,
            'gps_tow_tick': self.gps_tow_tick,
            'float_a': self.float_a,
            'float_b': self.float_b,
            'float_c_possibly_doppler_mps': self.float_c,
            'float_d_possibly_cno_db': self.float_d,
            'misc_status_byte': self.misc_status_byte,
            'flags1': self.flags1,
            'float_e': self.float_e,
            'float_f': self.float_f,
        }


@dataclass
class Mdm9607GalSv:
    """Per-SV Galileo slot for the MDM9607 variable-length variant (71 bytes).

    Five fields are ground-truth-validated against the co-temporal 0x14DE
    Galileo report from an EG25-G × LG290P bench; the full 71-byte slot is
    retained in ``raw`` for future RE of the remaining bytes.

    ``cno_raw`` / ``azimuth_rad`` / ``elevation_rad`` were pinned on a 30-min
    changing-geometry capture: each is a **bit-exact** copy of the same-epoch
    0x14DE Galileo field, joined by ``f_count`` over 12,593 (epoch, PRN)
    samples across 7 PRNs — slope 1.0, intercept 0, max|residual| 0.  (Both
    logs are the same engine's self-report, so this proves the FIELD
    identity; an independent LG290P/GSV az/el cross-check has not been done.)
    """
    sv_id_raw: int              # u8 @ slot+0
    prn: int | None             # PRN = sv_id_raw − 44, or None if out of range
    cno_raw: int                # u16 @ slot+8 — C/N0 in 0.01 dB-Hz (0 = no signal)
    measurement_unc: float      # f32 @ slot+31 — sigma; small locked / ~15 unlocked
    azimuth_rad: float          # f32 @ slot+44 — SV azimuth, radians (0..2π)
    elevation_rad: float        # f32 @ slot+48 — SV elevation, radians (0..π/2)
    raw: bytes                  # full 71-byte slot for downstream RE

    @property
    def cno_db_hz(self) -> float:
        """C/N0 in dB-Hz (``cno_raw`` × 0.01; same 0.01 dB-Hz scale as 0x14DE)."""
        return self.cno_raw * 0.01

    def to_dict(self) -> dict[str, Any]:
        return {
            'sv_id_raw': self.sv_id_raw,
            'prn': self.prn,
            'cno_raw': self.cno_raw,
            'cno_db_hz': self.cno_db_hz,
            'measurement_unc': self.measurement_unc,
            'azimuth_rad': self.azimuth_rad,
            'elevation_rad': self.elevation_rad,
        }


def _parse_mdm9607_sv_slot(data: bytes, offset: int) -> Mdm9607GalSv:
    sv_id_raw = data[offset]
    return Mdm9607GalSv(
        sv_id_raw=sv_id_raw,
        prn=_mdm9607_prn_from_raw(sv_id_raw),
        cno_raw=unpack_from('<H', data, offset + 8)[0],
        measurement_unc=unpack_from('<f', data, offset + 31)[0],
        azimuth_rad=unpack_from('<f', data, offset + 44)[0],
        elevation_rad=unpack_from('<f', data, offset + 48)[0],
        raw=bytes(data[offset:offset + _MDM9607_SV_SIZE]),
    )


def _parse_sv_slot(data: bytes, offset: int) -> GalileoSv:
    sv_id_raw = data[offset]
    return GalileoSv(
        sv_id_raw=sv_id_raw,
        prn=_prn_from_raw(sv_id_raw),
        status_counter=unpack_from('<H', data, offset + 10)[0],
        gps_tow_tick=unpack_from('<I', data, offset + 15)[0],
        float_a=unpack_from('<f', data, offset + 19)[0],
        float_b=unpack_from('<f', data, offset + 23)[0],
        float_c=unpack_from('<f', data, offset + 27)[0],
        float_d=unpack_from('<f', data, offset + 31)[0],
        misc_status_byte=data[offset + 35],
        flags1=unpack_from('<I', data, offset + 36)[0],
        float_e=unpack_from('<f', data, offset + 44)[0],
        float_f=unpack_from('<f', data, offset + 48)[0],
        raw=bytes(data[offset:offset + _SDX55_SV_SIZE]),
    )


@dataclass
class Diag0x1886:
    """Galileo E1 GNSS measurement report (0x1886).

    The canonical name is ``LOG_GNSS_GAL_E1_MEASUREMENT_REPORT_C``, taken from
    the firmware's own F3 message (``mc_gnssmeasreport.c``: ``Log packet
    allocation failed for GAL E1 0x1886``).  Some name tables bind the generic
    ``LOG_GNSS_GAL_MEASUREMENT_REPORT`` name to this code, but the firmware
    carries the generic ``LOG_GNSS_GAL_MEASUREMENT_REPORT_C`` symbol
    separately (a distinct, currently-unbound log packet), so 0x1886 is
    specifically the **E1** band, not the generic Galileo report.  The trailing
    ``_C`` is the standard log-code enum-constant suffix (every ``LOG_*``
    code has it) - NOT a "Compact"-variant marker.  The rich variable-extension
    size distribution below is per-SV slot count, not a format variant.

    **Size ladder** (17,403 records across 83 captures): 15 distinct payload
    sizes — ``30 / 101 / 172 / 243 / 314 / 456 / 527 / 598 / 669 / 740 / 811 /
    882 / 953 / 1024 / 1166 B``.  The 71-byte arithmetic progression is a
    fixed 30-byte header + N × 71-byte slots, where the 30 B form is the
    no-SV bottom of the ladder.

    Three formats are decoded, all at version byte 0:

    - **811-byte SDX55 rung** — Telit FN980m SDX55, header ``(b1,b2)=(6,5)`` +
      per-slot ``flags1=0x02c02006``.  30-byte fixed header + 71-byte anchor
      block + 10 × 71-byte SV slots.  All 10 SV slots populated; 10 Galileo
      PRNs tracked: 1, 4, 5, 6, 7, 14, 16, 18, 22, 31.  Decoded into the
      ``svs`` list (``sdx55_full_811``).
    - **MDM9607 variable-length variant** — Quectel EG25-G (MDM9607), header
      ``(b1,b2)=(4,0x46)``.  A DIFFERENT struct from the FN980m form: 30-byte
      header + **N × 71-byte SV slots** (no anchor block), N = tracked Galileo
      SV count, so ``size == 30 + N*71`` (811 B at N=11, 953 B at N=13, …).
      Per slot: sv_id_raw @0 (PRN=raw−44), C/N0 @8, measurement uncertainty
      @31, azimuth @44, elevation @48.  Validated against the co-temporal
      0x14DE Galileo report (290/290 at N=11, 13/13 at N=13).  Label
      ``mdm9607_gal``.  See the constants block above for the layout.
    - **30-byte rung** — indoor SDX55 captures (73 samples, no SVs
      populated).  Only the 30-byte header is present; the
      ``float_legacy_*`` fields decode this form.

    The other size rungs (101…1166 B) decode to ``parser_format='unknown'``
    — they are real records, just unmapped.

    **The 811 B FN980m slot layout does not extend to the intermediate
    rungs.**  Decoding each ``101 + N×71`` rung of the (header_b1, header_b2)
    = (6, 5) captures with the FN980m 71-byte slot offsets and checking the
    per-slot invariants (``flags1 == 0x02c02006``, ``sv_id_raw ∈ 50..85``)
    shows no shared layout — even at the validated 811 B size only ~20 % of
    (6, 5) records carry the FN980m ``flags1`` signature; the rest have
    ``flags1 = 0x02c82000`` and out-of-range sv_id bytes (PRN 0 / −1).  The
    ``flags1`` constant itself takes ≥3 values across rungs (``0x02c02006`` /
    ``0x02c82000`` / ``0x02002006``), so the real layout discriminator is
    finer than (size, b1, b2) — most likely a GNSS-ME firmware sub-format
    keyed by ``flags1`` (or a header sub-version byte), NOT the payload
    size.  Extending the parser per-rung on size alone would emit
    plausible-but-garbage measurements; a correct multi-rung decoder must
    first establish per-``flags1`` layout ground truth.

    **Structural non-invariants** (17,403-record corpus):

    - Byte 12 is **not** an SDX55-vs-SDX20 platform discriminator.  It takes
      **18 distinct values** across the corpus (0x00 at 27 %, 0x01 at 16 %,
      0x17 at 15 %, then a long tail of 0x10/0x1b/0x08/0x05/...) — most
      likely an intra-capture variant tag, not a chipset marker.
    - The 4-byte sequence ``5a 0f 2f 5e`` at offsets 17–20 is **not** an
      SDX55-class invariant.  Byte 17 = 0x5a is just the most-common single
      value (26.9 %), with 100+ other byte values present.  Holds only for
      the SDX55 30 B subset.
    - The 5-byte sequence ``bc 5a 0f 2f 5e`` at offsets 16–20 is not a
      sentinel either: byte 16 has 19 distinct values.

    **Field names are deliberately kept stable.**  On a single SDX55 EM9190
    capture ``float_legacy_2`` looks like a ``format_magic`` constant, but
    that holds only for SDX55-class chipsets; on SDX20 ``float_legacy_2`` is
    a real f32 measurement, so the field is not renamed.

    For the full (811 B) format, ``svs`` is a 10-element list of
    :class:`GalileoSv`; for the 30 B form ``svs`` is empty.
    """
    log_time: int
    version: int
    payload_size: int
    header_b1: int       # const 6 on validated corpus
    header_b2: int       # const 5 on validated corpus
    # Legacy 30-byte-format fields (kept for backward compat with the old
    # 73-sample SDX55 indoor corpus).  ``None`` on 811-byte records.
    field_a_u16: int | None = None
    system_time_u16: int | None = None
    float_legacy_1: float | None = None
    float_legacy_2: float | None = None
    float_legacy_3: float | None = None
    # Full-format fields
    header_raw: bytes = b''   # 101 bytes of header + anchor block (full format)
    svs: list[GalileoSv | Mdm9607GalSv] = field(default_factory=list)
    # Header u32 @3 = GNSS FCount (ms) and u32 @9 = GPS ms-of-week, on EVERY form
    # (F3-grounded: equal, <= 1 ms, to nf_navsolution.c "UpdEnvDetector:
    # [Fcount=%lu, GpsMsec=%lu" arg0/arg1 and gile_proc.c "… GpsMsec %u" arg0;
    # control 0). f_count also matches 0x14DE on the MDM9607 form.
    f_count: int | None = None
    gps_msec: int | None = None
    raw_hex: str = ''         # full payload hex for future RE
    parser_format: str = 'unknown'  # 'sdx55_full_811' | 'sdx55_811_unrecognized' | 'mdm9607_gal' | 'mdm9607_gal_unrecognized' | 'legacy_30' | 'unknown'

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'type': 'Diag0x1886',
            'log_time': self.log_time,
            'version': self.version,
            'payload_size': self.payload_size,
            'header_b1': self.header_b1,
            'header_b2': self.header_b2,
            'parser_format': self.parser_format,
        }
        if self.field_a_u16 is not None:
            d['field_a'] = self.field_a_u16
        if self.system_time_u16 is not None:
            d['system_time'] = self.system_time_u16
        if self.float_legacy_1 is not None:
            d['float_legacy_1'] = self.float_legacy_1
            d['float_legacy_2'] = self.float_legacy_2
            d['float_legacy_3'] = self.float_legacy_3
        if self.f_count is not None:
            d['f_count'] = self.f_count
        if self.gps_msec is not None:
            d['gps_msec'] = self.gps_msec
        if self.svs:
            d['sv_count'] = len(self.svs)
            d['svs'] = [sv.to_dict() for sv in self.svs]
        return d


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

@register(LOG_GNSS_GAL_MEASUREMENT_REPORT_C, domain="gnss",
    name="0x1886",
    issues=(),
    description="Galileo E1/L1 measurement report: SDX55 full 811-byte format with 10 SV slots (gated on the FN980m flags1=0x02c02006 slot signature; other 811-byte slot layouts land in 'sdx55_811_unrecognized' instead of a garbage SV decode), the MDM9607 (EG25-G) variable-length variant 'mdm9607_gal' (header b1=4/b2=0x46, 30-byte header + N×71-byte slots, PRN=raw-44, C/N0 u16 in 0.01 dB-Hz, measurement uncertainty, azimuth/elevation bit-exact vs the co-temporal 0x14DE Galileo report; failed-layout (4,0x46) records land in 'mdm9607_gal_unrecognized'), and the legacy 30-byte indoor format.",
    version=9,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail="Reverse-engineered from a Telit FN980m SDX55 5-minute capture with an LG290P reference receiver (23 × 811-byte records, 10 Galileo SVs tracked), an EG25-G (MDM9607) × LG290P same-antenna bench (MDM9607 slot layout validated 290/290 at N=11 and 13/13 at N=13 against the co-temporal 0x14DE Galileo report; azimuth/elevation/C/N0 bit-exact over 12,593 samples), and a 73-sample indoor SDX55 corpus for the 30-byte form. F3-grounded: header u32 @3 = GNSS FCount and u32 @9 = GPS ms-of-week on every form (equal, <=1 ms, to nf_navsolution.c UpdEnvDetector Fcount/GpsMsec and gile_proc.c GpsMsec; +500 ms control ~0). Header byte [29] is the slot count N (size == 30 + N*71 on every attested size); a payload shorter than the 30-byte header or than 30 + N*71 returns None (registry WARN). Gaps: the FN980m anchor block, per-SV bytes 12-15, and the intermediate size rungs.",
    source_url="https://github.com/lukejenkins",
    # 30-byte header: 3 documented binary fields (version, header_b1@1,
    # header_b2@2), all parsed. SDX55 full 811-byte format adds:
    #   - 71-byte anchor block at [30..100] — 1 identified region, unparsed
    #   - per-SV (×10): 11 binary fields parsed (sv_id_raw, status_counter,
    #     gps_tow_tick, float_a..d, misc_status_byte, flags1, float_e/f) +
    #     1 unparsed 3-byte region at slot+[12..15] (semantic TBD)
    # Legacy 30-byte form adds 5 fields (field_a, system_time, float_legacy_1..3)
    # all parsed. Net for full SDX55 path: 3 + 12 (SV: 11 parsed + 1 region)
    # + 1 (anchor block) = 16 identified, 3 + 11 = 14 parsed. Partial tier
    # — anchor block + per-SV bytes 12-15 region remain. The 13 intermediate
    # payload-size rungs (101..1166 B) are unparsed at the record-format
    # level and counted separately by the inventory.
    # MDM9607 variant grounded fields: header f_count (@3) + per-SV sv_id_raw/prn,
    # cno_raw (u16 @8, 0.01 dB-Hz), measurement_unc (@31), azimuth_rad (f32 @44),
    # elevation_rad (f32 @48) — all parsed and 0x14DE-grounded. Byte @9 is the
    # high byte of cno_raw@8, not a separate field.
    fields_identified=23,
    fields_parsed=21,
    # Layer-2 plausibility — 26,974 records across 15 payload sizes
    # (30/101/172/243/314/456/527/598/669/740/811/882/953/1024/1166 B) and
    # 10 chipset/firmware combinations:
    #   version (offset 0): 0x00 across 100% of records — corpus-wide invariant.
    # Declaring the enum here makes the audit toolchain surface any future
    # capture that breaks the invariant (e.g. a previously-unseen variant).
    # NOTE: header_b1 (offset 1) and header_b2 (offset 2) are chipset
    # discriminators, NOT invariants — they take values 0x04/0x06 and
    # 0x05/0x07/0x46 respectively. They cannot be declared as enum invariants
    # without a richer per-chipset spec mechanism.
    field_invariants={
        "version": {"enum": [0]},
    },
)
def parse_0x1886(log_time: int, data: bytes) -> Diag0x1886 | None:
    """Parse a LOG_GNSS_GAL_MEASUREMENT_REPORT_C (0x1886) log payload.

    Returns None (registry WARN) for a payload shorter than the 30-byte header
    or than the ``30 + N*71`` its header byte [29] declares.
    """
    if len(data) < _HDR_SIZE:
        return None
    if len(data) < _HDR_SIZE + data[_HDR_SLOT_COUNT_OFF] * _SLOT_SIZE:
        return None  # declared slot count overruns the payload

    version = data[0]
    # Layer-1 enforcement of field_invariants version=[0]. Across 26,974
    # records / 15 payload sizes / 10 chipset-firmware combos, 0x00 is the
    # only observed version byte. A foreign 811B payload with byte[0] != 0
    # would otherwise route through the full SDX55 decoder and emit
    # plausible-but-garbage PRN / Doppler / C/N0 values from unrelated wire
    # data.
    if version != 0:
        return None
    header_b1 = data[1]
    header_b2 = data[2]

    # Full SDX55 811-byte format — but ONLY the FN980m-validated slot layout.
    # Not every 811-byte / version-0 record shares the FN980m 71-byte slot
    # layout: the same 811-byte size + (header_b1, header_b2) = (6, 5) is also
    # emitted with a divergent slot layout (per-slot flags1 = 0x02c82000
    # instead of 0x02c02006, and sv_id_raw bytes outside the Galileo 50..85
    # PRN range).  Decoding those with the FN980m offsets would produce
    # plausible-but-garbage PRN / Doppler / C/N0.  Gate the SV decode on the
    # FN980m slot signature (first-slot flags1 magic + all-slot PRN
    # validity); otherwise emit a header-only 'sdx55_811_unrecognized' record
    # so the divergence is visible instead of silently mis-decoded.
    # MDM9607 Galileo variant (EG25-G), header (b1,b2)=(4,0x46).
    # A genuinely different 71-byte-slot struct from the FN980m form at the
    # same size.  Discriminated on the header pair so FN980m/RM520N 811-byte
    # records never enter this decoder, and gated on per-slot PRN validity so
    # a foreign (4,0x46) payload can't emit fabricated PRNs.

    n_mdm = (
        _mdm9607_slot_count(len(data))
        if header_b1 == _MDM9607_HDR_B1 and header_b2 == _MDM9607_HDR_B2
        else None
    )
    if n_mdm is not None:
        m_svs = [
            _parse_mdm9607_sv_slot(data, _MDM9607_HDR_SIZE + i * _MDM9607_SV_SIZE)
            for i in range(n_mdm)
        ]
        # Require a clear majority of in-range PRNs before trusting the layout
        # (the header pair alone is a weak gate; the PRN column is the strong
        # one that was validated 290/290 at N=11 and 13/13 at N=13 vs the 0x14DE
        # oracle). ``max(1, ...)`` keeps the threshold sane for tiny N.
        layout_ok = sum(sv.prn is not None for sv in m_svs) >= max(1, n_mdm - 2)
        return Diag0x1886(
            log_time=log_time,
            version=version,
            payload_size=len(data),
            header_b1=header_b1,
            header_b2=header_b2,
            header_raw=bytes(data[:_MDM9607_HDR_SIZE]),
            svs=m_svs if layout_ok else [],
            f_count=unpack_from('<I', data, 3)[0],
            gps_msec=unpack_from('<I', data, 9)[0],
            raw_hex=data.hex(),
            parser_format='mdm9607_gal' if layout_ok else 'mdm9607_gal_unrecognized',
        )

    if len(data) == _SDX55_FULL_SIZE:
        svs = [
            _parse_sv_slot(data, _SDX55_HDR_SIZE + i * _SDX55_SV_SIZE)
            for i in range(_SDX55_N_SLOTS)
        ]
        layout_ok = (
            svs[0].flags1 == _FN980M_SLOT_FLAGS1
            and all(sv.prn is not None for sv in svs)
        )
        return Diag0x1886(
            log_time=log_time,
            version=version,
            payload_size=len(data),
            header_b1=header_b1,
            header_b2=header_b2,
            header_raw=bytes(data[:_SDX55_HDR_SIZE]),
            svs=svs if layout_ok else [],
            f_count=unpack_from('<I', data, 3)[0],
            gps_msec=unpack_from('<I', data, 9)[0],
            raw_hex=data.hex(),
            parser_format='sdx55_full_811' if layout_ok else 'sdx55_811_unrecognized',
        )

    # Legacy 30-byte indoor/degraded format (also every unmapped size rung).
    # field_a/system_time are the two u16 halves of f_count (kept for compat);
    # float_legacy_1 (f32 @12) overlaps gps_msec's top byte — not a real float.
    field_a = unpack_from('<H', data, 3)[0] if len(data) >= 5 else None
    system_time = unpack_from('<H', data, 5)[0] if len(data) >= 7 else None
    float_1 = unpack_from('<f', data, 12)[0] if len(data) >= 16 else None
    float_2 = unpack_from('<f', data, 17)[0] if len(data) >= 21 else None
    float_3 = unpack_from('<f', data, 21)[0] if len(data) >= 25 else None

    return Diag0x1886(
        log_time=log_time,
        version=version,
        payload_size=len(data),
        header_b1=header_b1,
        header_b2=header_b2,
        field_a_u16=field_a,
        system_time_u16=system_time,
        float_legacy_1=float_1,
        float_legacy_2=float_2,
        float_legacy_3=float_3,
        f_count=unpack_from('<I', data, 3)[0],
        gps_msec=unpack_from('<I', data, 9)[0],
        raw_hex=data.hex(),
        parser_format='legacy_30' if len(data) <= 64 else 'unknown',
    )
