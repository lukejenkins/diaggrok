"""0x188B — GNSS reference-position cache.

See the module body for the field map and the evidence behind it.
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


# ---------------------------------------------------------------------------
# 0x188B — GNSS reference-position cache (257B MDM9x07/SDX20, 287B SDX55, 286B SDX24)
# ---------------------------------------------------------------------------
# Two distinct record variants exist:
#
#   - `v0_257B_mdm9x07_sdx20` — version=0, size=257. Observed on MDM9x07
#     (EP06A, EG18-NA, EG25-G) and SDX20 (LM960). 190/257 bytes constant;
#     6 coordinate-pair repeats at [4:12], [22:30], [130:138], [166:174],
#     [220:228], [238:246], all decoding to the receiver's known static
#     position (the capture site; value withheld). A firmware-default second
#     reference pair at [40:48] decodes to (38.0000°N, -117.0000°W)
#     constant across all chipsets.
#
#   - `v2_287B_sdx55` — version=2, size=287. Observed on FN980m (SDX55),
#     T99W640 and RM520N-GL. The record structure is **entirely different**
#     from the 257B form, not an extension of it: byte-0 differs, ref-pair
#     repeats are at [4], [166], [226], [246] (4 copies, not 6), and the
#     firmware-default (38N/-117W) pair at [40:48] is absent.
#
#     v2/287B stores the receiver's reference position in BOTH radians AND
#     decimal degrees:
#       [4:8]   = f32 ref_lat_rad
#       [8:12]  = f32 ref_lon_rad
#       [24:28] = f32 ref_lat_deg
#       [28:32] = f32 ref_lon_deg
#     The 257B variant has no decimal-degree fields.
#
#   - `v2_286B_sdx24` — version=2, size=286 (EM120R-GL, EM160R-GL SDX24):
#     the 287B layout minus one byte; see the 286 B branch of the parser.
#
# v2/287B is NOT a static cache: across 1260 FN980m records (five captures
# on different networks plus a cold reset) more than half the bytes that
# look constant in a short capture are per-record varying measurement
# fields.  Key decoded fields:
#
#       [12:16] f32  `altitude_ref_m`       — cached reference altitude
#                                             (matches the site elevation;
#                                             constant within a capture)
#       [32:36] f32  `altitude_fix_m`       — per-record current fix
#                                             altitude (~1240 distinct
#                                              values across 1260 rec)
#       [36:40] f32  `h_quality_scalar`     — horizontal position-quality
#                                             scalar; drops from ~12 to ~7
#                                             during fix acquisition.
#                                             CANDIDATE — not HDOP (below).
#       [40:44] f32  `v_quality_scalar`     — vertical position-quality scalar;
#                                             drops from ~12 to ~4 (rises on
#                                             GNSS-denied / indoor). CANDIDATE.
#
# v2/287B ground truth (FN980m SDX55 capture paired with a same-antenna
# LG290P reference receiver):
#   * ref position GROUNDED — the [24:32] deg pair AND the [4:12] rad pair both
#     recover the position within 2..4 m of the LG290P survey-grade fix and
#     of the co-temporal AT$GPSACP fix. The RAD pair [4:12] is CONSTANT across
#     the capture (static cached reference) while the DEG pair [24:32] VARIES
#     per-record (tracks the live fix) — the two are NOT redundant encodings.
#   * altitude_fix_m [32:36] GROUNDED — tracks the 0x1476 live-fix altitude
#     and AT$GPSACP within a few metres; altitude_ref_m [12:16] is a constant
#     cached reference.
#   * `h_quality_scalar` / `v_quality_scalar` (formerly dop_h_like/dop_v_like)
#     are NOT HDOP/VDOP: h_quality_scalar reads a CONSTANT 7.566 while the
#     true HDOP is 1.0 constant (Telit AT$GPSACP field 4, all poll samples)
#     and 1.01 (DIAG 0x1476). A field 7.5x the dimensionless DOP is not DOP.
#     Leading hypothesis: a meters-scale HEPE/VEPE-style estimated-position-
#     error or position-quality scalar — but v_quality_scalar (2.5..3.9) <
#     h_quality_scalar (7.566) argues against straightforward HEPE/VEPE (GNSS
#     vertical error usually exceeds horizontal). Held CANDIDATE, exposed
#     raw, pending an F3 arg-label or an AT+QGPSLOC=2 HEPE cross-check.
#   * QCSuper and SCAT do not decode 0x188B — the code is a proprietary
#     GNSS-ME cache absent from both tools' tables.
#   * F3: the GNSS-ME subsystem co-emits in the same capture but does NOT
#     arg-label the cache fields (the FN980m F3 plane is clock/time/power/
#     coex — tcxomgr/gts/mcpm/lmtsmgr — no position-cache printf). The
#     decode is content-grounded (LG290P + AT), subsystem-attributed, not
#     F3-arg-labeled.
#
# The four `(lat_rad, lon_rad)` repeats at [4], [166], [226], [246] each
# show slight per-record variance (5th/6th decimal place) — this is a
# short rolling history of recent fix lat/lon, not four copies of a
# static cache.
#
# v0/257B field map (condensed):
#     [0:2]  u16LE  version            = 0x0000 (CONSTANT)
#     [2]    u8     gen_marker         (0x87 EP06A/LM960/EG25-G, 0x8f EG18-NA;
#                                        see the cold-start note below)
#     [3]    u8     flag               = 0x02 (predominant; NOT constant —
#                                        transient 0x00, see below)
#     [4:8]  f32LE  ref_lat_rad        — receiver latitude (rad)
#     [8:12] f32LE  ref_lon_rad        — receiver longitude (rad)
#     [40:44] f32LE qcom_ref_lat_rad   = 0x3F800000 (firmware default)
#     [44:48] f32LE qcom_ref_lon_rad   = firmware default
#     [256]  u8     trailer            = 0x01 (CONSTANT)
#
# v0/257B cold-start ground truth (EG25-G MDM9607, 353 v0/257B records from
# an AT+QGPSDEL=3 forced-cold-start capture with a same-antenna LG290P):
#   * ref_lat_rad/ref_lon_rad [4:12] GROUNDED vs independent truth —
#     the cached ref sits 9.6 m median from the LG290P survey-grade fix
#     (9.4 m from the co-temporal AT+QGPSLOC). Confirms [4:12] = receiver
#     reference position (rad) on the MDM9607 v0/257B variant.
#   * The ref is a COARSE cache that CONVERGES: 349/353 records hold the
#     9.6 m value, 4 records show a monotone refinement walk
#     8.0→7.0→5.8→5.4 m toward LG290P truth during acquisition — the cache
#     updates, it is not purely static.
#   * v0_seed_lat_rad/lon [58:66] = (0,0) in 353/353 (raw bytes literally
#     8x 0x00) through a DELIBERATE assistance purge (AT+QGPSDEL=3, XTRA
#     included) → BLIND_SEARCH → confirmed 3D fix (340/340 QGPSLOC fix-type
#     3). Because a fix WAS achieved yet seed stayed zero, seed is NOT a
#     last-computed-fix cache; it is the INJECTED-assistance position slot
#     (0 when none injected). The with-assistance branch is not yet
#     captured.
#   * gen_marker [2] = 0x87 (353/353) on EG25-G MDM9607 (same MDM9x07
#     family as EP06A).
#   * flag [3] = 0x02 on 351/353; 0x00 on 2 consecutive byte-identical
#     mid-capture records (still carrying a valid ref position), so flag is
#     not constant. Semantics of the 0x00 transient TBD (state/retransmit
#     marker; not a position sentinel).
#
# v0/257B event and F3 grounding (EG25-G MDM9607 cold start, 353 records,
# and EG18-NA cold start, 294 records):
#   * The 0x60 event plane ARG-LABELS the ref position.
#     EVENT_GNSS_TLE_POS_UPDATE_C (event id 0x79c, DIAG_EVENT_REPORT_F 0x60)
#     co-emits 1:1 with 0x188B (353:353 on EG25-G, 299 events:294 records on
#     EG18-NA) and its 14-byte payload is
#     [u16 pad][f32 lat_rad][f32 lon_rad][f32 meas_scalar~20009]. The event's
#     (lat_rad, lon_rad) are BIT-IDENTICAL to 0x188B [4:12] on 349/353 EG25-G
#     records (the 4 misses are exactly the acquisition convergence-walk
#     records — a nearest-in-time join artifact, cache updated between the log
#     and event) and 294/294 EG18-NA records. Two f32 fields matching
#     bit-exactly across 643 records on two MDM9x07 chipsets is not
#     coincidence: the firmware's own event independently confirms
#     [4:12] = receiver reference position (rad) and names the emission a
#     TLE (Time/Location Estimate) position-cache update. The event's 3rd f32
#     also matches 0x188B [32:36] (~20009/20019 measurement-scalar family) on
#     the settled records — [32:36] is the TLE measurement scalar.
#   * F3 (0x79) plaintext plane: co-emits but does not arg-label. The
#     GNSS-ME 0x79 plane on this build is search strategy
#     (mc_gnsssearchstrategy.c), measurement report (mc_gnssmeasreport.c),
#     ephemeris/SV state (mgp_pe_common.c) and HEPE (lm_mgp.c) — there is NO
#     lat/lon/ref-position printf. The position cache is F3-co-emitted but
#     not F3-printf-labeled (same as v0x02); the arg-label comes from the
#     0x60 event plane.
#   * lm_mgp.c HEPE converges 403 -> 9.27 m across the cold start,
#     co-temporal with the 0x188B cache-update sequence — corroborating the
#     coarse cache that converges during acquisition. The v0/257B [36:40]
#     CANDIDATE quality scalar (f32 [2.5..~95], floors at 2.5) also
#     converges in the same window and direction (Pearson r=0.70 vs nearest
#     HEPE) BUT is NOT numerically HEPE (different range/floor: HEPE floors
#     at 9.27 m, [36:40] at 2.5). [36:40] stays a CANDIDATE convergence/
#     quality scalar — acquisition-linked, not HEPE-labeled.
#   * QCSuper and SCAT do not decode 0x188B (QCSuper geo-dumps positions
#     only from other GNSS codes it knows).
#   * gen_marker [2]: both the cold-start EG18-NA and the EG25-G show 0x87
#     (294/294 and 353/353), so the "0x8f = EG18-NA" attribution does not
#     hold on every capture; gen_marker may not be strictly chipset-bound.
#     The parser does not branch on gen_marker.
#
# v2/287B field map (condensed):
#     [0:2]  u16LE  version            = 0x0002 (CONSTANT)
#     [2]    u8     gen_marker         = 0x87 or 0x8f (varies 135/143)
#     [3]    u8     flag               = 0x00 (CONSTANT)
#     [4:8]  f32LE  ref_lat_rad        — receiver latitude (rad)
#     [8:12] f32LE  ref_lon_rad        — receiver longitude (rad)
#     [12:16] f32LE altitude_ref_m     — cached reference altitude (m)
#     [16:20] f32LE measurement_16     — ~20053..20058 (slowly drifts;
#                                        possibly ionosphere delay or
#                                        clock-drift scalar)
#     [20:24] f32LE measurement_20     — ~5232..5299 (slowly drifts)
#     [24:28] f32LE ref_lat_deg        — receiver latitude (decimal deg)
#     [28:32] f32LE ref_lon_deg        — receiver longitude (decimal deg)
#     [32:36] f32LE altitude_fix_m     — per-record current fix altitude
#     [36:40] f32LE h_quality_scalar   — horiz position-quality scalar (range
#                                        7..13). CANDIDATE; not HDOP (true
#                                        HDOP=1.0 while this reads 7.566).
#     [40:44] f32LE v_quality_scalar   — vert position-quality scalar (range
#                                        3..12). CANDIDATE.

@dataclass
class PositionSnapshot188B:
    """5-f32 position snapshot as it appears 4× in the v2/287B record.

    The ref snapshot at [4:24] and the 3 history snapshots at [166:186],
    [226:246], [246:266] all have this exact structure: ``(lat_rad,
    lon_rad, altitude_m, scalar_a, scalar_b)``.  ``scalar_a/b`` map to
    the existing ``measurement_16/20`` fields on the ref snapshot —
    values are slow-drift f32s in the ~20000 / ~5230 range, likely
    ionosphere / troposphere delay scalars or receiver clock-drift
    coefficients.
    """
    lat_rad: float
    lon_rad: float
    altitude_m: float
    scalar_a: float      # mirrors ref measurement_16 (~20053..20058)
    scalar_b: float      # mirrors ref measurement_20 (~5232..5299)

    def to_dict(self) -> dict[str, Any]:
        return {
            'lat_rad': self.lat_rad,
            'lon_rad': self.lon_rad,
            'altitude_m': self.altitude_m,
            'scalar_a': self.scalar_a,
            'scalar_b': self.scalar_b,
        }


def _snapshot_at(data: bytes, off: int) -> PositionSnapshot188B:
    return PositionSnapshot188B(
        lat_rad=unpack_from('<f', data, off)[0],
        lon_rad=unpack_from('<f', data, off + 4)[0],
        altitude_m=unpack_from('<f', data, off + 8)[0],
        scalar_a=unpack_from('<f', data, off + 12)[0],
        scalar_b=unpack_from('<f', data, off + 16)[0],
    )


@dataclass
class PositionSnapshotV0188B:
    """18-byte v0/257B position snapshot.

    879 v0/257B records show 4 snapshots at offsets [130, 166, 220, 238]
    in the v0/257B variant, each 18 bytes wide with the structure
    ``(lat_rad, lon_rad, mark_u16, f32_a, f32_b)``.  The ``mark_u16`` at +8
    is shared between snapshot pairs: slots (130, 166) share the mark in
    99.8% of records and slots (220, 238) in 96.5% — the 4 slots are
    organized as TWO paired snapshots.  Value range ~1380-1430
    (0x0574..0x0596), clustered around 0x0583 but not a cross-record
    constant — likely a GPS-week-shifted timestamp or ephemeris-set-id
    refreshed whenever the receiver updates its cached position.

    f32_a and f32_b vary per-snapshot within a single record (likely
    per-satellite or per-constellation auxiliary state) — exact
    semantics still TBD.

    slot[0].f32_a has a different physical magnitude than slots 1–3 (>20×
    larger) and pairs with slot[1] via a fixed +380000 offset:

      slot[0].f32_a - slot[1].f32_a ≈ 380000  (379999.986 on EP06A,
                                              EG18NA, LM960 fixtures)
      slot[0].f32_b == slot[1].f32_b           (paired exactly)
      slots 1–3 .f32_a in [20007..20085]

    An apparent "400009.0 constant" in slot[0].f32_a is a special case of
    this relationship — EP06A and LM960 happen to share slot[1].f32_a =
    20009.014, so slot[0].f32_a = 400009.0 on both. The EG18NA fixture has
    slot[1].f32_a = 20015.141 and correspondingly slot[0].f32_a =
    400015.125 — the offset is the cross-chipset structural invariant, not
    the absolute. Likely some pseudorange- or measurement-related scalar
    with slot[0] expressing a longer horizon (or different sample rate)
    than slot[1].
    """
    lat_rad: float
    lon_rad: float
    mark_u16: int           # u16 LE marker — shared between snapshot pairs
    f32_a: float
    f32_b: float

    def to_dict(self) -> dict[str, Any]:
        return {
            'lat_rad': self.lat_rad,
            'lon_rad': self.lon_rad,
            'mark_u16': self.mark_u16,
            'f32_a': self.f32_a,
            'f32_b': self.f32_b,
        }


def _snapshot_v0_at(data: bytes, off: int) -> PositionSnapshotV0188B:
    return PositionSnapshotV0188B(
        lat_rad=unpack_from('<f', data, off)[0],
        lon_rad=unpack_from('<f', data, off + 4)[0],
        mark_u16=unpack_from('<H', data, off + 8)[0],
        f32_a=unpack_from('<f', data, off + 10)[0],
        f32_b=unpack_from('<f', data, off + 14)[0],
    )


@dataclass
class Diag0x188B:
    """GNSS reference-position cache (0x188B) — v0/257B MDM9x07/SDX20, v2/287B SDX55 or v2/286B SDX24."""
    log_time: int
    variant: str              # 'v0_257B_mdm9x07_sdx20', 'v2_287B_sdx55' or 'v2_286B_sdx24'
    version: int
    gen_marker: int
    flag: int
    ref_lat_rad: float
    ref_lon_rad: float
    # v0-only fields (firmware-default assistance ref). None on v2.
    qcom_ref_lat_rad: float | None
    qcom_ref_lon_rad: float | None
    # v0/257B residue decode (3847-record 4-chipset corpus):
    #   [12..40] 7 x u32LE fields — semantic labels TBD; observed ranges:
    #     [12]: uniq=163 (timestamp-like, f32 ~2.7e9)
    #     [16]: uniq=276 (f32 small signed, clock_bias-like ~-3.6e-6)
    #     [20]: uniq=572 (f32 very small positive, ~1e-30)
    #     [24]: uniq=179 (f32 mixed, range [-1.3e-9..0.99])
    #     [28]: uniq=180 (f32 always-positive tiny)
    #     [32]: uniq=1572 (f32 measurement ~20007-20010 on ep06a,
    #           saturates up to 4.9M on lm960 — same scalar-family
    #           as v2/287B measurement_16)
    #     [36]: uniq=2794 (f32 [2.5..10000], DOP-like / uncertainty)
    v0_fields_12_40_u32: list[int] | None   # 7 u32LE at [12..40]
    # v0/257B [58..66] — 2 x f32 "seed position", NOT equal to
    # ref_lat_rad/ref_lon_rad at [4..12]; value is per-capture-state, NOT a
    # per-chipset constant. One EP06A capture (879 records) shows non-zero
    # values, while LG290P-paired LM960 (329 rec) and EP06A (299 rec)
    # captures and an assistance-purged EG25-G cold start show seed=0.0
    # across every record. Most likely the injected assistance position
    # (0 when none injected); captures with active assistance are needed to
    # characterize it further.
    v0_seed_lat_rad: float | None           # f32 at [58..62]
    v0_seed_lon_rad: float | None           # f32 at [62..66]
    # v0/257B [69..72] + [73..76] — two 3-byte values separated by a
    # byte-72 zero. On the 3847-record corpus these are chipset-
    # constant; semantic labels TBD. Stored as big-endian integers.
    v0_tail_a_u24: int | None               # 3B at [69..72]
    v0_tail_b_u24: int | None               # 3B at [73..76]
    # v2-only fields (decimal-degrees mirror + altitude + per-record fix fields). None on v0.
    ref_lat_deg: float | None
    ref_lon_deg: float | None
    altitude_ref_m: float | None      # renamed from field_12
    altitude_fix_m: float | None      # per-record current fix altitude (v2/287B only)
    # CANDIDATE: horiz/vert position-quality scalars at [36:40]/[40:44]
    # (v2/287B only). Formerly dop_h_like/dop_v_like — they are not HDOP/VDOP
    # (h reads constant 7.566 vs true HDOP 1.0).
    h_quality_scalar: float | None    # f32 at [36:40] (v2/287B only)
    v_quality_scalar: float | None    # f32 at [40:44] (v2/287B only)
    measurement_16: float | None      # f32 at [16:20] (v2 only, slow drift)
    measurement_20: float | None      # f32 at [20:24] (v2 only, slow drift)
    # v2-only position-history buffer — 3 snapshots at [166], [226], [246].
    # Each is a 20-byte 5×f32 block (same structure as ref [4..24]).
    # 1260 FN980m records confirm the layout.
    position_history: list[PositionSnapshot188B] | None
    # v2-only 12-byte altitude echo block — repeated bit-exact 3x across
    # the record at [174:186], [234:246], [254:266].  All 3 echoes are
    # byte-identical on 8/8 FN980m SDX55 v2/287B records.  Decode per echo:
    #   [+0:4]  f32 LE  altitude_ref_echo_m   — matches altitude_ref_m
    #                                           at [12:16]
    #   [+4:8]  f32 LE  measurement_b_echo    — stable "reference"
    #                                           version of measurement_16;
    #                                           differs slightly from the
    #                                           per-record value (20007.6
    #                                           vs 20053.6)
    #   [+8:12] f32 LE  measurement_c_echo    — matches measurement_20 at
    #                                           [20:24] (5234.3 on fixture)
    # Populated on v2/287B variant only (None on v0/257B).
    altitude_ref_echo_m: float | None
    measurement_b_echo: float | None
    measurement_c_echo: float | None
    altitude_echo_invariant_ok: bool | None
    # v0-only position-history buffer — 4 snapshots at [130], [166], [220],
    # [238], each 18B wide with (lat_rad, lon_rad, mark_u16, f32_a, f32_b).
    # 879 v0/257B records confirm the layout and the 0x0583-clustered u16
    # marker on all 4 × 879 = 3516 snapshot slots.
    position_history_v0: list[PositionSnapshotV0188B] | None
    # v0/257B reserved-zero regions — bit-exact zero across 3847/3847 v0/257B
    # records (4 chipsets: ep06a + eg18na + lm960 + eg25g). Exposed as a
    # boolean invariant rather than raw bytes. None on v2/287B.
    reserved_zero_148_166_ok: bool | None   # [148..166] 18B all zero
    reserved_zero_184_220_ok: bool | None   # [184..220] 36B all zero
    trailer: int | None       # only present in v0 (0x01); None on v2
    payload_size: int
    body_raw: bytes

    @property
    def field_12(self) -> float | None:
        """Back-compat alias for `altitude_ref_m`."""
        return self.altitude_ref_m

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            'type': 'Diag0x188B',
            'log_time': self.log_time,
            'variant': self.variant,
            'version': self.version,
            'gen_marker': self.gen_marker,
            'flag': self.flag,
            'ref_lat_rad': self.ref_lat_rad,
            'ref_lon_rad': self.ref_lon_rad,
            'qcom_ref_lat_rad': self.qcom_ref_lat_rad,
            'qcom_ref_lon_rad': self.qcom_ref_lon_rad,
            'ref_lat_deg': self.ref_lat_deg,
            'ref_lon_deg': self.ref_lon_deg,
            'altitude_ref_m': self.altitude_ref_m,
            'altitude_fix_m': self.altitude_fix_m,
            'h_quality_scalar': self.h_quality_scalar,
            'v_quality_scalar': self.v_quality_scalar,
            'measurement_16': self.measurement_16,
            'measurement_20': self.measurement_20,
            'trailer': self.trailer,
            'payload_size': self.payload_size,
            'altitude_ref_echo_m': self.altitude_ref_echo_m,
            'measurement_b_echo': self.measurement_b_echo,
            'measurement_c_echo': self.measurement_c_echo,
            'altitude_echo_invariant_ok': self.altitude_echo_invariant_ok,
            # v0/257B residue fields (None on v2/287B)
            'v0_fields_12_40_u32': (
                list(self.v0_fields_12_40_u32) if self.v0_fields_12_40_u32 is not None else None
            ),
            'v0_seed_lat_rad': self.v0_seed_lat_rad,
            'v0_seed_lon_rad': self.v0_seed_lon_rad,
            'v0_tail_a_u24': self.v0_tail_a_u24,
            'v0_tail_b_u24': self.v0_tail_b_u24,
            'reserved_zero_148_166_ok': self.reserved_zero_148_166_ok,
            'reserved_zero_184_220_ok': self.reserved_zero_184_220_ok,
        }
        if self.position_history is not None:
            out['position_history'] = [s.to_dict() for s in self.position_history]
        if self.position_history_v0 is not None:
            out['position_history_v0'] = [s.to_dict() for s in self.position_history_v0]
        return out


# ---------------------------------------------------------------------------
# Validating v2/287B against a host GNSS fix
# ---------------------------------------------------------------------------
# The RM520N-GL emits the v=0x02 / 287B SDX55-family variant (67/67 records
# across its captures). That variant exposes a decimal-degree receiver
# lat/lon mirror, a per-record fix altitude, and two position-quality
# scalars (h_quality_scalar/v_quality_scalar — not the dimensionless
# HDOP/VDOP). The position + altitude fields can be checked against the
# Quectel GNSS AT stack (AT+QGPSLOC=2). Caveat: this is a *cached
# reference* position, so lat/lon track the live fix only when a recent fix
# exists; compare during a stable stationary 3D fix so cache == fix.

# f64 constant opening the v2 tail (see the 286 B branch).
_V2_TAIL_ANCHOR = bytes.fromhex('1fc9293fb5b002c0')


@register(
    0x188B, domain="gnss",
    name="0x188B",
    description="GNSS reference-position cache — 257B MDM9x07/SDX20 + 287B SDX55 + 286B SDX24",
    version=12,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE across 14,896 records / 121 captures: 257B v0 records "
        "(version=0x00, MDM9x07/SDX20: EP06A, EG18-NA, EG25-G, LM960) and 287B "
        "v2 records (version=0x02, SDX55-family: FN980m, T99W640, RM520N-GL); "
        "version is locked to size and both are gated jointly before any body "
        "read. v0/257B is fully decoded: 7xu32LE at [12..40], a 2xf32 "
        "seed-position pair at [58..66] (zero when no assistance is injected), "
        "2xu24 tail values at [69..72]+[73..76], bit-exact zero reserved "
        "regions [148..166] + [184..220] (3847/3847 records), and a 4-entry "
        "position_history_v0. v2/287B adds a decimal-degree mirror, altitudes, "
        "a 3-entry position_history and a triple altitude echo block. Ground "
        "truth: the v2 ref position (deg [24:32] live + rad [4:12] static cache) "
        "lies within 2..4 m of a same-antenna LG290P fix and altitude_fix_m "
        "tracks the 0x1476 live fix; the v0 [4:12] ref lat/lon is bit-identical "
        "to the firmware's own EVENT_GNSS_TLE_POS_UPDATE_C (event 0x79c) payload "
        "on EG25-G (349/353) and EG18-NA (294/294) cold starts, naming the "
        "emission a TLE position-cache update. h_quality_scalar/v_quality_scalar "
        "are NOT HDOP/VDOP (h reads constant 7.566 vs true HDOP 1.0); the [36:40] "
        "quality scalars stay CANDIDATE. F3 co-emits but has no lat/lon printf; "
        "QCSuper/SCAT do not decode 0x188B. The 286B v2 form (EM120R-GL + "
        "EM160R-GL SDX24, 3 records / 2 captures) is the 287B layout minus one "
        "byte inside [24:85]: every populated tail region sits 1 B earlier, and "
        "174/201 tail bytes of an EM120R-GL 286B record equal a T99W640 287B "
        "record's at the -1 shift. [24:85] is zero in 3/3 records, so the "
        "byte's position (and the [24:44] fields) cannot be placed; those fields "
        "are None. [0:24] + shifted tail decode."
    ),
    source_url="",
    issues=(),
    # v0/257B fields: v0_fields_12_40_u32 (counts as 7), v0_seed_lat_rad,
    # v0_seed_lon_rad, v0_tail_a_u24, v0_tail_b_u24, reserved_zero_148_166_ok,
    # reserved_zero_184_220_ok = 13 fields on top of the 58 shared/v2 ones.
    # Total: 58 + 13 = 71 fields_parsed.
    fields_parsed=71,
    fields_identified=72,
    field_invariants={
        # version + payload_size are locked together: version 0 ↔ 257B
        # (mdm9x07/sdx20 v0 variant) and version 2 ↔ 286B/287B (v2
        # variants). The parser-body gate enforces the joint constraint;
        # these declarations protect each layer-2 independently.
        "version": {"enum": [0, 2]},
        "payload_size": {"enum": [257, 286, 287]},
    },
)
def parse_0x188b(log_time: int, data: bytes) -> Diag0x188B | None:
    n = len(data)
    # Joint (size, version) gate BEFORE reading any v0/v2 body field, so the
    # v0/257B branch never reads its u32×7 block at offset 12 from a record
    # whose version is unvalidated. Corpus (14,896 records / 121 captures):
    # the variants are locked to (size=257, version=0x00) and
    # (size=286/287, version=0x02).
    if n not in (257, 286, 287):
        return None
    # Explicit Layer-1 version gate. The subsequent compound
    # `(n, version_lo)` check is the joint (size, version) gate; this
    # explicit `not in` form makes byte-0 enforcement visible to audit
    # tooling.
    if data[0] not in (0x00, 0x02):
        return None
    # byte 0 is the low byte of u16 LE `version`; byte 1 is also part of
    # the version u16 and is 0x00 on both variants.
    version_lo = data[0]
    if not ((n == 257 and version_lo == 0x00)
            or (n in (286, 287) and version_lo == 0x02)):
        return None
    if data[1] != 0x00:
        return None
    if n == 257:
        # v0/257B body fully decoded.
        fields_12_40 = list(unpack_from('<7I', data, 12))
        seed_lat = unpack_from('<f', data, 58)[0]
        seed_lon = unpack_from('<f', data, 62)[0]
        # byte[72] is zero-constant across the 3847-record corpus; the
        # varying 3-byte u24 values live at [69..72] and [73..76].
        tail_a = int.from_bytes(data[69:72], 'big')
        tail_b = int.from_bytes(data[73:76], 'big')
        reserved_148_ok = data[148:166] == b'\x00' * 18
        reserved_184_ok = data[184:220] == b'\x00' * 36
        return Diag0x188B(
            log_time=log_time,
            variant='v0_257B_mdm9x07_sdx20',
            version=unpack_from('<H', data, 0)[0],
            gen_marker=data[2],
            flag=data[3],
            ref_lat_rad=unpack_from('<f', data, 4)[0],
            ref_lon_rad=unpack_from('<f', data, 8)[0],
            qcom_ref_lat_rad=unpack_from('<f', data, 40)[0],
            qcom_ref_lon_rad=unpack_from('<f', data, 44)[0],
            v0_fields_12_40_u32=fields_12_40,
            v0_seed_lat_rad=seed_lat,
            v0_seed_lon_rad=seed_lon,
            v0_tail_a_u24=tail_a,
            v0_tail_b_u24=tail_b,
            ref_lat_deg=None,
            ref_lon_deg=None,
            altitude_ref_m=None,
            altitude_fix_m=None,
            h_quality_scalar=None,
            v_quality_scalar=None,
            measurement_16=None,
            measurement_20=None,
            position_history=None,
            position_history_v0=[
                _snapshot_v0_at(data, 130),
                _snapshot_v0_at(data, 166),
                _snapshot_v0_at(data, 220),
                _snapshot_v0_at(data, 238),
            ],
            reserved_zero_148_166_ok=reserved_148_ok,
            reserved_zero_184_220_ok=reserved_184_ok,
            # altitude echo block — v2 only, None on v0/257B.
            altitude_ref_echo_m=None,
            measurement_b_echo=None,
            measurement_c_echo=None,
            altitude_echo_invariant_ok=None,
            trailer=data[256],
            payload_size=n,
            body_raw=b'',  # v0/257B fully decoded
        )
    if n == 286:
        # The SDX24 v2 form is the 287 B layout minus ONE byte inside
        # [24:85]. Every populated region after offset 85 sits exactly 1 B
        # earlier than on 287 B (86->85, 166->165, 226->225, 238->237,
        # 243->242, 258->257, 263->262), and 174/201 tail bytes of an
        # EM120R-GL 286 B record equal a T99W640 287 B record's at the -1
        # shift. [24:85] is all-zero in every 286 B record (3/3), so WHERE the
        # byte went is not measurable: the 287 B fields at [24:44] (deg pair,
        # altitude_fix_m, quality scalars) are therefore None here, and the
        # span stays in body_raw. [0:24] and the shifted tail decode as v2.
        #
        # Anchor: the tail opens with the 8-byte f64 constant 1fc9293fb5b002c0
        # (-2.3362832...) at [85:93] — at [86:94] on 287 B — in 6/6 records
        # across four chipsets (FN980m SDX55, T99W640, EM120R-GL, EM160R-GL).
        # A 287 B record cut by one byte has 0x00 at [85], so it rejects here
        # instead of silently decoding as this form.
        if data[85:93] != _V2_TAIL_ANCHOR:
            return None
        return Diag0x188B(
            log_time=log_time,
            variant='v2_286B_sdx24',
            version=unpack_from('<H', data, 0)[0],
            gen_marker=data[2],
            flag=data[3],
            ref_lat_rad=unpack_from('<f', data, 4)[0],
            ref_lon_rad=unpack_from('<f', data, 8)[0],
            qcom_ref_lat_rad=None,
            qcom_ref_lon_rad=None,
            v0_fields_12_40_u32=None,
            v0_seed_lat_rad=None,
            v0_seed_lon_rad=None,
            v0_tail_a_u24=None,
            v0_tail_b_u24=None,
            ref_lat_deg=None,
            ref_lon_deg=None,
            altitude_ref_m=unpack_from('<f', data, 12)[0],
            altitude_fix_m=None,
            h_quality_scalar=None,
            v_quality_scalar=None,
            measurement_16=unpack_from('<f', data, 16)[0],
            measurement_20=unpack_from('<f', data, 20)[0],
            position_history=[
                _snapshot_at(data, 165),
                _snapshot_at(data, 225),
                _snapshot_at(data, 245),
            ],
            position_history_v0=None,
            reserved_zero_148_166_ok=None,
            reserved_zero_184_220_ok=None,
            altitude_ref_echo_m=unpack_from('<f', data, 173)[0],
            measurement_b_echo=unpack_from('<f', data, 177)[0],
            measurement_c_echo=unpack_from('<f', data, 181)[0],
            altitude_echo_invariant_ok=(data[173:185] == data[233:245] == data[253:265]),
            trailer=None,
            payload_size=n,
            body_raw=bytes(data[24:165]) + bytes(data[185:225]) + bytes(data[245:253]) + bytes(data[265:286]),
        )
    if n == 287:
        # Altitude echo block — 12 bytes at [174:186] that repeat
        # bit-exact at [234:246] and [254:266] (8/8 FN980m SDX55 v2
        # records).

        echo_a = data[174:186]
        echo_b = data[234:246]
        echo_c = data[254:266]
        echo_ok = (echo_a == echo_b == echo_c)
        return Diag0x188B(
            log_time=log_time,
            variant='v2_287B_sdx55',
            version=unpack_from('<H', data, 0)[0],
            gen_marker=data[2],
            flag=data[3],
            ref_lat_rad=unpack_from('<f', data, 4)[0],
            ref_lon_rad=unpack_from('<f', data, 8)[0],
            qcom_ref_lat_rad=None,
            qcom_ref_lon_rad=None,
            v0_fields_12_40_u32=None,
            v0_seed_lat_rad=None,
            v0_seed_lon_rad=None,
            v0_tail_a_u24=None,
            v0_tail_b_u24=None,
            ref_lat_deg=unpack_from('<f', data, 24)[0],
            ref_lon_deg=unpack_from('<f', data, 28)[0],
            altitude_ref_m=unpack_from('<f', data, 12)[0],
            altitude_fix_m=unpack_from('<f', data, 32)[0],
            h_quality_scalar=unpack_from('<f', data, 36)[0],
            v_quality_scalar=unpack_from('<f', data, 40)[0],
            measurement_16=unpack_from('<f', data, 16)[0],
            measurement_20=unpack_from('<f', data, 20)[0],
            position_history=[
                _snapshot_at(data, 166),
                _snapshot_at(data, 226),
                _snapshot_at(data, 246),
            ],
            position_history_v0=None,
            reserved_zero_148_166_ok=None,
            reserved_zero_184_220_ok=None,
            altitude_ref_echo_m=unpack_from('<f', data, 174)[0],
            measurement_b_echo=unpack_from('<f', data, 178)[0],
            measurement_c_echo=unpack_from('<f', data, 182)[0],
            altitude_echo_invariant_ok=echo_ok,
            trailer=None,
            payload_size=n,
            # body_raw now excludes the three echo regions (we decoded them)
            body_raw=bytes(data[44:166]) + bytes(data[186:226]) + bytes(data[246:254]) + bytes(data[266:287]),
        )
    return None
