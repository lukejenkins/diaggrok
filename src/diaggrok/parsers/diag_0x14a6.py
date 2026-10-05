"""0x14A6 — GNSS per-SV ephemeris (IODE) snapshot.

The full byte map is in the comment block below the imports.

Log name: LOG_CGPS_SM_EPH_RANDOMIZATION_INFO_C
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

# version -> (payload size, per-SV slot width, slot count). The table
# starts at [23] on both; v0x02 has an 80B zero tail after its 12 slots.
_14A6_LAYOUT = {0x01: (87, 2, 32), 0x02: (151, 4, 12)}
_SLOT_BASE = 23

# --- ground-truth recipe -------------------------------------------------
# 0x14A6 is a GNSS per-SV ephemeris snapshot: a 12-slot table of (sv_id,
# iode) plus SV-count fields. sv_id grounds against the modem's NMEA GSV PRN
# set under a real sky fix (hardware-verified, sv_id == GPS PRN). The per-SV
# `iode` scalar is not C/N0: it is a frozen-per-session u8 that reaches 235,
# while real C/N0 lives in the co-temporal `mc_glodebits`/`mc_meas` F3. IODE
# has NO NMEA source — ground it against a RINEX .nav ephemeris IODE per PRN
# or a 0x99/QSR4 F3 IODE print, NOT GSV SNR.
# --- end recipe ----------------------------------------------------------


# ---------------------------------------------------------------------------
# 0x14A6 — GNSS per-SV ephemeris (IODE) snapshot (v0x02 151B, v0x01 87B)
# ---------------------------------------------------------------------------
# Corpus (v0x02): 3195 records / 151B fixed / 12 chipset+firmware pairs.
#
# Full-byte decode (every byte named — zero body_raw):
#   [0]      u8  version = 2 (constant 3195/3195)
#   [1]      u8  flag_1 ∈ {0, 1}
#   [2:10]   8B  stats_header = two u32 LE GPS SV bitmasks (bit n-1 = PRN n),
#                F3-grounded against tm_core.c
#                "LM's GPS eph. req suppressed: Nd=%x,HV=%x,VB=%x" and
#                "GPS Eph. req to protocol-sub: Nd=%x,HV=%x,VB=%x", printed
#                ~450 ticks before the record:
#       [2:6]  u32 gps_eph_have_mask  = HV — 100% on every paired record
#                (RM500Q-AE 526, SIM8202G 640, Wistron 6167, EG18-NA 245,
#                EG25-G 60, Carcom-G1 193; 3-4 distinct masks per capture on
#                the first three). The sv_slots table is the first 12 PRNs of
#                this mask, in order (v0x02 100% bar Wistron 6181/6197, where HV had just cleared; v0x01
#                648/648), so the table is the have-valid-ephemeris set.
#       [6:10] u32 gps_eph_vb_mask    = VB — 100% on the same pairs (2-3
#                distinct masks on RM500Q / SIM8202G). F3 names it only "VB".
#   [10]     u8  reserved_10 = 0 (constant across RE corpus + EM7565).
#   [11:13]  u16 nav_state (LE). 0x0000 (clear) or 0x0110
#                (set: byte[11]=0x10, byte[12]=0x01). Zero across the entire
#                3195-record cross-chipset RE corpus, but on Sierra EM7565
#                SWI9X50C it is a **latching GNSS receiver-state / nav-
#                maturity flag**: in a 339-record EM7565 GNSS capture
#                it transitions exactly ONCE (164 clear → 175 set, in
#                capture-time order) and never reverts. It is orthogonal to
#                the SV-count fields — two record shapes with byte-identical
#                counts (fam=fix=trk=6, subset=0, flag_15=0) differ only in
#                nav_state (12 clear vs 30 set), which rules out any "derived
#                from counts" reading. The clear→set edge coincides with the
#                receiver maturing from initial GPS-only acquisition (fix=5)
#                toward steady-state navigation (fix up to 7, tracked up to
#                8); C/N0 is comparable across both states so it is not a
#                signal-quality gate. Value is kept raw (size-invariance ≠
#                format-invariance) — a future capture may show other values.
#                Cross-modem scope: nav_state is NOT chipset- or vendor-
#                specific. A Quectel EG18-NA (MDM9640) capture carries
#                nav_state = 0x0010 on 290/290 records — a different vendor
#                AND a different chipset family from the Sierra EM7565
#                (MDM9x50, nav_state 0x0110). byte[11]=0x10 is the shared
#                "set" bit across both non-zero sources; byte[12] varies
#                (0x01 on EM7565, 0x00 on EG18-NA). It is not tied to the
#                silicon either: EM7511 (same MDM9x50 silicon + same SWI9X50C
#                family as EM7565) is 0x00 across all 10 in-corpus captures
#                (1271/1271 records), and another EG18-NA capture reads 0x00.
#                What keys the flag is not established; the two EG18-NA
#                captures differ in GPS week (see [21:23]), not in a known
#                firmware property.
#   [13]     u8  reserved_13 = 0 (constant across RE corpus + EM7565).
#   [14]     u8  num_sv_family_a ∈ {0, 4, 5, 6, 8}
#   [15]     u8  flag_15 ∈ {0, 1}
#   [16]     u8  num_sv_fix ∈ {0..11} — F3-grounded as gps_svs_in_view:
#                tm_core.c "Visible SVs in view %d" 100% (RM500Q 526/526,
#                Wistron 6161/6161, SIM8202G 639/639; 4-6 distinct values).
#                Matches the populated-slot count on 2295/3195 records (72%);
#                on the remainder, populated is higher than byte[16]
#                (typical range: byte[16] < populated ≤ byte[18]).
#   [17]     u8  num_sv_subset ∈ {0..9}
#   [18]     u8  num_sv_tracked ∈ {0..12} — upper bound on populated
#                slot count; populated slots ≤ byte[18] on 3195/3195.
#   [19]     u8  aux_19
#   [20]     u8  aux_20
#   [21:23]  u16 gps_week (LE) — the GPS WEEK NUMBER.
#                fw_tag ([21]) and sub_type ([22]) below are its low / high
#                bytes, not an ASCII build-channel letter: 'm'/'n'/'o'/'t'/
#                'u'/'z' = 0x6D/6E/6F/74/75/7A with sub_type 0x09 are weeks
#                2413/2414/2415/2420/2421/2426. Grounded 173/173 against the
#                co-captured 0x13C4 gps_week (F3-grounded) over every capture
#                that carries a real week in both codes (the 8 others are
#                0xFFFF = week unknown); the corpus spans 2411..2437 in
#                calendar order, plus 1394/1397/1398 on 1024-wrapped Sierra
#                firmware (the MC7700's own AT!GPSLOC? date reads exactly
#                1024 weeks before the capture). 0 on empty records. 0x1509
#                byte[1:3] carries the same week.
#   [21]     u8  fw_tag — low byte of gps_week (name kept for API stability).
#   [22]     u8  sub_type — high byte of gps_week (= 0 only on empty records)
#   [23:71]  48B sv_slots — 12 slots × 4 bytes each:
#                - slot[i][0:2]  u16 LE sv_id
#                - slot[i][2:4]  u16 LE iode (back-compat alias `cno_metric`)
#                (sv_id and iode values fit in u8 range, hence the
#                 "every other byte is zero" pattern.)
#                Populated count matches byte[16] on 3195/3195 records.
#   [71:151] 80B reserved_tail = 0 (constant 3195/3195)
#
# v0x01 87B — Sierra MC7700 MDM9200, 730 records. Same [0:23] header
# positions (counts, nav_state byte[11]=0x10 on 680/730, gps_week 0x0575 =
# 1397); the per-SV table is 32 packed u8 (sv_id, iode) pairs at [23:87],
# contiguous from [23], sv_id strictly ascending in 1..32, zero-filled after
# (730/730). iode is frozen per SV (0 changes over 8,087 observations). AT
# ground truth: the run's AT!GPSSATINFO? GPS PRNs are all in the table (8/8
# run 1, 7/8 run 2); the table is a superset (ephemeris held for SVs not in
# view). The v0x02 "populated <= num_sv_tracked" bound does NOT hold on
# v0x01 (388/730).

@dataclass
class GnssSvCno14A6Slot:
    """One slot in the 12-slot SV table of 0x14A6.

    (The ``Cno`` in the class name is kept for API stability; the per-SV
    scalar is ``iode``, with ``cno_metric`` as a deprecated alias.)
    """
    sv_id: int         # u16 LE
    iode: int          # u16 LE (u8-range) — per-SV Issue Of Data, Ephemeris

    @property
    def cno_metric(self) -> int:
        """Deprecated back-compat alias for :attr:`iode`.

        The scalar is not C/N0: it is frozen per-SV across whole captures
        (0-1 changes over 600-1259 records, in stationary *and* moving
        drives) and reaches raw 235 — impossible for any dB-Hz scale — while
        co-temporal F3 (`mc_glodebits` CNo / `mc_meas` G_CNo) carries the
        *actual*, time-varying C/N0. The frozen-until-eph-refresh u8
        behaviour + the canonical name ``LOG_CGPS_SM_EPH_RANDOMIZATION_INFO_C``
        identify it as IODE. New code should read ``iode``.
        """
        return self.iode

    @property
    def is_populated(self) -> bool:
        return self.sv_id != 0 or self.iode != 0


@dataclass
class Diag0x14A6:
    """GNSS per-SV ephemeris (IODE) snapshot (0x14A6) — v0x02 151B / v0x01 87B.

    Every byte is exposed as a named field or structured slot.
    """
    log_time: int
    version: int
    flag_1: int
    stats_header: bytes      # [2:10]
    reserved_10: int         # [10]    constant 0
    nav_state: int           # [11:13] u16 LE — latching nav-maturity flag
    reserved_13: int         # [13]    constant 0
    num_sv_family_a: int     # [14]
    flag_15: int             # [15]
    num_sv_fix: int          # [16]  see module docstring for semantics
    num_sv_subset: int       # [17]
    num_sv_tracked: int      # [18]  upper bound on populated slots
    aux_19: int              # [19]
    aux_20: int              # [20]
    fw_tag: int              # [21]  low byte of gps_week
    sub_type: int            # [22]  high byte of gps_week
    gps_week: int            # [21:23] u16 LE — GPS week
    sv_slots: list[GnssSvCno14A6Slot]  # v2: 12 x u16 pairs [23:71]; v1: 32 x u8 pairs [23:87]
    reserved_tail: bytes     # v2: [71:151]; v1: b"" (the table fills the record)
    payload_size: int

    @property
    def gps_eph_have_mask(self) -> int:
        """[2:6] u32 — GPS SVs with valid ephemeris (F3 tm_core.c ``HV``)."""
        return int.from_bytes(self.stats_header[0:4], 'little')

    @property
    def gps_eph_vb_mask(self) -> int:
        """[6:10] u32 — GPS SV mask the F3 prints as ``VB`` (tm_core.c)."""
        return int.from_bytes(self.stats_header[4:8], 'little')

    @property
    def gps_svs_in_view(self) -> int:
        """[16] — F3 tm_core.c "Visible SVs in view %d"; same byte as num_sv_fix."""
        return self.num_sv_fix

    @property
    def counter(self) -> int:
        """Back-compat alias (prior stub named byte[2] as `counter`)."""
        return self.stats_header[0]

    @property
    def reserved_mid(self) -> bytes:
        """Back-compat: the [10:14] blob, formerly a single `reserved_mid`
        field. Reconstructed from reserved_10 / nav_state / reserved_13
        so existing consumers (and the zero-region tests on the RE-corpus
        fixtures) keep working."""
        return bytes((self.reserved_10,)) + \
            self.nav_state.to_bytes(2, 'little') + \
            bytes((self.reserved_13,))

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x14A6',
            'log_time': self.log_time,
            'version': self.version,
            'flag_1': self.flag_1,
            'stats_header': self.stats_header.hex(),
            'gps_eph_have_mask': self.gps_eph_have_mask,
            'gps_eph_vb_mask': self.gps_eph_vb_mask,
            'gps_svs_in_view': self.gps_svs_in_view,
            # reserved_mid_zero now means the *truly*-reserved bytes [10] and
            # [13] are zero; [11:13] is the named nav_state field.
            'reserved_mid_zero': self.reserved_10 == 0 and self.reserved_13 == 0,
            'nav_state': self.nav_state,
            'num_sv_family_a': self.num_sv_family_a,
            'flag_15': self.flag_15,
            'num_sv_fix': self.num_sv_fix,
            'num_sv_subset': self.num_sv_subset,
            'num_sv_tracked': self.num_sv_tracked,
            'aux_19': self.aux_19,
            'aux_20': self.aux_20,
            'fw_tag': self.fw_tag,
            'sub_type': self.sub_type,
            'gps_week': self.gps_week,
            'sv_slots': [
                # `iode` is the canonical key. `cno_metric` is a
                # deprecated back-compat mirror for existing consumers (e.g. the
                # 0x147D f32-outlier `_cno_summary` walker + external JSON
                # readers); it carries the identical value and will be dropped
                # once those consumers migrate to `iode`.
                {'sv_id': s.sv_id, 'iode': s.iode, 'cno_metric': s.iode}
                for s in self.sv_slots if s.is_populated
            ],
            'reserved_tail_zero': not any(self.reserved_tail),
            'payload_size': self.payload_size,
        }


@register(
    0x14A6, domain="gnss",
    name="0x14A6",
    description="GNSS per-SV ephemeris (IODE) snapshot (0x14A6) — v0x02 151B / v0x01 87B "
                "(MDM9200), fully decoded; [21:23] is the GPS week",
    version=11,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE. v0x02 (151 B) from a 3195-record cross-chipset corpus: "
        "EG12-GT, EG18-NA SDX20 V2, EG25-G MDM9207, EM7511 MDM9650, EP06-A MDM9x07, "
        "FN980 SDX55, LM960 SDX20 (5 firmware generations), RM500Q SDX65; every byte "
        "named, no body_raw. Header fields are F3-grounded: tm_core.c prints "
        "'LM's GPS eph. req suppressed: Nd=%x,HV=%x,VB=%x' (and 'GPS Eph. req to "
        "protocol-sub: …') ~450 ticks before each record, with HV = u32 [2:6] and "
        "VB = u32 [6:10] on 100% of paired records over six captures (RM500Q-AE, "
        "SIM8202G, Wistron 81UMV91B1, EG18-NA, EG25-G, Carcom-G1); 'Visible SVs in "
        "view %d' = [16] 100% (4-6 distinct values per capture); 'PE: Slow Clock "
        "Time: Wk=%u' = gps_week. [21:23] is the GPS week (fw_tag/sub_type are its "
        "bytes), also matching the co-captured F3-grounded 0x13C4 gps_week on 173/173 "
        "captures (weeks 2411..2437 in calendar order; 0xFFFF = unknown; 1024-wrapped "
        "1394..1398 on old Sierra firmware), so it carries no enum. The sv_slots table "
        "is the first 12 PRNs of the HV mask in order (all but 16/6197 Wistron "
        "records), i.e. the have-valid-ephemeris set; sv_id equals the GPS PRN, "
        "verified against NMEA GSV on an RM520N-GL (SDX62) with a live 3D fix. The "
        "per-SV scalar is IODE (Issue Of Data, Ephemeris), inferred from behaviour: "
        "frozen per SV across whole captures (at most one change, at the fix/no-fix "
        "transition) and reaching raw 235, impossible for a dB-Hz scale, while the "
        "co-temporal 0x79 F3 carries the time-varying C/N0 (mc_glodebits, mc_meas); "
        "the canonical name LOG_CGPS_SM_EPH_RANDOMIZATION_INFO_C agrees. A 0x99/QSR4 "
        "F3 IODE print or a value step at an ephemeris refresh would confirm it; "
        "cno_metric is kept as a deprecated alias. nav_state [11:13] is a latching "
        "flag: zero across the RE corpus, 0x0110 on Sierra EM7565 (one clear-to-set "
        "transition per capture, orthogonal to the SV counts) and 0x0010 on a Quectel "
        "EG18-NA capture; kept raw, not enum-gated. v0x01 (87 B, Sierra MC7700 "
        "MDM9200, 730 records): same [0:23] header, 32 packed u8 (sv_id, iode) pairs "
        "at [23:87]; the run's AT!GPSSATINFO? GPS PRNs are all in the table, iode is "
        "frozen per SV (0/8087 changes) and the table follows the HV mask on 648/648. "
        "The version byte is coupled to the payload size. reserved bytes and the "
        "reserved tail are verified zero in tests but not enforced via "
        "field_invariants (layer-2 enum gating covers scalar fields only)."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    # version, flag_1, stats_header, reserved_10, nav_state, reserved_13,
    # num_sv_family_a, flag_15, num_sv_fix, num_sv_subset, num_sv_tracked,
    # aux_19, aux_20, fw_tag, sub_type, sv_slots, reserved_tail,
    # payload_size — 151/151 bytes named across 12-chipset corpus + EM7565.
    fields_identified=19,
    fields_parsed=19,
    field_invariants={
        # byte 0 is the version, coupled to the payload size (v0x02 151B,
        # v0x01 87B). Layer-2 protection against drift; the parser-body gate
        # is the primary defense.
        "version": {"enum": sorted(_14A6_LAYOUT)},
        "payload_size": {"enum": sorted(v[0] for v in _14A6_LAYOUT.values())},
        # fw_tag / sub_type carry no enum: they are the low/high bytes of the
        # GPS week at [21:23], so every new calendar week would read as a
        # fresh invariant violation. The corpus already spans weeks
        # 2411..2437 (fw_tag 0x6b..0x85).
    },
)
def parse_0x14a6(log_time: int, data: bytes) -> Diag0x14A6 | None:
    if not data:
        return None
    # Hard gate on the version byte before the SV-slot loop, coupled to the
    # size — v0x02 = 151B, v0x01 = 87B (MDM9200); a valid size under the
    # other version byte is rejected.
    layout = _14A6_LAYOUT.get(data[0])
    if layout is None or len(data) != layout[0]:
        return None
    _, width, count = layout
    fmt = '<HH' if width == 4 else '<BB'
    slots: list[GnssSvCno14A6Slot] = []
    for i in range(count):
        sv_id, iode = unpack_from(fmt, data, _SLOT_BASE + i * width)
        slots.append(GnssSvCno14A6Slot(sv_id=sv_id, iode=iode))
    table_end = _SLOT_BASE + width * count
    return Diag0x14A6(
        log_time=log_time,
        version=data[0],
        flag_1=data[1],
        stats_header=bytes(data[2:10]),
        reserved_10=data[10],
        nav_state=unpack_from('<H', data, 11)[0],
        reserved_13=data[13],
        num_sv_family_a=data[14],
        flag_15=data[15],
        num_sv_fix=data[16],
        num_sv_subset=data[17],
        num_sv_tracked=data[18],
        aux_19=data[19],
        aux_20=data[20],
        fw_tag=data[21],
        sub_type=data[22],
        gps_week=unpack_from('<H', data, 21)[0],
        sv_slots=slots,
        reserved_tail=bytes(data[table_end:]),
        payload_size=len(data),
    )
