"""GNSS search-strategy task-allocation parser (0x148A) — one record per constellation.

Canonical name ``LOG_GNSS_SEARCH_STRATEGY_TASK_ALLOCATION_C``; emitted by the
firmware's ``mc_gnsssearchstrategy.c`` once per constellation per strategy cycle
(4 records / cycle on a GPS+GLO+BDS+GAL engine). Every on-wire version shares ONE
family layout:

    +0        u8   version (format discriminator; size is fixed per version)
    +1..+3    raw  per-cycle counter (increments by 1-3 per cycle; raw)
    +4        raw  0 on 80% of records; takes dozens of values on v0x07/6a/79/7b
    +5        u8   constellation id — 0=GPS 1=GLO 2=BDS 3=GAL
    +6, +7    raw  two small per-constellation counts (raw)
    +8..+103  u64[12] SV-category bitmask block (bit i = PRN i+1, LE u64)
    ...       version-specific task-allocation counters + SrchStrategySelect lists

    Size  Ver   Silicon                                                    grounding
    ────  ────  ─────────────────────────────────────────────────────────  ───────────────────
    182B  0x02  MDM9600 (Sierra MC7700) — GPS (+GLONASS, 151 recs)          AT!GPSSATINFO elev
    258B  0x07  MDM9607 (Quectel EG25-G)                                    F3 plaintext
    288B  0x05  MDM9230 (Sierra EM7455/MC7455)                              F3 legacy-QSR 0x92
    329B  0x68  MDM9150 (WNC 81UMV91M21 — incl. the same modem inside the    F3 plaintext, 2 devices
                Kapsch RIS-9260), MDM9250 (Ficosa Carcom-G1),
                MDM9650 (Sierra EM7511/MC7411/EM7565)
    334B  0x6a  SDX20 V2 (Quectel EG18-NA)                                  F3 plaintext
    387B  0x79  SDX55/SDX62 (RM500Q-AE, FN980m, …)                          F3 plaintext
    388B  0x7a  SDX65 (Inseego M3100)                                       in-capture 0x1477
    397B  0x7b  SDX72 (Foxconn T99W640)                                     F3 plaintext
    379B  0x78  SDX24 (Quectel EM160R, 2 firmware builds)                   F3 plaintext, 4 captures

=== MASK WORD ORDER =======================================================
The firmware prints each mask as ``0x%08x 0x%08x`` = (HIGH word, LOW word) —
shown by the BDS/GAL complements (BDS ``t_SvAssignNever 0xffffffff 0xc0000000``
+ ``t_SvUnknown 0x00000000 0x3fffffff`` partition PRN 1..64 only when read hi,lo).
The record stores the mask as a little-endian u64 (low word FIRST). Searching
for ``hi@o, lo@o+4`` — the print order — matches GPS/GLO masks (high word 0)
4 bytes EARLY, giving ``(lo << 32) | junk`` at +52/+84/+92/+168/+176/+192/+216
instead of the true slots 4 bytes later.

=== F3 / ORACLE GROUND TRUTH ===============================================
Method: pair each F3 print with the co-temporal (±800k ticks, measured lag 0 ms)
record of ITS OWN constellation (stream-order state machine over
``Strategylist - GNSS : X`` / ``X Task Allocation`` headers; SDX72 prints the
constellation as an arg). Masks: 64-bit (hi,lo) value searched as LE u64;
order-proof when both words ≠ 0. Counters: value tracked across ≥3 distinct
values at 100% hit rate.

Mask block (identical offsets on EVERY version):
    +8   t_SvAssignNever      F3 order-proof: v0x68 (2 devices), v0x79, v0x6a, v0x05
    +16  t_SvNoExist          F3: v0x68, v0x79, v0x6a, v0x05 (GPS: 0x1000 = PRN 13)
    +24  t_SvKnownNotVisible  F3: v0x68, v0x79, v0x6a, v0x05
    +32  t_SvKnownVisible     F3 pair w/ +56 (values coincide on every F3 capture);
                              resolved on v0x7a: +32 ⊋ +56, +56 == 0x1477 tracked set 45/45
    +40  t_SvUnhealthy        F3 v0x05 legacy site 6147 (low word, 2 distinct values)
    +48  raw                  {t_SvUnknown | t_ShallowUnKnown} coincide on v0x68/v0x05;
                              SDX72 "ShallowUnknown Svs" == +48 885/885 + 371/371;
                              v0x78 SEPARATES them: +48 == t_SvUnknown (see below)
    +56  t_Dedicated          == tracked SVs (0x1477, v0x7a, 45/45); see +32
    +64, +72, +80  raw        (Deep / DeepMfs / ShallowKnown candidates; on v0x7a
                              +64 == +80 == +32 minus +56)
    +88  raw                  {t_SvUnknown | t_ShallowUnKnown} (see +48);
                              v0x78: +88 == t_ShallowUnKnown
    +96  t_SvAbove5Degrees    F3: v0x68, v0x79, v0x6a, v0x05; AT elevation on v0x02:
                              0<e<=5 deg SVs in +96 7/152 vs in +32 150/152
Structural invariants — measured on EVERY record of a single corpus walk
(676 captures, 1,053,850 records, all 8 pre-v0x78 versions):
    100% on every version: Above5 ⊆ KnownVisible; KnownNotVisible ⊆ AssignNever
      (GPS lo word); AssignNever ∪ NoExist ∪ KnownVisible ∪ Unknown(+48) = all 32
      GPS PRNs (a cold engine parks PRNs in Unknown); constellation byte ∈ {0..3};
      acq-run DedicatedCount == popcount(t_Dedicated) (v0x05 + v0x68, 376,297 recs).
    93–99.99% (transient mid-update states): Dedicated ⊆ KnownVisible,
      Unknown ∩ KnownVisible = ∅, KnownVisible disjoint from AssignNever/NoExist.
    NoExist vs AssignNever: neither disjoint nor nested on any version (NoExist ⊆
      AssignNever on 0–90% of GPS records per version) — not asserted.

SrchStrategySelect lists: ShouldRunList/RunningList at +172/+180 (v0x68, v0x6a,
v0x79 F3; v0x7a 0x1477 tracked ⊆ both; v0x7b raw) and +208/+216 on v0x05 (F3
legacy sites 1135/1137).

Task-allocation counters (u8 unless noted; per-version table ``_COUNTERS``):
    v0x07  +132 Allocated, +133 u32 Requested, +234 Search      (F3, EG25-G)
           Requested is u32, not u16: 6,919 GAL records (9.9%) carry
           138240 = 0x21C00, which a u16 read truncates to 7168 — same bytes as the
           F3-grounded v0x05 GAL record (``0c 00 1c 02 00``).
    v0x05  +164 Allocated, +165 u32 Requested, +169 Dedicated, +187 Search,
           +195..+199 AcqCount/DedicatedCount/FirstSvCount/TSwCount/SvAssignable (F3)
    v0x68  +132 Total, +137 Dedicated, +150 ShallowUnknown, +230 Search,
           +159..+163 AcqCount/DedicatedCount/FirstSvCount/TSwCount/SvAssignable (F3, 2 devices)
    v0x6a/v0x79/v0x7b  +132 Total/Alloc, +230 Search (+150 ShallowUnknown on 6a/7b) (F3)
    v0x02/v0x7a  +148/+132 Allocated, +153/+137 Dedicated, +171/+230 Search —
           no F3 exists: v0x02 shares v0x05's F3-grounded sub-struct geometry
           (base+0 Allocated, +5 Dedicated, +23 Search); v0x7a shares v0x68's.
The Dedicated byte is always followed by an equal twin (+138 / +170 / +154) —
100% of records on every version; surfaced raw via ``body_raw``.
Allocated == Dedicated + Search is STATE-DEPENDENT, not an identity: corpus
walk 100% on v0x79/7a/7b, 99.99% v0x68, 98.6% v0x07, 95.9% v0x02, 94.2% v0x6a,
67.6% v0x05 (it holds 1504/1504 on the F3-paired EM7455 capture; tracking
states allocate other task classes). On v0x6a the +137 byte is NOT Dedicated
(F3 tied +133/+138 with 3 values), so v0x6a exposes no task_dedicated.

v0x78 (379B, SDX24 Quectel EM160R) — F3-grounded. Four EM160R captures hold
744 v0x78 records with plaintext F3 (2 firmware builds). Burst-exact pairing (each ``Strategylist - GNSS : X`` burst against the
co-temporal record of constellation X, lag p50 ~56k ticks), 744 bursts:
    +8 AssignNever, +32 KnownVisible, +40 Unhealthy, +48 t_SvUnknown,
    +56 Dedicated, +64 t_Deep, +80 t_ShallowKnown, +88 t_ShallowUnKnown,
    +172 ShouldRunList, +180 RunningList — 100% on all 4 captures.
SDX24 is the first chipset whose F3 tells +48 from +88 (they agree on only
41–81% of bursts) and +64 from +80 (49–88%), so v0x78 names them
(``_VERSION_MASKS``). +16 NoExist, +24 KnownNotVisible, +72 DeepMfs and +96
Above5 were all-zero on every burst: the family offsets are consistent with the
F3 but not proven by it, so they keep the family names without new evidence.
Counters, each matched by its own ``X Task Allocation`` prefix (100%, ≥3
distinct values on every capture unless noted): +132 Total, +137 Dedicated (=
+138 twin), +140 Deep (2–3 distinct only), +145 Shallow, +150 ShallowUnknown,
+230 Search; acq run ``AcqCnt/DedCnt/TSwCnt/SvAssignCnt`` at +159/+160/+162/
+163 (Acq and TSw are equal on every record, so +159/+162 follow v0x68's order;
FSvCnt was always 0 and is not exposed).
Two odd-size v0x78 records stay rejected: the 341B one is a splice artifact
(its tail is the F3 string ``PE2ME: AlmNeed … RcvrInUSA 2\0mc_srchstrategy.c``
glued onto a truncated record), and the 365B one comes from one of the same
firmware builds.

Size-invariance ≠ format-invariance: each version's size is fixed across the
current corpus, but a future firmware may ship a new layout in the same length
under a new version byte — ``field_invariants`` pins the version enum.

Log name: LOG_GNSS_SEARCH_STRATEGY_TASK_ALLOCATION_C
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

LOG_GNSS_SEARCH_STRATEGY = 0x148A

# version -> fixed payload size (every record of that version in the corpus).
_PROFILES: dict[int, int] = {
    0x02: 182,   # MDM9600 (MC7700)
    0x05: 288,   # MDM9230 (EM7455/MC7455)
    0x07: 258,   # MDM9607 (EG25-G)
    0x68: 329,   # MDM9150 / MDM9250 / MDM9650
    0x6a: 334,   # SDX20 V2 (EG18-NA)
    0x79: 387,   # SDX55 / SDX62
    0x7a: 388,   # SDX65 (M3100)
    0x7b: 397,   # SDX72 (T99W640)
    0x78: 379,   # SDX24 (EM160R), F3-grounded
}
_VERSIONS = tuple(sorted(_PROFILES))

_CONSTELLATION_OFF = 5
_CONSTELLATIONS = {0: "GPS", 1: "GLO", 2: "BDS", 3: "GAL"}

# The 12-slot u64 SV-category mask block — same offsets on every version.
_MASK_BLOCK: tuple[int, ...] = tuple(range(8, 104, 8))
# Named (F3 / oracle-grounded) slots; +48/+64/+72/+80/+88 stay raw in sv_masks.
_NAMED_MASKS: dict[int, str] = {
    8: "sv_assign_never",
    16: "sv_no_exist",
    24: "sv_known_not_visible",
    32: "sv_known_visible",
    40: "sv_unhealthy",
    56: "sv_dedicated",
    96: "sv_above_5_degrees",
}
# Per-version extra named masks, where that version's own F3 separates slots the
# family leaves raw (v0x78: SDX24 tells Unknown from ShallowUnknown, Deep from
# ShallowKnown). Exposed in ``extra_masks`` / to_dict.
_VERSION_MASKS: dict[int, dict[int, str]] = {
    0x78: {48: "sv_unknown", 64: "sv_deep", 80: "sv_shallow_known", 88: "sv_shallow_unknown"},
}
# SrchStrategySelect (ShouldRunList, RunningList) u64 slots.
_RUN_LISTS: dict[int, tuple[int, int]] = {
    0x05: (208, 216),
    0x68: (172, 180),
    0x6a: (172, 180),
    0x79: (172, 180),
    0x7a: (172, 180),
    0x78: (172, 180),
}
# Raw-only run-list slots (present, not grounded on this version's own oracle).
_RAW_RUN_LISTS: dict[int, tuple[int, int]] = {0x7b: (172, 180)}

# Per-version task-allocation counters: name -> (offset, struct fmt).
_ACQ_RUN = ("acq_count", "dedicated_count", "first_sv_count", "tsw_count", "sv_assignable")
_COUNTERS: dict[int, dict[str, tuple[int, str]]] = {
    0x02: {"task_allocated": (148, "B"), "task_dedicated": (153, "B"), "task_search": (171, "B")},
    0x05: {"task_allocated": (164, "B"), "task_requested": (165, "<I"),
           "task_dedicated": (169, "B"), "task_search": (187, "B"),
           **{n: (195 + i, "B") for i, n in enumerate(_ACQ_RUN)}},
    0x07: {"task_allocated": (132, "B"), "task_requested": (133, "<I"), "task_search": (234, "B")},
    0x68: {"task_allocated": (132, "B"), "task_dedicated": (137, "B"),
           "shallow_unknown_allocated": (150, "B"), "task_search": (230, "B"),
           **{n: (159 + i, "B") for i, n in enumerate(_ACQ_RUN)}},
    0x6a: {"task_allocated": (132, "B"), "shallow_unknown_allocated": (150, "B"),
           "task_search": (230, "B")},
    0x79: {"task_allocated": (132, "B"), "task_search": (230, "B")},
    0x7a: {"task_allocated": (132, "B"), "task_dedicated": (137, "B"), "task_search": (230, "B")},
    0x7b: {"task_allocated": (132, "B"), "shallow_unknown_allocated": (150, "B"),
           "task_search": (230, "B")},
    0x78: {"task_allocated": (132, "B"), "task_dedicated": (137, "B"),
           "deep_allocated": (140, "B"), "shallow_allocated": (145, "B"),
           "shallow_unknown_allocated": (150, "B"), "task_search": (230, "B"),
           "acq_count": (159, "B"), "dedicated_count": (160, "B"),
           "tsw_count": (162, "B"), "sv_assignable": (163, "B")},
}


@dataclass
class Diag0x148A:
    """GNSS search-strategy task-allocation record (0x148A) — one constellation.

    ``sv_masks`` maps every mask-block slot (+8..+96) and the version's
    SrchStrategySelect slots to its raw LE u64 (bit i = PRN i+1); the grounded
    slots are also exposed by name. Counters are per-version (``_COUNTERS``);
    a counter not grounded for this version is None.
    """
    log_time: int
    version: int
    size: int
    constellation_id: int
    constellation: str | None
    sv_masks: dict[int, int] = field(default_factory=dict)
    sv_assign_never: int = 0
    sv_no_exist: int = 0
    sv_known_not_visible: int = 0
    sv_known_visible: int = 0
    sv_unhealthy: int = 0
    sv_dedicated: int = 0
    sv_above_5_degrees: int = 0
    should_run_list: int | None = None
    running_list: int | None = None
    counters: dict[str, int] = field(default_factory=dict)
    extra_masks: dict[str, int] = field(default_factory=dict)
    body_raw: bytes = b""

    @property
    def task_requested(self) -> int | None:
        return self.counters.get("task_requested")

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'type': 'Diag0x148A',
            'log_time': self.log_time,
            'version': self.version,
            'payload_size': self.size,
            'constellation_id': self.constellation_id,
            'constellation': self.constellation,
        }
        for name in _NAMED_MASKS.values():
            d[name] = getattr(self, name)
        if self.should_run_list is not None:
            d['should_run_list'] = self.should_run_list
            d['running_list'] = self.running_list
        d.update(self.counters)
        d.update(self.extra_masks)
        d['sv_masks'] = {f'+{o}': v for o, v in self.sv_masks.items()}
        return d


@register(
    LOG_GNSS_SEARCH_STRATEGY,
    domain="gnss",
    name="0x148A",
    description=(
        "GNSS search-strategy task-allocation (0x148A) — one record per "
        "constellation (+5); 9-version family (0x02/05/07/68/6a/78/79/7a/7b) sharing a "
        "u64 SV-category mask block at +8..+96 (AssignNever/NoExist/KnownNotVisible/"
        "KnownVisible/Unhealthy/Dedicated/Above5Degrees named) + per-version task "
        "counters and SrchStrategySelect run lists; F3/AT/0x1477-grounded"
    ),
    version=5,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE. One per-constellation family layout across 9 "
        "versions (MDM9600 through SDX72): a u64 SV-category mask block at "
        "+8..+96 (F3 prints masks hi,lo; the record stores LE u64) plus "
        "per-version task counters and run lists. Grounded on each version's "
        "own F3 where it exists (v0x07, v0x6a, v0x79, v0x7b plaintext; v0x05 "
        "legacy-QSR 0x92 sites; v0x68 plaintext on 2 devices: the 81UMV91M21 "
        "unit, also seen inside the Kapsch RIS-9260, and the MDM9250 "
        "Carcom-G1; v0x78 burst-exact on 4 SDX24 EM160R captures / 2 firmware "
        "builds, whose F3 separates +48 Unknown / +88 ShallowUnknown and +64 "
        "Deep / +80 ShallowKnown, named per version in extra_masks). v0x02 "
        "(MC7700) is grounded by an AT!GPSSATINFO elevation witness and v0x7a "
        "(M3100) by in-capture 0x1477 tracked-SV sets. Structural invariants "
        "hold on all 1,053,850 records of a 676-capture corpus walk. Raw "
        "slots: +48/+64/+72/+80/+88 outside v0x78, and v0x7b run lists."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    field_invariants={
        "version": {"enum": list(_VERSIONS)},
        # corpus walk: every one of 1,053,850 records has +5 in 0..3
        "constellation_id": {"enum": [0, 1, 2, 3]},
    },
)
def parse_0x148a(log_time: int, data: bytes) -> Diag0x148A | None:
    """Parse a GNSS search-strategy task-allocation (0x148A) payload.

    byte[0] is the version; each version has one fixed size. Returns None for an
    unknown version or a size that doesn't match the version's profile (the
    registry WARNs on that drop).
    """
    if len(data) < 104:
        return None
    version = data[0]
    size = len(data)
    if _PROFILES.get(version) != size:
        return None

    cid = data[_CONSTELLATION_OFF]
    rec = Diag0x148A(
        log_time=log_time,
        version=version,
        size=size,
        constellation_id=cid,
        constellation=_CONSTELLATIONS.get(cid),
        body_raw=data[1:],
    )
    for off in _MASK_BLOCK:
        rec.sv_masks[off] = unpack_from("<Q", data, off)[0]
    for off, name in _NAMED_MASKS.items():
        setattr(rec, name, rec.sv_masks[off])
    run = _RUN_LISTS.get(version)
    for off in run or _RAW_RUN_LISTS.get(version, ()):
        rec.sv_masks[off] = unpack_from("<Q", data, off)[0]
    if run:
        rec.should_run_list = rec.sv_masks[run[0]]
        rec.running_list = rec.sv_masks[run[1]]
    for name, (off, fmt) in _COUNTERS.get(version, {}).items():
        rec.counters[name] = unpack_from(fmt, data, off)[0]
    for off, name in _VERSION_MASKS.get(version, {}).items():
        rec.extra_masks[name] = rec.sv_masks[off]
    return rec
