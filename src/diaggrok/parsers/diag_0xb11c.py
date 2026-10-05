"""0xB11C — LTE LL1 per-subframe firmware timeline (XO/Ts timestamps, subframe, O_STMR).

Every size class is one record per LTE subframe (1 ms cadence) whose u32
words are **hardware-timer stamps** of LL1 firmware processing for that
subframe, plus the subframe number.

## What the record is

Consecutive records advance word 0 by exactly one millisecond of a timer:
**19,200 ticks** (19.2 MHz XO / VSTMR) on the 632 B and 760 B layouts,
**30,720 ticks** (30.72 MHz, LTE ``Ts``) on the 272 / 400 / 416 B layouts.
Byte 0 — the legacy ``counter`` — is therefore the **low byte of that timer
stamp**, which is why it takes all 256 values uniformly; it was never an
SFN or transaction id and never a DIAG version (``version_less=True``
stands; the real layout key is ``payload_size``).

Three layouts, dispatched on ``payload_size``:

  ======  ===========  ========  =============================================
  size    layout       timebase  observed on (2,445,651-record corpus)
  ======  ===========  ========  =============================================
  760 B   ``xo``       19.2 MHz  LM960 (SDX20), EG12-GT, EG18-NA  1,316,537
  632 B   ``xo``       19.2 MHz  EM7565/EM7511 (MDM9x50), MC7411, FM101 771,636
  416 B   ``ts416``    30.72     MC7455/EM7455 (MDM9x30)               335,972
  400 B   ``ts400``    30.72     EP06-A, AC791L, RM520N-class          3,535
  272 B   ``ts272``    30.72     SC200E                               17,887
  ======  ===========  ========  =============================================

Whole-corpus check (2,445,750 records / 164 sessions): across every
layout the subframe index advances by exactly +1 on 100% of the 2,385,100
record pairs 1 ms apart, and on ``xo`` the O_STMR word advances +30,720 on
99.65% of them.

Field captures also contain 84 one-off sizes (HDLC misframes); the parser
returns None for them, so the registry warns instead of the
``payload_size`` invariant dropping them silently.

### ``xo`` layout (632 B / 760 B) — F3-GROUNDED

  off   field               ground
  ===   ==================  ==================================================
  0     timeline_ts         u32 low word of the 19.2 MHz XO counter.
                            **F3-GROUND** (``vstmr_epoch.c:183`` "VSTMR epoch
                            update at 0x%06x%08x"): the printed XO low word
                            leads the co-timed record's word 0 by 2.9-4.4 ms
                            on 1,509/1,509 events (EM7565) and 1,157/1,157
                            (LM960) — same clock.
  12    frame_subframe_idx  LTE subframe 0-9. **F3-GROUND**
                            (``lte_LL1_cmd_proc_sys.c`` "Doppler Init req :
                            subframe_num=%d"): record subframe == F3
                            subframe_num + 6 (mod 10) on 210/210 (EM7565)
                            and 147/165 (LM960; the rest ±1, nearest-record
                            jitter) co-timed events.
  16    state_flag          {0,1,2}, ≥98% zero (CANDIDATE, unlabelled).
  72    ustmr24_ts          24-bit XO-domain stamp == (word0 + ~12,750) mod
                            2^24 on every record (structural).
  80    o_stmr_ts           LTE O_STMR in Ts (30.72 MHz): +30,720/record.
                            **F3-GROUND** (``gts.c`` "GTS: OstmrDiff SysFN
                            ( %lu ) ..."): the printed SysFN O_STMR sits a
                            constant ~2.67 subframes after the co-timed
                            record's word @80 (98.5% of 325 EM7565 / 99.6%
                            of 248 LM960 events).
  408+  task_slots          16-byte slots to end of record (22 in 760 B, 14 in
                            632 B), each all-zero or ``{kind, xo_ts, a, b}``.
                            Corpus (8,236,714 populated slots): kind 1-3
                            dominate, kind 4/5 ~5%; ``xo_ts`` lies within
                            ±2 subframes of word 0 on >99.5% (a small tail
                            of stale stamps). ``a``/``b`` small (CANDIDATE
                            durations, unlabelled — exposed raw).

Every other word between 4 and 404 is either a word-0-relative XO stamp or
a small duration/count; they are left in ``body_raw`` (no F3 site labels
them).

### ``ts400`` (400 B), ``ts272`` (272 B), ``ts416`` (416 B) — STRUCTURAL

word 0 is the 30.72 MHz stamp (+30,720/record); the subframe index is u32 @16
(``ts400`` / ``ts272``) or @116 (``ts416``), each duplicated later in the
record (@212 / @164 / @176 respectively). No F3 site in the 416 B corpus (0 F3-bearing
captures); these layouts are structurally grounded only.

## Name

The canonical log name is ``LOG_LTE_LL1_SERVING_CELL_TTL_RESULTS``; a
newer item-type list calls it ``LOG_LTE_LL1_FAP_UL_TIMING``. The content (a
per-subframe LL1 processing timeline) fits a timing/profiling log; no
time-tracking-loop *result* (timing offset estimate) was identified.

Log name: LOG_LTE_LL1_SERVING_CELL_TTL_RESULTS
Also known as: LOG_SERVING_CELL_TTL_RESULTS, LOG_LTE_LL1_FAP_UL_TIMING
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


#: ``payload_size`` -> layout key. Byte 0 is a timer LSB, never a version.
_LAYOUT = {760: "xo", 632: "xo", 400: "ts400", 272: "ts272", 416: "ts416"}
#: Tick rate of word 0 per layout (measured: +19,200 / +30,720 per 1 ms record).
_TIMEBASE_HZ = {"xo": 19_200_000, "ts400": 30_720_000, "ts272": 30_720_000,
                "ts416": 30_720_000}
#: Offset of the u32 LTE subframe index per layout.
_SUBFRAME_OFF = {"xo": 12, "ts400": 16, "ts272": 16, "ts416": 116}
#: ``xo`` layout: 16-byte task slots run from here to the end of the record.
_XO_SLOT_BASE = 408


@dataclass
class Diag0xB11C:
    """LTE LL1 per-subframe firmware timeline (see the module docstring).

    ``layout`` is ``"xo"`` (632/760 B, 19.2 MHz XO stamps), ``"ts400"``
    (400 B), ``"ts272"`` (272 B) or ``"ts416"`` (416 B), all 30.72 MHz. Any
    other size is not decoded: the parser returns None.
    ``timeline_ts`` ticks at ``timebase_hz``. Stamps in ``task_slots`` are
    given relative to ``timeline_ts`` (``xo_ts_rel``, signed XO ticks).
    """
    log_time: int
    counter: int            # byte[0] == timeline_ts & 0xFF (timer LSB), kept for
                            # back-compat; NOT an SFN and NOT a DIAG version
    config_word: int        # legacy u32 @4 (a word-0-relative stamp on "xo")
    data_density: float
    payload_size: int
    body_raw: bytes
    frame_subframe_idx: int | None = None
    state_flag: int | None = None
    layout: str | None = None
    timebase_hz: int | None = None
    timeline_ts: int | None = None
    ustmr24_ts: int | None = None
    o_stmr_ts: int | None = None
    task_slots: list[dict[str, int]] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB11C",
            "log_time": self.log_time,
            "counter": self.counter,
            "config_word": self.config_word,
            "data_density": self.data_density,
            "payload_size": self.payload_size,
            "body_raw": self.body_raw,
            "frame_subframe_idx": self.frame_subframe_idx,
            "state_flag": self.state_flag,
            "layout": self.layout,
            "timebase_hz": self.timebase_hz,
            "timeline_ts": self.timeline_ts,
            "ustmr24_ts": self.ustmr24_ts,
            "o_stmr_ts": self.o_stmr_ts,
            "task_slots": self.task_slots,
        }


@register(
    0xB11C,
    name="0xB11C",
    description=(
        "LTE LL1 per-subframe FW timeline — timer stamp (19.2 MHz XO on "
        "632/760 B, 30.72 MHz Ts on 272/400/416 B), subframe index, O_STMR, "
        "task slots (F3-grounded)"
    ),
    version=6,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Five layouts keyed on payload_size (272/400/416/632/760 B); word 0 "
        "is a hardware timer stamp stepping +19,200 (632/760 B, XO) or "
        "+30,720 (272/400/416 B, Ts) per 1 ms record, so byte 0 (`counter`) "
        "is its LSB and the log is version-less. F3-grounded on the xo "
        "layout in two F3-armed captures (EM7565 632 B, LM960 760 B): "
        "vstmr_epoch.c VSTMR XO leads word 0 by 2-4.4 ms on 2,666/2,666 "
        "events; gts.c O_STMR SysFN sits 2.67 subframes after word @80 on "
        "98.5-99.6%; lte_LL1_cmd_proc_sys.c Doppler Init subframe_num + 6 == "
        "word @12 (mod 10) on 357/375. The 272/400/416 B layouts are "
        "structurally grounded only. Any other size (e.g. a truncated "
        "record) returns None (registry warning)."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=12,
    fields_parsed=12,
    field_invariants={
        "payload_size": {"enum": [272, 400, 416, 632, 760]},
        "frame_subframe_idx": {"range": [0, 9]},
        "state_flag": {"enum": [0, 1, 2]},
    },
    # byte-0 is the LSB of a free-running timer stamp (NOT a DIAG version);
    # payload_size is the layout key (layer-2 drops any foreign size).
    version_less=True,
    wigle_direct=False,
    wigle_roles=("rat-context",),
)
def parse_0xb11c(log_time: int, data: bytes) -> Diag0xB11C | None:
    # The layout is keyed purely on payload_size, so
    # a size outside _LAYOUT (a truncated record, an HDLC misframe, or a new
    # layout) cannot be decoded — return None (registry WARN) instead of a
    # size-agnostic stub that layer-2's payload_size enum would drop silently.
    if len(data) not in _LAYOUT:
        return None
    counter = data[0]  # timer-stamp LSB, NOT a version (see docstring)
    if len(data) >= 8:
        config_word = unpack_from('<I', data, 4)[0]
    elif len(data) >= 2:
        config_word = data[1]
    else:
        config_word = 0
    if len(data) > 2:
        nonzero = sum(1 for b in data[2:] if b != 0)
        total = max(len(data) - 2, 1)
        density = round(nonzero / total, 2)
    else:
        density = 0.0

    out = Diag0xB11C(
        log_time=log_time,
        counter=counter,
        config_word=config_word,
        data_density=density,
        payload_size=len(data),
        body_raw=data[1:],
    )
    layout = _LAYOUT.get(len(data))
    if layout is None:
        return out
    ts0 = unpack_from('<I', data, 0)[0]
    out.layout = layout
    out.timebase_hz = _TIMEBASE_HZ[layout]
    out.timeline_ts = ts0
    sfi = unpack_from('<I', data, _SUBFRAME_OFF[layout])[0]
    if layout == "xo":
        sf = unpack_from('<I', data, 16)[0]
        if sfi <= 9 and sf <= 2:
            out.frame_subframe_idx = sfi
            out.state_flag = sf
        out.ustmr24_ts = unpack_from('<I', data, 72)[0]
        out.o_stmr_ts = unpack_from('<I', data, 80)[0]
        slots = []
        for i, off in enumerate(range(_XO_SLOT_BASE, len(data) - 15, 16)):
            kind, xo_ts, a, b = unpack_from('<4I', data, off)
            if kind == xo_ts == a == b == 0:
                continue
            rel = (xo_ts - ts0) & 0xFFFFFFFF
            slots.append({
                "slot": i,
                "kind": kind,
                "xo_ts_rel": rel - (1 << 32) if rel >= 1 << 31 else rel,
                "a": a,
                "b": b,
            })
        out.task_slots = slots
    elif sfi <= 9:
        out.frame_subframe_idx = sfi
    return out
