"""0x4179 -- WCDMA PN search results (LOG_WCDMA_PN_SEARCH_EDITION_2).

**F3-grounded identity.** The canonical name is right: this is a WCDMA
searcher record, not an LTE neighbour-measurement record despite its pairing
with LTE ML1 logs (see Emission below). On the LM960 (SDX20, v=0x05) the firmware's own F3 prints pin the record byte for
byte, at the identical DIAG tick, on every F3-bearing record (6/6):

* ``wsrch.c:16351 "PN Logging: num_tasks:%d rxd:%d pd:%d len:%d tot_pks:%d
  num_pks_task:%d num_rslts_task:%d"`` fires once per 0x4179 record. It is the
  log-packet builder: ``num_pks_task = 6`` is the six-slot array, ``len`` is
  the DIAG log length (12-byte log header + payload), ``num_tasks`` is the
  number of search tasks the searcher ran, ``num_rslts_task`` the result sets
  per task.
* ``srchacq.c:2221 "ACQ PN Done: AGC:%d num_tasks:%d task1-Pos0 %d Eng0 %d"``
  names the first task's first peak: ``Pos0``/``Eng0`` equal task 0's
  ``array_a[0]`` / ``array_b[0]`` exactly (285064/179, 79472/195, 202484/198,
  264452/181, 18032/217, 36420/144 -- six for six).
* ``srchsetutil.c:3328 "print set 4 on carr 0 cell_idx[%d] => cell ... {carr:
  %d, freq: %d, psc: %d, ...}"`` lists the PN search set immediately before the
  record: one UARFCN per record (= ``uarfcn``, prefix u16), one PSC per task
  (= each task preamble's ``scr_code >> 4``).

So, per record: **one UARFCN**, ``num_tasks`` search **tasks** (one per
candidate cell = primary scrambling code), and per task ``num_rslts_task``
**result sets** of six **peaks** -- each peak a PN position in chip x8 units
(``peak_pos_cx8``, 0..307199 = 38400 chips x 8; corpus max 307196) with its
searcher energy (``peak_energy``), sorted descending by energy, zero-filled
below the reported count. The values are not frequencies or per-cell RSRP,
and the six slots are six multipath peaks of ONE scrambling code, not six
cells.

Two firmware-side facts the record cannot state on its own, both F3-witnessed:

* **The log is capped at 20 tasks.** F3 ``num_tasks`` read 22/22/23/23/24
  while every matching record carried ``num_tasks = 20`` in a 1448-byte
  payload (v=0x05); tasks beyond the twentieth are simply not logged.
  ``tasks_capped`` flags a record at the cap.
* ``results_per_task`` is 1 in 682/787 v=0x05 corpus records and 2 in the
  105 records of 147 bytes (one task, two result sets, preamble byte[1] = 3).
  Both blocks of a 147-byte record are the same task's results, not a prior
  measurement window.

Record layout (both versions; ``P`` = prefix size, ``G`` = gap, ``T`` =
trailer, ``B`` = num_tasks, ``R`` = results_per_task)::

    prefix[P]                                  P = 29 (v=0x05) / 15 (v=0x08)
    B x preamble[11]                           one per task, contiguous
    gap[G]                                     0x00 fill, G = 11 / 3
    (B-1) x ( R x peaks[48] + trailer[T] )     T = 12 / 4
    R x peaks[48]                              last task, no trailer

    size == (P + G - T) + B * (11 + T + 48 R)  ->  v=0x05: 28 + B(23 + 48R)
                                                  v=0x08: 14 + B(15 + 48R)

    peaks[48]   = u32 LE peak_pos_cx8[6] + u32 LE peak_energy[6]
    preamble[11]= 23 | flags | 00 | word[2] | scr_code u16 LE | c0 00 | f1 | f2
                  scr_code = psc * 16 (5,347/5,347 corpus preambles; all 512
                  PSCs seen); f2 == 0 marks the LAST task's preamble;
                  flags == 3 on the two-result-set form; word[2] is unnamed.
    prefix      : version @0; num_tasks @26 (v=0x05) / @12 (v=0x08);
                  uarfcn u16 LE @16 (v=0x05) / @8 (v=0x08) -- WCDMA band
                  UARFCNs corpus-wide (I/II/IV/V/VIII), F3-matched 6/6.

``num_tasks`` is read from the prefix AND cross-checked against the size law
(``num_tasks_mirror_ok``); ``results_per_task`` is derived from the size law
given ``num_tasks``. A payload SHORTER than the size law requires for the
prefix ``num_tasks`` (with R = 2 when the first preamble's flags == 3) is
truncated and returns None; a longer off-law payload still decodes only its
trailing 48 bytes. The peak-block gate (energies non-increasing, positions
< 2^19 with byte-2 <= 4) is the corpus invariant every real block satisfies;
a record with any failing block exposes ``tasks=[]`` rather than a
half-populated structure (size-vs-format invariance), while the last task's
last result set is always decoded into the top-level ``peak_*`` fields.

Emission: the WCDMA searcher runs during limited-service / idle IRAT cell
search and reselection, which is why this code emits on airplane cycles, SIM
power cycles, PLMN scans and drives and never on a steady LTE camp
(RM520N-GL). Its ~100 ms pairing with the LTE ML1 0x187B ``num_cells=1``
announcement is an LTE-idle -> WCDMA-search handoff,
not an LTE neighbour-measurement carrier.

**v=0x08 same-silicon F3 grounding.** The v=0x08 layout is not merely
structurally transferred from v=0x05: the searcher's
own ``srchacq.c "ACQ PN Done: AGC:%d num_tasks:%d task1-Pos0 %ld Eng0 %u"``
print pins the record on the SDX6x silicon the same way it pinned the SDX20
v=0x05, at the same DIAG tick (F3 leads the log by 0-3 ms):

* **RM520N-GL (SDX62)**, F3 100 % resolved: 15/15 records match ``tasks[0]`` peak-0 position AND energy
  byte for byte; ``num_tasks`` matches 13/15, the two exceptions being the
  20-task cap (F3 ``num_tasks`` 23, record logs 20, the peak values still exact)
  -- ``tasks_capped`` re-witnessed on v=0x08, on a different SoC than v=0x05.
* **T99W175 (SDX55)**, F3 100 % resolved: 4/4 records match ``num_tasks`` (10/11/8/1) and peak-0 position +
  energy exactly (SIM power cycle).

So ``num_tasks``, ``peak_pos_cx8`` and ``peak_energy`` are same-silicon
F3-grounded on v=0x08 (SDX62 + SDX55), not transferred. Two of the v=0x05
witnesses are simply not compiled into these builds -- ``wsrch.c "PN Logging"``
(the log-packet builder) and the ``srchsetutil.c`` set listing that names
freq/psc -- so ``uarfcn`` (WCDMA-band u16 @8 on every corpus record) and
``psc_list`` (psc*16 in every preamble) stay structurally grounded on v=0x08,
pending a build that prints the set listing. The searcher line moves per build
tree (v=0x05 LM960 ``srchacq.c:2221``; SDX55 ``:2269``; SDX62 ``:2278``).

Log name: LOG_WCDMA_PN_SEARCH_EDITION_2
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

_SUPPORTED_VERSIONS = frozenset({0x05, 0x08})
_BASE_SIZE_FOR_VERSION = {0x05: 99, 0x08: 77}
_PEAK_SLOTS = 6
_ARRAY_BYTES = _PEAK_SLOTS * 4  # 24
_PEAKS_BYTES = 2 * _ARRAY_BYTES  # 48: positions[6] + energies[6]
_PREAMBLE_SIZE = 11
#: Firmware log cap on tasks per record (F3-witnessed: num_tasks 22-24 logged
#: as 20 in a 1448 B v=0x05 payload; 124/787 corpus records sit at the cap).
_TASK_CAP = 20
#: chip x8 positions span one 10 ms WCDMA frame: 38400 chips x 8.
PN_POS_CX8_MAX = 38400 * 8  # 307200

# Per-version layout. c0 = prefix + gap - trailer is R-independent; the task
# stride is 11 + trailer + 48*R.
_LAYOUT = {
    0x05: dict(prefix=29, taskcount_off=26, uarfcn_off=16, gap=11, trailer=12),
    0x08: dict(prefix=15, taskcount_off=12, uarfcn_off=8, gap=3, trailer=4),
}
# Back-compat names some call sites / tests reference.
_TAIL_BYTES = _PEAKS_BYTES
for _v, _L in _LAYOUT.items():
    _L["c0"] = _L["prefix"] + _L["gap"] - _L["trailer"]
    _L["stride"] = _PREAMBLE_SIZE + _L["trailer"] + _PEAKS_BYTES  # R=1 stride
    _L["base"] = _BASE_SIZE_FOR_VERSION[_v]
    _L["blkcount_off"] = _L["taskcount_off"]
_MULTI_LAYER_PARAMS = {
    v: (_PREAMBLE_SIZE, L["trailer"], L["stride"]) for v, L in _LAYOUT.items()
}

_PRE_MARKER = 0x23
_PRE_CONST = b"\xc0\x00"


@dataclass
class PnSearchResult:
    """One result set of six PN peaks: position (chip x8) + searcher energy,
    energy-sorted descending, zero-filled below ``peaks_reported``."""
    array_a_raw: list[int]          # positions incl. zero-fill
    array_b_raw: list[int]          # energies incl. zero-fill
    peak_pos_cx8: list[int | None]  # None where energy == 0 (unreported slot)
    peak_energy: list[int | None]
    peaks_reported: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "array_a_raw": self.array_a_raw,
            "array_b_raw": self.array_b_raw,
            "peak_pos_cx8": self.peak_pos_cx8,
            "peak_energy": self.peak_energy,
            "peaks_reported": self.peaks_reported,
        }


@dataclass
class PnSearchTask:
    """One search task = one candidate cell (primary scrambling code) on the
    record's UARFCN, with ``results_per_task`` result sets."""
    preamble_raw: bytes
    psc: int                        # scr_code >> 4, 0..511
    scr_code: int                   # u16 LE at preamble[5:7] = psc * 16
    preamble_flags: int             # preamble[1]: 0 (one result set) / 3 (two)
    preamble_word_raw: bytes        # preamble[3:5], unnamed
    preamble_marker_ok: bool        # preamble[0] == 0x23
    preamble_const_ok: bool         # preamble[7:9] == c0 00
    preamble_flag_a: int            # preamble[9]  (0x04 / 0x00, unnamed)
    preamble_is_final: bool         # preamble[10] == 0 -> last task
    results: list[PnSearchResult]
    trailer_raw: bytes              # empty on the last task

    def to_dict(self) -> dict[str, Any]:
        return {
            "preamble_raw": self.preamble_raw,
            "psc": self.psc,
            "scr_code": self.scr_code,
            "preamble_flags": self.preamble_flags,
            "preamble_word_raw": self.preamble_word_raw,
            "preamble_marker_ok": self.preamble_marker_ok,
            "preamble_const_ok": self.preamble_const_ok,
            "preamble_flag_a": self.preamble_flag_a,
            "preamble_is_final": self.preamble_is_final,
            "results": [r.to_dict() for r in self.results],
            "trailer_raw": self.trailer_raw,
        }


@dataclass
class Diag0x4179:
    """0x4179 -- WCDMA PN search results record (see module docstring)."""
    log_time: int
    version: int
    payload_size: int
    header_size: int
    # Search tasks logged in this record (prefix byte) + size-law mirror.
    num_tasks: int
    num_tasks_mirror_ok: bool
    results_per_task: int
    tasks_capped: bool
    # Prefix. uarfcn is F3-grounded (6/6 LM960 v=0x05; WCDMA-band values on
    # every corpus record of both versions). The rest is raw / witness.
    prefix_raw: bytes
    uarfcn: int | None
    prefix_u16_at3: int | None      # u16 LE @[3:5], unnamed (NOT a counter)
    prefix_flag_a: int | None       # data[2]
    prefix_flag_b: int | None       # v=0x08 data[13]
    sub_format: int | None          # v=0x08 data[1] == 0x01 (RM520N-GL const)
    format_const_raw: bytes         # v=0x08 data[5:8] == 00 02 00
    prefix_tag: int | None          # v=0x08 data[14] == 0x01
    prefix_const_ok: bool
    block_trailers_zeroed: bool     # every non-last task trailer all-zero
    preambles: list[dict[str, Any]]
    gap_raw: bytes
    # Per-task PSC list (len == num_tasks on on-law records).
    psc_list: list[int]
    # The last task's last result set (the trailing 48 bytes), surfaced flat
    # for one-line consumers.
    peak_pos_cx8: list[int | None]
    peak_energy: list[int | None]
    peaks_reported: int
    array_a_raw: list[int]
    array_b_raw: list[int]
    header_raw: bytes
    middle_raw: bytes
    # Every task, in order (empty when the record is off-law or any peak
    # block fails the gate -- no half-populated structure).
    tasks: list[PnSearchTask] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x4179",
            "log_time": self.log_time,
            "version": self.version,
            "payload_size": self.payload_size,
            "header_size": self.header_size,
            "num_tasks": self.num_tasks,
            "num_tasks_mirror_ok": self.num_tasks_mirror_ok,
            "results_per_task": self.results_per_task,
            "tasks_capped": self.tasks_capped,
            "prefix_raw": self.prefix_raw,
            "uarfcn": self.uarfcn,
            "prefix_u16_at3": self.prefix_u16_at3,
            "prefix_flag_a": self.prefix_flag_a,
            "prefix_flag_b": self.prefix_flag_b,
            "sub_format": self.sub_format,
            "format_const_raw": self.format_const_raw,
            "prefix_tag": self.prefix_tag,
            "prefix_const_ok": self.prefix_const_ok,
            "block_trailers_zeroed": self.block_trailers_zeroed,
            "preambles": self.preambles,
            "gap_raw": self.gap_raw,
            "psc_list": self.psc_list,
            "peak_pos_cx8": self.peak_pos_cx8,
            "peak_energy": self.peak_energy,
            "peaks_reported": self.peaks_reported,
            "array_a_raw": self.array_a_raw,
            "array_b_raw": self.array_b_raw,
            "header_raw": self.header_raw,
            "middle_raw": self.middle_raw,
            "tasks": [t.to_dict() for t in self.tasks],
        }


def _peak_block_valid(array_a: list[int], array_b: list[int]) -> bool:
    """Corpus invariant every real 48-byte peak block satisfies: energies
    non-increasing across the 6 slots (zero-fill is naturally non-increasing),
    and on every reported slot the position has byte-3 == 0 and byte-2 <= 4
    (i.e. < 327680; the chip x8 range tops out at 307199)."""
    if not all(array_b[i] >= array_b[i + 1] for i in range(_PEAK_SLOTS - 1)):
        return False
    for a, b in zip(array_a, array_b):
        if b == 0:
            continue
        if (a >> 24) != 0 or ((a >> 16) & 0xff) > 4:
            return False
    return True


# Kept under its historical name for callers/tests that import it.
_block48_valid = _peak_block_valid


def _decode_result(data: bytes, off: int) -> PnSearchResult:
    a = list(unpack_from("<6I", data, off))
    b = list(unpack_from("<6I", data, off + _ARRAY_BYTES))
    pos: list[int | None] = []
    eng: list[int | None] = []
    n = 0
    for x, y in zip(a, b):
        if y == 0:
            pos.append(None)
            eng.append(None)
        else:
            pos.append(x)
            eng.append(y)
            n += 1
    return PnSearchResult(array_a_raw=a, array_b_raw=b, peak_pos_cx8=pos,
                          peak_energy=eng, peaks_reported=n)


def _decode_preamble(pre: bytes) -> dict[str, Any]:
    """Decode one 11-byte task preamble (see module docstring). Tolerant of a
    short slice: literals read as absent, psc as None, never raises."""
    if len(pre) < _PREAMBLE_SIZE:
        return {"preamble_raw": bytes(pre), "psc": None, "scr_code": None,
                "flags": None, "word_raw": b"", "marker_ok": False,
                "const_ok": False, "flag_a": None, "is_final": False}
    scr = unpack_from("<H", pre, 5)[0]
    return {
        "preamble_raw": bytes(pre),
        "psc": scr >> 4,
        "scr_code": scr,
        "flags": pre[1],
        "word_raw": bytes(pre[3:5]),
        "marker_ok": pre[0] == _PRE_MARKER,
        "const_ok": pre[7:9] == _PRE_CONST,
        "flag_a": pre[9],
        "is_final": pre[10] == 0,
    }


def _solve_layout(version: int, sz: int, tasks_from_prefix: int | None):
    """Return ``(num_tasks, results_per_task, mirror_ok, on_law)`` for a size.

    Tries R = 1 then R = 2 against ``size == c0 + B*(11 + T + 48R)``; a
    solution matching the prefix task count wins (mirror_ok), else the first
    integral solution (on_law, mirror False); else the prefix count (or 1)
    with both False -- an off-law size decodes only its trailing 48 bytes.
    """
    L = _LAYOUT[version]
    c0 = L["c0"]
    sols = []
    for r in (1, 2):
        stride = _PREAMBLE_SIZE + L["trailer"] + _PEAKS_BYTES * r
        if sz >= c0 + stride and (sz - c0) % stride == 0:
            sols.append(((sz - c0) // stride, r))
    for b, r in sols:
        if b == tasks_from_prefix:
            return b, r, True, True
    if sols:
        return sols[0][0], sols[0][1], False, True
    return (tasks_from_prefix or 1), 1, False, False


@register(
    0x4179, domain="wcdma-signal",
    name="0x4179",
    description=(
        "0x4179 -- WCDMA PN search results (LOG_WCDMA_PN_SEARCH_EDITION_2). "
        "F3-grounded: per record one UARFCN (prefix u16) "
        "and num_tasks search tasks, one per candidate primary scrambling code "
        "(task preamble scr_code = psc*16), each with results_per_task result "
        "sets of six energy-sorted PN peaks (peak_pos_cx8 in chip x8, 0..307199, "
        "+ peak_energy). Matched byte-for-byte to the firmware's own F3 on the "
        "LM960 SDX20: wsrch.c 'PN Logging: num_tasks/len/num_pks_task=6/"
        "num_rslts_task' fires once per record, srchacq.c 'ACQ PN Done: "
        "task1-Pos0 %%d Eng0 %%d' == task 0 peak 0 (6/6 records), and "
        "srchsetutil.c's set listing supplies the UARFCN + per-task PSC. Not an "
        "LTE neighbour-cell measurement; the 147 B form is one task with TWO "
        "result sets (not a prior window). Firmware caps the log at 20 tasks (F3 reports "
        "22-24) -> tasks_capped. v=0x05 (LM960 SDX20, EG25-G/EC25 MDM9607, "
        "EG95, FM101-GL, MC7411) size 28 + B(23+48R); v=0x08 (SDX55/SDX62 "
        "family) 14 + B(15+48R)."
    ),
    version=12,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "F3 grounding, v=0x05: on two LM960 (SDX20) F3 captures (6 records, "
        "F3 100%% resolved) every record sits at the identical DIAG tick as "
        "wsrch.c:16351 'PN Logging' and srchacq.c:2221 'ACQ PN Done'; the F3 "
        "'len' equals 12 + 28 + 71*num_tasks_F3 while the logged record is "
        "1448 B = 20 tasks (cap). Task-0 Pos0/Eng0 equal array_a[0]/array_b[0] "
        "on 6/6; UARFCN@16 equals the F3 set freq on 6/6 (4425, 4428, 4424, "
        "4416, 4421, 4362); the first six task PSCs equal scr_code>>4 on 6/6. "
        "Whole v=0x05 corpus (787 rec / 30 captures): 787/787 decode, 682 on "
        "the R=1 law, 105 x 147 B on the R=2 law (task preamble flags==3), "
        "5347/5347 preambles carry a valid psc*16 (512 distinct PSCs), max "
        "position 307196 < 307200, prefix UARFCNs all in WCDMA bands "
        "I/II/IV/V/VIII. F3 grounding, v=0x08 (same silicon): srchacq.c 'ACQ "
        "PN Done' task1-Pos0/Eng0 == tasks[0] peak-0 position+energy "
        "byte-for-byte on RM520N-GL SDX62 (srchacq.c:2278, 15/15 records; 2 "
        "at the 20-task cap re-witness tasks_capped) and T99W175 SDX55 "
        "(srchacq.c:2269, 4/4); num_tasks matches. wsrch.c 'PN Logging' and "
        "the srchsetutil.c set listing are not compiled into these SDX6x "
        "builds, so uarfcn@8 and psc*16 stay structurally grounded on v=0x08 "
        "(multi-block layout 80/80 v=0x08, prefix constants 28/28 RM520N-GL). "
        "Truncated payloads (shorter than the size law for the prefix "
        "num_tasks and the preamble-flag result-set count) return None "
        "(registry WARN)."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=25,
    fields_parsed=25,
    wigle_direct=True,
    wigle_roles=("identity", "signal"),
    supported_versions=sorted(_SUPPORTED_VERSIONS),
    field_invariants={
        "version": {"enum": sorted(_SUPPORTED_VERSIONS)},
    },
)
def parse_0x4179(log_time: int, data: bytes) -> Diag0x4179 | None:
    if len(data) < _PEAKS_BYTES + 1:
        return None
    version = data[0]
    if version not in _SUPPORTED_VERSIONS:
        return None
    base = _BASE_SIZE_FOR_VERSION[version]
    sz = len(data)
    if sz < base:
        return None
    header_size = base - _PEAKS_BYTES  # 51 for v=0x05, 29 for v=0x08
    L = _LAYOUT[version]
    prefix_size, gap_size, trailer_size = L["prefix"], L["gap"], L["trailer"]

    # The prefix declares num_tasks and the first preamble's
    # flags declare the result-set count (flags == 3 -> R = 2, the 147 B
    # form); the size law then gives the bytes the record must hold. A
    # shorter payload is truncated -> None (registry WARN) instead of the
    # off-law "decode only the trailing 48 bytes" fallback. Longer (off-law)
    # payloads are still tolerated.
    declared_tasks = data[L["taskcount_off"]]
    declared_r = 2 if data[prefix_size + 1] == 0x03 else 1
    if sz < L["c0"] + declared_tasks * (
            _PREAMBLE_SIZE + trailer_size + _PEAKS_BYTES * declared_r):
        return None

    # The last task's last result set always lives in the trailing 48 bytes.
    last = _decode_result(data, sz - _PEAKS_BYTES)
    header_raw = bytes(data[:header_size])
    middle_raw = bytes(data[header_size:sz - _PEAKS_BYTES])

    tasks_from_prefix = data[L["taskcount_off"]] if sz > L["taskcount_off"] else None
    num_tasks, results_per_task, mirror_ok, on_law = _solve_layout(
        version, sz, tasks_from_prefix)

    prefix_raw = bytes(data[:prefix_size])
    uarfcn = unpack_from("<H", data, L["uarfcn_off"])[0] if sz >= L["uarfcn_off"] + 2 else None
    prefix_u16_at3 = unpack_from("<H", data, 3)[0] if sz >= 5 else None
    prefix_flag_a = data[2] if sz > 2 else None
    if version == 0x08:
        prefix_flag_b: int | None = data[13] if sz > 13 else None
        sub_format: int | None = data[1] if sz > 1 else None
        format_const_raw = bytes(data[5:8]) if sz >= 8 else b""
        prefix_tag: int | None = data[14] if sz > 14 else None
        prefix_const_ok = (sub_format == 0x01 and format_const_raw == b"\x00\x02\x00"
                           and prefix_tag == 0x01)
    else:
        prefix_flag_b = None
        sub_format = None
        format_const_raw = b""
        prefix_tag = None
        prefix_const_ok = False

    preambles: list[dict[str, Any]] = []
    gap_raw = b""
    tasks: list[PnSearchTask] = []
    if on_law:
        for i in range(num_tasks):
            off = prefix_size + i * _PREAMBLE_SIZE
            preambles.append(_decode_preamble(data[off:off + _PREAMBLE_SIZE]))
        gap_off = prefix_size + num_tasks * _PREAMBLE_SIZE
        gap_raw = bytes(data[gap_off:gap_off + gap_size])
        results_off = gap_off + gap_size
        task_stride = _PEAKS_BYTES * results_per_task + trailer_size
        gates_pass = True
        for i in range(num_tasks):
            t_off = results_off + i * task_stride
            results = []
            for r in range(results_per_task):
                res = _decode_result(data, t_off + r * _PEAKS_BYTES)
                if not _peak_block_valid(res.array_a_raw, res.array_b_raw):
                    gates_pass = False
                    break
                results.append(res)
            if not gates_pass:
                break
            is_last = i == num_tasks - 1
            tr_off = t_off + _PEAKS_BYTES * results_per_task
            trailer = b"" if is_last else bytes(data[tr_off:tr_off + trailer_size])
            p = preambles[i]
            tasks.append(PnSearchTask(
                preamble_raw=p["preamble_raw"], psc=p["psc"] if p["psc"] is not None else -1,
                scr_code=p["scr_code"] if p["scr_code"] is not None else -1,
                preamble_flags=p["flags"] if p["flags"] is not None else -1,
                preamble_word_raw=p["word_raw"], preamble_marker_ok=p["marker_ok"],
                preamble_const_ok=p["const_ok"],
                preamble_flag_a=p["flag_a"] if p["flag_a"] is not None else -1,
                preamble_is_final=p["is_final"], results=results, trailer_raw=trailer,
            ))
        if not gates_pass:
            tasks = []

    psc_list = [p["psc"] for p in preambles if p["psc"] is not None]
    block_trailers_zeroed = all(
        all(byte == 0 for byte in t.trailer_raw) for t in tasks
    )

    return Diag0x4179(
        log_time=log_time,
        version=version,
        payload_size=sz,
        header_size=header_size,
        num_tasks=num_tasks,
        num_tasks_mirror_ok=mirror_ok,
        results_per_task=results_per_task,
        tasks_capped=num_tasks >= _TASK_CAP,
        prefix_raw=prefix_raw,
        uarfcn=uarfcn,
        prefix_u16_at3=prefix_u16_at3,
        prefix_flag_a=prefix_flag_a,
        prefix_flag_b=prefix_flag_b,
        sub_format=sub_format,
        format_const_raw=format_const_raw,
        prefix_tag=prefix_tag,
        prefix_const_ok=prefix_const_ok,
        block_trailers_zeroed=block_trailers_zeroed,
        preambles=preambles,
        gap_raw=gap_raw,
        psc_list=psc_list,
        peak_pos_cx8=last.peak_pos_cx8,
        peak_energy=last.peak_energy,
        peaks_reported=last.peaks_reported,
        array_a_raw=last.array_a_raw,
        array_b_raw=last.array_b_raw,
        header_raw=header_raw,
        middle_raw=middle_raw,
        tasks=tasks,
    )
