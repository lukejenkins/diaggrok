"""0x1D23 — LOG_GNSS_POWER_PROFILING_REPORT_C (v0x04, F3-grounded).

**Canonical name** ``LOG_GNSS_POWER_PROFILING_REPORT_C`` (``0xD23 +
LOG_1X_BASE_C``), as listed in the public zukgit GPS modem-log blog post.
It sits between ``LOG_GNSS_POWER_STATUS_REPORT_C`` (0x1D22) and
``LOG_GNSS_MC_JAMMER_STATUS_C`` (0x1D24) — a GNSS measurement-engine code,
not NR5G ML1 despite its position in the code range.

Layout — v0x04, fixed 54 B, corpus-wide (847/847 records, 19 captures,
7 firmware builds on RM520N-GL SDX62, EM9291 SDX65, T99W640, T99W373 and
Inseego M3100):

  [0]       u8    version = 4
  [1:5]     u32   reserved_1 — 0 on 847/847 records (NOT pinned; see below)
  [5:32]    27×u8 pwrprf_u8[0..26] — PwrPrf columns 0..26
  [32:36]   u32   pwrprf_u32_27    — PwrPrf column 27 (0 corpus-wide)
  [36:38]   u16   pwrprf_u16_28    — PwrPrf column 28 (DPO-scoped, see below)
  [38:42]   u32   dpo_dwell_ms     — PwrPrf column 29 == F3 ``DPO_DWELL``
  [42:46]   u32   tail_u32_a       — CANDIDATE receiver time stamp
  [46:50]   u32   tail_u32_b       — raw
  [50:54]   u32   tail_u32_c       — CANDIDATE receiver time stamp

F3 ground truth
---------------
Two in-capture oracles, both on the Inseego M3100 (100 % 0x99
resolution), which emits this code at **1 Hz**
— once per DPO (duty-cycled GNSS) sleep entry — instead of the once-per-
session edge seen on every other chipset:

* **``mgp_gpm.cpp:4180`` — ``PwrPrf,<30 comma-separated values>``** (0x79
  plaintext, pre-rendered by the firmware) co-fires ~5 µs before each
  record: **166/166** records in one M3100 capture plus **1/1** in an
  M3100 walk capture.
  The mapping is strictly positional and exact on every column of every
  pair: column *i* is the u8 at ``+5+i`` for i = 0..26, column 27 the u32 at
  +32, column 28 the u16 at +36, column 29 the u32 at +38. That fixes every
  field boundary from +5 to +42. The print carries **no labels**, so
  columns 0..28 are F3-*silent* on meaning and are surfaced raw
  (``pwrprf_u8`` / ``pwrprf_u32_27`` / ``pwrprf_u16_28``), not named.
* **``mc_receiver.c:2155`` — ``DPO_DWELL:%u``** fires in the same burst and
  equals the u32 at +38 on **166/166** (the only F3 argument out of every
  site within 1.1 s that matches a ≥5-valued column on ≥97 % of records).
  ``mc_tick.c:3762 DPO sleep timer started N`` + DPO_DWELL ≈ 1000 ms on each
  cycle, so +38 is the **DPO awake dwell in ms within the 1 s duty cycle**
  → ``dpo_dwell_ms``.

Trigger (F3, all chipsets): every record lands on the MC receiver power-
down transition — ``Eval Rcvr. Curr 12 Des 0`` → ``MC Rcvr States. MC:0``
(full receiver OFF) on RM520N-GL, T99W640 (two builds) and T99W373,
and ``Curr 12 Des 5`` → ``MC:5`` (DPO sleep) on the M3100. On the non-DPO
chipsets +36..+41 (``pwrprf_u16_28``, ``dpo_dwell_ms``) are 0 on every record
— they are DPO-cycle fields.

0x60 oracle: ``EVENT_GNSS_RCVR_STATE`` (event id 2603) co-fires with
598/599 records of an M3100 survey capture (payload ``u32 time, u32 state``;
state 6 = wake, 5 = DPO sleep, matching F3 ``MC:5``). Its u32 is in the
same time domain as ``tail_u32_a`` / ``tail_u32_c`` — A sits a median 4
units after the wake event's stamp, C a median 54 — but equals neither
(0/599), so the tail is exposed raw. The unit is not settled: bits 31:15
advance by exactly 1 per 1 s record (560/599), yet wake→sleep spans a
median 273 units against 283 ms of DIAG time, which is not a plain 32 kHz
SCLK. On non-DPO chipsets the tail holds unrelated magnitudes (and is all
zero on T99W640), so it is CANDIDATE only.

Neither QCSuper nor SCAT decodes 0x1D23 (silent on the
M3100 captures).

Invariants: ``version`` (byte 0) and ``payload_size`` are pinned. The
body is **not** pinned — size invariance ≠ format invariance; ``reserved_1``
and ``pwrprf_u32_27`` are 0 on every record today but a populated capture
may legitimately fill them.
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

V4_VERSION = 0x04
V4_SIZE = 54
PWRPRF_U8_OFFSET = 5
PWRPRF_U8_COUNT = 27


@dataclass
class Diag0x1D23:
    """0x1D23 — LOG_GNSS_POWER_PROFILING_REPORT_C v0x04."""
    log_time: int
    version: int
    reserved_1: int             # u32 [1:5] — 0 corpus-wide, not pinned
    pwrprf_u8: tuple[int, ...]  # 27×u8 [5:32] — F3 PwrPrf columns 0..26
    pwrprf_u32_27: int          # u32 [32:36] — PwrPrf column 27
    pwrprf_u16_28: int          # u16 [36:38] — PwrPrf column 28 (DPO-scoped)
    dpo_dwell_ms: int           # u32 [38:42] — PwrPrf col 29 == F3 DPO_DWELL
    tail_u32_a: int             # u32 [42:46] — CANDIDATE receiver time stamp
    tail_u32_b: int             # u32 [46:50] — raw
    tail_u32_c: int             # u32 [50:54] — CANDIDATE receiver time stamp
    payload_size: int

    @property
    def pwrprf_columns(self) -> list[int]:
        """The 30 values in firmware ``PwrPrf,`` F3 print order."""
        return [*self.pwrprf_u8, self.pwrprf_u32_27, self.pwrprf_u16_28,
                self.dpo_dwell_ms]

    @property
    def dpo_active(self) -> bool:
        """True when the report closes a DPO duty cycle (M3100-style 1 Hz)."""
        return self.dpo_dwell_ms != 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x1D23",
            "log_time": self.log_time,
            "version": self.version,
            "reserved_1": self.reserved_1,
            "pwrprf_u8": list(self.pwrprf_u8),
            "pwrprf_u32_27": self.pwrprf_u32_27,
            "pwrprf_u16_28": self.pwrprf_u16_28,
            "dpo_dwell_ms": self.dpo_dwell_ms,
            "dpo_active": self.dpo_active,
            "tail_u32_a": self.tail_u32_a,
            "tail_u32_b": self.tail_u32_b,
            "tail_u32_c": self.tail_u32_c,
            "payload_size": self.payload_size,
        }


@register(
    0x1D23, domain="gnss",
    name="0x1D23",
    description="LOG_GNSS_POWER_PROFILING_REPORT_C (0x1D23) v0x04 — GNSS power-profiling report at receiver power-down / DPO sleep; PwrPrf columns + DPO dwell F3-grounded",
    version=2,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail="Canonical name LOG_GNSS_POWER_PROFILING_REPORT_C per the public zukgit GPS modem-log blog. Field boundaries +5..+42 F3-grounded 167/167 against the firmware's own 'PwrPrf,<30 values>' print (mgp_gpm.cpp:4180) and +38 against 'DPO_DWELL:%u' (mc_receiver.c:2155) on Inseego M3100; tail u32s share the EVENT_GNSS_RCVR_STATE (0x60 id 2603) time domain, kept raw. 847/847 records on 7 firmware builds across 5 modem families are v0x04, 54 B.",
    source_url="",
    issues=(),
    fields_identified=35,
    fields_parsed=35,
    field_invariants={
        "version": {"enum": [V4_VERSION]},
        "payload_size": {"enum": [V4_SIZE]},
    },
)
def parse_0x1d23(log_time: int, data: bytes) -> Diag0x1D23 | None:
    if len(data) != V4_SIZE:
        return None
    if data[0] != V4_VERSION:
        return None
    end = PWRPRF_U8_OFFSET + PWRPRF_U8_COUNT
    tail_a, tail_b, tail_c = unpack_from('<3I', data, 42)
    return Diag0x1D23(
        log_time=log_time,
        version=data[0],
        reserved_1=unpack_from('<I', data, 1)[0],
        pwrprf_u8=tuple(data[PWRPRF_U8_OFFSET:end]),
        pwrprf_u32_27=unpack_from('<I', data, 32)[0],
        pwrprf_u16_28=unpack_from('<H', data, 36)[0],
        dpo_dwell_ms=unpack_from('<I', data, 38)[0],
        tail_u32_a=tail_a,
        tail_u32_b=tail_b,
        tail_u32_c=tail_c,
        payload_size=len(data),
    )
