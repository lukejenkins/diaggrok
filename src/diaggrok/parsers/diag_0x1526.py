"""GNSS navigation measurement report parser (0x1526).

Modern 54-byte fixed-size record, **version byte 0x02** — 22.01M records over
770 captures (exhaustive corpus walk; every v0x02 record
is 54 B — the manifest's 22..2058 B "v0x02" outliers are single misframed records
in one kismet stress capture, not a layout). A legacy 44-byte v=0x01 variant
exists on the Sierra MC7700 (see below).

## What this log is

0x1526 is a **per-satellite GNSS measurement-engine record**, NOT a per-fix
summary. The GNSS measurement engine emits one record per (satellite,
measurement-task) per epoch, so a single 1 Hz epoch produces dozens of records
(~66/s observed on an RM520N-GL sky-fix capture: ~18.7 measurement blocks/epoch
× a handful of SVs each). Byte 1 is therefore a per-SV id, not an SV count
(it is erratic and exceeds 32 when read as one), and bytes 32-35 are the low
word of a receiver clock, not a float (near-unique ±1e38 when read as f32).

### The 54-byte layout (offsets are LE)

| Off | Sz | Field                | Status     | Meaning |
|-----|----|----------------------|------------|---------|
| 0   | 1  | `version`            | confirmed  | always 0x02 (Layer-1 gate) |
| 1   | 1  | `sv_id`              | verified   | satellite id **in the namespace set by `meas_task_id`** — GPS PRN, Galileo E-PRN, raw SBAS PRN, or GLONASS FCN+8 |
| 2   | 1  | `aux_b2_raw`         | raw        | 0x00 on SDX-class; **populated in 100 % of records on MDM9x07 / MDM9230 / MDM9240** (per-task values, e.g. EG25-G {14,20,7,…}) — semantics unknown, surfaced raw |
| 3   | 1  | `meas_task_id`       | partial    | measurement-task / signal-job discriminator (see task map) |
| 4   | 1  | `signal_marker` lo   | confirmed  | 0x02 always |
| 5   | 1  | `signal_marker` hi   | partial    | 0x00 single-signal; **0x02 or 0x03 ⇔ the 2nd-signal pair b46-53 is present** (509/509). F3 shows it selects which slot the engine reports: 0x03 → primary slot (233/246), 0x02 → 2nd slot (22/25) |
| 6-7 | 2  | `meas_age_companion` | partial    | block-level state, bijectively paired with `meas_age_accum`; b6>b24 always |
| 8-23| 16 | `aux_b8_23_raw`      | raw        | all zero on SDX-class; **partly populated on MDM9x07 / MDM9230 / MDM9240** (EG25-G: u32@16 in 100 %, u32@8/u32@20 in ~12 %) — semantics unknown, surfaced raw |
| 24-25| 2 | `meas_age_accum`     | confirmed  | measurement-age / accumulated-drift accumulator (block-constant); grows at an exact per-task rate while unmeasured, resets after a valid measurement |
| 26-27| 2 | reserved             | confirmed  | 0x0000 (so field is u16, not u32) |
| 28-29| 2 | `meas_uncertainty`   | partial    | per-SV noise/uncertainty word; weak, per-task-dominated anti-correlation with C/N0 (pooled r −0.14) |
| 30-31| 2 | reserved             | confirmed  | 0x0000 |
| 32-35| 4 | `rcvr_time` lo       | verified   | LOW 32 bits of the measurement-engine **FCount** (Q16 ms) |
| 36-37| 2 | `rcvr_time` hi       | verified   | HIGH 16 bits of the same counter |
| 38-41| 4 | `cn0_dbhz`           | partial    | **pre-adjustment** C/N0 in dB-Hz (f32); 0x00000000 ⇒ no valid measurement ⇒ None. NOT the value the engine reports (F3 matches it in only 19 %) |
| 42-45| 4 | `cn0_adj_dbhz`       | verified   | **the C/N0 the measurement engine reports**: `mc_peak.c` `CNo` == `(int)(cn0_adj·10)` on 10 794/10 858 F3-joined records, 8 SoC families. = `cn0_dbhz − k·0.1` dB, k signed. −30.0 is a no-signal floor (F3 prints `CNo: 0`) |
| 46-49| 4 | `cn0_sig2_dbhz`      | partial    | 2nd-signal C/N0; present iff `signal_marker` hi ∈ {0x02, 0x03} |
| 50-53| 4 | `cn0_sig2_adj_dbhz`  | partial    | adjusted companion; **is** the engine-reported CNo when `signal_marker` hi == 0x02 (22/25 F3-joined) |

### The 48-bit receiver clock — it is the measurement-engine FCount

`rcvr_time = (u16@36 << 32) | u32@32`, in **1/65536-ms ticks (Q16 milliseconds)**
— `rcvr_time_ms = rcvr_time / 65536`. **`int(rcvr_time_ms)` is the GNSS
measurement engine's own 1 kHz frame count (FCount)** — the same counter the
firmware prints as `FC:` / `FCount:` in `mc_peak.c` and `PkFC:` in
`mc_multipath.c`, which is what makes the exact F3 join below possible (F3-VERDICT
v0x02). Proof: a constant 65 536 000 counts/s
slope for every SV; the high word (b36-37) increments by exactly 1 each time the
low word wraps (every 65.536 s); an RM520N-GL capture's clock span is
104 972 ms ≈ its ~105 s wall-clock duration. Byte 36 values such as
{0xf6,0xf7}, which can look like a validity mask, are the low byte of the high
word during that capture.

### `meas_task_id` (b3) — do NOT hardcode a constellation table

`meas_task_id` is a per-firmware **measurement-task** id, not a constellation
enum: its values differ across chipsets (RM520N-GL {0,1,3,5,12,30,33} vs em9190
{0,7,8,21,22,29}) even though each value's SV-id set maps cleanly to one
constellation. Constellation is therefore inferred from the `sv_id` namespace +
task behaviour, not from a fixed `meas_task_id` value. Observed RM520N-GL
(SDX62) map, for reference only: 0=GPS/QZSS L1CA blind-scan, 1=verify of
0, 3=GPS L1CA track, 5=SBAS L1 track (sv_id=133), 12=GLONASS L1OF track
(sv_id=FCN+8), 30=Galileo search/reacq, 33=Galileo E1 track. `(N, N+1)` values
are an (acquisition-scan, candidate-verify) stage pair of one search task.

The F3 join (below) labels each task with the firmware's own constellation name
and confirms the map is per-firmware. GPS track, for example, is task 3 on
MDM9x07 (EG25-G) and MDM9150, 43 on SDX55 (RM500Q-AE), and 37 on SDX20 (EG18-NA).
Track tasks are single-constellation, while search tasks (0/7/29/30) mix systems.

## Legacy variant - 44-byte v=0x01 on Sierra MC7700

A distinct **44-byte, version=0x01** variant of 0x1526 is emitted by the Sierra
MC7700 (MDM9200-class): 11,198 records across 5 captures, all `44|0x01`, one
modem model. It is the SAME per-satellite measurement-engine record as v=0x02,
with a shorter middle reserved region (the C/N0 quartet lands at the tail,
b28-43 = 4x f32, mirroring v2's b38-53). Decoded by `_parse_v01` into
`Diag0x1526V01`; the version enum is `{0x01, 0x02}` because v=0x01 has its OWN
layout (it is not parsed with the v=2 struct).

### The 44-byte v=0x01 layout (offsets are LE)

| Off  | Sz | Field                | Status     | Meaning |
|------|----|----------------------|------------|---------|
| 0    | 1  | `version`            | confirmed  | always 0x01 (Layer-1 gate) |
| 1    | 1  | `sv_id`              | verified   | satellite id in the `meas_task_id` namespace (range 2-135, GPS PRNs + SBAS) |
| 2    | 1  | reserved             | confirmed  | 0x00 (all 11,198 records) |
| 3    | 1  | `meas_task_id`       | partial    | measurement-task discriminator ({3,7,13,17,...}) |
| 4    | 1  | `signal_marker` lo   | confirmed  | 0x02 always |
| 5    | 1  | `signal_marker` hi   | confirmed  | 0x00 single-signal (9104), 0x03 dual-signal (2094) |
| 6-7  | 2  | `meas_age_companion` | partial    | block-level state (paired with b18-19) |
| 8-27 | 20 | reserved / partial   | unmapped   | middle region; b10-13/b27 zero; b22-25 vary; awaits MDM9200 ground truth |
| 28-31| 4  | `cn0_dbhz`           | verified   | primary C/N0 in dB-Hz (f32); 0x00000000 => absent => None. GSV-corroborated (mean 35.6, range 19.4-46.1 vs the modem's own GSV mean 38.4) |
| 32-35| 4  | `cn0_adj_dbhz`       | verified   | adjusted C/N0 = `cn0_dbhz - k*0.1` dB; present iff `cn0_dbhz` present |
| 36-39| 4  | `cn0_sig2_dbhz`      | verified   | 2nd-signal C/N0 (f32); present iff `signal_marker` hi == 0x03 (2094/2094 bijection) |
| 40-43| 4  | `cn0_sig2_adj_dbhz`  | verified   | adjusted companion of `cn0_sig2_dbhz` |

**F3-VERDICT v0x01: F3-ABSENT — no in-capture firmware oracle exists; grounded
on external NMEA GSV.** Both in-capture oracles were checked, not just F3:
- **F3 (0x79/0x92/0x93/0x98/0x99): 0 records across all 13 MC7700 captures.**
  This includes one raw-HDLC capture, where F3 would be visible if emitted
  (every F3 family 0) — a negative control showing the silicon emits none,
  not a DLF-path blind spot. The MDM9200 (2011-era) predates the EXT_MSG_F /
  QSR F3 machinery, so no firmware debug-print oracle is obtainable.
- **`0x60 DIAG_EVENT_REPORT_F`: not represented in the capture medium.** The 5
  v=0x01 captures are all flat-DLF, which frames LOG_F (0x10) records only — the
  event channel has no container slot there, so the second in-capture oracle
  cannot co-emit with 0x1526 either (a medium limitation on top of the silicon
  one).
- **QCSuper / SCAT: silent.** QCSuper decodes only position/RRC on these
  captures; neither tool field-decodes 0x1526 (GNSS Nav Meas Validity).

cn0_dbhz is therefore grounded on the modems' own co-captured NMEA GSV C/N0 (the
next-best independent oracle) - the same relationship verified for v=0x02 on the
RM520N-GL. 11,198/11,198 records parse (0 invariant violations), cn0_dbhz mean 35.6 / range 19.4-46.1, `signal_marker` hi==0x03
bijects 2094/2094 with cn0_sig2 presence; on the co-NMEA gnss_comparison window
DIAG mean 34.4 vs GSV mean 37.5 dB-Hz (DIAG lower = measurement-engine sees
weaker SVs than the receiver elects to report in GSV).

## Ground truth

(superseded for C/N0 identity by the F3-VERDICT below — the
distribution match here holds for both C/N0 floats, which differ by ~1 dB, so it
could not tell them apart.) `cn0_dbhz` and `sv_id` were checked against an
RM520N-GL sky-fix capture: pooled `cn0_dbhz`
(n=2120, 7.16–33.41 dB-Hz, mean 24.13) matches NMEA GSV (mean 25.41) and the F3
`onGnssSvCb` per-SV C/N0 (mean 24.92) with rank-perfect per-SV agreement, and
each `meas_task_id`'s `sv_id` set equals the matching F3 constellation SV set
exactly. See the RM520N-GL ground-truth recipe below.

## F3-VERDICT v0x02: GROUND

The firmware's own measurement-engine prints name this record's quantities, in
the same captures, joined on an **exact key** `(sv_id, int(rcvr_time_ms))` ==
`(SV, FCount)` — never nearest-timestamp.

* **`mc_peak.c` `<SYS> PeakProcess(n) SV: s, FC[ount]: f, CNo: c` — per-SV C/N0.**
  `c == max(0, (int)(f32(cn0_adj_dbhz) * 10.0f))` on **10 794 / 10 858** joined
  measured records across 16 captures from 8 SoC families: MDM9x07 (EG25-G),
  MDM9230 (EM7455), MDM9240 (EP06-A), MDM9150 (81UMV91-M21 — the RIS-9260 captures are the same
  81UMV91M21 modem, same physical unit; cross_device_for_logcodes: false,
  so they add uptime, not a second device), MDM9650
  (81UMV91-B1), SDX20 (EG18-NA, LM960), SDX24 (EM160R) and SDX55 (RM500Q-AE,
  SIM8202G-M2, FN980, EM9190). Every capture is 100 % except EM160R (514/576),
  EG18-NA and LM960 (one miss each).
  The EM160R misses are almost all **key collisions** (≥2 0x1526 records share
  one (SV, FC) and the single print belongs to one of them) plus the 0x0202
  rows below. The print is a **truncation**: residuals are only {0.0, +0.1 dB}
  under rounding, and f32 arithmetic is needed (30.1 → `CNo: 300`). The
  `cn0_dbhz` (b38-41) control matches only 2 030 / 10 858 (19 %). On EG25-G
  (MDM9607) it is systematically about +2.6 dB high, which is why the parser
  labels b38-41 *pre-adjustment* and b42-45 *reported*.
* **`signal_marker` hi 0x02 → the 2nd slot is the reported one:** on 0x0202
  records `CNo` matches `cn0_sig2_adj_dbhz` (22/25) and not `cn0_adj_dbhz`, even
  where the primary is stronger (21/25). That rules out a "max of two signals"
  rule.
* **`mc_multipath.c` `GNSS:g … SV:s PkFC:f` — identity + timing on SDX62**,
  where `PeakProcess` is QSR4-hashed and no build-matched qdb is held: RM520N-GL
  **850/850** print keys have a 0x1526 partner (all of them measured records,
  never an unmeasured one); RG520N-NA (CFW-3212) **82/84**. The firmware's
  constellation enum labels the tasks: task 3 ↔ `GNSS:0` (GPS), 12 ↔ `GNSS:1`
  (GLONASS), 33 ↔ `GNSS:3` (Galileo).

**Controls (why the join is not coincidental):**
* Shuffled-CNo null: 126 / 10 858 (1.2 %).
* Adjacent-epoch FC+1000 null: 0–12 % per capture.
* Decoy FC±1 and `sv_id ± 1`: collapse to 0 on the multipath join. On SDX55,
  FC+1 key hits occur from sub-ms neighbouring tasks, but their C/N0 content
  does not match.
* `PeakProcess` `Ms` / `SubMs` / `Speed` and `mc_multipath` `Pk` / `Steer` /
  `Res` match no 0x1526 field (|r| ≤ 0.75 and not consistent in sign across
  chipsets). So `meas_uncertainty` / `meas_age_*` stay partial.

**The other oracles — all checked:**
* **HAL `onGnssSvCb`** (`quectel_gps_api.cpp`, RM520N-GL): there is **no
  per-record identity** at any epoch offset (best ≈ 13 % vs a ≈ 5 % background).
  It is a downstream, smoothed product, so it is distribution-level
  corroboration only (the rank-perfect per-SV means).
* **`0x60 DIAG_EVENT_REPORT_F`: PRESENT, corroborating timing only.**
  `EVENT_GNSS_ME_MULTIPATH_ENV_IND` (3204) carries two u32 FCounts about 505 ms
  apart. On T99W640 (**SDX72** — no F3 oracle there) 42/42 event FCs fall
  inside the 0x1526 FC span, with the nearest record at a median of 7 ms. On
  EM9190 the figure is 67/68. That ties `rcvr_time` to the same 1 kHz ME
  counter on SDX72. Every other GNSS event is lifecycle-only
  (`GPS_PD_SESSION_*`, `FIX_*`, `GPS_LM_*`, `TLE_*`); none carries a per-SV C/N0.
* **Black-box (qcsuper/SCAT): NO COVERAGE.** On EG25-G, qcsuper emits only
  `0xB0C0` frames and SCAT prints no C/N0. Neither decodes 0x1526.

**Not grounded on this version:** SDX62 C/N0 (`PeakProcess` is hashed there)
and SDX72 C/N0 (no plaintext GNSS F3). The byte layout is identical (54 B, same
version), so the MDM/SDX20/24/55 identity transfers structurally but is not
claimed as measured there.

## Field status

All 54 bytes are assigned. Verified: version, sv_id, rcvr_time (= ME FCount),
cn0_adj_dbhz (the engine-reported C/N0), meas_age_accum. Partial (structure known,
physical meaning not fully pinned): cn0_dbhz (pre-adjustment C/N0), meas_task_id,
meas_age_companion, meas_uncertainty, signal_marker, the 2nd-signal C/N0 pair.
Raw (populated on MDM9x07/9230/9240 only, semantics unknown): b2, b8-23.

Naming note: the name `LOG_DTV_ISDB_TRAFFIC_LOST` (digital-TV broadcast) that
an older name table assigns to this code, listed below, does not fit. The
parser's `LOG_GNSS_NAV_MEAS_VALIDITY` constant + the RE observation are the
grounded reading — this is a GNSS measurement report, confirmed by the F3
`mc_gnssmeasreport.c` source-file label and `onGnssSvCb` C/N0 correlation.

Log name: LOG_DTV_ISDB_TRAFFIC_LOST
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any, Optional

from diaggrok.codes import LOG_GNSS_NAV_MEAS_VALIDITY
from diaggrok.registry import register

# Fixed record size — corpus-wide invariant across 3.19M records.
_FIXED_SIZE = 54
_KNOWN_VERSION = 0x02
# Legacy MDM9200 (Sierra MC7700) variant: 44-byte, version 0x01.
_V01_SIZE = 44
_V01_VERSION = 0x01
# Receiver clock is Q16 milliseconds (1 tick = 1/65536 ms).
_CLOCK_TICKS_PER_MS = 65536.0


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass
class Diag0x1526:
    log_time: int
    version: int                       # b0 — always 2
    sv_id: int                         # b1 — SV id in the meas_task_id namespace
    meas_task_id: int                  # b3 — measurement-task / signal discriminator
    signal_marker: int                 # b4-5 u16 — 0x0002 normally, 0x0302 dual-signal
    meas_age_companion: int            # b6-7 u16 — block-level age companion
    meas_age_accum: int                # b24-25 u16 — measurement-age accumulator
    meas_uncertainty: int              # b28-29 u16 — per-SV noise/uncertainty
    rcvr_time_ticks: int               # (b36-37 << 32) | b32-35 — Q16 ms, 48-bit
    cn0_dbhz: Optional[float]          # b38-41 f32 — primary C/N0, None if absent
    cn0_adj_dbhz: Optional[float]      # b42-45 f32 — adjusted C/N0
    cn0_sig2_dbhz: Optional[float]     # b46-49 f32 — rare 2nd-signal C/N0
    cn0_sig2_adj_dbhz: Optional[float] # b50-53 f32 — rare 2nd-signal adjusted C/N0
    # Raw-surfaced bytes: zero on SDX-class, populated on MDM9x07/9230/9240.
    aux_b2_raw: int = 0                # b2 u8 — semantics unknown
    aux_b8_23_raw: bytes = bytes(16)   # b8-23 — semantics unknown

    @property
    def rcvr_time_ms(self) -> float:
        """Free-running receiver clock in milliseconds (48-bit / 65536)."""
        return self.rcvr_time_ticks / _CLOCK_TICKS_PER_MS

    @property
    def rcvr_time_lo(self) -> int:
        """Low 32 bits of the receiver clock — the raw u32 wire word @b32-35.

        `rcvr_time_ticks` is the derived (hi<<32)|lo combination; this and
        `rcvr_time_hi` expose the two native on-wire words the firmware emits,
        so the raw u32/u16 layout is directly inspectable (and diffable against
        a Kaitai .ksy, which reads them as two positional fields — a
        composed 48-bit value instance overflows ksc 0.10's int32 calc type).
        """
        return self.rcvr_time_ticks & 0xFFFFFFFF

    @property
    def rcvr_time_hi(self) -> int:
        """High 16 bits of the receiver clock — the raw u16 wire word @b36-37."""
        return self.rcvr_time_ticks >> 32

    @property
    def has_measurement(self) -> bool:
        """True when this record carries a valid C/N0 (SV was measured)."""
        return self.cn0_dbhz is not None

    @property
    def cn0_correction_db(self) -> Optional[float]:
        """`cn0_dbhz − cn0_adj_dbhz` — the 0.1-dB-quantized derating, or None."""
        if self.cn0_dbhz is None or self.cn0_adj_dbhz is None:
            return None
        return self.cn0_dbhz - self.cn0_adj_dbhz

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1526',
            'log_time': self.log_time,
            'version': self.version,
            'sv_id': self.sv_id,
            'meas_task_id': self.meas_task_id,
            'signal_marker': self.signal_marker,
            'meas_age_companion': self.meas_age_companion,
            'meas_age_accum': self.meas_age_accum,
            'meas_uncertainty': self.meas_uncertainty,
            'rcvr_time_ticks': self.rcvr_time_ticks,
            'rcvr_time_ms': self.rcvr_time_ms,
            'cn0_dbhz': self.cn0_dbhz,
            'cn0_adj_dbhz': self.cn0_adj_dbhz,
            'cn0_correction_db': self.cn0_correction_db,
            'cn0_sig2_dbhz': self.cn0_sig2_dbhz,
            'cn0_sig2_adj_dbhz': self.cn0_sig2_adj_dbhz,
            'has_measurement': self.has_measurement,
            'aux_b2_raw': self.aux_b2_raw,
            'aux_b8_23_raw': self.aux_b8_23_raw.hex(),
        }


@dataclass
class Diag0x1526V01:
    """Legacy 44-byte, version 0x01 0x1526 GNSS measurement record.

    Emitted by the Sierra MC7700 (MDM9200-class). It is the SAME per-satellite
    measurement-engine record as the modern 54-byte v=0x02 layout, just with a
    shorter middle reserved region (44 vs 54 bytes: the v2 b8-23 16-byte reserved
    run + wider clock area are compressed). The C/N0 quartet lands at the tail
    (b28-43 = 4x f32) exactly as v2 puts it at b38-53; sv_id / meas_task_id /
    signal_marker sit at the same low offsets. Structurally RE'd from 11,198
    records across 5 MC7700 captures; cn0_dbhz corroborated against the modems'
    own co-captured NMEA GSV C/N0 (same units, overlapping dB-Hz distribution,
    DIAG slightly lower than reported-SV GSV - the same measurement-engine vs
    reported-SV relationship verified for v2 on the RM520N-GL).
    """
    log_time: int
    version: int                        # b0 - always 1 (Layer-1 gate)
    sv_id: int                          # b1 - SV id in the meas_task_id namespace
    meas_task_id: int                   # b3 - measurement-task / signal discriminator
    signal_marker: int                  # b4-5 u16 - 0x0002 single, 0x0302 dual-signal
    meas_age_companion: int             # b6-7 u16 - block-level age companion (partial)
    cn0_dbhz: Optional[float]           # b28-31 f32 - primary C/N0, None if absent
    cn0_adj_dbhz: Optional[float]       # b32-35 f32 - adjusted C/N0
    cn0_sig2_dbhz: Optional[float]      # b36-39 f32 - 2nd-signal C/N0 (dual-signal only)
    cn0_sig2_adj_dbhz: Optional[float]  # b40-43 f32 - 2nd-signal adjusted C/N0

    @property
    def has_measurement(self) -> bool:
        """True when this record carries a valid primary C/N0."""
        return self.cn0_dbhz is not None

    @property
    def cn0_correction_db(self) -> Optional[float]:
        """`cn0_dbhz - cn0_adj_dbhz` - the 0.1-dB-quantized derating, or None."""
        if self.cn0_dbhz is None or self.cn0_adj_dbhz is None:
            return None
        return self.cn0_dbhz - self.cn0_adj_dbhz

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1526V01',
            'log_time': self.log_time,
            'version': self.version,
            'sv_id': self.sv_id,
            'meas_task_id': self.meas_task_id,
            'signal_marker': self.signal_marker,
            'meas_age_companion': self.meas_age_companion,
            'cn0_dbhz': self.cn0_dbhz,
            'cn0_adj_dbhz': self.cn0_adj_dbhz,
            'cn0_correction_db': self.cn0_correction_db,
            'cn0_sig2_dbhz': self.cn0_sig2_dbhz,
            'cn0_sig2_adj_dbhz': self.cn0_sig2_adj_dbhz,
            'has_measurement': self.has_measurement,
        }


# ---------------------------------------------------------------------------
# Ground-truth recipe — RM520N-GL (verified)
# ---------------------------------------------------------------------------
# Per-modem recipe keyed to the Quectel RM520N-GL (SDX62). 0x1526 is a single
# v=0x02 / 54B layout with no chipset-specific path, so the RM decodes
# identically to every other emitter; an RM520N-GL owner can validate the
# parser against their modem via the Quectel GNSS AT stack. cn0_dbhz + sv_id
# are VERIFIED against a sky-fix capture's lockstep GSV/F3; the remaining
# fields ground by correlation/behaviour, not by any AT command returning a
# literal value.

# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _opt_f32(data: bytes, off: int) -> Optional[float]:
    """f32 LE at ``off``, or None when the 4 bytes are all zero (= field absent).

    A valid C/N0 is never exactly 0x00000000 in the corpus; the all-zero
    pattern encodes "SV in view but not measured this epoch", so we surface it
    as None rather than a spurious 0.0 dB-Hz reading.
    """
    if data[off:off + 4] == b'\x00\x00\x00\x00':
        return None
    return unpack_from('<f', data, off)[0]


@register(LOG_GNSS_NAV_MEAS_VALIDITY, domain="gnss",
    name="0x1526",
    description=(
        "GNSS per-satellite measurement report — 54B fixed v=2 record; all 54 "
        "bytes decoded (sv_id, meas_task_id, ME FCount clock, pre-adjustment + "
        "engine-reported C/N0, measurement-age accumulator). sv_id/rcvr_time/"
        "cn0_adj F3-verified (mc_peak.c / mc_multipath.c exact join)"
    ),
    version=8,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "v=0x02 (54B): full-field RE from an RM520N-GL (SDX62) sky-fix "
        "capture (6622 records) with lockstep AT+QGPSLOC/GSV + F3 onGnssSvCb "
        "ground truth; F3-VERDICT v0x02 GROUND via an exact (SV, FCount) join "
        "to the firmware's mc_peak.c per-SV CNo (== int(cn0_adj*10) on "
        "10,794/10,858 records, 16 captures, 8 SoC families) and mc_multipath.c "
        "(SDX62 850/850); corpus 22.01M records / 770 captures. v=0x01 (44B): structural RE from 11,198 "
        "Sierra MC7700 (MDM9200) records / 5 captures; no in-capture F3 "
        "exists on that silicon, so cn0_dbhz is corroborated vs the modems' "
        "co-captured NMEA GSV C/N0. Partial: meas_task_id, "
        "meas_age_companion, meas_uncertainty, signal_marker; the v=0x01 "
        "middle region b8-27 is unmapped."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    # Layer-2 invariant: version is 0x02 (modern, SDX-class) or 0x01 (legacy 44B
    # MDM9200 / MC7700). Each version has its OWN layout + size consequence-check
    # in its branch. A version not in the enum is refused (return None) rather
    # than mis-parsed under a foreign layout ("size-invariance != format-
    # invariance"). 0x01 is in the enum because v=0x01 has its own decoded
    # layout (it is not parsed with the v=2 struct).
    field_invariants={"version": {"enum": [_V01_VERSION, _KNOWN_VERSION]}},
    # v=0x02 (54B): all 54 bytes assigned; verified-semantic (6): version, sv_id,
    # rcvr_time (lo+hi), cn0_dbhz, cn0_adj_dbhz, meas_age_accum. v=0x01 (44B):
    # cn0 quartet (b28-43) + sv_id/meas_task_id/signal_marker RE'd; middle
    # b8-27 left partial/reserved pending MDM9200 ground truth.
    fields_identified=13,
    fields_parsed=8,
    ascii_kinds=(),
)
def parse_0x1526(log_time: int, data: bytes) -> Optional[Diag0x1526 | Diag0x1526V01]:
    """Parse a LOG_GNSS_NAV_MEAS_VALIDITY (0x1526) per-SV measurement record.

    Layer-1 version gate: dispatch on byte[0]. v=0x02 is the modern 54-byte
    SDX-class record; v=0x01 is the legacy 44-byte MDM9200 (Sierra MC7700)
    variant. Each branch also size-checks (a consequence-check, not the
    discriminator - size invariance != format invariance). Any other version, or
    a size mismatch within a branch, returns None so firmware drift surfaces as a
    parse-rate drop rather than silent garbage.
    """
    if not data:
        return None
    version = data[0]
    # Reject-first Layer-1 gate: any version outside the known set is refused
    # before any structural decode. Each branch then size-checks its own
    # layout.
    if version not in (_V01_VERSION, _KNOWN_VERSION):
        return None
    if version == _KNOWN_VERSION:
        return _parse_v02(log_time, data)
    return _parse_v01(log_time, data)


def _parse_v02(log_time: int, data: bytes) -> Optional[Diag0x1526]:
    """The modern 54-byte v=0x02 layout."""
    if len(data) != _FIXED_SIZE:
        return None

    # 48-bit free-running receiver clock: low 32 @32, high 16 @36 (Q16 ms).
    rcvr_lo = unpack_from('<I', data, 32)[0]
    rcvr_hi = unpack_from('<H', data, 36)[0]
    rcvr_time_ticks = (rcvr_hi << 32) | rcvr_lo

    return Diag0x1526(
        log_time=log_time,
        version=data[0],
        sv_id=data[1],
        meas_task_id=data[3],
        signal_marker=unpack_from('<H', data, 4)[0],
        meas_age_companion=unpack_from('<H', data, 6)[0],
        meas_age_accum=unpack_from('<H', data, 24)[0],
        meas_uncertainty=unpack_from('<H', data, 28)[0],
        rcvr_time_ticks=rcvr_time_ticks,
        cn0_dbhz=_opt_f32(data, 38),
        cn0_adj_dbhz=_opt_f32(data, 42),
        cn0_sig2_dbhz=_opt_f32(data, 46),
        cn0_sig2_adj_dbhz=_opt_f32(data, 50),
        aux_b2_raw=data[2],
        aux_b8_23_raw=bytes(data[8:24]),
    )


def _parse_v01(log_time: int, data: bytes) -> Optional[Diag0x1526V01]:
    """The legacy 44-byte v=0x01 MDM9200 layout (Sierra MC7700).

    Same per-SV measurement semantics as v=0x02; the C/N0 quartet sits at the
    tail (b28-43) and sv_id/meas_task_id/signal_marker at the same low offsets.
    The 2nd-signal C/N0 pair (b36-43) is present iff signal_marker hi == 0x03,
    exactly as v=0x02 gates its cn0_sig2 pair on b5 == 0x03.
    """
    if len(data) != _V01_SIZE:
        return None
    return Diag0x1526V01(
        log_time=log_time,
        version=data[0],
        sv_id=data[1],
        meas_task_id=data[3],
        signal_marker=unpack_from('<H', data, 4)[0],
        meas_age_companion=unpack_from('<H', data, 6)[0],
        cn0_dbhz=_opt_f32(data, 28),
        cn0_adj_dbhz=_opt_f32(data, 32),
        cn0_sig2_dbhz=_opt_f32(data, 36),
        cn0_sig2_adj_dbhz=_opt_f32(data, 40),
    )
