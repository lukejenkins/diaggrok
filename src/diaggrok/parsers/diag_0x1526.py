"""GNSS navigation measurement report parser (0x1526).

Single-version 54-byte fixed-size record, **version byte 0x02 corpus-wide**
(3.19M records / 33 chipsets / 79 captures per the #N 2026-05-08 walk).

## What this log actually is (#N, 2026-07-02 full-field RE)

0x1526 is a **per-satellite GNSS measurement-engine record**, NOT a per-fix
summary. The GNSS measurement engine emits one record per (satellite,
measurement-task) per epoch, so a single 1 Hz epoch produces dozens of records
(~66/s observed on the RM520N-GL sky-fix capture: ~18.7 measurement blocks/epoch
× a handful of SVs each). This reframing corrected the earlier parser, whose
`sv_count` (erratic, values >32) and `float_value` (near-unique, ±1e38) fields
were **refuted** by hardware validation — they were a per-SV id and the low word
of a receiver clock, respectively, never a count or a float.

### The 54-byte layout (offsets are LE)

| Off | Sz | Field                | Status     | Meaning |
|-----|----|----------------------|------------|---------|
| 0   | 1  | `version`            | confirmed  | always 0x02 (Layer-1 gate) |
| 1   | 1  | `sv_id`              | verified   | satellite id **in the namespace set by `meas_task_id`** — GPS PRN, Galileo E-PRN, raw SBAS PRN, or GLONASS FCN+8 |
| 2   | 1  | reserved             | confirmed  | 0x00 (10 622 records / 2 chipsets); likely sv_id high byte |
| 3   | 1  | `meas_task_id`       | partial    | measurement-task / signal-job discriminator (see task map) |
| 4   | 1  | `signal_marker` lo   | confirmed  | 0x02 always |
| 5   | 1  | `signal_marker` hi   | partial    | 0x00 normally; 0x03 on the 4 dual-signal records (b46-53 populated) |
| 6-7 | 2  | `meas_age_companion` | partial    | block-level state, bijectively paired with `meas_age_accum`; b6>b24 always |
| 8-23| 16 | reserved             | confirmed  | all zero |
| 24-25| 2 | `meas_age_accum`     | confirmed  | measurement-age / accumulated-drift accumulator (block-constant); grows at an exact per-task rate while unmeasured, resets after a valid measurement |
| 26-27| 2 | reserved             | confirmed  | 0x0000 (so field is u16, not u32) |
| 28-29| 2 | `meas_uncertainty`   | partial    | per-SV noise/uncertainty word, anti-correlated with C/N0 (r −0.58..−0.85) |
| 30-31| 2 | reserved             | confirmed  | 0x0000 |
| 32-35| 4 | `rcvr_time` lo       | confirmed  | LOW 32 bits of a 48-bit free-running receiver clock |
| 36-37| 2 | `rcvr_time` hi       | confirmed  | HIGH 16 bits of the same clock (wraps every 65.536 s) |
| 38-41| 4 | `cn0_dbhz`           | verified   | primary C/N0 in dB-Hz (f32); 0x00000000 ⇒ no valid measurement ⇒ decoded as None |
| 42-45| 4 | `cn0_adj_dbhz`       | verified   | adjusted C/N0 = `cn0_dbhz − k·0.1` dB (k integer); present iff `cn0_dbhz` present |
| 46-49| 4 | `cn0_sig2_dbhz`      | hypothesis | rare 2nd-signal C/N0 (4/6622 recs, strongest GPS SVs only) — L2C/L5 candidate |
| 50-53| 4 | `cn0_sig2_adj_dbhz`  | hypothesis | adjusted companion of `cn0_sig2_dbhz` |

### The 48-bit receiver clock (was `float_value` + `validity_mask`)

`rcvr_time = (u16@36 << 32) | u32@32`, in **1/65536-ms ticks (Q16 milliseconds)**
— `rcvr_time_ms = rcvr_time / 65536`. Proof: a constant 65 536 000 counts/s
slope for every SV; the high word (b36-37) increments by exactly 1 each time the
low word wraps (every 65.536 s); the owned RM520N-GL capture's clock span is
104 972 ms ≈ its ~105 s wall-clock duration; the earlier "validity_mask"
values {0xf6,0xf7} were simply the low byte of the high word during that
capture. This is why the old `float_value` was near-unique ±1e38 (a fast
counter reinterpreted as f32) — a hardware refutation that pointed straight at
the correct typing.

### `meas_task_id` (b3) — do NOT hardcode a constellation table

`meas_task_id` is a per-firmware **measurement-task** id, not a constellation
enum: its values differ across chipsets (RM520N-GL {0,1,3,5,12,30,33} vs em9190
{0,7,8,21,22,29}) even though each value's SV-id set maps cleanly to one
constellation. Constellation is therefore inferred from the `sv_id` namespace +
task behaviour, not from a fixed `meas_task_id` value. Observed RM520N-GL
(SDX62, A0.303) map, for reference only: 0=GPS/QZSS L1CA blind-scan, 1=verify of
0, 3=GPS L1CA track, 5=SBAS L1 track (sv_id=133), 12=GLONASS L1OF track
(sv_id=FCN+8), 30=Galileo search/reacq, 33=Galileo E1 track. `(N, N+1)` values
are an (acquisition-scan, candidate-verify) stage pair of one search task.

## Legacy variant - 44-byte v=0x01 on Sierra MC7700 (decoded, #N)

A distinct **44-byte, version=0x01** variant of 0x1526 is emitted by the Sierra
MC7700 (MDM9200-class): 11,198 records across 5 captures, all `44|0x01`, one
modem model. It is the SAME per-satellite measurement-engine record as v=0x02,
with a shorter middle reserved region (the C/N0 quartet lands at the tail,
b28-43 = 4x f32, mirroring v2's b38-53). Decoded by `_parse_v01` into
`Diag0x1526V01`; the version enum is widened to `{0x01, 0x02}` because v=0x01 now
has its OWN correct layout (this is NOT absorbing it into the v=2 struct).

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

**F3 ground truth: none exists for this variant.** All 10 MC7700 captures were
probed at raw-record level for every F3 family (0x79 EXT_MSG plaintext, 0x99
QSR4-terse, 0x98 multi-radio wrapper, 0x92 QSR): 0 records of any family
corpus-wide. MDM9200 (2011-era Gobi3000) predates the EXT_MSG_F / QSR F3
machinery, so there is no firmware debug-print oracle. cn0_dbhz is instead
grounded on the modems' own co-captured NMEA GSV C/N0 (the next-best independent
oracle) - the same relationship verified for v=0x02 on the RM520N-GL.

## Ground truth (#N / #N)

`cn0_dbhz` and `sv_id` are **verified** against the owned RM520N-GL sky-fix
capture (`<redacted-pii>`): pooled `cn0_dbhz`
(n=2120, 7.16–33.41 dB-Hz, mean 24.13) matches NMEA GSV (mean 25.41) and the F3
`onGnssSvCb` per-SV C/N0 (mean 24.92) with rank-perfect per-SV agreement, and
each `meas_task_id`'s `sv_id` set equals the matching F3 constellation SV set
exactly. See the RM520N-GL ground-truth recipe below.

## Closure status (#N) — tracker STAYS OPEN (stays-open policy #N/#N)

All 54 bytes are now assigned to named, typed fields. Verified: version, sv_id,
rcvr_time, cn0_dbhz, cn0_adj_dbhz, meas_age_accum. Partial (structure known,
physical unit not fully pinned): meas_task_id, meas_age_companion,
meas_uncertainty, signal_marker. Hypothesis: the rare 2nd-signal C/N0 pair.

=== names-block:start (auto-generated by tools/inject_names_block_parsers.py) ===

Names by source (from sources/DIAG_LOG_INDEX.yaml):
    canonical: LOG_DTV_ISDB_TRAFFIC_LOST
        source: qxdm_3_12_714_2017_diag_log_codes (authority: community)
    aliases:
        RESERVED
            source: qxdm_itemtype_list_zukgit_2025_04_03

Source-precedence (#N): vendor_official > observation >
community (specification) > community (reference).

NOTE: the QXDM-canonical name `LOG_DTV_ISDB_TRAFFIC_LOST` (digital-TV broadcast)
is a community mis-map. The parser's own `LOG_GNSS_NAV_MEAS_VALIDITY` constant +
the #N RE observation (precedence: observation > community) is the grounded
reading — this is a GNSS measurement report, confirmed by the F3
`mc_gnssmeasreport.c` source-file label and `onGnssSvCb` C/N0 correlation.
=== names-block:end ===
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
# Legacy MDM9200 (Sierra MC7700) variant: 44-byte, version 0x01 (#N).
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

    @property
    def rcvr_time_ms(self) -> float:
        """Free-running receiver clock in milliseconds (48-bit / 65536)."""
        return self.rcvr_time_ticks / _CLOCK_TICKS_PER_MS

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
        }


@dataclass
class Diag0x1526V01:
    """Legacy 44-byte, version 0x01 0x1526 GNSS measurement record (#N).

    Emitted by the Sierra MC7700 (MDM9200-class). It is the SAME per-satellite
    measurement-engine record as the modern 54-byte v=0x02 layout, just with a
    shorter middle reserved region (44 vs 54 bytes: the v2 b8-23 16-byte reserved
    run + wider clock area are compressed). The C/N0 quartet lands at the tail
    (b28-43 = 4x f32) exactly as v2 puts it at b38-53; sv_id / meas_task_id /
    signal_marker sit at the same low offsets. Structurally RE'd from 11,198
    records across 5 MC7700 captures; cn0_dbhz corroborated against the modems'
    own co-captured NMEA GSV C/N0 (same units, overlapping dB-Hz distribution,
    DIAG slightly lower than reported-SV GSV - the same measurement-engine vs
    reported-SV relationship verified for v2 on the RM520N-GL, #N).
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
# Ground-truth recipe (#N / #N) — RM520N-GL, verified 2026-07-02
# ---------------------------------------------------------------------------
# Per-modem recipe keyed to the Quectel RM520N-GL (SDX62). 0x1526 is a single
# v=0x02 / 54B layout with no chipset-specific path, so the RM decodes
# identically to every other emitter; the value of an RM-keyed recipe is that an
# RM520N-GL owner can validate the parser version their (house-default, most-
# capable) modem emits, via the Quectel GNSS AT stack. cn0_dbhz + sv_id were
# VERIFIED against the owned sky-fix capture's lockstep GSV/F3; the remaining
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
        "bytes decoded (sv_id, meas_task_id, 48-bit receiver clock, primary + "
        "adjusted C/N0, measurement-age accumulator). cn0_dbhz/sv_id/rcvr_time "
        "verified vs RM520N-GL GSV+F3 (#N)"
    ),
    version=6,
                # sibling layout - cn0 quartet + sv_id/task/signal_marker RE'd
                # from 11,198 records / 5 captures, cn0 corroborated vs GSV.
                # v5 (#N): full-field RE of the 54B v=0x02 record.
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "v=0x02 (54B): full-field RE from the owned RM520N-GL (SDX62 A0.303) "
        "sky-fix capture <redacted-pii> (6622 "
        "records) with lockstep AT+QGPSLOC/GSV + F3 onGnssSvCb ground truth, "
        "cross-checked on em9190; + #N 2026-05-08 corpus walk (3.19M records / "
        "33 chipsets). v=0x01 (44B): structural RE from 11,198 Sierra MC7700 "
        "(MDM9200) records / 5 captures; cn0_dbhz corroborated vs the modems' "
        "co-captured NMEA GSV C/N0 (#N)"
    ),
    source_url="",
    issues=(),
    primary_issue=None,  # #N is the canonical 0x1526 tracker; #N = v=0x01 variant
    # Layer-2 invariant: version is 0x02 (modern, SDX-class) or 0x01 (legacy 44B
    # MDM9200 / MC7700). Each version has its OWN layout + size consequence-check
    # in its branch. A version not in the enum is refused (return None) rather
    # than mis-parsed under a foreign layout ("size-invariance != format-
    # invariance"). Widening to include 0x01 is correct now that v=0x01 has a
    # real decoded layout (it is NOT absorbing it into the v=2 struct).
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
    variant (#N). Each branch also size-checks (a consequence-check, not the
    discriminator - size invariance != format invariance). Any other version, or
    a size mismatch within a branch, returns None so firmware drift surfaces as a
    parse-rate drop rather than silent garbage.
    """
    if not data:
        return None
    version = data[0]
    # Reject-first Layer-1 gate: any version outside the known set is refused
    # before any structural decode (the canonical form the version-gate audit
    # recognizes, #N). Each branch then size-checks its own layout.
    if version not in (_V01_VERSION, _KNOWN_VERSION):
        return None
    if version == _KNOWN_VERSION:
        return _parse_v02(log_time, data)
    return _parse_v01(log_time, data)


def _parse_v02(log_time: int, data: bytes) -> Optional[Diag0x1526]:
    """The modern 54-byte v=0x02 layout (#N)."""
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
    )


def _parse_v01(log_time: int, data: bytes) -> Optional[Diag0x1526V01]:
    """The legacy 44-byte v=0x01 MDM9200 layout (Sierra MC7700, #N).

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
