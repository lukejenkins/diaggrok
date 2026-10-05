"""GNSS per-constellation RF statistics parser (0x158C).

**Identity (F3): PMIC ADC conversion results, not GNSS RF statistics.** The
byte offsets below are right, but the GNSS-flavoured names are legacy:
``(metric_a, metric_b, metric_c, metric_d)`` equal the firmware's
``VAdcLog.c`` "VADC conv result for <CHANNEL>: … nPhysical, uPercent,
uMicrovolts, uCode" exactly on 41,342 records (24/24 discovery units), and
the site fires within ±10 ms of the records on 489/567 F3-bearing units.
``seq_num`` is the PMIC ADC channel (PMIC_THERM, XO_THERM,
XO_THERM_GPS_MED/HIGH, SYS_THERM, PA_THERM, QTM_THERM…; build-specific),
not a GNSS constellation, so the ``constellation`` field below is a legacy
label, not a decode. This matches the canonical name ``LOG_XO_ADC``. The
field names are kept for compatibility.

Fixed 49-byte payload, one record per channel (``seq_num``), emitted at
~21 Hz on SDX55 and at a lower rate on SDX20 V2. Each epoch emits one
``seq_num``; channels interleave across epochs.

## Key observations

- ``metric_c / metric_b ≈ 28.6111`` on every active record across every
  chipset **except MC7455 MDM9x30**, which uses ≈ 27.46 (and ≈ 82.17 on
  seq 0). The 28.611 ratio is 515/18 exactly at low precision — a
  chipset-generation-dependent fixed-point scaling.
- ``metric_d / metric_b`` splits by chipset:
    - **SDX20 / MDM9650** (em7511, lm960, eg18na, MC7411): ``d = round(b / 4)``
      (exact on every active record; ratio = 0.250 ± 0.00002).
    - **SDX55** (fn980m, em9190, RM500Q-AE, RXM-G1): ``d / b ≈ 0.441``
      (no exact integer ratio found).
    - **MC7455 MDM9x30**: neither — ratio drifts per-seq from 0.85 to 1.40
      (the MC7455 "metric_d" field may carry a different quantity entirely).
- ``seq_num`` sets differ by chipset: {1..9} on SDX20/SDX55/SDX62,
  {0, 3, 4, 7, 8, 9, 10} on MC7455 MDM9x30, {0, 1, 4, 6, 9} on MC7411
  (MDM9650), with seq 10-16 seen on T99W640 SDX72. Seq 0 carries
  ``c/b ≈ 85.83 = 3×28.611`` on MC7411.
- Inactive slots (seq 6..8 on most firmwares) have ``metric_a = -56`` (i32)
  with validity flags 0xFF. Some em7511 firmwares and FN980m also show small
  ``metric_a`` values such as ``24/25/33/-50`` on active records, while seq
  1/4 report in the 20k-40k range.
- The 25-byte tail (offsets 25..48) is mostly zero except a ``flags`` byte
  at offset 41. Corpus distribution across 1.09 M records: ``0x02`` (82.6 %),
  ``0x03`` (10.8 %), ``0x01`` (6.6 %). ``0x03`` and ``0x01`` correlate with
  cold-start / SIM-cycle / airplane-cycle scenarios — likely a state bit,
  not a constant. 40 captures show intra-capture variance, so this byte is
  genuinely state-dependent and **must not** be declared a field-invariant.
- The version byte (offset 0) and sub_version byte (offset 1) are stable
  at ``0x01`` across every record in the corpus (1.09 M records, 235
  captures, 16 chipsets — MDM9x07 / MDM9x30 / MDM9650 / SDX20 / SDX20 V2 /
  SDX55 / SDX62). Declared as ``field_invariants`` on the registry entry.

## Cross-chipset metric_a range table

    chipset           seq=1       seq=4       seq=6/7/8   seq=9
    ----------------- ----------- ----------- ----------- -----------
    em7511 MDM9650    25k-26k     25k-26k     24..25      -50 (const)
    fn980m SDX55      40k (avg)   36k (avg)   -40 (const) 33 (avg)
    lm960 SDX20       28k (avg)   25k (avg)   n/a         24 (const)
    eg18na SDX20 V2   34k (avg)   31k (avg)   n/a         30/125 (var)

Log name: LOG_XO_ADC
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import calcsize, unpack_from
from typing import Any

from diaggrok.registry import register

# Not in codes.py yet — add the constant here; cross-ref to codes.py later
LOG_GNSS_RF_STATS = 0x158C

# Payload layout (49 bytes):
#   u8   version           @ 0
#   u8   sub_version       @ 1
#   u8   reserved[3]       @ 2..4
#   u8   seq_num           @ 5     constellation/band slot index
#   u8   reserved[3]       @ 6..8
#   i32  metric_a          @ 9     primary metric (or -56 sentinel for inactive)
#   i32  metric_b          @ 13    secondary metric
#   u32  metric_c          @ 17    ≈ metric_b × 28.61
#   u32  metric_d          @ 21    ≈ metric_b × 0.441
#   u8   reserved2[16]     @ 25    exposed raw: all-zero on modern
#                                  silicon, but 4 live LE u32 on MC7455/MDM9x30
#                                  (semantics TBD — likely a legacy second metric
#                                  quartet).
#   u8   flags             @ 41    state-dependent: {0x01, 0x02, 0x03}
#   u8   zeros[7]          @ 42
_RF_STATS_FMT = '<BBBBBBBBBiiII16sB7s'
_RF_STATS_SZ = calcsize(_RF_STATS_FMT)
assert _RF_STATS_SZ == 49, f"Expected 49, got {_RF_STATS_SZ}"

# Legacy seq → constellation labels (from the 0x14DE OEM DRE sequencing on
# SDX20/SDX55/SDX62). F3 shows seq_num is a PMIC ADC channel, so these labels
# are kept for compatibility only (see the module docstring).
_SEQ_CONSTELLATION = {
    1: 'GPS',
    2: 'SBAS',
    3: 'GLONASS',  # not observed in FN980m, but expected from OEM DRE mapping
    4: 'Galileo',
    5: 'BeiDou',   # hypothesis — BeiDou B1 slot
    6: 'unknown',  # L5-band hypothesis
    7: 'unknown',  # L5-band hypothesis
    8: 'unknown',  # L5-band hypothesis
    9: 'GLONASS',  # observed in FN980m — may be G1 or alternate GLO slot
}

# MC7455 MDM9x30 uses different seq numbers than the modern family. Seq
# values observed on MC7455 (9,754 records):
#   0 (n=20, outlier c/b≈82), 3 (n=3055, GPS-like),
#   4 (n=20, tiny metric_a — GLONASS?), 7 (n=11), 8 (n=6504, GPS-like),
#   9 (n=72), 10 (n=72). The parser does NOT apply an MDM9x30-specific map
#   because the log packet carries no chipset ID; callers with chipset
#   context can reinterpret ``seq_num`` as needed.


@dataclass
class Diag0x158C:
    """Per-constellation RF statistics report (0x158C).

    One record per ``seq_num`` slot. F3 identifies the four metrics as a
    PMIC VADC conversion result (nPhysical, uPercent, uMicrovolts, uCode)
    and ``seq_num`` as the ADC channel; ``constellation`` is a legacy label.
    The fixed ratios (metric_c ≈ 28.6 × metric_b, metric_d ≈ 0.441 ×
    metric_b on SDX55) are per-chipset scaling constants.
    """
    log_time: int
    version: int
    sub_version: int
    seq_num: int
    constellation: str
    metric_a: int       # i32 — primary measurement; -56 sentinel for inactive bands
    metric_b: int       # i32 — secondary measurement
    metric_c: int       # u32 — ≈ metric_b × 28.61
    metric_d: int       # u32 — ≈ metric_b × 0.441
    reserved2: bytes    # 16B @25 — 0 on modern silicon,
                        #   4 live LE u32 on MC7455/MDM9x30 (semantics TBD)
    flags: int          # u8 — state-dependent: {0x01, 0x02, 0x03}
    active: bool        # True if not an inactive sentinel

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x158C',
            'log_time': self.log_time,
            'version': self.version,
            'sub_version': self.sub_version,
            'seq_num': self.seq_num,
            'constellation': self.constellation,
            'metric_a': self.metric_a,
            'metric_b': self.metric_b,
            'metric_c': self.metric_c,
            'metric_d': self.metric_d,
            'reserved2': self.reserved2.hex(),
            'flags': self.flags,
            'active': self.active,
        }


# --- Ground-truth recipe ---------------------------------------------------
# v1 is the RM520N-GL (SDX62) emission (byte-0 == 0x01 on 7016 sampled
# records; sub_version 0x01). The recipe was written under the GNSS
# RF-statistics reading (grounding metrics against NMEA GSV per-SV C/N0 via
# the seq_num→constellation map). F3 has since identified the record as PMIC
# VADC conversion results, so that grounding target does not apply.

@register(
    LOG_GNSS_RF_STATS, domain="gnss",
    name="0x158C",
    primary_issue=None,  #
    description="Per-constellation RF signal statistics (0x158C)",
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    version=6,
    source_type="re",
    source_detail="Clean-room RE from FN980m SDX55 + EG18-NA SDX20 V2 + RM520N-GL SDX62 captures; v=0x01 + c/b=28.611 / d/b=0.441 ratios confirmed on T99W640 SDX72 (seq 10-16 unmapped). F3 identifies (metric_a..d) as VAdcLog.c PMIC VADC conversion results (nPhysical, uPercent, uMicrovolts, uCode) on 41,342 records and seq_num as the ADC channel; the constellation labels are legacy.",
    source_url="",
    # version, sub_version, seq_num, constellation, metric_a, metric_b,
    # metric_c, metric_d, reserved2, flags, active — 11 named fields covering
    # EVERY byte of the 49B record, including reserved2 [25:41].
    fields_identified=11,
    fields_parsed=11,
    # version=0x01 / sub_version=0x01 confirmed across 1.09 M records,
    # 235 captures, 16 chipsets (offset 0/1 distribution shows no
    # other value). flags @ +41 is state-dependent and NOT invariant
    # (0x02 82.6 %, 0x03 10.8 %, 0x01 6.6 %).
    field_invariants={
        "version": {"enum": [0x01]},
        "sub_version": {"enum": [0x01]},
    },
    # WiGLE tagging: gnss-quality, assigned under the GNSS RF-statistics
    # reading (CN0 / jammer / noise-floor metrics). F3 identifies the record
    # as PMIC ADC data (see the module docstring). No identity / position /
    # PCI-EARFCN fields at the dataclass level.
    wigle_direct=True,
    wigle_roles=("gnss-quality",),
)
def parse_0x158c(log_time: int, data: bytes) -> Diag0x158C | None:
    """Parse a GNSS RF Stats (0x158C) log payload.

    Returns None if the payload is too short.
    """
    if len(data) < _RF_STATS_SZ:
        return None
    # Layer-1 version gate: byte[0] is version invariant 0x01 across
    # 1.09M records, all chipsets. Reject foreign payloads.
    if data[0] != 0x01:
        return None

    (version, sub_version,
     _r0, _r1, _r2,
     seq_num,
     _r3, _r4, _r5,
     metric_a, metric_b, metric_c, metric_d,
     reserved2, flags, _trail) = unpack_from(_RF_STATS_FMT, data)

    constellation = _SEQ_CONSTELLATION.get(seq_num, f'unknown-{seq_num}')

    # Inactive bands have metric_a = -56 (sentinel) and 0xFF validity flags
    active = metric_a != -56

    return Diag0x158C(
        log_time=log_time,
        version=version,
        sub_version=sub_version,
        seq_num=seq_num,
        constellation=constellation,
        metric_a=metric_a,
        metric_b=metric_b,
        metric_c=metric_c,
        metric_d=metric_d,
        reserved2=reserved2,
        flags=flags,
        active=active,
    )
