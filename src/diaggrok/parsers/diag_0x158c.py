"""GNSS per-constellation RF statistics parser (0x158C).

Emitted once per constellation/band slot at ~21 Hz on SDX55, lower rate
on SDX20 V2.  Fixed 49-byte payload, one record per (constellation, band)
combination — same sequencing scheme as OEM DRE (0x14DE):

    seq 1 = GPS L1, seq 2 = SBAS, seq 4 = Galileo E1,
    seq 5 = BeiDou B1 (corroborated 2026-06-23 — RXM-G1 SDX55 emits 1110
    seq-5 records tracking seq-1 GPS / seq-4 Galileo 1:1, i.e. a genuine
    co-tracked constellation slot, not a stray), seq 6..8 = L5-band slots
    (inactive on most firmwares), seq 9 = GLONASS G1.

RE history:
- 2026-04-12 #N: initial clean-room RE from FN980m SDX55, EG18-NA SDX20 V2,
  and RM520N-GL SDX62 DLF captures (all produce 49-byte payloads).
- 2026-04-20 #N: chipset-specific ``metric_d`` ratio pinned:
  ``d = round(metric_b / 4)`` on SDX20/MDM9650 (em7511, lm960, eg18na)
  — verified to hold exactly on every active record across 14,973 records
  from three chipsets.  On SDX55 (fn980m, em9190) the ratio is instead
  ``d/b ≈ 0.441`` — same relationship, different fixed-point scaling.
- 2026-04-21 #N: MC7455 (MDM9x30 legacy) cross-check — the c/b=28.611
  invariant does NOT hold on MDM9x30 (instead c/b ≈ 27.46 on seq∈{3,4,7,8,9,10}
  and c/b ≈ 82.17 on seq=0). The seq→constellation mapping also differs;
  MC7455 emits seq ∈ {0, 3, 4, 7, 8, 9, 10} vs newer chipsets using
  {1..9}. See ``_SEQ_CONSTELLATION_MDM9X30`` for the MC7455 map.
- 2026-06-23 #N/#N (<redacted-ref> n=1, FN980 F3-harvest pass): Compal RXM-G1
  SDX55 (``RXMG1.20.00.244_0C03``) added as a **3rd independent SDX55
  emitter** confirming both invariants exactly — across GPS/Galileo/BeiDou/
  SBAS medians, ``c/b = 28.6111`` and ``d/b = 0.4410`` to 4 decimals
  (3896 records, ``<redacted-pii>``). The
  per-constellation seq round-robin (seq 1/4/5 GPS/Galileo/BeiDou emit in
  equal counts) **structurally refutes the community names-block guess
  ``LOG_XO_ADC``** — a scalar crystal-oscillator ADC reading would carry no
  constellation-keyed sequencing. Observation-based identity GNSS RF stats
  stands (#N: observation > community).
- 2026-06-23 #N/#N: **first co-temporal F3↔0x158C grounding source
  identified.** The FN980 worklist F3 (qdb ``e6f2cc1b``, 100%) is in a
  binary-log-suppressed validate capture that carries NO 0x158C, so it
  cannot ground this code; but the RXM-G1 ``gnss-f3`` capture (qdb
  ``77c0963a``, 100%) carries both 0x158C **and** decodable GNSS F3.
  Co-temporal F3 oracles: ``mc_peak.c:7199`` per-SV ``CNo`` (raw 0.1 dB-Hz:
  GPS≈243, Galileo≈300, GLONASS≈250, BeiDou≈208 median) and the
  ``mc_gnssmeasreport.c:5567`` per-SV measurement table. NB: 0x158C
  ``metric_a`` (33k-35k for GPS/Galileo/BeiDou/SBAS) is **not** raw per-SV
  CN0 — it is an RF-chain accumulator; the F3 grounding path is aggregate-
  trend correlation over a window, not a direct per-SV equality.
- 2026-06-23 #N/#N (<redacted-ref> n=1, RM500Q-AE F3-harvest pass): the deferred
  aggregate-trend correlation from the RXM-G1 entry above was **executed** on
  a 2nd independent co-temporal source — Quectel RM500Q-AE SDX55
  (``<redacted-firmware>``), capture
  ``20260612-165100-RM500Q-AE-5govalidate-allmask-f3`` (7945 0x158C records +
  F3 100%, qdb ``404921d3``). Both SDX55 invariants reconfirmed exactly
  (``c/b = 28.611``, ``d/b = 0.4410`` across all active seqs). The F3
  ``mc_peak.c:6744`` CNo oracle (``Gnss:%u,Job:%u,SV:%u,C/No:%u,...``) and the
  ``:7199`` plaintext (``GAL/GPS/GLO PeakProcess``) **self-label** their
  constellation — giving an F3-internal enum **0=GPS, 1=GLONASS, 3=Galileo**
  that is *distinct* from this code's ``seq_num`` enum (1/4/5/9). Binning both
  streams into 30 co-temporal time windows and correlating per-constellation:
  **``metric_a`` tracks per-SV *mean* CNo** — Spearman ρ ≈ **+0.64 (GPS)** and
  **+0.65 (Galileo)** vs mean CNo, but only +0.15 / +0.60 vs *sum* CNo and
  +0.02 / +0.33 vs SV-count. Cross-constellation static ordering agrees (GPS
  mean CNo 30.9 > Galileo 28.3 dB-Hz **and** GPS metric_a 34816 > Galileo
  34001). This grounds ``metric_a`` as a **mean-CNo-correlated RF accumulator**
  (signal-quality, not energy-sum or SV-count) — quantitatively corroborating
  the GNSS-RF-stats identity and refuting the scalar ``LOG_XO_ADC`` guess.
  Correlatable overlap is GPS(seq1)+Galileo(seq4) only: F3 ``mc_peak`` CNo
  covers GPS/GLONASS/Galileo while 0x158C actively reports GPS/Galileo/BeiDou
  (seq9 GLONASS is the inactive ``-40`` sentinel here) — BeiDou is still
  F3-tracked (29,855 BDS prints) just absent from the ``mc_peak`` CNo site, so
  ``seq5 = BeiDou`` is **not** contradicted. Caveat: stationary capture, so
  this is trend-correlation, not causal per-SV equality.
  **NAViC negative control (same capture):** 18,831 NAViC/IRNSS F3 prints fire
  (SVID block 401-414, ``cd_navicdecode.c`` / ``cd_naviccalc.c`` /
  ``mc_gnsssearchstrategy.c``) yet NAViC is *dormant* — ``tm_util.c: NAVIC sv
  mask used=0x00 usable=0x00``, ``Strategy State NAVIC: IDLE``,
  ``NAVIC_allowed_as_addon 0`` — because the modem was in Ogden, UT (41.2°N,
  −111.9°W, from co-captured ``Serving cell position updated`` F3), outside
  NAViC's Indian-regional footprint, so no NAViC SV is ever acquired. It
  therefore emits **no 0x158C seq slot and no ``mc_peak`` CNo** — confirming the
  observed seq map (1/2/4/5/9 + 6-8 L5) is complete *for this geography* and
  predicting that a future India-region capture of an NAViC-capable modem should
  surface a new active seq slot — a concrete falsification test of the
  seq→constellation map.
- 2026-06-23 #N/#N (<redacted-ref> n=1, mc7411 F3-harvest pass): **first
  structural invariant test on Sierra MC7411 (MDM9650 / SDX50M)** —
  fw ``SWI9X50C_01.14.03.00``, fix-bearing capture
  ``gnss_diag_capture_2026-06-16.dlf`` (1882 0x158C records; F3 100% via
  qdb ``04b8d441``). Both family invariants confirmed: ``c/b = 28.6112``
  on the GNSS seqs (1=GPS / 4=Galileo / 6=L5) and ``d = round(b/4)`` at
  **100%** of every b>0 record across *all* seqs — i.e. MC7411 obeys the
  **MDM9650/SDX20 ``d=round(b/4)`` rule (d/b=0.25), NOT the SDX55 d/b≈0.441**,
  cementing it in the MDM9650 family alongside em7511/lm960/eg18na.
  Seq map is the hybrid ``{0,1,4,6,9}``: it emits the **legacy seq=0 slot**
  (``c/b ≈ 85.83 = 3×28.611``, metric_a≈3620) that only the older Sierra
  parts emit (MC7455 MDM9x30 seq=0 was c/b≈82.17; SDX55/SDX62 omit seq=0
  entirely) **while** using the modern seq=1=GPS / seq=4=Galileo mapping —
  bridging the MC7455↔SDX55 seq-map divide. Each epoch emits exactly one
  seq (GPS 917 / Galileo 915 interleaved ~1:1; seq6 L5 ×24, seq9 ×8,
  seq0 ×5) — not an intra-epoch round-robin. **F3 grounding of the open
  seq↔constellation mystery:** the now-decodable MC7411 F3 carries an
  ``e_GnssType`` enum (``mc_jobmanager.c`` Dedicated-Resource prints) =
  **0=GPS (SV 1-37), 1=GLONASS (1-14), 2=BeiDou (6-30), 3=Galileo (5-35)**
  — confirming the F3-internal enum is *distinct* from this code's seq_num
  (as on RXM-G1) and that the 0x158C seq set is a **chipset-specific subset
  of actually-tracked constellations**: BeiDou is actively tracked here
  (F3 e_GnssType=2, 56 prints) yet emits **no 0x158C seq=5 slot**, and the
  seq=9 GLONASS slot reads sentinel (b=3, metric_a=125) despite GLONASS
  being searched (F3 e_GnssType=1). NB chipset-attribution fix: the #N
  "Observed on" table lists MC7411 as MDM9x07 — the qdb + filesystem say
  **MDM9650 (SDX50M)**.

## Key observations

- ``metric_c / metric_b ≈ 28.6111`` on every active record across every
  chipset **except MC7455 MDM9x30**, which uses ≈ 27.46. The 28.611 ratio
  is 515/18 exactly at low precision — a chipset-generation-dependent
  fixed-point scaling inside the RF accumulator.
- ``metric_d / metric_b`` splits by chipset:
    - **SDX20 / MDM9650**: ``d = round(b / 4)`` (exact; ratio = 0.250 ± 0.00002).
    - **SDX55**: ``d / b ≈ 0.441`` (no exact integer ratio found).
    - **MC7455 MDM9x30**: neither — ratio drifts per-seq from 0.85 to 1.40
      (the MC7455 "metric_d" field may carry a different quantity entirely).
  The divergence suggests each chipset-generation uses a different
  oversampling / integration constant.
- Inactive L5-band slots (seq 6..8) have ``metric_a = -56`` (i32) with
  validity flags 0xFF, indicating no active measurement.  On some em7511
  firmwares and FN980m ``metric_a`` can also appear as small values like
  ``24/25/33/-50`` — these are active records reporting a different
  quantity from the GPS/Galileo seq which report in the 20k-40k range.
- The 25-byte tail (offsets 25..48) is mostly zero except a ``flags`` byte
  at offset 41. Corpus distribution across 1.09 M records: ``0x02`` (82.6 %),
  ``0x03`` (10.8 %), ``0x01`` (6.6 %). ``0x03`` and ``0x01`` correlate with
  cold-start / SIM-cycle / airplane-cycle scenarios — likely a tracker
  state bit, not a constant. 40 captures show intra-capture variance, so
  this byte is genuinely state-dependent and **must not** be declared a
  field-invariant.
- The version byte (offset 0) and sub_version byte (offset 1) are stable
  at ``0x01`` across every record in the corpus (1.09 M records, 235
  captures, 16 chipsets — MDM9x07 / MDM9x30 / MDM9650 / SDX20 / SDX20 V2 /
  SDX55 / SDX62). Declared as ``field_invariants`` on the registry entry.

## Cross-chipset metric_a range table (2026-04-20)

    chipset           seq=1       seq=4       seq=6/7/8   seq=9
    ----------------- ----------- ----------- ----------- -----------
    em7511 MDM9650    25k-26k     25k-26k     24..25      -50 (const)
    fn980m SDX55      40k (avg)   36k (avg)   -40 (const) 33 (avg)
    lm960 SDX20       28k (avg)   25k (avg)   n/a         24 (const)
    eg18na SDX20 V2   34k (avg)   31k (avg)   n/a         30/125 (var)

The sequence → constellation mapping (1=GPS, 2=SBAS, 4=Galileo, 5=BeiDou,
9=GLONASS) is consistent with OEM DRE (0x14DE).  The 6..8 slots are L5-band
variants that are inactive on most firmwares.

=== names-block:start (auto-generated by tools/inject_names_block_parsers.py) ===

Names by source (from sources/DIAG_LOG_INDEX.yaml):
    canonical: LOG_XO_ADC
        source: qxdm_itemtype_list_zukgit_2025_04_03 (authority: community)
    aliases: (none recorded)

Source-precedence (#N): vendor_official > observation >
community (specification) > community (reference).
=== names-block:end ===
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
#   u8   zeros[16]         @ 25
#   u8   flags             @ 41    state-dependent: {0x01, 0x02, 0x03} (#N)
#   u8   zeros[7]          @ 42
_RF_STATS_FMT = '<BBBBBBBBBiiII16sB7s'
_RF_STATS_SZ = calcsize(_RF_STATS_FMT)
assert _RF_STATS_SZ == 49, f"Expected 49, got {_RF_STATS_SZ}"

# Seq → constellation mapping (matches OEM DRE on SDX20/SDX55/SDX62).
# MC7455 MDM9x30 uses its own seq encoding — see _SEQ_CONSTELLATION_MDM9X30.
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

# MC7455 MDM9x30 (SWI9X30C) uses different seq numbers than the modern
# family.  Seq values observed on MC7455 (9,754 records, 2026-04-21):
#   0 (n=20, outlier c/b≈82), 3 (n=3055, GPS-like),
#   4 (n=20, tiny metric_a — GLONASS?), 7 (n=11), 8 (n=6504, GPS-like),
#   9 (n=72), 10 (n=72).  Absolute constellation mapping not yet
#   confirmed.  The parser deliberately does NOT auto-apply a MDM9x30-
#   specific map because the log packet carries no chipset ID; callers
#   with chipset context can reinterpret ``seq_num`` as needed.


@dataclass
class Diag0x158C:
    """Per-constellation RF statistics report (0x158C).

    One record per constellation/band slot.  The exact semantic of the
    metric fields is not yet determined — the strong mathematical
    relationships (metric_c ≈ 28.6 × metric_b, metric_d ≈ 0.441 × metric_b)
    suggest they are RF front-end signal/noise statistics derived from
    the same underlying accumulator.
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
            'flags': self.flags,
            'active': self.active,
        }


# --- Ground-truth recipe (#N) ------------------------------------------
# v1 is the RM520N-GL (SDX62) emission (byte-0 == 0x01 on 7016 sampled
# records; sub_version 0x01). DISCOVERY design: metric_a..d are RF-chain
# statistics (CN0 / noise-floor / jammer per the #N WiGLE tagging), with
# the internal fixed-point RATIOS pinned across chipsets (c/b ≈ 28.611,
# d ≈ b/4 on SDX20) but the ABSOLUTE physical quantity + dB scaling NOT yet
# pinned. The recipe grounds the per-(constellation,band) metrics against
# NMEA GSV per-SV C/N0, aggregated per constellation via the seq_num→
# constellation map, to recover which metric is CN0 (dB-Hz) and its scale.

@register(
    LOG_GNSS_RF_STATS, domain="gnss",
    name="0x158C",
    primary_issue=None,  # #N: per-code diag 0x158C tracker (vs #N recipe meta)
    description="Per-constellation RF signal statistics (0x158C)",
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    version=5,
    source_type="re",
    source_detail="Clean-room RE from FN980m SDX55 + EG18-NA SDX20 V2 + RM520N-GL SDX62 DLF captures (#N); v=0x01 + c/b=28.611 / d/b=0.441 ratios HW-confirmed on T99W640 SDX72, seq 10-16 unmapped (#N, 2026-06-10)",
    source_url="",
    # version, sub_version, seq_num, constellation, metric_a, metric_b,
    # metric_c, metric_d, flags, active — 10 named fields covering every
    # byte of the 49B per-(constellation,band) record. (#N)
    fields_identified=10,
    fields_parsed=10,
    # version=0x01 / sub_version=0x01 confirmed across 1.09 M records,
    # 235 captures, 16 chipsets (offset 0/1 distribution shows no
    # other value). flags @ +41 is state-dependent and NOT invariant
    # (0x02 82.6 %, 0x03 10.8 %, 0x01 6.6 %). (#N)
    field_invariants={
        "version": {"enum": [0x01]},
        "sub_version": {"enum": [0x01]},
    },
    # WiGLE tagging — #N Phase 6 chain 1 (cluster 1 GNSS, 2026-05-16).
    # Per-constellation RF chain statistics: CN0 metrics, jammer indicator,
    # noise floor. These directly drive the fix-quality interpretation that
    # feeds WiGLE's AccuracyMeters / signal-quality columns for GNSS captures.
    # Closed-vocab match: gnss-quality. No identity / position / PCI-EARFCN
    # fields at the dataclass level so no additional roles apply.
    wigle_direct=True,
    wigle_roles=("gnss-quality",),
)
def parse_0x158c(log_time: int, data: bytes) -> Diag0x158C | None:
    """Parse a GNSS RF Stats (0x158C) log payload.

    Returns None if the payload is too short.
    """
    if len(data) < _RF_STATS_SZ:
        return None
    # Layer-1 version gate (#N): byte[0] is version invariant 0x01 across
    # 1.09M records, all chipsets. Reject foreign payloads.
    if data[0] != 0x01:
        return None

    (version, sub_version,
     _r0, _r1, _r2,
     seq_num,
     _r3, _r4, _r5,
     metric_a, metric_b, metric_c, metric_d,
     _zeros, flags, _trail) = unpack_from(_RF_STATS_FMT, data)

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
        flags=flags,
        active=active,
    )
