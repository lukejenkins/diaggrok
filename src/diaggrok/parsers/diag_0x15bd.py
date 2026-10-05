"""0x15BD — GNSS report of 10 × 28 B sub-record samples (LOG_RGS_LOG_PACKET).

See the class docstrings below for the field map and evidence.

Log name: LOG_RGS_LOG_PACKET
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


# ---------------------------------------------------------------------------
# 0x15BD — Rare fixed-size report (289 bytes)
# ---------------------------------------------------------------------------

@dataclass
class V3SubRecord:
    """Per-sub-record fields for 0x15BD v=3 payloads (modern chipsets).

    Each sub-record is 28 bytes. 10 sub-records per 289-byte v=3 payload,
    starting at payload offset 9.

    ## Sub-record classes — byte [25] is the real discriminator

    ``kind_tag`` (byte [7]) == 0x57 ("kind A") vs 0x00 ("kind B") is only a
    coarse split. A 72,590-sub-record walk (73 captures / 45 chipsets) shows
    only **five** (kind_tag, end_tag_b, byte6≠0, byte27≠0) combinations
    exist, and byte [25] (``end_tag_b``) splits "kind B" in half:

    | ``kind`` [7] | ``end_tag_b`` [25] | [6]≠0 | [27]≠0 | count  |
    |--------------|--------------------|-------|--------|-------:|
    | 0x57         | 0x01               | yes   | yes    |  6,326 |
    | 0x57         | 0x01               | yes   | no     |     82 |
    | 0x00         | 0x0D               | no    | no     | 33,120 |
    | 0x00         | 0x11               | no    | no     | 32,995 |
    | 0x00         | 0x04               | no    | no     |     67 |

    ``end_tag_b == 0x11`` is as common as 0x0D. It is **NOT a whole-record
    mode** — it is a **per-sub-record sample type**. A v=3 record is simply
    the next 10 sub-records of a continuous 1-per-second stream, so:

    - **0x0D, 0x11 and kind-A (0x01) freely interleave in arbitrary slot
      positions, and all three co-occur in a single 289-byte payload.**
      Byte-proven in two *clean bench* (drop-free) captures: an EM9291 GNSS
      comparison capture emits a record decoding ``DDDQQQQAQQ`` — 3×0x0D +
      6×0x11 + 1×kind-A in one payload — and dozens like ``ADADADDAAD``
      (kind-A/0x0D interleaved every which way); on an RM500Q-AE GNSS
      comparison capture record 5 = ``AQAAAAAAAD`` (sub[1]=0x11,
      sub[9]=0x0D). Kind-A interleaves with 0x11 as well as with 0x0D
      (6/77 records on that EM9291 capture).
    - Pure ``0x11×10`` / ``0x0D×10`` records come from the
      **continuous-measurement (driving) regime**: every 1 Hz slot in the
      window happens to be a measurement of the same class, which can make
      the class look like a whole-record mode. In a 9-capture spot check
      990/1,095 records were pure-single-class — but 673 of those come from
      two RM500Q-AE drive captures (all ``0x11×10``); the two stationary
      bench captures show the interleave openly.
    - 0x0D vs 0x11 nonetheless appear in **sustained runs**, not
      sample-to-sample noise: EM9291 holds 0x0D for ~44 records, switches to
      0x11 for ~5 (one transition record carries both), then returns to 0x0D.
      So the class is a receiver STATE sampled per sub-record; its meaning
      (constellation set / tracking mode / fix class) is still **open**.

    The counts in the table above are per-*sub-record*. 0x11 is emitted by
    em9190/RM520N-GL/RM500Q-AE/EM9291/RXM-G1/SIM8202G-M2/T99W640/M2000/
    RG520N-NA; 0x0D by EG25-G/FN980/LM960/EP06/SIM7600NA and others — but that
    split is per-CAPTURE dominance, not a chipset property: RM500Q-AE and
    EM9291 each emit both, sometimes in the same record.

    ## Layout

    Corpus basis: 72,590 v=3 sub-records / 7,259 records / 73 captures
    unless a line says otherwise.

    ```
    off  type   name                notes
     0..3  u32LE  tick                MILLISECOND clock. Not an arbitrary
                                       counter: over 50 captures the
                                       transport ts64 (52.4288 MHz, applied
                                       by the DIAG framework — an
                                       INDEPENDENT clock) gives a median
                                       52,428.8 ts64 per tick, i.e.
                                       999.999 Hz, median |error| 1.2 ppm
                                       (best 0.0, worst 7.9).
                                       It is the SCFB-COMPENSATED F3
                                       ``TkMs`` (GROUNDED, two chipsets):
                                       header_tick ≈ TkMs·(1 − SCFB·1e-6),
                                       SCFB = the slow-clock frequency bias
                                       (ppm) of ``mc_slow_clk.c:3536`` /
                                       ``:3327``:
                                       - EG25-G (737 rec × 8,999
                                         ``:2464`` TkMs frames, 1,798 s):
                                         TkMs − header_tick = 1,129 →
                                         1,160 ms, slope vs TkMs
                                         +15.437 ppm; mean SCFB +15.318;
                                         TkMs·SCFB predicts 1,137 ms
                                         (obs 1,144, 0.6 %).
                                       - EG18-NA (369 rec × 1,649
                                         ``:2384`` frames): slope −0.071
                                         ppm, SCFB −0.059; gap −1.6..+1.3
                                         ms (|TkMs − header_tick| ≤ 1 ms
                                         in 99.9 %).
                                       Hence header_tick tracks DIAG ts64
                                       to −0.03 ppm while raw TkMs runs
                                       +15.4 ppm on the biased EG25-G. Not
                                       GPS time (F3 ``GpsMs`` 7.4 M ms
                                       away).
                                       ``0x60`` LABELS the same clock
                                       (2 chipsets):
                                       ``EVENT_GNSS_TLE_TIME_UPDATE_C``
                                       (id 1951, 15 B, ~1 Hz) carries it
                                       at payload [1:5] u32, paired with
                                       GPS week u16 [9:11] + GPS
                                       ms-of-week u32 [11:15] — the TLE's
                                       local-ms↔GPS time transfer.
                                       event − header_tick (interp at the
                                       event ts64): EG25-G median −0.47 ms
                                       (p5..p95 −1.07..+0.66, slope
                                       +0.15 ppm, 1,799/1,799 within
                                       ±50 ms; raw TkMs − event +15.30
                                       ppm ≈ SCFB); EG18-NA −0.07 ms
                                       (439/439). Time-shifted controls
                                       (±60 s, +600 s): 0 hits.
                                       EG18-NA's SCFB ≈ −0.06 ppm is
                                       below the 1 ms resolution over
                                       30 min, so only EG25-G (+15.3 ppm)
                                       DISCRIMINATES compensated vs raw
                                       TkMs; EG18-NA is consistent, not
                                       discriminating.
                                       Full u32 (it can look 24-bit on
                                       short-uptime captures).
     4..5  u16LE  aux_u16             kind A only; 0 otherwise. 1 Hz COUNTER:
                                       +1 per kind-A sub-record, and kind-A
                                       sub-records are emitted at exactly
                                       1000 ms of ``tick``. ``tick -
                                       1000*aux_u16`` is stable to ~±12 ms
                                       within a capture (12 distinct offsets
                                       over 287 samples) — a free-running 1 Hz
                                       counter loosely aligned to tick, NOT an
                                       exact function of it.
     6     u8     possibly_session_tag  kind A only; 0 otherwise. Not a
                                       constant — 17 distinct
                                       values corpus-wide (1, 5, 15, 19, 24,
                                       28, 34, 35, 38, 44, 53, 66, 93, 161,
                                       162, 172, 173), and **constant within a
                                       capture in 19/19 captures that carry
                                       kind-A records**. Two captures of one
                                       wistron 81UMV91M21 differ by exactly 1
                                       (161/162), which is why the name says
                                       *possibly*: a boot/session counter is
                                       the natural reading (cf. 0x1509
                                       ``fw_tag`` stepping 0x7f→0x80 on the
                                       same bench) but is NOT grounded.
     7     u8     kind_tag            0x57 or 0x00. Coarse discriminator; see
                                       the class table above — [25] is finer.
     8..11 4B     reserved_zeros      always 0 (72,590/72,590)
    12..13 u16LE  field_x             SLOW-CLOCK-domain quantity — MIRRORS the
                                       SCFB coupling of field_y/z (rank ρ vs F3
                                       ``SCFB`` = −0.71..−0.83, detrended).
                                       NOT a counter and NOT a
                                       clock: across consecutive 1 Hz kind-A
                                       sub-records Δfield_x spreads over
                                       {-6..+19} with 65/286 steps == 0
                                       (mean 5.36/s) — a drifting quantity.
                                       Corpus range 3,561..57,268. Kind A and
                                       kind B sampled ~100 ms apart carry
                                       DIFFERENT values (32641 vs 32638), so
                                       the classes are parallel channels, not
                                       checkpoint/delta of one channel.
                                       v=2 also exposes this offset under
                                       the deprecated alias ``tick`` — see
                                       :class:`V2SubRecord`.
    14..15 u16LE  flag_14            NOT always 0. Zero everywhere except
                                       Quectel RG520N-NA (Casa CFW3212 +
                                       rg520n-na surveys), where it is
                                       constant **1** — 390/72,590 sub-records
                                       across exactly 2 captures.
    16..17 i16LE  field_y             SLOW-CLOCK FREQUENCY-BIAS-domain — co-varies
                                       with F3 ``SCFB`` (rank ρ +0.71..+0.83,
                                       detrended; GROUNDED). Signed;
                                       corpus range -5,369..3,544; steady-state
                                       centered ~ -95 and drifting (NOT near
                                       zero — see below).
    18..19 i16LE  field_z             SLOW-CLOCK FREQUENCY-BIAS-domain, twin of
                                       field_y (ρ +0.71..+0.83 vs SCFB; tracks
                                       field_y closely, |z-y| ~10..30 on EG25-G).
                                       Signed; corpus range -5,612..3,579.
    20..23 4B     reserved_zeros      always 0 (72,590/72,590)
    24     u8     end_tag_a           constant 1 (72,590/72,590)
    25     u8     end_tag_b           SUB-RECORD CLASS: 0x01 / 0x0D / 0x11 /
                                       0x04 — see the class table above.
    26     u8     aux_byte            kind A only (165 distinct values); 0
                                       otherwise.
    27     u8     byte_27             UNIDENTIFIED live payload, kind A only.
                                       Nonzero in 6,326/6,408 kind-A
                                       sub-records (98.7%) and in 0/66,182
                                       non-kind-A. 149 distinct values; 351
                                       distinct (aux_byte, byte_27) pairs.
                                       Not a constant, although a small
                                       sample can show it as constant 1.
    ```

    ## field_x / field_y / field_z ARE slow-clock frequency-bias-domain
    ## quantities — GROUNDED against F3 ``SCFB``

    A 30-minute steady-state EG25-G capture (737 records + **2,175,393**
    plaintext ``0x79`` F3 records) grounds the triple:
    **field_y and field_z co-vary with the receiver's Slow-Clock Frequency Bias
    (``SCFB``); field_x is the mirror of them.** Print site
    ``mc_slow_clk.c:3536`` — ``DPO11: SCDiff … GpsTDiff … SCFB 15.456948
    SCFBUnc … SCFBRaw 15.456099`` — token ``SCFB``:

    | field   | rank ρ vs SCFB, linear→quartic detrend |
    |---------|----------------------------------------|
    | field_y | +0.828 → +0.774 → +0.731 → +0.711      |
    | field_z | +0.827 → +0.770 → +0.729 → +0.711      |
    | field_x | −0.828 → −0.772 → −0.730 → −0.713      |

    Why this is a real coupling and not the trend confound below:
    - **Stable across detrend order.** A shared-trend/curvature artifact
      collapses toward 0 as the polynomial soaks up the common curve; SCFB
      holds ≈0.71 even at quartic. The positive control (field_y~field_z, the
      same quantity ±15) holds at ≈0.99 throughout.
    - **Specific to SCFB.** ``SCFBRaw`` (SCFB's near-twin) tracks at +0.63→+0.46;
      the *other* tokens printed on the very same F3 line — ``SCDiff`` and
      ``GpsTDiff`` — read ρ≈+0.01, so it is not the line's cadence aliasing the
      field. Competing GNSS-geometry tokens (``PDOP``, ``NumSvAbove20``, ``Alt``)
      sign-flip and collapse under higher-order detrend — the curvature-confound
      signature.
    - This **explains the cold-start convergence**: field_y decaying 653→27 over
      the 336 s cold-start acquisition IS the clock-bias estimate settling as the
      receiver locks. Same physics, both captures.

    ## Tested negatives

    - **No F3 record prints any of them as a literal integer.** Exhaustive
      nearest-in-time (±1.2 s) exact-integer match over all 422,416 F3
      records of a cold-start capture found nothing above coincidence (best 7
      distinct values, 0.3% hit).
      They co-*vary* with SCFB but are **not** an F3-printed value — and **not a
      scaled/proportional uncertainty**: field_y/SCFB ratio CV is 0.75..0.96
      (``FUnc``/``TUnc``/``SCFB``/``SCFBUnc``/``UcMs``/``Unc`` all fail the
      constant-ratio test). Monotone co-variation, not a linear map.

    ## Steady state: the fields drift, they do not settle at zero

    field_y/field_z converge during cold-start acquisition, but they are
    neither near zero nor flat in steady state. In the 30-min steady-state
    capture field_y is centered **−95.6** (min −146, max 61), field_z
    **−107.4**, and all three **drift monotonically across the window** (kind-A
    field_y early-mean −7.9 → late-mean −136.9; field_x climbs 34290→34803). A
    40-record steady-state EG25-G test fixture pins this.

    ## Methodology: the monotone confound is trend-driven, not cold-start-driven

    A steady-state capture does not rescue raw rank correlation from the
    confound: because field_x/y/z carry their own slow secular drift *even in
    steady state*, raw Spearman against any monotone F3 clock/counter
    (``mc_clock.c``, ``mc_slow_clk.c`` timestamps, …) still returns ≈0.987 for
    ~dozens of unrelated sites. The confound is *trend*, not *cold-start*. The
    instrument that isolates real coupling is a **trend-robust** one —
    first-differences (validated: tick~mc_clock Δρ=0.812) or, less lossily,
    **linear+ detrend-residual rank correlation** (used above; validated:
    field_y~field_z=0.994). Raw rank correlation on a drifting field is never a
    grounding, in either capture regime.
    """
    tick: int
    kind: int         # byte [7]: 0x00 or 0x57 — see end_tag_b for the finer class
    aux_u16: int
    field_x: int
    field_y: int
    field_z: int
    aux_byte: int
    possibly_session_tag: int = 0   # byte [6]
    end_tag_b: int = 0              # byte [25] — real sub-record class tag
    byte_27: int = 0                # byte [27] — live, unidentified
    flag_14: int = 0                # bytes [14:16] — 0 except RG520N-NA (==1)

    def to_dict(self) -> dict[str, Any]:
        return {
            'tick': self.tick,
            'kind': self.kind,
            'aux_u16': self.aux_u16,
            'field_x': self.field_x,
            'field_y': self.field_y,
            'field_z': self.field_z,
            'aux_byte': self.aux_byte,
            'possibly_session_tag': self.possibly_session_tag,
            'end_tag_b': self.end_tag_b,
            'byte_27': self.byte_27,
            'flag_14': self.flag_14,
        }


@dataclass
class V2SubRecord:
    """MDM9x30/9x35 (v=2) per-sub-record fields — 28 bytes each, 10 per payload.

    ## The whole 28-byte sub-record is the v=3 layout

    Corpus basis: **all 243 v=2 records / 2,430 sub-records / 11 captures**
    (MC7455 + EM7455 MDM9x30, and Netgear AirCard 791L MDM9x35).
    ``285 = 289 - 4``: a v=2 payload is a v=3 payload **minus the 4-byte
    header_tick**, and every sub-record byte maps 1:1 onto
    :class:`V3SubRecord` — only the UNIT of [0:4] differs:

    | off     | v=2 name               | measured on v=2 (2,430 sub-records)       |
    |---------|------------------------|-------------------------------------------|
    | [0:4]   | ``time_s``             | u32 SECONDS on the modem system clock — GROUNDED below |
    | [4:6]   | ``aux_u16``            | kind-A only; ``== time_s & 0xFFFF`` in 130/142, ±1 in 12 |
    | [6]     | ``possibly_session_tag`` | kind-A only; 34 in 142/142 (one capture) |
    | [7]     | ``kind``               | 0x57 (kind A, 142) / 0x00 (2,288)          |
    | [8:12]  | zeros                  | 0 in 2,430/2,430                           |
    | [12:14] | ``field_x``            | u16, as v=3                                |
    | [14:16] | ``flag_14``            | 0 in 2,430/2,430                           |
    | [16:20] | ``field_y``/``field_z``| i16, as v=3                                |
    | [20:24] | zeros; [24] == 1       | 2,430/2,430                                |
    | [25]    | ``end_tag_b``          | {0x0D: 2,278, 0x01: 142 (== kind A), 0x04: 10} |
    | [26]/[27] | ``aux_byte``/``byte_27`` | nonzero on 106 kind-A + 3 others        |

    On a single capture [1:4] can look like an invariant tag trio
    (``05 07 57``); at corpus scale [1] takes 18 values and [2] six, because
    [1:4] are the upper bytes of ``time_s``, and [4:8] carry the kind-A trio
    on the one capture that emits kind A.

    ### ``time_s`` [0:4] — GROUNDED: whole seconds of the DIAG-timestamp clock

    - **Independent clock:** the LAST sub-record's ``time_s`` equals
      ``floor(ts64 seconds)`` of the record's own DIAG transport timestamp
      (``(ts64 >> 16) * 1.25 ms``) in **243/243** records, all 11 captures,
      both chipset families. It is NOT the v=3 millisecond ``tick`` —
      same offset, different quantity (version-bound). (Neither is the F3
      ``TkMs`` slow clock — see the v=3 ``tick`` note.)
    - **F3 names it** (an EM7455 all-diag + F3 capture, 159,714 plaintext
      0x79): ``gpstask.c:957`` prints ``M: time_stamp_gps = %d,
      time_stamp_local = %d``; ``time_stamp_local == floor(F3 ts64 s)`` in
      155/155 and matches the co-temporal 0x15BD ``time_s`` (0/±1 s — the
      window's sampling instants), while ``time_stamp_gps == local + 19`` in
      155/155. The hashed 0x92 site ``cd_svcalc.c:2328`` arg0 runs
      ``ts + 18`` (878/1,033). So ``time_s`` is the firmware's
      ``time_stamp_local`` — seconds since the GPS epoch (1980-01-06) on the
      system clock, **leap seconds NOT applied**; true GPS seconds ≈ +18.
    - **Before system time is known it counts from boot:** the two
      post-reset MC7455 captures start at ``time_s == 7`` and jump by
      ~1.46e9 mid-record once time is set; the AirCard 791L (no GNSS time
      on a CDMA-search drive capture) sits at ~355,043 s — and so does its
      ts64.
    - **Windows may carry a stale prefix:** the EM7455 F3 capture's first
      record's subs [0:4] are 246,552 s (2.85 days) older than subs [4:10] —
      the sample ring survives across sessions. 3/243 records carry a
      >1,000 s intra-record jump, each the first record of its capture.
    - Up to 4 sub-records share one ``time_s`` (the stream samples faster
      than 1 Hz but stamps at 1 s resolution); consecutive records share 0
      sub-records in 218/231 pairs — a record is the next 10 samples.

    ``slot_id``/``tag_a`` remain as back-compat fields: they are simply bytes
    [0] and [1] of ``time_s``. ``Diag0x15BD.header_tick`` on v=2 is NOT a
    header field (v=2 has none) — it reads payload [5:9], which is
    ``v2_sub_records[0].time_s``.

    ### ``field_x``/``field_y``/``field_z`` — v=3's SCFB relation replicates

    The same EM7455 capture prints ``mc_slow_clk.c:3557`` (``SCFB %f``) 154×.
    Per-second v=2 means vs same-second SCFB (153 s aligned), detrended
    rank ρ (deg 1/2/3): field_x −0.59/−0.59/−0.57, field_y +0.57/+0.56/+0.55,
    field_z +0.59/+0.58/+0.57; lag-shuffle null p95 0.34; same-line
    ``SCDiff``/``GpsTDiff`` +0.04 (specific to SCFB). Same sign structure as
    v=3 (ρ≈0.71) but one 2.5-min capture and a weak first-difference
    signal — corroboration, not a v=2 grounding. Fields stay unnamed.

    F3 summary for v0x02: GROUND ``time_s`` (gpstask.c:957 time_stamp_local +
    ts64 243/243); CORROBORATE field_x/y/z SCFB domain. 0x60: absent on all
    11 captures. qcsuper/SCAT: silent (0x15BD not in either table). The [25]
    class meaning remains open (v=2 shows only 0x0D/0x01/0x04, never 0x11).

    ## [12..25] is a COMMON interior shared with v=3

    Bytes [12..25] carry identical structure in both variants — verified over
    2,060 v=2 and 72,590 v=3 sub-records:

    | off      | v=2 deprecated alias | v=3 name    | shared evidence                       |
    |----------|----------------|-------------|---------------------------------------|
    | [12:14]  | ``tick``       | ``field_x`` | u16; ranges overlap (v2 26,173..38,664 / v3 3,561..57,268) |
    | [14:16]  | zeros          | ``flag_14`` | 0 in all 2,060 v=2                     |
    | [16:18]  | ``field_a``    | ``field_y`` | i16 — see the signedness note below    |
    | [18:20]  | ``field_b``    | ``field_z`` | i16                                    |
    | [20:24]  | zeros          | zeros       | 0 in 2,060/2,060 and 72,590/72,590     |
    | [24]     | 1              | 1           | constant 1 in both                      |
    | [25]     | 0x0d           | class tag   | v=2 also takes {0x01: 142, 0x0d: 1908, 0x04: 10} — v=2 has kind-A sub-records too |

    Byte [12] is ``field_x``, a drifting quantity (~9/s on v=2; the
    equivalent EG25-G v=3 measurement is ~5.4/s with 65/286 zero steps), not
    a clock. v=2 has **no millisecond clock at all** — its u32 at [0:4] is
    ``time_s``, a SECONDS clock (above), not a counter + marker pair.
    ``tick``/``field_a``/``field_b`` remain as deprecated @property aliases.

    ## Signedness — [16:18] and [18:20] are i16, not u16

    A u16 histogram over all 2,060 v=2 sub-records is **bimodal at the two
    extremes and empty in between**:

        u16 in     0..4,095  →   310 sub-records
        u16 in 61,440..65,535 → 1,750 sub-records   (85.0%)
        anything else         →     0

    That is the signature of a signed field read as unsigned: e.g. an EM7455
    GNSS comparison capture emits 63,058, which is **-2,478**. The same
    offsets are ``<h`` in v=3, whose corpus range genuinely spans
    -5,369..3,544.

    Semantic interpretation of field_x/field_y/field_z is still open; see
    :class:`V3SubRecord` for the tested negatives that also apply here.
    """
    slot_id: int           # byte [0] — low byte of time_s (back-compat)
    tag_a: int             # byte [1] — bits 8..15 of time_s (back-compat)
    field_x: int
    field_y: int
    field_z: int
    end_tag_b: int = 0     # byte [25] — {0x01, 0x0d, 0x04}, same tag as v=3
    time_s: int = 0        # u32 [0:4] — system-clock SECONDS (time_stamp_local)
    aux_u16: int = 0       # u16 [4:6] — kind A only; time_s & 0xFFFF
    possibly_session_tag: int = 0  # u8 [6] — kind A only
    kind: int = 0          # u8 [7] — 0x57 kind A / 0x00
    flag_14: int = 0       # u16 [14:16] — 0 corpus-wide on v=2
    aux_byte: int = 0      # u8 [26]
    byte_27: int = 0       # u8 [27]

    @property
    def tick(self) -> int:
        """Deprecated alias for :attr:`field_x` — byte [12] is NOT a clock.

        [12:14] is the same field v=3 calls ``field_x``, a drifting quantity,
        not a tick. v=2 carries no millisecond clock (that is the v=3-only
        u32 at [0:4]).
        """
        return self.field_x

    @property
    def field_a(self) -> int:
        """Deprecated alias for :attr:`field_y` (v=3's name for [16:18]).

        NOTE this offset is i16, not u16.
        """
        return self.field_y

    @property
    def field_b(self) -> int:
        """Deprecated alias for :attr:`field_z` (v=3's name for [18:20]).

        NOTE this offset is i16, not u16.
        """
        return self.field_z

    def to_dict(self) -> dict[str, Any]:
        return {
            'slot_id': self.slot_id,
            'tag_a': self.tag_a,
            'field_x': self.field_x,
            'field_y': self.field_y,
            'field_z': self.field_z,
            'end_tag_b': self.end_tag_b,
            'time_s': self.time_s,
            'aux_u16': self.aux_u16,
            'possibly_session_tag': self.possibly_session_tag,
            'kind': self.kind,
            'flag_14': self.flag_14,
            'aux_byte': self.aux_byte,
            'byte_27': self.byte_27,
            # Back-compat emission (deprecated names, corrected values).
            'tick': self.field_x,
            'field_a': self.field_y,
            'field_b': self.field_z,
        }


@dataclass
class Diag0x15BD:
    """Rare GNSS report (0x15BD) — size varies by chipset generation.

    ## Size variants

    - **289 bytes** — all modern chipsets (SDX20+: EM7511 MDM9650,
      LM960 SDX20, EG18-NA SDX20 V2, EM9190 SDX55, etc.), version byte == 3
    - **285 bytes** — MC7455/EM7455 (MDM9x30) and AirCard 791L (MDM9x35),
      version byte == 2; 4 bytes shorter because it has NO header_tick —
      the 10 sub-records start at [5] and use the v=3 sub-record layout
      with [0:4] in seconds (see :class:`V2SubRecord`)

    ## Invariants across modern (289B, version=3) chipsets

    Verified across **174 captures / 7,187 records / 9 chipsets**, including
    the SDX62-class RM520N-GL (100 recs) and Inseego M2000:

    - [0] ``version`` — always **3** (modern); **2** on MC7455 (legacy)
    - [1] ``sub_type`` — always **1**
    - [2] ``counter`` — LOW byte of the u16LE record counter ``counter16``
      at [2..3] (increments per record, wraps 255→0 every 256 records)
    - [3] ``byte_3`` — HIGH byte of ``counter16`` (carries 0→1 at each
      byte-2 wrap). NOT a state flag: byte_3 just reflects how many times
      byte 2 has wrapped, so it stays 0 on short captures and climbs
      (0x0f/0x1e/0xfd seen) on long sessions.
    - [4] ``record_type_tag`` — always **10 (0x0A)** across ALL chipsets
      including MC7455 (``flags`` is a deprecated alias — a byte with a
      constant value is a record-type identifier, not runtime flags)
    - [8], [12] — **NOT always 0** at corpus scale (short-uptime captures
      can make them look constant). Byte [8] is the high byte (bits 24..31)
      of ``header_tick`` (u32LE @ [5..8]); on extended-uptime / cold-start
      captures it carries values 0x01, 0x02, 0x06. Byte [12] is the
      analogous bits 24..31 of ``v3_sub_records[0].tick``. ``[8]`` is
      populated on MC7455 v=2 (carries 0x57 — first byte of v=2 sub-record
      trailer; ``header_tick`` is v3-only).

    ## Body structure — v3 (modern)

    Offsets [9..288] hold 10 × 28-byte sub-records (see :class:`V3SubRecord`
    for layout).

    Offsets [5..8] are a single ``u32LE header_tick`` field: the
    log-emission time in **MILLISECONDS**, on the same clock as
    ``V3SubRecord.tick``.

    **``header_tick`` is the tick of the LAST sub-record, ±1 ms.** Measured
    over 7,259 v=3 records / 73 captures / 45 chipsets:

    - ``header_tick == v3_sub_records[-1].tick`` — 7,053/7,259 (97.16%)
    - ``header_tick == v3_sub_records[-1].tick + 1`` — 206/7,259 (2.84%)
    - anything else — **0/7,259**

    So ``0 <= header_tick - v3_sub_records[-1].tick <= 1`` holds corpus-wide.
    The record is emitted at the instant its last sub-record is stamped, and
    the 1 ms cases are rounding, not latency.

    The delta against ``v3_sub_records[0]`` (e.g. +3,592 to +7,176 ticks on
    em7511, +4,998 to +5,120 on lm960, +5,371 to +6,395 on ec25/eg25g) is not
    a chipset/firmware-specific quantity: it is simply the **span of the
    10-sub-record window** (how long the window took), which naturally
    differs per capture. ``header_tick > v3_sub_records[0].tick`` holds in
    7,259/7,259.

    Bits 16..23 of this u32 (``param_b``) take per-capture value sets (em7511
    {3..8}, lm960 {126..130}, eg18na {12..15}, em9190 {92..93}) that reflect
    modem uptime, not a chipset-specific kind.

    ## Body structure — v2 (MC7455 MDM9x30 legacy)

    Ten fixed 28-byte sub-records from offset 5, no remainder. The
    sub-record is the full v=3 layout with a u32 ``time_s`` (seconds) at
    [0:4] — see :class:`V2SubRecord`. When ``version == 2`` the parser
    populates ``v2_sub_records`` with the 10 decoded :class:`V2SubRecord`
    instances; modern (v=3) records leave it empty.

    On v=2, bytes [16:18] / [18:20] are **i16, not u16** (85% of the v=2
    corpus is small negatives), and [12:14] (deprecated alias ``tick``) is
    v=3's ``field_x`` — v=2 carries **no** millisecond clock; its clock is
    ``time_s`` [0:4] in whole SECONDS. ``end_tag_b`` is not constant: v=2
    takes {0x01: 142, 0x0d: 1908, 0x04: 10} over 2,060 sub-records.
    """
    log_time: int
    version: int          # byte 0 — always 3 (modern) or 2 (MC7455 legacy)
    sub_type: int         # byte 1 — always 1
    counter: int          # byte 2 — LOW byte of the u16LE record counter
                          #   (see counter16). Wraps 255→0 every 256 records.
    byte_3: int           # byte 3 — HIGH byte of the u16LE record counter
                          #   at [2..3] (see counter16): carries 0→1 exactly
                          #   when byte 2 wraps 255→0, and counter16 = counter |
                          #   byte_3<<8 steps +1 per record. Grounded across
                          #   RM520N-GL (v=3, 281/281 exact +1 steps) and
                          #   MC7455 (v=2), the only non-+1 steps being +2..+4
                          #   gaps in lossy drive captures (dropped records —
                          #   the counter keeps counting). Not a state flag:
                          #   long sessions reach high byte_3 (0x0f/0x1e/0xfd
                          #   observed at corpus scale), short captures sit
                          #   at 0x00.
    record_type_tag: int  # byte 4 — always 10 (0x0A) on all chipsets
    header_tick: int      # u32LE @ [5..8] on v=3 — log-emission time in
                          #   MILLISECONDS. Equals
                          #   v3_sub_records[-1].tick or that +1 in
                          #   7259/7259 records (2,424 records / 979 files:
                          #   header_tick − last tick ∈ {0: 2351, 1: 73},
                          #   0 violations). The ms rate is grounded
                          #   against the INDEPENDENT transport ts64 clock:
                          #   median 52,428.8 ts64/tick == 999.999 Hz,
                          #   median |err| 1.2 ppm over 50 captures. It is
                          #   the SCFB-compensated F3 TkMs: header_tick ≈
                          #   TkMs·(1 − SCFB ppm·1e-6) — slope +15.437 vs
                          #   SCFB +15.318 ppm (EG25-G), −0.071 vs −0.059
                          #   (EG18-NA); see the V3SubRecord tick note. Not
                          #   GPS time (F3 GpsMs is 7.4M ms away).
                          #   v=2 has NO header_tick (285 = 289 - 4):
                          #   there [5:9] is v2_sub_records[0].time_s, in
                          #   SECONDS. Value kept for back-compat; use
                          #   v2_sub_records[-1].time_s (== floor(ts64 s),
                          #   243/243) for emission time.
    payload_size: int
    body_raw: bytes
    v2_sub_records: list[V2SubRecord]  # populated only when version == 2
    v3_sub_records: list[V3SubRecord]  # populated only when version == 3

    @property
    def counter16(self) -> int:
        """u16LE record counter at bytes [2..3] — ``counter | byte_3<<8``.

        ``counter`` (byte 2) is the low byte and
        ``byte_3`` (byte 3) the high byte of a single 16-bit little-endian
        record counter that increments by 1 per emitted 0x15BD record.
        Grounded by exact +1 monotonicity across RM520N-GL (v=3) and MC7455
        (v=2), with a byte_3 carry at every byte-2 wrap; the only non-+1 steps
        are small forward gaps in lossy wardrive captures (dropped records).
        ``byte[4]`` is the constant ``record_type_tag`` (0x0A), so the counter
        is exactly 16 bits — it does not extend past byte 3.
        """
        return self.counter | (self.byte_3 << 8)

    @property
    def flags(self) -> int:
        """Backward-compat alias for ``record_type_tag``.
        Deprecated — the byte is a fixed record-type marker, not flags.
        """
        return self.record_type_tag

    @property
    def param_a(self) -> int:
        """Deprecated back-compat alias.

        Historically named as ``u16 @ [5..6]``; bytes [5..8] are a single
        u32LE log-emission tick (``header_tick``). ``param_a`` is
        the low 16 bits of that u32.  Kept as a property so existing
        consumers don't break.
        """
        return self.header_tick & 0xFFFF

    @property
    def param_b(self) -> int:
        """Deprecated back-compat alias.

        Historically named as ``u8 @ [7]``; bits 16..23 of ``header_tick``.
        Its per-capture value sets
        (em7511 {3..8}, lm960 {126..130}, eg18na {12..15}, em9190 {92..93})
        are bits 16..23 of the u32 reflecting per-capture modem
        uptime, not a chipset-specific kind.  Kept as a property.
        """
        return (self.header_tick >> 16) & 0xFF

    @property
    def param_c(self) -> int:
        """Deprecated back-compat alias.

        Historically named as a "second value sub-record" at u16 @ 9.  These
        bytes are the low 16 bits of ``v3_sub_records[0].tick`` — not a
        standalone field.  Kept as a property so existing consumers don't
        break; returns 0 on v=2.
        """
        if self.v3_sub_records:
            return self.v3_sub_records[0].tick & 0xFFFF
        return 0

    @property
    def param_d(self) -> int:
        """Deprecated back-compat alias.

        Historically named as a "second kind sub-record" at u8 @ 11.  This
        byte is bits 16-23 of ``v3_sub_records[0].tick``.  The tick is a
        full u32 (not 24-bit), so param_d can take non-zero values on
        long-uptime captures and should not be relied on as a constant.
        Kept as a property; returns 0 on v=2.
        """
        if self.v3_sub_records:
            return (self.v3_sub_records[0].tick >> 16) & 0xFF
        return 0

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            'type': 'Diag0x15BD',
            'log_time': self.log_time,
            'version': self.version,
            'sub_type': self.sub_type,
            'counter': self.counter,
            'byte_3': self.byte_3,
            'counter16': self.counter16,
            'record_type_tag': self.record_type_tag,
            'header_tick': self.header_tick,
            # Back-compat emission
            'flags': self.record_type_tag,
            'param_a': self.param_a,
            'param_b': self.param_b,
            'param_c': self.param_c,
            'param_d': self.param_d,
            'payload_size': self.payload_size,
        }
        if self.v2_sub_records:
            out['v2_sub_records'] = [s.to_dict() for s in self.v2_sub_records]
        if self.v3_sub_records:
            out['v3_sub_records'] = [s.to_dict() for s in self.v3_sub_records]
        return out


# The fixed sub-record array — 10 x 28 B on both versions.
_SUB_RECORDS = 10
_SUB_RECORD_SZ = 28


def _decode_v2_sub_records(body: bytes) -> list[V2SubRecord]:
    """Decode the 10×28B sub-record body on MC7455 (v=2) 0x15BD payloads."""
    sub_records: list[V2SubRecord] = []
    n_sub = len(body) // 28
    for i in range(n_sub):
        s = body[i * 28:(i + 1) * 28]
        if len(s) < 28:
            break
        sub_records.append(V2SubRecord(
            slot_id=s[0],
            tag_a=s[1],
            field_x=unpack_from('<H', s, 12)[0],
            # i16, not u16 — 85% of the v=2 corpus reads as a small NEGATIVE
            # here and the u16 histogram is empty between the two extremes.
            # Same offsets are <h on v=3.
            field_y=unpack_from('<h', s, 16)[0],
            field_z=unpack_from('<h', s, 18)[0],
            end_tag_b=s[25],
            # The v=2 sub-record is the v=3 layout, with [0:4] in SECONDS
            # (time_stamp_local), not v=3's milliseconds.
            time_s=unpack_from('<I', s, 0)[0],
            aux_u16=unpack_from('<H', s, 4)[0],
            possibly_session_tag=s[6],
            kind=s[7],
            flag_14=unpack_from('<H', s, 14)[0],
            aux_byte=s[26],
            byte_27=s[27],
        ))
    return sub_records


def _decode_v3_sub_records(body: bytes) -> list[V3SubRecord]:
    """Decode the 10×28B sub-record body on modern (v=3) 0x15BD payloads.

    Expects ``body`` to be the 280 bytes starting at payload offset 9
    (the 9-byte header has already been consumed by the caller).
    """
    sub_records: list[V3SubRecord] = []
    n_sub = len(body) // 28
    for i in range(n_sub):
        s = body[i * 28:(i + 1) * 28]
        if len(s) < 28:
            break
        sub_records.append(V3SubRecord(
            tick=unpack_from('<I', s, 0)[0],
            kind=s[7],
            aux_u16=unpack_from('<H', s, 4)[0],
            field_x=unpack_from('<H', s, 12)[0],
            field_y=unpack_from('<h', s, 16)[0],
            field_z=unpack_from('<h', s, 18)[0],
            aux_byte=s[26],
            # [27] is nonzero in 98.7% of kind-A sub-records, and [25] is the
            # real sub-record class tag.
            possibly_session_tag=s[6],
            end_tag_b=s[25],
            byte_27=s[27],
            flag_14=unpack_from('<H', s, 14)[0],
        ))
    return sub_records


# Ground-truth recipe — not yet run on hardware (hw_run_performed=False); every
# field is a hypothesis. Target: SIMCom SIM7600NA-H (MDM9207), a v=0x03 / 289B
# emitter (same MDM9x07 class as the EP06-A). This is a
# DISCOVERY/correlation recipe: the decoded fields are GNSS measurement-engine
# internals (monotonic ticks + a slowly-varying epoch index) — no AT command
# returns their literal values, so they ground by emit-gating and increment/
# co-variation, not value-equality. Canonical name LOG_RGS_LOG_PACKET;
# the code appears only while the GNSS engine is running (corpus: GNSS-restart
# edge-case captures).

@register(
    0x15BD, domain="gnss",
    primary_issue=None,
    name="0x15BD",
    description=(
        "Rare GNSS report (0x15BD) — 289B (version=3 modern chipsets) or "
        "285B (version=2 MC7455 MDM9x30 legacy). Header fields: version, "
        "sub_type, counter16 (u16LE record counter @ [2..3], low byte "
        "counter / high byte byte_3), record_type_tag, header_tick (u32LE "
        "@ [5..8] on v=3, log-emission time in MILLISECONDS — equals the last "
        "sub-record's tick ±1 ms). Body is decoded into a list of 10 "
        "28-byte sub-records on both versions: V2SubRecord on v=2 "
        "(time_s, aux_u16, possibly_session_tag, kind, field_x, field_y, "
        "field_z, flag_14, end_tag_b, aux_byte, byte_27; slot_id/tag_a are "
        "the low bytes of time_s) and "
        "V3SubRecord on v=3 (tick, kind, aux_u16, field_x, field_y, field_z, "
        "aux_byte, possibly_session_tag, end_tag_b, byte_27, flag_14). "
        "Back-compat: param_a/param_b/param_c/param_d on the record and "
        "tick/field_a/field_b on V2SubRecord are @property aliases."
    ),
    version=8,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE across FN980m SDX55, EG18-NA SDX20 V2, LM960 SDX20, "
        "EM7511 MDM9650, EM9190 SDX55, EP06A MDM9x07 (289B, version=3) and "
        "MC7455/EM7455 MDM9x30 + AirCard 791L MDM9x35 (285B, version=2); "
        "corpus basis 7,465 records / 72,590+2,060 sub-records / 73 captures / "
        "45 chipsets. Both versions decode into 10×28B sub-records with the "
        "same layout; v=2 lacks the 4-byte header_tick. Header: counter16 "
        "(u16LE record counter @ [2..3], +1/record) and the constant sub_type "
        "/ record_type_tag. v=3 tick/header_tick is a MILLISECOND clock: "
        "999.999 Hz against the independent DIAG ts64 (1.2 ppm over 50 "
        "captures), header_tick == last sub-record tick +0/+1 ms (7259/7259), "
        "and the SCFB-compensated F3 TkMs (header_tick ~= TkMs*(1 - SCFB "
        "ppm*1e-6); slope +15.437 vs SCFB +15.318 ppm on EG25-G, -0.071 vs "
        "-0.059 on EG18-NA). The 0x60 event EVENT_GNSS_TLE_TIME_UPDATE_C "
        "(1951) labels the same clock: payload [1:5] u32 == header_tick "
        "(median -0.47 ms EG25-G 1,799/1,799, -0.07 ms EG18-NA 439/439; "
        "shift controls 0 hits), paired with GPS week [9:11] + GPS "
        "ms-of-week [11:15]. v=2 [0:4] time_s is whole SECONDS of the system "
        "clock (== floor(DIAG ts64 s) 243/243 over 11 captures; named "
        "time_stamp_local by F3 gpstask.c:957, 155/155). Byte [25] is the "
        "per-sub-record class tag (0x01/0x0D/0x11/0x04). field_x/y/z co-vary "
        "with F3 SCFB (detrended rank rho ~0.71..0.83) but no F3 site prints "
        "them; their meaning, byte_27 and the [25] class meaning remain open. "
        "A payload shorter than the fixed header + 10 x 28 B array returns None."
    ),
    source_url="",
    # v=2 and v=3: 7 header + 110 sub-record fields (11 × 10 sub-records) =
    #   117 named. On v=2, slot_id/tag_a are folded into time_s (they are its
    #   bytes [0]/[1] and are not counted twice).
    # These two counters mean "fields the record is known to HAVE" and
    # "fields the parser EXTRACTS" — coverage is parsed/identified, so they
    # are equal here: everything known is decoded. Semantic confidence is
    # tracked separately: `byte_27` is extracted but its MEANING is still
    # open, and `possibly_session_tag` carries the `possibly_` prefix because
    # only its scope is measured (kind-A only, constant per capture), not its
    # meaning. Invariant bytes and reserved zeros account for the residue in
    # both variants.
    fields_parsed=117,
    fields_identified=117,
    # Layer-2 plausibility. Derived from a corpus-wide walk over
    # 8,877 records / 229 captures (offsets 0, 1, 4):
    #
    # `version` (offset+0) — 2 distinct values:
    #   0x03 (8,552 rec, 98.2%): modern chipsets at 289B
    #   0x02 (  155 rec,  1.8%): MC7455 minority at 285B
    #
    # `sub_type` (offset+1) — corpus-wide invariant 0x01 across all 8,877
    #   records. Verified at 4-chipset fixture level (eg18na/em7511/ep06a/mc7455).
    #
    # `record_type_tag` (offset+4) — corpus-wide invariant 0x0A (10) across
    #   all 8,877 records, both v=2 and v=3 families. NOTE: byte[3] is NOT
    #   invariant and NOT a state flag — it is the HIGH byte of the u16LE
    #   record counter at [2..3] (counter16): 0 on captures shorter than 256
    #   records, climbing (0x0f/0x1e/0xfd observed) on long sessions as byte 2
    #   wraps. Not asserted as an invariant (it is a running counter, exposed
    #   via counter16).
    field_invariants={
        "version":         {"enum": [2, 3]},
        "sub_type":        {"enum": [1]},
        "record_type_tag": {"enum": [10]},
    },
)
def parse_0x15bd(log_time: int, data: bytes) -> Diag0x15BD | None:
    if len(data) < 16:
        return None
    if data[0] not in (2, 3):
        return None
    # Both versions are a fixed header + 10 x 28 B sub-records (v=2: 5 + 280
    # = 285 B; v=3: 9 + 280 = 289 B). A shorter payload is truncated and
    # returns None (registry WARN). Only the 10 declared sub-records are
    # decoded; trailing bytes beyond them are tolerated.
    hdr = 5 if data[0] == 2 else 9
    if len(data) < hdr + _SUB_RECORDS * _SUB_RECORD_SZ:
        return None
    body = data[hdr:hdr + _SUB_RECORDS * _SUB_RECORD_SZ]
    v2_sub_records: list[V2SubRecord] = []
    v3_sub_records: list[V3SubRecord] = []
    if data[0] == 2:
        v2_sub_records = _decode_v2_sub_records(body)
    else:
        v3_sub_records = _decode_v3_sub_records(body)
    return Diag0x15BD(
        log_time=log_time,
        version=data[0],
        sub_type=data[1],
        counter=data[2],
        byte_3=data[3],
        record_type_tag=data[4],
        header_tick=unpack_from('<I', data, 5)[0],
        payload_size=len(data),
        body_raw=data[16:],
        v2_sub_records=v2_sub_records,
        v3_sub_records=v3_sub_records,
    )
