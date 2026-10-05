"""Thermal-monitor sensor reading parser (0x14D8, LOG_TEMPERATURE_MONITOR_LOG).

This is not a GNSS log, although the legacy field names (``fix_type``,
``sv_used``, ``fix_flags`` ...) come from an earlier "GNSS ME Position Fix"
reading of it. Every record is ONE temperature reading from ONE thermal
sensor, logged by the modem's thermal monitor microseconds after the driver
print that produced it (F3 ``DALTsens.c`` TSENS, ``VAdcLog.c`` thermistor
conversions, ``rfdevice_therm_common.cpp`` RF-front-end reads). The
``Diag0x14D8`` docstring's "Semantics" section carries the grounded field
map; the sections after it record per-chipset observations under the legacy
field names, which the decoder still emits for back-compat.

0x14D8 has no struct-level relationship to 0x1476 PositionReport; the
cross-references in this docstring are timing correlations only.

Log name: LOG_TEMPERATURE_MONITOR_LOG
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_TEMPERATURE_MONITOR_LOG
from diaggrok.registry import register


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass
class Diag0x14D8:
    """Thermal-monitor sensor reading (0x14D8, LOG_TEMPERATURE_MONITOR_LOG).

    ## Semantics — one record per thermal-sensor reading

    The canonical log name ``LOG_TEMPERATURE_MONITOR_LOG`` describes the
    content; the legacy GNSS field names do not. The thermal monitor polls
    its configured sensors (T99W175 SDX55: one burst every ~5.1 s, right
    after ``mcpm_therm.c`` "Therm request received") and logs one record per
    sensor, microseconds after that driver's own F3 print::

        offset  field (legacy name)                meaning
        +0      u32 version (fix_type)             layout version; 1 on every record
        +4      u32 field_1 (engine_state)         record class: 1 on SDX20/9x07/SDX62;
                                                   2 on SDX55 sensor rows (1 on its
                                                   'hrde'-tagged row). Unresolved (T1).
        +8      u32 sensor_group (num_engines)     firmware-config sensor group
        +12     u32 sensor id (field_3_u32)        hi16 sensor_subgroup : lo16 sensor_index
        +16     i32 temperature_c (fix_flags)      whole degC, truncated toward zero
        +20     84 B (104-byte form only)          zero on every record

    Ground truth:

    - **F3, value-exact 1:1** — ``DALTsens.c:763`` ``"TSENS: Sensor = %u,
      DeciDegC = %i"`` precedes each ``(f2=2, lo16=Sensor)`` record by ~2-10 us
      and ``temperature_c == trunc(DeciDegC / 10)`` on **5,630 / 5,630**
      records (RM520N-GL SDX62, 30-min capture; rounding would match
      only 45%). ``sensor_index`` IS the driver's TSENS sensor number.
    - **F3, per-read, every cycle (T99W175 SDX55, 59/59 cycles)** — ``VAdcLog.c``
      ``PA_THERM`` -> ``(2,0,0:0)``, ``PA_THERM1`` -> ``(2,0,0:1)`` (-40),
      ``SYS_THERM1``/``SYS_THERM2`` -> ``(2,1,0:0)``/``(2,1,0:1)``; TSENS 4/6 ->
      ``(2,2,0:4)``/``(2,2,0:6)``; ``rfdevice_therm_common.cpp`` RFFE PA
      devices 0..3 -> ``(2,0,2:0..3)`` (slots 4..6 absent, -273); QET
      (``rfdevice_papm_therm.cpp``) -> ``(2,0,4:0)``. The XO slot ``(2,5,0:0)``
      tracks ``XO_THERM`` within 1 degC but is NOT value-exact (reads 1 below
      trunc(mdegC/1000) every cycle — likely a filtered XO value).
    - **F3, 104-byte form (MC7411 SDX50M)** — ``PA_THERM1`` -> ``(1,0,0:1)``
      37/37, ``SYS_THERM1`` -> ``(1,0,0:0)`` 61/61, TSENS sensor 2 ->
      ``(1,0,0:2)`` 74/74, TSENS sensor 4 -> ``(1,1,0:4)`` 37/37
      (value-matched per burst).
    - **AT+QTEMP (T3)** — per-sensor joins at r = 0.99-1.00 on an RM500Q-AE
      SDX55 drive (``qfe_wtr_pa0..3`` -> ``(2,0,2:0..3)`` 88-96% exact,
      ``xo-therm-usr`` -> ``(2,5,0:0)`` 93%); RM520N-GL SDX62
      (``modem-mmw0 = -273`` <-> the ``f2=8`` slots, six ``sdr*-pa* = 0`` <->
      the ``f2=7`` rows); EG25-G MDM9607 104-byte form (positional
      ``pmic,xo,pa``: ``pa`` -> ``(1,0,0:0)`` 87-97%, ``pmic`` -> ``(1,1,0:2)``
      83-87%).

    ``sensor_group`` numbering is FIRMWARE-CONFIG-SPECIFIC, not a universal
    class enum: TSENS rows are ``f2=2`` on SDX55/SDX62 but ``f2=0``/``f2=1`` on
    MC7411. Treat ``(sensor_group, sensor_subgroup, sensor_index)`` as an
    opaque per-build sensor key; only ``sensor_index`` == TSENS sensor number
    is F3-proven across generations.

    Value conventions (F3/AT-grounded):

    - ``-273`` (0 K): the slot's sensor is not present (e.g. mmW-module slots
      on a sub-6-only module — ``AT+QTEMP`` prints the same ``-273``) —
      :attr:`is_sensor_absent`.
    - ``-40`` / ``+125`` (``-45`` / ``-50`` on some builds): a thermistor
      channel pinned at its conversion-table rail — open/unpopulated
      (``VADC ... PA_THERM1: nPhysical -40``) or shorted (``nPhysical 125,
      uMicrovolts 0`` on MC7411). The rail a channel sits at is a property of
      the module's board, so the same value recurs on every capture from a
      given module.
    - ``0`` on some groups (``f2=7`` on SDX55/SDX62, ``(6, 0, 0)`` on SDX20):
      a channel that reports zero (``AT+QTEMP``'s ``sdr*-pa*`` rows read 0).

    ## Per-chipset observations (legacy field names)

    The observations below use the legacy names: ``num_engines`` / ``f2`` =
    sensor_group, ``field_3`` / ``f3`` = sub-group:index, ``field_4_i32`` /
    ``f4`` = temperature_c, ``engine_state`` / ``es`` = field_1. A "stage" or
    "burst" is one pass of the thermal monitor's per-build **sensor poll
    order**, and the ``field_3_high16`` values are **sensor sub-group ids**.
    The SDX62 ``high16`` 8/10 pair is two adjacent slots (``8:0``, ``10:0``);
    EM9291 SDX65 polls five (``8:0..8:3``, ``10:0``), so the pairing is
    sensor config, not a flag. The SIM7600NA "bimodal field_4" is two
    different physical sensors.

    ### Size forms

    - **20 B short form** (SDX55, SDX62, SDX72): 5 x u32 header at offsets
      0, 4, 8, 12, 16. ~6 Hz on FN980m (1761 records in a 5-minute capture).
    - **104 B long form** (EG18-NA SDX20 V2, EM7511 SDX20/MDM9650, MC7455
      MDM9x30, MC7411 SDX50M, SIM7600NA-H MDM9x07, LM960 SDX20, EG25-G /
      EC25 / EP06A / EG12-GT MDM9207, MDM9150 C-V2X roadside unit): the same
      20-byte header followed by 84 zero bytes. The tail is **always zero**
      on **12,047 records / 35 chipset+firmware buckets / 5 vendors**,
      including every LM960 firmware build, both EM7511 builds, both
      EG12-GT builds and three EG25-G builds. MC7411 across three firmware
      builds yields 1,847+ records, all 104 B / v=1. ~0.4 Hz on EG18-NA,
      a bursty ~0.6 Hz average on EM7511.
    - **44 B legacy form** (header + 24 B block) is accepted by the parser;
      see "Bytes 20..43" below.

    The MDM9150 roadside unit (Kapsch RIS9260, which houses the
    same 81UMV91M21 modem as the bench captures) emits the 104 B form at 100% parse and reproduces the EM7511
    5-stage poll order stage-for-stage, with ``f4`` reading **+30..+46 °C**
    against +24..+29 °C on indoor bench captures — consistent with a
    sun-exposed roadside enclosure running hotter.

    ### Poll order per chipset — tuples are ``(f2, f3, f4)``

    **EM7511 SDX20/MDM9650** (295 records, 44 bursts, 5 stages)::

        1. (0, 1, -50)
        2. (6, 0,   0)
        3. (1, 4, +25+/-1)
        4. (0, 2, +25+/-1)
        5. (7, 0, +25+/-1)

    Between bursts: ``(0, 0, +25+/-1)``. The ``-50`` rail value does not
    appear on LM960 or EG18-NA.

    **LM960 SDX20** (136 records, 34 bursts, 4 stages)::

        1. (0, 0, +24..25)
        2. (0, 1, +24..25)  ~837 us after 1
        3. (6, 0,   0)      same log_time as 4
        4. (1, 4, +24..27)  same log_time as 3

    All four fire within ~1 ms, and the cycle repeats **every ~10 s**
    (inter-burst gap 524M ticks at the 52.4288 MHz DIAG tick clock). Against
    a contemporaneous 0x1476 PositionReport stream (1,129 records),
    ``field_3_u32`` stays in {0, 1, 4} while 0x1476 reports 3 SVs: the
    field does not track the satellite count.

    **EG18-NA SDX20 V2** (124 records): ``(0,1)``, ``(6,0)``, ``(1,4)`` plus
    ``(0,0)`` — the same order as LM960.

    **MC7455 MDM9x30** (156 records, 5-min stationary capture)::

        1. (0, 0, +30..31)
        2. (0, 1, +30..31)
        3. (6, 0,   0)

    Byte +12 in {0x00, 0x01} — narrower than the LM960/EG18-NA/EM7511
    bucket ({0x00, 0x01, 0x04}) and the EG25-G/EP06A/SIM7600NA bucket
    ({0x00, 0x01, 0x02}).

    **EP06A SDX20** (145 records): ``(0,1)``, ``(6,0)``, ``(6,1)``, ``(1,2)``
    plus ``(0,0)``.

    **MC7411 SDX50M** (617 records across three firmware builds, 6 stages)::

        1. (0, 0, +25..+34)
        2. (0, 1, +125)      constant across all builds; does not track ambient
        3. (6, 0,    0)      is_sdx20_stage2_sentinel
        4. (1, 4, +25..+34)
        5. (0, 2, +25..+34)
        6. (7, 0, +25..+34)

    A superset of the EM7511 order plus the ``(0, 1, +125)`` slot — the
    ``PA_THERM1`` channel at its shorted rail (see Value conventions). The
    test ``test_mc7411_stage_a_f4_constant_across_thermal_stages`` pins its
    independence from ambient. :attr:`engine_generation` returns ``sdx20``
    for all six (104-byte rule).

    **SIM7600NA-H MDM9x07** (124 records, 5-min stationary capture)::

        1. (0, 0, +33..34)
        2. (0, 1, +52..54)
        3. (1, 2, +35..39)   byte +12 = 0x02
        4. (6, 0,   0)

    The ``(0, 1)`` slot reads ~17 °C above the others on the same stream —
    a different physical sensor.

    ### SDX55-family markers (FN980, EM9190, RM500Q, RM520N-GL, Wistron LV55, SIM8202GM2)

    - ``field_1`` (offset +4) takes values in {1, 2} on every SDX55-class
      capture (~82% 2, ~17% 1 corpus-wide), usually varying within a
      capture. SDX20-class chipsets (LM960, EG18-NA, EG25-G, EP06A, EM7511,
      EG12-GT, SIM7600NA, M2000) emit ``field_1 == 1`` on 100% of records,
      so ``field_1 == 2`` anywhere in a capture marks the SDX55 family.
    - Offset +14 (``field_3`` byte 2) takes a stable 6-value distribution
      across every SDX55-class capture::

         offset+14  field_3 upper bucket   share
         --------   --------------------   -----------------
         0x00       0x00000                ~50%
         0x02       0x20000                ~40%, bit 17 set
         0x04       0x40000                ~10%, bit 18 set
         0x08       0x80000                ~3%, bit 19 set
         0x09       0x90000                ~3%, bits 16+19 set
         0x0a       0xa0000                ~3%, bits 17+19 set

      Bits 16/17/18 are mutually exclusive; bit 19 co-occurs with bit 16
      (0x09) or bit 17 (0x0a) but never with bit 18.
    - The ``hrde`` ASCII tag (``field_2 == 0x68726465`` LE = 1701081704) is
      SDX55-family-wide: observed on FN980, EM9190, RM500Q, Wistron LV55
      and SIM8202GM2 (4,832 records, all 20 B, 151 hrde-tagged on the
      ``f1=1`` minority class). Never observed on an SDX20-class capture.

    **Corpus-wide invariants** (138 captures, 71,482 records):
    ``field_0 == 1`` always, and **offset +15 is always 0x00**, so
    ``field_3`` uses at most 24 bits on both the SDX20 and SDX55 layouts.

    ### SDX62 (RM520N-GL)

    A 17,787-record, 1,338.9 s drive capture (DIAG tick rate ~58
    Mticks/s)::

        Tuple (f2, field_3_low16, f4)          Count
        ---------------------------------------------------
        (7, 0, 0)                              7,032 (39.5%)
        (2, 4, +25..+32)                       2,593 (14.6%)
        (2, 6, +25..+32)                       2,593 (14.6%)
        (7, N, 0) for N=1..12                  293 each
        (0, 2, -40)                            293
        (0, 0, +pos), (0, 1, +pos)             293 each
        (8, 0, -273) [high16=8 OR 10]          586
        (0, 0, -273), (0, 1, -273) [high16=4]  196 each
        (9, 0, -273) [high16=0]                98

    ``(2, 4, +)`` and ``(2, 6, +)`` (TSENS sensors 4 and 6) are always
    emitted ~10 us apart (median 551 ticks) at ~1.8 Hz. ``(7, 0, 0)`` fires
    at ~5.3 Hz. Total rate ~13 Hz, against ~6 Hz on FN980m and ~0.5 Hz on
    LM960.

    Temperature behaviour of the ``(2, 4)`` / ``(2, 6)`` pair on 2,593
    consecutive pairs:

    1. Within-pair (10 us apart): ``f4_b - f4_a == 0`` for **82.8%**; the
       rest differ by +/-1.
    2. Inter-pair: ``|f4_a(i) - f4_a(i-1)| <= 1`` for **100%** of
       consecutive pairs.
    3. Capture-quartile means 25.6 -> 26.0 -> 27.7 -> 31.2: a 5-6 °C
       warm-up over 22 minutes of vehicle operation.

    The same ``(f2=2, f3_low in {4, 6})`` coordinates appear on SDX55
    EM9190 (``engine_state=2``, 22+22 records at 26-27 °C in a drive
    capture) and SDX62 (``engine_state=1``); on LM960 SDX20 the
    corresponding slot is ``(1, 4)`` (31 records, all 29 °C, in a
    thermally stable capture).

    The ``(7, N, 0)`` ladder is a **single atomic 36-record burst** emitted
    every ~4.6 s, byte-identical on all 293 occurrences::

        low16 sequence: [0, 1, 2, 3, ..., 12, 0, 0, 0, 0, 0, ...]
                         |<--13 records,-->||<-- 23 records,  -->|
                         |  low16 = 0..12  ||   all low16 = 0    |

    The burst completes within ~200 us (~5 us / ~310 ticks per record):
    sensor group 7 slots that read zero, matching the ``sdr*-pa* = 0`` rows
    of ``AT+QTEMP``.

    **``field_3_high16`` on SDX62** is non-zero on 100% of the
    ``f4 = -273`` records (978/978) and only there. ``high16=4`` occurs
    only with ``f2=0``; ``high16=8`` only with ``f2=8``; bit 1 (``high16=10``)
    only together with bit 3, never alone and never with bit 2. Odd values and
    {2, 6, 12, 14, 16+} never appear in the 17,787 records. The tagged
    records arrive in pairs ~6 us apart (median 342 ticks); ~5.5% of
    records carry a non-zero high16.

    **SDX55 comparison** (EM9190 1,320 records + FN980 32 records from a
    parallel drive capture):

    - ``high16=4`` occurs with ``f2=0`` on both families (EM9190 176/176,
      RM520N 392/392); ``high16 in {8, 9, 10}`` with ``f2=8`` on both
      (EM9190 132/132, RM520N 586/586).
    - SDX55 only: ``high16=2`` alone on 46.7% of EM9190 records (with
      ``engine_state=2`` and ``f2=0``), and ``high16=9`` (bits 0+3) on 44
      records, all ``f2=8`` / ``f4=-273``. An odd high16 value therefore
      separates SDX55 from SDX62.
    - ``high16 != 0`` on ~70% of SDX55 records against 5.5% on SDX62.
    - ``high16 != 0 => f4 = -273`` holds on 100% of SDX62 records but only
      33-52% of SDX55 records (SDX55 emits e.g. ``(high16=4, f4=+23)``).

    ## Bytes 20..43 (legacy "optional position block") are never populated

    The dataclass exposes ``lat``, ``lon``, ``alt`` and a ``has_position``
    property inherited from a reading of bytes 20..43 as a 3 * float64
    position block. **No observed firmware writes that region**: 0 of
    12,047 104 B records across 35 chipset+firmware buckets / 5 vendors has
    a non-zero byte anywhere in [+20..+103] (a strict superset of the
    lat/lon/alt block). SDX55/SDX62 emit only the 20 B form, so the region
    does not exist there.

    Position output lives in **0x1476 PositionReport**, not here. The
    parser does NOT unpack [+20..+43] — ``lat``/``lon``/``alt`` are set to
    0.0 unconditionally and retained only for consumers that read them.
    ``has_position`` is always False on the current corpus, and these
    fields are not counted as parsed: the decoder covers the 5×u32 header
    plus payload_size.

    ## Sentinel values in ``temperature_c`` / ``field_4_i32``

        Family                      Value(s)         Predicate
        --------------------------  ---------------  ----------------------------
        Sensor absent               -273 (= 0 K)     is_sensor_absent /
                                                     is_sdx55_invalid_sentinel
        Thermistor rail             -40 / -45 / -50  (none - per-build lookup)
                                    / +125
        SDX20 zero channel          0 on (6, 0, _)   is_sdx20_stage2_sentinel

    The first and third are structural predicates that apply across every
    capture of their chipset family. The rail values depend on the build
    and board::

        Chipset / build             Value   Tuple signature                           Count
        --------------------------  ------  ----------------------------------------  -----
        SDX20 LM960                 (none)  uses the (6, 0, 0) zero channel           -
        SDX20 EM7511                -50     (es=1, f2=0, f3_low=1, f3_hi=0)           see EM7511 order
        SDX55 EM9190                -45     (es=2, f2=1, f3_low in {0, 1}, f3_hi=0)   88
        SDX55 FN980m                -40     mixed signatures, small sample            3
        SDX62 RM520N-GL             -40     (es=1, f2=0, f3_low=2, f3_hi=0)           293
        SDX50M MC7411               +125    (0, 1, _)                                 see MC7411 order

    LM960, EG18-NA and EP06A show no negative rail value in their poll
    order. Each value is stable for a given chipset/build.

    **For temperature statistics**, filter all three families: leaving them
    in skews the mean toward -273 or toward the rail value. The
    ``is_sensor_absent`` / ``is_sdx55_invalid_sentinel`` and
    ``is_sdx20_stage2_sentinel`` predicates cover the structural families;
    the rail values have no predicate (they differ by build), so exclude
    them by value when the chipset/build is known.

    ## Legacy field names

    The 5 u32 fields at offsets 0..19 keep names from the GNSS-era reading:

    - ``fix_type`` / ``field_0_u32`` (offset 0): the layout version, 1 on
      every record (:attr:`version_byte`).
    - ``engine_state`` / ``field_1_u32`` (offset 4): 1 or 2; record class,
      unresolved.
    - ``num_engines`` / ``field_2_u32`` (offset 8): :attr:`sensor_group`.
    - ``sv_used`` / ``field_3_u32`` (offset 12): sensor sub-group (high 16)
      and index (low 16). Concurrent 0x1476 PositionReport data shows it
      does not track the satellite count on any observed chipset. ``sv_used``
      is a read-only property; pass ``field_3_u32=`` to the constructor.
    - ``fix_flags`` / ``field_4_i32`` (offset 16): signed whole-degC
      temperature (:attr:`temperature_c`), not a bitmask.

    ``to_dict()`` emits the legacy names, the positional ``field_N_*``
    names and the thermal-monitor names over the same bytes.
    """
    log_time: int
    # Legacy names (see docstring). ``field_3_u32`` carries the sensor
    # sub-group/index, not a satellite count; the ``sv_used`` property below
    # preserves the legacy attribute name for read access. Do not pass
    # ``sv_used=`` as a constructor kwarg; use ``field_3_u32=``.
    # u32 at offset 0, surfaced via the ``version_byte`` property as the
    # layout version. It is 1 on every observed record; a future v=0x02
    # firmware is rejected as a layout-version bump, not read as "a
    # different fix-type".
    fix_type: int
    engine_state: int   # u32 at offset 4
    num_engines: int    # u32 at offset 8
    field_3_u32: int    # u32 at offset 12 - sensor sub-group:index, NOT sv count
    fix_flags: int      # u32 at offset 16 - signed i32 temperature (degC)
    # Legacy optional position block (24 B ddd at offsets 20..43)
    lat: float          # degrees (0.0 if no fix or payload < 44 bytes)
    lon: float          # degrees (0.0 if no fix or payload < 44 bytes)
    alt: float          # meters  (0.0 if no fix or payload < 44 bytes)
    # Raw record size (bytes). Observed values: 20 (SDX55/SDX62 short form),
    # 44 (legacy MDM9607 with position block), 104 (SDX20 V2 padded long
    # form). Used by :meth:`engine_generation` to distinguish SDX62 from
    # SDX20 in the ambiguous field-only zone. Defaults to 20 when
    # a record is synthesized from legacy callers that don't supply it.
    payload_size: int = 20

    @property
    def has_position(self) -> bool:
        return self.lat != 0.0 or self.lon != 0.0

    @property
    def version_byte(self) -> int:
        """Layout-version byte (u32 at offset 0, constant 1 across the corpus).

        Aliased to :attr:`fix_type` for back-compat. Named ``version_byte``
        in :meth:`to_dict` output so a future unknown-version rejection
        reads as a layout-version bump, not as a semantic "different
        fix-type" hint. 0x14CE uses the same convention.
        """
        return self.fix_type

    @property
    def field_4_i32(self) -> int:
        """Signed i32 interpretation of the legacy ``fix_flags`` field.

        This is the sensor temperature in whole degC — see
        :attr:`temperature_c` (the descriptive name) and the class "Semantics"
        section. Kept under this name for back-compat.
        """
        return self.fix_flags - (1 << 32) if self.fix_flags >= (1 << 31) else self.fix_flags

    @property
    def temperature_c(self) -> int:
        """The sensor's temperature in whole degC (same bytes as :attr:`field_4_i32`).

        F3-grounded: ``trunc(DeciDegC / 10)`` of the preceding ``DALTsens.c``
        TSENS print on 5,630/5,630 records. ``-273`` = sensor absent
        (:attr:`is_sensor_absent`); ``-40`` / ``+125`` (``-45`` / ``-50`` on
        some builds) = a thermistor channel at a conversion-table rail.
        """
        return self.field_4_i32

    @property
    def sensor_group(self) -> int:
        """Firmware-config sensor group (u32 @ +8; legacy ``num_engines``).

        Per-build numbering — TSENS is ``2`` on SDX55/SDX62 but ``0``/``1`` on
        MC7411 — so use it as part of an opaque sensor key, not a class enum.
        """
        return self.num_engines

    @property
    def sensor_subgroup(self) -> int:
        """Sensor sub-group id: high 16 bits of the u32 @ +12 (== :attr:`field_3_high16`)."""
        return self.field_3_high16

    @property
    def sensor_index(self) -> int:
        """Sensor index within its group: low 16 bits of the u32 @ +12.

        For TSENS rows this IS the driver's sensor number (F3 ``DALTsens.c``
        ``Sensor = %u``, proven on SDX50M, SDX55 and SDX62).
        """
        return self.field_3_low16

    @property
    def is_sensor_absent(self) -> bool:
        """True iff ``temperature_c == -273`` (0 K): the slot's sensor is not present.

        Same value, same meaning as ``AT+QTEMP``'s ``-273`` rows (e.g.
        ``modem-mmw0`` on a sub-6-only RM520N-GL). Identical predicate to the
        legacy :attr:`is_sdx55_invalid_sentinel`.
        """
        return self.field_4_i32 == -273

    @property
    def engine_generation(self) -> str:
        """Coarse chipset-generation label - best-available per-record call.

        Discriminators in priority order:

        1. ``payload_size == 104`` -> ``sdx20``. SDX20 V2 (EG18-NA,
           EM7511, LM960, EP06A, EG25-G OCPU - anything MDM9x07 /
           MDM9650 era) emits the 104-byte padded form exclusively.
           Across the fixture corpus every SDX20 record is 104 bytes and
           no SDX55/SDX62 record ever is.
           This is the decisive SDX20 signal.
        2. ``engine_state == 2`` -> ``sdx55`` (SDX55/SDX65 majority
           state; observed as majority on FN980m, EM9190, RM500Q,
           Wistron LV55). Only reachable when ``payload_size != 104``.
        3. ``engine_state == 1`` AND ``num_engines > 0xFFFF`` ->
           ``sdx55``. Catches the FN980m/EM9190 "hrde" ASCII-tagged
           records (num_engines = 0x65647268 = 1701081704). In an EM9190
           drive capture all 109 engine_state=1 records carry the hrde
           tag.
        4. ``engine_state == 1`` AND (``num_engines in {2, 8, 9}`` OR
           ``(sv_used >> 16) & 0xFFFF != 0``) -> ``sdx62``. SDX62-R03
           fingerprints observed on RM520N-GL (a 2,770-record drive
           capture) and never on SDX20 or SDX55.
        5. ``engine_state == 1`` AND ``payload_size == 20`` -> ``sdx62``.
           Length-based exclusion: SDX20 always emits 104-byte records,
           and SDX55 with engine_state==1 always carries the hrde tag
           (caught by rule 3). The remaining 20-byte engine_state=1
           records with small num_engines are SDX62 - this branch covers
           the ~60% of SDX62 records where the rule 4 fingerprints don't
           fire (validated on 2,770 RM520N records).
        6. ``engine_state == 1`` with other ``payload_size`` -> ``sdx20``
           (legacy MDM9607-era captures with optional 44-byte position
           block, or future variants).

        Values of ``engine_state`` outside {1, 2} return ``'other'``.
        """
        # Rule 1 - length-based SDX20 detection
        if self.payload_size == 104:
            return 'sdx20'
        # Rule 2 - SDX55 majority state
        if self.engine_state == 2:
            return 'sdx55'
        if self.engine_state == 1:
            # Rule 3 - FN980m/EM9190 hrde ASCII-tagged records
            if self.num_engines > 0xFFFF:
                return 'sdx55'
            # Rule 4 - SDX62-specific field fingerprints
            if self.num_engines in (2, 8, 9):
                return 'sdx62'
            if (self.field_3_u32 >> 16) & 0xFFFF:
                return 'sdx62'
            # Rule 5 - length-based SDX62 exclusion (20-byte form on
            # engine_state==1 without hrde tag is SDX62 by elimination)
            if self.payload_size == 20:
                return 'sdx62'
            # Rule 6 - legacy variants
            return 'sdx20'
        return 'other'

    @staticmethod
    def classify_corpus(records) -> str:
        """Return the authoritative engine-generation for a batch of records.

        Per-record :meth:`engine_generation` is ambiguous between SDX20 and
        SDX62 for records where ``field_1==1 AND field_2 in {0, 7} AND
        field_3 < 0x10000`` - on SDX62/R03 this is ~60% of records, and
        they look identical to real SDX20 records at the struct level.

        This batch classifier resolves the ambiguity: if *any* record in
        the batch carries an SDX62 fingerprint, the whole batch is
        classified as ``'sdx62'``. Otherwise the majority
        per-record label wins.

        Typical usage: pass in all 0x14D8 records from one
        capture. A 10+ record sample is usually enough to trip a SDX62
        fingerprint if the source is SDX62.
        """
        from collections import Counter
        labels = Counter()
        for r in records:
            labels[r.engine_generation] += 1
        if labels.get('sdx62', 0) > 0:
            return 'sdx62'
        if not labels:
            return 'other'
        return labels.most_common(1)[0][0]

    @property
    def is_sdx55_invalid_sentinel(self) -> bool:
        """True iff ``field_4_i32 == -273`` - SDX55 "value-not-available" sentinel.

        Identical to :attr:`is_sensor_absent`. Corpus observation (6,893
        records):

          FN980m               500/1761  (28.4%)
          EM9190 (build A)     260/611   (42.6%)
          EM9190 (build B)     286/656   (43.6%)
          RM500Q (mixed SDX55) 165/450   (36.7%)
          Wistron LV55          44/91    (48.4%)
          RM520N-GL (2 builds) ~21-22/~400 (~5-6%)

        On SDX20 chipsets (LM960, EG18-NA, EM7511, etc.) the value is
        never observed - zero occurrences across 2,000+ records. -273 degC
        is 0 K: the slot's sensor is not present.
        """
        return self.field_4_i32 == -273

    @property
    def is_sdx20_stage2_sentinel(self) -> bool:
        """True iff ``(field_2, field_3, field_4_i32) == (6, 0, 0)``.

        This tuple is the SDX20 zero-reading channel in the per-chipset
        poll order (see the class docstring). Its share of records is a
        consistent ~25% across SDX20 chipsets -

          EG25-G (build A)       18/72   (25.0%)
          EG25-G (build B)       19/76   (25.0%)
          EG18-NA                81/323  (25.1%)
          EG12-GT                 4/16   (25.0%)
          LM960                  26/104  (25.0%)
          SIM7600NA               4/16   (25.0%)
          EP06A                  34/170  (20.0%)
          EM7511                 97/641  (15.1%)

        That is the fraction expected from a 4-slot poll order (1 in 4
        records is this slot). On SDX55 chipsets the tuple is absent - the
        complement of ``is_sdx55_invalid_sentinel``.
        """
        return (self.num_engines == 6
                and self.field_3_u32 == 0
                and self.field_4_i32 == 0)

    @property
    def sv_used(self) -> int:
        """**Deprecated** legacy alias for :attr:`field_3_u32`.

        The name assumes a count of satellites used in a fix. On SDX55
        (FN980m, EM9190), SDX62 (RM520N-GL) and SDX20 (LM960, EG18-NA,
        EM7511) the field carries the sensor sub-group/index, not a
        satellite count.

        Kept as a read-only property so existing consumers continue
        to work. Do not pass ``sv_used=`` to the dataclass constructor
        in new code - use ``field_3_u32=``.
        """
        return self.field_3_u32

    @property
    def field_3_high16(self) -> int:
        """High 16 bits of field_3_u32 - the sensor sub-group id.

        Observed distributions:

        - **SDX55** (FN980m, EM9190): high16 in {0, 2, 4, 8, 9, 10};
          ``2`` is the modal value (~47% on EM9190).
        - **SDX62** (RM520N-GL): high16 in {0, 4, 8, 10} with ``0`` modal
          (~95%); {8, 10} recur once per 293-count poll cycle.
        - **SDX20** (LM960, EG18-NA, EM7511, EP06A): always 0 - field_3
          stays small (0..7) on this generation.
        """
        return (self.field_3_u32 >> 16) & 0xFFFF

    @property
    def field_3_low16(self) -> int:
        """Low 16 bits of field_3_u32 - the sensor index within its
        sub-group. On SDX55, observed 0..6 for sub-group 0x0002 and 0..1
        for sub-group 0x0004. On SDX62 the low16 distribution is similarly
        small-integer; on SDX20 the entire field is small so low16 is
        the field's full value."""
        return self.field_3_u32 & 0xFFFF

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x14D8',
            'log_time': self.log_time,
            # ``version`` is the canonical field-invariant key (byte0 layout
            # version). ``version_byte`` is retained below as a back-compat
            # alias.
            'version': self.fix_type,
            'version_byte': self.fix_type,
            # Legacy names (kept for back-compat, do not trust semantically)
            'fix_type': self.fix_type,
            'engine_state': self.engine_state,
            'num_engines': self.num_engines,
            'sv_used': self.field_3_u32,  # legacy alias - sensor sub-group:index, not SV count
            'fix_flags': self.fix_flags,
            # Positional field names
            'field_0_u32': self.fix_type,
            'field_1_u32': self.engine_state,
            'field_2_u32': self.num_engines,
            'field_3_u32': self.field_3_u32,
            'field_4_u32': self.fix_flags,
            'field_4_i32': self.field_4_i32,
            # Cross-chipset classifiers
            'engine_generation': self.engine_generation,
            'is_sdx55_invalid_sentinel': self.is_sdx55_invalid_sentinel,
            'is_sdx20_stage2_sentinel': self.is_sdx20_stage2_sentinel,
            'field_3_high16': self.field_3_high16,
            'field_3_low16': self.field_3_low16,
            # Thermal-monitor names (F3 DALTsens/VAdc + AT+QTEMP grounded) over
            # the same bytes as the legacy keys above, which stay
            # byte-identical for back-compat.
            'temperature_c': self.temperature_c,
            'sensor_group': self.sensor_group,
            'sensor_subgroup': self.sensor_subgroup,
            'sensor_index': self.sensor_index,
            'is_sensor_absent': self.is_sensor_absent,
            # Raw record size - used by engine_generation for length-based
            # SDX20 vs SDX62 discrimination.
            'payload_size': self.payload_size,
            'lat': self.lat,
            'lon': self.lon,
            'alt': self.alt,
        }


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

@register(LOG_TEMPERATURE_MONITOR_LOG,
    name="0x14D8",
    description=("Thermal monitor sensor reading (LOG_TEMPERATURE_MONITOR_LOG): "
                 "sensor group/sub-group/index + temperature degC — NOT a GNSS "
                 "fix (legacy 'ME Position Fix' field names kept for back-compat)"),
    version=12,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Binary capture analysis. Each record is one thermal-sensor reading "
        "(LOG_TEMPERATURE_MONITOR_LOG), not a GNSS position fix. F3: "
        "DALTsens.c:763 'TSENS: Sensor = %u, DeciDegC = %i' precedes each "
        "(f2=2, lo16=Sensor) record by ~2-10 us and field_4_i32 == "
        "trunc(DeciDegC/10) on 5,630/5,630 records (RM520N-GL SDX62); on "
        "T99W175 SDX55 the VAdcLog.c PA_THERM/PA_THERM1/SYS_THERM1/SYS_THERM2, "
        "TSENS 4/6, rfdevice_therm RFFE PA devices 0..3 and QET reads each land "
        "on their own key in every one of 59 thermal cycles; the MC7411 104 B "
        "form value-matches TSENS sensors 2/4, PA_THERM1 (+125 rail) and "
        "SYS_THERM1. AT+QTEMP per-sensor joins reach r=0.99-1.00 (RM500Q-AE, "
        "RM520N-GL, EG25-G). Layout version byte0 == 1 on 899,438 corpus "
        "records across every chipset bucket (SDX20, SDX50M, MDM9x07/9x30, "
        "MDM9150, SDX55, SDX62, SDX72); payload size is 20 B (SDX55 and later) "
        "or 104 B (earlier generations, 84-byte tail zero on 12,047/12,047 "
        "records); field_3_u32 byte+15 == 0 on 473,834/473,834 records. "
        "to_dict emits thermal names (temperature_c / sensor_group / "
        "sensor_subgroup / sensor_index / is_sensor_absent) alongside the "
        "byte-identical legacy GNSS-era keys and the engine_generation / "
        "sentinel classifiers. A byte0 other than 1, a payload under 20 B, or "
        "a length strictly between the 20/44/104 B forms returns None. Open: "
        "field_1 (record class) is unresolved, and sensor_group numbering is "
        "per-build rather than a universal enum."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    # Identified fields (corpus-validated):
    #   5 × u32 header (fix_type, engine_state, num_engines,
    #     field_3_u32, fix_flags) — all parsed
    #   payload_size (size dispatch) — parsed
    #   5 × derived classifier fields (engine_generation, 2x sentinel
    #     booleans, field_3_high16/low16) — computed from parsed bytes
    # Total: 11 fields actually decoded from payload bytes + computed.
    #
    # The dataclass also exposes lat/lon/alt for back-compat but the
    # parser hardcodes them to 0.0 — they are NOT parsed from bytes
    # [+20..+43] because that region is zero on all 12,047 corpus records,
    # and knowing where a field would live is not the same as decoding
    # observed data from it. See the dataclass docstring "Bytes 20..43"
    # section.
    #
    # +1 derived classifier (is_sensor_absent). The other thermal keys
    # (temperature_c / sensor_group / sensor_subgroup / sensor_index) are
    # renamed views of already-counted bytes, so they are not
    # double-counted. field_1 remains T1 (record class, unresolved).
    fields_identified=12,
    fields_parsed=12,
    field_invariants={
        # ``version`` is the canonical field-invariant key. byte0 is the
        # layout-version byte — fix_type u32 @ +0, v=0x01 across 899,438
        # corpus records. The parser body enforces a matching gate
        # (`if data[0] != 1: return None`) so a future v=0x02 layout is
        # rejected as a new version, not read as "a different fix-type".
        "version": {"enum": [1]},
        "payload_size": {"enum": [20, 104]},
        # ``field_3_u32`` upper bound — byte+15 (bits 24-31) is 0x00 on
        # 473,834/473,834 records, so field_3_u32 never uses its top byte:
        # max observed value is 0x00FFFFFF. field_3_u32 is emitted in
        # to_dict(), so the range check is reachable.
        #
        # NOT declared here (and why):
        #  - byte+1 == 0x00 (100%): subsumed by ``version_byte`` == 1,
        #    which already constrains the whole bytes[0:4] u32 to
        #    01 00 00 00, hence byte+1 == 0.
        #  - 104B records byte+14 == 0x00: size-CONDITIONAL, not flat-
        #    expressible. 20B (SDX55/SDX62) records legitimately carry a
        #    nonzero byte+14 as the sensor sub-group id (corpus dist
        #    {0x00, 0x02, 0x04, 0x08, 0x09, 0x0a, 0x05}); a flat const/enum
        #    would wrongly reject valid 20B records. Enforced instead by
        #    the parser's size dispatch + engine_generation classifier.
        "field_3_u32": {"range": [0, 0x00FFFFFF]},
    },
    # No WiGLE role: each record is one thermal-sensor poll, carrying no
    # position (lat/lon are always 0.0) and emitted on the thermal
    # monitor's own cycle, independent of any GNSS fix. (False, ())
    # records that as a decision rather than an unreviewed default.
    wigle_direct=False,
    wigle_roles=(),
)
def parse_0x14d8(log_time: int, data: bytes) -> Diag0x14D8 | None:
    """Parse a LOG_TEMPERATURE_MONITOR_LOG (0x14D8) thermal-sensor reading.

    Not a GNSS position fix, despite the legacy LOG_GNSS_ME_POSITION_FIX
    label and field names.

    20-byte header: fix_type, engine_state, num_engines, field_3_u32, fix_flags.
    field_3_u32 keeps the legacy name ``sv_used`` as a read-only property
    alias.
    Bytes 20-43 (legacy position-block reading): lat (f64), lon (f64), alt
    (f64) - never populated in any observed capture: 0/12,047 104B records
    across 35 chipset+firmware buckets / 5 vendors has a non-zero byte
    anywhere in the [+20..+103] tail (a strict superset of the lat/lon/alt
    block). SDX55/SDX62 only emit 20B.
    Populated position output across every chipset observed lives in 0x1476
    PositionReport, not here. The lat/lon/alt fields on this dataclass are
    retained at 0.0 for backward compat with consumers that read them.
    """
    # Fail loudly (None -> registry WARN), never raise. The record comes in three fixed forms — 20 B short form
    # (SDX55/SDX62), 44 B legacy form (header + 24 B position block) and
    # 104 B padded long form (SDX20 V2). A length strictly between two
    # forms is a truncated longer form and is rejected rather than parsed
    # as if it were complete. Payloads at or beyond 104 B are accepted.
    n = len(data)
    if n < 20 or 20 < n < 44 or 44 < n < 104:
        return None
    # Version gate. byte0 is the layout-version byte (fix_type u32 @ +0;
    # LE low byte), v=0x01 across 899,438 corpus records / every chipset
    # bucket. Reject any other byte0 BEFORE structural decode so a future
    # v=0x02 layout surfaces as None rather than being silently mis-parsed
    # as v=1: an unchanged size does not imply an unchanged format.
    # The full-u32 fix_type==1 constraint is still enforced via
    # check_invariants (to_dict emits ``version``); this is the fast
    # byte-0 prefilter.
    if data[0] != 1:
        return None
    vals = unpack_from('<IIIII', data)
    return Diag0x14D8(
        log_time=log_time,
        fix_type=vals[0],
        engine_state=vals[1],
        num_engines=vals[2],
        field_3_u32=vals[3],
        fix_flags=vals[4],
        lat=0.0,
        lon=0.0,
        alt=0.0,
        payload_size=len(data),
    )
