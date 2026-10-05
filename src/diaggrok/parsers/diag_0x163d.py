"""GNSS_ME_RF_BP_AGC (0x163D) — full-layout parser, F3-mirrored.

Periodic once-per-second ME RF metrics record from the GNSS RF Bandpass family
(`GNSS_ME_RF_BP_*` codes 0x163D / 0x163E / 0x163F).

## The firmware prints this record as text — `$PQME1` / `$PQWM1`

Every tick, ``mc_tick.c`` renders proprietary NMEA-style sentences into F3,
and ``$PQME1`` (``mc_tick.c:2412`` on the Kapsch RIS-9260 captures) is the 0x163D
record itself, field for field. ``$PQWM1`` (``mc_tick.c:2136`` on an EG25-G
build, ``mc_tick.c:1586`` on RIS-9260) carries a subset. (The RIS-9260 is a
Linux host around the same 81UMV91M21 (MDM9150) modem as the bench captures;
its captures add uptime, not a second device or build.) Joined to the
co-emitted record, every non-constant sentence field lands on exactly one
offset:

======  =====  ==================  ===========================  ================
offset  type   field               F3 mirror                    semantic label
======  =====  ==================  ===========================  ================
+0      u8     version             —                            enum {3, 4}
+1      u8     sub_version         —                            0x00
+2      i32    counter_a           PQME1 f00                    FEE ``Offset`` *
+6      i32    counter_b           PQME1 f01                    —
+10     i32    metric_10           PQME1 f02 / PQWM1 f05        —
+14     u32    metric_14           PQME1 f03 / PQWM1 f06        —
+18     u8     flag_18             PQME1 f04                    —
+19     char   status_a            PQME1 f05  (``'U'``)         ASCII letter
+20     u8     byte_20             —  (0 in 99.98%)             —
+21     i32    metric_21           PQME1 f06                    —
+25     i32    metric_25           PQME1 f07                    —
+29     u16    bp_amp_i            PQME1 f10 / PQWM1 f09        ``GPS_L1CA bpAmpI``
+31     u16    bp_amp_q            PQME1 f11 / PQWM1 f10        ``GPS_L1CA bpAmpQ``
+33     u32    metric_33           PQME1 f14 / PQWM1 f04        99999999 = unset
+37     u8     flag_37             PQME1 f12                    —
+38     f32    rf_metric_a         PQME1 f08  (``%.3f``)        —
+42     f32    rf_metric_b         PQME1 f09  (``%.3f``)        —
+46     i32    metric_46           PQME1 f24                    100000 = unset
+50     u32    amp2_i              PQME1 f25 / PQWM1 f11        —
+54     u32    amp2_q              PQME1 f26 / PQWM1 f12        —
+58     char   status_b            PQME1 f27  (``'U'``)         ASCII letter
+59     u8     metric_59           PQME1 f29 / PQWM1 f07        —
+60     i8     band1_pga_gain_db   PQME1 f17 / PQWM1 f08        ``band1PgaGainDb``
======  =====  ==================  ===========================  ================

(*) ``counter_a`` equals the ``Offset`` argument of ``mc_fee.c``
``ProcCgpsFreqEstimate ... Offset %d`` (0.977 over 40 distinct values on one
EG25-G build); that site prints *after* the record and drifts tick to tick,
so it is a semantic CANDIDATE, not an identity. The ``$PQME1`` mirror is the
identity.

``$PQME*`` / ``$PQWM1`` carry no field names, so the mirror grounds **offset,
width, signedness and encoding** of every field but names only the three that
a *labelled* F3 site also prints: ``bp_amp_i`` / ``bp_amp_q`` and
``band1_pga_gain_db`` (``loc_pd.c`` ``PDSM_GNSS_SIG_TYPE_GPS_L1CA metrices
bpAmpI/bpAmpQ`` and ``... ME_METRICS ... band1PgaGainDb``). Everything else is
named by offset on purpose.

**The 60 B v=0x03 form is the 61 B v=0x04 form without byte +60.** The EG25-G
``$PQWM1`` prints ``band1PgaGainDb`` (-12) as its f08 like every other build,
but the 60 B record has nowhere to put it. All other v=0x03 offsets are
identical, ``$PQWM1``-mirrored 90/90 and 30/30 on two EG25-G builds, so the
v=0x03 body is decoded too (``band1_pga_gain_db`` is ``None`` there).

**+19 and +58 are ASCII status letters.** They print as characters in
``$PQME1`` (f05 / f27). Across 151,803 corpus records +19 takes only ``L``,
``N``, ``U`` and ``G``, and +58 only ``L``, ``N``, ``U``, ``G`` and ``W`` (the
non-letter residue is <= 0.03%, misframe noise). The byte is not a chipset
marker, an RX-chain marker or an RF-state index. What the letters mean is not
labelled anywhere in F3.

Two coexisting (size, version) forms observed across the corpus
(24,021 records / 60 captures):

| Form        | Count          | Where seen                                 |
|-------------|----------------|--------------------------------------------|
| 61 B v=0x04 | 21,934 (91.3%) | every modem family in the corpus           |
| 60 B v=0x03 |  2,087 ( 8.7%) | MDM9x07-class: EG25-G (three builds), EG95, EP06, SIM7600, MC7455/EM7455 |

Body-field notes:

- ``agc_pair_a``/``agc_pair_b`` (+29..30 / +31..32 u16-LE) are F3-GROUNDED
  as **w_BpAmpI / w_BpAmpQ**, the I and Q components of one
  bandpass-amplitude measurement. Exposed under the semantic aliases
  ``bp_amp_i`` / ``bp_amp_q`` in ``to_dict``. They are near-equal (median
  |a-b| = 0 across 11/12 modems) not because there are two RF chains but
  because |I| ~ |Q| for a noise-like GNSS signal. Firmware ground truth:
  ``sm_api.c:3241`` (``sm_ReportMEMetrics w_BpAmpI=%d, w_BpAmpQ=%d``) and
  ``loc_pd.c:7361`` (per-signal ME metrics), cross-confirmed on two
  independent SDX55 builds: Quectel RM500Q (260/260) and SIMCom SIM8202G
  (1492/1492), both conf 1.00.
- ``rf_metric_a``/``rf_metric_b`` (+38..41 / +42..45 **LE**-f32) are a
  near-equal pair of smoothly-varying dB-scale measurements. On an RM500Q
  SDX55 drive capture they span 35.8..56.6 dB (529 / 1412 distinct values
  over 1,495 records); on an RM520N-GL SDX62 drive capture 27.0..31.7 dB
  (890 / 604 distinct over 1,017). They are one quantity read twice:
  ``r(rf_metric_a, rf_metric_b)`` is **+0.9997** on RM500Q and **+0.9991** on
  RM520N-GL - the same "two readings of one quantity" motif as
  ``bp_amp_i``/``bp_amp_q`` here, ``meas_block_a``/``_b`` in 0x163F and
  ``rf_metric_1``/``_2`` in 0x1646.

  .. warning::
     The **unit** is still open, and the tempting reading does NOT survive a
     second build. On RM500Q the pair varies inversely with ``bp_amp_i``
     (Pearson r = -0.76 over 1,495 records), which looks like a receiver AGC
     gain and matches this code's name. On RM520N-GL the same correlation is
     **-0.12** (and -0.13 against ``jammerPwrDb``). The AGC-gain reading is
     not supported by the SDX55 number alone.

## Alignment of the +38/+42 floats

The two floats are little-endian at +38 and +42. A big-endian f32 read at
+41/+45 looks plausible ("bounded dB-like values clustering at {8, 20, 32,
63}", with +41 "near-constant, delta ~ 0.06") but straddles a field boundary,
and the near-constancy is an artifact of the misalignment rather than a
property of the radio.

Reading big-endian at +41 takes ``[b41][b42][b43][b44]``, where:

  * ``b41`` is the *top* (sign+exponent) byte of the LE float starting at +38
  * ``b42`` is the *lowest* mantissa byte of the LE float starting at +42,
    which is ``0x00`` in every record observed
  * ``b43``/``b44`` are that second float's middle mantissa bytes

A BE float of the form ``(b41, 0x00, m, m)`` is pinned to
``[2**k, 2**k * (1 + 2**-7))`` - a window only ``2**k / 128`` wide. (``2**-7``,
not ``2**-8``: f32 byte 1 is ``exp[0] + mantissa[22:16]``, so forcing it to
``0x00`` zeroes the exponent's low bit plus only *seven* mantissa bits, leaving
16 - ``0xFFFF / 0x800000 = 1/128``.) So the value cannot vary more than that
no matter what the receiver is doing, and a "delta ~ 0.06" is exactly
``8 / 128``, not a measurement.

The cross-build comparison settles it. The exponent byte differs between
firmwares, and the misaligned "field" rescales with it:

===================  ============  ====================  ====================
build                 byte +41      BE@41 range           LE@38 range
===================  ============  ====================  ====================
RM500Q SDX55 (1495)   ``0x42``      32.000 .. 32.249      35.79 .. 56.57
RM520N-GL SDX62(1017) ``0x41``      8.000 ..  8.062       27.00 .. 31.74
===================  ============  ====================  ====================

The misaligned field's entire dynamic range changes by 4x between the two
builds - exactly the ratio ``2**5 / 2**3`` of the two exponent bytes. A
physical dB quantity does not rescale its range by the ratio of two powers of
two when the modem changes; a misaligned read does. Corroborating byte census:
``+38`` and ``+42`` are ``0x00`` in 1495/1495 and 1017/1017 records on the two
builds and in all 7 test fixtures, which is the signature of an LE-f32 low
mantissa byte; ``+41``/``+45`` are single-valued per build (the exponent).

Sweeping every offset and both endiannesses over each capture finds exactly
three "well-behaved" float readings in the 61-byte record - ``LE@38``,
``LE@42``, and the ``BE@41`` artifact, whose 0.06-0.25 dB range identifies it.
``$PQME1`` f08/f09 print exactly the LE@38/LE@42 floats at ``%.3f``, which
confirms the alignment from the firmware side.

## Why the unit is not grounded

Correlating against the ME-metrics F3 sites with float dtypes, over 17
encodings (including the x256/x100 scalings that a Q-format dB would need), on
two independent builds: the sites' three integer arguments are ``bpAmpI`` /
``bpAmpQ`` / ``jammerPwrDb``; the first two ground at +29/+31 at confidence
1.00 (the positive control), and **no float hypothesis clears confidence 0.90
with >= 3 distinct targets on either build**. ``jammerPwrDb`` takes only 6
distinct values (75..80) on the RM500Q capture while ``LE@38`` takes 529, and
on RM520N-GL, where it has 110 distinct values, it still matches nothing, so
0x163D does not appear to carry ``jammerPwrDb`` at all. ``$PQME1`` mirrors the
floats but carries no unit either.

A +49/+53 u16 pair is not a field boundary — the real fields are u32 at
+50/+54 (``amp2_i`` / ``amp2_q``).

## Family note — chain_id is an ASCII status letter

`chain_id` at +19 takes 4+ distinct values across the corpus and varies
within single captures (e.g. one LM960 capture has 206×0x4c + 98×0x55).
Those values are ``'L'`` (0x4c), ``'U'`` (0x55), ``'N'`` (0x4e) and ``'G'``
(0x47): ``$PQME1`` prints the byte as a character (f05). ``chain_id`` keeps
the raw int for back-compat; ``status_a`` / ``status_b`` expose the letters.

Sibling code 0x163E (JAMMER) carries the same byte at a different offset
(+11); see `diag_0x163e.py`.  Sibling 0x163F (NOTCH) exhibits a separate
chipset-generation populated/all-zero body story.

Test fixtures (per (chipset, code) cross-validation): one 61 B v=0x04 record
each from EG18-NA (SDX20), LM960 (SDX20) and RM500Q (SDX55); a 61 B v=0x04
RIS-9260 record whose co-emitted $PQME1 is pinned field-by-field in the tests;
and a 60 B v=0x03 EG25-G record whose co-emitted $PQWM1 is pinned in the tests.
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


LOG_GNSS_ME_RF_BP_AGC = 0x163D

# Field offsets. Every one is mirrored by the firmware's own
# $PQME1 / $PQWM1 F3 rendering of this record — see the module docstring's
# field map. Identical on both forms except +60, which only v=0x04 carries.
_AGC_PAIR_A_OFF = 29   # u16-LE = GPS_L1CA bpAmpI (loc_pd.c / sm_api.c F3 label)
_AGC_PAIR_B_OFF = 31   # u16-LE = GPS_L1CA bpAmpQ
# rf_metric_a/b are LITTLE-endian f32 at +38/+42, NOT big-endian at +41/+45
# (that read straddles a field boundary) — see "Alignment of the +38/+42
# floats" in the module docstring. $PQME1 f08/f09 print exactly these floats.
_RF_METRIC_A_OFF = 38  # LE-f32 ($PQME1 f08; unit not labelled)
_RF_METRIC_B_OFF = 42  # LE-f32 ($PQME1 f09)
_PGA_GAIN_OFF = 60     # i8, v=0x04 only = band1PgaGainDb (loc_pd.c F3 label)
_V3_LEN = 60           # 60B v=0x03: everything through +59
_V4_LEN = 61           # 61B v=0x04: + band1_pga_gain_db at +60


def _chr(b: int) -> str:
    """A status byte as its printable letter ($PQME1 prints it with %c)."""
    return chr(b) if 0x20 <= b < 0x7f else f'\\x{b:02x}'


@dataclass
class Diag0x163D:
    """GNSS RF Bandpass ME metrics (0x163D) — full layout, F3-mirrored.

    Two coexisting record formats observed in the corpus:

    - **61 B, version=0x04** — every SDX / MDM96xx / MDM9150 (incl. via RIS-9260) build
    - **60 B, version=0x03** — MDM9x07 / MDM9x30 class (EG25-G, EG95, EP06,
      SIM7600, MC7455 / EM7455); the v=0x04 layout without byte +60

    Every field is mirrored by a ``$PQME1`` / ``$PQWM1`` sentence the firmware
    prints in the same tick (see the module docstring). Only ``bp_amp_i`` /
    ``bp_amp_q`` and ``band1_pga_gain_db`` carry a firmware *name*; the rest
    are named by offset because no F3 site labels them.
    """
    log_time: int
    version: int                # +0   — 0x04 (61B form) or 0x03 (60B form)
    sub_version: int            # +1   — 0x00 cross-corpus (likely subtype)
    counter_a: int              # +2..5  i32 ($PQME1 f00; ~ mc_fee ProcCgpsFreqEstimate Offset)
    counter_b: int              # +6..9  i32 ($PQME1 f01)
    chain_id: int               # +19  — raw status byte; an ASCII letter (see status_a)
    payload_size: int
    raw: bytes                  # full payload retained for downstream RE
    # --- body fields (always populated: a record shorter than its form
    #     returns None; band1_pga_gain_db is v=0x04 only) ---
    agc_pair_a: int | None      # +29..30 u16-LE = GPS_L1CA bpAmpI; alias bp_amp_i
    agc_pair_b: int | None      # +31..32 u16-LE = GPS_L1CA bpAmpQ; alias bp_amp_q
    rf_metric_a: float | None   # +38..41 LE-f32 ($PQME1 f08; unit not labelled)
    rf_metric_b: float | None   # +42..45 LE-f32 ($PQME1 f09)
    metric_10: int | None = None        # +10..13 i32  ($PQME1 f02 / $PQWM1 f05)
    metric_14: int | None = None        # +14..17 u32  ($PQME1 f03 / $PQWM1 f06)
    flag_18: int | None = None          # +18 u8       ($PQME1 f04)
    status_a: str | None = None         # +19 char     ($PQME1 f05) — L / N / U / G
    byte_20: int | None = None          # +20 u8       (0 in 99.98%; no F3 mirror)
    metric_21: int | None = None        # +21..24 i32  ($PQME1 f06)
    metric_25: int | None = None        # +25..28 i32  ($PQME1 f07)
    metric_33: int | None = None        # +33..36 u32  ($PQME1 f14 / $PQWM1 f04; 99999999 = unset)
    flag_37: int | None = None          # +37 u8       ($PQME1 f12)
    metric_46: int | None = None        # +46..49 i32  ($PQME1 f24; 100000 = unset)
    amp2_i: int | None = None           # +50..53 u32  ($PQME1 f25 / $PQWM1 f11)
    amp2_q: int | None = None           # +54..57 u32  ($PQME1 f26 / $PQWM1 f12)
    status_b: str | None = None         # +58 char     ($PQME1 f27) — L / N / U / G / W
    metric_59: int | None = None        # +59 u8       ($PQME1 f29 / $PQWM1 f07)
    band1_pga_gain_db: int | None = None  # +60 i8, v=0x04 only = band1PgaGainDb

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x163D',
            'log_time': self.log_time,
            'version': self.version,
            'sub_version': self.sub_version,
            'counter_a': self.counter_a,
            'counter_b': self.counter_b,
            'metric_10': self.metric_10,
            'metric_14': self.metric_14,
            'flag_18': self.flag_18,
            'chain_id': self.chain_id,
            'status_a': self.status_a,
            'byte_20': self.byte_20,
            'metric_21': self.metric_21,
            'metric_25': self.metric_25,
            'agc_pair_a': self.agc_pair_a,
            'agc_pair_b': self.agc_pair_b,
            # F3-grounded semantic aliases (labelled loc_pd.c GPS_L1CA site):
            # I/Q bandpass amplitude.
            'bp_amp_i': self.agc_pair_a,
            'bp_amp_q': self.agc_pair_b,
            'metric_33': self.metric_33,
            'flag_37': self.flag_37,
            'rf_metric_a': self.rf_metric_a,
            'rf_metric_b': self.rf_metric_b,
            'metric_46': self.metric_46,
            'amp2_i': self.amp2_i,
            'amp2_q': self.amp2_q,
            'status_b': self.status_b,
            'metric_59': self.metric_59,
            'band1_pga_gain_db': self.band1_pga_gain_db,
            'payload_size': self.payload_size,
            'parser_status': 'full-layout-f3-mirrored',
            'parser_note': (
                f'{self.payload_size}B v={self.version:#04x}. Every field is '
                'mirrored by the firmware\'s own $PQME1/$PQWM1 F3 rendering of '
                'this record (mc_tick.c), which grounds offset/width/encoding. '
                'Named by F3 label: bp_amp_i/bp_amp_q (GPS_L1CA bpAmpI/Q) and '
                'band1_pga_gain_db (band1PgaGainDb, v=0x04 only). chain_id is '
                'an ASCII status letter (status_a); the rest are named by offset '
                'because no F3 site labels them.'
            ),
        }


# Ground-truth recipe — EC25/EG25 family (MDM9607). GNSS RF bandpass AGC.
# This is a DISCOVERY recipe: no AT/QMI command returns GNSS front-end AGC gain
# or the rf_metric floats, so every field grounds by CORRELATION against an
# observable RF quantity, not value-equality.
# Version/build: every EG25-G build in the corpus, like every MDM9x07 build,
# emits the 60B v=0x03 form. The v=0x03 body is decoded too, so EG25-G is a
# valid target for every field except band1_pga_gain_db (+60, v=0x04 only).
# cond="sky-fix": AGC/rf_metric track the live GNSS RF environment.

@register(
    LOG_GNSS_ME_RF_BP_AGC, domain="gnss",
    name="0x163D",
    description=(
        "GNSS_ME_RF_BP_AGC (0x163D) — once-per-tick GNSS ME RF metrics; full "
        "layout mirrored by the firmware's own $PQME1/$PQWM1 F3 rendering; "
        "61B v=0x04 (+ band1PgaGainDb at +60) and 60B v=0x03 (MDM9x07-class); "
        "+19/+58 are ASCII status letters"
    ),
    version=10,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Full layout, both forms (61 B v=0x04; 60 B v=0x03 = the v=0x04 form "
        "minus byte +60), every field mirrored by the firmware's own F3: "
        "mc_tick.c renders the record every tick as $PQME1 (mc_tick.c:2412, "
        "RIS-9260 / MDM9150) field for field, and as $PQWM1 (mc_tick.c:2136 "
        "EG25-G / :1586 RIS-9260) for a subset. Every $PQME1 mapping holds "
        "3882/3882 over 14 v=0x04 captures on four distinct modems (RIS-9260 "
        "MDM9150, Quectel EG18-NA, Sierra EM9190, Telit LM960; up to 601 "
        "distinct values per field); every $PQWM1 mapping holds 251/251 over "
        "9 v=0x03 captures (two EG25-G builds). The sentences carry no names, "
        "so the mirror grounds offset/width/sign/encoding; names come only "
        "from labelled sites: loc_pd.c 'PDSM_GNSS_SIG_TYPE_GPS_L1CA metrices "
        "bpAmpI = %d, bpAmpQ = %d' -> +29/+31 (RM520N-GL SDX62 235/235, "
        "T99W640 361/361; also sm_api.c:3241 w_BpAmpI/w_BpAmpQ on RM500Q and "
        "SIM8202G SDX55 at conf 1.00) and 'ME_METRICS ... band1PgaGainDb = %d' "
        "-> +60 i8 (942/942 across RM520N-GL, T99W640 and Inseego M3100). "
        "counter_a (+2) tracks mc_fee.c ProcCgpsFreqEstimate 'Offset' at "
        "0.977 (CANDIDATE: that site prints after the record and drifts). "
        "+19/+58 are ASCII status letters ($PQME1 prints them %c; L/N/U/G and "
        "L/N/U/G/W over 151,803 records); their meanings are unlabelled. "
        "rf_metric_a/b are LE-f32 at +38/+42 (near-equal, r >= 0.999 on two "
        "builds). +50/+54 (amp2_i/amp2_q) is a second near-equal I/Q-like "
        "pair that tracks GPS_L1CA bpAmp (r ~0.85) but equals no labelled "
        "per-signal bpAmp. +33 (99999999) and +46 (100000) are "
        "sentinel-valued live fields. Not grounded: physical units of "
        "rf_metric_a/b, amp2_* and the metric_* fields; +20 has no F3 mirror "
        "(0 in 99.98%). A payload shorter than its form returns None."
    ),
    fields_parsed=23,
    fields_identified=23,
    issues=(),
    ascii_kinds=("label",),
    field_invariants={"version": {"enum": [0x03, 0x04]}},
)
def parse_0x163d(log_time: int, data: bytes) -> Diag0x163D | None:
    """Parse a LOG_GNSS_ME_RF_BP_AGC (0x163D) payload — full layout."""
    if len(data) < 20:
        return None
    if data[0] not in (0x03, 0x04):
        return None
    # Each form is fixed-size (v=0x03 60 B, v=0x04 61 B). A shorter payload is truncated and returns None (registry
    # WARN) instead of silently dropping the body / the v=0x04 PGA gain.
    if len(data) < (_V4_LEN if data[0] == 0x04 else _V3_LEN):
        return None

    body: dict[str, Any] = {}
    agc_a = agc_b = None
    rf_a = rf_b = None
    # The two forms share every offset through +59; v=0x04 appends +60.
    if len(data) >= _V3_LEN:
        agc_a = unpack_from('<H', data, _AGC_PAIR_A_OFF)[0]
        agc_b = unpack_from('<H', data, _AGC_PAIR_B_OFF)[0]
        rf_a = unpack_from('<f', data, _RF_METRIC_A_OFF)[0]
        rf_b = unpack_from('<f', data, _RF_METRIC_B_OFF)[0]
        body = dict(
            metric_10=unpack_from('<i', data, 10)[0],
            metric_14=unpack_from('<I', data, 14)[0],
            flag_18=data[18],
            status_a=_chr(data[19]),
            byte_20=data[20],
            metric_21=unpack_from('<i', data, 21)[0],
            metric_25=unpack_from('<i', data, 25)[0],
            metric_33=unpack_from('<I', data, 33)[0],
            flag_37=data[37],
            metric_46=unpack_from('<i', data, 46)[0],
            amp2_i=unpack_from('<I', data, 50)[0],
            amp2_q=unpack_from('<I', data, 54)[0],
            status_b=_chr(data[58]),
            metric_59=data[59],
        )
    if data[0] == 0x04 and len(data) >= _V4_LEN:
        body['band1_pga_gain_db'] = unpack_from('<b', data, _PGA_GAIN_OFF)[0]

    return Diag0x163D(
        log_time=log_time,
        version=data[0],
        sub_version=data[1],
        counter_a=unpack_from('<i', data, 2)[0],
        counter_b=unpack_from('<i', data, 6)[0],
        chain_id=data[19],
        payload_size=len(data),
        raw=bytes(data),
        agc_pair_a=agc_a,
        agc_pair_b=agc_b,
        rf_metric_a=rf_a,
        rf_metric_b=rf_b,
        **body,
    )
