"""0x1587 — GNSS per-fix MGP report (variable: 49..416 bytes; 52/85/115 on SDX55).

20-byte header + size-keyed body; 5 known versions {0x0C..0x10} with a
per-version sentinel byte at offset 19. The 115-byte fix-detail body carries
HEPE, vertical uncertainty and ellipsoidal altitude, F3-grounded on every
version. The other size-classes' bodies are still exposed raw.

Log name: LOG_EVENT_IPSEC_CHILD_SA_REKEY_DONE
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from diaggrok.registry import register

LOG_GNSS_TRACKING_1587 = 0x1587

# Layer-1 version gate.
# 5 versions observed across a 142,127-record corpus walk:
# 0x0C (4,245), 0x0D (21,188), 0x0E (25,288), 0x0F (70,688), 0x10 (20,718).
# Any other byte-0 value indicates a firmware-format change and must be
# rejected at parse time rather than silently decoded into the per-
# version sentinel slot at offset +19 (which will be a stale value).
# When a v0x11 capture is decoded, ADD 0x11 here AND to the matching
# field_invariants enum on @register below.
_KNOWN_VERSIONS = frozenset({0x0C, 0x0D, 0x0E, 0x0F, 0x10})

# Record offset where the length-declared remainder begins;
# u16 LE @+23 == len(record) - 25 (see parse_0x1587).
_BODY_PREFIX_END = 25


@dataclass
class Diag0x1587:
    """GNSS tracking detail report (0x1587).

    Variable-length: 20-byte header + N × variable body entries.

    ## Cross-corpus version distribution (142,127 records)

        offset 0 (version):   0x0F (49.7%), 0x0E (17.8%), 0x0D (14.9%),
                              0x10 (14.6%), 0x0C (3.0%) — 5 versions
        offset 19 ('sentinel'): 0x26 (49.7%), 0x1F (17.8%), 0x19 (14.9%),
                              0x27 (14.6%), ... — distribution mirrors
                              version exactly, suggesting byte 19 is a
                              per-version sentinel/tail-marker.

    A single-modem sample (FN980m) shows only 0x0F / 0x26 at these offsets;
    neither is constant corpus-wide. Size invariance is not format
    invariance: a future v=0x11 record (next sequential version) is the
    expected failure mode. The ``field_invariants={"version": {"enum": [...]}}``
    declaration on ``@register`` rejects unknown versions as None,
    surfacing a parse-rate drop instead of silent garbage. Add 0x11 to
    the enum once a v=0x11 capture is decoded.

    Body sizes observed (corpus-wide): 30..200 B with concentrations
    at 32, 65, 95, 96 B (totaling 52/85/115/116 B with 20-byte header).

    ## 20-byte header fully mapped

    A version-conditional walk (73,887 records) characterizes every header
    byte. The `marker_6` invariant below is validated against the full
    corpus — 199,121 records — with 0 violations. Per-offset finding
    (offsets relative to record start):

        +3  byte_3   counter/index, 6..151 uniq per version — MIRRORS +13
        +4  flag_4   state flag {0x00 dom, 0x01..0x04 minority} — MIRRORS +14
        +5  state_5  GNSS tracking-state byte {0x6b..0x74, 0xff}, 100%
                     nonzero, per-version modal (v0E peaks 0x6d, v10 peaks
                     0x72). Same 0x6d..0x72+0xff signature as 0x14E0 byte+20
                     — likely a shared firmware GNSS state indicator.
        +6  marker_6 low-cardinality marker — exactly {0x05, 0x09, 0xff}
                     across ALL 199,121 records, full corpus (declared as an invariant).
                     0xff is the uninitialized-sentinel value.
        +7..+12      mid_raw — 6 high-entropy bytes (256 uniq each, ~99%
                     nonzero). Not per-SV counters / measurement deltas (see
                     the F3 note below): in a v0x0D MC7411 capture these move
                     as additional per-record counter-triples (mirroring the
                     +1/+2/+3 triple), tracking the record counter, not
                     per-SV data. Opaque as to scale.
        +13 byte_13  identical distribution to +3 (mirror pair).
        +14 flag_14  identical distribution to +4 (mirror pair).
        +15..+18     zero-padding: 0x00 across 100% of all records / versions.
        +19 sentinel per-version tail-marker.

    The +3≡+13 / +4≡+14 mirror suggests the header carries a repeated
    field pair at a +10 stride. Every header byte is named.

    ## The small body classes are NOT per-SV measurements (F3)

    In an MC7411 v0x0D GNSS-active capture (184 records, 92×50B + 92×85B,
    fully resolved F3), the ENTIRE body (+14 onward) is **byte-constant
    across all 92 records of each size**, while the co-recorded F3 carries
    live per-SV C/No (`mc_peak.c` GnssType/SV/C-No, 267 prints, values
    swinging 203-320 across 30 SVs). A body that never moves while the
    per-SV measurements swing cannot BE those measurements — the SMALL
    size-classes (50B/85B) are a static config/status snapshot.

    ## The record IS the per-fix MGP report; +86 = HEPE — F3-GROUNDED

    v0x0D, v0x0E and v0x10 are grounded against decodable plaintext (0x79)
    GNSS F3 on their own silicon (EG25-G MDM9x07, EG18-NA, RM520N-GL SDX62
    respectively). Two results, both version-bound:

    **(1) Co-emission — the record IS the MGP fix report.** Every 0x1587 record
    is emitted co-temporally with GNSS-engine-active F3: 100% of the 5,561 v0x0D
    (EG25-G) and 5,410 v0x0E (EG18-NA) records fall inside the
    `mc_peak.c` per-SV C/No active window, and the 0x1587 emission is 1:1 with
    the `lm_mgp.c` "Received FIX REPORT from MGP" cycle (record-set count ==
    FIX-REPORT count exactly on every tested capture). `state_5` is therefore
    the GNSS **tracking-state** byte: 0x80 while actively tracking (Quectel
    MDM9x07/Cat-x engines), 0x72/0x78 tracking on SDX62, 0xff on no-valid-fix.

    **(2) size-115 body carries the fix accuracy — `+86` LE-f32 = HEPE.** The
    115-byte record (body_size 95) is the per-fix position-**accuracy** member.
    Its body offset +86 (LE float32) decodes to the exact value the firmware
    prints at `lm_mgp.c` "New fix saved as best. hepe: X" — measured 1:1 by
    count and value-exact on valid fixes:

        version  size-115 recs  lm_mgp hepe prints  valid-fix +86==hepe (±0.01)
        v0x0D    1,799          1,800               1,141/1,159  (98.4%)
        v0x0E    1,802          1,802               1,017/1,671  (60.9%*)
        v0x10    1,108          1,108                 261/399    (65.4%*)
        (* lower rate is nearest-F3-sample ALIGNMENT slack when hepe changes
         faster than record cadence, not value disagreement — the float values
         are hepe-space on every capture; the 1:1 COUNT is exact on all three.)

    `+82` (LE-f32) is a second accuracy float that co-moves with hepe (a
    related uncertainty / semi-axis) — surfaced as `accuracy2_m` CANDIDATE, not
    named. The two bytes at `+91` are not a u16 fix/epoch counter even though
    they ramp: they are the low half of the `+91` LE-f32 vertical uncertainty
    (mantissa bits).
    A NULL-fix size-115 record carries 0.0 at +86/+82 (the firmware's own
    no-valid-fix sentinel), passed through verbatim.

    Scope note: the HEPE decode is gated on the 115-byte layout (size-keyed).
    `body_raw` is still exposed in full; the 50B/85B classes remain the
    static snapshot above, and the 114/136/211B classes (different
    varying-offset clusters) are not yet decoded.

    ## v0x0C + v0x0F grounded; the 115-byte slot map

    The 115-byte body is ONE slot map shared by every version, and it
    carries more than HEPE. Record offsets:

        +20..+23  tag `00 03 00 5a` (same bytes on v0x0C and v0x0F) — raw
                  (bytes +23..+24 are a u16 LE length word,
                  == record length - 25 on every size class)
        +80  u8    horiz_flag_80  horizontal-block flag (CANDIDATE)
        +81  u8    vert_flag_81   vertical-block quality flag (CANDIDATE)
        +82  f32   accuracy2_m    2nd horizontal accuracy float (CANDIDATE)
        +86  f32   hepe_m         HEPE (m)                       F3-GROUND
        +91  f32   alt_unc_m      vertical uncertainty (m)       F3-GROUND
        +95  f32   altitude_hae_m altitude above WGS-84 ellipsoid (m) F3-GROUND
        +99..+106                 raw (all-zero on >=92% incl. every v0x0F/v0x10)
        +107..+114                2nd (alt_unc, altitude) pair — equal to
                                  +91..+98 on 95.6% of records (raw)

    **v0x0C** — Sierra EM7455 (MDM9x30), the only v0x0C capture with
    plaintext F3. It has 465 records, 155 each at 49/85/115 B,
    and 155 `lm_mgp.c:229` "New fix saved as best. hepe:" prints, so the
    115-byte record is again 1:1 with the fix cycle. That F3 dump carries no
    timestamps, so the check is an in-order alignment:

        +86 == hepe            151/155 at alignment offset 0
                               (3-8/155 at every shifted offset ±1..±3;
                                the 4 misses are within 0.08 m of hepe)
        +91 == AltUnc          151/155 (tle_log.c:645, exact to 1e-5 rel.)
        +95 vs tle_log "Alt:"  altitude-space, NOT exact (7/155; median delta
                               -2.6 m, stdev 6.7 m) — that MDM9x30 TLE print
                               is a different altitude estimate than the fix's
        +80/+81                0x01/0x01 on all 155

    **v0x0F** — two SDX55 builds from one drive, each with a timestamped F3
    sidecar (nearest-F3-sample alignment):

        capture                  115B  +80=0x00, +82/+86==0.0  +91==AltUnc  +95==Alt
        Quectel RM500Q-AE         658  658/658                 560/658      615/658 (654 @1e-3)
        SIMCom SIM8202G-M2        580  580/580                 403/580      391/580 (426 @1e-3)
        (tolerance 1e-4 relative; oracle = tle_base.cpp:104 "PTM:ALE pos ...
         Alt:, PUNC:, AltUnc:")

    On these builds the **horizontal block is empty**: +80 is 0x00 and
    +82/+86 are 0.0 on every record, yet the F3 prints a real hepe for every
    fix (RM500Q: 657 `lm_mgp.c:391` prints vs 658 records). The layout is not
    a different one at the same size: the vertical pair sits in the same
    slots as on v0x0C, and +80 records that the horizontal block is absent.
    `hepe_m` therefore reads 0.0 on these builds and is passed through
    verbatim, so a consumer should gate on `horiz_flag_80`. `vert_flag_81` is a
    quality flag, not a hard zero-gate: on SIM8202G-M2 the 74 records with
    +81 == 0x00 carry 0.0 altitude on 14 and a low-quality early estimate on
    the rest (39 of 74 still match F3).

    **Altitude reference.** On the RM500Q drive the co-recorded NMEA GGA puts
    the +95 distribution (p10/p50/p90) within ~1 m of GGA MSL + geoid
    separation, and a full geoid separation below GGA MSL. So +95 is
    height above the ellipsoid, not MSL.

    **Corpus validation walk.** 682 capture sessions, 634,238 records:
    **0 parse rejects, 0 invariant violations**. Byte 0 takes only
    {0x0C, 0x0D, 0x0E, 0x0F, 0x10}, so there is no sixth version. Every
    115-byte record, on every version, carries the tag `00 03 00 5a`:

        version  115B recs  captures  +80=0x01 (horiz. populated)  +107 pair == +91 pair
        v0x0C       1,201        7        865                           760
        v0x0D      54,034      168      6,056                        52,701
        v0x0E      13,338       75      5,092                        10,378
        v0x0F      22,106       85          0 (none, all builds)     22,106
        v0x10      17,315       72      4,571                        17,315

    - `+80 == 0x00` ⇔ `+82 == +86 == 0.0` on **107,994/107,994** records.
      `+80 == 0x01` always comes with `+81 == 0x01`.
    - Every populated HEPE and accuracy2 in the corpus lies in [9.268, 15.0) m.
      That looks like a firmware gate (the horizontal block is filled only for
      fixes under 15 m) on v0x0C/0D/0E/10. On SDX55 v0x0F the block is never
      filled: 254 of the 658 RM500Q records follow an F3 hepe under 15 m and
      still carry `+80 == 0x00`. The flag therefore stays CANDIDATE.
    - `alt_unc_m` spans exactly [2.5, 10000.0] m on every version, which look
      like clamps (a floor and an "unknown" ceiling). With `+81 == 0x01` the
      altitude is never 0.0 (32,323 records); `+81 == 0x00` records sometimes
      carry 0.0 (3,189) or an out-of-range early estimate (186 records outside
      -1000..20000 m, all versions combined).
    - `+107..+114` is a second (alt_unc, altitude) pair. It equals `+91..+98`
      on 103,260/107,994 records, and on every v0x0F/v0x10 record. The 4,734
      exceptions are v0x0C/0D/0E records on 46 captures: 34 state-transition
      captures (reboot / airplane / boot+GNSS) and 12 ordinary GNSS sessions
      (LM960, MC7455, EG25-G). In the ones inspected the second pair is a
      slightly different estimate (cm–dm), `+99` f32 ramps and `+103` f32 holds
      an altitude-scale constant. All of it stays raw in `body_raw`.
    """
    log_time: int
    version: int           # byte 0 — one of {0x0C, 0x0D, 0x0E, 0x0F, 0x10}
    counter_hi: int        # byte 1
    counter_lo: int        # byte 2
    byte_3: int            # byte 3 — counter/index; mirrors byte_13
    flag_4: int            # byte 4 — state flag; mirrors flag_14
    state_5: int           # byte 5 — GNSS tracking-state byte (parallels 0x14E0 byte+20)
    marker_6: int          # byte 6 — marker, enum {0x05, 0x09, 0xff}
    mid_raw: bytes         # bytes 7..12 — high-entropy counter/measurement (opaque)
    byte_13: int           # byte 13 — mirror of byte_3
    flag_14: int           # byte 14 — mirror of flag_4
    pad_15_18: bytes       # bytes 15..18 — confirmed zero-padding (corpus-wide)
    sentinel: int          # byte 19 — per-version, distribution mirrors version
    body_size: int
    body_raw: bytes
    # --- size-115 "fix-detail" variant, F3-grounded ---
    # Only populated for the 115-byte record (body_size == 95), the per-fix
    # position-accuracy member emitted 1:1 with lm_mgp.c "Received FIX REPORT
    # from MGP" (see docstring). None for every other size-class.
    horiz_flag_80: int | None  # rec +80 u8 — horizontal-block valid flag (CANDIDATE; 0x00 ⇒ +82/+86 unpopulated)
    vert_flag_81: int | None   # rec +81 u8 — vertical-block quality flag (CANDIDATE)
    accuracy2_m: float | None  # rec +82 LE-f32 — 2nd accuracy float, tracks hepe (CANDIDATE)
    hepe_m: float | None       # rec +86 LE-f32 — HEPE (m); == lm_mgp.c "hepe:" (F3-GROUND)
    alt_unc_m: float | None    # rec +91 LE-f32 — vertical uncertainty (m); == TLE "AltUnc:" (F3-GROUND)
    altitude_hae_m: float | None  # rec +95 LE-f32 — altitude above WGS-84 ellipsoid (m); == TLE "Alt:" (F3-GROUND)

    def to_dict(self) -> dict[str, Any]:
        d = {
            'type': 'Diag0x1587',
            'log_time': self.log_time,
            'version': self.version,
            'counter_hi': self.counter_hi,
            'counter_lo': self.counter_lo,
            'byte_3': self.byte_3,
            'flag_4': self.flag_4,
            'state_5': self.state_5,
            'marker_6': self.marker_6,
            'mid_hex': self.mid_raw.hex(),
            'byte_13': self.byte_13,
            'flag_14': self.flag_14,
            'pad_15_18_hex': self.pad_15_18.hex(),
            'sentinel': self.sentinel,
            'body_size': self.body_size,
            'payload_size': 20 + self.body_size,
        }
        if self.hepe_m is not None:
            d['horiz_flag_80'] = self.horiz_flag_80
            d['vert_flag_81'] = self.vert_flag_81
            d['accuracy2_m'] = self.accuracy2_m
            d['hepe_m'] = self.hepe_m
            d['alt_unc_m'] = self.alt_unc_m
            d['altitude_hae_m'] = self.altitude_hae_m
        return d


# Ground-truth recipe — NOT hardware-verified. SIM8202G-M2 (SIMCom SDX55) is
# the recommended target. Written for v=0x0F, the most-attested version
# corpus-wide (49.7%); the 5 versions {0x0C..0x10} are sequential
# firmware-rev sentinels, not chipset-locked, so the validator confirms the
# exact byte-0 value the SIM8202G-M2 firmware emits at capture time and
# re-stamps `version` if it differs. The older community name for this code
# (LOG_EVENT_IPSEC_CHILD_SA_REKEY_DONE / RESERVED) is an IPsec event name for
# a code whose content (state_5 GNSS tracking-state byte, GNSS F3 co-emission)
# is unambiguously GNSS, so this grounds against the GNSS engine.

@register(
    LOG_GNSS_TRACKING_1587, domain="gnss",
    name="0x1587",
    description="GNSS per-fix MGP report (0x1587); 20-byte header + size-keyed body; 5 versions {0x0C..0x10}; size-115 fix-detail carries HEPE @+86, vertical uncertainty @+91 and ellipsoidal altitude @+95 (F3-grounded on all 5 versions)",
    version=7,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    # Pin the tracker explicitly.
    issues=(),
    source_detail=(
        "Clean-room RE across a 634,238-record corpus (5 versions "
        "{0x0C..0x10}, 0 rejects / 0 invariant violations), F3-grounded on "
        "every version: v0x0C EM7455 (MDM9x30), v0x0D EG25-G (MDM9x07), v0x0E "
        "EG18-NA, v0x0F RM500Q-AE + SIM8202G-M2 (SDX55), v0x10 RM520N-GL "
        "(SDX62). The record is the per-fix MGP report — 100% co-emitted with "
        "mc_peak.c per-SV C/No and 1:1 with lm_mgp.c 'Received FIX REPORT "
        "from MGP'. Header: all 20 bytes named (+3/+13 and +4/+14 mirror "
        "pairs, +5 GNSS tracking-state, +6 marker enum {0x05,0x09,0xff}, "
        "+15..+18 zero padding, +19 per-version sentinel); u16 LE @+23 is a "
        "length word (len == 25 + u16@23 on 960,982/960,983 records). The "
        "115-byte body is one slot map across all versions: +86 LE-f32 HEPE "
        "(== lm_mgp.c 'hepe:'), +91 LE-f32 vertical uncertainty (== TLE "
        "'AltUnc:'), +95 LE-f32 altitude above the ellipsoid (== TLE 'Alt:'; "
        "HAE per NMEA GGA); +80/+81 flags and +82 accuracy2 are CANDIDATE; "
        "+80==0x00 <=> +82==+86==0.0 on 107,994/107,994 (SDX55 v0x0F never "
        "fills the horizontal block). The 50B/85B classes are a static "
        "config snapshot, not per-SV data. mid_raw (+7..+12) and the other "
        "size classes' bodies remain opaque. A declared length overrunning "
        "the payload, or a payload under 25 B, returns None."
    ),
    source_url="",
    # 11 named header scalars (version, counter_hi, counter_lo, byte_3,
    # flag_4, state_5, marker_6, byte_13, flag_14, sentinel, body_size) +
    # hepe_m, alt_unc_m, altitude_hae_m (size-115 body, F3-grounded) = 14
    # IDENTIFIED. accuracy2_m (+82) and the +80/+81 flag bytes are CANDIDATE —
    # parsed but not yet named → 17 parsed. mid_raw (+7..+12) and the rest of
    # body_raw (+20..) remain opaque — the record is NOT 100% decoded.
    fields_parsed=17,
    fields_identified=14,
    # version is genuinely polymorphic — 5 sequential format revisions
    # observed across the corpus. Size invariance is not format invariance:
    # this enum is the protection against silent mis-parse on a future
    # v=0x11 record. ADD 0x11 (and any later values) here when a new
    # version's body is decoded.
    #
    # marker_6 (byte +6) takes EXACTLY {0x05, 0x09, 0xff} across all
    # 199,121 records / 5 versions (full-corpus walk). 0xff is the
    # uninitialized-sentinel value. A 4th value would signal a firmware
    # format change — surfaced as an enum violation.
    field_invariants={
        "version":  {"enum": [0x0C, 0x0D, 0x0E, 0x0F, 0x10]},
        "marker_6": {"enum": [0x05, 0x09, 0xFF]},
    },
)
def parse_0x1587(log_time: int, data: bytes) -> Diag0x1587 | None:
    """Parse a 0x1587 GNSS tracking detail record.

    Layer-1 first-byte version-gate: only the 5 corpus-observed versions
    {0x0C..0x10} are accepted; anything else returns None.  The matching
    layer-2 ``field_invariants={"version": {"enum": [...]}}`` on the
    @register call provides a backstop via ``check_invariants()``.
    """
    if len(data) < _BODY_PREFIX_END:
        return None
    if data[0] not in _KNOWN_VERSIONS:
        return None
    # u16 LE @+23 declares the byte count that follows the 25-byte prefix
    # (len == 25 + u16@23 on 41/41 sampled corpus records spanning all 5
    # versions and 17 size classes, 46..416 B, and consistent with the
    # byte+23/+24 histograms of 960,982/960,983 records in 993 capture
    # sidecars). A
    # declared length overrunning the payload means the record is truncated:
    # return None (registry WARN) instead of a silently short body. Trailing
    # bytes beyond the declared length are still tolerated.
    if _BODY_PREFIX_END + struct.unpack_from('<H', data, 23)[0] > len(data):
        return None
    body_size = len(data) - 20
    # size-115 "fix-detail" variant: the per-fix position-accuracy member.
    # F3-grounded: rec +86 LE-f32 == lm_mgp.c "hepe:"
    # (exact value match, 1:1 with FIX REPORT count) on v0x0D/v0x0E/v0x10.
    # Gated on the 115-byte layout (body_size == 95), NOT on version — the
    # body grammar is size-keyed; the version byte only tags the GNSS-engine
    # firmware vintage. NULL-fix records carry 0.0 here (the firmware's own
    # no-valid-fix sentinel), which is surfaced verbatim, not suppressed.
    # The same 115-byte slot map holds on v0x0C and v0x0F.
    # The SDX55 v0x0F builds leave the horizontal block empty (+80 == 0x00,
    # +82/+86 == 0.0) and still carry the vertical pair at +91/+95. A second
    # vertical pair at +107..+114 (usually identical) stays raw in body_raw.
    horiz_flag_80 = vert_flag_81 = None
    hepe_m = accuracy2_m = alt_unc_m = altitude_hae_m = None
    if body_size == 95:
        horiz_flag_80 = data[80]
        vert_flag_81 = data[81]
        accuracy2_m = struct.unpack_from('<f', data, 82)[0]
        hepe_m = struct.unpack_from('<f', data, 86)[0]
        alt_unc_m = struct.unpack_from('<f', data, 91)[0]
        altitude_hae_m = struct.unpack_from('<f', data, 95)[0]
    return Diag0x1587(
        log_time=log_time,
        version=data[0],
        counter_hi=data[1],
        counter_lo=data[2],
        byte_3=data[3],
        flag_4=data[4],
        state_5=data[5],
        marker_6=data[6],
        mid_raw=data[7:13],
        byte_13=data[13],
        flag_14=data[14],
        pad_15_18=data[15:19],
        sentinel=data[19],
        body_size=body_size,
        body_raw=data[20:],
        horiz_flag_80=horiz_flag_80,
        vert_flag_81=vert_flag_81,
        accuracy2_m=accuracy2_m,
        hepe_m=hepe_m,
        alt_unc_m=alt_unc_m,
        altitude_hae_m=altitude_hae_m,
    )
