"""GNSS RF hardware status parser (0x147E).

LOG_GNSS_PRX_RF_HW_STATUS_REPORT — reports the state of the GNSS front-end
(PRX = Parallel RX RF).  Format variants observed:

- **MDM9200 (Sierra MC7700, SWI9200X)**: fixed 129 bytes, version byte = 1 —
  a DIFFERENT, shorter header: u32 ``ms_counter`` at [2:6] and the RF
  transceiver part ``'RTR8600'`` at [6:18]; no fw_id / constellations /
  board_id strings (exposed as ``''``); binary body like v4 (``rf_bands`` /
  ``glonass_channels`` empty). See the v1 grounding note below.

- **SDX20 V2 (EG18-NA)**: fixed 349 bytes, version byte = 4
- **SDX55 (FN980m)**: fixed 722 bytes, version byte = 5
- **SDX62 (RM520N-GL)**: fixed 749 bytes, version byte = 6
- **SDX72 (Foxconn T99W640)**: fixed 816 bytes, version byte = 7

  The v7 header is byte-for-byte offset-stable with v4/5/6:
  ``fw_id='9.010.0060'``, ``sdr_chip='SDR753'``, ``board_id='L1EG0'``,
  ``ms_counter`` at [36:40]. NOTE: the co-temporal F3 GNSS-RF driver module
  reports itself as ``navrx_sdr875.cpp`` while the record's ``sdr_chip``
  string is ``SDR753`` — a driver-family-vs-reported-part label difference
  on the DW5934e, not a decode error.

  **v7 F3 grounding** — a GNSS-active T99W640 capture (65 v7 records, live
  GLONASS SV tracking):
    * The **v7 body is ASCII-labeled like v5/v6**, NOT binary like v4. All
      65 records extract ``rf_bands=('GPS L1', 'BDS B1')`` and a
      per-record-varying ``glonass_channels`` (real FDMA channels in -6..+4).
    * ``ms_counter`` is the GNSS-ME 1 Hz count: it locks to the F3
      ``mc_gnssmeasreport.c`` ``L1Gps_MBlk(1Hz) ... FC <n>`` counter at a
      constant phase (ms - FC = +462, 51/58 co-temporal records; the same
      +462 seen on v6), both stepping 1000 (GPS Wk 2423 co-reported).
    * ``rf_bands=('GPS L1','BDS B1')`` is grounded in the tracking direction
      by co-temporal ``mc_gnsssearchstrategy.c``: GPS + BDS are in active
      ``MIXED_UNC`` tracking (BDS ``B1_Track:5``) so both emit their band
      block; GAL is only ``BLIND_SEARCH`` (searching, not locked) so there is
      no ``GAL E1`` block; NAVIC ``IDLE``. The same presence logic holds at
      v5 (all-active -> all-bands) and v6 (idle-BDS -> no BDS B1).
    * ``glonass_channels`` is corroborated: F3 ``mc_gloafc.c`` /
      ``mc_glodebits.c`` show live GLONASS SV 9/12 AFC-lock + nav-bit demod
      (``GLOPRN 9 ... PRIME_BUFFER --> MS_SYNC``) — GLONASS is really
      tracking, matching the populated channel list. The exact FDMA-channel
      <-> orbital-slot mapping remains a CANDIDATE (as on v5/v6).
    * ``constellations='16'`` is a **CANDIDATE of unconfirmed semantics** on
      v7 — do NOT read it as v4's SET / v5's COUNT / v6's bitmask. F3 shows
      the active set is {GPS, GLO, BDS tracking; GAL searching; NAVIC idle}:
      that is 4 active systems (``'4'`` under v5's count semantics) whose
      v6-style bitmask (GPS|GLO|GAL|BDS = 1+2+4+8) would be ``'15'`` —
      neither is ``'16'``. The firmware's own config is ``GnssCfg=0x907``
      (``mc_gnssconfig.c``), also not 16. The parser exposes the field
      verbatim; v7's active constellations are established by ``rf_bands`` +
      ``glonass_channels`` + F3, NOT by this field.
    * QCSuper and SCAT do not decode 0x147E. The capture carries no
      DIAG_EVENT_REPORT_F (0x60) frames.

**v=0x01 grounding** — 767 records / 5 MC7700 captures (two firmware builds,
two units), all DLF, so **F3 is absent** (no 0x79/0x99/0x60 plane survives
HDLC→DLF). Grounded on the firmware's own co-emitted GNSS reports:

  * Emitted **once per GNSS-ME epoch**, in lockstep with 0x1477 v0 and
    0x147D v0 (GNSS comparison runs: 300/300/300 and 305/301/301).
  * ``ms_counter`` (u32 @2) on the **older build**: ``ms_counter −
    0x1477.f_count == +11768`` on **81/81** records — the same
    constant-phase lock that grounds v5/v6/v7 — and it reproduces the frame
    count's *irregular* +740 step exactly, not just the regular +1000s.
  * ``ms_counter`` on the **newer build**: advances at exactly **0.200 or
    0.320 ×** the frame count (334 / 339 of 673 one-second pairs; never in
    between). That shape fits a duty-cycled RF on-time accumulator
    (always-on = 1.0 on the older build), but no body byte separates the two
    rates, so that reading is a **CANDIDATE**; only the older-build lock is
    claimed.
  * ``sdr_chip = 'RTR8600'`` on 767/767 (the MDM9200's RF transceiver) —
    a hardware-identity string, documented but not independently grounded,
    as on v4–v7.
  * byte [1] = 0x03 on 767/767 — an unnamed constant.

The v4–v7 header region (bytes 0..63) is stable across records and contains
identity strings + a millisecond counter. The body region (bytes 64 to end)
holds repeating measurement/state entries whose struct is only partially
decoded; it is expected to carry per-path RF state (AGC, LNA gain, noise
floor, jamming indicators), but no field offsets are confirmed. The full
payload is preserved as ``raw``.

Canonical code name from an external MIT-licensed reference:
``LOG_GNSS_PRX_RF_HW_STATUS_REPORT = 0x147E``. That reference declares the
constant but doesn't parse the body, so this parser is the first known
open-source decoder for the identity + counter header.

## Header layout (validated against EG18-NA and FN980m)

    Bytes  0..0:    u8    version        (4 on SDX20 V2, 5 on SDX55)
    Bytes  1..15:   cstr  fw_id          e.g. "Gen9HT 9.1.0" (SDX20 V2)
    Bytes 16..31:   cstr  constellations e.g. "GPS/GLO/BDS/GAL"
    Bytes 32..35:   4 B   (constant / reserved)
    Bytes 36..39:   u32   ms_counter     millisecond counter — increments
                                         ~1000/sec, corroborating that
                                         the modem emits this log code
                                         once per second
    Bytes 40..47:   cstr  sdr_chip       e.g. "SDR845" (SDX20 V2)
    Bytes 48..51:   4 B   (zero / reserved)
    Bytes 52..63:   cstr  board_id       e.g. "M5ET" (SDX20 V2)
    Bytes 64..end:  raw   body           per-path RF measurement state
                                         (partially decoded)

## Body region observations

- On a 305-record EG18-NA sample, the body has a pattern of scattered
  variable bytes at ~4-byte stride suggesting an array of i32 or u32
  values where the high bytes are often stable (small values near zero)
  and the low byte carries per-epoch variation.
- Values like ``0xfffffff8`` (= -8) appear at several offsets, consistent
  with per-band AGC or signal-level corrections in units of dB or
  0.1 dB.
- On the FN980m 722-byte variant, the body is roughly 2× the size of the
  SDX20 V2 body — consistent with double the number of RF paths /
  constellation bands being monitored (SDX55 tracks more bands).
  The body region also contains a second band ID string ("L1-E") at
  offset 70-77, mirroring the L5-E band ID at offset 52-59 — evidence
  that SDX55 has separate per-band RF state blocks.

## Body ASCII-label catalog (8,000-record sample, 100% parse)

Decoding every ASCII run in the body (bytes 64+) per version shows the
body holds **structured RF-band + GLONASS-channel labels** on the NR5G-
capable generations — these are the per-path RF state-block headers, and
are the concrete content behind the "L1-E / L5-E" observation above:

* **v=5 (SDX55, 722B)** body labels (single fingerprint
  ``fw_id='9.510.0000' sdr='SDR865' board='L5-E'``):
  ``GPS L1``, ``GAL E1``, ``BDS B1``, ``L1-E`` (per-constellation L1 band
  blocks), ``L5/E5A/B2A`` (L5 band group), and ``GLO G1 SV <n>`` for n in
  -7..+6 — the **GLONASS FDMA frequency-channel numbers** the front-end is
  tracking (G1 = GLONASS L1 sub-band).
* **v=6 (SDX62, 749B)** body labels (single fingerprint
  ``fw_id='9.510.0100' sdr='SDR735' board='L5-E'``): same set, but the L5
  group is spelled **lowercase** ``L5/E5a/B2a`` (vs v5's uppercase
  ``L5/E5A/B2A``) — a firmware-version ASCII tell.
* **v=4 (SDX20, 349B)** body is mostly binary (float32) with no structured
  band labels; the *header* fingerprint, however, is NOT single — the
  sample carries **three distinct GNSS-engine builds**:
  ``Gen8C-L-turbo`` / ``WTR2965`` / board ``M5-ET``;
  ``Gen8C-lite`` / ``WTR3925`` / ``M5-ET``;
  ``Gen9HT 9.1.0`` / ``SDR845`` / ``M5ET`` (note the board_id hyphenation
  varies: ``M5-ET`` on Gen8C, ``M5ET`` on Gen9HT).

The partial-constellation signature (see below) appears in the corpus: 351
of the sampled v=4 records report ``constellations='GPS/BDS'`` (2 of 4)
alongside the healthy ``GPS/GLO/BDS/GAL``. The v5/v6/v7 band labels are
extracted into ``rf_bands`` / ``glonass_channels``.

## Version-specific quirks

- **Version 4 (SDX20-class)**: 349-byte payload, ``constellations`` is
  a slash-separated string at offset 16..31 (e.g. ``GPS/GLO/BDS/GAL``).
  The number of slashes + 1 is the constellation count.
  **F3-grounded** on an EG25-G all-log + F3 capture (248 v4 records, Gen8C
  fingerprint ``fw_id='Gen8C-L-turbo'`` / ``sdr='WTR2965'`` /
  ``board='M5-ET'``): the record ``constellations='GPS/GLO/BDS/GAL'`` is
  the literal enabled SET, per co-temporal ``mc_gnsssearchstrategy.c``
  F3 — exactly those four systems in active ``BLIND_SEARCH`` (no NAVIC). The
  slash-string is a genuine SET, distinct from v5's numeric *count* (``'4'``)
  and v6's *bitmask* (``'7'``); consumers dispatch on ``version``.
  ``ms_counter`` is the GNSS-ME 1 Hz count: all 248 values equal a
  ``mc_gnssmeasreport.c`` ``Gps_MeasBlk`` ``FC`` value EXACTLY (zero phase,
  248/248). ``rf_bands`` / ``glonass_channels`` are empty on v4 (binary body).
- **Version 5 (SDX55-class)**: 722-byte payload. The byte at offset 16
  is a u8 numeric constellation count (e.g. 4 = "all four"), NOT a
  string. The parser reads bytes 16..31 as a NUL-terminated ASCII string,
  which yields the literal value ``"4"`` for SDX55.
  **F3-grounded** on an EM9190 (SWIX55C) GNSS-acquire capture: the record
  ``constellations='4'`` is a *count*, per co-temporal
  ``mc_gnsssearchstrategy.c`` — exactly four constellations in active
  ``BLIND_SEARCH`` (GPS/GLO/BDS/GAL) with ``NAVIC: IDLE``; all four
  ``rf_bands`` are present because all four are active (inverse of the v6
  case, where an idle BeiDou drops ``BDS B1``); ``ms_counter`` locks 1:1 to
  the F3 ``Gps_MeasBlk(1Hz) FC`` counter at a constant phase. This
  numeric-*count* semantics is distinct from v6's *bitmask* (``'7'`` =
  GPS|GLO|GAL). The string read is kept deliberately because:
    1. The numeric-as-string value is harmless for human inspection.
    2. Consumers can dispatch on ``version`` to decide whether to
       interpret ``constellations`` as a string set or a count.
    3. A v5 special-case branch would couple the dataclass shape to a
       version-specific layout, which is the wrong abstraction.

## Partial-constellation detection

An EG18-NA capture taken with a misconfigured GNSS constellation setting
reports ``constellations='GPS/BDS'`` — only 2 of the 4 enabled
constellations. After the configuration fix, a capture from the same module
reports ``constellations='GPS/GLO/BDS/GAL'``. The 0x147E header is therefore
a passive validator for GNSS configuration: if a capture reports fewer
constellations than expected, the modem isn't actually tracking what its
config claims.

Log name: LOG_GNSS_PRX_RF_HW_STATUS_REPORT_C
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from typing import Any

from diaggrok.codes import LOG_GNSS_PRX_RF_HW_STATUS_REPORT
from diaggrok.registry import register


def _cstr(data: bytes, start: int, end: int) -> str:
    """Extract a NUL-terminated ASCII string from a fixed-size slot."""
    slot = data[start:end]
    nul = slot.find(b'\x00')
    if nul >= 0:
        slot = slot[:nul]
    try:
        return slot.decode('ascii')
    except UnicodeDecodeError:
        return ''


# --- Body band-block extraction ---------------------------------------------
#
# A corpus offset map (8,000-record sample) shows the v5/v6 body ASCII band
# labels sit at quasi-fixed body offsets (L1-E@66, GPS L1@141, GAL E1@168,
# BDS B1@239, L5-group@695; GLO SV blocks at a 27-byte stride from @371) and
# that *presence varies per record*: each block is emitted only for a band
# the front-end is actively tracking (e.g. a v6 record with GPS L1 + GLONASS
# only, no Galileo/BeiDou/L5). Extraction is by SCAN, not fixed offset: the
# labels are distinctive multi-byte ASCII that binary-float body noise will
# not forge, and scanning survives a future firmware shifting the blocks
# within the same payload size (same size does not imply same format).
_BAND_LABEL_RES = [
    re.compile(rb"GPS L1"),
    re.compile(rb"GAL E1"),
    re.compile(rb"BDS B1"),
    re.compile(rb"L1-E"),
    re.compile(rb"L5/E5[Aa]/B2[Aa]"),  # L5 band group; spelling is a fw tell
]
# GLONASS L1 is FDMA: each tracked SV reports its frequency-channel number
# (-7..+6) in a `GLO G1 SV <n>` block.
_GLO_SV_RE = re.compile(rb"GLO G1 SV (-?\d+)")


def _extract_rf_bands(body: bytes) -> tuple[str, ...]:
    """Per-band RF front-end block labels present in the body, in body order.

    Returned in byte-offset order so the L5-group spelling is preserved
    verbatim (``L5/E5A/B2A`` upper = v5/SDR865, ``L5/E5a/B2a`` lower =
    v6/SDR735 — a firmware tell). Empty on v4 (binary body, no labels).
    """
    hits: list[tuple[int, str]] = []
    for rx in _BAND_LABEL_RES:
        for m in rx.finditer(body):
            hits.append((m.start(), m.group().decode("ascii")))
    hits.sort()
    return tuple(label for _off, label in hits)


def _extract_glonass_channels(body: bytes) -> tuple[int, ...]:
    """GLONASS FDMA frequency-channel numbers from ``GLO G1 SV <n>`` blocks.

    In body order (the SV-block order), not sorted — faithful to the record.
    Empty on v4 (no GLONASS band blocks emitted).
    """
    return tuple(int(m.group(1)) for m in _GLO_SV_RE.finditer(body))


@dataclass
class Diag0x147E:
    """LOG_GNSS_PRX_RF_HW_STATUS_REPORT (0x147E).

    Fields exposed from the stable-identity header region:

    - ``version``:         version byte (observed 4=SDX20V2, 5=SDX55)
    - ``fw_id``:           GNSS RF firmware identifier (e.g. "Gen9HT 9.1.0")
    - ``constellations``:  configured constellation string (e.g. "GPS/GLO/BDS/GAL")
    - ``sdr_chip``:        SDR chip model (e.g. "SDR845")
    - ``board_id``:        additional board/module ID string (e.g. "M5ET")
    - ``ms_counter``:      millisecond counter at byte 36, ~1000/sec
                           cadence — confirms the modem emits this log
                           code once per second
    - ``rf_bands``:        per-band RF front-end block labels present in
                           the body, in body order (``GPS L1``, ``GAL E1``,
                           ``BDS B1``, ``L1-E``, ``L5/E5x/B2x``). Empty on
                           v4. Membership varies per record — the front-end
                           emits a block only for a band it is tracking.
    - ``glonass_channels``: GLONASS FDMA frequency-channel numbers (-7..+6)
                           from the ``GLO G1 SV <n>`` blocks, one per tracked
                           GLONASS SV, in body order. Empty on v4.

    The full payload is retained in ``raw`` so the remaining binary
    measurement region can be inspected the remaining binary measurement region (per-path AGC /
    noise-floor floats) without re-reading the DLF.
    """

    log_time: int
    version: int
    fw_id: str
    constellations: str
    sdr_chip: str
    board_id: str
    ms_counter: int
    rf_bands: tuple[str, ...]
    glonass_channels: tuple[int, ...]
    raw: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x147E',
            'log_time': self.log_time,
            'version': self.version,
            'fw_id': self.fw_id,
            'constellations': self.constellations,
            'sdr_chip': self.sdr_chip,
            'board_id': self.board_id,
            'ms_counter': self.ms_counter,
            'rf_bands': list(self.rf_bands),
            'glonass_channels': list(self.glonass_channels),
            'payload_size': len(self.raw),
        }


# Ground-truth recipe, authored offline (hw_run_performed=False); every field
# is a hypothesis until a hardware run confirms it. Target: SIMCom
# SIM7600NA-H (MDM9207), the v=0x04 / 349B emitter. The v4 body is BINARY (no
# ASCII band labels), so the parser leaves rf_bands AND glonass_channels EMPTY
# for this variant (an offline corpus check confirms both == []) — they are
# NOT groundable here and are deliberately omitted from the field map. The
# groundable v4 field is `constellations`, the enabled-GNSS-systems set
# (offline: 'GPS/GLO/BDS/GAL'); `ms_counter` is a free-running tick.
# fw_id/sdr_chip/board_id are GNSS hardware-identity strings (constant per
# unit, no AT readback) — documented in notes, not grounded.

#: Fixed record size per version: MDM9200 / SDX20 V2 / SDX55 / SDX62 /
#: SDX72.
_FIXED_SIZE = {1: 129, 4: 349, 5: 722, 6: 749, 7: 816}


@register(LOG_GNSS_PRX_RF_HW_STATUS_REPORT, domain="gnss",
    name="0x147E",
    primary_issue=None,
    description="GNSS front-end RF hardware status: version, fw_id, SDR chip, constellation config, ms counter; extracts per-band RF block labels (rf_bands) + GLONASS FDMA channels (glonass_channels) from the v5/v6/v7 body; remaining binary measurement region preserved as raw",
    version=10,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Five fixed-size (size, version) profiles: 129B/v=1 (MDM9200: Sierra "
        "MC7700, 767 records), 349B/v=4 (SDX20-class: EG12/EG18/EG25/EG95/"
        "EP06/LM960/MC74xx/EM75xx/SIM7600, ~23,000 records), 722B/v=5 (SDX55: "
        "FN980m, EM9190, RM500Q, M2000; ~31,500 records), 749B/v=6 (SDX62: "
        "RM520N-GL, CFW-3212; ~50,900 records), 816B/v=7 (SDX72: Foxconn "
        "T99W640 / Dell DW5934e; 287 records). v4-v7 share a header: fw_id "
        "cstr [1:16], constellations cstr [16:32], u32 ms_counter @36, "
        "sdr_chip cstr [40:48], board_id cstr [52:64]. v1 has a short header "
        "(ms_counter u32 @2, sdr_chip 'RTR8600' @6..18; the other strings "
        "absent) and a binary body. The v5/v6/v7 bodies carry ASCII band "
        "labels (GPS L1 / GAL E1 / BDS B1 / L1-E / L5/E5x/B2x; the present set "
        "varies per record) and 'GLO G1 SV <n>' blocks at a 27-byte stride, "
        "extracted by scan into rf_bands and glonass_channels (GLONASS FDMA "
        "channel numbers -7..+6); the v4 and v1 bodies are binary, so both "
        "fields are empty there. "
        "Each version with F3 is grounded against co-temporal F3: ms_counter "
        "is the GNSS-ME 1 Hz count, locked to mc_gnssmeasreport.c 'MeasBlk "
        "... FC <n>' at a constant phase — v4 zero phase 248/248 (EG25-G), "
        "v5 +6019387 (+/-1) on 1,476/1,484 (EM9190), v6 +462 (CFW-3212, 244 "
        "records), v7 +462 on 51/58 (T99W640). constellations semantics are "
        "per-version, per co-temporal mc_gnsssearchstrategy.c 'Strategy "
        "State' prints: v4 = slash-separated SET of enabled systems "
        "('GPS/GLO/BDS/GAL', 4 systems in BLIND_SEARCH), v5 = numeric COUNT "
        "('4', 4 active, NAVIC idle), v6 = bitmask ('7' = GPS|GLO|GAL, BDS "
        "and NAVIC idle; also matches the GSV talkers on an RM520N-GL "
        "hardware run), v7 = '16', a CANDIDATE of unconfirmed semantics (4 "
        "active systems would read '4' as a count or '15' as a bitmask; "
        "firmware config GnssCfg=0x907). rf_bands presence follows tracking: "
        "all four active -> all four band blocks (v5); idle BDS -> no BDS B1 "
        "(v6); GAL only searching -> no GAL E1 (v7). glonass_channels is "
        "corroborated by mc_glodebits.c / mc_gloafc.c GLONASS tracking; the "
        "exact FDMA-channel <-> orbital-slot mapping is a CANDIDATE. "
        "v1 (no F3: DLF captures) is grounded against the co-emitted 0x1477 "
        "frame count: constant phase +11768 on 81/81 records of one firmware "
        "build (including an irregular +740 step); on a second build "
        "ms_counter advances at 0.200/0.320x the frame count — a CANDIDATE "
        "duty-cycled on-time, not claimed. "
        "QCSuper and SCAT do not decode 0x147E; DIAG_EVENT_REPORT_F (0x60) "
        "frames, where present, carry nothing for these fields. fw_id / "
        "sdr_chip / board_id are hardware-identity strings (documented, not "
        "independently grounded). Code name cross-checked against an external "
        "MIT-licensed reference that does not decode the body. Records "
        "shorter than their version's fixed size return None (registry WARN)."
    ),
    source_url="",
    # Layer-2 plausibility: the version byte (offset 0) cleanly correlates
    # with payload size —
    #     0x01 = 129B (MDM9200: MC7700)
    #     0x04 = 349B (SDX20: EG18-NA, EG25-G, LM960)
    #     0x05 = 722B (SDX55: FN980m, EM9190, RM500Q, M2000)
    #     0x06 = 749B (SDX62: RM520N-GL)
    #     0x07 = 816B (SDX72: Foxconn T99W640; header offset-stable with
    #            v4/5/6)
    # Declaring the enum makes audit tooling surface previously-unseen
    # variants instead of silently passing them through with garbage strings.
    # The body region (bytes 64..end) is only partially decoded: AGC,
    # jamming indicators, noise floor and per-path RF lock flags are
    # expected there but are not decoded into named fields; that needs
    # cross-layer ground truth (e.g. controlled-jamming AT correlation).
    field_invariants={
        "version": {"enum": [1, 4, 5, 6, 7]},
    },
    # ASCII audit (Quectel sample): 31/31 records carry fixed
    # GNSS-engine / RF-chip descriptor labels in the body region
    # ('Gen8C-L-turbo', 'Gen9HT 9.1.0', 'WTR2965', 'GPS/GLO/BDS/GAL').
    ascii_kinds=("label",),
)
def parse_0x147e(
    log_time: int, data: bytes
) -> Diag0x147E | None:
    """Parse a LOG_GNSS_PRX_RF_HW_STATUS_REPORT (0x147E) log payload.

    Extracts the version byte, four stable ASCII identifier strings, and
    a millisecond counter from the header region; preserves the full
    payload for further analysis of the body measurement/state bytes.
    """
    # Minimum length for the shortest version (v1, 129 B); the per-version
    # fixed-size gate below is the real check.
    if len(data) < 18:
        return None
    # Layer-1 version gate. Reject records whose byte-0
    # version is outside the declared field_invariants enum. A future
    # SDX65/SDX75 record with a new version byte at the same 749/685/etc.
    # size would otherwise silently route through structural decode and
    # produce ASCII strings sliced at offsets that no longer hold them.
    if data[0] not in (1, 4, 5, 6, 7):
        return None
    # Each version is a fixed-size record (v1 129 B, v4 349 B,
    # v5 722 B, v6 749 B, v7 816 B — module docstring). A shorter one is
    # truncated: return None (registry WARN) instead of a partial body.
    if len(data) < _FIXED_SIZE[data[0]]:
        return None
    if data[0] == 1:
        # v1 (MC7700 MDM9200, 129 B): short header, binary body.
        return Diag0x147E(
            log_time=log_time,
            version=1,
            fw_id='',
            constellations='',
            sdr_chip=_cstr(data, 6, 18),
            board_id='',
            ms_counter=struct.unpack_from('<I', data, 2)[0],
            rf_bands=(),
            glonass_channels=(),
            raw=data,
        )
    body = data[64:]
    return Diag0x147E(
        log_time=log_time,
        version=data[0],
        fw_id=_cstr(data, 1, 16),
        constellations=_cstr(data, 16, 32),
        sdr_chip=_cstr(data, 40, 48),
        board_id=_cstr(data, 52, 64),
        ms_counter=struct.unpack_from('<I', data, 36)[0],
        rf_bands=_extract_rf_bands(body),
        glonass_channels=_extract_glonass_channels(body),
        raw=data,
    )
