"""GNSS RF hardware status parser (0x147E).

LOG_GNSS_PRX_RF_HW_STATUS_REPORT — reports the state of the GNSS front-end
(PRX = Parallel RX RF).  Two format variants observed:

- **SDX20 V2 (EG18-NA)**: fixed 349 bytes, version byte = 4
- **SDX55 (FN980m)**: fixed 722 bytes, version byte = 5

The header region (bytes 0..63) is stable across records and contains
identity strings + a millisecond counter. The body region (bytes 64 to
end) holds repeating measurement/state entries whose exact struct is
only partially RE'd — per-path AGC, LNA gain, noise floor, jamming
indicators per an external reference, but the exact field offsets
aren't confirmed. The full payload is preserved as ``raw`` so downstream
RE can continue.

Canonical code name from an external MIT reference:
``LOG_GNSS_PRX_RF_HW_STATUS_REPORT = 0x147E``. That reference declares the
constant but doesn't parse the body, so this parser is the first
known open-source decoder for the identity + counter header.

## Header layout (validated 2026-04-11 against EG18-NA and FN980m)

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
                                         (not yet fully RE'd)

## Body region observations

- On the EG18-NA 305-record corpus, the body has a pattern of scattered
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
  offset 70-77, mirroring the L5-E band ID at offset 52-59 — strong
  evidence that SDX55 has separate per-band RF state blocks.
- Full body RE is tracked in #N.

## Body ASCII-label catalog (2026-05-31 <redacted-ref> ASCII-lens, 8,000-record sample, 100% parse)

Decoding every ASCII run in the body (bytes 64+) per version shows the
body holds **structured RF-band + GLONASS-channel labels** on the NR5G-
capable generations — these are the per-path RF state-block headers, and
are the concrete content the "L1-E / L5-E" observation above hinted at:

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

The #N partial-constellation signature is **live in the corpus**: 351 of
the sampled v=4 records report ``constellations='GPS/BDS'`` (2 of 4) — the
exact gnssconfig-misconfig tell — alongside the healthy
``GPS/GLO/BDS/GAL``. Next step for body decode: the v5/v6 band labels sit
at quasi-fixed offsets per band block, so a structural ``rf_bands`` /
``glonass_channels`` extraction is the natural follow-up (currently all in
``raw``).

## Version-specific quirks

- **Version 4 (SDX20-class)**: 349-byte payload, ``constellations`` is
  a slash-separated string at offset 16..31 (e.g. ``GPS/GLO/BDS/GAL``).
  The number of slashes + 1 is the constellation count.
- **Version 5 (SDX55-class)**: 722-byte payload. The byte at offset 16
  is a u8 numeric constellation count (e.g. 4 = "all four"), NOT a
  string. The current parser still reads bytes 16..31 as a NUL-terminated
  ASCII string, which yields the literal value ``"4"`` for SDX55. This
  is documented + tested but not "fixed" because:
    1. The numeric-as-string artifact is harmless for human inspection.
    2. Consumers can dispatch on ``version`` to decide whether to
       interpret ``constellations`` as a string set or a count.
    3. A v5 special-case branch would couple the dataclass shape to a
       version-specific layout, which is the wrong abstraction.

## #N detection capability

The pre-#N-fix EG18-NA capture (2026-04-08) reports
``constellations='GPS/BDS'`` — only 2 of the 4 enabled constellations,
which is the exact signature of the gnssconfig misconfig that #N
chases. The post-fix v2 capture (2026-04-11) reports
``constellations='GPS/GLO/BDS/GAL'``. This means the 0x147E header is
a passive validator for GNSS configuration: if a future capture reports
fewer constellations than expected, the modem isn't actually tracking
what its config claims.

=== names-block:start (auto-generated by tools/inject_names_block_parsers.py) ===

Names by source (from sources/DIAG_LOG_INDEX.yaml):
    canonical: LOG_GNSS_PRX_RF_HW_STATUS_REPORT_C
        source: qualcomm_diag_log_codes_h (authority: vendor_official)
    aliases: (none recorded)

Source-precedence (#N): vendor_official > observation >
community (specification) > community (reference).
=== names-block:end ===
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


# --- v3 body band-block extraction (#N, 2026-06-01 ASCII-lens follow-up) ---
#
# 824a cataloged the v5/v6 body ASCII band labels but left them in `raw`.
# A corpus offset-map (tools/diag_147e_band_offsets.py, 8,000-record sample)
# confirms they sit at quasi-fixed body offsets (L1-E@66, GPS L1@141,
# GAL E1@168, BDS B1@239, L5-group@695; GLO SV blocks at a 27-byte stride
# from @371) and — critically — that *presence varies per record*: each
# block is emitted only for a band the front-end is actively tracking
# (e.g. a v6 record with GPS L1 + GLONASS only, no Galileo/BeiDou/L5).
# We extract by SCAN, not fixed offset: the labels are distinctive multi-byte
# ASCII that binary-float body noise will not forge, and scanning survives a
# future firmware shifting the blocks within the same payload size (the
# project's "size invariance != format invariance" trap).
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

    The full payload is retained in ``raw`` so future reverse engineering
    can inspect the remaining binary measurement region (per-path AGC /
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


# Ground-truth recipe (#N). Authored OFFLINE (hw_run_performed=False); every
# field is a hypothesis until a hardware run confirms it. Target: SIMCom
# SIM7600NA-H (MDM9207), the v=0x04 / 349B emitter. ⚠ The v4 body is BINARY (no
# ASCII band labels) so the parser leaves rf_bands AND glonass_channels EMPTY
# for this variant (offline corpus peek confirmed both == []) — they are NOT
# groundable here and are deliberately omitted from the field map. The
# groundable v4 field is `constellations`, the decoded enabled-GNSS-systems
# bitmask (offline peek: 'GPS/GLO/BDS/GAL'); `ms_counter` is a free-running
# tick. fw_id/sdr_chip/board_id are GNSS hardware-identity strings (constant per
# unit, no AT readback) — documented in notes, not grounded.

@register(LOG_GNSS_PRX_RF_HW_STATUS_REPORT, domain="gnss",
    name="0x147E",
    primary_issue=None,  # #N: per-code diag 0x147E tracker (vs #N recipe meta)
    description="GNSS front-end RF hardware status: version, fw_id, SDR chip, constellation config, ms counter; v3 extracts per-band RF block labels (rf_bands) + GLONASS FDMA channels (glonass_channels) from the v5/v6 body; remaining binary measurement region preserved as raw (#N)",
    version=4,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "v4 (#N, 2026-06-11): first per-modem HW validation (#N) on Quectel "
        "RM520N-GL @ RM520NGLAAR03A03M4G (SDX62, sole v=0x06 emitter, <redacted-ref> "
        "5174, live fix) — constellations VERIFIED (bitmask 7 = GPS|GLO|GAL, "
        "matches GSV talkers), glonass_channels/rf_bands/ms_counter PARTIAL. "
        "Initial RE: EG18-NA SDX20 V2 + FN980m SDX55 DLF capture analysis. "
        "2026-05-08 corpus walk (48,309 records / 196 captures) confirms "
        "3 cross-generation (size, version) profiles: 349B/v=4 (SDX20: "
        "EG18-NA, EG25-G, LM960; 21,199 records), 722B/v=5 (SDX55: FN980m, "
        "EM9190, RM500Q, M2000; 20,441 records), 749B/v=6 (SDX62: "
        "RM520N-GL only; 5,673 records — fw_id='9.510.0100', sdr_chip="
        "'SDR735'). Code name cross-checked against an external MIT reference "
        "that does not decode the body. "
        "v3 (2026-06-01, <redacted-ref> ASCII-lens follow-up to 824a): structural "
        "extraction of the v5/v6 body band labels into rf_bands (per-band "
        "RF block membership — GPS L1 / GAL E1 / BDS B1 / L1-E / "
        "L5/E5x/B2x, present-set varies per record) + glonass_channels "
        "(GLONASS FDMA channel numbers -7..+6 from GLO G1 SV blocks). "
        "Offset map (tools/diag_147e_band_offsets.py, 8,000 records): band "
        "labels at fixed body offsets, GLO SV blocks at 27-byte stride; "
        "extracted by scan (not fixed offset) for size-vs-format robustness. "
        "v4 body is binary (no labels) -> both fields empty."
    ),
    source_url="",
    # Layer-2 plausibility — corpus walk 2026-05-22 against 40,269 records:
    #   version (offset 0): {0x04, 0x05, 0x06} corpus-wide
    #     0x04 = 349B (SDX20: EG18-NA, EG25-G, LM960)
    #     0x05 = 722B (SDX55: FN980m, EM9190, RM500Q, M2000)
    #     0x06 = 749B (SDX62: RM520N-GL)
    # The version byte cleanly correlates with payload size. The parser
    # currently reads `version` and emits it but does NOT validate it.
    # Declaring the enum makes the audit toolchain surface previously-unseen
    # variants (e.g., an SDX65 v=7 variant) instead of silently passing them
    # through with garbage strings.
    # NOTE: closure for the body region (bytes 64..end — 285/658/685 B
    # depending on variant) remains open. Per #N issue: AGC, jamming
    # indicators, noise floor, per-path RF lock flags are all there but
    # are not yet decoded into named fields. The version-byte enum is a
    # layer-2 hardening only — body-decode closure is gated on cross-layer
    # ground truth (controlled-jamming AT correlation or vendor docs).
    field_invariants={
        "version": {"enum": [4, 5, 6]},
    },
    # ASCII audit (#N, Quectel slice): 31/31 records carry fixed
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
    payload for downstream RE of the body measurement/state bytes.
    """
    # Minimum length to safely read all header fields through byte 64.
    if len(data) < 64:
        return None
    # Layer-1 version gate (#N / #N). Reject records whose byte-0
    # version is outside the declared field_invariants enum. A future
    # SDX65/SDX75 record with a new version byte at the same 749/685/etc.
    # size would otherwise silently route through structural decode and
    # produce ASCII strings sliced at offsets that no longer hold them.
    if data[0] not in (4, 5, 6):
        return None
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
