"""GPS L1C measurement skeleton parser (0x1855) — #N.

GPS L1C is the modernized civil signal on L1 (1575.42 MHz), distinct
from the legacy L1 C/A signal. RINEX 3.04 obs codes for L1C are the
L1L / L1M / L1S / L1N / L1P families depending on the tracking mode;
this skeleton routes records with ``band='L1C'`` so the RINEX writer
(``apps/diaggpsd/rinex_writer.py``) can assign an obs-code group once
per-SV RE lands.

## Observed variants — 4 versions × many sizes

Cross-chipset corpus scan (2026-04-24) over 11 modem families and
~413 records identified **4 distinct version bytes**:

| Version | Chipset family    | Modems                       | Sizes (B) |
|---------|-------------------|------------------------------|-----------|
| `0x01`  | MDM9x07, MDM9x40  | EP06A, MC7455                | 68, 92, 256, 268, 360 |
| `0x02`  | MDM9650, SDX20    | EM7511, LM960                | 400, 528  |
| `0x03`  | SDX55             | EM9190, FN980, LV55          | 40, 336, 400, 528 |
| `0x04`  | SDX62             | RM520N                       | 16, 296, 336 |

### v=0x01 EP06A "1× per size per capture" pattern (session ``kali`` finding)

Every EP06A capture in the corpus (3 of 3 walked) emits **exactly one
0x1855 record at each of 4 sizes per capture: 68B + 92B + 256B + 360B**.
This is a structurally different traffic pattern from the periodic
per-SV measurement codes — 0x1855 on EP06A looks like a session-init /
config-dump code rather than a measurement stream.  The 4 sizes likely
correspond to 4 distinct report types within the L1C subsystem (e.g.,
satellite-list / signal-state / per-band-stats / config-snapshot).

256B and 360B were missing from the prior docstring's v=0x01 size list
(which named only 68, 92, 268).  Per-size body RE within v=0x01 EP06A is
now a smaller task: ~4 records per size per chipset across 8 EP06A
captures suffice for variance analysis.

### MDM9x07 non-emitter chipsets

Three MDM9x07 chipsets in the corpus do **not** emit 0x1855 at all:
EG25-G (6 captures), Quectel EG95NA (11 captures), and SIMCom SIM7600NA
(9 captures).  Compare with EP06A (also MDM9x07) which emits the 4-size
report bundle described above.  This makes 0x1855 emission **firmware-
dependent, not silicon-dependent** — the same MDM9x07 silicon either
tracks GPS L1C or doesn't, depending on the firmware build.  The
parallel finding for 0x184E (B2b) on MC7455 in #N supports the
same conclusion in the opposite direction (MC7455 silicon "officially"
GPS+GLONASS-only per Sierra docs but firmware emits B2b records).

This refines the L1C truth-gap closure path (#N): EG25-G, EG95NA,
and SIM7600NA captures cannot contribute corpus growth for 0x1855
field-level RE — only EP06A and MC7455 + the SDX2x/55/62 chipsets
emit this code.

Earlier docstring claim that 528B was "FN980-only" turned out to be
wrong — also seen on EG12-GT, EG18NA, LM960. The size landscape doesn't
correlate cleanly with version: e.g., 336B appears on both v3 (SDX55)
and v4 (SDX62), and 400B appears on both v2 (MDM9650) and v3 (SDX55).

## Known header structure (16-byte minimum)

- `byte[0]`       u8   `version` (1 / 2 / 3 / 4 — chipset generation)
- `bytes[1..3]`   u24  `session_tag` — **shared with 0x1856 (B1C) within
                       the same boot session**. See cross-code invariant
                       below.
- `bytes[4..7]`   u32  `reserved_4` — `0x00000000` in 98.2% of the corpus
                       (5,358 / 5,697 records).  One FN980m wardriving
                       boot session (`<redacted-pii>`
                       `capture_20260327_051208.dlf.gz`) emits all 98 of
                       its records with `reserved_4 = 0x00000006`
                       (capture-wide; no intra-capture variance).  The
                       earlier "invariant zero" claim from the v3
                       fixture set was selection bias — corpus-wide,
                       `reserved_4 ∈ {0x00000000, 0x00000006}`.  The
                       0x06 value is likely a per-boot-session config
                       flag bit; semantic TBD.
- `bytes[8..11]`  u32  `config_word` (0x00a00100 on v3 40B records)
- `bytes[12..15]` u32  `descriptor` (payload / SV-count hint)

## Cross-code session_tag invariant (2026-04-25 RE finding)

`bytes[1:4]` is a **24-bit GNSS_ME wide-band session tag** that is
constant across both 0x1855 (GPS L1C) and 0x1856 (BeiDou B1C) records
emitted within a single capture / boot session. Both signals are at
**1575.42 MHz** and share the QCA wide-band tracking block, so the
GNSS_ME subsystem stamps both record streams with the same per-session
identifier.

Verified across 4 paired-fixture sessions in the cross-chipset corpus:

| Modem (chipset)    | 0x1855 fixtures                  | 0x1856 fixtures             | Shared `session_tag` |
|--------------------|----------------------------------|-----------------------------|----------------------|
| FN980 (SDX55)      | 1855_fn980_336, 1855_fn980_40    | 1856_fn980_680              | `0x00146e0a`         |
| LV55 (SDX55)       | 1855_lv55_40                     | 1856_lv55_172               | `0x00bc1f20`         |
| MC7455 (MDM9x40)   | 1855_mc7455_92, 1855_mc7455_268  | 1856_mc7455_48              | `0x003856d9`         |
| RM520N (SDX62)     | 1855_rm520ngl_16                 | 1856_rm520ngl_16            | `0x001f34c8`         |

Use case: an analyst correlating GPS L1C and BeiDou B1C records across a
multi-code DIAG capture can use this u24 to confirm both streams came
from the same boot session, even if the captures are interleaved or
partially truncated.

## TBD for full closure (#N)

- Per-version SV-table layout — likely needs a separate decoder per
  (version, size) tuple, similar to 0x184E B2b.
- GPS L1C PRN encoding (likely 1..32 shared with L1 C/A).
- C/N0 / carrier phase / Doppler / pilot-vs-data channel split.

## ★ 2026-05-21 paradigm shift (<redacted-ref>, two-capture differential test)

**0x1855 is NOT a per-SV measurement report — it is a session-init
configuration enumeration of the L1C subsystem.** The "skeleton parser,
per-SV RE pending" framing in prior versions of this docstring (and the
issue body of #N) was directing RE work at a tail that does not
contain SV-specific data.

How we know:

Two PocketSDR-paired captures on the same RM520N-GL hardware, ~5 hours
apart, with **completely different L1C-tracking PRN truth sets**:

| Capture | Time (UTC)         | PocketSDR sigid-31 PRNs (L1C-data truth) |
|---------|--------------------|------------------------------------------|
| Run 2   | 2026-05-21 13:15Z  | ``[6, 14, 17, 19]``                      |
| Run 3   | 2026-05-21 16:58Z  | ``[5, 11, 13]``                          |

Both captures emit the same 8-record 0x1855 session-init burst
(sizes 16/16/48/64/144/192/232/336 B; identical sizes, identical
``config_word`` values, identical body bytes other than the
session_tag at bytes [1:4] and the high 16 bits of the ``descriptor``
field at bytes [14:16]).  In particular:

- **The ``82 00 03 00`` "per-SV slot" hypothesis is FALSIFIED.** Slot
  payload bytes are bit-identical across the two captures despite the
  L1C PRN truth being completely disjoint. The seq_id values
  ``{0x0d, 0x0e, 0x0f, 0x10, 0x1c, 0x1d, 0x1e, 0x1f}`` are fixed
  allocator-bank slot positions, not PRN identifiers, and the slot
  payloads carry **static** subsystem configuration constants
  (``06 0c 00 00 …`` discriminator + small fixed counter), not
  measurement data.
- **Same conclusion for every other prefix type** in the body
  (``22 00 03 00``, ``20 80 04 00``, ``02 80 03 00``, etc.) — they're
  all static across runs.

What actually varies across boot sessions:

- ``bytes[1:4]``  ``session_tag``  — per-boot identifier (already documented above)
- ``bytes[14:16]``  high 16 bits of ``descriptor`` — varies per-record per-session,
  likely a hash/CRC/frame-counter of the rest of the record. Not yet decoded.

### Parser-invariant finding: ``descriptor & 0xFFFF == payload_size - 16``

Independent of the session, the **low 16 bits of the descriptor field
encode the body length** (= payload_size - 16-byte header):

| payload_size | observed ``descriptor & 0xFFFF`` | body_length = size - 16 |
|--------------|----------------------------------|-------------------------|
| 16           | 0x0000                           | 0                       |
| 48           | 0x0020 (=32)                     | 32                      |
| 64           | 0x0030 (=48)                     | 48                      |
| 144          | 0x0080 (=128)                    | 128                     |
| 192          | 0x00b0 (=176)                    | 176                     |
| 232          | 0x00d8 (=216)                    | 216                     |
| 336          | 0x0140 (=320)                    | 320                     |

Verified across all 16 v=0x04 records in runs 2 + 3 (8 per run).
Suitable as a parse-validation invariant for v=0x04 SDX62 records;
needs verification on v=0x01/0x02/0x03 records before extending.

### Where the real L1C per-SV measurements live (TBD)

L1C measurements presumably exist somewhere in the modem's DIAG stream,
but **NOT in 0x1855**.  Candidate locations under investigation:

1. **0x1477 GpsMeasurementReport** — already carries per-SV L1 C/A data.
   Record size varies per epoch (run 2: 938 B × 295, run 3: 798 B × 295),
   suggesting per-SV slot allocation. However the parser exposes no
   ``band``/``signal_id`` field per SV — either the existing parser
   loses the band info, or 0x1477 only carries L1 C/A and L1C lives
   elsewhere.  The per-SV ``measurement_status`` u32 (e.g. 136577279 =
   0x082410FF) is a bitmask that *might* encode multi-band tracking
   state; needs decoder.
2. **A separate L1C-specific measurement code** not yet catalogued.
   Worth scanning ``modem-survey-diag`` output for SDX62 codes whose
   record count matches L1C-tracking SV count × 1 Hz × 300 s.

For #N closure, the **issue framing needs revision**: this code is
``GNSS_ME_GPS_L1C`` per Qualcomm's catalog (correctly identified as
"GPS L1C engine"), but the contents are the engine's CONFIGURATION
snapshot, not per-SV measurements. Title should be updated from
"GPS L1C Measurement Report — decode payload" to something like
"GPS L1C session-init configuration enumeration — verify the
configuration / state interpretation and find the corresponding
periodic measurement code".

### Original capture inputs

- Run 2: <redacted-capture-path>
- Run 3: <redacted-capture-path>

### Initial run 2 structural observations (still valid as catalog)

Body-tier structure (sizes 144 / 192 / 232 / 336 B):

- The body (after the 16-byte header) is a sequence of **typed field
  records** introduced by a 4-byte prefix ``XX YY ZZ 00`` where ``ZZ ∈
  {0x03, 0x04}`` (likely a per-field-type version) and the high nibble
  of ``XX`` + ``YY`` selects the field type.
- 9 distinct field-type prefixes observed in the 336B / 232B records:
  ``22 00 03 00``, ``20 80 04 00``, ``02 80 03 00``, ``82 04 03 00``,
  ``00 80 03 00``, ``20 00 04 00``, ``82 00 03 00``, ``20 00 03 00``,
  ``01 00 02 00``.
- The ``82 00 03 00`` slots are 24-byte fixed-pitch records:
  ``82 00 03 00 [seq_id u16 LE] 08 00 [16B payload split 8+8]``.
  ``seq_id`` values observed: ``{0x0d, 0x0e, 0x0f, 0x10}`` in 336B record,
  ``{0x1c, 0x1d, 0x1e, 0x1f}`` in 232B record, fixed across boot
  sessions — these are static slot positions in the L1C tracker's
  resource layout, NOT PRN identifiers (falsified by the run-3
  differential test above).
- All 8 records span ~2 seconds (1612 ticks × 1.25 ms) — session-init
  burst pattern, not periodic measurements. Same overall shape as
  the EP06A v=0x01 4-bundle pattern documented earlier.

These observations remain useful as a CATALOG of the L1C subsystem's
configuration structure, but should NOT be interpreted as decoding
per-SV measurements.

## Test fixtures (9 fixtures × 4 versions × 4 chipset generations)

- ``gps_l1c_1855_fn980_40.bin``      —  40B v3 (FN980 SDX55)
- ``gps_l1c_1855_lv55_40.bin``       —  40B v3 (Wistron LV55 SDX55)
- ``gps_l1c_1855_fn980_336.bin``     — 336B v3 (FN980 SDX55)
- ``gps_l1c_1855_em7511_400.bin``    — 400B v2 (Sierra EM7511 MDM9650)
- ``gps_l1c_1855_lm960_528.bin``     — 528B v2 (Telit LM960 SDX20) **NEW**
- ``gps_l1c_1855_ep06a_68.bin``      —  68B v1 (Quectel EP06A MDM9x07) **NEW**
- ``gps_l1c_1855_mc7455_92.bin``     —  92B v1 (Sierra MC7455 MDM9x40) **NEW**
- ``gps_l1c_1855_mc7455_268.bin``    — 268B v1 (Sierra MC7455 MDM9x40) **NEW**
- ``gps_l1c_1855_rm520ngl_16.bin``   —  16B v4 (Quectel RM520N SDX62) **NEW**
- ``gps_l1c_1855_fn980_v3_40b_reserved_06.bin`` —  40B v3 (FN980 SDX55,
  ``reserved_4 = 0x06`` capture-wide divergence from the 2026-03-26
  wardriving boot session — locks in the corpus-wide retraction of the
  "reserved_4 invariant zero" claim)

Audit-noise note (#N, 2026-05-27) — ⛔ RETRACTED 2026-06-11 (#N)
--------------------------------------------------------------------

The 2026-05-27 note below dismissed **byte+0=0x06** on the Foxconn T99W640
as DLF mis-framing noise ("6 unrelated sizes 16/48/64/144/400/504, no size
cohort, intentionally not widening the enum"). **That conclusion was WRONG
and is RETRACTED.** A fresh CLEAN capture (5govalidate 2026-06-11,
`capture_dlf_from_diag.py` over `/dev/mhi_DIAG`, **0 dropped frames**;
`FDE2.F0.0.0.1.2.TO.001/diag/<redacted-pii>`) proves
v=0x06 is a REAL SDX72 (SDXPINN) variant, not mis-framing:

  * The v3 self-consistency invariant `descriptor & 0xFFFF == payload_size
    - 16` HOLDS on all 8 records across the 6 sizes (16/48/64/144/400/504
    -> body 0/32/48/128/384/488). Byte-misaligned frames cannot satisfy
    this length self-encoding across 6 distinct sizes.
  * The documented cross-code session_tag invariant HOLDS: bytes[1:4] =
    0x92d080 is IDENTICAL across all 0x1855 records AND the 0x1856 (BeiDou
    B1C) records captured in the same boot session — exactly the wide-band
    GNSS_ME session-tag the v3 RE established.

The 16-byte header decodes identically to v1-v4. The enum is now widened
to include 0x06 (see @register field_invariants) and a hw-validated
T99W640 v6 recipe added. Original (now-superseded) note retained for the
audit-history trail:

  "The audit sweep surfaces byte+0=0x06 (n=7) on a single T99W640 capture
   across 6 unrelated sizes; treated as the 0xB826 v=0x07 / 0x1C00 v=0x03
   DLF mis-framing class and not widened." — that capture was likely a
   genuinely mis-framed older DLF; the clean 2026-06-11 capture is not.

=== names-block:start (auto-generated by tools/inject_names_block_parsers.py) ===

Names by source (from sources/DIAG_LOG_INDEX.yaml):
    canonical: LOG_EVENTS_DS_GSM_HANDOVER_END
        source: qxdm_3_12_714_2017_diag_log_codes (authority: community)
    aliases:
        LOG_EVENTS_GSM_DS_HANDOVER_END
            source: qxdm_3_12_714_2017_diag_log_codes
        RESERVED
            source: qxdm_itemtype_list_zukgit_2025_04_03

Source-precedence (#N): vendor_official > observation >
community (specification) > community (reference).
=== names-block:end ===
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_GNSS_ME_GPS_L1C
from diaggrok.registry import register


@dataclass
class Diag0x1855:
    """GPS L1C measurement report (0x1855) — skeleton parser.

    Exposes header-level identification only; per-SV tail RE is open
    (see #N). ``constellation`` / ``band`` are set so the RINEX writer
    can route L1C records to the C1L/L1L obs-code group once per-SV
    measurements are decoded.
    """

    log_time: int
    version: int              # u8 at offset 0 — chipset generation (1=MDM9x07/40, 2=MDM9650/SDX20, 3=SDX55, 4=SDX62)
    session_tag: int          # u24 at offset 1 — shared with 0x1856 in same session
    header_marker: int        # u32 at offset 0 (version + session_tag) — kept for backward compat
    reserved_4: int           # u32 at offset 4 — 0x00000000 in 98.2% of corpus, 0x00000006 in one FN980m wardriving boot session (#N v4)
    config_word: int          # u32 at offset 8
    descriptor: int           # u32 at offset 12
    payload_size: int
    size_variant: str         # 'small_40' | 'medium_336' | 'large_400' | 'xlarge_528' | 'unknown'
    raw: bytes
    constellation: str = 'GPS'
    band: str = 'L1C'

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1855',
            'log_time': self.log_time,
            'version': self.version,
            'session_tag': self.session_tag,
            'header_marker': self.header_marker,
            'reserved_4': self.reserved_4,
            'config_word': self.config_word,
            'descriptor': self.descriptor,
            'payload_size': self.payload_size,
            'size_variant': self.size_variant,
            'constellation': self.constellation,
            'band': self.band,
            'parser_status': 'skeleton',
            'parser_note': 'per-SV tail RE open — see #N (L1C infra — #N wired via band=L1C)',
        }


def _classify_size(n: int) -> str:
    """Classify into a known observed size variant, or 'unknown' for novel sizes.

    Size variants observed corpus-wide:
        16 / 40 / 68 / 92 / 256 / 268 / 296 / 336 / 360 / 400 / 528

    EP06A v=0x01 emits the 4-bundle `(68, 92, 256, 360)` — exactly one record
    of each size per capture session — likely 4 distinct L1C report types
    rather than periodic per-SV measurements.  See #N 2026-05-07 comment.
    """
    if n == 16:
        return 'tiny_16'         # SDX62 RM520N — minimum-header
    if n == 40:
        return 'small_40'        # SDX55 multi-modem — header-only / no-track
    if n == 68:
        return 'medium_68'       # MDM9x07 EP06A
    if n == 92:
        return 'medium_92'       # MDM9x40 MC7455 / MDM9x07 EP06A
    if n == 256:
        return 'medium_256'      # MDM9x07 EP06A — bundle slot 3
    if n == 268:
        return 'medium_268'      # MDM9x40 MC7455
    if n == 296:
        return 'medium_296'      # SDX62 RM520N
    if n == 336:
        return 'medium_336'      # SDX55 / SDX62
    if n == 360:
        return 'medium_360'      # MDM9x07 EP06A — bundle slot 4
    if n == 400:
        return 'large_400'       # MDM9650 EM7511
    if n == 528:
        return 'xlarge_528'      # multi-modem (EG12-GT, EG18NA, LM960)
    if n == 48:
        return 'small_48'        # SDX72 T99W640 v=0x06 burst member
    if n == 64:
        return 'small_64'        # SDX72 T99W640 v=0x06 burst member
    if n == 144:
        return 'medium_144'      # SDX72 T99W640 v=0x06 burst member
    if n == 504:
        return 'large_504'       # SDX72 T99W640 v=0x06 burst member
    return 'unknown'


# Ground-truth recipe (#N). Authored offline (session <redacted-ref>) — NOT
# hardware-verified. SIM8202G-M2 (SIMCom SDX55) recommended target; SDX55
# emits v=0x03. ⛔ Critical honesty: per the 2026-05-21 paradigm shift
# (<redacted-ref>, two-capture differential test documented above), 0x1855 is
# a GPS-L1C session-init CONFIGURATION enumeration, NOT a per-SV measurement
# report — the "per-SV slot" hypothesis was FALSIFIED (slot payloads are
# bit-identical across captures with disjoint L1C PRN truth sets). So this
# recipe does NOT try to ground per-SV measurements (they live elsewhere,
# see #N / candidate 0x1477). It grounds the config burst's IDENTITY and
# TIMING. The vendor-catalog name GNSS_ME_GPS_L1C is authoritative; the
# community names-block (LOG_EVENTS_DS_GSM_HANDOVER_END / RESERVED) is bogus
# index noise. Also note: descriptor & 0xFFFF == payload_size - 16 is a
# parser-internal self-consistency invariant, NOT an external ground-truth,
# so it is deliberately not a field_map entry.

@register(
    LOG_GNSS_ME_GPS_L1C,
    name="0x1855",
    description="GPS L1C signal measurements — skeleton parser, per-SV RE pending (#N)",
    version=6,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "v4 (2026-04-27, <redacted-ref> RTCM-revisit redo via "
        "tools/parser_corpus_summary.py): walked 5,697 records across 115 "
        "captures.  Two v3 claims refined:\n"
        "(1) reserved_4 'invariant zero across all 9 fixtures' — corpus-wide "
        "false: 98 records (1.7%) in `<redacted-pii>"
        "capture_20260327_051208.dlf.gz` have reserved_4 = 0x00000006 "
        "(capture-wide consistent, no intra-capture variance).  The v3 "
        "fixture set was 100% from the 0x00 majority form — selection bias "
        "identical to the 0x163E session-1a4f / 0x163D session-11d0 "
        "patterns.  Corpus reality: reserved_4 ∈ {0x00000000, 0x00000006}, "
        "with the 0x06 form likely a per-boot-session config flag.  New "
        "fixture `gps_l1c_1855_fn980_v3_40b_reserved_06.bin` locks the 0x06 "
        "form in.\n"
        "(2) Size-variant taxonomy — corpus has ~13 sizes the parser maps "
        "to 'unknown' (32 / 48 / 56 / 80 / 152 / 200 / 208 / 240 / 280 / "
        "288 / 304 / 312 / 328 B and others).  Not a parse-rate issue "
        "(header still decodes), but the variant enum is incomplete.  No "
        "code change in v4 — flagging as a known gap.\n"
        "v5 (2026-05-07, <redacted-ref>): added `medium_256` to _classify_size "
        "to close the gap left by the prior comment-only update.  The "
        "`(68, 92, 256, 360)` 4-tuple is EP06A v=0x01's per-capture bundle — "
        "1× of each size per session (3/3 EP06A captures audited).  Cross-"
        "record session_tag invariance verified: all 4 sizes share the same "
        "u24 session tag at bytes[1:4] within a capture, consistent with the "
        "v3 cross-code session_tag finding.  Two new fixtures landed: "
        "`gps_l1c_1855_ep06a_256.bin`, `gps_l1c_1855_ep06a_360.bin` "
        "(extracted from <redacted-pii>).\n"
        "RTCM-truth gap: the LG290P MSM7 stream does NOT include GPS L1C "
        "sigids (RTCM 30/31/32) in its current firmware — the existing "
        "paired-RTCM corpus cannot verify any L1C-tracking claim.  Filed "
        "as #N (high-priority operator capture with a non-LG290P L1C-"
        "capable reference receiver)."
    ),
    # v6 (2026-06-11, #N 5govalidate): ADD version 0x06 — the Foxconn
    # T99W640 (SDX72/SDXPINN) emits 0x1855 at byte0=0x06. This RETRACTS the
    # "Audit-noise note (#N)" below that had dismissed byte0=0x06 on this
    # exact unit as DLF mis-framing and intentionally NOT widened the enum.
    # A fresh CLEAN capture (capture_dlf_from_diag.py over /dev/mhi_DIAG, 0
    # dropped frames; <redacted-pii>) shows v=0x06 is a REAL,
    # correctly-framed variant: (1) the v3 self-consistency invariant
    # `descriptor & 0xFFFF == payload_size - 16` HOLDS on all 8 records across
    # 6 sizes (16/48/64/144/400/504 -> body 0/32/48/128/384/488) — impossible
    # under mis-framing; (2) the documented cross-code session_tag invariant
    # HOLDS — bytes[1:4]=0x92d080 is identical to the 0x1856 (B1C) records in
    # the same session. The 16-byte header decodes identically to v1-v4, so
    # the skeleton parser extracts it directly; per-SV/body tail stays opaque.
    source_url="",
    # 9 named header fields; per-SV signal-metric body still opaque as
    # body_raw — skeleton parser, per-SV RE pending.
    # 9 parsed / 10 identified. (#N)
    fields_parsed=9,
    fields_identified=10,
    # Layer-2 version invariant — per #N / #N follow-up (b).
    # Corpus per #N (v3 docstring): 4 distinct version bytes 0x01..0x04
    # corresponding to chipset generation. Cross-code invariant: version
    # tracks 0x1856 (BDS B1C) version in the same boot session. A future
    # firmware shipping v=0x05+ in any existing size class would silently
    # route through the existing size→variant map. Reject unknown versions
    # so the parse-rate drop is visible.
    field_invariants={
        "version": {"enum": [0x01, 0x02, 0x03, 0x04, 0x06]},
    },
    issues=(),
    primary_issue=None,
)
def parse_0x1855(
    log_time: int, data: bytes
) -> Diag0x1855 | None:
    """Parse a LOG_GNSS_ME_GPS_L1C (0x1855) log payload — skeleton (#N)."""
    if len(data) < 16:
        return None
    if data[0] not in (0x01, 0x02, 0x03, 0x04, 0x06):
        return None
    return Diag0x1855(
        log_time=log_time,
        version=data[0],
        session_tag=int.from_bytes(data[1:4], 'little'),
        header_marker=unpack_from('<I', data, 0)[0],
        reserved_4=unpack_from('<I', data, 4)[0],
        config_word=unpack_from('<I', data, 8)[0],
        descriptor=unpack_from('<I', data, 12)[0],
        payload_size=len(data),
        size_variant=_classify_size(len(data)),
        raw=bytes(data),
    )
